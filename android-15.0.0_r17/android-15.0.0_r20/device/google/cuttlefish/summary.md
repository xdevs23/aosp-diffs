```
13ed53bad: Use Skia to handle more screenshot formats (Jason Macnak <natsu@google.com>)
e31d4c5cf: Add `cvd display screenshot` functionality (Jason Macnak <natsu@google.com>)
61c16b819: Add HDCP AIDL to the KnownMissingAidl (Armelle Laine <armellel@google.com>)
14d15eca0: Blocklist snd-aloop.ko kernel module (Marcin Radomski <dextero@google.com>)
01eb90b89: Mark `android.system.vold` as unimplemented (Weston Carvalho <westoncarvalho@google.com>)
54d3208ca: Add vendor_capabilities_service to the list of missing HALs (Nikita Ioffe <ioffe@google.com>)
a1abf1aa5: Unlock after reboot in snapshot tests (Jason Macnak <natsu@google.com>)
4596136aa: file_contexts: support secure storage in system for test (Armelle Laine <armellel@google.com>)
939ffa804: Workaround casimir dropping ints with value 0 (Brad Lassey <lassey@google.com>)
c53799c30: Add android.media.audio.eraser.types to kAlwaysMissingAidl (Shunkai Yao <yaoshunkai@google.com>)
8db69c435: Fix HexToBytes vector size (Maksym Korotych <max.korotych@gmail.com>)
4d1e258e8: Add bluetooth socket service (Jayden Kim <jaydenk@google.com>)
1adc362bf: Refactor input_connector code (Jorge E. Moreira <jemoreira@google.com>)
7caffcab6: Bpfmt all Android.bp (Keiichi Watanabe <keiichiw@google.com>)
1d03ab6c9: process_sandboxer: Fixes to support compiling after import (A. Cody Schuffelen <schuffelen@google.com>)
637e4c69b: [tests] Add HwCrypto hal as known missing AIDL (Orlando Arbildo <oarbildo@google.com>)
a36268962: Stop matching deprecated Ika target (Shao-Chuan Lee <shaochuan@google.com>)
43cb82bca: Define vendor_ramdisk version of fstab.cf.* modules (Jihoon Kang <jihoonkang@google.com>)
025fe666c: Bpfmt shared/config/Android.bp (Jihoon Kang <jihoonkang@google.com>)
1ceb3a284: Update cpuvulkan version to 1.3 to match swiftshader (Jason Macnak <natsu@google.com>)
5b0dd41ff: Load wildcarded kernel modules from conditional path (Marcin Radomski <dextero@google.com>)
a556f71a7: Revert "Use a local copy of vulkanhpp" (Chris Forbes <chrisforbes@google.com>)
e5307028b: Add DEBUG logger to audio server (Jorge E. Moreira <jemoreira@google.com>)
10ba2d888: Revert "Use a local copy of vulkanhpp" (Chris Forbes <chrisforbes@google.com>)
51175384c: Try a different unlock mechanism for snapshot tests (Jason Macnak <natsu@google.com>)
8900b4937: Mark secure storage aidl as always missing (Weston Carvalho <westoncarvalho@google.com>)
3d837e1f1: Use a local copy of vulkanhpp (Jason Macnak <natsu@google.com>)
eea2e012c: Disable exposeES32ForTesting on Cuttlefish (Jason Macnak <natsu@google.com>)
a1812d8fb: Remote impl of KeyMint is v3 not current (David Drysdale <drysdale@google.com>)
4f4decc0f: Revert "[uwb-overlay] Support multicast list update rsp v2 on cf" (Pechetty Sravani (xWF) <pechetty@google.com>)
6407b61b5: Add secondary command buffer snapshot tests (Jason Macnak <natsu@google.com>)
b7d58252e: Add test rule to unlock device before each test (Jason Macnak <natsu@google.com>)
1acda8ee5: Set ro.vendor.hwc.drm.present_fence_not_reliable=true (Tim Van Patten <timvp@google.com>)
522c79ff9: Reapply "Update kernel module paths" (Marcin Radomski <dextero@google.com>)
66f3d615b: Save screenshots on failure (Jason Macnak <natsu@google.com>)
680cc37ab: Revert "Update kernel module paths" (Liana Kazanova <lkazanova@google.com>)
272f41107: [uwb-overlay] Support multicast list update rsp v2 on cf (James Eidson <jmes@google.com>)
e67cffefd: sepolicy definitions for WV Trusty VM (Orlando Arbildo <oarbildo@google.com>)
a1d3dd467: Update kernel module paths (Marcin Radomski <dextero@google.com>)
c2d4959f8: Decrease the trusty security VM memory (Alice Wang <aliceywang@google.com>)
a355152f4: Avoid empty cvd_bugreport_build.log. (Sergio Andres Rodriguez Orama <sorama@google.com...)
7b12296c6: Add AuthMgr  AIDL to the KnownMissingAidl (Hasini Gunasinghe <hasinitg@google.com>)
c2b5678ac: Remove |ro.hardware.| prefix in KM VM sys property (Alice Wang <aliceywang@google.com>)
53faad346: Deduplicate `Result`-to-`Status` conversion in casimir_control_server (A. Cody Schuffelen <schuffelen@google.com>)
25103ebfb: Tie `CasimirController`'s initialization to its lifetime (A. Cody Schuffelen <schuffelen@google.com>)
257941a31: Don't use `std::shared_ptr`s for hex strings (A. Cody Schuffelen <schuffelen@google.com>)
40cc3cc0a: Rename `utils.h` to `hex.h` in `casimir_control_server` (A. Cody Schuffelen <schuffelen@google.com>)
da0c6f11e: Order class members in `casimir_control_server` (A. Cody Schuffelen <schuffelen@google.com>)
6bc29337a: Put `casimir_control_server` entirely in the `cuttlefish` namespace (A. Cody Schuffelen <schuffelen@google.com>)
d8d63d7cb: Update sandbox policies for casimir using unix sockets (A. Cody Schuffelen <schuffelen@google.com>)
9b2cd94b8: Use unix sockets for casimir (A. Cody Schuffelen <schuffelen@google.com>)
edf2ca428: casimir_control_server: Support a unix rf server (A. Cody Schuffelen <schuffelen@google.com>)
6597d3b49: Add REAR_DISPLAY_OUTER_DEFAULT to CF configuration (Kevin Chyn <kchyn@google.com>)
cca82ec60: Revert "Reapply "Update kernel module paths"" (Liana Kazanova <lkazanova@google.com>)
148b5d924: cuttlefish: use Health V4 (Daniel Zheng <zhengdaniel@google.com>)
56d4daadb: Add new log messages around super image mixing (Chad Reynolds <chadreynolds@google.com>)
ba4a3390c: Implement field on notificaitons and setting the power level on casimir (Brad Lassey <lassey@google.com>)
e1d289088: Reapply "Update kernel module paths" (Marcin Radomski <dextero@google.com>)
6e8608796: Move early_vms.xml out of cuttlefish specific directory for reusability (Willis Kung <williskung@google.com>)
fc584ba31: Refactor all of the path logic together (Chad Reynolds <chadreynolds@google.com>)
487d80c07: Revert "Update kernel module paths" (Chaitanya Cheemala (xWF) <ccheemala@google.com>)
e9c422b22: minidroid: fix build (Marcin Radomski <dextero@google.com>)
0da427c64: Update kernel module paths (Marcin Radomski <dextero@google.com>)
b8def3319: Rename generic_system_image to aosp_shared_system_image (Justin Yun <justinyun@google.com>)
78646a27b: Add vulkan snapshot tests (Jason Macnak <natsu@google.com>)
2ec62dc50: Rename system property to enable KeyMint VM (Alice Wang <aliceywang@google.com>)
8761f51db: Add `CuttlefishConfig::EnvironmentSpecific::casimir{nci,rf}::socket_path... (A. Cody Schuffelen <schuffelen@google.com>)
fb63a7ee4: Use the fluent Command syntax for launching casimir (A. Cody Schuffelen <schuffelen@google.com>)
adbd90802: tcp_connector: support unix sockets (A. Cody Schuffelen <schuffelen@google.com>)
5b2c759ce: blocklist dummy-cpufreq.ko for aarch64 cf targets (David Dai <davidai@google.com>)
182f60ad9: Ignore all Android.mk files in aosp_cf phone products of vsoc_x86_64 and... (Wei Li <weiwli@google.com>)
7620aa709: Revert "Change how hibernation image is generated" (Terry Guan <terryguan@google.com>)
69760a5c7: Cope with new KeyMint tag (David Drysdale <drysdale@google.com>)
83e4284b7: Hold the lock on the mutex only while accessing the data (Jorge E. Moreira <jemoreira@google.com>)
cb5bcd6d3: Move non-vcpu/critical tasks to workers cgroup (Wei-chung Hsu <weihsu@google.com>)
87987271e: Set guest_soc prop at boot (David Dai <davidai@google.com>)
7b1767bf6: cuttlefish: Update kHwComposerDrm to "drm_hwcomposer" (Tim Van Patten <timvp@google.com>)
0c437bee8: Run multidevice tests with Cuttlefish (Brad Lassey <lassey@google.com>)
de2cced87: Derive the number of vCPUs from the vcpu_config_path instead (David Dai <davidai@google.com>)
86f86d237: Change TEST_MAPPING (terryguan <terryguan@google.com>)
b4d09f7a1: Revert "Delete CF hal_{gatekeeper,keymint}_default.te files" (Priyanka Advani (xWF) <padvani@google.com>)
a8368f3f4: Disable prime shader cache for CF (Robin Lee <rgl@google.com>)
cbb889cf3: Add `CrosvmBuilder` commands for cpu flags (A. Cody Schuffelen <schuffelen@google.com>)
dbf38117d: Move frequency domain crosvm arguments to a separate file (A. Cody Schuffelen <schuffelen@google.com>)
527f84791: Delete CF hal_{gatekeeper,keymint}_default.te files (A. Cody Schuffelen <schuffelen@google.com>)
f9cd3210a: Remove `/tmp` mount in `assemble_cvd` or `avbtool` (A. Cody Schuffelen <schuffelen@google.com>)
ca49374eb: Add a `early_tmp_dir` flag to control file locations (A. Cody Schuffelen <schuffelen@google.com>)
315bd0310: Change how hibernation image is generated (terryguan <terryguan@google.com>)
774502ed4: Revert^3 "Changed how hibernation image is generated" (Terry Guan <terryguan@google.com>)
d99d9d6c9: Revert^2 "Changed how hibernation image is generated" (ELIYAZ MOMIN <mohammedeliyaz@google.com>)
13daa35a7: Make auto_ethernet optional (Alin Gherman <alingherman@google.com>)
71938af67: Add wheel event handler to mouse (ruki <ruki@google.com>)
5e2256013: Revert "Changed how hibernation image is generated" (Gurchetan Singh <gurchetansingh@google.com>)
a369894cd: Update overrides in vsoc_arm boardconfig (David Dai <davidai@google.com>)
4679ff686: Radio: bump rest of declared AIDL services (Tomasz Wasilczyk <twasilczyk@google.com>)
779de3ae5: Radio: bump rest of declared AIDL services (Tomasz Wasilczyk <twasilczyk@google.com>)
d882d90a5: Add parsing for freq_domain and cgroups (David Dai <davidai@google.com>)
8483f5deb: Bump KeyMint version (Karuna Wadhera <kwadhera@google.com>)
3381bd867: Fixing watchdog for trade-in mode (Paul Lawrence <paullawrence@google.com>)
680083ec1: Re-enable soong-built system image for aosp_cf targets (Justin Yun <justinyun@google.com>)
b78e5ea9c: Send touch up/down events for all contacts (Jorge E. Moreira <jemoreira@google.com>)
fde718488: Don't use slot id as tracking id (Jorge E. Moreira <jemoreira@google.com>)
ee2d7d24d: Don't access iterator after erase (Jorge E. Moreira <jemoreira@google.com>)
a9d066630: Don't send BTN_TOUCH UP unless down is false (Jorge E. Moreira <jemoreira@google.com>)
ea3b10887: SnapshotTest avoid delete on snapshot fail, throw errors (Elie Kheirallah <khei@google.com>)
64f1300bc: Changed how hibernation image is generated (terryguan <terryguan@google.com>)
7625f5eea: Update ARpcServer_newVsock for new method (Devin Moore <devinmoore@google.com>)
be8715805: Rename KM VM related system properties (Alice Wang <aliceywang@google.com>)
d3b40dc79: Use `JoinPath` rather than concatenation in all sandbox policies (A. Cody Schuffelen <schuffelen@google.com>)
f2cb73ecd: Use Kati to build the system image for cuttlefish targets (Justin Yun <justinyun@google.com>)
7c3f580d5: Use a tmpfs mount for netsimd `/tmp` (A. Cody Schuffelen <schuffelen@google.com>)
3fb567197: Use random data for sandbox pingback values. (A. Cody Schuffelen <schuffelen@google.com>)
8e316f654: Remove `TraceAndAllow` implementation. (A. Cody Schuffelen <schuffelen@google.com>)
c88f895e3: Bump KeyMint version (Karuna Wadhera <kwadhera@google.com>)
c196a4485: Fix sepolicy errors on switching keymint/gatekeeper domains (A. Cody Schuffelen <schuffelen@google.com>)
2b1a5078c: Reapply "Add serialno access to the kefault keymint domain" (A. Cody Schuffelen <schuffelen@google.com>)
fe788787d: Fix function pointer type mismatch for C23. (Elliott Hughes <enh@google.com>)
60d913a69: Revert^2 "Enable Media Quality Service on Cuttlefish" (Haofan Wang <haofanw@google.com>)
f5578415c: Revert "Enable Media Quality Service on Cuttlefish" (Greg Kaiser <gkaiser@google.com>)
0efbecbb8: Disable CBS V4 on cuttlefish (sadiqsada <sadiqsada@google.com>)
5491a3733: Remove egrep usage (Chad Reynolds <chadreynolds@google.com>)
52cd8e365: Revert "Enable checkpoints in cf with ext4" (Liana Kazanova <lkazanova@google.com>)
ee9df3eec: Remove displays from streamer after display sinks (Jorge E. Moreira <jemoreira@google.com>)
5bb5ffb46: Protect access to the display sinks with the send mutex (Jorge E. Moreira <jemoreira@google.com>)
ae05510ff: Radio: bump declared AIDL services (Tomasz Wasilczyk <twasilczyk@google.com>)
b774f8f81: Use libradiocompat aidl_deps for AIDL dependencies (Tomasz Wasilczyk <twasilczyk@google.com>)
b6866b06f: Reformat reference-libril makefile (Tomasz Wasilczyk <twasilczyk@google.com>)
925ece353: Pin KeyMint dependency to correct/specific version (Karuna Wadhera <kwadhera@google.com>)
37b5a42f0: Revert "Use new Radio HALs" (Liana Kazanova <lkazanova@google.com>)
4206297b0: Fix path for 6.6 kernel (David Dai <davidai@google.com>)
ca15fe231: Add support for multiple custom partition paths (Ethan Lee <ethanalee@google.com>)
dcc0f1623: Add overlay xml file to fix test error for cuttlefish (tomhsu <tomhsu@google.com>)
3aa3c3dc6: Revert "Add serialno access to the kefault keymint domain" (Priyanka Advani (xWF) <padvani@google.com>)
aee062532: Remove dependencies on the 1-variant fallback (Cole Faust <colefaust@google.com>)
d3cb58ac1: Set vsoc_arm to use 6.6 kernel (David Dai <davidai@google.com>)
06fc37f52: Enable Media Quality Service on Cuttlefish (Haofan Wang <haofanw@google.com>)
13dab8199: Rename trusty_vm_launcher and move it to packages/modules/Virtualization (Inseob Kim <inseob@google.com>)
4dd6c97e0: Add serialno access to the kefault keymint domain (A. Cody Schuffelen <schuffelen@google.com>)
beeb6582c: simplify ProcessMonitor::Properties API (Frederick Mayle <fmayle@google.com>)
f16db40c3: fix openwrt crosvm crash on CF shutdown (Frederick Mayle <fmayle@google.com>)
4d8c82f49: Use new Radio HALs (Tomasz Wasilczyk <twasilczyk@google.com>)
e4d16d1eb: delete openwrt crosvm control socket on powerwash (Frederick Mayle <fmayle@google.com>)
6822d3ffb: Add android.media.audio.eraser.types to kAlwaysMissingAidl (Shunkai Yao <yaoshunkai@google.com>)
3c6865ab6: Use `AutoSetup` for `InitializeEspImage` (A. Cody Schuffelen <schuffelen@google.com>)
ac31394c9: Update auto_portrait dimension (Calvin Huang <calhuang@google.com>)
0f500fa96: Add a default implementation of `SetupFeature::Enabled` returning `true`... (A. Cody Schuffelen <schuffelen@google.com>)
bf69ab9a1: Delete snapshot after every test in SnapshotTest (Elie Kheirallah <khei@google.com>)
68c5186c7: Revert^2 "Add Cuttlefish frontend mouse support." (Linjiao Zhao <ruki@google.com>)
d77868439: Revert "Removing vhost_user_vsock" (Terry Guan <terryguan@google.com>)
306965e4f: Add back drm hwcomposer support (Jason Macnak <natsu@google.com>)
976bab23e: Removing vhost_user_vsock (terryguan <terryguan@google.com>)
3ce82399b: CUTTLEFISH: cf_x86_64_desktop builds use AL kernel (Greg Edelston <gredelston@google.com>)
23151cd24: Use soong-built system image for aosp foldable (Inseob Kim <inseob@google.com>)
927e97664: android-info: add prefer_drm_virgl_when_supported flag (Marcin Radomski <dextero@google.com>)
7908da819: [trusty] Move trusty kernel to etc/vm/trusty_vm directory (Alice Wang <aliceywang@google.com>)
f2d28e319: aosp_cf_x86_64_phone uses soong defined system image (Justin Yun <justinyun@google.com>)
a5e65999a: Use canonical copy of ABSL for WebRTC dep. (Krzysztof Kosiński <krzysio@google.com>)
4db79c4f3: Setup ethernet for cf_auto target. (Yu Shan <shanyu@google.com>)
ddc833225: Add overlay xml file to fix test error for cuttlefish (tomhsu <tomhsu@google.com>)
880fdac38: Add vsoc_arm target to be used by Wear targets (David Dai <davidai@google.com>)
354159a52: Fix build with fmtlib 11.0.2 (Yi Kong <yikong@google.com>)
f8067dd68: Populate shared desktop directory (Shao-Chuan Lee <shaochuan@google.com>)
347a0bfe2: Add support for vvmtruststore partition to Cuttlefish (Istvan Nador <istvannador@google.com>)
51411d514: Add back drm hwcomposer support (Jason Macnak <natsu@google.com>)
3a35d43a4: Revert^3 "Drop guest-side socket_vsock_proxy" (Chaitanya Cheemala (xWF) <ccheemala@google.com>)
f012f05cc: Sync with new drm common aidl interface (Huihong Luo <huisinro@google.com>)
58f3d25c8: Revert^2 "Drop guest-side socket_vsock_proxy" (Alistair Delva <adelva@google.com>)
8c3018893: Don't audit vendor_boot_security_patch_level_prop read denial (Alice Wang <aliceywang@google.com>)
b880d8c37: Use profile at framework/base/boot/ instead of the combined one at frame... (Islam Elbanna <islamelbanna@google.com>)
e12b8481b: Move the soong-built system image to build/make/target (Justin Yun <justinyun@google.com>)
36b2e32e9: Move the soong-built system image to build/make/target (Justin Yun <justinyun@google.com>)
f901f1412: shared: sepolicy: system_ext: enforce secure storage types (Armelle Laine <armellel@google.com>)
bfabbaffc: Fixes `cvd suspend` getting stuck when `adb_connector` is not running. (Sergio Andres Rodriguez Orama <sorama@google.com...)
907736269: Skip logs only if log dir already exists on restore (Elie Kheirallah <khei@google.com>)
b815bf742: shared: device.mk: add trusty-ut-ctl (Armelle Laine <armellel@google.com>)
ac67a1996: shared: device.mk: Add secure storage for the Trusty VM (Armelle Laine <armellel@google.com>)
76d60d103: Add new createVm argument (Elie Kheirallah <khei@google.com>)
b18a0e44c: Replace uses of egrep and fgrep with grep -E/-F (Ivan Tkachenko <me@ratijas.tk>)
0b0357ead: Add auto cf specific logic needed for hibernation (terryguan <terryguan@google.com>)
5998bc63e: Change vintf_fragment_modules to prebuilts (Deyao Ren <deyaoren@google.com>)
f555c7f61: Enable checkpoints in cf with ext4 (Paul Lawrence <paullawrence@google.com>)
```

