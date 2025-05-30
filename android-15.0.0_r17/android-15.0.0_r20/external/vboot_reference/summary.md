```
0d49b8fd: recovery_kernel: add signing type recovery_kernel (Benjamin Shai <bshai@google.com>)
1f7ca823: gpt_misc: Return uint64_t from GptGetEntrySize functions (Tomasz Michalec <tmichalec@google.com>)
36621031: Reland "host/lib/flashrom: Use flashrom provided in PATH" (Jakub Czapiga <czapiga@google.com>)
dbcfe4c5: OWNERS.android: Add bernacki@google.com (Jakub Czapiga <czapiga@google.com>)
26e8011f: Add configurable temporary directory path (Jakub Czapiga <czapiga@google.com>)
a0f83f9f: futility: Drop futility execution logging to /tmp/futility.log (Jakub Czapiga <czapiga@google.com>)
862e250e: crossystem: Make crossystem vendor_available (Rob Barnes <robbarnes@google.com>)
3246e484: futility: updater: Increase try count from 11 to 13 (Yu-Ping Wu <yupingso@chromium.org>)
2ab8888b: make_dev_ssd: add upstream cmdline flag for ptracers (Arnaud Ferraris <arnaud.ferraris@collabora.corp-...)
3c2ef940: Update Rust OWNERS file to include libchromeos-rs/OWNERS (Allen Webb <allenwebb@google.com>)
c5af1fd8: make_dev_ssd.sh: avoid page cache aliasing (Ross Zwisler <zwisler@google.com>)
38f9c255: Revert "host/lib/flashrom: Use flashrom provided in PATH" (Hsuan Ting Chen <roccochen@chromium.org>)
7d4b23f9: futility: updater: Revise the test script (Hung-Te Lin <hungte@chromium.org>)
8494502d: futility: updater: Support emulation in the output mode (Hung-Te Lin <hungte@chromium.org>)
54be900d: futility: updater: Handle flashrom read failure in load_system_firmware (Hung-Te Lin <hungte@chromium.org>)
2a787558: futility: updater: Drop `signature_id` from implementation (Hung-Te Lin <hungte@chromium.org>)
90f59170: futility: updater: Add a new config 'output_only' (Hung-Te Lin <hungte@chromium.org>)
94d884d8: futility: updater: Deprecate `--signature_id` by `--model` (Hung-Te Lin <hungte@chromium.org>)
24fd715c: host/lib/flashrom: Use flashrom provided in PATH (Jakub Czapiga <czapiga@google.com>)
ac49f1ca: Build thin archives (Arthur Heymans <arthur@aheymans.xyz>)
640fe19f: host/lib/crossystem: Make CROSSYSTEM_LOCK_PATH configurable (Jakub Czapiga <czapiga@google.com>)
86b42b6a: sign_android_image: calculate and store the vb meta digest (Luzanne Batoon <batoon@google.com>)
da1d153b: Move futility and cgpt to vendor partition (Jakub Czapiga <czapiga@google.com>)
80955816: futility: updater: Remove 'allow_empty_custom_label_tag' quirk (Hung-Te Lin <hungte@chromium.org>)
7ad2b0ab: futility: updater: Process custom label as standard models (Hung-Te Lin <hungte@chromium.org>)
13400d69: futility: updater: Remove signature_id from manifest (Hung-Te Lin <hungte@chromium.org>)
f770c7d0: futility: updater: Remove the legacy 'setvars.sh' manifest (Hung-Te Lin <hungte@chromium.org>)
ed4556ed: tests/futility: Add test cases for unmodified RO (DennisYeh <dennis.yeh@cienet.com>)
21902629: futility/file_type_bios.c: Skip keyblock checks if magic is invalid (Michał Kopeć <michal@nozomi.space>)
f5924321: Fix partition type check for miniOS B (Jae Hoon Kim <kimjae@chromium.org>)
83f845b3: signing: clean up owners (Benjamin Shai <bshai@google.com>)
dc5102f2: signing: miniOS signing in docker. (Benjamin Shai <bshai@google.com>)
16e6aa89: futility: updater: Provide default DUT properties for emulation (Yu-Ping Wu <yupingso@chromium.org>)
e56f3686: tests/futility/test_update: Fix --sys_props argument (Yu-Ping Wu <yupingso@chromium.org>)
7e2828a1: futility: updater: cleanup: Remove duplicated comments (Hung-Te Lin <hungte@chromium.org>)
060efa0c: vboot: Only execute TPM clear on nonchrome FW (Nehemiah Dureus <ndureus@chromium.org>)
2fc6815b: sign_official_build: Include full loem.ini path (Madeleine Hardt <hardtmad@google.com>)
47658f3c: 2lib/2load_kernel: Remove unused VB2_LOAD_PARTITION_WORKBUF_BYTES (Yu-Ping Wu <yupingso@chromium.org>)
7cc2ce4c: futility: Skip printing EC RW version if non-printable (Yu-Ping Wu <yupingso@chromium.org>)
8365d546: futility/load_fmap: Erase remaining bytes if file smaller than area (Yu-Ping Wu <yupingso@chromium.org>)
ec01126c: swap_ec_rw: Search for keyset in source tree too (Jack Rosenthal <jrosenth@chromium.org>)
b76d74dc: futility/load_fmap: use WARN() on non-critical error (Ting Shen <phoenixshen@google.com>)
f1f70f46: 2lib: Add gbb flag to enforce CSE sync (Dinesh Gehlot <digehlot@google.com>)
e4977a64: Deprecate GBB flag RUNNING_FAFT (Jeremy Bettis <jbettis@chromium.org>)
```

