```
3bf4f7add: Pin sharetest to sdk 35 (Matt Casey <mrcasey@google.com>)
18db980cd: Canvas unit tests. (Priyanka <priyankaspatel@google.com>)
d291b91c3: Use std::sync::LazyLock rather than once_cell. (Andrew Walbran <qwandor@google.com>)
87c252153: Explicitly address change in dark mode for rects. (Priyanka <priyankaspatel@google.com>)
d4d06f716: Draw only rect scene changes. (Priyanka <priyankaspatel@google.com>)
2a9710686: Extend Mapper3D and fix pan/click conflict in RectsComponent. (Priyanka <priyankaspatel@google.com>)
4becafe1f: Geometry and scene/camera class changes. (Priyanka <priyankaspatel@google.com>)
053620e3b: Suppress cfg(soong) warning. (James Farrell <jamesfarrell@google.com>)
fc7c3b5be: Extend ArrayUtils#equals to take optional predicate. (Priyanka <priyankaspatel@google.com>)
6bf8283da: Use LazyLock rather than lazy_static. (Andrew Walbran <qwandor@google.com>)
adf34ddbb: Sort trace config alphabetically. (Priyanka <priyankaspatel@google.com>)
7b52e374a: Make screen recording draggable from title if only one file uploaded. (Priyanka <priyankaspatel@google.com>)
5336df8d6: Right align integers in log views. (Priyanka <priyankaspatel@google.com>)
c8e8911fb: Log extra data about user snackbar messages. (Priyanka <priyankaspatel@google.com>)
ab7fdcfae: Enforce horizontal width restriction to media based component overlay. (Priyanka <priyankaspatel@google.com>)
43f251ba0: Recursively unzip archives. (Priyanka <priyankaspatel@google.com>)
503159461: VDM demo for android:turnScreenOn and android:showWhenLocked (Vladimir Komsiyski <vladokom@google.com>)
9fd28a108: Notify snackbar warnings in batches properly. (Priyanka <priyankaspatel@google.com>)
164ee5e72: Update perfetto protolog parser test. (Priyanka <priyankaspatel@google.com>)
3b1c71eab: Make trace collection box bigger. (Priyanka <priyankaspatel@google.com>)
fe1245cac: Download proxy as actual file. (Priyanka <priyankaspatel@google.com>)
08bf4a16f: VdmClient: Attempt reconnect on network lost (Marvin Ramin <marvinramin@google.com>)
25237636a: Add junitparams to the list of packages (Vadim Caen <caen@google.com>)
e5ebfd09b: Change time duration format for transition duration column. (Priyanka <priyankaspatel@google.com>)
3ff8cd02c: Make the overlays display in full width on phones (Jordan Demeulenaere <jdemeulenaere@google.com>)
f34a6a16c: Add NotificationShade and QuickSettingsShade to the STL demo (Jordan Demeulenaere <jdemeulenaere@google.com>)
67570dd88: Run ktfmt on samples/SceneTransitionLayout/ (Jordan Demeulenaere <jdemeulenaere@google.com>)
ef57f10c0: Stop building versioner. (Dan Albert <danalbert@google.com>)
9860e47d5: Remove getters in DraggableCanvasObjectImpl. (Priyanka <priyankaspatel@google.com>)
61fd35f29: Run ktfmt 0.52 on SceneTransitionLayoutDemo (omarmt <omarmt@google.com>)
838f803da: Filter __attribute__((availability)) (Hsin-Yi Chen <hsinyichen@google.com>)
18e1463fd: Catch missing flags on older SDKs (Marvin Ramin <marvinramin@google.com>)
c3dd0bcd6: Update e2e tests after colour scheme and timeline input changes. (Priyanka <priyankaspatel@google.com>)
fb4604a5d: Fix parsing of cargo.out when rustc has an absolute path. (Andrew Walbran <qwandor@google.com>)
cce18198d: Handle another license combination. (Andrew Walbran <qwandor@google.com>)
684150f48: update proxy version. (Priyanka <priyankaspatel@google.com>)
4fbd817b8: StatusBar and insets in VDM Demo app (Vladimir Komsiyski <vladokom@google.com>)
fd36fb64d: Format timestamps without date unless multiple dates present in trace. (Priyanka <priyankaspatel@google.com>)
9e02ef9d4: Replace whole relZChildren node when adding to it. (Priyanka <priyankaspatel@google.com>)
291c21de5: Show display id on hover in display selector. (Priyanka <priyankaspatel@google.com>)
a40f4aefb: Crop entered timestamp to within timeline range. (Priyanka <priyankaspatel@google.com>)
c2e880f2c: Retrieve scss variables for active/hover timelines. (Priyanka <priyankaspatel@google.com>)
93dc59ad8: Adjust colours for warning/error uploads. (Priyanka <priyankaspatel@google.com>)
808cd3031: Reduce colours in property values and make them bold. (Priyanka <priyankaspatel@google.com>)
9f4d8a561: Colour changes to chips. (Priyanka <priyankaspatel@google.com>)
684828d9c: Soften diff backgrounds. (Priyanka <priyankaspatel@google.com>)
a993c9fd1: Update VdmHost permission behavior (Marvin Ramin <marvinramin@google.com>)
3f7eaa6a3: Preserve *.mk files when regenerating crates. (James Farrell <jamesfarrell@google.com>)
a90cea19b: Remove most logic from CrateCollection. (James Farrell <jamesfarrell@google.com>)
f12d35123: Remove obsolete code related to "migratability". (James Farrell <jamesfarrell@google.com>)
4c916ea32: Fix all clippy lints. (James Farrell <jamesfarrell@google.com>)
d9af52f69: Add Android.bp files for name_and_version and name_and_version_map. (James Farrell <jamesfarrell@google.com>)
3fb1863e8: Preserve Cargo.lock when running cargo_embargo. (James Farrell <jamesfarrell@google.com>)
b916d472d: Add more cleanups for METADATA files. (James Farrell <jamesfarrell@google.com>)
265fe4a64: Unify hover/selected background states. (Priyanka <priyankaspatel@google.com>)
27ee28efc: Update trace type colours. (Priyanka <priyankaspatel@google.com>)
1ba0c98cc: Add the new secure window callback to VDM host (Vladimir Komsiyski <vladokom@google.com>)
ce8027199: [MTE] teach stack to handle MTE stack reports (Florian Mayer <fmayer@google.com>)
506716916: cargo_embargo: Parse out raw_name from src_path (Per Larsen <perlarsen@google.com>)
4c60be835: Add Android.bps for google_metadata and rooted_path. (James Farrell <jamesfarrell@google.com>)
fe9dc16df: Fix compile error. (James Farrell <jamesfarrell@google.com>)
c563ea9e1: Generate a list of crates separate from Cargo.toml. (James Farrell <jamesfarrell@google.com>)
65c72c6ef: Use is_ascii_whitespace. (Andrew Walbran <qwandor@google.com>)
0e5c42340: Support workspace_excludes in metadata-only mode. (Andrew Walbran <qwandor@google.com>)
10fbf1237: Ignore `--check-cfg`. (Andrew Walbran <qwandor@google.com>)
c78f00c82: Prevent wheel event from shifting expanded timeline viewport. (Priyanka <priyankaspatel@google.com>)
bc608b834: Presenter tests. (Priyanka <priyankaspatel@google.com>)
85a66286b: cargo_embargo: use FIND_CRATE to locate Trusty modules (Per Larsen <perlarsen@google.com>)
7be189f8c: Presenter/Mediator changes to save presets. (Priyanka <priyankaspatel@google.com>)
871acee98: Changes to TraceViewComponent for filter presets. (Priyanka <priyankaspatel@google.com>)
40d142ada: Introduce callback to convert rect id to showstate key in rect filter. (Priyanka <priyankaspatel@google.com>)
dd8e95f30: cargo_embargo: add BSD-2-Clause OR Apache-2 OR MIT (Per Larsen <perlarsen@google.com>)
4cd89a12a: Shift filter flags handling into presenters. (Priyanka <priyankaspatel@google.com>)
89e7ade0f: License file and METADATA checker/fixer. (James Farrell <jamesfarrell@google.com>)
f7cb61bf3: Move GoogleMetadata to a separate crate. (James Farrell <jamesfarrell@google.com>)
98f508d5d: Crop media based file name correctly. (Priyanka <priyankaspatel@google.com>)
8744f8f5e: Add search flag options to protolog search. (Priyanka <priyankaspatel@google.com>)
08989cbd4: Add search flag options to hierarchy/properties. (Priyanka <priyankaspatel@google.com>)
befa10246: Filter flags and search box component. (Priyanka <priyankaspatel@google.com>)
e22681cd1: Refactor to use name_and_version crate. (James Farrell <jamesfarrell@google.com>)
ddaff9735: Refactor name-and-version data structures into a separate crate. (James Farrell <jamesfarrell@google.com>)
ee52dd964: Unify store interfaces. (Priyanka <priyankaspatel@google.com>)
967c42662: Dump __attribute__((availability)) (Hsin-Yi Chen <hsinyichen@google.com>)
948daab28: Update e2e test after zordering fixes. (Priyanka <priyankaspatel@google.com>)
def9526b0: VDM Display Power Demo (Vladimir Komsiyski <vladokom@google.com>)
eb65e9d87: Make java_sdk_library dependencies explicit (Jihoon Kang <jihoonkang@google.com>)
8c9b907f9: cargo_embargo: add BSD-3-Clause OR MIT OR Apache-2 (Neill Kapron <nkapron@google.com>)
9e478a88e: [STLDemo] Add PredictiveBack key to bouncer-to-lockscreen transition (Johannes Gallmann <gallmann@google.com>)
cc1915f08: Load and navigate multiple screen recordings. (Priyanka <priyankaspatel@google.com>)
e153510ec: Collect multiple screen recordings simultaneously. (Priyanka <priyankaspatel@google.com>)
329d419e8: Provide rel z children in SF curated properties. (Priyanka <priyankaspatel@google.com>)
ac02541b8: Fix error in use of RootedPath. (James Farrell <jamesfarrell@google.com>)
b677d81c5: Only check changed crates in preupload. (James Farrell <jamesfarrell@google.com>)
c33feb170: When staging, check that patches apply successfully, and cargo_embargo s... (James Farrell <jamesfarrell@google.com>)
6fd936579: Extend SF computation tests. (Priyanka <priyankaspatel@google.com>)
2d2364aaa: Unify tree traversal between rects computation and visibility computatio... (Priyanka <priyankaspatel@google.com>)
80defde8c: Traverse tree accounting for computed z order path in visibility computa... (Priyanka <priyankaspatel@google.com>)
7cb4ac9c8: Refactor code to use RootedPath. (James Farrell <jamesfarrell@google.com>)
372285a2d: Refactor RepoPath into RootedPath crate. (James Farrell <jamesfarrell@google.com>)
21bcec1ee: Add support for importing new crates. (James Farrell <jamesfarrell@google.com>)
750d3b995: Make RepoPath absolute-first. (James Farrell <jamesfarrell@google.com>)
86d32ccda: Component tests for multidisplay changes. (Priyanka <priyankaspatel@google.com>)
fab7ec10a: Don't require --unpinned. (James Farrell <jamesfarrell@google.com>)
56b5e6656: Rename (Observable)Transition.ChangeCurrentScene to ChangeScene (2/2) (Jordan Demeulenaere <jdemeulenaere@google.com>)
ad195a113: Viewer - visualise screen recording/screenshots for multi-display device... (Priyanka <priyankaspatel@google.com>)
3b7863f2f: Reorganise and rename screen recording and screenshot related files/clas... (Priyanka <priyankaspatel@google.com>)
205a4d6f1: Trace config - collect screen recording/screenshot for multi-display dev... (Priyanka <priyankaspatel@google.com>)
ac37d6fd6: Proxy - collect screen recording/screenshot for multi-display device. (Priyanka <priyankaspatel@google.com>)
8375f0e0a: Allow checking migration health of multiple crates. (James Farrell <jamesfarrell@google.com>)
1028279a6: Check that the deps in Cargo.toml match the managed crate directories. (James Farrell <jamesfarrell@google.com>)
1ea17f1e2: Don't check in Cargo.lock. (James Farrell <jamesfarrell@google.com>)
433874c76: Allow migrating with versions unpinned. (James Farrell <jamesfarrell@google.com>)
140a1df86: Set the missing sensor properties in VDM Demo (Vladimir Komsiyski <vladokom@google.com>)
a529de66a: License classifier crate (James Farrell <jamesfarrell@google.com>)
b6e8c241e: Adjust indices after filtering entries. (Priyanka <priyankaspatel@google.com>)
9fbbc35b9: Migrate ARCHIVE identifiers to Archive (Matthew Maurer <mmaurer@google.com>)
d7c4bddf9: Migrate HOMEPAGE entries from identifier to third_party (Matthew Maurer <mmaurer@google.com>)
1df291933: STL: Default overscroll ProgressConverter slowly approaches 0.2f [2/2] (omarmt <omarmt@google.com>)
2ddac543a: Stabilise e2e tests. (Priyanka <priyankaspatel@google.com>)
bb4a85462: Remove redundant permission check from VDM Host (Vladimir Komsiyski <vladokom@google.com>)
e08040263: Introduce overlays in SceneTransitionLayout (2/2) (Jordan Demeulenaere <jdemeulenaere@google.com>)
039da6658: Move ContentState.Transition back into TransitionState.Transition (2/2) (Jordan Demeulenaere <jdemeulenaere@google.com>)
7255e3db6: Add more license expressions (James Farrell <jamesfarrell@google.com>)
15b460f74: Load gzipped archives. (Priyanka <priyankaspatel@google.com>)
dbebba4fe: STL: Add defaultOverscrollProgressConverter in SceneTransitions [2/2] (omarmt <omarmt@google.com>)
c1b116aa2: STL: Add ProgressConverter class [2/2] (omarmt <omarmt@google.com>)
27e00f52f: STL Demo: Add EdgeWithPreview in interactive Notifications (omarmt <omarmt@google.com>)
8119ed7a3: Additional tests for tree component and tree node component. (Priyanka <priyankaspatel@google.com>)
445f70588: Copy button for properties tree. (Priyanka <priyankaspatel@google.com>)
44fc18a7d: Show touchable region properly in curated properties. (Priyanka <priyankaspatel@google.com>)
198d64edb: Update VDM Demo with activity control API changes (Vladimir Komsiyski <vladokom@google.com>)
5b40e9b1d: ADB package: Allow push without compression (Fabien Sanglard <sanglardf@google.com>)
54b55f108: Use uinput touchscreen to inject monkey touch events (Siarhei Vishniakou <svv@google.com>)
dcb4f91ea: Clear curated properties if highlighted node not found. (Priyanka <priyankaspatel@google.com>)
6470eac75: Increase coverage on transition timeline tests. (Priyanka <priyankaspatel@google.com>)
a30b2206e: Render transitions with unknown start/end as minimum width entry. (Priyanka <priyankaspatel@google.com>)
399cc1311: Add current index to CUJs and Transitions ui data. (Priyanka <priyankaspatel@google.com>)
dbb3dd3a0: Add two-stage predictive back animation to Bouncer in demo app (Johannes Gallmann <gallmann@google.com>)
13fd67148: Add UserNotifier spies for test suites that call classes with notifier. (Priyanka <priyankaspatel@google.com>)
2858cbb46: Parse transitions trace with partially corrupted transitions. (Priyanka <priyankaspatel@google.com>)
759bac11d: Notify user of some console warnings. (Priyanka <priyankaspatel@google.com>)
3de3c2b4a: Do not reduce opacity for hierarchies without rects. (Priyanka <priyankaspatel@google.com>)
91e0810b1: Fix bug. (James Farrell <jamesfarrell@google.com>)
9a6a4a182: Handle change from zero to 1+ displays found in rects component. (Priyanka <priyankaspatel@google.com>)
9d7d7ebd0: Script to run the latest prebuilt version of cargo. (James Farrell <jamesfarrell@google.com>)
5d8fcf902: ManagedRepo struct. (James Farrell <jamesfarrell@google.com>)
9dd868524: Show timestamp in navigator if only one available. (Priyanka <priyankaspatel@google.com>)
496ee6ab0: Orange border for pinned rects. (Priyanka <priyankaspatel@google.com>)
cea07d034: Use "cargo tree" to determine deps. (James Farrell <jamesfarrell@google.com>)
2447fd0f4: Add Apache or BSD clause to the map. (Elie Kheirallah <khei@google.com>)
2422023ae: Ignore ownership changes. (James Farrell <jamesfarrell@google.com>)
9874e56ba: Ensure the staging dir exists. (James Farrell <jamesfarrell@google.com>)
186334840: Add function to run cargo_embargo autoconfig. (James Farrell <jamesfarrell@google.com>)
5a03c6f24: Add license fields to crate type. (James Farrell <jamesfarrell@google.com>)
369539f94: RunQuiet helper trait (James Farrell <jamesfarrell@google.com>)
1c50d7bb6: Inform user of proxy version properly. (Priyanka <priyankaspatel@google.com>)
ac8b7045a: Update proxy major version. (Priyanka <priyankaspatel@google.com>)
26c9c6aa1: Notify user if requested traces not collected. (Priyanka <priyankaspatel@google.com>)
4a5083b7c: remerge3: Redo 3-way merge for files with conflict markers (Yi-Yo Chiang <yochiang@google.com>)
e8693b5d7: Set the year field. (James Farrell <jamesfarrell@google.com>)
5cdc45db1: Remove OUT_DIR from environment (James Farrell <jamesfarrell@google.com>)
6f4b67c14: Allow parsing of SF entry despite missing layer ids. (Priyanka <priyankaspatel@google.com>)
2513b04af: Unify makeHierarchyTreeMethods in SF parsers. (Priyanka <priyankaspatel@google.com>)
746a537fa: Add download progress bar. (Priyanka <priyankaspatel@google.com>)
c5702ab31: Gzip collected traces in proxy. (Priyanka <priyankaspatel@google.com>)
1ff347b7f: Disable ripple in STL benchmarks (Jordan Demeulenaere <jdemeulenaere@google.com>)
41f7235ee: Add extra to disable ripple in STL demo (Jordan Demeulenaere <jdemeulenaere@google.com>)
bdad38b3b: Improve formatting in monkey code (Siarhei Vishniakou <svv@google.com>)
e409da31a: Update METADATA file. (James Farrell <jamesfarrell@google.com>)
d49d95bf4: Add checks for bpfmt and clang-format (Siarhei Vishniakou <svv@google.com>)
f20fedf72: Improve proxy connection tests. (Priyanka <priyankaspatel@google.com>)
3aafa04d2: Move dump files to backup dir before fetching. (Priyanka <priyankaspatel@google.com>)
623b22929: Start only required threads and try fetch only files associated with tho... (Priyanka <priyankaspatel@google.com>)
82057b2b9: Position camera in front of first rect. (Priyanka <priyankaspatel@google.com>)
a02b16042: Draw multiple selected displays separately. (Priyanka <priyankaspatel@google.com>)
7bf83b6b1: Use wm focused display id to choose SF active display. (Priyanka <priyankaspatel@google.com>)
e93d7e499: Allow multiple displays selection. (Priyanka <priyankaspatel@google.com>)
0af1020b4: Default display selection to active display. (Priyanka <priyankaspatel@google.com>)
88ed5a0e7: Keep removed constituent from traces parsers for download. (Priyanka <priyankaspatel@google.com>)
f4c632fb2: Add tooltips to occluded/covered by. (Priyanka <priyankaspatel@google.com>)
70b468fca: Change default SF tracing flags (Kean Mariotti <keanmariotti@google.com>)
19e0dcb7a: add3prf.py: Support lowercased license (Li-Yu Yu <aaronyu@google.com>)
d9848555d: adb proxy: support perfetto WM data source (Kean Mariotti <keanmariotti@google.com>)
0715cdfc3: Ensure that Rust crates still conform for Android test ownership. (Stephen Hines <srhines@google.com>)
8555912df: Ensure perfetto trace config file fully updated before starting perfetto... (Priyanka <priyankaspatel@google.com>)
fbb9818aa: Remove old HTML report code. (James Farrell <jamesfarrell@google.com>)
d821fbf05: Migrate multiple crates at once. (James Farrell <jamesfarrell@google.com>)
a6762c789: Use prebuilt bpfmt. (James Farrell <jamesfarrell@google.com>)
d1c84b44b: Remove old TEST_MAPPING when migrating. (James Farrell <jamesfarrell@google.com>)
0cf940607: Update python version listed in proxy and component. (Priyanka <priyankaspatel@google.com>)
fdf97f135: Extract common geometry types from types2d/types3d. (Priyanka <priyankaspatel@google.com>)
525db9c50: Revert "Create config.json in each llndk abi-dump." (Hsin-Yi Chen <hsinyichen@google.com>)
4b32d5de9: Make sure we query the location row (Pablo Gamito <pablogamito@google.com>)
eb0e58902: Do not literally compare referenced_type of class fields (Hsin-Yi Chen <hsinyichen@google.com>)
86e9be148: Correctly report USB connection loss and tracing timeout. (Priyanka <priyankaspatel@google.com>)
5392516d5: Report screen recording failures to user. (Priyanka <priyankaspatel@google.com>)
7b83e333b: Improve handling of taking dumps. (Priyanka <priyankaspatel@google.com>)
09e10f7f8: Improve handling of corrupted/empty traces. (Priyanka <priyankaspatel@google.com>)
241b2a069: Preupload check for managed crates. (James Farrell <jamesfarrell@google.com>)
0a97a667b: Clean up old VDM display flags (Vladimir Komsiyski <vladokom@google.com>)
100063e62: Grey out hierarchy elements with non rendered rects. (Priyanka <priyankaspatel@google.com>)
123daf418: Display categories and restricted activities VDM Demo. (Vladimir Komsiyski <vladokom@google.com>)
0e79f471a: Generate license section based on metadata. (Andrew Walbran <qwandor@google.com>)
a85acf8ef: Show location for processed protolog message (Pablo Gamito <pablogamito@google.com>)
e59bce5e6: Introduce GeometryFactory. (Priyanka <priyankaspatel@google.com>)
38f81e739: Add a dialog prompting the user to unlock keyguard (Vladimir Komsiyski <vladokom@google.com>)
3f3ba0775: VDM activity policy demo (Vladimir Komsiyski <vladokom@google.com>)
d1ba7ff3c: Winscope: ViewerInput: Differentiate currentEntry and selectedEntry (Prabir Pradhan <prabirmsp@google.com>)
32378e7a7: Winscope: Reorganize geometry types into a new /src/common/geometry dir (Prabir Pradhan <prabirmsp@google.com>)
d6fe94a26: Winscope: s/TransformUtils/TransformType (Prabir Pradhan <prabirmsp@google.com>)
907c0ef6e: Winscope: ViewerInput: Fill input window rect with its touchable region (Prabir Pradhan <prabirmsp@google.com>)
fcee85f2c: Do not deselect trace from store if it is active. (Priyanka <priyankaspatel@google.com>)
7dd3722eb: Remove constituents of TracesParser correctly. (Priyanka <priyankaspatel@google.com>)
a77f920cb: Ignore stderr from cargo metadata. (Andrew Walbran <qwandor@google.com>)
1650c251a: Add an option to exclude compoent (sefl) from the Chooser app list (Andrey Yepin <ayepin@google.com>)
4b3e82133: Remove *.bp and cargo_embargo.json when migrating. (James Farrell <jamesfarrell@google.com>)
d19c02c98: Handle displays for foldables. (Priyanka <priyankaspatel@google.com>)
b7558cf26: If no valid files loaded, do not load viewers. (Priyanka <priyankaspatel@google.com>)
5791e5e44: Run traces separately in proxy. (Priyanka <priyankaspatel@google.com>)
6ffda7a95: Cleanup in proxy. (Priyanka <priyankaspatel@google.com>)
90a3c16ec: Fix bugs with trace config propagation. (Priyanka <priyankaspatel@google.com>)
90cecbbb7: Unfocus mat select on selection of same option. (Priyanka <priyankaspatel@google.com>)
45bd8261a: Handle internal errors re Wayland availability. (Priyanka <priyankaspatel@google.com>)
05f91776c: Introduce StaticElementContentPicker (2/2) (Jordan Demeulenaere <jdemeulenaere@google.com>)
29c20cb1e: Rename ElementScenePicker to ElementContentPicker (2/2) (Jordan Demeulenaere <jdemeulenaere@google.com>)
473e208e4: Move TransitionState into its own file (2/2) (Jordan Demeulenaere <jdemeulenaere@google.com>)
43856e327: Fix input parser descriptors. (Priyanka <priyankaspatel@google.com>)
fad4faad0: Remove tracing config singleton and improve change detection. (Priyanka <priyankaspatel@google.com>)
3ef54c804: Empty implementation of pre-upload check. (James Farrell <jamesfarrell@google.com>)
ba1cbf4a5: Add migrate and regenerate commands. (James Farrell <jamesfarrell@google.com>)
31471c48b: migration_health improvements (James Farrell <jamesfarrell@google.com>)
a5715a145: Create config.json in each llndk abi-dump. (Justin Yun <justinyun@google.com>)
2119a63b8: Update time crate (James Farrell <jamesfarrell@google.com>)
f17caa254: Log user notifications from anywhere. (Priyanka <priyankaspatel@google.com>)
27a184aa5: Translate intdef for requestedVisibleTypes in WindowState. (Priyanka <priyankaspatel@google.com>)
720057376: Use window setInterval and clearInterval. (Priyanka <priyankaspatel@google.com>)
ae4ef88d4: [DO NOT MERGE] Use window setInterval and clearInterval. (Priyanka <priyankaspatel@google.com>)
7d2f69c03: Fix build (Priyanka <priyankaspatel@google.com>)
2d401bb14: Properly type workers. (Priyanka <priyankaspatel@google.com>)
00dd9f441: Winscope: Update TransformMatrix labels to to match platform code (Prabir Pradhan <prabirmsp@google.com>)
cb0f4b819: Use CujType from intdef mapping. (Priyanka <priyankaspatel@google.com>)
56775d803: Miscellaneous improvements to migration health cmd. (James Farrell <jamesfarrell@google.com>)
fde1183be: Revert "Handle input traces without vsync ids." (Prabir Pradhan <prabirmsp@google.com>)
3835f3d89: Address gaps between rects and new label overlap issues. (Priyanka <priyankaspatel@google.com>)
707b742f2: Handle tab overflow. (Priyanka <priyankaspatel@google.com>)
f651ea900: Fix build on branches != main (Priyanka <priyankaspatel@google.com>)
146c6d2f6: Add new CUJ tags (Pablo Gamito <pablogamito@google.com>)
e9fab7bdd: Winscope: Ensure input parsers robust to missing vsync ids (Prabir Pradhan <prabirmsp@google.com>)
d3652a2a8: Do not crash UI if frame mapping fails. (Priyanka <priyankaspatel@google.com>)
e3e8e5550: Only store security token if not empty. (Priyanka <priyankaspatel@google.com>)
6410b2482: Use the input events' down/event times (Vladimir Komsiyski <vladokom@google.com>)
5e158a771: Handle input traces without vsync ids. (Priyanka <priyankaspatel@google.com>)
b4e9bdd79: Collect metrics for proxy. (Priyanka <priyankaspatel@google.com>)
26f9a1253: Cleanup HttpRequest and ProxyConnection. (Priyanka <priyankaspatel@google.com>)
d151119b7: Bump revision to 35.0.2 for adb/fastboot (Fabien Sanglard <sanglardf@google.com>)
cbb865ce1: Apply configs on proxy side. (Priyanka <priyankaspatel@google.com>)
76b0e0642: ProxyConnection tests. (Priyanka <priyankaspatel@google.com>)
682ae75d2: CollectTracesComponent and AdbProxyComponent tests. (Priyanka <priyankaspatel@google.com>)
a2df975b7: Refactor TS-side interfaces. (Priyanka <priyankaspatel@google.com>)
9c2d720c5: New TS-side interfaces for adb/proxy connection. (Priyanka <priyankaspatel@google.com>)
aff8de012: Winscope: Make LogPresenter generic on LogEntry (Prabir Pradhan <prabirmsp@google.com>)
b15bc2a72: ViewerInput: Show rects with input windows when SF trace available (Prabir Pradhan <prabirmsp@google.com>)
a719c950f: Add overscrollDisabled DSL in SceneTransitionsBuilder [2/2] (omarmt <omarmt@google.com>)
9ede96023: Invalid bounds from display can be rotated. (Priyanka <priyankaspatel@google.com>)
eaf04bb98: Remove "isVirtual" rect property. (Priyanka <priyankaspatel@google.com>)
249ab5c48: Fix parsing of critical WM trace. (Priyanka <priyankaspatel@google.com>)
2f0a09822: Make AbstractHierarchyViewerPresenter generic on UiDataHierarchy. (Priyanka <priyankaspatel@google.com>)
9c6bc9002: Winscope: RectsPresenter: s/ignoreNonHidden/ignoreRectShowState (Prabir Pradhan <prabirmsp@google.com>)
1c0456245: Winscope: ViewerInput: Format dispatched pointers for readability (Prabir Pradhan <prabirmsp@google.com>)
8eda74cc6: Winscope: FrameMapper: Apply mapping to INPUT_EVENT_MERGED trace (Prabir Pradhan <prabirmsp@google.com>)
d2a08d05e: Update to clang-r530567 (Yabin Cui <yabinc@google.com>)
0434755c6: Iterate on motion test viewer (Mike Schneider <michschn@google.com>)
47e9c2395: Winscope: ViewerInput: Use operation for formatting window name (Prabir Pradhan <prabirmsp@google.com>)
9fdcd3691: Winscope: AbstractLogViewerPresenter: Make uiData readonly (Prabir Pradhan <prabirmsp@google.com>)
d94fcdf3e: cargo_embargo: Add host_cross_supported property (Ivan Lozano <ivanlozano@google.com>)
da00a82fb: Remove unnecessary nestedScrollToScene modifiers (omarmt <omarmt@google.com>)
a6b47638b: Report added symbols (Hsin-Yi Chen <hsinyichen@google.com>)
5532bf8f6: Winscope: Make AbstractLogViewerPresenter generic on UiData (Prabir Pradhan <prabirmsp@google.com>)
22865ce0b: Polishing for fetch traces button. (Priyanka <priyankaspatel@google.com>)
83bf481e3: Update isLockscreenDismissed when swiping in STL demo (Jordan Demeulenaere <jdemeulenaere@google.com>)
88e887b50: Restrict expanded timeline/filter select max height. (Priyanka <priyankaspatel@google.com>)
7a3434eb2: Fix duplication of pinned layers. (Priyanka <priyankaspatel@google.com>)
f1bd7f294: Show chip for hidden by policy layers. (Priyanka <priyankaspatel@google.com>)
0e267c225: Add invisibility reason for occluded layers. (Priyanka <priyankaspatel@google.com>)
c313ec4a4: Use display size if layerStackSpaceRect unavailable. (Priyanka <priyankaspatel@google.com>)
0e55a9a53: Do not compose infinite media player transition if it is not used (Jordan Demeulenaere <jdemeulenaere@google.com>)
efb0db080: Winscope: ViewerInput: Allow filtering events by target windows (Prabir Pradhan <prabirmsp@google.com>)
920d286a2: Make stub scenes depend on RTL layout in STL demo (Jordan Demeulenaere <jdemeulenaere@google.com>)
b6a0fbeec: Construct ModuleIR without arguments (Hsin-Yi Chen <hsinyichen@google.com>)
0080325f9: Decouple IRReader from the constructor of ModuleIR (Hsin-Yi Chen <hsinyichen@google.com>)
36664e584: Winscope: Use factory method pattern to create new UiData objects (Prabir Pradhan <prabirmsp@google.com>)
efed030e3: Winscope: PresenterInputTest: override expectedIndexOfFirstPositionUpdat... (Prabir Pradhan <prabirmsp@google.com>)
7a2c8d455: Only stream device aware permissions in VDM demo app (Yuting <yutingfang@google.com>)
29a09286e: Introduce ViewerInput as a Winscope Tab (Prabir Pradhan <prabirmsp@google.com>)
a6de60d11: Define invalid bounds as in SurfaceFlinger.cpp (Priyanka <priyankaspatel@google.com>)
620c1555b: Increase threshold for bounds being equal. (Priyanka <priyankaspatel@google.com>)
ffabcad61: Replace hoisted STLState by MutableSTLState in STL demo (Jordan Demeulenaere <jdemeulenaere@google.com>)
69e781e7c: Remove SysUI license in SceneTransitionLayoutDemo app (Jordan Demeulenaere <jdemeulenaere@google.com>)
38916491c: Draw SF rects that are not visible and have valid screen bounds. (Priyanka <priyankaspatel@google.com>)
7bed11f2a: Make proper invalid timestamps for transitions without dispatch time. (Priyanka <priyankaspatel@google.com>)
201f51ef1: Do not binary search to update transition log index. (Priyanka <priyankaspatel@google.com>)
1f204ece6: Fix color/alpha and transform formatting. (Priyanka <priyankaspatel@google.com>)
a98b03db0: Winscope: Allow underscores in device ids (Pierre Barbier de Reuille <pbdr@google.com>)
e70b5facf: Reset zoom button resets to initial auto-zoom (crops start to beginning ... (Priyanka <priyankaspatel@google.com>)
3084b8f4a: Move the SceneTransitionLayout demo to development/samples/ (1/3) (Jordan Demeulenaere <jdemeulenaere@google.com>)
43e299ce5: Warn user about IME frame mapping grouping. (Priyanka <priyankaspatel@google.com>)
679878be5: Demo for virtual display rotation (Vladimir Komsiyski <vladokom@google.com>)
2d3a27a13: Update E2E test to show Window Manager Dump. (Priyanka <priyankaspatel@google.com>)
98db3767b: Winscope: Support trace collection from android.input.inputevent (Prabir Pradhan <prabirmsp@google.com>)
656beea84: Winscope: Use int-based enums to differentiate log field types (Prabir Pradhan <prabirmsp@google.com>)
818215705: Rename proxy states. (Priyanka <priyankaspatel@google.com>)
22a12b58b: Properly lose focus on interactive elements. (Priyanka <priyankaspatel@google.com>)
00972160f: Don't center align icon columns in log view. (Priyanka <priyankaspatel@google.com>)
2ac0771fb: Reducing imports of INVALID_TIME_NS everywhere. (Priyanka <priyankaspatel@google.com>)
e9ce7c00e: Trace visibility improvements. (Priyanka <priyankaspatel@google.com>)
34a8998b1: add perfetto WindowManager parser (Kean Mariotti <keanmariotti@google.com>)
cf8848c71: prepare for WindowManager perfetto parser (3) (Kean Mariotti <keanmariotti@google.com>)
593dc66ff: prepare for WindowManager perfetto parser (2) (Kean Mariotti <keanmariotti@google.com>)
268e8e790: prepare for WindowManager perfetto parser (1) (Kean Mariotti <keanmariotti@google.com>)
407898085: Check connection before setting state "END_TRACE". (Priyanka <priyankaspatel@google.com>)
955561c96: Allow user select in buttons. (Priyanka <priyankaspatel@google.com>)
81452988b: Winscope: Reformat LogComponent template (Prabir Pradhan <prabirmsp@google.com>)
7365fc020: Winscope: Increase lightness of the input trace color (Prabir Pradhan <prabirmsp@google.com>)
400a240fd: TracesParserInput: Use triple-equals (Prabir Pradhan <prabirmsp@google.com>)
5acdc0b60: Fix update_crate_tests.py by removing bp2build (Ivan Lozano <ivanlozano@google.com>)
0fb24e2f1: Add jank CUJ tag viewer (Pablo Gamito <pablogamito@google.com>)
9a9e7170d: Disallow relative imports in eslint. (Priyanka <priyankaspatel@google.com>)
a2d9344dd: More proxy bug fixes. (Priyanka <priyankaspatel@google.com>)
9e24d36a1: Fix bug with updating file buffers and clearing last session. (Priyanka <priyankaspatel@google.com>)
c5c6038c6: Support VSYNCID custom query for the merged input trace (Prabir Pradhan <prabirmsp@google.com>)
8ffdd0bf8: Introduce TracesParserInput to merge key and motion event traces (Prabir Pradhan <prabirmsp@google.com>)
723a6a906: fix formatting (Kean Mariotti <keanmariotti@google.com>)
6da10439e: Update tests (Pablo Gamito <pablogamito@google.com>)
93392cf25: Update tests (Pablo Gamito <pablogamito@google.com>)
3f99f98b7: Increase testing via DOM. (Priyanka <priyankaspatel@google.com>)
2c628b0a2: Fix CUJ parser bug (Pablo Gamito <pablogamito@google.com>)
7710e0bd0: Remove CUJ trace upload info (Pablo Gamito <pablogamito@google.com>)
32dff5241: Rename CUJ type property (Pablo Gamito <pablogamito@google.com>)
04ff9773a: Get rid of CujTimestamp type (Pablo Gamito <pablogamito@google.com>)
4bca5b2c5: Fix flaky Winscope tests. (Priyanka <priyankaspatel@google.com>)
30dfd213d: TracesParser: reorganize directory (Kean Mariotti <keanmariotti@google.com>)
9023eaab8: Remove nested log view. (Priyanka <priyankaspatel@google.com>)
8aae6746d: TracesParser: refactoring to support perfetto traces (Kean Mariotti <keanmariotti@google.com>)
0b0ebade1: cargo_embargo: fix generation of rules.mk (Per Larsen <perlarsen@google.com>)
1fb748e45: Support frame association for input traces (Prabir Pradhan <prabirmsp@google.com>)
0884dd9a9: Remove hashed subdir for the compare tool (Justin Yun <justinyun@google.com>)
ea100757b: Only send a single accelerometer from the VDM client. (Vladimir Komsiyski <vladokom@google.com>)
74fc96ac3: Update bpflatten for blueprint changes (Cole Faust <colefaust@google.com>)
70ae7d137: Update bpflatten for blueprint changes (Cole Faust <colefaust@google.com>)
a9c560dc3: SampleSyncAdapter minsdk bump from 8 to 21 (Anvesh Renikindi <renikindi@google.com>)
7fc3d7126: Do not delete files from device prematurely. (Priyanka <priyankaspatel@google.com>)
2ec062986: Do not crash Winscope when loading viewers fails. (Priyanka <priyankaspatel@google.com>)
f26669e71: Update bpflatten for blueprint changes (Cole Faust <colefaust@google.com>)
b2b4f4429: Initial renaming and cleanup related to proxy connection. (Priyanka <priyankaspatel@google.com>)
b54a439e7: Add download all option for uploaded/collected traces before visualisati... (Priyanka <priyankaspatel@google.com>)
435465451: Improve error messages. (Priyanka <priyankaspatel@google.com>)
1101e4254: Virtual rotary encoder demo (Vladimir Komsiyski <vladokom@google.com>)
3b2fc8b3e: Remove VirtualCameraDemo (Vadim Caen <caen@google.com>)
be64650cb: Click on mini timeline sets active trace before finding closest timestam... (Priyanka <priyankaspatel@google.com>)
aee8a7c65: Changes to improve parsing/navigation of Winscope S traces. (Priyanka <priyankaspatel@google.com>)
36e67cdc3: Address rect label overlap. (Priyanka <priyankaspatel@google.com>)
d93b6f291: Split zoom analytics into scroll and key. Add analytics for bookmarking. (Priyanka <priyankaspatel@google.com>)
cbb0f4a85: Update e2e tests after presenter refactor. (Priyanka <priyankaspatel@google.com>)
70a45c43f: Remove IRToProtobufConverter (Hsin-Yi Chen <hsinyichen@google.com>)
d3aa67e3f: Remove IRDiffToProtobufConverter (Hsin-Yi Chen <hsinyichen@google.com>)
a799fb208: Remove IRToJsonConverter (Hsin-Yi Chen <hsinyichen@google.com>)
15ad5d8fd: Winscope: Update golden trace for input parser tests (Prabir Pradhan <prabirmsp@google.com>)
c565d223c: Dedupe presenter tests. (Priyanka <priyankaspatel@google.com>)
023e3f1d8: Dedupe Transitions. (Priyanka <priyankaspatel@google.com>)
0b7976ea7: Dedupe Transactions and Protolog. (Priyanka <priyankaspatel@google.com>)
56dacaf5e: AbstractLogViewerPresenter, LogComponent, UiDataLog, LogPresenter. (Priyanka <priyankaspatel@google.com>)
8fb82ad77: Restrict gradient ratio between 0 and 1. (Priyanka <priyankaspatel@google.com>)
507d30588: Update SfSubtree display names properly. (Priyanka <priyankaspatel@google.com>)
d1bee06a8: Crop transitions without start/end time to width of zoom range. (Priyanka <priyankaspatel@google.com>)
6c1285c87: Update to clang-r522817 (Yi Kong <yikong@google.com>)
e5f72a02d: SampleSyncAdapter minsdk bump from 8 to 21 (Anvesh Renikindi <renikindi@google.com>)
```

