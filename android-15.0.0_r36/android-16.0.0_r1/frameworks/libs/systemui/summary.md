```
a5f64fa: Migration ColorExtractor to kotlin (Sunny Goyal <sunnygoyal@google.com>)
04bf757: Measure performance of MotionValues 1/2 (Omar Miatello <omarmt@google.com>)
6195ebb: Make sure icon cache method for getting icons respects skipAddToMemCache... (Charlie Anderson <charlander@google.com>)
b77106a: viewcapture: remove runOnUiThread() call (Kean Mariotti <keanmariotti@google.com>)
745ad89: Change ViewCaptureAwareWindowManager to extend WindowManagerImpl directl... (archisha <archisha@google.com>)
0656f03: Add support for custom lifecycle manager for PerDisplayRepository (Nicolo' Mazzucato <nicomazz@google.com>)
435b684: Implement `ViewMotionValue` runtime independent of compose (Mike Schneider <michschn@google.com>)
dc53bf8: Implement `ViewMotionValue` runtime independent of compose (Mike Schneider <michschn@google.com>)
32b7b54: [revert^2] Move PerDisplayRepository from SystemUI to displaylib (Nicolo' Mazzucato <nicomazz@google.com>)
c054267: Revert "Move PerDisplayRepository from SystemUI to displaylib" (Chaitanya Cheemala (xWF) <ccheemala@google.com>)
8d7ac1d: Add onKeyguardAppearing to LiveWallpaperKeyguardEventListener (Sherry Zhou <yuandizhou@google.com>)
77637ac: Move PerDisplayRepository from SystemUI to displaylib (Nicolo' Mazzucato <nicomazz@google.com>)
2f2518e: Add flags for updating Smartspace UI. (Xiaowen Lei <xilei@google.com>)
803c107: Move DisplayRepository from SystemUI to displaylib (Nicolo' Mazzucato <nicomazz@google.com>)
e7560c6: Create skeleton for DisplayLib (Nicolo' Mazzucato <nicomazz@google.com>)
4767fda: Floating version of VerticalExpandContainerSpec (Mike Schneider <michschn@google.com>)
2785ec3: Fix CustomDynamicColors to disallow low contrast. (Marcelo Arteiro <arteiro@google.com>)
8dffa8b: Add shapePath parameter for BitmapInfo badge shapes (Charlie Anderson <charlander@google.com>)
c165c18: Use `directMapped` velocity to prime new springs. (Mike Schneider <michschn@google.com>)
7d629e9: Protect MotionValue runtime from non-finite numbers (Mike Schneider <michschn@google.com>)
956157a: Add smartspace_remoteviews_intent_handler flag (Liam, Lee Pong Lam <iamiam@google.com>)
94e4529: Fix nullability for Kotlin 2.1 (Dave Mankoff <mankoff@google.com>)
14665d4: Invalidate icon cache to clear misshapen images (Sihua Ma <sihua@google.com>)
f597276: [Hot Corner] Add aconfig flag (helencheuk <helencheuk@google.com>)
480028b: Fix an issue where forced theme icon will show blank (Sihua Ma <sihua@google.com>)
ca93864: Implement verticalContainerReveal according to spec (Mike Schneider <michschn@google.com>)
9974177: Updating disabled state of badged bitmap (Sunny Goyal <sunnygoyal@google.com>)
1580a50: Revert^2 "Add config value for enabling forced themed icon" (Sihua Ma <sihua@google.com>)
9fbdb9c: Revert "Add config value for enabling forced themed icon" (Chaitanya Cheemala (xWF) <ccheemala@google.com>)
d07ba25: Add the 'public' visibility modifier to CustomDynamicColors.java (Marcelo Arteiro <arteiro@google.com>)
4f1be44: Use setFlow instead of addFlow (Zimuzo Ezeozue <zezeozue@google.com>)
4e32fde: Add config value for enabling forced themed icon (Sihua Ma <sihua@google.com>)
2c0ce43: Replace `coerce*` calls with `fastCoerce*` (Mike Schneider <michschn@google.com>)
206793f: Keep animation loop running while there are input/state changes (Mike Schneider <michschn@google.com>)
032991b: Add `keepRunningWhile()` to end MotionValue based on a condition (Mike Schneider <michschn@google.com>)
fb888de: Fix generate frame buffer being called unnecessarily when matrix changes... (Sherry Zhou <yuandizhou@google.com>)
5897414: Fix shaping of themed icons (Charlie Anderson <charlander@google.com>)
a7a1ed5: Fix perfetto category registration order (Zimuzo Ezeozue <zezeozue@google.com>)
3ec7d2a: Exclude dynamic shortcuts from being force themed (Sihua Ma <sihua@google.com>)
d38edc3: Predefined constants for stable threshold (Mike Schneider <michschn@google.com>)
f7e46e8: Add preferred_image_editor flag. (Matt Casey <mrcasey@google.com>)
5bdac8e: Simplifying icon normalization for adaptive icons (Sunny Goyal <sunnygoyal@google.com>)
3e5b99b: Add flag enable_lpp_squeeze_effect in shared SystemUI aconfig file (Bharat Singh <bharatkrsingh@google.com>)
ad6bfdf: MM Introduce a Kotlin type-safe builder for DirectionalMotionSpec (Omar Miatello <omarmt@google.com>)
7e967e4: Add flag specific to smartspace layout changes (Hawkwood Glazier <jglazier@google.com>)
44bc7c8: tracinglib: delegate traceAs calls (Peter Kalauskas <peskal@google.com>)
a738183: Embedding themeId in the themeController (Sunny Goyal <sunnygoyal@google.com>)
d09819d: tracinglib: add delegated types for tracing (Peter Kalauskas <peskal@google.com>)
fa53a55: Rename COMMAND_LOCKSCREEN_TAP and refactor parameters of onLockscreenFoc... (Sherry Zhou <yuandizhou@google.com>)
2956842: Removes duplicate sysui shared flag for icon shapes (Charlie Anderson <charlander@google.com>)
9f96cbb: Add applyWallpaper to TorusEngine (Aurélien Pomini <pomini@google.com>)
95f4abe: tracinglib: remove nameCoroutine() (Peter Kalauskas <peskal@google.com>)
e2f828a: optimize snow effects (Sherry Zhou <yuandizhou@google.com>)
621c3b1: Rain effect optimization (Sherry Zhou <yuandizhou@google.com>)
2de3ce4: Replace .toList() with .collect() (Cole Faust <colefaust@google.com>)
f92eac1: Revert "Revert "Updating FastBitmapDrawable to store BitmapInfo ..." (Sunny Goyal <sunnygoyal@google.com>)
ecb3891: viewcapture: fix NPE (WindowListener#mRoot) (Kean Mariotti <keanmariotti@google.com>)
937257f: Revert "Updating FastBitmapDrawable to store BitmapInfo instead ..." (Pechetty Sravani (xWF) <pechetty@google.com>)
433b8a3: Move extended wallpapers aconfig flag to shared (Hawkwood Glazier <jglazier@google.com>)
55682c5: Adding ability to override the app-info icon loading behavior (Sunny Goyal <sunnygoyal@google.com>)
275681c: Updating FastBitmapDrawable to store BitmapInfo instead of bitmap and ic... (Sunny Goyal <sunnygoyal@google.com>)
27f8f5c0: Pass tap event from keyguard to magic portrait (Sherry Zhou <yuandizhou@google.com>)
5675593: Move clock flags to shared lib (Hawkwood Glazier <jglazier@google.com>)
c89cbc1: [ambient] Initiate ambient library in android repo. (Holly Sun <jiuyu@google.com>)
aa64f18: Layout shape effects correctly in foldable and tablet (Sherry Zhou <yuandizhou@google.com>)
bc4fe08: Prettier visualization for motion mechanics debug. (Mike Schneider <michschn@google.com>)
49f0130: Add an interface to collect MotionValues for debug purposes. (Mike Schneider <michschn@google.com>)
ec7e31d: tracinglib: query aflag instead of sysprop (Peter Kalauskas <peskal@google.com>)
a9df4a5: Add traceSyncAndAsync and traceAsyncClosable (Nicolo' Mazzucato <nicomazz@google.com>)
4985d46: Remove getShapePath from GraphicsUtils to rely on IconShape instead (Charlie Anderson <charlander@google.com>)
e6b414f: tracinglib: consolidate thread-local usage (Peter Kalauskas <peskal@google.com>)
118954e: Setup TorusEngine with WallpaperDescription (Florence Yang <florenceyang@google.com>)
2ed63f2: Convert `composed {}` to Node #MotionMechanics (Mike Schneider <michschn@google.com>)
b213631: Adding some source hints when generating theme icons (Sunny Goyal <sunnygoyal@google.com>)
2df5cc8: Inroducing ability to enable/disable hover scale for icon's dislay (Jagrut Desai <jagrutdesai@google.com>)
d621d83: Allow passing in a custom color provider (Ioana Alexandru <aioana@google.com>)
edb5a8c: Implement `GestureContext` for gesture transitions #MotionMechanics #STL (Mike Schneider <michschn@google.com>)
0d70b63: Update icon factory to enable overriding shape (Charlie Anderson <charlander@google.com>)
ba845b7: Move com.android.systemui.status_bar_connected_displays to com.android.s... (Alina Zaidi <alinazaidi@google.com>)
c1850b4: Experimentally increasing contrast for themed icons (Sihua Ma <sihua@google.com>)
836a575: Removing shape detection in icon loader lib (Sunny Goyal <sunnygoyal@google.com>)
cae548f: tracinglib: demo updates (Peter Kalauskas <peskal@google.com>)
f06ee37: Fix flakiness in MotionValue test (Mike Schneider <michschn@google.com>)
eacb8a4: tracinglib: fix test annotation usage (Peter Kalauskas <peskal@google.com>)
24aaa52: Rename gesture `distance` to `dragOffset` #MotionMechanics (Mike Schneider <michschn@google.com>)
c0a6d19: Updating nexus launcher target (Sunny Goyal <sunnygoyal@google.com>)
81c78d6: tracinglib: fix thread-local slice counter (Peter Kalauskas <peskal@google.com>)
2af8c1e: Moving some listener methods to theme manager (Sunny Goyal <sunnygoyal@google.com>)
b835d28: viewcapture: fix NPE (WindowListener#mRoot) (Kean Mariotti <keanmariotti@google.com>)
75b3339: tracinglib: improve inline usage (Peter Kalauskas <peskal@google.com>)
ab8561a: Add instantForGroup utils to TrackTracer (Nicolo' Mazzucato <nicomazz@google.com>)
ffc9e21: Removing Dead Flag Test: CI Bug: 386652866 (Rex Hoffman <rexhoffman@google.com>)
66c8d88: tracinglib: deprecate nameCoroutine, fix bugs (Peter Kalauskas <peskal@google.com>)
efa7875: Move screenshot_context_url to sysui shared flags (Matt Casey <mrcasey@google.com>)
61eb827: Replacing some hardcoded use of lowRes boolean with lookup flag (Sunny Goyal <sunnygoyal@google.com>)
89db0c1: Converting BaseIconCache to kotlin (Sunny Goyal <sunnygoyal@google.com>)
23a2326: Avoid reallocating FrameBuffer when bitmaps don't need updating. (Shan Huang <shanh@google.com>)
8f546b0: viewcapture: support concurrent UI threads (Kean Mariotti <keanmariotti@google.com>)
b87d34a: Add Debug Logs to AllAppsStore's dump for Bitmap flags (Stefan Andonian <andonian@google.com>)
81d2702: Add TrackTracer to trace to a single perfetto track (Nicolo' Mazzucato <nicomazz@google.com>)
43d2864: tracinglib: fix nameCoroutine usage in flows (Peter Kalauskas <peskal@google.com>)
f3e6de2: tracinglib: improve continuation performance (Peter Kalauskas <peskal@google.com>)
eb30074: Revert "viewcapture: guarantee happens-before relationship" (Kean Mariotti <keanmariotti@google.com>)
1cc29a1: Add debug visualizations for [MotionValue] #MotionMechanics (Mike Schneider <michschn@google.com>)
2aed534: Suspend [MotionValue.keepRunning] when idle #MotionMechanics (Mike Schneider <michschn@google.com>)
a7a2c33: Add [DebugInspector] to [MotionValue] #MotionMechanics (Mike Schneider <michschn@google.com>)
139a2cb: [MotionValue] implementation #MotionMechanics (Mike Schneider <michschn@google.com>)
ff62c45: Replacing all int lookup flags and boolean overrides with an object to m... (Sunny Goyal <sunnygoyal@google.com>)
31f7147: Updating KEYPRESS_STANDARD token. (Juan Sebastian Martinez <juansmartinez@google.co...)
014d7ad: Update flag description (Daniel Sandler <dsandler@android.com>)
7fe9e8f: tracinglib: changes to coroutine tracing format (Peter Kalauskas <peskal@google.com>)
```

