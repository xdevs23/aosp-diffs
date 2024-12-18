```
e5c763ec: Filter UserPicker touches when partially obscured (Alex Stetson <alexstetson@google.com>)
6bacf709: Revert "Get display id from base view" (Ankur Bakshi <ankurbakshi@google.com>)
6d8352c4: Get display id from base view (Alex Stetson <alexstetson@google.com>)
0c83a977: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
b4f03388: Update dependencies (Alex Stetson <alexstetson@google.com>)
e439d91b: Remove reordering of task view task in startAnimation (Rachit Jain <jainrachit@google.com>)
ddbb65a8: Add a debug panel on the top bar (cassieyw <cassieyw@google.com>)
a98c660b: Refactor keyguard APIs from CarSystemBarController (Saeid Farivar Asanjan <farivar@google.com>)
c0488574: Gate secure user start with flag (Alex Stetson <alexstetson@google.com>)
3942f193: Fix RB ABA behavior (Eric Chiang <eschiang@google.com>)
fcfa8d94: Make CarSystemBarController an interface (Saeid Farivar Asanjan <farivar@google.com>)
3c5c3bad: Re-enable DisplayCompact in left system bar (Jainam Shah <jainams@google.com>)
c22e291f: Make java_sdk_library dependencies explicit (Jihoon Kang <jihoonkang@google.com>)
156fa856: Fix default ABA behavior (Eric Chiang <eschiang@google.com>)
6a48cf8b: Migrate profile switcher to flexible components (Alex Stetson <alexstetson@google.com>)
b572d2af: Update Media ABA logic (Eric Chiang <eschiang@google.com>)
436e6e85: Make java_sdk_library dependencies explicit (Jihoon Kang <jihoonkang@google.com>)
9b8635f5: Make java_sdk_library dependencies explicit (Jihoon Kang <jihoonkang@google.com>)
3900a217: Allow touches to pass through HUN scrim (Abhijoy Saha <abhijoy@google.com>)
b1e7b36d: Prevent keyguard password text from getting cut off (Alex Stetson <alexstetson@google.com>)
63de21f2: Fix NullPointerException in car service due to invalid display. (Vivek Shaw <vshaw17@ford.com>)
30b71dd0: Prevent dependency.get error on tests (Matt Pietal <mpietal@google.com>)
fa8857f0: Reset HVAC auto dismiss timer when interactions are active (Mounika Nekkalapudi <snekkalapudi@google.com>)
63467029: Use systemui:icon attr for notification system bar button (Abhijoy Saha <abhijoy@google.com>)
57e50e7c: Move code from CarSystemBars to controller class (Saeid Farivar Asanjan <farivar@google.com>)
83c6a7ff: Privacy chip dark icon color should be dark (Alex Stetson <alexstetson@google.com>)
b42f177d: Add AudioModule to CarVolumeModule to provide AudioRepository (Anton Potapov <apotapov@google.com>)
0744519b: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
37885b5e: Disable some tests for form factors with  multi-tasking window (Jane Ha <hatrang@google.com>)
52c9a2d0: Reset cache in UserPickerPassengerHeaderTest (Jane Ha <hatrang@google.com>)
351ab139: Prevent NPE on config change prior to car connecting (Alex Stetson <alexstetson@google.com>)
6ef7ad2f: Set QC's popup window behavior to be always to top of IME (Jane Ha <hatrang@google.com>)
13897e1f: Reorder embedded tasks to top when the task view is coming to the top (Rachit Jain <jainrachit@google.com>)
a269ff54: Only consider multi window tasks for automotive ui portrait (Rachit Jain <jainrachit@google.com>)
c2e2ea69: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
4e0d247b: Remove padding to correct thumb offset (Alex Stetson <alexstetson@google.com>)
8430de18: Fix volume control is not working after 1st change (Wonil Kim <wonil@google.com>)
72a1c4a5: Remove duplicate CarServiceProvider listener (Alex Stetson <alexstetson@google.com>)
95a8d50d: Specify app name in data subscription reactive messages (Jane Ha <hatrang@google.com>)
1eb32684: Remove DisplayStatusIconController (Alex Stetson <alexstetson@google.com>)
2890ee1c: Fix volume key is not working on Tangorpro and Pixel Car (Wonil Kim <wonil@google.com>)
2d71e6ef: Combine RB and Hudson Profile Switcher (Alex Stetson <alexstetson@google.com>)
3156ca84: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
b7cd2187: Report multi window tasks to CarService. (Gaurav Bhola <gauravbhola@google.com>)
b9a1f2d3: Support auto closing and custom animation for HVAC panel (Alex Stetson <alexstetson@google.com>)
cbfcd7d7: Move volume and microphone for consistency with MD Driver SysUI (Roma Modi <romam@google.com>)
bd966e58: Add deviceless testing to CarSystemUI (Alex Stetson <alexstetson@google.com>)
d6614a94: Implement setDozeScreenBrightnessFloat (Piotr Wilczyński <wilczynskip@google.com>)
747d8019: Improve passenger keyguard experience (Alex Stetson <alexstetson@google.com>)
28cabbd2: Update lock status for visible background users (seokgyun.hong <seokgyun.hong@lge.com>)
54acf69f: Set use_resource_processor: false for CarSystemUI and CarSystemUITests (Colin Cross <ccross@android.com>)
9a19eb78: Remove unused binder in setImeWindowStatus calls (Cosmin Băieș <cosminbaies@google.com>)
5aacf283: Set use_resource_processor: false for CarSystemUI and CarSystemUITests (Colin Cross <ccross@android.com>)
c00c3cd4: Fix inconsistent notificiaton overlay direction for secondary user (Calvin Huang <calhuang@google.com>)
321b5bc3: Add UX specs for Data Subscription pop-up (Jane Ha <hatrang@google.com>)
c36daae7: Adjusting the updateRequestedVisibleTypes interface to use ImeStatsToken (Felix Stern <fstern@google.com>)
040395f5: Replace get/setPendingIntentBackgroundActivityLaunchAllowedByPermission (Achim Thesmann <achim@google.com>)
89e0696b: Add CarLauncher to data subcription pop-up's package blocked list (Jane Ha <hatrang@google.com>)
35c98903: [Audiosharing] Include empty audio sharing module (Yiyi Shen <yiyishen@google.com>)
6f2db8a5: Fix scroll bar flickering on user picker for secondary user (Calvin Huang <calhuang@google.com>)
7f3edd80: Remove calls to set ui mode on config change (Alex Stetson <alexstetson@google.com>)
0411fdaa: Allow all system bar button views to be optional (Alex Stetson <alexstetson@google.com>)
8c971be9: Get correct audio zone id (Alex Stetson <alexstetson@google.com>)
36ca39ae: Change BugReportApp trigger action (Joy Yoonhyung Lee <yooonlee@google.com>)
72e06b50: Setup transient show sysmtem bar by swipe for UserPickerActivity (Calvin Huang <calhuang@google.com>)
a6f60b3c: Update WCT#addInsetsSource signature (Jorge Gil <jorgegil@google.com>)
d96604b5: Re-add bar control policy option (Alex Stetson <alexstetson@google.com>)
f4d284f8: Check for null UserCreationResult (Alex Stetson <alexstetson@google.com>)
19ab4b3a: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
423af5fc: Only call IStatusBarService from foreground user (Alex Stetson <alexstetson@google.com>)
7f21a64c: AutoConnect external display for Car targets (ankiit <ankiit@google.com>)
eff1aaf7: Replace all available Volume items (Robert Gross <robertgross@google.com>)
a816aad9: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
0f408b99: Add TrunkStable flag for daview based windowing on AAOS (Gaurav Bhola <gauravbhola@google.com>)
9ce8c7e6: Slight UI adjustment for the positioning of the volume panel (cassieyw <cassieyw@google.com>)
2f8b948f: Wait to show ABA blocking content (Eric Chiang <eschiang@google.com>)
ba375b81: Rename a flag (cassieyw <cassieyw@google.com>)
1d1e7fb2: Add QC UI for the sound panel (cassieyw <cassieyw@google.com>)
2f17c475: Update BarTransitions import (Tracy Zhou <tracyzhou@google.com>)
e5800b2c: Show the icon for the brightness slider (cassieyw <cassieyw@google.com>)
2e62ea84: Reduce redundant systme bar refresh on overlay change (Calvin Huang <calhuang@google.com>)
266278d7: Add DD flag to enable task moving feature to SysUI (Priyank Singh <priyanksingh@google.com>)
cf4bf3c9: Include accessibility modules in CarSystemUI (Josh Yang <yzj@google.com>)
```

