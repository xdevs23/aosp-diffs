```diff
diff --git a/builtInServices/src/com/android/internal/car/CarServiceHelperService.java b/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
index 3724bf5..6257ce7 100644
--- a/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
+++ b/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
@@ -118,6 +118,7 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.List;
+import java.util.Locale;
 import java.util.Map;
 import java.util.Objects;
 import java.util.concurrent.CompletableFuture;
@@ -140,6 +141,17 @@ public class CarServiceHelperService extends SystemService
 
     private static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
 
+    private static final String[] CAR_JAVA_STACKS_OF_INTEREST = new String[] {
+            "com.android.car"
+    };
+
+    private static final String[] CAR_NATIVE_STACKS_OF_INTEREST = new String[] {
+            "/system/bin/cardisplayproxyd",
+            "/system/bin/carpowerpolicyd",
+            "/system/bin/carwatchdogd",
+            "/system/bin/evsmanagerd",
+    };
+
     private static final List<String> CAR_HIDL_INTERFACES_OF_INTEREST = Arrays.asList(
             "android.hardware.automotive.audiocontrol@1.0::IAudioControl",
             "android.hardware.automotive.audiocontrol@2.0::IAudioControl",
@@ -172,6 +184,7 @@ public class CarServiceHelperService extends SystemService
                     + "(?<startClockTicks>[0-9]*)\\s(?:-?[0-9]*\\s)*-?[0-9]*";
     private static final String AIDL_VHAL_INTERFACE_PREFIX =
             "android.hardware.automotive.vehicle.IVehicle/";
+    private static final String DEFAULT_PROC_ROOT_DIR = "/proc";
 
     private static final boolean sVisibleBackgroundUsersEnabled =
             UserManager.isVisibleBackgroundUsersEnabled();
@@ -212,6 +225,8 @@ public class CarServiceHelperService extends SystemService
 
     private CarServiceHelperServiceUpdatable mCarServiceHelperServiceUpdatable;
 
+    private String mProcRootDir;
+
     /**
      * End-to-end time (from process start) for unlocking the first non-system user.
      */
@@ -224,7 +239,8 @@ public class CarServiceHelperService extends SystemService
                 /* carServiceHelperServiceUpdatable= */ null,
                 /* carDevicePolicySafetyChecker= */ null,
                 new CarActivityInterceptor(),
-                new CarDisplayCompatScaleProvider(context)
+                new CarDisplayCompatScaleProvider(context),
+                DEFAULT_PROC_ROOT_DIR
         );
     }
 
@@ -236,7 +252,8 @@ public class CarServiceHelperService extends SystemService
             @Nullable CarServiceHelperServiceUpdatable carServiceHelperServiceUpdatable,
             @Nullable CarDevicePolicySafetyChecker carDevicePolicySafetyChecker,
             @Nullable CarActivityInterceptor carActivityInterceptor,
-            @Nullable CarDisplayCompatScaleProvider carDisplayCompatScaleProvider) {
+            @Nullable CarDisplayCompatScaleProvider carDisplayCompatScaleProvider,
+            String procRootDir) {
         super(context);
 
         mContext = context;
@@ -246,6 +263,7 @@ public class CarServiceHelperService extends SystemService
         mCarActivityInterceptor = carActivityInterceptor;
         mCarDisplayCompatScaleProvider = carDisplayCompatScaleProvider;
         mCarWatchdogDaemonHelper = carWatchdogDaemonHelper;
+        mProcRootDir = procRootDir;
         try {
             if (carServiceHelperServiceUpdatable == null) {
                 Map<String, Object> interfaces = new ArrayMap<>();
@@ -294,7 +312,7 @@ public class CarServiceHelperService extends SystemService
 
                 @Override
                 public void onUserRemoved(UserInfo user) {
-                    if (DBG) Slogf.d(TAG, "onUserRemoved(): $s", user.toFullString());
+                    if (DBG) Slogf.d(TAG, "onUserRemoved(): %s", user.toFullString());
                     mCarServiceHelperServiceUpdatable.onUserRemoved(user.getUserHandle());
                 }
             });
@@ -553,8 +571,7 @@ public class CarServiceHelperService extends SystemService
     private static void addInterestingHidlPids(HashSet<Integer> pids) {
         try {
             IServiceManager serviceManager = IServiceManager.getService();
-            ArrayList<IServiceManager.InstanceDebugInfo> dump =
-                    serviceManager.debugDump();
+            List<IServiceManager.InstanceDebugInfo> dump = serviceManager.debugDump();
             for (IServiceManager.InstanceDebugInfo info : dump) {
                 if (info.pid == IServiceManager.PidConstant.NO_PID) {
                     continue;
@@ -603,7 +620,11 @@ public class CarServiceHelperService extends SystemService
         addInterestingHidlPids(pids);
         addInterestingAidlPids(pids);
 
-        int[] nativePids = Process.getPidsForCommands(Watchdog.NATIVE_STACKS_OF_INTEREST);
+        String[] nativeStacksOfInterest = Arrays.copyOf(Watchdog.NATIVE_STACKS_OF_INTEREST,
+            Watchdog.NATIVE_STACKS_OF_INTEREST.length + CAR_NATIVE_STACKS_OF_INTEREST.length);
+        System.arraycopy(CAR_NATIVE_STACKS_OF_INTEREST, 0, nativeStacksOfInterest,
+            Watchdog.NATIVE_STACKS_OF_INTEREST.length, CAR_NATIVE_STACKS_OF_INTEREST.length);
+        int[] nativePids = Process.getPidsForCommands(nativeStacksOfInterest);
         if (nativePids != null) {
             for (int i : nativePids) {
                 pids.add(i);
@@ -613,6 +634,19 @@ public class CarServiceHelperService extends SystemService
         return new ArrayList<Integer>(pids);
     }
 
+    private static List<Integer> getInterestingJavaPids() {
+        HashSet<Integer> pids = new HashSet<Integer>();
+
+        int[] javaPids = Process.getPidsForCommands(CAR_JAVA_STACKS_OF_INTEREST);
+        if (javaPids != null) {
+            for (int pid : javaPids) {
+                pids.add(pid);
+            }
+        }
+
+        return new ArrayList<Integer>(pids);
+    }
+
     static CarWatchdogProcessStats constructCarWatchdogProcessStatsLocked(
             List<ProcessIdentifier> clients) {
         CarWatchdogProcessStats.Builder carWatchdogProcessStats =
@@ -637,6 +671,7 @@ public class CarServiceHelperService extends SystemService
     public File dumpServiceStacks() {
         ArrayList<Integer> pids = new ArrayList<>();
         pids.add(Process.myPid());
+        pids.addAll(getInterestingJavaPids());
 
         // Use the long version used by Watchdog since the short version is removed by the compiler.
         return StackTracesDumpHelper.dumpStackTraces(
@@ -711,7 +746,7 @@ public class CarServiceHelperService extends SystemService
         }
     }
 
-    private static void killProcesses(List<ProcessIdentifier> processIdentifiers,
+    private void killProcesses(List<ProcessIdentifier> processIdentifiers,
             boolean useSigsys) {
         for (int i = 0; i < processIdentifiers.size(); i++) {
             ProcessIdentifier processIdentifier = processIdentifiers.get(i);
@@ -747,8 +782,8 @@ public class CarServiceHelperService extends SystemService
         }
     }
 
-    private static String getProcessCmdLine(int pid) {
-        String filename = "/proc/" + pid + "/cmdline";
+    private String getProcessCmdLine(int pid) {
+        String filename = String.format(Locale.getDefault(), "%s/%d/cmdline", mProcRootDir, pid);
         try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
             String line = reader.readLine().replace('\0', ' ').trim();
             int index = line.indexOf(' ');
@@ -762,12 +797,8 @@ public class CarServiceHelperService extends SystemService
         }
     }
 
-    static ProcessInfo getProcessInfo(int pid) {
-        // TODO(b/400455938): This function used to be private but it was updated to enable
-        // tests to access this method for stubbing. However, this approach is not
-        // recommended. Once the tests are modified to use fake proc fs files, revert this
-        // change. The tests must verify this implementation and not stub it.
-        String filename = "/proc/" + pid + "/stat";
+    private ProcessInfo getProcessInfo(int pid) {
+        String filename = String.format(Locale.getDefault(), "%s/%d/stat", mProcRootDir, pid);
         try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
             String line = reader.readLine().replace('\0', ' ').trim();
             Matcher m = sProcPidStatPattern.matcher(line);
@@ -1048,7 +1079,7 @@ public class CarServiceHelperService extends SystemService
             }
         }
 
-        private static void dumpProcesses(List<ProcessIdentifier> processIdentifiers) {
+        private void dumpProcesses(List<ProcessIdentifier> processIdentifiers) {
             ArrayList<Integer> javaPids = new ArrayList<>(1);
             ArrayList<Integer> nativePids = new ArrayList<>();
             for (int i = 0; i < processIdentifiers.size(); i++) {
@@ -1067,6 +1098,7 @@ public class CarServiceHelperService extends SystemService
                             processIdentifier.pid, e);
                 }
             }
+            javaPids.addAll(getInterestingJavaPids());
             nativePids.addAll(getInterestingNativePids());
             StackTracesDumpHelper.dumpStackTraces(
                     /* firstPids= */ javaPids, /* processCpuTracker= */ null, /* lastPids= */ null,
@@ -1075,8 +1107,9 @@ public class CarServiceHelperService extends SystemService
                     /* auxiliaryTaskExecutor= */ Runnable::run, /* latencyTracker= */ null);
         }
 
-        private static boolean isJavaApp(int pid) throws IOException {
-            Path exePath = new File("/proc/" + pid + "/exe").toPath();
+        private boolean isJavaApp(int pid) throws IOException {
+            Path exePath = new File(String.format(Locale.getDefault(),
+                    "%s/%d/exe", mProcRootDir, pid)).toPath();
             String target = Files.readSymbolicLink(exePath).toString();
             // Zygote's target exe is also /system/bin/app_process32 or /system/bin/app_process64.
             // But, we can be very sure that Zygote will not be the client of car watchdog daemon.
@@ -1109,7 +1142,7 @@ public class CarServiceHelperService extends SystemService
             }
         }
 
-        private static List<ProcessIdentifier> removeDeadProcesses(
+        private List<ProcessIdentifier> removeDeadProcesses(
                 List<ProcessIdentifier> processIdentifiers) {
             processIdentifiers.removeIf(processIdentifier -> {
                 ProcessInfo processInfo = getProcessInfo(processIdentifier.pid);
@@ -1120,10 +1153,7 @@ public class CarServiceHelperService extends SystemService
         }
     }
 
-    @VisibleForTesting
-    static final class ProcessInfo {
-        // TODO(b/400455938): Refer to the comment in `getProcessInfo` for context.
-        // Revert this class to private.
+    private static final class ProcessInfo {
         public static final String UNKNOWN_PROCESS = "unknown process";
         public static final int INVALID_START_TIME = -1;
 
diff --git a/builtInServices/src/com/android/server/wm/CarDisplayAreaPolicyProvider.java b/builtInServices/src/com/android/server/wm/CarDisplayAreaPolicyProvider.java
index 493845b..d1d52ae 100644
--- a/builtInServices/src/com/android/server/wm/CarDisplayAreaPolicyProvider.java
+++ b/builtInServices/src/com/android/server/wm/CarDisplayAreaPolicyProvider.java
@@ -81,17 +81,17 @@ public class CarDisplayAreaPolicyProvider implements DisplayAreaPolicy.Provider
                     imeContainer);
         }
 
-        TaskDisplayArea backgroundTaskDisplayArea = new TaskDisplayArea(content, wmService,
+        TaskDisplayArea backgroundTaskDisplayArea = new TaskDisplayArea(wmService,
                 "BackgroundTaskDisplayArea", BACKGROUND_TASK_CONTAINER,
                 /* createdByOrganizer= */ false, /* canHostHomeTask= */ false);
         backgroundTaskDisplayArea.setWindowingMode(WINDOWING_MODE_MULTI_WINDOW);
 
-        TaskDisplayArea controlBarDisplayArea = new TaskDisplayArea(content, wmService,
+        TaskDisplayArea controlBarDisplayArea = new TaskDisplayArea(wmService,
                 "ControlBarTaskDisplayArea", CONTROL_BAR_DISPLAY_AREA,
                 /* createdByOrganizer= */ false, /* canHostHomeTask= */ false);
         controlBarDisplayArea.setWindowingMode(WINDOWING_MODE_MULTI_WINDOW);
 
-        TaskDisplayArea voicePlateTaskDisplayArea = new TaskDisplayArea(content, wmService,
+        TaskDisplayArea voicePlateTaskDisplayArea = new TaskDisplayArea(wmService,
                 "VoicePlateTaskDisplayArea", FEATURE_VOICE_PLATE,
                 /* createdByOrganizer= */ false, /* canHostHomeTask= */ false);
         // voicePlatTaskDisplayArea needs to be in full screen windowing mode.
@@ -121,8 +121,9 @@ public class CarDisplayAreaPolicyProvider implements DisplayAreaPolicy.Provider
                 "FeatureForegroundApplication", FOREGROUND_DISPLAY_AREA_ROOT);
         defaultAppsRoot.setWindowingMode(WINDOWING_MODE_MULTI_WINDOW);
 
-        TaskDisplayArea defaultAppTaskDisplayArea = new TaskDisplayArea(content, wmService,
-                "DefaultApplicationTaskDisplayArea", DEFAULT_APP_TASK_CONTAINER);
+        TaskDisplayArea defaultAppTaskDisplayArea = new TaskDisplayArea(wmService,
+                "DefaultApplicationTaskDisplayArea", DEFAULT_APP_TASK_CONTAINER,
+                false /* createdByOrganizer */, true /* canHostHomeTask */);
         List<TaskDisplayArea> firstTdaList = new ArrayList<>();
         firstTdaList.add(defaultAppTaskDisplayArea);
         DisplayAreaPolicyBuilder.HierarchyBuilder applicationHierarchy =
@@ -134,8 +135,7 @@ public class CarDisplayAreaPolicyProvider implements DisplayAreaPolicy.Provider
                                 .and(TYPE_APPLICATION_OVERLAY)
                                 .build());
 
-        return new DisplayAreaPolicyBuilder()
-                .setRootHierarchy(rootHierarchy)
+        return new DisplayAreaPolicyBuilder(content.getDisplayId(), rootHierarchy)
                 .addDisplayAreaGroupHierarchy(applicationHierarchy)
                 .build(wmService);
     }
diff --git a/builtInServices/tests/Android.bp b/builtInServices/tests/Android.bp
index b60109a..8225ae3 100644
--- a/builtInServices/tests/Android.bp
+++ b/builtInServices/tests/Android.bp
@@ -40,6 +40,7 @@ android_test {
         "truth",
         "car-frameworks-service.impl",
         "flag-junit",
+        "compatibility-device-util-axt",
     ],
 
     // mockito-target-extended dependencies
diff --git a/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/1/stat b/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/1/stat
new file mode 100644
index 0000000..88dc045
--- /dev/null
+++ b/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/1/stat
@@ -0,0 +1 @@
+1 (process1) S 0 0 0 0 -1 4194560 15491 1888153 107 1257 19 194 1731 1183 20 0 3 0 100 11912400896 1477 18446744073709551615 1 1 0 0 0 0 65536 0 1073779960 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0
\ No newline at end of file
diff --git a/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/2/stat b/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/2/stat
new file mode 100644
index 0000000..fd41405
--- /dev/null
+++ b/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/2/stat
@@ -0,0 +1 @@
+2 (process2) S 0 0 0 0 -1 4194560 15491 1888153 107 1257 19 194 1731 1183 20 0 3 0 200 11912400896 1477 18446744073709551615 1 1 0 0 0 0 65536 0 1073779960 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0
\ No newline at end of file
diff --git a/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/3/stat b/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/3/stat
new file mode 100644
index 0000000..4ae85a4
--- /dev/null
+++ b/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/3/stat
@@ -0,0 +1 @@
+3 (process3) S 0 0 0 0 -1 4194560 15491 1888153 107 1257 19 194 1731 1183 20 0 3 0 300 11912400896 1477 18446744073709551615 1 1 0 0 0 0 65536 0 1073779960 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0
\ No newline at end of file
diff --git a/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/4/stat b/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/4/stat
new file mode 100644
index 0000000..6075c42
--- /dev/null
+++ b/builtInServices/tests/assets/CarServiceHelperServiceTest/proc/4/stat
@@ -0,0 +1 @@
+4 (process4) S 0 0 0 0 -1 4194560 15491 1888153 107 1257 19 194 1731 1183 20 0 3 0 400 11912400896 1477 18446744073709551615 1 1 0 0 0 0 65536 0 1073779960 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0
\ No newline at end of file
diff --git a/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java b/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
index 84a55c8..657367b 100644
--- a/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
+++ b/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
@@ -21,19 +21,23 @@ import static com.google.common.truth.Truth.assertWithMessage;
 import static org.junit.Assume.assumeTrue;
 
 import android.app.Instrumentation;
+import android.app.UiAutomation;
 import android.content.ComponentName;
 import android.content.Intent;
 import android.view.KeyEvent;
 import android.view.accessibility.AccessibilityManager;
 
-import androidx.test.filters.FlakyTest;
 import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.uiautomator.Condition;
+import androidx.test.uiautomator.Configurator;
 import androidx.test.uiautomator.UiDevice;
 import androidx.test.uiautomator.UiObject;
 import androidx.test.uiautomator.UiObjectNotFoundException;
 import androidx.test.uiautomator.UiSelector;
 
+import com.android.compatibility.common.util.PollingCheck;
+import com.android.compatibility.common.util.SystemUtil;
+
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
@@ -48,27 +52,45 @@ import java.io.IOException;
 public final class ActivityResolverTest {
 
     private static final long WAIT_TIMEOUT_MS = 3_000;
+    private static final long POLLING_CHECK_TIMEOUT_MILLIS = 10000L;
     private static final String TRIGGER_ACTIVITY_RESOLVER_RESOURCE_ID =
             "com.google.android.car.kitchensink:id/trigger_activity_resolver";
     private static final String DISMISS_BUTTON_RESOURCE_ID =
             "com.google.android.car.kitchensink:id/dismiss_button";
-    private static final String TITLE_ID = "android:id/title";
     private static final ComponentName ROTARY_SERVICE_COMPONENT_NAME =
             ComponentName.unflattenFromString("com.android.car.rotary/.RotaryService");
 
     private static final String KITCHEN_SINK_APP = "com.google.android.car.kitchensink";
 
+    private static final UiAutomation sUiAutomation =
+            InstrumentationRegistry.getInstrumentation().getUiAutomation(
+                    UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
+
     private Instrumentation mInstrumentation;
     private UiDevice mDevice;
     private AccessibilityManager mAccessibilityManager;
 
     @Before
-    public void setUp() throws IOException {
+    public void setUp() throws Exception {
         mInstrumentation = InstrumentationRegistry.getInstrumentation();
         mAccessibilityManager = mInstrumentation.getContext().getSystemService(
                 AccessibilityManager.class);
+
+        // If this flag is not set, RotaryService will be killed. See (b/421487382).
+        Configurator configurator = Configurator.getInstance();
+        configurator.setUiAutomationFlags(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
         mDevice = UiDevice.getInstance(mInstrumentation);
+
         closeKitchenSink();
+
+        assumeHasRotaryService();
+
+        launchResolverActivity();
+
+        // RotaryService might be killed by other tests using UiAutomation without
+        // FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES flag.
+        PollingCheck.waitFor(POLLING_CHECK_TIMEOUT_MILLIS, () -> isRotaryServiceRunning(),
+                "RotaryService is not running yet");
     }
 
     @After
@@ -82,8 +104,6 @@ public final class ActivityResolverTest {
 
     @Test
     public void testListItemFocusable_threeItems() throws UiObjectNotFoundException, IOException {
-        assumeHasRotaryService();
-        launchResolverActivity();
         assumeTrue(hasThreeListItems());
 
         // Press TAB key to focus first list item
@@ -108,10 +128,7 @@ public final class ActivityResolverTest {
     }
 
     @Test
-    @FlakyTest(bugId = 397717760)
     public void testListItemFocusable_twoItems() throws UiObjectNotFoundException, IOException {
-        assumeHasRotaryService();
-        launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
         // Press TAB key to focus first list item
@@ -139,8 +156,6 @@ public final class ActivityResolverTest {
     @Test
     public void testActionButtonsNotFocusable_threeItems()
             throws UiObjectNotFoundException, IOException {
-        assumeHasRotaryService();
-        launchResolverActivity();
         assumeTrue(hasThreeListItems());
 
         // The two buttons should be disabled if the test activity is never opened by
@@ -160,8 +175,6 @@ public final class ActivityResolverTest {
 
     @Test
     public void testClickListItem_threeItems() throws UiObjectNotFoundException, IOException {
-        assumeHasRotaryService();
-        launchResolverActivity();
         assumeTrue(hasThreeListItems());
 
         // Press TAB key to focus first list item
@@ -207,10 +220,7 @@ public final class ActivityResolverTest {
     }
 
     @Test
-    @FlakyTest(bugId = 397717760)
     public void testClickListItem_twoItems() throws UiObjectNotFoundException, IOException {
-        assumeHasRotaryService();
-        launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
         // Press TAB key to focus first list item
@@ -229,10 +239,7 @@ public final class ActivityResolverTest {
     }
 
     @Test
-    @FlakyTest(bugId = 397717760)
     public void testClickJustOnceButton_twoItems() throws UiObjectNotFoundException, IOException {
-        assumeHasRotaryService();
-        launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
         // Press TAB key thrice to focus justOnceButton
@@ -271,6 +278,7 @@ public final class ActivityResolverTest {
         intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
         intent.putExtra("select", "activity resolver");
         mInstrumentation.getContext().startActivity(intent);
+        mDevice.waitForIdle();
 
         UiObject button = mDevice.findObject(new UiSelector().resourceId(
                 TRIGGER_ACTIVITY_RESOLVER_RESOURCE_ID));
@@ -287,6 +295,7 @@ public final class ActivityResolverTest {
     }
 
     private void waitAndAssertFocused(UiObject view) throws UiObjectNotFoundException {
+        mDevice.waitForIdle();
         mDevice.wait(isViewFocused(view), WAIT_TIMEOUT_MS);
         assertWithMessage("The view " + view + " should be focused")
                 .that(view.isFocused())
@@ -302,4 +311,21 @@ public final class ActivityResolverTest {
             }
         };
     }
+
+    private static Boolean isRotaryServiceRunning() {
+        try {
+            String output = SystemUtil.runShellCommand(sUiAutomation, "dumpsys activity service "
+                    + ROTARY_SERVICE_COMPONENT_NAME.flattenToShortString());
+            // Wait for RotaryService to be recreated and running in case it was killed by other
+            // tests using UiAutomation.
+            // When it is running, the dumpsys result is like:
+            // SERVICE com.android.car.rotary/.RotaryService 898025b pid=2101 user=10
+            // Otherwise, the dumpsys result is like:
+            // SERVICE com.android.car.rotary/.RotaryService 19f3b7e pid=(not running))
+            return output.contains("user");
+
+        } catch (IOException e) {
+            throw new RuntimeException(e);
+        }
+    }
 }
diff --git a/builtInServices/tests/src/com/android/internal/car/CarServiceHelperServiceTest.java b/builtInServices/tests/src/com/android/internal/car/CarServiceHelperServiceTest.java
index 2933704..f73a07d 100644
--- a/builtInServices/tests/src/com/android/internal/car/CarServiceHelperServiceTest.java
+++ b/builtInServices/tests/src/com/android/internal/car/CarServiceHelperServiceTest.java
@@ -48,12 +48,15 @@ import android.car.test.mocks.AbstractExtendedMockitoTestCase;
 import android.car.watchdoglib.CarWatchdogDaemonHelper;
 import android.content.Context;
 import android.content.pm.PackageManager;
+import android.content.res.AssetManager;
 import android.os.IBinder;
 import android.os.ServiceDebugInfo;
 import android.os.ServiceManager;
 import android.os.UserHandle;
+import android.util.Slog;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.internal.util.CarWatchdogKillStatsReported;
 import com.android.internal.util.CarWatchdogProcessStats;
@@ -66,6 +69,9 @@ import com.android.server.pm.UserManagerInternal;
 import com.android.server.wm.CarDisplayCompatScaleProvider;
 import com.android.server.wm.CarLaunchParamsModifier;
 
+import libcore.io.Streams;
+
+import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -73,10 +79,15 @@ import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
 
+import java.io.File;
+import java.io.FileOutputStream;
+import java.io.InputStream;
+import java.io.OutputStream;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.util.ArrayList;
 import java.util.List;
+import java.util.Objects;
 import java.util.concurrent.Future;
 
 /**
@@ -84,10 +95,18 @@ import java.util.concurrent.Future;
  */
 @RunWith(AndroidJUnit4.class)
 public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase {
+    private static final String TAG = CarServiceHelperServiceTest.class.getSimpleName();
+    private static final String ROOT_DIR_NAME = "CarServiceHelperServiceTest";
     private static final String SAMPLE_AIDL_VHAL_INTERFACE_NAME =
             "android.hardware.automotive.vehicle.IVehicle/SampleVehicleHalService";
     private static final int MAX_WAIT_TIME_MS = 3000;
 
+    private final Context mContext =
+            InstrumentationRegistry.getInstrumentation().getTargetContext();
+    private final File mCacheRoot = new File(mContext.getCacheDir(), ROOT_DIR_NAME);
+    private final AssetManager mAssetManager = mContext.getAssets();
+
+
     private CarServiceHelperService mHelper;
 
     @Mock
@@ -147,7 +166,7 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
     }
 
     @Before
-    public void setTestFixtures() {
+    public void setTestFixtures() throws Exception {
         mHelper = new CarServiceHelperService(
                 mMockContext,
                 mCarLaunchParamsModifier,
@@ -155,12 +174,24 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
                 mCarServiceHelperServiceUpdatable,
                 mCarDevicePolicySafetyChecker,
                 mActivityInterceptor,
-                mCarDisplayCompatScaleProvider);
+                mCarDisplayCompatScaleProvider,
+                String.format("%s/proc", mCacheRoot.getAbsolutePath()));
         when(mMockContext.getPackageManager()).thenReturn(mPackageManager);
         when(mMockContext.getSystemService(ActivityManager.class)).thenReturn(mActivityManager);
 
         doReturn(mUserManagerInternal)
                 .when(() -> LocalServices.getService(UserManagerInternal.class));
+
+        copyAssets(ROOT_DIR_NAME, mContext.getCacheDir());
+        assertWithMessage("Cache root dir %s", mCacheRoot.getAbsolutePath())
+            .that(mCacheRoot.exists()).isTrue();
+    }
+
+    @After
+    public void teardown() throws Exception {
+        if (!deleteDirectory(mCacheRoot)) {
+            Slog.e(TAG, "Failed to delete cache root directory " + mCacheRoot.getAbsolutePath());
+        }
     }
 
     @Test
@@ -288,7 +319,6 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
     public void
             testHandleClientsNotRespondingWithAnrMetricsFeatureDisabledOnEmptyProcessIdentifiers()
             throws Exception {
-        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
         List<ProcessIdentifier> processIdentifiers = new ArrayList<ProcessIdentifier>();
 
         mHelper.handleClientsNotResponding(processIdentifiers);
@@ -307,7 +337,7 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         List<ProcessIdentifier> expectedProcessIdentifiers = new ArrayList<ProcessIdentifier>();
 
         ProcessIdentifier processIdentifier1 = new ProcessIdentifier();
-        processIdentifier1.processName = "name1";
+        processIdentifier1.processName = "process1";
         processIdentifier1.pid = 1;
         processIdentifier1.uid = testUid1;
         processIdentifier1.startTimeMillis = 1000;
@@ -315,7 +345,7 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         expectedProcessIdentifiers.add(processIdentifier1);
 
         ProcessIdentifier processIdentifier2 = new ProcessIdentifier();
-        processIdentifier2.processName = "name2";
+        processIdentifier2.processName = "process2";
         processIdentifier2.pid = 2;
         processIdentifier2.uid = testUid1;
         processIdentifier2.startTimeMillis = 2000;
@@ -323,7 +353,7 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         expectedProcessIdentifiers.add(processIdentifier2);
 
         ProcessIdentifier processIdentifier3 = new ProcessIdentifier();
-        processIdentifier3.processName = "name3";
+        processIdentifier3.processName = "process3";
         processIdentifier3.pid = 3;
         processIdentifier3.uid = testUid2;
         processIdentifier3.startTimeMillis = 3000;
@@ -331,10 +361,10 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         expectedProcessIdentifiers.add(processIdentifier3);
 
         ProcessIdentifier processIdentifier4 = new ProcessIdentifier();
-        processIdentifier4.processName = "name4";
+        processIdentifier4.processName = "process4";
         processIdentifier4.pid = 4;
         processIdentifier4.uid = testUid2;
-        processIdentifier4.startTimeMillis = 4000;
+        processIdentifier4.startTimeMillis = 500;
         processIdentifiers.add(processIdentifier4);
 
         List<Integer> expectedPids = new ArrayList<>();
@@ -342,13 +372,6 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
             expectedPids.add(processIdentifier.pid);
         }
 
-        CarServiceHelperService.ProcessInfo invalidProcess =
-                new CarServiceHelperService.ProcessInfo(4,
-                    CarServiceHelperService.ProcessInfo.UNKNOWN_PROCESS,
-                    5000);
-
-        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
-        doReturn(invalidProcess).when(() -> CarServiceHelperService.getProcessInfo(4));
         doReturn(null).when(() -> StackTracesDumpHelper.dumpStackTraces(any(), any(), any(), any(),
                 any(), any(), any()));
         doReturn(mMockPath).when(() -> Files.readSymbolicLink(any()));
@@ -378,34 +401,33 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
 
     @Test
     public void testHandleClientsNotRespondingWithAnrMetricsFeatureDisabled() throws Exception {
-        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
         int testUid1 = 1001;
         int testUid2 = 1002;
         List<ProcessIdentifier> expectedProcessIdentifiers = new ArrayList<ProcessIdentifier>();
 
         ProcessIdentifier processIdentifier1 = new ProcessIdentifier();
-        processIdentifier1.processName = "name1";
+        processIdentifier1.processName = "process1";
         processIdentifier1.pid = 1;
         processIdentifier1.uid = testUid1;
         processIdentifier1.startTimeMillis = 1000;
         expectedProcessIdentifiers.add(processIdentifier1);
 
         ProcessIdentifier processIdentifier2 = new ProcessIdentifier();
-        processIdentifier2.processName = "name2";
+        processIdentifier2.processName = "process2";
         processIdentifier2.pid = 2;
         processIdentifier2.uid = testUid1;
         processIdentifier2.startTimeMillis = 2000;
         expectedProcessIdentifiers.add(processIdentifier2);
 
         ProcessIdentifier processIdentifier3 = new ProcessIdentifier();
-        processIdentifier3.processName = "name3";
+        processIdentifier3.processName = "process3";
         processIdentifier3.pid = 3;
         processIdentifier3.uid = testUid2;
         processIdentifier3.startTimeMillis = 3000;
         expectedProcessIdentifiers.add(processIdentifier3);
 
         ProcessIdentifier processIdentifier4 = new ProcessIdentifier();
-        processIdentifier4.processName = "name4";
+        processIdentifier4.processName = "process4";
         processIdentifier4.pid = 4;
         processIdentifier4.uid = testUid2;
         processIdentifier4.startTimeMillis = 4000;
@@ -446,7 +468,6 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
 
     @Test
     public void testHandleClientsNotRespondingOnEmptyClientsNotRespondingInfo() throws Exception {
-        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
         List<ProcessIdentifier> processIdentifiers = new ArrayList<ProcessIdentifier>();
 
         ClientsNotRespondingInfo clientsNotRespondingInfo = new ClientsNotRespondingInfo();
@@ -468,7 +489,7 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         List<ProcessIdentifier> expectedProcessIdentifiers = new ArrayList<ProcessIdentifier>();
 
         ProcessIdentifier processIdentifier1 = new ProcessIdentifier();
-        processIdentifier1.processName = "name1";
+        processIdentifier1.processName = "process1";
         processIdentifier1.pid = 1;
         processIdentifier1.uid = testUid1;
         processIdentifier1.startTimeMillis = 1000;
@@ -476,7 +497,7 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         expectedProcessIdentifiers.add(processIdentifier1);
 
         ProcessIdentifier processIdentifier2 = new ProcessIdentifier();
-        processIdentifier2.processName = "name2";
+        processIdentifier2.processName = "process2";
         processIdentifier2.pid = 2;
         processIdentifier2.uid = testUid1;
         processIdentifier2.startTimeMillis = 2000;
@@ -484,7 +505,7 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         expectedProcessIdentifiers.add(processIdentifier2);
 
         ProcessIdentifier processIdentifier3 = new ProcessIdentifier();
-        processIdentifier3.processName = "name3";
+        processIdentifier3.processName = "process3";
         processIdentifier3.pid = 3;
         processIdentifier3.uid = testUid2;
         processIdentifier3.startTimeMillis = 3000;
@@ -492,10 +513,10 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         expectedProcessIdentifiers.add(processIdentifier3);
 
         ProcessIdentifier processIdentifier4 = new ProcessIdentifier();
-        processIdentifier4.processName = "name4";
+        processIdentifier4.processName = "process4";
         processIdentifier4.pid = 4;
         processIdentifier4.uid = testUid2;
-        processIdentifier4.startTimeMillis = 4000;
+        processIdentifier4.startTimeMillis = 500;
         processIdentifiers.add(processIdentifier4);
 
         List<Integer> expectedPids = new ArrayList<>();
@@ -507,13 +528,6 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         clientsNotRespondingInfo.processIdentifiers = processIdentifiers;
         clientsNotRespondingInfo.garageMode = GarageMode.GARAGE_MODE_ON;
 
-        CarServiceHelperService.ProcessInfo invalidProcess =
-                new CarServiceHelperService.ProcessInfo(4,
-                    CarServiceHelperService.ProcessInfo.UNKNOWN_PROCESS,
-                    5000);
-
-        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
-        doReturn(invalidProcess).when(() -> CarServiceHelperService.getProcessInfo(4));
         doReturn(null).when(() -> StackTracesDumpHelper.dumpStackTraces(any(), any(), any(), any(),
                 any(), any(), any()));
         doReturn(mMockPath).when(() -> Files.readSymbolicLink(any()));
@@ -560,34 +574,33 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
 
     @Test
     public void testHandleClientsNotResponding() throws Exception {
-        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
         int testUid1 = 1001;
         int testUid2 = 1002;
         List<ProcessIdentifier> expectedProcessIdentifiers = new ArrayList<ProcessIdentifier>();
 
         ProcessIdentifier processIdentifier1 = new ProcessIdentifier();
-        processIdentifier1.processName = "name1";
+        processIdentifier1.processName = "process1";
         processIdentifier1.pid = 1;
         processIdentifier1.uid = testUid1;
         processIdentifier1.startTimeMillis = 1000;
         expectedProcessIdentifiers.add(processIdentifier1);
 
         ProcessIdentifier processIdentifier2 = new ProcessIdentifier();
-        processIdentifier2.processName = "name2";
+        processIdentifier2.processName = "process2";
         processIdentifier2.pid = 2;
         processIdentifier2.uid = testUid1;
         processIdentifier2.startTimeMillis = 2000;
         expectedProcessIdentifiers.add(processIdentifier2);
 
         ProcessIdentifier processIdentifier3 = new ProcessIdentifier();
-        processIdentifier3.processName = "name3";
+        processIdentifier3.processName = "process3";
         processIdentifier3.pid = 3;
         processIdentifier3.uid = testUid2;
         processIdentifier3.startTimeMillis = 3000;
         expectedProcessIdentifiers.add(processIdentifier3);
 
         ProcessIdentifier processIdentifier4 = new ProcessIdentifier();
-        processIdentifier4.processName = "name4";
+        processIdentifier4.processName = "process4";
         processIdentifier4.pid = 4;
         processIdentifier4.uid = testUid2;
         processIdentifier4.startTimeMillis = 4000;
@@ -728,4 +741,34 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
         serviceDebugInfo.debugPid = debugPid;
         return serviceDebugInfo;
     }
+
+    private void copyAssets(String assetPath, File targetRoot) throws Exception {
+        File target = new File(targetRoot, assetPath);
+        String[] assets = mAssetManager.list(assetPath);
+        if (assets == null || assets.length == 0) {
+            try (InputStream in = mAssetManager.open(assetPath);
+                    OutputStream out = new FileOutputStream(target)) {
+                Streams.copy(in, out);
+            }
+            return;
+        }
+        assertWithMessage("Make target directory %s", target).that(target.mkdir()).isTrue();
+        for (int i = 0; i < assets.length; i++) {
+            copyAssets(String.format("%s%s%s", assetPath, File.separator, assets[i]), targetRoot);
+        }
+    }
+
+    private static boolean deleteDirectory(File rootDir) {
+        if (!rootDir.exists() || !rootDir.isDirectory()) {
+            return false;
+        }
+        for (File file : Objects.requireNonNull(rootDir.listFiles())) {
+            if (file.isDirectory()) {
+                deleteDirectory(file);
+            } else if (!file.delete()) {
+                return false;
+            }
+        }
+        return rootDir.delete();
+    }
 }
diff --git a/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java b/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
index 0c1a8cf..a7e0b0e 100644
--- a/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
+++ b/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
@@ -27,7 +27,6 @@ import android.car.ICarResultReceiver;
 import android.car.builtin.os.UserManagerHelper;
 import android.car.builtin.util.EventLogHelper;
 import android.car.builtin.util.Slogf;
-import android.car.feature.Flags;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
@@ -54,6 +53,7 @@ import com.android.internal.car.CarServiceHelperInterface;
 import com.android.internal.car.CarServiceHelperServiceUpdatable;
 import com.android.server.wm.CarActivityInterceptorInterface;
 import com.android.server.wm.CarActivityInterceptorUpdatableImpl;
+import com.android.server.wm.CarDisplayCompatActivityInterceptor;
 import com.android.server.wm.CarDisplayCompatScaleProviderInterface;
 import com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl;
 import com.android.server.wm.CarLaunchParamsModifierInterface;
@@ -146,7 +146,8 @@ public final class CarServiceHelperServiceUpdatableImpl
         mCarActivityInterceptorUpdatable.registerInterceptor(/* index = */ 0,
                 new MediaTemplateActivityInterceptorForSuspension());
         mCarActivityInterceptorUpdatable.registerInterceptor(/* index = */ 1,
-                mCarDisplayCompatScaleProviderUpdatable);
+                new CarDisplayCompatActivityInterceptor(context,
+                       mCarDisplayCompatScaleProviderUpdatable));
         // Interceptor for redirecting launch on a private display or a root task
         mCarLaunchRedirectActivityInterceptor =
                 new CarLaunchRedirectActivityInterceptor(context);
@@ -450,11 +451,8 @@ public final class CarServiceHelperServiceUpdatableImpl
 
         @Override
         public boolean requiresDisplayCompatForUser(String packageName, int userId) {
-            if (Flags.displayCompatibilityCaptionBar()) {
-                return mCarDisplayCompatScaleProviderUpdatable.requiresDisplayCompat(packageName,
-                        userId);
-            }
-            return false;
+            return mCarDisplayCompatScaleProviderUpdatable.requiresDisplayCompat(packageName,
+                    userId);
         }
     }
 
diff --git a/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java b/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java
new file mode 100644
index 0000000..fe53e15
--- /dev/null
+++ b/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java
@@ -0,0 +1,182 @@
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
+package com.android.server.wm;
+
+import static android.content.pm.PackageManager.MATCH_SYSTEM_ONLY;
+import static android.content.pm.PackageManager.PERMISSION_GRANTED;
+import static android.view.Display.DEFAULT_DISPLAY;
+import static android.view.Display.INVALID_DISPLAY;
+
+import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.FEATURE_CAR_DISPLAY_COMPATIBILITY;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.SystemApi;
+import android.app.ActivityOptions;
+import android.car.builtin.util.Slogf;
+import android.car.feature.Flags;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.content.pm.PackageManager;
+import android.content.pm.ResolveInfo;
+import android.content.res.Resources;
+import android.os.ServiceSpecificException;
+import android.util.Log;
+
+import com.android.car.internal.dep.Trace;
+import com.android.internal.annotations.VisibleForTesting;
+
+/**
+ * This class handles launching the display compat host app.
+ *
+ * @hide
+ */
+@SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
+public final class CarDisplayCompatActivityInterceptor implements CarActivityInterceptorUpdatable {
+
+    public static final String TAG = CarDisplayCompatActivityInterceptor.class.getSimpleName();
+    private static final boolean DBG = Slogf.isLoggable(TAG, Log.DEBUG);
+    private static final ActivityOptionsWrapper EMPTY_LAUNCH_OPTIONS_WRAPPER =
+            ActivityOptionsWrapper.create(ActivityOptions.makeBasic());
+    @VisibleForTesting
+    static final String LAUNCHED_FROM_HOST =
+            "android.car.app.CarDisplayCompatManager.launched_from_host";
+    @VisibleForTesting
+    static final String LAUNCH_ACTIVITY_OPTIONS =
+            "android.car.app.CarDisplayCompatManager.launch_activity_options";
+    @VisibleForTesting
+    static final String PERMISSION_DISPLAY_COMPATIBILITY =
+            "android.car.permission.MANAGE_DISPLAY_COMPATIBILITY";
+    @NonNull
+    private final Context mContext;
+    @NonNull
+    private final CarDisplayCompatScaleProviderUpdatableImpl mDisplayCompatProvider;
+    @Nullable
+    private ComponentName mHostActivity;
+
+    public CarDisplayCompatActivityInterceptor(@NonNull Context context,
+            @NonNull CarDisplayCompatScaleProviderUpdatableImpl carDisplayCompatProvider) {
+        mContext = context;
+        mDisplayCompatProvider = carDisplayCompatProvider;
+        if (!Flags.displayCompatibility()) {
+            Slogf.i(TAG, "Flag %s is not enabled", Flags.FLAG_DISPLAY_COMPATIBILITY);
+            return;
+        }
+        PackageManager packageManager = context.getPackageManager();
+        if (packageManager == null) {
+            // This happens during tests where mock context is used.
+            return;
+        }
+        if (!packageManager.hasSystemFeature(FEATURE_CAR_DISPLAY_COMPATIBILITY)) {
+            Slogf.i(TAG, "Feature %s is not available", FEATURE_CAR_DISPLAY_COMPATIBILITY);
+            return;
+        }
+        Resources r = context.getResources();
+        if (r == null) {
+            // This happens during tests where mock context is used.
+            Slogf.e(TAG, "Couldn't read DisplayCompat host activity.");
+            return;
+        }
+        int id = r.getIdentifier("config_defaultDisplayCompatHostActivity", "string", "android");
+        if (id != 0) {
+            mHostActivity = ComponentName.unflattenFromString(r.getString(id));
+            if (mHostActivity == null) {
+                Slogf.e(TAG, "Couldn't read DisplayCompat host activity.");
+                return;
+            }
+            Intent intent = new Intent();
+            intent.setComponent(mHostActivity);
+            ResolveInfo ri = packageManager.resolveActivity(intent,
+                    PackageManager.ResolveInfoFlags.of(MATCH_SYSTEM_ONLY));
+            if (ri == null) {
+                Slogf.e(TAG, "Couldn't resolve DisplayCompat host activity. %s", mHostActivity);
+                mHostActivity = null;
+                return;
+            }
+        }
+    }
+
+    @Override
+    public ActivityInterceptResultWrapper onInterceptActivityLaunch(
+            ActivityInterceptorInfoWrapper info) {
+        if (mHostActivity == null) {
+            return null;
+        }
+        Intent launchIntent = info.getIntent();
+        if (launchIntent == null || launchIntent.getComponent() == null) {
+            return null;
+        }
+        try {
+            Trace.beginSection(
+                    "CarDisplayActivity-onInterceptActivityLaunchIntentComponent: "
+                            + launchIntent.getComponent());
+            boolean requiresDisplayCompat = mDisplayCompatProvider
+                    .requiresDisplayCompat(launchIntent.getComponent().getPackageName(),
+                            info.getUserId());
+            if (!requiresDisplayCompat) {
+                return null;
+            }
+
+            boolean isLaunchedFromHost = launchIntent
+                    .getBooleanExtra(LAUNCHED_FROM_HOST, false);
+            int callingPid = info.getCallingPid();
+            int callingUid = info.getCallingUid();
+            boolean hasPermission = (mContext.checkPermission(
+                    PERMISSION_DISPLAY_COMPATIBILITY, callingPid, callingUid)
+                            == PERMISSION_GRANTED);
+            if (isLaunchedFromHost && !hasPermission) {
+                Slogf.e(TAG, "Calling package (%s) doesn't have required permissions %s",
+                        info.getCallingPackage(),
+                        PERMISSION_DISPLAY_COMPATIBILITY);
+                // fall-through, we'll launch the host instead.
+            }
+
+            mDisplayCompatProvider.onInterceptActivityLaunch(info);
+
+            ActivityOptionsWrapper launchOptions = info.getCheckedOptions();
+            if (launchOptions == null) {
+                launchOptions = EMPTY_LAUNCH_OPTIONS_WRAPPER;
+            }
+            if (!isLaunchedFromHost || (isLaunchedFromHost && !hasPermission)) {
+                // Launch the host
+                Intent intent = new Intent();
+                intent.setComponent(mHostActivity);
+
+                intent.putExtra(Intent.EXTRA_INTENT, launchIntent);
+                intent.putExtra(LAUNCH_ACTIVITY_OPTIONS, launchOptions.getOptions().toBundle());
+
+                // Launch host on the display that the app was supposed to be launched.
+                ActivityOptionsWrapper optionsWrapper =
+                        ActivityOptionsWrapper.create(ActivityOptions.makeBasic());
+                int launchDisplayId = launchOptions.getOptions().getLaunchDisplayId();
+                int hostDisplayId = (launchDisplayId == INVALID_DISPLAY)
+                        ? DEFAULT_DISPLAY : launchDisplayId;
+                if (DBG) {
+                    Slogf.d(TAG, "DisplayCompat host displayId %d LaunchDisplayId %d",
+                            hostDisplayId, launchDisplayId);
+                }
+                optionsWrapper.setLaunchDisplayId(hostDisplayId);
+                return ActivityInterceptResultWrapper.create(intent, optionsWrapper.getOptions());
+            }
+        } catch (ServiceSpecificException e) {
+            Slogf.e(TAG, "Error while intercepting activity " + launchIntent.getComponent(), e);
+        } finally {
+            Trace.endSection();
+        }
+        return null;
+    }
+}
diff --git a/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
index 6c96046..4c4e5e3 100644
--- a/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
@@ -50,7 +50,6 @@ import android.content.pm.PackageManager.PackageInfoFlags;
 import android.content.res.CompatScaleWrapper;
 import android.database.ContentObserver;
 import android.net.Uri;
-import android.os.Bundle;
 import android.os.Environment;
 import android.os.Handler;
 import android.os.ServiceSpecificException;
@@ -90,8 +89,6 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
     static final String FEATURE_CAR_DISPLAY_COMPATIBILITY =
             "android.software.car.display_compatibility";
     @VisibleForTesting
-    static final String META_DATA_DISTRACTION_OPTIMIZED = "distractionOptimized";
-    @VisibleForTesting
     static final String PLATFORM_PACKAGE_NAME = "android";
     private static final String CONFIG_PATH = "etc/display_compat_config.xml";
     // {@code android.os.UserHandle.USER_NULL}
@@ -115,6 +112,9 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
     private final PackageManager mPackageManager;
     @NonNull
     private final CarDisplayCompatScaleProviderInterface mCarCompatScaleProviderInterface;
+    @NonNull
+    // Class-level variable to store the last dumped configuration
+    private String mLastConfigDump = "";
 
     // {@link StampedLock} is used for 2 reasons
     // 1) the # of reads is way higher than # of writes.
@@ -330,6 +330,11 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
 
     @Override
     public boolean requiresDisplayCompat(@NonNull String packageName, @UserIdInt int userId) {
+        if (mPackageManager != null
+                && !mPackageManager.hasSystemFeature(FEATURE_CAR_DISPLAY_COMPATIBILITY)) {
+            Slogf.d(TAG, "Feature %s is not available", FEATURE_CAR_DISPLAY_COMPATIBILITY);
+            return false;
+        }
         long stamp = mConfigLock.tryOptimisticRead();
         Boolean res = mRequiresDisplayCompat.get(packageName);
         if (!mConfigLock.validate(stamp)) {
@@ -457,48 +462,39 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         int displayId = getPackageDisplayIdAsUserLocked(packageName, userId);
         CarDisplayCompatConfig.Key key =
                 new CarDisplayCompatConfig.Key(displayId, packageName, userId);
+
+        // Try to get the scale factor for the specific user and package
         float scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-        boolean hasConfig = true;
-        if (scaleFactor == NO_SCALE) {
-            key.mUserId = UserHandle.ALL.getIdentifier();
-            scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-            if (scaleFactor == NO_SCALE) {
-                hasConfig = false;
-            }
-        }
+        boolean hasConfig = (scaleFactor != NO_SCALE);
 
-        boolean result = requiresDisplayCompatNotCachedLocked(packageName, userId);
-        if (!hasConfig && !result) {
-            // Package is opt-out
-            mConfig.setScaleFactor(key, OPT_OUT);
-        } else if (!hasConfig && result) {
-            // Apply user default scale or display default scale to the package
-            key.mPackageName = ANY_PACKAGE;
-            key.mUserId = userId;
-            scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-            if (scaleFactor == NO_SCALE) {
-                key.mUserId = UserHandle.ALL.getIdentifier();
-                scaleFactor = mConfig.getScaleFactor(key, DEFAULT_SCALE);
-            }
+        // Check if display compatibility is required
+        boolean requiresCompat = requiresDisplayCompatNotCachedLocked(packageName, userId);
+
+        // If no config was found earlier and compatibility is required, apply default scale
+        if (!hasConfig && requiresCompat) {
+            scaleFactor = getPackageScaleFactor(key, packageName, userId);
             mConfig.setScaleFactor(key, scaleFactor);
-        } else if (hasConfig) {
-            // Package was opt-out, but now is opt-in or the otherway around
-            mConfig.setScaleFactor(key, result ? abs(scaleFactor) : -1 * abs(scaleFactor));
         }
 
-        mRequiresDisplayCompat.put(packageName, result);
-        mCarCompatScaleProviderInterface.putStringForUser(mContext.getContentResolver(),
-                DISPLAYCOMPAT_SETTINGS_SECURE_KEY, mConfig.dump(),
-                getCurrentOrTargetUserId());
+        Boolean cachedValue = mRequiresDisplayCompat.get(packageName);
+        if (cachedValue == null || cachedValue != requiresCompat) {
+            mRequiresDisplayCompat.put(packageName, requiresCompat);
+        }
+
+        String configDump = mConfig.dump();
+        if (!configDump.equals(mLastConfigDump)) {
+            mCarCompatScaleProviderInterface.putStringForUser(mContext.getContentResolver(),
+                    DISPLAYCOMPAT_SETTINGS_SECURE_KEY, configDump, getCurrentOrTargetUserId());
+            mLastConfigDump = configDump;
+        }
 
-        return result;
+        return requiresCompat;
     }
 
     // @GuardedBy("mConfigLock")
     // TODO(b/343755550): add back when error-prone supports {@link StampedLock}
     private boolean requiresDisplayCompatNotCachedLocked(@NonNull String packageName,
             @UserIdInt int userId) throws PackageManager.NameNotFoundException {
-
         UserHandle userHandle = UserHandle.of(userId);
         ApplicationInfoFlags appFlags = ApplicationInfoFlags.of(GET_META_DATA);
         ApplicationInfo applicationInfo = mPackageManager
@@ -542,21 +538,6 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
             return false;
         }
 
-        // Opt out if has at least 1 activity that has
-        // {@code META_DATA_DISTRACTION_OPTIMIZED} metadata set to true
-        // This case should prevent NDO apps to accidentally launch in display compat host.
-        for (ActivityInfo ai : pkgInfo.activities) {
-            Bundle activityMetaData = ai.metaData;
-            if (activityMetaData != null && activityMetaData
-                    .getBoolean(META_DATA_DISTRACTION_OPTIMIZED)) {
-                if (isDebugLoggable()) {
-                    Slogf.d(TAG, "Package %s has %s", packageName,
-                            META_DATA_DISTRACTION_OPTIMIZED);
-                }
-                return false;
-            }
-        }
-
         if (applicationInfo != null) {
             // Opt out if it's a privileged package
             if (applicationInfo.isPrivilegedApp()) {
@@ -588,6 +569,41 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         return true;
     }
 
+    private float getPackageScaleFactor(CarDisplayCompatConfig.Key key, String packageName,
+                int userId) {
+        // First try the global package config for the given user
+        key.mPackageName = ANY_PACKAGE;
+        float scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
+        // Re-apply package name
+        key.mPackageName = packageName;
+
+        if (scaleFactor != NO_SCALE) {
+            return scaleFactor;
+
+        }
+
+        // Next try to get the global user config for the package
+        key.mUserId = UserHandle.ALL.getIdentifier();
+        scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
+        // Re-apply the user-specific config
+        key.mUserId = userId;
+
+        if (scaleFactor != NO_SCALE) {
+            return scaleFactor;
+        }
+
+        // Check global package and global user config
+        key.mUserId = UserHandle.ALL.getIdentifier();
+        key.mPackageName = ANY_PACKAGE; // Default package
+        scaleFactor = mConfig.getScaleFactor(key, DEFAULT_SCALE);
+
+        // Reapply specific package and user values
+        key.mPackageName = packageName;
+        key.mUserId = userId;
+
+        return scaleFactor;
+    }
+
     /**
      * @return {@code true} if local config and settings is successfully updated, false otherwise.
      */
@@ -661,26 +677,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         if (scaleFactor != NO_SCALE) {
             return new CompatScaleWrapper(DEFAULT_SCALE, abs(scaleFactor));
         }
-        // Query the scale factor for all packages for a specific user.
-        key.mPackageName = ANY_PACKAGE;
-        scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-        if (scaleFactor != NO_SCALE) {
-            return new CompatScaleWrapper(DEFAULT_SCALE, abs(scaleFactor));
-        }
-        // Query the scale factor for a specific package across all users.
-        key.mPackageName = packageName;
-        key.mUserId = UserHandle.ALL.getIdentifier();
-        scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-        if (scaleFactor != NO_SCALE) {
-            return new CompatScaleWrapper(DEFAULT_SCALE, abs(scaleFactor));
-        }
-        // Query the scale factor for a specific display regardless of
-        // user or package name.
-        key.mPackageName = ANY_PACKAGE;
-        scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-        if (scaleFactor != NO_SCALE) {
-            return new CompatScaleWrapper(DEFAULT_SCALE, abs(scaleFactor));
-        }
+
         return null;
     }
 
diff --git a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatActivityInterceptorTest.java b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatActivityInterceptorTest.java
new file mode 100644
index 0000000..b3dd895
--- /dev/null
+++ b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatActivityInterceptorTest.java
@@ -0,0 +1,290 @@
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
+package com.android.server.wm;
+
+import static android.car.feature.Flags.FLAG_DISPLAY_COMPATIBILITY;
+import static android.content.pm.PackageManager.PERMISSION_DENIED;
+import static android.content.pm.PackageManager.PERMISSION_GRANTED;
+import static android.view.Display.DEFAULT_DISPLAY;
+import static android.view.Display.INVALID_DISPLAY;
+
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
+import static com.android.server.wm.CarDisplayCompatActivityInterceptor.LAUNCHED_FROM_HOST;
+import static com.android.server.wm.CarDisplayCompatActivityInterceptor.PERMISSION_DISPLAY_COMPATIBILITY;
+import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.FEATURE_CAR_DISPLAY_COMPATIBILITY;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.when;
+
+import android.app.ActivityOptions;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.content.pm.PackageManager;
+import android.content.pm.PackageManager.ResolveInfoFlags;
+import android.content.pm.ResolveInfo;
+import android.content.res.Resources;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
+
+@RequiresFlagsEnabled(FLAG_DISPLAY_COMPATIBILITY)
+@RunWith(AndroidJUnit4.class)
+public class CarDisplayCompatActivityInterceptorTest {
+
+    @Rule
+    public final CheckFlagsRule checkFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    private MockitoSession mMockingSession;
+
+    @Mock
+    private Resources mMockResources;
+    @Mock
+    private Context mMockContext;
+    @Mock
+    private PackageManager mMockPackageManager;
+    @Mock
+    private CarDisplayCompatScaleProviderUpdatableImpl mMockCarDisplayCompatScaleProvider;
+    @Mock
+    private ActivityInterceptorInfoWrapper mMockInfo;
+
+
+    private CarDisplayCompatActivityInterceptor mInterceptor;
+    private ComponentName mHostActitivy = ComponentName.unflattenFromString(
+            "com.displaycompathost/.StartActivity");
+
+    @Before
+    public void setUp() {
+        mMockingSession = mockitoSession()
+            .initMocks(this)
+            .strictness(Strictness.LENIENT)
+            .startMocking();
+
+        when(mMockResources.getIdentifier(
+                eq("config_defaultDisplayCompatHostActivity"), eq("string"), eq("android")
+        )).thenReturn(1);
+        when(mMockResources.getString(eq(1))).thenReturn(mHostActitivy.flattenToString());
+        when(mMockContext.getResources()).thenReturn(mMockResources);
+        when(mMockPackageManager.hasSystemFeature(FEATURE_CAR_DISPLAY_COMPATIBILITY))
+                .thenReturn(true);
+        when(mMockPackageManager.resolveActivity(any(Intent.class), any(ResolveInfoFlags.class)))
+                .thenReturn(mock(ResolveInfo.class));
+        when(mMockContext.getPackageManager()).thenReturn(mMockPackageManager);
+
+        mInterceptor = new CarDisplayCompatActivityInterceptor(mMockContext,
+                mMockCarDisplayCompatScaleProvider);
+    }
+
+    @After
+    public void tearDown() {
+        // If the exception is thrown during the MockingSession setUp, mMockingSession can be null.
+        if (mMockingSession != null) {
+            mMockingSession.finishMocking();
+        }
+    }
+
+    @Test
+    public void hostActivity_isIgnored() {
+        Intent intent = new Intent(Intent.ACTION_MAIN);
+        intent.setComponent(mHostActitivy);
+
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    @Test
+    public void nonDisplayCompatActivity_isIgnored() {
+        Intent intent = getNoDisplayCompatRequiredActivity();
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    @Test
+    public void displayCompatActivity_launchedFromHost_isIgnored() {
+        Intent intent = getDisplayCompatRequiredActivity();
+        String packageName = intent.getComponent().getPackageName();
+        intent.putExtra(LAUNCHED_FROM_HOST, true);
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        when(mMockInfo.getCallingPackage()).thenReturn(packageName);
+        when(mMockInfo.getCallingPid()).thenReturn(1);
+        when(mMockInfo.getCallingUid()).thenReturn(2);
+        when(mMockContext.checkPermission(PERMISSION_DISPLAY_COMPATIBILITY, 1, 2))
+                .thenReturn(PERMISSION_GRANTED);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    @Test
+    public void displayCompatActivity_returnsHost() {
+        Intent intent = getDisplayCompatRequiredActivity();
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNotNull();
+        assertThat(result.getInterceptResult()).isNotNull();
+        assertThat(result.getInterceptResult().getIntent()).isNotNull();
+        assertThat(result.getInterceptResult().getIntent().getComponent()).isEqualTo(mHostActitivy);
+        Intent launchIntent = (Intent) result.getInterceptResult().getIntent()
+                .getExtra(Intent.EXTRA_INTENT);
+        assertThat(launchIntent).isNotNull();
+    }
+
+    @Test
+    public void displayCompatActivity_launchedFromDisplayCompatApp_returnsHost() {
+        Intent intent = getDisplayCompatRequiredActivity();
+        String packageName = intent.getComponent().getPackageName();
+        when(mMockInfo.getIntent()).thenReturn(intent);
+        when(mMockCarDisplayCompatScaleProvider
+                .requiresDisplayCompat(eq(packageName), any(int.class)))
+                .thenReturn(true);
+
+        when(mMockInfo.getCallingPackage()).thenReturn(packageName);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNotNull();
+        assertThat(result.getInterceptResult()).isNotNull();
+        assertThat(result.getInterceptResult().getIntent()).isNotNull();
+        assertThat(result.getInterceptResult().getIntent().getComponent()).isEqualTo(mHostActitivy);
+        Intent launchIntent = (Intent) result.getInterceptResult().getIntent()
+                .getExtra(Intent.EXTRA_INTENT);
+        assertThat(launchIntent).isNotNull();
+    }
+
+    @Test
+    public void displayCompatActivity_noPermission_returnsHost() {
+        Intent intent = getDisplayCompatRequiredActivity();
+        String packageName = intent.getComponent().getPackageName();
+        intent.putExtra(LAUNCHED_FROM_HOST, true);
+        when(mMockInfo.getIntent()).thenReturn(intent);
+        when(mMockCarDisplayCompatScaleProvider
+                .requiresDisplayCompat(eq(packageName), any(int.class)))
+                .thenReturn(true);
+
+        when(mMockInfo.getCallingPackage()).thenReturn(packageName);
+        when(mMockInfo.getCallingPid()).thenReturn(1);
+        when(mMockInfo.getCallingUid()).thenReturn(2);
+        when(mMockContext.checkPermission(PERMISSION_DISPLAY_COMPATIBILITY, 1, 2))
+                .thenReturn(PERMISSION_DENIED);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNotNull();
+        assertThat(result.getInterceptResult()).isNotNull();
+        assertThat(result.getInterceptResult().getIntent()).isNotNull();
+        assertThat(result.getInterceptResult().getIntent().getComponent()).isEqualTo(mHostActitivy);
+        Intent launchIntent = (Intent) result.getInterceptResult().getIntent()
+                .getExtra(Intent.EXTRA_INTENT);
+        assertThat(launchIntent).isNotNull();
+    }
+
+    @Test
+    public void hostActivity_whenNoLaunchDisplayId_launchesOnDefaultDisplay() {
+        Intent intent = getDisplayCompatRequiredActivity();
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        ActivityOptions mockActivityOptions = mock(ActivityOptions.class);
+        when(mockActivityOptions.getLaunchDisplayId()).thenReturn(INVALID_DISPLAY);
+        ActivityOptionsWrapper mockActivityOptionsWrapper = mock(ActivityOptionsWrapper.class);
+        when(mockActivityOptionsWrapper.getOptions()).thenReturn(mockActivityOptions);
+        when(mMockInfo.getCheckedOptions()).thenReturn(mockActivityOptionsWrapper);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result.getInterceptResult().getActivityOptions().getLaunchDisplayId())
+                .isEqualTo(DEFAULT_DISPLAY);
+    }
+
+    @Test
+    public void hostActivity_withLaunchDisplayId_launchesOnCorrectDisplay() {
+        Intent intent = getDisplayCompatRequiredActivity();
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        ActivityOptions mockActivityOptions = mock(ActivityOptions.class);
+        when(mockActivityOptions.getLaunchDisplayId()).thenReturn(2);
+        ActivityOptionsWrapper mockActivityOptionsWrapper = mock(ActivityOptionsWrapper.class);
+        when(mockActivityOptionsWrapper.getOptions()).thenReturn(mockActivityOptions);
+        when(mMockInfo.getCheckedOptions()).thenReturn(mockActivityOptionsWrapper);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result.getInterceptResult().getActivityOptions().getLaunchDisplayId())
+                .isEqualTo(2);
+    }
+
+    /**
+     * Returns an {@link Intent} associated with an {@link Activity} that does not need to run in
+     * display compat mode.
+     */
+    private Intent getNoDisplayCompatRequiredActivity() {
+        ComponentName displayCompatActivity =
+                ComponentName.unflattenFromString("com.test/.NoDisplayCompatRequiredActivity");
+        Intent intent = new Intent(Intent.ACTION_MAIN);
+        intent.setComponent(displayCompatActivity);
+        when(mMockCarDisplayCompatScaleProvider
+                .requiresDisplayCompat(eq(displayCompatActivity.getPackageName()), any(int.class)))
+                .thenReturn(false);
+        return intent;
+    }
+
+    /**
+     * Returns an {@link Intent} associated with an {@link Activity} that needs to run in
+     * display compat mode.
+     */
+    private Intent getDisplayCompatRequiredActivity() {
+        ComponentName displayCompatActivity =
+                ComponentName.unflattenFromString("com.test/.DisplayCompatRequiredActivity");
+        Intent intent = new Intent(Intent.ACTION_MAIN);
+        intent.setComponent(displayCompatActivity);
+        when(mMockCarDisplayCompatScaleProvider
+                .requiresDisplayCompat(eq(displayCompatActivity.getPackageName()), any(int.class)))
+                .thenReturn(true);
+        return intent;
+    }
+}
diff --git a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
index 3d61757..77156e8 100644
--- a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
+++ b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
@@ -29,11 +29,9 @@ import static android.view.Display.DEFAULT_DISPLAY;
 import static com.android.server.wm.CarDisplayCompatConfig.ANY_PACKAGE;
 import static com.android.server.wm.CarDisplayCompatConfig.DEFAULT_SCALE;
 import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.NO_SCALE;
-import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.OPT_OUT;
 import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.DATA_SCHEME_PACKAGE;
 import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.DISPLAYCOMPAT_SETTINGS_SECURE_KEY;
 import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.FEATURE_CAR_DISPLAY_COMPATIBILITY;
-import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.META_DATA_DISTRACTION_OPTIMIZED;
 import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.PLATFORM_PACKAGE_NAME;
 import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.USER_NULL;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
@@ -249,19 +247,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isFalse();
     }
 
-    @Test
-    public void hasDistractionOptimizedActivity_returnsFalse() throws NameNotFoundException {
-        ActivityInfo[] activities = new ActivityInfo[1];
-        activities[0] = new ActivityInfo();
-        activities[0].metaData = new Bundle();
-        activities[0].metaData.putBoolean(META_DATA_DISTRACTION_OPTIMIZED, true);
-        mPackageInfo.activities = activities;
-        when(mInterface.getPackageInfoAsUser(eq("package1"), any(PackageInfoFlags.class),
-                any(int.class))).thenReturn(mPackageInfo);
-
-        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isFalse();
-    }
-
     @Test
     public void isPrivileged_returnsFalse() throws NameNotFoundException {
         ActivityInfo[] activities = new ActivityInfo[1];
@@ -327,13 +312,12 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
                 any(ApplicationInfoFlags.class), any(UserHandle.class)))
                         .thenReturn(mApplicationInfo);
 
-        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
-
         CarDisplayCompatConfig.Key key =
                 new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, ANY_PACKAGE,
                         UserHandle.ALL.getIdentifier());
         mConfig.setScaleFactor(key, 0.5f);
 
+        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
     }
@@ -351,16 +335,15 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
                 any(ApplicationInfoFlags.class), any(UserHandle.class)))
                         .thenReturn(mApplicationInfo);
 
-        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
-
         CarDisplayCompatConfig.Key key =
                 new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, "package1",
                         UserHandle.ALL.getIdentifier());
         mConfig.setScaleFactor(key, 0.5f);
+
+        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
-        assertThat(mImpl.getCompatScale("package2", CURRENT_USER).getDensityScaleFactor())
-                .isEqualTo(DEFAULT_SCALE);
+        assertThat(mImpl.getCompatScale("package2", CURRENT_USER)).isNull();
     }
 
     @Test
@@ -376,17 +359,16 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
                 any(ApplicationInfoFlags.class), any(UserHandle.class)))
                         .thenReturn(mApplicationInfo);
 
-        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
-        assertThat(mImpl.requiresDisplayCompat("package1", ANOTHER_USER)).isTrue();
 
         CarDisplayCompatConfig.Key key =
                 new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, ANY_PACKAGE, CURRENT_USER);
         mConfig.setScaleFactor(key, 0.5f);
 
+        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
+        assertThat(mImpl.requiresDisplayCompat("package1", ANOTHER_USER)).isTrue();
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
-        assertThat(mImpl.getCompatScale("package1", ANOTHER_USER).getDensityScaleFactor())
-                .isEqualTo(DEFAULT_SCALE);
+        assertThat(mImpl.getCompatScale("package1", ANOTHER_USER)).isNull();
     }
 
     @Test
@@ -420,10 +402,8 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
 
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
-        assertThat(mImpl.getCompatScale("package1", ANOTHER_USER).getDensityScaleFactor())
-                .isEqualTo(DEFAULT_SCALE);
-        assertThat(mImpl.getCompatScale("package2", CURRENT_USER).getDensityScaleFactor())
-                .isEqualTo(DEFAULT_SCALE);
+        assertThat(mImpl.getCompatScale("package1", ANOTHER_USER)).isNull();
+        assertThat(mImpl.getCompatScale("package2", CURRENT_USER)).isNull();
     }
 
     @Test
@@ -440,7 +420,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
                 any(ApplicationInfoFlags.class), any(UserHandle.class)))
                         .thenReturn(mApplicationInfo);
 
-        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
 
         CarDisplayCompatConfig.Key key =
                 new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, "package1", CURRENT_USER);
@@ -449,6 +428,7 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         mConfig.setScaleFactor(key, 0.5f);
         mConfig.setScaleFactor(key1, 0.6f);
 
+        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
     }
@@ -466,8 +446,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
                 any(ApplicationInfoFlags.class), any(UserHandle.class)))
                         .thenReturn(mApplicationInfo);
 
-        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
-
         CarDisplayCompatConfig.Key key =
                 new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, ANY_PACKAGE, CURRENT_USER);
         CarDisplayCompatConfig.Key key1 =
@@ -476,6 +454,7 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         mConfig.setScaleFactor(key, 0.5f);
         mConfig.setScaleFactor(key1, 0.6f);
 
+        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
     }
@@ -493,7 +472,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
                 any(ApplicationInfoFlags.class), any(UserHandle.class)))
                         .thenReturn(mApplicationInfo);
 
-        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
 
         CarDisplayCompatConfig.Key key =
                 new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, "package1",
@@ -504,6 +482,7 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         mConfig.setScaleFactor(key, 0.5f);
         mConfig.setScaleFactor(key1, 0.6f);
 
+        assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isTrue();
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
     }
@@ -550,7 +529,7 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
                 new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, "package1",
                         UserHandle.ALL.getIdentifier());
 
-        assertThat(mConfig.getScaleFactor(key, NO_SCALE)).isEqualTo(OPT_OUT);
+        assertThat(mConfig.getScaleFactor(key, NO_SCALE)).isEqualTo(NO_SCALE);
     }
 
     @Test
@@ -702,9 +681,11 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
                 return new ByteArrayInputStream(configWithDisplayValue.getBytes());
             }
         };
+
+        mImpl.requiresDisplayCompat(pkg1Name, CURRENT_USER);
         CompatScaleWrapper result = mImpl.getCompatScale(pkg1Name, CURRENT_USER);
 
-        assertThat(result.getDensityScaleFactor()).isEqualTo(DEFAULT_SCALE);
+        assertThat(result).isNull();
     }
 
     @Test
diff --git a/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java b/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
index c3ca6f3..676f0d8 100644
--- a/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
+++ b/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
@@ -175,8 +175,10 @@ public class CarLaunchParamsModifierUpdatableTest {
 
         // Return the same id as the display for simplicity
         DisplayContent dc = mock(DisplayContent.class);
-        TaskDisplayArea defaultTaskDisplayArea = new TaskDisplayArea(dc, mWindowManagerService,
-                "defaultTDA#" + displayId, DisplayAreaOrganizer.FEATURE_DEFAULT_TASK_CONTAINER);
+        TaskDisplayArea defaultTaskDisplayArea = new TaskDisplayArea(mWindowManagerService,
+                "defaultTDA#" + displayId, DisplayAreaOrganizer.FEATURE_DEFAULT_TASK_CONTAINER,
+                false /* createdByOrganizer */, true /* canHostHomeTask */);
+        defaultTaskDisplayArea.mDisplayContent = dc;
         when(mRootWindowContainer.getDisplayContent(displayId)).thenReturn(dc);
         when(mRootWindowContainer.getDisplayContentOrCreate(displayId)).thenReturn(dc);
         when(dc.getDisplay()).thenReturn(display);
@@ -236,8 +238,9 @@ public class CarLaunchParamsModifierUpdatableTest {
         mDisplayArea0ForDriver = mockDisplay(mDisplay0ForDriver, DEFAULT_DISPLAY,
                 FLAG_TRUSTED, /* type= */ 0);
         DisplayContent defaultDC = mRootWindowContainer.getDisplayContentOrCreate(DEFAULT_DISPLAY);
-        mMapTaskDisplayArea = new TaskDisplayArea(
-                defaultDC, mWindowManagerService, "MapTDA", FEATURE_MAP_ID);
+        mMapTaskDisplayArea = new TaskDisplayArea(mWindowManagerService, "MapTDA", FEATURE_MAP_ID,
+                false /* createdByOrganizer */, true /* canHostHomeTask */);
+        mMapTaskDisplayArea.mDisplayContent = defaultDC;
         doAnswer((invocation) -> {
             Function<TaskDisplayArea, TaskDisplayArea> callback = invocation.getArgument(0);
             return callback.apply(mMapTaskDisplayArea);
```

