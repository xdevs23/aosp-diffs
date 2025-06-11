```diff
diff --git a/Android.bp b/Android.bp
index c9fe14fb..2d91ada9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -54,7 +54,7 @@ java_defaults {
         "car-telephony-common-no-overlayable",
         "car-ui-lib-no-overlayable",
         "car-qc-lib",
-        "car-resource-common",
+        "car-scalable-ui-lib",
         "com_android_systemui_car_flags_lib",
         "androidx.annotation_annotation",
         "androidx.legacy_legacy-support-v4",
@@ -79,11 +79,15 @@ java_defaults {
         "CarDockLib",
         "androidx.test.rules",
         "car-data-subscription-lib",
+        "Car-WindowManager-Shell",
+        "oem-token-lib",
     ],
 
     libs: [
         "android.car",
+        "token-shared-lib-prebuilt",
     ],
+    enforce_uses_libs: false,
 
     // TODO(b/319708040): re-enable use_resource_processor
     use_resource_processor: false,
@@ -124,8 +128,11 @@ android_app {
 
     libs: [
         "android.car",
+        "token-shared-lib-prebuilt",
     ],
 
+    enforce_uses_libs: false,
+
     resource_dirs: [],
 
     overrides: [
@@ -200,36 +207,15 @@ android_library {
 
 // End daggervis
 
-// Resource lib
-// To be used ONLY for RROs of CarSystemUI
-android_library {
-    name: "CarSystemUI-res",
-    sdk_version: "system_current",
-    resource_dirs: [
-        "res-keyguard",
-        "res",
-    ],
-    manifest: "AndroidManifest-res.xml",
-    use_resource_processor: true,
-    static_libs: [
-        "SystemUI-res",
-        "CarNotification-res",
-        "car-resource-common",
-        "car-ui-lib-no-overlayable",
-    ],
-    lint: {
-        disabled_checks: ["MissingClass"],
-    },
-}
-
 android_library {
     name: "CarSystemUI-tests-base",
     manifest: "tests/AndroidManifest-base.xml",
     resource_dirs: [
         "tests/res",
+        "res-keyguard",
+        "res",
     ],
     static_libs: [
-        "CarSystemUI-res",
         "SystemUI-tests-base",
         "CarNotificationLib",
         "android.car.test.utils",
@@ -238,13 +224,21 @@ android_library {
         "car-telephony-common-no-overlayable",
         "car-ui-lib-no-overlayable",
         "car-qc-lib",
-        "car-resource-common",
+        "car-scalable-ui-lib",
         "com_android_systemui_car_flags_lib",
         "CarDockLib",
         "car-data-subscription-lib",
         "testng",
         "//external/kotlinc:kotlin-annotations",
+        "Car-WindowManager-Shell",
+        "oem-token-lib",
     ],
+
+    libs: [
+        "token-shared-lib-prebuilt",
+    ],
+    enforce_uses_libs: false,
+
 }
 
 android_library {
@@ -260,6 +254,9 @@ android_library {
         "src/**/I*.aidl",
         ":statslog-carsystemui-java-gen",
     ],
+
+    kotlin_lang_version: "1.9",
+
     static_libs: [
         "SystemUI-tests",
         "CarSystemUI-tests-base",
@@ -268,8 +265,12 @@ android_library {
         "android.test.runner.stubs.system",
         "android.test.base.stubs.system",
         "android.car",
+        "token-shared-lib-prebuilt",
+        "android.test.mock.stubs.system",
     ],
 
+    enforce_uses_libs: false,
+
     aaptflags: [
         "--extra-packages",
         "com.android.systemui",
@@ -312,7 +313,11 @@ android_app {
     libs: [
         "keepanno-annotations",
         "android.car",
+        "token-shared-lib-prebuilt",
     ],
+
+    enforce_uses_libs: false,
+
     aaptflags: [
         "--extra-packages",
         "com.android.systemui",
@@ -347,13 +352,14 @@ android_robolectric_test {
     ],
     libs: [
         "android.car",
-        "android.test.runner.stubs.system",
-        "android.test.base.stubs.system",
-        "android.test.mock.stubs.system",
+        "android.test.runner.impl",
+        "android.test.base.impl",
+        "android.test.mock.impl",
         "truth",
+        "token-shared-lib-prebuilt",
     ],
 
-    upstream: true,
+    enforce_uses_libs: false,
 
     instrumentation_for: "CarSystemUIRobo-stub",
     java_resource_dirs: ["tests/robolectric/config"],
@@ -372,7 +378,6 @@ android_ravenwood_test {
     ],
     static_libs: [
         "CarSystemUI-core",
-        "CarSystemUI-res",
         "CarSystemUI-tests-base",
         "androidx.test.uiautomator_uiautomator",
         "androidx.core_core-animation-testing",
@@ -385,7 +390,10 @@ android_ravenwood_test {
         "android.test.runner.stubs.system",
         "android.test.base.stubs.system",
         "android.test.mock.stubs.system",
+        "token-shared-lib-prebuilt",
     ],
+
+    enforce_uses_libs: false,
     auto_gen_config: true,
     plugins: [
         "dagger2-compiler",
@@ -397,5 +405,6 @@ filegroup {
     srcs: [
         "multivalentTests/src/**/*.kt",
         "multivalentTests/src/**/*.java",
+        "tests/utils/src/com/android/systemui/*.java",
     ],
 }
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 341ccf06..2f374a7a 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -77,6 +77,7 @@
         tools:replace="android:name,android:appComponentFactory"
         android:name=".CarSystemUIApplication"
         android:appComponentFactory="com.android.systemui.CarSystemUIAppComponentFactory">
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
         <activity
             android:name=".car.wm.activity.ActivityBlockingActivity"
             android:documentLaunchMode="always"
@@ -84,7 +85,7 @@
             android:configChanges="screenSize|smallestScreenSize|screenLayout|orientation"
             android:exported="false"
             android:showForAllUsers="true"
-            android:theme="@style/Theme.NoTitleBar.NoSplash">
+            android:theme="@style/Theme.ActivityBlockingActivity">
             <intent-filter>
                 <action android:name="android.intent.action.MAIN"/>
             </intent-filter>
@@ -92,7 +93,7 @@
         <activity
             android:name=".car.wm.activity.ContinuousBlankActivity"
             android:excludeFromRecents="true"
-            android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
+            android:theme="@style/Theme.ContinuousBlankActivity"
             android:exported="false"
             android:launchMode="singleTask">
         </activity>
@@ -104,7 +105,7 @@
             android:launchMode="singleInstance"
             android:noHistory="true"
             android:permission="android.car.permission.ACCESS_PRIVATE_DISPLAY_ID"
-            android:theme="@android:style/Theme.Translucent.NoTitleBar"/>
+            android:theme="@style/Theme.LaunchOnPrivateDisplayRouterActivity"/>
         <activity
             android:name=".car.userpicker.UserPickerActivity"
             android:label="UserPicker"
diff --git a/OWNERS b/OWNERS
index b7e7e6eb..65e6e886 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,7 +3,6 @@ alexstetson@google.com
 
 # Secondary
 babakbo@google.com
-nehah@google.com
 
 # Owners from Core Android SystemUI in case quick approval is needed for simple refactoring.
 # But generally, someone from the AAOS SystemUI listed above should be included.
diff --git a/aconfig/Android.bp b/aconfig/Android.bp
index d6e84446..6477eace 100644
--- a/aconfig/Android.bp
+++ b/aconfig/Android.bp
@@ -21,7 +21,7 @@ package {
 aconfig_declarations {
     name: "com_android_systemui_car_flags",
     package: "com.android.systemui.car",
-    container: "system",
+    container: "system_ext",
     srcs: [
         "*.aconfig",
     ],
diff --git a/aconfig/carsystemui.aconfig b/aconfig/carsystemui.aconfig
index 4334e857..d371443f 100644
--- a/aconfig/carsystemui.aconfig
+++ b/aconfig/carsystemui.aconfig
@@ -1,5 +1,5 @@
 package: "com.android.systemui.car"
-container: "system"
+container: "system_ext"
 
 flag {
     name: "config_aware_systemui"
@@ -50,9 +50,30 @@ flag {
     bug: "364382110"
 }
 
+flag {
+    name: "display_compatibility_caption_bar"
+    namespace: "car_sys_exp"
+    description: "This flag controls enabling the back button for display compatibility using caption bar."
+    bug: "370104463"
+}
+
 flag {
     name: "scalable_ui"
     namespace: "car_sys_exp"
     description: "This flag controls the development to enable scalable UI feature."
     bug: "382109339"
-}
\ No newline at end of file
+}
+
+flag {
+    name: "auto_task_stack_windowing"
+    namespace: "car_framework"
+    description: "Flag to enable the AutoTaskStackController in WmShell."
+    bug: "384082238"
+}
+
+flag {
+    name: "package_level_system_bar_visibility"
+    namespace: "car_sys_exp"
+    description: "Allow per-package persistent system bar visibility control."
+    bug: "328511033"
+}
diff --git a/daggervis/parser.py b/daggervis/parser.py
index 0a1fd5bb..d3f03b33 100755
--- a/daggervis/parser.py
+++ b/daggervis/parser.py
@@ -8,111 +8,143 @@ reachable from the beginning_nodes_filter if it's specified.
 """
 import sys
 import os
+import random
 try:
-  import pydot
+    import pydot
 except ImportError as e:
-  print("Error: python3-pydot is not installed. Please run \"sudo apt install python3-pydot\" first.", file=sys.stderr)
-  sys.exit(1)
+    print("Error: python3-pydot is not installed. Please run \"sudo apt install python3-pydot\" first.", file=sys.stderr)
+    sys.exit(1)
 
 def main():
-  # Parse args
-  if len(sys.argv) < 2:
-    print("Error: please specify an input dot file", file=sys.stderr)
-    sys.exit(1)
-  if len(sys.argv) < 3:
-    print("Error: please specify an output dot file", file=sys.stderr)
-    sys.exit(1)
-  input_path = sys.argv[1]
-  output_path = sys.argv[2]
-  if len(sys.argv) > 3:
-    beginning_nodes_filter= sys.argv[3]
-  else:
-    beginning_nodes_filter= None
+    # Parse args
+    if len(sys.argv) < 2:
+        print("Error: please specify an input dot file", file=sys.stderr)
+        sys.exit(1)
+    if len(sys.argv) < 3:
+        print("Error: please specify an output dot file", file=sys.stderr)
+        sys.exit(1)
+    input_path = sys.argv[1]
+    output_path = sys.argv[2]
+    if len(sys.argv) > 3:
+        beginning_nodes_filter= sys.argv[3]
+    else:
+        beginning_nodes_filter= None
 
-  # Load graph
-  try:
-    graph = pydot.graph_from_dot_file(input_path)[0]
-  except Exception as e:
-    print("Error: unable to load dot file \"" + input_path + "\"", file=sys.stderr)
-    sys.exit(1)
-  print("Loaded dot file from " + input_path)
+    # Load graph
+    try:
+        graph = pydot.graph_from_dot_file(input_path)[0]
+    except Exception as e:
+        print("Error: unable to load dot file \"" + input_path + "\"", file=sys.stderr)
+        sys.exit(1)
+    print("Loaded dot file from " + input_path)
 
-  # Trim graph
-  if beginning_nodes_filter!= None:
-    trim_graph(graph, beginning_nodes_filter)
+    # Trim graph
+    if beginning_nodes_filter!= None:
+        trim_graph(graph, beginning_nodes_filter)
 
-  # Add styles
-  style_graph(graph)
+    # Add styles
+    style_graph(graph)
 
-  with open(output_path, "w") as f:
-    f.write(str(graph))
-    print("Saved output dot file " + output_path)
+    with open(output_path, "w") as f:
+        f.write(str(graph))
+        print("Saved output dot file " + output_path)
 
 """
 Trim a graph by only keeping nodes/edges reachable from beginning nodes.
 """
 def trim_graph(graph, beginning_nodes_filter):
-  beginning_node_names = set()
-  all_nodes = graph.get_nodes()
-  for n in all_nodes:
-    if beginning_nodes_filter in get_label(n):
-      beginning_node_names.add(n.get_name())
-  if len(beginning_node_names) == 0:
-    print("Error: unable to find nodes matching \"" + beginning_nodes_filter + "\"", file=sys.stderr)
-    sys.exit(1)
-  filtered_node_names = set()
-  all_edges = graph.get_edges()
-  for node_name in beginning_node_names:
-    dfs(all_edges, node_name, filtered_node_names)
-  cnt_trimmed_nodes = 0
-  for node in all_nodes:
-    if not node.get_name() in filtered_node_names:
-      graph.del_node(node.get_name())
-      cnt_trimmed_nodes += 1
-  cnt_trimmed_edges = 0
-  for edge in all_edges:
-    if not edge.get_source() in filtered_node_names:
-      graph.del_edge(edge.get_source(), edge.get_destination())
-      cnt_trimmed_edges += 1
-  print("Trimed " + str(cnt_trimmed_nodes) + " nodes and " + str(cnt_trimmed_edges) + " edges")
+    beginning_node_names = set()
+    all_nodes = graph.get_nodes()
+    for n in all_nodes:
+        if beginning_nodes_filter in get_label(n):
+            beginning_node_names.add(n.get_name())
+    if len(beginning_node_names) == 0:
+        print("Error: unable to find nodes matching \"" + beginning_nodes_filter + "\"", file=sys.stderr)
+        sys.exit(1)
+    filtered_node_names = set()
+    all_edges = graph.get_edges()
+    for node_name in beginning_node_names:
+        dfs(all_edges, node_name, filtered_node_names)
+    cnt_trimmed_nodes = 0
+    for node in all_nodes:
+        if not node.get_name() in filtered_node_names:
+            graph.del_node(node.get_name())
+            cnt_trimmed_nodes += 1
+    cnt_trimmed_edges = 0
+    for edge in all_edges:
+        if not edge.get_source() in filtered_node_names:
+            graph.del_edge(edge.get_source(), edge.get_destination())
+            cnt_trimmed_edges += 1
+    print("Trimed " + str(cnt_trimmed_nodes) + " nodes and " + str(cnt_trimmed_edges) + " edges")
 
 def dfs(all_edges, node_name, filtered_node_names):
-  if node_name in filtered_node_names:
-    return
-  filtered_node_names.add(node_name)
-  for edge in all_edges:
-    if edge.get_source() == node_name:
-      dfs(all_edges, edge.get_destination(), filtered_node_names)
+    if node_name in filtered_node_names:
+        return
+    filtered_node_names.add(node_name)
+    for edge in all_edges:
+        if edge.get_source() == node_name:
+            dfs(all_edges, edge.get_destination(), filtered_node_names)
 
 """
 Apply styles to the dot graph.
 """
 def style_graph(graph):
-  for n in graph.get_nodes():
-    label = get_label(n)
-    # Style SystemUI nodes
-    if "com.android.systemui" in label:
-      n.obj_dict["attributes"]["color"] = "burlywood"
-      n.obj_dict["attributes"]["shape"] = "box"
-      n.add_style("filled")
-    # Style CarSystemUI nodes
-    elif ("car" in label):
-      n.obj_dict["attributes"]["color"] = "darkolivegreen1"
-      n.add_style("filled")
+    for n in graph.get_nodes():
+        label = get_label(n)
+        # Contains additional classes that are outside the typical CarSystemUI package path/naming
+        additional_car_systemui_classes = [
+            "com.android.systemui.wm.BarControlPolicy",
+            "com.android.systemui.wm.DisplaySystemBarsController",
+            "com.android.systemui.wm.DisplaySystemBarsInsetsControllerHost"
+            ]
+        # Style SystemUI nodes
+        if ("com.android.systemui" in label):
+            if ("com.android.systemui.car" in label or "Car" in label or label in additional_car_systemui_classes):
+                n.obj_dict["attributes"]["color"] = "darkolivegreen1"
+                n.add_style("filled")
+            else:
+                n.obj_dict["attributes"]["color"] = "burlywood"
+                n.obj_dict["attributes"]["shape"] = "box"
+                n.add_style("filled")
+
+        # Trim common labels
+        trim_replacements = [("java.util.", ""), ("javax.inject.", "") , ("com.", "c."),
+                             ("google.", "g."), ("android.", "a."),
+                             ("java.lang.", ""), ("dagger.Lazy", "Lazy"), ("java.util.function.", "")]
+        for (before, after) in trim_replacements:
+            if before in label:
+               n.obj_dict["attributes"]["label"] = label = label.replace(before, after)
 
-    # Trim common labels
-    trim_replacements = [("java.util.", ""), ("javax.inject.", "") , ("com.", "c."),
-                         ("google.", "g."), ("android.", "a."), ("car.", "c."),
-                         ("java.lang.", ""), ("dagger.Lazy", "Lazy"), ("java.util.function.", "")]
-    for (before, after) in trim_replacements:
-      if before in label:
-         n.obj_dict["attributes"]["label"] = label = label.replace(before, after)
+    all_edges = graph.get_edges()
+    for edge in all_edges:
+        edge_hash = abs(hash(edge.get_source())) + abs(hash(edge.get_destination()))
+        r = get_rgb_value(edge_hash, 2)
+        g = get_rgb_value(edge_hash, 1)
+        b = get_rgb_value(edge_hash, 0)
+        if (r > 180 and g > 180 and b > 180):
+            # contrast too low - lower one value at random to maintain contrast against background
+            rand_value = random.randint(1, 3)
+            if (rand_value == 1):
+                r = 180
+            elif (rand_value == 2):
+                g = 180
+            else:
+                b = 180
+        hex = "#{0:02x}{1:02x}{2:02x}".format(clamp_rgb(r), clamp_rgb(g), clamp_rgb(b))
+        edge.obj_dict["attributes"]["color"] = hex
 
 def get_label(node):
-  try:
-    return node.obj_dict["attributes"]["label"]
-  except Exception:
-    return ""
+    try:
+        return node.obj_dict["attributes"]["label"]
+    except Exception:
+        return ""
+
+def get_rgb_value(hash, position):
+    divisor = pow(10, (3 * position))
+    return (hash // divisor % 1000) % 255
+
+def clamp_rgb(c):
+    return max(0, min(c, 255))
 
 if __name__ == "__main__":
     main()
\ No newline at end of file
diff --git a/daggervis/visualize_dagger_component.sh b/daggervis/visualize_dagger_component.sh
index 8832de8e..808783c9 100755
--- a/daggervis/visualize_dagger_component.sh
+++ b/daggervis/visualize_dagger_component.sh
@@ -46,4 +46,6 @@ if [[ $? -ne 0 ]]; then
 fi
 
 echo "Visualizing $PARSED_DOT_FILE"
-dot -v -T svg $PARSED_DOT_FILE > $1
+# dot -v -T svg $PARSED_DOT_FILE > $1
+dot -v -T svg -Ktwopi -Goverlap=prism -Gsplines=true $PARSED_DOT_FILE > $1
+
diff --git a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactoryTest.java b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactoryTest.java
index 2e39fc16..e32b6913 100644
--- a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactoryTest.java
+++ b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactoryTest.java
@@ -35,7 +35,7 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
 import com.android.internal.widget.LockPatternUtils;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.settings.UserTracker;
@@ -49,7 +49,7 @@ import org.mockito.MockitoAnnotations;
 @CarSystemUiTest
 @RunWith(AndroidJUnit4.class)
 @SmallTest
-public class PassengerKeyguardCredentialViewControllerFactoryTest extends SysuiTestCase {
+public class PassengerKeyguardCredentialViewControllerFactoryTest extends CarSysuiTestCase {
     private static final int TEST_USER_ID = 1000;
 
     private PassengerKeyguardCredentialViewControllerFactory mFactory;
diff --git a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelperTest.java b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelperTest.java
index 63c92636..0e9a20f2 100644
--- a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelperTest.java
+++ b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelperTest.java
@@ -27,8 +27,8 @@ import androidx.test.filters.SmallTest;
 
 import com.android.internal.widget.LockPatternUtils;
 import com.android.settingslib.utils.StringUtil;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.settings.UserTracker;
 
@@ -42,7 +42,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class PassengerKeyguardLockoutHelperTest extends SysuiTestCase {
+public class PassengerKeyguardLockoutHelperTest extends CarSysuiTestCase {
     private static final int TEST_USER_ID = 1000;
     private static final int TEST_TIMEOUT_LENGTH_MS = 1000; // 1 second
 
diff --git a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadViewTest.java b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadViewTest.java
index 7a86a09d..a69b4091 100644
--- a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadViewTest.java
+++ b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadViewTest.java
@@ -30,8 +30,8 @@ import android.view.View;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.Before;
@@ -46,7 +46,7 @@ import java.util.Arrays;
 @RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class PassengerPinPadViewTest extends SysuiTestCase {
+public class PassengerPinPadViewTest extends CarSysuiTestCase {
     private static int[] sAllKeys =
             Arrays.copyOf(PassengerPinPadView.PIN_PAD_DIGIT_KEYS, PassengerPinPadView.NUM_KEYS);
 
diff --git a/multivalentTests/src/com/android/systemui/car/systembar/DebugPanelButtonViewControllerTest.java b/multivalentTests/src/com/android/systemui/car/systembar/DebugPanelButtonViewControllerTest.java
index 26b75254..dad01d8c 100644
--- a/multivalentTests/src/com/android/systemui/car/systembar/DebugPanelButtonViewControllerTest.java
+++ b/multivalentTests/src/com/android/systemui/car/systembar/DebugPanelButtonViewControllerTest.java
@@ -27,7 +27,7 @@ import android.testing.TestableLooper;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.statusicon.StatusIconPanelViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -48,7 +48,7 @@ import javax.inject.Provider;
 @RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class DebugPanelButtonViewControllerTest extends SysuiTestCase {
+public class DebugPanelButtonViewControllerTest extends CarSysuiTestCase {
     @Mock
     private CarSystemBarPanelButtonView mView;
     @Mock
diff --git a/multivalentTests/src/com/android/systemui/car/systembar/UserNameImageViewControllerTest.java b/multivalentTests/src/com/android/systemui/car/systembar/UserNameImageViewControllerTest.java
index cb2aed8b..79074667 100644
--- a/multivalentTests/src/com/android/systemui/car/systembar/UserNameImageViewControllerTest.java
+++ b/multivalentTests/src/com/android/systemui/car/systembar/UserNameImageViewControllerTest.java
@@ -19,18 +19,18 @@ package com.android.systemui.car.systembar;
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.content.pm.UserInfo;
 import android.graphics.drawable.Drawable;
-import android.os.UserManager;
 import android.testing.TestableLooper;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
@@ -52,7 +52,7 @@ import java.util.concurrent.Executor;
 @RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class UserNameImageViewControllerTest extends SysuiTestCase {
+public class UserNameImageViewControllerTest extends CarSysuiTestCase {
     private final UserInfo mUserInfo1 =
             new UserInfo(/* id= */ 0, /* name= */ "User 1", /* flags= */ 0);
     private final UserInfo mUserInfo2 =
@@ -67,8 +67,6 @@ public class UserNameImageViewControllerTest extends SysuiTestCase {
     @Mock
     private UserTracker mUserTracker;
     @Mock
-    private UserManager mUserManager;
-    @Mock
     private CarProfileIconUpdater mIconUpdater;
     @Mock
     private UserIconProvider mUserIconProvider;
@@ -84,14 +82,12 @@ public class UserNameImageViewControllerTest extends SysuiTestCase {
     public void setUp() {
         MockitoAnnotations.initMocks(this);
 
-        when(mUserManager.getUserInfo(mUserInfo1.id)).thenReturn(mUserInfo1);
-        when(mUserManager.getUserInfo(mUserInfo2.id)).thenReturn(mUserInfo2);
         when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
-        when(mUserIconProvider.getRoundedUserIcon(any(), any())).thenReturn(mTestDrawable1);
+        when(mUserIconProvider.getRoundedUserIcon(anyInt())).thenReturn(mTestDrawable1);
 
         mView = new CarSystemBarImageView(mContext);
         mController = new UserNameImageViewController(mView, mDisableController,
-                mStateController, mContext, mExecutor, mUserTracker, mUserManager, mIconUpdater,
+                mStateController, mContext, mExecutor, mUserTracker, mIconUpdater,
                 mUserIconProvider);
     }
 
@@ -128,7 +124,7 @@ public class UserNameImageViewControllerTest extends SysuiTestCase {
         assertThat(captor.getValue()).isNotNull();
 
         when(mUserTracker.getUserId()).thenReturn(mUserInfo2.id);
-        when(mUserIconProvider.getRoundedUserIcon(any(), any())).thenReturn(mTestDrawable2);
+        when(mUserIconProvider.getRoundedUserIcon(anyInt())).thenReturn(mTestDrawable2);
         captor.getValue().onUserChanged(mUserInfo2.id, mContext);
 
         assertThat(mView.getDrawable()).isEqualTo(mTestDrawable2);
@@ -143,7 +139,7 @@ public class UserNameImageViewControllerTest extends SysuiTestCase {
         assertThat(captor.getValue()).isNotNull();
 
         when(mUserTracker.getUserId()).thenReturn(mUserInfo2.id);
-        when(mUserIconProvider.getRoundedUserIcon(any(), any())).thenReturn(mTestDrawable2);
+        when(mUserIconProvider.getRoundedUserIcon(anyInt())).thenReturn(mTestDrawable2);
         captor.getValue().onUserIconUpdated(mUserInfo2.id);
 
         assertThat(mView.getDrawable()).isEqualTo(mTestDrawable2);
diff --git a/multivalentTests/src/com/android/systemui/car/systembar/UserNameTextViewControllerTest.java b/multivalentTests/src/com/android/systemui/car/systembar/UserNameTextViewControllerTest.java
index ea803b97..eda64844 100644
--- a/multivalentTests/src/com/android/systemui/car/systembar/UserNameTextViewControllerTest.java
+++ b/multivalentTests/src/com/android/systemui/car/systembar/UserNameTextViewControllerTest.java
@@ -31,7 +31,7 @@ import android.testing.TestableLooper;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -52,7 +52,7 @@ import java.util.concurrent.Executor;
 @RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class UserNameTextViewControllerTest extends SysuiTestCase {
+public class UserNameTextViewControllerTest extends CarSysuiTestCase {
     private static final String USER_1_NAME = "User 1";
     private static final String USER_2_NAME = "User 2";
     private final UserInfo mUserInfo1 =
diff --git a/multivalentTests/src/com/android/systemui/car/users/CarProfileIconUpdaterTest.java b/multivalentTests/src/com/android/systemui/car/users/CarProfileIconUpdaterTest.java
index cbf86a4c..ae86cb51 100644
--- a/multivalentTests/src/com/android/systemui/car/users/CarProfileIconUpdaterTest.java
+++ b/multivalentTests/src/com/android/systemui/car/users/CarProfileIconUpdaterTest.java
@@ -35,7 +35,7 @@ import android.testing.TestableLooper;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.userswitcher.UserIconProvider;
@@ -56,7 +56,7 @@ import java.util.concurrent.Executor;
 @RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CarProfileIconUpdaterTest extends SysuiTestCase {
+public class CarProfileIconUpdaterTest extends CarSysuiTestCase {
     private final UserInfo mUserInfo1 =
             new UserInfo(/* id= */ 0, /* name= */ "User 1", /* flags= */ 0);
     private final UserInfo mUserInfo2 =
@@ -111,7 +111,7 @@ public class CarProfileIconUpdaterTest extends SysuiTestCase {
         captor.getValue().onReceive(getContext(),
                 new Intent(Intent.ACTION_USER_INFO_CHANGED));
 
-        verify(mUserIconProvider).setRoundedUserIcon(any(), any());
+        verify(mUserIconProvider).setRoundedUserIcon(anyInt());
         verify(mTestCallback).onUserIconUpdated(anyInt());
     }
 
@@ -125,7 +125,7 @@ public class CarProfileIconUpdaterTest extends SysuiTestCase {
         captor.getValue().onReceive(getContext(),
                 new Intent(Intent.ACTION_USER_INFO_CHANGED));
 
-        verify(mUserIconProvider, never()).setRoundedUserIcon(any(), any());
+        verify(mUserIconProvider, never()).setRoundedUserIcon(anyInt());
         verify(mTestCallback, never()).onUserIconUpdated(anyInt());
     }
 
diff --git a/multivalentTests/src/com/android/systemui/wm/BarControlPolicyTest.java b/multivalentTests/src/com/android/systemui/wm/BarControlPolicyTest.java
index cd025abf..33b840e4 100644
--- a/multivalentTests/src/com/android/systemui/wm/BarControlPolicyTest.java
+++ b/multivalentTests/src/com/android/systemui/wm/BarControlPolicyTest.java
@@ -19,16 +19,21 @@ package com.android.systemui.wm;
 import static android.view.WindowInsets.Type.navigationBars;
 import static android.view.WindowInsets.Type.statusBars;
 
+import static com.android.systemui.car.Flags.FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import android.car.settings.CarSettings;
+import android.platform.test.annotations.DisableFlags;
+import android.platform.test.annotations.EnableFlags;
 import android.provider.Settings;
-import android.testing.TestableLooper;
+import android.testing.TestableLooper.RunWithLooper;
+import android.view.WindowInsets.Type.InsetsType;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.After;
@@ -38,11 +43,23 @@ import org.junit.runner.RunWith;
 
 @CarSystemUiTest
 @RunWith(AndroidJUnit4.class)
-@TestableLooper.RunWithLooper
+@RunWithLooper
 @SmallTest
-public class BarControlPolicyTest extends SysuiTestCase {
+public class BarControlPolicyTest extends CarSysuiTestCase {
 
     private static final String PACKAGE_NAME = "sample.app";
+    private static final String PACKAGE_NAME2 = "sample2.app";
+
+    @InsetsType
+    private static final int REQUESTED_VISIBILITY_IRRELEVANT = 0;
+    @InsetsType
+    private static final int REQUESTED_VISIBILITY_HIDE_ALL_BARS = 0;
+    @InsetsType
+    private static final int REQUESTED_VISIBILITY_STATUS_BARS = statusBars();
+    @InsetsType
+    private static final int REQUESTED_VISIBILITY_NAVIGATION_BARS = navigationBars();
+    @InsetsType
+    private static final int REQUESTED_VISIBILITY_SHOW_ALL_BARS = statusBars() | navigationBars();
 
     @Before
     public void setUp() {
@@ -63,47 +80,27 @@ public class BarControlPolicyTest extends SysuiTestCase {
 
     @Test
     public void reloadFromSetting_invalidPolicyControlString_doesNotSetFilters() {
-        String text = "sample text";
-        Settings.Global.putString(
-                mContext.getContentResolver(),
-                CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                text
-        );
-
-        BarControlPolicy.reloadFromSetting(mContext);
+        configureBarPolicy("sample text");
 
         assertThat(BarControlPolicy.sImmersiveStatusFilter).isNull();
     }
 
     @Test
     public void reloadFromSetting_validPolicyControlString_setsFilters() {
-        String text = "immersive.status=" + PACKAGE_NAME;
-        Settings.Global.putString(
-                mContext.getContentResolver(),
-                CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                text
-        );
-
-        BarControlPolicy.reloadFromSetting(mContext);
+        configureBarPolicy("immersive.status=" + PACKAGE_NAME);
 
         assertThat(BarControlPolicy.sImmersiveStatusFilter).isNotNull();
     }
 
     @Test
     public void reloadFromSetting_filtersSet_doesNotSetFiltersAgain() {
-        String text = "immersive.status=" + PACKAGE_NAME;
-        Settings.Global.putString(
-                mContext.getContentResolver(),
-                CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                text
-        );
-
-        BarControlPolicy.reloadFromSetting(mContext);
+        configureBarPolicy("immersive.status=" + PACKAGE_NAME);
 
         assertThat(BarControlPolicy.reloadFromSetting(mContext)).isFalse();
     }
 
     @Test
+    @DisableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
     public void getBarVisibilities_policyControlNotSet_showsSystemBars() {
         int[] visibilities = BarControlPolicy.getBarVisibilities(PACKAGE_NAME);
 
@@ -112,12 +109,9 @@ public class BarControlPolicyTest extends SysuiTestCase {
     }
 
     @Test
+    @DisableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
     public void getBarVisibilities_immersiveStatusForAppAndMatchingApp_hidesStatusBar() {
-        Settings.Global.putString(
-                mContext.getContentResolver(),
-                CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                "immersive.status=" + PACKAGE_NAME);
-        BarControlPolicy.reloadFromSetting(mContext);
+        configureBarPolicy("immersive.status=" + PACKAGE_NAME);
 
         int[] visibilities = BarControlPolicy.getBarVisibilities(PACKAGE_NAME);
 
@@ -126,26 +120,20 @@ public class BarControlPolicyTest extends SysuiTestCase {
     }
 
     @Test
+    @DisableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
     public void getBarVisibilities_immersiveStatusForAppAndNonMatchingApp_showsSystemBars() {
-        Settings.Global.putString(
-                mContext.getContentResolver(),
-                CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                "immersive.status=" + PACKAGE_NAME);
-        BarControlPolicy.reloadFromSetting(mContext);
+        configureBarPolicy("immersive.status=" + PACKAGE_NAME);
 
-        int[] visibilities = BarControlPolicy.getBarVisibilities("sample2.app");
+        int[] visibilities = BarControlPolicy.getBarVisibilities(PACKAGE_NAME2);
 
         assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
         assertThat(visibilities[1]).isEqualTo(0);
     }
 
     @Test
+    @DisableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
     public void getBarVisibilities_immersiveStatusForAppsAndNonApp_showsSystemBars() {
-        Settings.Global.putString(
-                mContext.getContentResolver(),
-                CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                "immersive.status=apps");
-        BarControlPolicy.reloadFromSetting(mContext);
+        configureBarPolicy("immersive.status=apps");
 
         int[] visibilities = BarControlPolicy.getBarVisibilities(PACKAGE_NAME);
 
@@ -154,12 +142,9 @@ public class BarControlPolicyTest extends SysuiTestCase {
     }
 
     @Test
+    @DisableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
     public void getBarVisibilities_immersiveFullForAppAndMatchingApp_hidesSystemBars() {
-        Settings.Global.putString(
-                mContext.getContentResolver(),
-                CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                "immersive.full=" + PACKAGE_NAME);
-        BarControlPolicy.reloadFromSetting(mContext);
+        configureBarPolicy("immersive.full=" + PACKAGE_NAME);
 
         int[] visibilities = BarControlPolicy.getBarVisibilities(PACKAGE_NAME);
 
@@ -168,30 +153,249 @@ public class BarControlPolicyTest extends SysuiTestCase {
     }
 
     @Test
+    @DisableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
     public void getBarVisibilities_immersiveFullForAppAndNonMatchingApp_showsSystemBars() {
-        Settings.Global.putString(
-                mContext.getContentResolver(),
-                CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                "immersive.full=" + PACKAGE_NAME);
-        BarControlPolicy.reloadFromSetting(mContext);
+        configureBarPolicy("immersive.full=" + PACKAGE_NAME);
 
-        int[] visibilities = BarControlPolicy.getBarVisibilities("sample2.app");
+        int[] visibilities = BarControlPolicy.getBarVisibilities(PACKAGE_NAME2);
 
         assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
         assertThat(visibilities[1]).isEqualTo(0);
     }
 
     @Test
+    @DisableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
     public void getBarVisibilities_immersiveFullForAppsAndNonApp_showsSystemBars() {
+        configureBarPolicy("immersive.full=apps");
+
+        int[] visibilities = BarControlPolicy.getBarVisibilities(PACKAGE_NAME);
+
+        assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
+        assertThat(visibilities[1]).isEqualTo(0);
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities2_policyControlNotSet_showsSystemBars() {
+        int[] visibilities =
+                BarControlPolicy.getBarVisibilities(PACKAGE_NAME, REQUESTED_VISIBILITY_IRRELEVANT);
+
+        assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
+        assertThat(visibilities[1]).isEqualTo(0);
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities2_immersiveStatusForAppAndMatchingApp_hidesStatusBar() {
+        configureBarPolicy("immersive.status=" + PACKAGE_NAME);
+
+        int[] visibilities =
+                BarControlPolicy.getBarVisibilities(PACKAGE_NAME, REQUESTED_VISIBILITY_IRRELEVANT);
+
+        assertThat(visibilities[0]).isEqualTo(navigationBars());
+        assertThat(visibilities[1]).isEqualTo(statusBars());
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities2_immersiveStatusForAppAndNonMatchingApp_showsSystemBars() {
+        configureBarPolicy("immersive.status=" + PACKAGE_NAME);
+
+        int[] visibilities =
+                BarControlPolicy.getBarVisibilities(PACKAGE_NAME2, REQUESTED_VISIBILITY_IRRELEVANT);
+
+        assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
+        assertThat(visibilities[1]).isEqualTo(0);
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities2_immersiveStatusForAppsAndNonApp_showsSystemBars() {
+        configureBarPolicy("immersive.status=apps");
+
+        int[] visibilities =
+                BarControlPolicy.getBarVisibilities(PACKAGE_NAME, REQUESTED_VISIBILITY_IRRELEVANT);
+
+        assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
+        assertThat(visibilities[1]).isEqualTo(0);
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities2_immersiveFullForAppAndMatchingApp_hidesSystemBars() {
+        configureBarPolicy("immersive.full=" + PACKAGE_NAME);
+
+        int[] visibilities =
+                BarControlPolicy.getBarVisibilities(PACKAGE_NAME, REQUESTED_VISIBILITY_IRRELEVANT);
+
+        assertThat(visibilities[0]).isEqualTo(0);
+        assertThat(visibilities[1]).isEqualTo(statusBars() | navigationBars());
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities2_immersiveFullForAppAndNonMatchingApp_showsSystemBars() {
+        configureBarPolicy("immersive.full=" + PACKAGE_NAME);
+
+        int[] visibilities =
+                BarControlPolicy.getBarVisibilities(PACKAGE_NAME2, REQUESTED_VISIBILITY_IRRELEVANT);
+
+        assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
+        assertThat(visibilities[1]).isEqualTo(0);
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities2_immersiveFullForAppsAndNonApp_showsSystemBars() {
+        configureBarPolicy("immersive.full=apps");
+
+        int[] visibilities =
+                BarControlPolicy.getBarVisibilities(PACKAGE_NAME, REQUESTED_VISIBILITY_IRRELEVANT);
+
+        assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
+        assertThat(visibilities[1]).isEqualTo(0);
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities_immersiveStatusWithAllowPolicy_allowsShowStatus() {
+        configureBarPolicy("immersive.status=+" + PACKAGE_NAME);
+
+        @InsetsType int[] visibilitiesShowStatus = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_STATUS_BARS);
+
+        assertThat(barsShown(visibilitiesShowStatus, navigationBars() | statusBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowStatus, /* barTypes= */ 0)).isTrue();
+
+        @InsetsType int[] visibilitiesShowAllBars = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_SHOW_ALL_BARS);
+
+        assertThat(barsShown(visibilitiesShowAllBars, navigationBars() | statusBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowAllBars, /* barTypes= */ 0)).isTrue();
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities_immersiveStatusWithAllowPolicy_allowsHideStatus() {
+        configureBarPolicy("immersive.status=+" + PACKAGE_NAME);
+
+        @InsetsType int[] visibilitiesShowStatus = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_NAVIGATION_BARS);
+
+        assertThat(barsShown(visibilitiesShowStatus, navigationBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowStatus, statusBars())).isTrue();
+
+        @InsetsType int[] visibilitiesShowAllBars = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_HIDE_ALL_BARS);
+
+        assertThat(barsShown(visibilitiesShowAllBars, navigationBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowAllBars, statusBars())).isTrue();
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities_immersiveNavigationWithAllowPolicy_allowsShowNavigation() {
+        configureBarPolicy("immersive.navigation=+" + PACKAGE_NAME);
+
+        @InsetsType int[] visibilitiesShowStatus = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_NAVIGATION_BARS);
+
+        assertThat(barsShown(visibilitiesShowStatus, navigationBars() | statusBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowStatus, /* barTypes= */ 0)).isTrue();
+
+        @InsetsType int[] visibilitiesShowAllBars = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_SHOW_ALL_BARS);
+
+        assertThat(barsShown(visibilitiesShowAllBars, navigationBars() | statusBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowAllBars, /* barTypes= */ 0)).isTrue();
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities_immersiveNavigationWithAllowPolicy_allowsHideNavigation() {
+        configureBarPolicy("immersive.navigation=+" + PACKAGE_NAME);
+
+        @InsetsType int[] visibilitiesShowStatus = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_STATUS_BARS);
+
+        assertThat(barsShown(visibilitiesShowStatus, statusBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowStatus, navigationBars())).isTrue();
+
+        @InsetsType int[] visibilitiesShowAllBars = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_SHOW_ALL_BARS);
+
+        assertThat(barsShown(visibilitiesShowAllBars, navigationBars() | statusBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowAllBars, /* barTypes= */ 0)).isTrue();
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities_immersiveFullWithAllowPolicy_allowsShowAndHideBars() {
+        configureBarPolicy("immersive.full=+" + PACKAGE_NAME);
+
+        @InsetsType int[] visibilitiesShowStatus = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_SHOW_ALL_BARS);
+
+        assertThat(barsShown(visibilitiesShowStatus, navigationBars() | statusBars())).isTrue();
+        assertThat(barsHidden(visibilitiesShowStatus, /* barTypes= */ 0)).isTrue();
+
+        @InsetsType int[] visibilitiesShowAllBars = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_HIDE_ALL_BARS);
+
+        assertThat(barsShown(visibilitiesShowAllBars, /* barTypes= */ 0)).isTrue();
+        assertThat(barsHidden(visibilitiesShowAllBars, navigationBars() | statusBars())).isTrue();
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities_combinedImmersiveStatusWithAllowPolicy_hidesSelectively() {
+        configureBarPolicy(String.format("immersive.status=%s,+%s", PACKAGE_NAME, PACKAGE_NAME2));
+
+        @InsetsType int[] visibilities0 = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_SHOW_ALL_BARS);
+
+        assertThat(barsShown(visibilities0, navigationBars())).isTrue();
+        assertThat(barsHidden(visibilities0, statusBars())).isTrue();
+
+        @InsetsType int[] visibilities1 = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME2, REQUESTED_VISIBILITY_SHOW_ALL_BARS);
+
+        assertThat(barsShown(visibilities1, statusBars() | navigationBars())).isTrue();
+        assertThat(barsHidden(visibilities1, /* barTypes= */ 0)).isTrue();
+    }
+
+    @Test
+    @EnableFlags(FLAG_PACKAGE_LEVEL_SYSTEM_BAR_VISIBILITY)
+    public void getBarVisibilities_combinedImmersiveNavigationWithAllowPolicy_hidesSelectively() {
+        configureBarPolicy(
+                String.format("immersive.navigation=+%s,%s", PACKAGE_NAME, PACKAGE_NAME2));
+
+        @InsetsType int[] visibilities0 = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME, REQUESTED_VISIBILITY_SHOW_ALL_BARS);
+
+        assertThat(barsShown(visibilities0, statusBars() | navigationBars())).isTrue();
+        assertThat(barsHidden(visibilities0, /* barTypes= */ 0)).isTrue();
+
+        @InsetsType int[] visibilities1 = BarControlPolicy.getBarVisibilities(
+                PACKAGE_NAME2, REQUESTED_VISIBILITY_SHOW_ALL_BARS);
+
+        assertThat(barsShown(visibilities1, statusBars())).isTrue();
+        assertThat(barsHidden(visibilities1, navigationBars())).isTrue();
+    }
+
+    private void configureBarPolicy(String configuration) {
         Settings.Global.putString(
                 mContext.getContentResolver(),
                 CarSettings.Global.SYSTEM_BAR_VISIBILITY_OVERRIDE,
-                "immersive.full=apps");
+                configuration);
         BarControlPolicy.reloadFromSetting(mContext);
+    }
 
-        int[] visibilities = BarControlPolicy.getBarVisibilities(PACKAGE_NAME);
+    private static boolean barsShown(@InsetsType int[] visibilities, @InsetsType int barTypes) {
+        return visibilities[0] == barTypes;
+    }
 
-        assertThat(visibilities[0]).isEqualTo(statusBars() | navigationBars());
-        assertThat(visibilities[1]).isEqualTo(0);
+    private static boolean barsHidden(@InsetsType int[] visibilities, @InsetsType int barTypes) {
+        return visibilities[1] == barTypes;
     }
 }
diff --git a/multivalentTests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java b/multivalentTests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java
index 1c5648ed..d2fe5738 100644
--- a/multivalentTests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java
+++ b/multivalentTests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java
@@ -30,7 +30,7 @@ import android.view.IWindowManager;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.wm.shell.common.DisplayController;
 import com.android.wm.shell.common.DisplayInsetsController;
@@ -46,7 +46,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class DisplaySystemBarsControllerTest extends SysuiTestCase {
+public class DisplaySystemBarsControllerTest extends CarSysuiTestCase {
 
     private DisplaySystemBarsController mController;
 
diff --git a/res-keyguard/color/button_background.xml b/res-keyguard/color/button_background.xml
new file mode 100644
index 00000000..c43af02f
--- /dev/null
+++ b/res-keyguard/color/button_background.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2025, The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License")
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:color="?oemColorBlueContainer"/>
+</selector>
\ No newline at end of file
diff --git a/res-keyguard/color/button_text.xml b/res-keyguard/color/button_text.xml
new file mode 100644
index 00000000..a6858ef3
--- /dev/null
+++ b/res-keyguard/color/button_text.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2025, The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License")
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:color="?oemColorOnBlueContainer"/>
+</selector>
\ No newline at end of file
diff --git a/res-keyguard/layout-land/keyguard_pattern_view.xml b/res-keyguard/layout-land/keyguard_pattern_view.xml
index ef90ddef..778096a4 100644
--- a/res-keyguard/layout-land/keyguard_pattern_view.xml
+++ b/res-keyguard/layout-land/keyguard_pattern_view.xml
@@ -55,8 +55,7 @@
             android:layout_height="wrap_content"
             android:layout_margin="@*android:dimen/car_padding_2"
             android:gravity="center"
-            android:textColor="@android:color/white"
-            android:textSize="@*android:dimen/car_body1_size"
+            android:textAppearance="?oemTextAppearanceTitleLarge"
             android:text="@string/car_keyguard_enter_your_pattern" />
 
         <include layout="@layout/keyguard_message_area" />
diff --git a/res-keyguard/layout-land/keyguard_pin_view.xml b/res-keyguard/layout-land/keyguard_pin_view.xml
index 05415f37..fa540184 100644
--- a/res-keyguard/layout-land/keyguard_pin_view.xml
+++ b/res-keyguard/layout-land/keyguard_pin_view.xml
@@ -96,15 +96,14 @@
             android:id="@+id/divider"
             android:layout_width="@dimen/keyguard_security_width"
             android:layout_height="@dimen/divider_height"
-            android:background="@android:color/white" />
+            android:background="?oemColorOnSurface" />
 
         <TextView
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
             android:layout_margin="@*android:dimen/car_padding_2"
             android:gravity="center"
-            android:textColor="@android:color/white"
-            android:textSize="@*android:dimen/car_body1_size"
+            android:textAppearance="?oemTextAppearanceTitleLarge"
             android:text="@string/car_keyguard_enter_your_pin" />
 
         <include layout="@layout/keyguard_message_area" />
diff --git a/res-keyguard/layout-land/keyguard_sim_pin_view.xml b/res-keyguard/layout-land/keyguard_sim_pin_view.xml
index 5f43a028..b14ff112 100644
--- a/res-keyguard/layout-land/keyguard_sim_pin_view.xml
+++ b/res-keyguard/layout-land/keyguard_sim_pin_view.xml
@@ -95,15 +95,14 @@
             android:id="@+id/divider"
             android:layout_width="@dimen/keyguard_security_width"
             android:layout_height="@dimen/divider_height"
-            android:background="@android:color/white" />
+            android:background="?oemColorOnSurface" />
 
         <TextView
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
             android:layout_margin="@*android:dimen/car_padding_2"
             android:gravity="center"
-            android:textColor="@android:color/white"
-            android:textSize="@*android:dimen/car_body1_size"
+            android:textAppearance="?oemTextAppearanceTitleLarge"
             android:text="@string/car_keyguard_enter_your_pin" />
 
         <include layout="@layout/keyguard_message_area" />
diff --git a/res-keyguard/layout/keyguard_message_area.xml b/res-keyguard/layout/keyguard_message_area.xml
index 57b70dd8..05cc1e4c 100644
--- a/res-keyguard/layout/keyguard_message_area.xml
+++ b/res-keyguard/layout/keyguard_message_area.xml
@@ -28,4 +28,4 @@
     android:ellipsize="marquee"
     android:focusable="true"
     android:layout_marginBottom="@*android:dimen/car_padding_4"
-    android:textSize="@*android:dimen/car_body2_size" />
+    android:textAppearance="?oemTextAppearanceTitleMedium" />
diff --git a/res-keyguard/layout/keyguard_password_view.xml b/res-keyguard/layout/keyguard_password_view.xml
index 716648e8..8693c211 100644
--- a/res-keyguard/layout/keyguard_password_view.xml
+++ b/res-keyguard/layout/keyguard_password_view.xml
@@ -52,9 +52,8 @@
             android:singleLine="true"
             android:textStyle="normal"
             android:inputType="textPassword"
-            android:textSize="@*android:dimen/car_body1_size"
             android:textColor="?attr/wallpaperTextColor"
-            android:textAppearance="?android:attr/textAppearanceMedium"
+            android:textAppearance="?oemTextAppearanceTitleMedium"
             android:imeOptions="flagForceAscii|actionDone"
             android:maxLength="@integer/password_max_length"
          />
@@ -64,8 +63,7 @@
             android:layout_height="wrap_content"
             android:layout_margin="@*android:dimen/car_padding_2"
             android:gravity="center"
-            android:textColor="@android:color/white"
-            android:textSize="@*android:dimen/car_body1_size"
+            android:textAppearance="?oemTextAppearanceTitleLarge"
             android:text="@string/car_keyguard_enter_your_password" />
 
         <Button
diff --git a/res-keyguard/layout/keyguard_pattern_view.xml b/res-keyguard/layout/keyguard_pattern_view.xml
index 9540a9a0..a00aa112 100644
--- a/res-keyguard/layout/keyguard_pattern_view.xml
+++ b/res-keyguard/layout/keyguard_pattern_view.xml
@@ -46,8 +46,7 @@
             android:layout_height="wrap_content"
             android:layout_margin="@*android:dimen/car_padding_2"
             android:gravity="center"
-            android:textColor="@android:color/white"
-            android:textSize="@*android:dimen/car_body1_size"
+            android:textAppearance="?oemTextAppearanceTitleLarge"
             android:text="@string/car_keyguard_enter_your_pattern"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
diff --git a/res-keyguard/layout/keyguard_pin_view.xml b/res-keyguard/layout/keyguard_pin_view.xml
index f354a1f3..0eb98842 100644
--- a/res-keyguard/layout/keyguard_pin_view.xml
+++ b/res-keyguard/layout/keyguard_pin_view.xml
@@ -86,15 +86,14 @@
             android:id="@+id/divider"
             android:layout_width="@dimen/keyguard_security_width"
             android:layout_height="@dimen/divider_height"
-            android:background="@android:color/white" />
+            android:background="?oemColorOnSurface" />
 
         <TextView
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
             android:layout_margin="@*android:dimen/car_padding_2"
             android:gravity="center"
-            android:textColor="@android:color/white"
-            android:textSize="@*android:dimen/car_body1_size"
+            android:textAppearance="?oemTextAppearanceTitleLarge"
             android:text="@string/car_keyguard_enter_your_pin" />
 
         <include layout="@layout/keyguard_message_area" />
diff --git a/res-keyguard/layout/keyguard_sim_pin_view.xml b/res-keyguard/layout/keyguard_sim_pin_view.xml
index d4ae98f0..c31b8ed1 100644
--- a/res-keyguard/layout/keyguard_sim_pin_view.xml
+++ b/res-keyguard/layout/keyguard_sim_pin_view.xml
@@ -83,15 +83,14 @@
             android:id="@+id/divider"
             android:layout_width="@dimen/keyguard_security_width"
             android:layout_height="@dimen/divider_height"
-            android:background="@android:color/white" />
+            android:background="?oemColorOnSurface" />
 
         <TextView
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
             android:layout_margin="@*android:dimen/car_padding_2"
             android:gravity="center"
-            android:textColor="@android:color/white"
-            android:textSize="@*android:dimen/car_body1_size"
+            android:textAppearance="?oemTextAppearanceTitleLarge"
             android:text="@string/car_keyguard_enter_your_pin" />
 
         <include layout="@layout/keyguard_message_area" />
diff --git a/res-keyguard/layout/passenger_keyguard_loading_dialog.xml b/res-keyguard/layout/passenger_keyguard_loading_dialog.xml
index 6a6cb1cb..6657ea09 100644
--- a/res-keyguard/layout/passenger_keyguard_loading_dialog.xml
+++ b/res-keyguard/layout/passenger_keyguard_loading_dialog.xml
@@ -25,6 +25,6 @@
         android:layout_height="50dp"
         style="?android:attr/progressBarStyleHorizontal"
         android:indeterminate="true"
-        android:indeterminateTint="@color/car_on_surface"
+        android:indeterminateTint="?oemColorOnSurface"
         android:layout_gravity="center"/>
 </FrameLayout>
diff --git a/res-keyguard/layout/passenger_keyguard_overlay_window.xml b/res-keyguard/layout/passenger_keyguard_overlay_window.xml
index f1467281..bd2cd904 100644
--- a/res-keyguard/layout/passenger_keyguard_overlay_window.xml
+++ b/res-keyguard/layout/passenger_keyguard_overlay_window.xml
@@ -21,5 +21,5 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:fillViewport="true"
-    android:background="@color/car_surface">
+    android:background="?oemColorSurface">
 </FrameLayout>
\ No newline at end of file
diff --git a/res-keyguard/layout/passenger_keyguard_password_view.xml b/res-keyguard/layout/passenger_keyguard_password_view.xml
index 44e80ca1..7b4b4286 100644
--- a/res-keyguard/layout/passenger_keyguard_password_view.xml
+++ b/res-keyguard/layout/passenger_keyguard_password_view.xml
@@ -30,7 +30,7 @@
         android:gravity="center"
         android:inputType="textPassword"
         android:maxLines="1"
-        android:textAppearance="?android:attr/textAppearanceLarge">
+        android:textAppearance="?oemTextAppearanceTitleLarge">
         <requestFocus/>
     </EditText>
 
@@ -39,7 +39,7 @@
         android:layout_height="wrap_content"
         android:gravity="center"
         android:text="@string/car_keyguard_enter_your_password"
-        android:textAppearance="?android:attr/textAppearanceLarge"/>
+        android:textAppearance="?oemTextAppearanceTitleLarge"/>
 
     <TextView
         android:id="@+id/message"
@@ -47,7 +47,7 @@
         android:layout_height="wrap_content"
         android:freezesText="true"
         android:gravity="center"
-        android:textAppearance="?android:attr/textAppearanceMedium"/>
+        android:textAppearance="?oemTextAppearanceTitleMedium"/>
 
     <Button
         android:id="@+id/cancel_button"
diff --git a/res-keyguard/layout/passenger_keyguard_pattern_view.xml b/res-keyguard/layout/passenger_keyguard_pattern_view.xml
index be6a4a81..0f75f280 100644
--- a/res-keyguard/layout/passenger_keyguard_pattern_view.xml
+++ b/res-keyguard/layout/passenger_keyguard_pattern_view.xml
@@ -28,7 +28,7 @@
         android:layout_height="wrap_content"
         android:layout_marginBottom="@dimen/confirm_lock_message_vertical_spacing"
         android:text="@string/car_keyguard_enter_your_pattern"
-        android:textAppearance="?android:attr/textAppearanceLarge"/>
+        android:textAppearance="?oemTextAppearanceTitleLarge"/>
 
     <TextView
         android:id="@+id/message"
@@ -36,7 +36,7 @@
         android:layout_height="wrap_content"
         android:layout_marginBottom="@dimen/confirm_lock_message_vertical_spacing"
         android:gravity="center"
-        android:textAppearance="?android:attr/textAppearanceMedium"/>
+        android:textAppearance="?oemTextAppearanceTitleMedium"/>
 
     <com.android.internal.widget.LockPatternView
         android:id="@+id/lockPattern"
diff --git a/res-keyguard/layout/passenger_keyguard_pin_view.xml b/res-keyguard/layout/passenger_keyguard_pin_view.xml
index a5eb9698..30e17d69 100644
--- a/res-keyguard/layout/passenger_keyguard_pin_view.xml
+++ b/res-keyguard/layout/passenger_keyguard_pin_view.xml
@@ -56,7 +56,7 @@
             android:gravity="center"
             android:inputType="textPassword"
             android:maxLines="1"
-            android:textAppearance="?android:attr/textAppearanceLarge"/>
+            android:textAppearance="?oemTextAppearanceTitleLarge"/>
 
         <TextView
             android:layout_width="match_parent"
@@ -64,14 +64,14 @@
             android:layout_marginBottom="@dimen/confirm_lock_message_vertical_spacing"
             android:gravity="center"
             android:text="@string/car_keyguard_enter_your_pin"
-            android:textAppearance="?android:attr/textAppearanceLarge"/>
+            android:textAppearance="?oemTextAppearanceTitleLarge"/>
 
         <TextView
             android:id="@+id/message"
             android:layout_width="match_parent"
             android:layout_height="wrap_content"
             android:gravity="center"
-            android:textAppearance="?android:attr/textAppearanceMedium"/>
+            android:textAppearance="?oemTextAppearanceTitleMedium"/>
 
         <Button
             android:id="@+id/cancel_button"
diff --git a/res-keyguard/values/colors.xml b/res-keyguard/values/colors.xml
index 6f6247fb..326bb0fd 100644
--- a/res-keyguard/values/colors.xml
+++ b/res-keyguard/values/colors.xml
@@ -16,7 +16,5 @@
 -->
 
 <resources>
-    <color name="button_background">@*android:color/car_dark_blue_grey_600</color>
-    <color name="button_text">@android:color/white</color>
     <drawable name="num_pad_key_background">@android:color/transparent</drawable>
 </resources>
diff --git a/res-keyguard/values/styles.xml b/res-keyguard/values/styles.xml
index 814de58f..5938bf3c 100644
--- a/res-keyguard/values/styles.xml
+++ b/res-keyguard/values/styles.xml
@@ -34,8 +34,8 @@
 
     <style name="NumPadKeyButton.LastRow">
         <item name="android:layout_marginBottom">0dp</item>
-        <item name="android:colorControlNormal">?android:attr/colorBackground</item>
-        <item name="android:colorControlHighlight">?android:attr/colorAccent</item>
+        <item name="android:colorControlNormal">?oemColorOnSurfaceVariant</item>
+        <item name="android:colorControlHighlight">?oemColorPrimary</item>
     </style>
 
     <style name="KeyguardButton" parent="@android:style/Widget.DeviceDefault.Button">
@@ -45,7 +45,6 @@
     </style>
 
     <style name="Widget.TextView.NumPadKey" parent="@android:style/Widget.TextView">
-        <!-- Only replaces the text size. -->
-        <item name="android:textSize">@*android:dimen/car_body1_size</item>
+        android:textAppearance="?oemTextAppearanceTitleLarge"
     </style>
 </resources>
diff --git a/res/color/activity_blocking_action_button_background_color.xml b/res/color/activity_blocking_action_button_background_color.xml
new file mode 100644
index 00000000..bdec3f9c
--- /dev/null
+++ b/res/color/activity_blocking_action_button_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHighest"/>
+</selector>
diff --git a/res/color/activity_blocking_activity_background.xml b/res/color/activity_blocking_activity_background.xml
new file mode 100644
index 00000000..f31e4cd5
--- /dev/null
+++ b/res/color/activity_blocking_activity_background.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:alpha="0.78"
+        android:color="?oemColorBackground"/>
+</selector>
diff --git a/res/color/blocking_text.xml b/res/color/blocking_text.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/blocking_text.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/car_control_highlight.xml b/res/color/car_control_highlight.xml
new file mode 100644
index 00000000..bd2c736f
--- /dev/null
+++ b/res/color/car_control_highlight.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2023 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:alpha="0.6"
+        android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/car_managed_device_icon_color.xml b/res/color/car_managed_device_icon_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/car_managed_device_icon_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/car_nav_icon_background_color.xml b/res/color/car_nav_icon_background_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/car_nav_icon_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/car_nav_icon_background_color_selected.xml b/res/color/car_nav_icon_background_color_selected.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/car_nav_icon_background_color_selected.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/car_nav_icon_fill_color.xml b/res/color/car_nav_icon_fill_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/car_nav_icon_fill_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/car_nav_icon_fill_color_selected.xml b/res/color/car_nav_icon_fill_color_selected.xml
index 9878ecd2..c1ca2092 100644
--- a/res/color/car_nav_icon_fill_color_selected.xml
+++ b/res/color/car_nav_icon_fill_color_selected.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2023 The Android Open Source Project
+  ~ Copyright (C) 2025 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -16,6 +16,7 @@
   -->
 
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:color="@color/car_on_primary"  android:state_selected="true"/>
-    <item android:color="@color/car_primary_100"/>
+    <item android:color="?oemColorOnPrimary"  android:state_selected="true"/>
+    <!-- This needs to be onSurface to work with both dark and light theme-->
+    <item android:color="?oemColorOnSurface"/>
 </selector>
diff --git a/AndroidManifest-res.xml b/res/color/car_nav_unseen_indicator_color.xml
similarity index 77%
rename from AndroidManifest-res.xml
rename to res/color/car_nav_unseen_indicator_color.xml
index a06afbb3..8694c27f 100644
--- a/AndroidManifest-res.xml
+++ b/res/color/car_nav_unseen_indicator_color.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2024 The Android Open Source Project
+  ~ Copyright (C) 2025 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -14,6 +14,7 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<manifest package= "com.android.systemui.car.res">
-    <application/>
-</manifest>
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorError"/>
+</selector>
diff --git a/res/color/car_qc_unseen_indicator_color.xml b/res/color/car_qc_unseen_indicator_color.xml
new file mode 100644
index 00000000..57050bd4
--- /dev/null
+++ b/res/color/car_qc_unseen_indicator_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorYellow"/>
+</selector>
diff --git a/res/color/car_quick_controls_icon_drawable_color.xml b/res/color/car_quick_controls_icon_drawable_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/car_quick_controls_icon_drawable_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/car_quick_controls_pill_button_background_color.xml b/res/color/car_quick_controls_pill_button_background_color.xml
new file mode 100644
index 00000000..bdec3f9c
--- /dev/null
+++ b/res/color/car_quick_controls_pill_button_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHighest"/>
+</selector>
diff --git a/res/color/car_user_switcher_add_user_add_sign_color.xml b/res/color/car_user_switcher_add_user_add_sign_color.xml
new file mode 100644
index 00000000..eeda059b
--- /dev/null
+++ b/res/color/car_user_switcher_add_user_add_sign_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurfaceVariant"/>
+</selector>
diff --git a/res/color/car_user_switcher_add_user_background_color.xml b/res/color/car_user_switcher_add_user_background_color.xml
new file mode 100644
index 00000000..3df445b6
--- /dev/null
+++ b/res/color/car_user_switcher_add_user_background_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceVariant"/>
+</selector>
diff --git a/res/color/car_user_switcher_background_color.xml b/res/color/car_user_switcher_background_color.xml
new file mode 100644
index 00000000..72ba4e7f
--- /dev/null
+++ b/res/color/car_user_switcher_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorBackground"/>
+</selector>
diff --git a/res/color/car_user_switcher_name_text_color.xml b/res/color/car_user_switcher_name_text_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/car_user_switcher_name_text_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/car_user_switching_dialog_background_color.xml b/res/color/car_user_switching_dialog_background_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/car_user_switching_dialog_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/car_user_switching_dialog_loading_text_color.xml b/res/color/car_user_switching_dialog_loading_text_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/car_user_switching_dialog_loading_text_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/car_volume_dialog_tint.xml b/res/color/car_volume_dialog_tint.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/car_volume_dialog_tint.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/car_volume_item_background_color.xml b/res/color/car_volume_item_background_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/car_volume_item_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/car_volume_item_divider_color.xml b/res/color/car_volume_item_divider_color.xml
new file mode 100644
index 00000000..845e875f
--- /dev/null
+++ b/res/color/car_volume_item_divider_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOutline"/>
+</selector>
diff --git a/res/color/display_input_lock_background_color.xml b/res/color/display_input_lock_background_color.xml
new file mode 100644
index 00000000..715ca467
--- /dev/null
+++ b/res/color/display_input_lock_background_color.xml
@@ -0,0 +1,19 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="?oemColorSurfaceContainerHighest"/>
+</selector>
diff --git a/res/color/display_input_lock_icon_color.xml b/res/color/display_input_lock_icon_color.xml
new file mode 100644
index 00000000..142af275
--- /dev/null
+++ b/res/color/display_input_lock_icon_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2021 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/docked_divider_background.xml b/res/color/docked_divider_background.xml
new file mode 100644
index 00000000..3ccd1f7a
--- /dev/null
+++ b/res/color/docked_divider_background.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/hvac_background_color.xml b/res/color/hvac_background_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/hvac_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/hvac_fanspeed_bg_color.xml b/res/color/hvac_fanspeed_bg_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/hvac_fanspeed_bg_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/hvac_fanspeed_off_active_bg.xml b/res/color/hvac_fanspeed_off_active_bg.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/hvac_fanspeed_off_active_bg.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/hvac_fanspeed_off_active_text_color.xml b/res/color/hvac_fanspeed_off_active_text_color.xml
new file mode 100644
index 00000000..59386e8a
--- /dev/null
+++ b/res/color/hvac_fanspeed_off_active_text_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/hvac_fanspeed_off_inactive_text_color.xml b/res/color/hvac_fanspeed_off_inactive_text_color.xml
new file mode 100644
index 00000000..bd8f7d08
--- /dev/null
+++ b/res/color/hvac_fanspeed_off_inactive_text_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSecondary"/>
+</selector>
diff --git a/res/color/hvac_fanspeed_segment_color.xml b/res/color/hvac_fanspeed_segment_color.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/hvac_fanspeed_segment_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/hvac_icon_color.xml b/res/color/hvac_icon_color.xml
new file mode 100644
index 00000000..191ee486
--- /dev/null
+++ b/res/color/hvac_icon_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSecondaryContainer"/>
+</selector>
diff --git a/res/color/hvac_icon_off_foreground_color.xml b/res/color/hvac_icon_off_foreground_color.xml
new file mode 100644
index 00000000..191ee486
--- /dev/null
+++ b/res/color/hvac_icon_off_foreground_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSecondaryContainer"/>
+</selector>
diff --git a/res/color/hvac_icon_on_background_color.xml b/res/color/hvac_icon_on_background_color.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/hvac_icon_on_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/hvac_icon_on_foreground_color.xml b/res/color/hvac_icon_on_foreground_color.xml
new file mode 100644
index 00000000..59386e8a
--- /dev/null
+++ b/res/color/hvac_icon_on_foreground_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/hvac_master_switch_color.xml b/res/color/hvac_master_switch_color.xml
new file mode 100644
index 00000000..191ee486
--- /dev/null
+++ b/res/color/hvac_master_switch_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSecondaryContainer"/>
+</selector>
diff --git a/res/color/hvac_module_background_color.xml b/res/color/hvac_module_background_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/hvac_module_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/hvac_panel_handle_bar_color.xml b/res/color/hvac_panel_handle_bar_color.xml
new file mode 100644
index 00000000..c39fd105
--- /dev/null
+++ b/res/color/hvac_panel_handle_bar_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceVariant"/>
+</selector>
diff --git a/res/color/hvac_seat_heat_level_drawable_off_fill_color.xml b/res/color/hvac_seat_heat_level_drawable_off_fill_color.xml
new file mode 100644
index 00000000..62cd3b8e
--- /dev/null
+++ b/res/color/hvac_seat_heat_level_drawable_off_fill_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerLow"/>
+</selector>
diff --git a/res/color/hvac_seat_heat_level_drawable_on_fill_color.xml b/res/color/hvac_seat_heat_level_drawable_on_fill_color.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/hvac_seat_heat_level_drawable_on_fill_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/hvac_temperature_control_icon_fill_color.xml b/res/color/hvac_temperature_control_icon_fill_color.xml
new file mode 100644
index 00000000..59386e8a
--- /dev/null
+++ b/res/color/hvac_temperature_control_icon_fill_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/hvac_temperature_default_bg_color.xml b/res/color/hvac_temperature_default_bg_color.xml
new file mode 100644
index 00000000..8694c27f
--- /dev/null
+++ b/res/color/hvac_temperature_default_bg_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorError"/>
+</selector>
diff --git a/res/color/hvac_temperature_level_1.xml b/res/color/hvac_temperature_level_1.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/hvac_temperature_level_1.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/hvac_temperature_off_text_bg_color.xml b/res/color/hvac_temperature_off_text_bg_color.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/hvac_temperature_off_text_bg_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/ic_ux_restricted_color.xml b/res/color/ic_ux_restricted_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/ic_ux_restricted_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/keyguard_keypad_image_color.xml b/res/color/keyguard_keypad_image_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/keyguard_keypad_image_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/list_divider_color.xml b/res/color/list_divider_color.xml
new file mode 100644
index 00000000..845e875f
--- /dev/null
+++ b/res/color/list_divider_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOutline"/>
+</selector>
diff --git a/res/color/notification_handle_bar_color.xml b/res/color/notification_handle_bar_color.xml
new file mode 100644
index 00000000..c39fd105
--- /dev/null
+++ b/res/color/notification_handle_bar_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceVariant"/>
+</selector>
diff --git a/res/color/notification_shade_background_color.xml b/res/color/notification_shade_background_color.xml
new file mode 100644
index 00000000..59fa86b5
--- /dev/null
+++ b/res/color/notification_shade_background_color.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:alpha="0.84"
+        android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/pin_pad_icon_background_color.xml b/res/color/pin_pad_icon_background_color.xml
index a2b9c76d..56e663b7 100644
--- a/res/color/pin_pad_icon_background_color.xml
+++ b/res/color/pin_pad_icon_background_color.xml
@@ -23,27 +23,27 @@
             <item android:state_activated="true">
                 <shape>
                     <solid android:color="@color/car_control_highlight"/>
-                    <corners android:radius="@dimen/pin_pad_key_radius"/>
+                    <corners android:radius="?pinPadKeyRadius"/>
                 </shape>
             </item>
             <item android:state_focused="true" android:state_pressed="true">
                 <shape>
                     <solid android:color="@color/car_rotary_focus_pressed_fill_color"/>
                     <stroke android:width="@dimen/car_rotary_focus_pressed_stroke_width" android:color="@color/car_rotary_focus_stroke_color"/>
-                    <corners android:radius="@dimen/pin_pad_key_radius"/>
+                    <corners android:radius="?pinPadKeyRadius"/>
                 </shape>
             </item>
             <item android:state_focused="true">
                 <shape>
                     <solid android:color="@color/car_rotary_focus_fill_color"/>
                     <stroke android:width="@dimen/car_rotary_focus_stroke_width" android:color="@color/car_rotary_focus_stroke_color"/>
-                    <corners android:radius="@dimen/pin_pad_key_radius"/>
+                    <corners android:radius="?pinPadKeyRadius"/>
                 </shape>
             </item>
             <item>
                 <shape>
                     <solid android:color="@color/car_secondary_container"/>
-                    <corners android:radius="@dimen/pin_pad_key_radius"/>
+                    <corners android:radius="?pinPadKeyRadius"/>
                 </shape>
             </item>
         </selector>
@@ -51,9 +51,9 @@
 
     <item android:id="@android:id/mask">
         <shape>
-            <corners android:radius="@dimen/pin_pad_key_radius"/>
+            <corners android:radius="?pinPadKeyRadius"/>
             <!-- This is a mask color and needs to be set. Would not show in UI. -->
-            <solid android:color="@android:color/white"/>
+            <solid android:color="?oemColorOnSurface"/>
         </shape>
     </item>
 </ripple>
\ No newline at end of file
diff --git a/res/color/privacy_chip_dark_icon_color.xml b/res/color/privacy_chip_dark_icon_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/privacy_chip_dark_icon_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/privacy_chip_indicator_color.xml b/res/color/privacy_chip_indicator_color.xml
new file mode 100644
index 00000000..4a67b096
--- /dev/null
+++ b/res/color/privacy_chip_indicator_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorGreen"/>
+</selector>
diff --git a/res/color/privacy_chip_indicator_outside_stroke_color.xml b/res/color/privacy_chip_indicator_outside_stroke_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/privacy_chip_indicator_outside_stroke_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/qc_pop_up_color.xml b/res/color/qc_pop_up_color.xml
new file mode 100644
index 00000000..62cd3b8e
--- /dev/null
+++ b/res/color/qc_pop_up_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerLow"/>
+</selector>
diff --git a/res/color/qc_pop_up_text_color.xml b/res/color/qc_pop_up_text_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/qc_pop_up_text_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/status_icon_highlighted_color.xml b/res/color/status_icon_highlighted_color.xml
new file mode 100644
index 00000000..59386e8a
--- /dev/null
+++ b/res/color/status_icon_highlighted_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/status_icon_not_highlighted_color.xml b/res/color/status_icon_not_highlighted_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/status_icon_not_highlighted_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/status_icon_panel_bg_color.xml b/res/color/status_icon_panel_bg_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/status_icon_panel_bg_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/status_icon_selected_button_color.xml b/res/color/status_icon_selected_button_color.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/status_icon_selected_button_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/system_bar_background_opaque.xml b/res/color/system_bar_background_opaque.xml
new file mode 100644
index 00000000..a9d25cc5
--- /dev/null
+++ b/res/color/system_bar_background_opaque.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/system_bar_background_pill_color.xml b/res/color/system_bar_background_pill_color.xml
new file mode 100644
index 00000000..7bcf67eb
--- /dev/null
+++ b/res/color/system_bar_background_pill_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHigh"/>
+</selector>
diff --git a/res/color/system_bar_clock_text_color.xml b/res/color/system_bar_clock_text_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/system_bar_clock_text_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/system_bar_icon_color.xml b/res/color/system_bar_icon_color.xml
new file mode 100644
index 00000000..0ba648b7
--- /dev/null
+++ b/res/color/system_bar_icon_color.xml
@@ -0,0 +1,19 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/system_bar_icon_selected_color.xml b/res/color/system_bar_icon_selected_color.xml
new file mode 100644
index 00000000..59386e8a
--- /dev/null
+++ b/res/color/system_bar_icon_selected_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/system_bar_text_color.xml b/res/color/system_bar_text_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/system_bar_text_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/system_bar_text_selected_color.xml b/res/color/system_bar_text_selected_color.xml
new file mode 100644
index 00000000..59386e8a
--- /dev/null
+++ b/res/color/system_bar_text_selected_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/user_picker_background_pill_color.xml b/res/color/user_picker_background_pill_color.xml
new file mode 100644
index 00000000..7bcf67eb
--- /dev/null
+++ b/res/color/user_picker_background_pill_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHigh"/>
+</selector>
diff --git a/res/color/user_picker_bottom_bar_color.xml b/res/color/user_picker_bottom_bar_color.xml
new file mode 100644
index 00000000..3485a60c
--- /dev/null
+++ b/res/color/user_picker_bottom_bar_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurface"/>
+</selector>
diff --git a/res/color/user_picker_current_login_state_color.xml b/res/color/user_picker_current_login_state_color.xml
new file mode 100644
index 00000000..d71020a6
--- /dev/null
+++ b/res/color/user_picker_current_login_state_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/user_picker_other_login_state_color.xml b/res/color/user_picker_other_login_state_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/user_picker_other_login_state_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/user_picker_snack_bar_background_color.xml b/res/color/user_picker_snack_bar_background_color.xml
new file mode 100644
index 00000000..7bcf67eb
--- /dev/null
+++ b/res/color/user_picker_snack_bar_background_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHigh"/>
+</selector>
diff --git a/res/color/user_picker_snack_bar_transparent_color.xml b/res/color/user_picker_snack_bar_transparent_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/user_picker_snack_bar_transparent_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/user_picker_user_name_color.xml b/res/color/user_picker_user_name_color.xml
new file mode 100644
index 00000000..a6eaa09a
--- /dev/null
+++ b/res/color/user_picker_user_name_color.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/drawable/activity_blocking_action_button_background.xml b/res/drawable/activity_blocking_action_button_background.xml
index 14c695e8..efb7106c 100644
--- a/res/drawable/activity_blocking_action_button_background.xml
+++ b/res/drawable/activity_blocking_action_button_background.xml
@@ -19,7 +19,7 @@
     <item>
         <shape android:shape="rectangle">
             <solid android:color="@color/activity_blocking_action_button_background_color" />
-            <corners android:radius="@dimen/activity_blocking_action_button_corner_radius"/>
+            <corners android:radius="?activityBlockingActionButtonCornerRadius"/>
         </shape>
     </item>
 </ripple>
diff --git a/res/drawable/arrow_back.xml b/res/drawable/arrow_back.xml
new file mode 100644
index 00000000..f73a96e3
--- /dev/null
+++ b/res/drawable/arrow_back.xml
@@ -0,0 +1,27 @@
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportHeight="24"
+    android:viewportWidth="24">
+    <group>
+        <clip-path android:pathData="M0,0h24v24h-24z" />
+        <path
+            android:fillColor="?oemColorOnSurface"
+            android:pathData="M7.825,13L13.425,18.6L12,20L4,12L12,4L13.425,5.4L7.825,11H20V13H7.825Z" />
+    </group>
+</vector>
diff --git a/res/drawable/bg_arrow_container_default.xml b/res/drawable/bg_arrow_container_default.xml
index f74cec26..8fc684d4 100644
--- a/res/drawable/bg_arrow_container_default.xml
+++ b/res/drawable/bg_arrow_container_default.xml
@@ -17,5 +17,5 @@
 <shape xmlns:android="http://schemas.android.com/apk/res/android"
     android:shape="rectangle">
     <solid android:color="@color/qc_pop_up_color" />
-    <corners android:radius="@dimen/data_subscription_pop_up_radius" />
+    <corners android:radius="?dataSubscriptionPopUpRadius" />
 </shape>
\ No newline at end of file
diff --git a/res/drawable/car_ic_arrow.xml b/res/drawable/car_ic_arrow.xml
index cfacbf98..019a5432 100644
--- a/res/drawable/car_ic_arrow.xml
+++ b/res/drawable/car_ic_arrow.xml
@@ -19,6 +19,6 @@
         android:viewportWidth="48.0"
         android:viewportHeight="48.0">
     <path
-        android:fillColor="#FFFFFFFF"
+        android:fillColor="?oemColorOnSurface"
         android:pathData="M14.0,20.0l10.0,10.0 10.0,-10.0z"/>
 </vector>
diff --git a/res/drawable/car_ic_arrow_drop_up.xml b/res/drawable/car_ic_arrow_drop_up.xml
index 81e7262c..356c2eb0 100644
--- a/res/drawable/car_ic_arrow_drop_up.xml
+++ b/res/drawable/car_ic_arrow_drop_up.xml
@@ -19,6 +19,6 @@
         android:viewportWidth="48.0"
         android:viewportHeight="48.0">
     <path
-        android:fillColor="#FFFFFFFF"
+        android:fillColor="?oemColorOnSurface"
         android:pathData="M14 28l10-10 10 10z"/>
 </vector>
diff --git a/res/drawable/car_ic_keyboard_arrow_down.xml b/res/drawable/car_ic_keyboard_arrow_down.xml
index 3709aa54..b3e1d2ba 100644
--- a/res/drawable/car_ic_keyboard_arrow_down.xml
+++ b/res/drawable/car_ic_keyboard_arrow_down.xml
@@ -23,5 +23,5 @@
     android:viewportHeight="48.0">
   <path
       android:pathData="M14.83 16.42L24 25.59l9.17-9.17L36 19.25l-12 12-12-12z"
-      android:fillColor="#ffffff"/>
+      android:fillColor="?oemColorOnSurface"/>
 </vector>
\ No newline at end of file
diff --git a/res/drawable/car_ic_logout.xml b/res/drawable/car_ic_logout.xml
index 276e4596..ba9ab9ff 100644
--- a/res/drawable/car_ic_logout.xml
+++ b/res/drawable/car_ic_logout.xml
@@ -22,6 +22,6 @@
         android:viewportHeight="24.0">
 
     <path
-        android:fillColor="#FFFFFFFF"
+        android:fillColor="?oemColorOnSurface"
         android:pathData="M5 21q-0.825 0-1.413-0.587Q3 19.825 3 19V5q0-0.825 0.587 -1.413Q4.175 3 5 3h7v2H5v14h7v2Zm11-4-1.375-1.45 2.55-2.55H9v-2h8.175l-2.55-2.55L16 7l5 5Z" />
 </vector>
\ No newline at end of file
diff --git a/res/drawable/car_ic_navigation.xml b/res/drawable/car_ic_navigation.xml
index 07a53728..24dd11c1 100644
--- a/res/drawable/car_ic_navigation.xml
+++ b/res/drawable/car_ic_navigation.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="24"
     android:viewportHeight="24">
   <path
-      android:fillColor="#000000"
+      android:fillColor="?oemColorSurface"
       android:pathData="M12,2L4,20l1,1l7,-3l7,3l1,-1L12,2z"/>
 </vector>
diff --git a/res/drawable/car_ic_navigation_mute.xml b/res/drawable/car_ic_navigation_mute.xml
index c46a0a20..3db17d9b 100644
--- a/res/drawable/car_ic_navigation_mute.xml
+++ b/res/drawable/car_ic_navigation_mute.xml
@@ -21,11 +21,11 @@
     android:viewportHeight="24">
   <path
       android:pathData="M8.923,8.9233L4,20L5,21L12,18L19,21L19.9998,20.0002L8.923,8.9233Z"
-      android:fillColor="#000000"/>
+      android:fillColor="?oemColorSurface"/>
   <path
       android:pathData="M17.7443,14.9246L9.7907,6.971L12,2L17.7443,14.9246Z"
-      android:fillColor="#000000"/>
+      android:fillColor="?oemColorSurface"/>
   <path
       android:pathData="M3.41,3L2,4.41L20.38,22.79L21.79,21.38L3.41,3Z"
-      android:fillColor="#000000"/>
+      android:fillColor="?oemColorSurface"/>
 </vector>
diff --git a/res/drawable/car_ic_phone.xml b/res/drawable/car_ic_phone.xml
index 51e7239a..18fcf2cd 100644
--- a/res/drawable/car_ic_phone.xml
+++ b/res/drawable/car_ic_phone.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="24"
     android:viewportHeight="24">
   <path
-      android:fillColor="#FF000000"
+      android:fillColor="?oemColorSurface"
       android:pathData="M7.96,14.46l2.62,2.62c2.75,-1.49 5.01,-3.75 6.5,-6.5l-2.62,-2.62c-0.24,-0.24 -0.34,-0.58 -0.27,-0.9l0.65,-3.26c0.09,-0.46 0.5,-0.8 0.98,-0.8h4.15c0.56,0 1.03,0.47 1,1.03 -0.17,2.91 -1.04,5.63 -2.43,8.01 -1.57,2.69 -3.81,4.93 -6.5,6.5 -2.38,1.39 -5.1,2.26 -8.01,2.43 -0.56,0.03 -1.03,-0.44 -1.03,-1v-4.15c0,-0.48 0.34,-0.89 0.8,-0.98l3.26,-0.65c0.33,-0.07 0.67,0.04 0.9,0.27z"/>
 </vector>
diff --git a/res/drawable/car_ic_phone_volume.xml b/res/drawable/car_ic_phone_volume.xml
index 51e7239a..18fcf2cd 100644
--- a/res/drawable/car_ic_phone_volume.xml
+++ b/res/drawable/car_ic_phone_volume.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="24"
     android:viewportHeight="24">
   <path
-      android:fillColor="#FF000000"
+      android:fillColor="?oemColorSurface"
       android:pathData="M7.96,14.46l2.62,2.62c2.75,-1.49 5.01,-3.75 6.5,-6.5l-2.62,-2.62c-0.24,-0.24 -0.34,-0.58 -0.27,-0.9l0.65,-3.26c0.09,-0.46 0.5,-0.8 0.98,-0.8h4.15c0.56,0 1.03,0.47 1,1.03 -0.17,2.91 -1.04,5.63 -2.43,8.01 -1.57,2.69 -3.81,4.93 -6.5,6.5 -2.38,1.39 -5.1,2.26 -8.01,2.43 -0.56,0.03 -1.03,-0.44 -1.03,-1v-4.15c0,-0.48 0.34,-0.89 0.8,-0.98l3.26,-0.65c0.33,-0.07 0.67,0.04 0.9,0.27z"/>
 </vector>
diff --git a/res/drawable/car_ic_phone_volume_mute.xml b/res/drawable/car_ic_phone_volume_mute.xml
index 8005045c..13c5a7f3 100644
--- a/res/drawable/car_ic_phone_volume_mute.xml
+++ b/res/drawable/car_ic_phone_volume_mute.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="24"
     android:viewportHeight="24">
   <path
-      android:fillColor="#FF000000"
+      android:fillColor="?oemColorSurface"
       android:pathData="M14.22,17.05c-0.69,0.55 -1.41,1.05 -2.18,1.49 -2.38,1.39 -5.1,2.26 -8.01,2.43 -0.56,0.03 -1.03,-0.44 -1.03,-1v-4.15c0,-0.48 0.34,-0.89 0.8,-0.98l3.26,-0.65c0.33,-0.07 0.67,0.04 0.9,0.27l2.62,2.62c0.78,-0.42 1.52,-0.91 2.22,-1.45L1.39,4.22l1.42,-1.41L21.19,21.2l-1.41,1.41 -5.56,-5.56zM15.62,12.82c0.55,-0.7 1.04,-1.45 1.47,-2.24l-2.62,-2.62c-0.24,-0.24 -0.34,-0.58 -0.27,-0.9l0.65,-3.26c0.09,-0.46 0.5,-0.8 0.98,-0.8h4.15c0.56,0 1.03,0.47 1,1.03 -0.17,2.91 -1.04,5.63 -2.43,8.01 -0.45,0.77 -0.96,1.51 -1.51,2.2l-1.42,-1.42z"/>
 </vector>
diff --git a/res/drawable/car_ic_selection_bg.xml b/res/drawable/car_ic_selection_bg.xml
index 12993f5b..3a421978 100644
--- a/res/drawable/car_ic_selection_bg.xml
+++ b/res/drawable/car_ic_selection_bg.xml
@@ -23,6 +23,6 @@
         android:fillColor="?android:attr/colorAccent"
         android:fillType="evenOdd"
         android:pathData="M4,0L66,0A4,4 0,0 1,70 4L70,66A4,4 0,0 1,66 70L4,70A4,4 0,0 1,0 66L0,4A4,4 0,0 1,4 0z"
-        android:strokeColor="#00000000"
+        android:strokeColor="?oemColorSurface"
         android:strokeWidth="1"/>
 </vector>
diff --git a/res/drawable/car_quick_controls_pill_button_background.xml b/res/drawable/car_quick_controls_pill_button_background.xml
index f91a7bfb..10c2efc6 100644
--- a/res/drawable/car_quick_controls_pill_button_background.xml
+++ b/res/drawable/car_quick_controls_pill_button_background.xml
@@ -21,7 +21,7 @@
         <aapt:attr name="android:drawable">
             <shape android:shape="rectangle">
                 <solid android:color="@color/car_quick_controls_pill_button_background_color"/>
-                <corners android:radius="@dimen/system_bar_pill_radius"/>
+                <corners android:radius="?systemBarPillRadius"/>
             </shape>
         </aapt:attr>
     </item>
diff --git a/res/drawable/car_rounded_bg_bottom.xml b/res/drawable/car_rounded_bg_bottom.xml
index 07227fbe..d834ec01 100644
--- a/res/drawable/car_rounded_bg_bottom.xml
+++ b/res/drawable/car_rounded_bg_bottom.xml
@@ -17,11 +17,11 @@
 
 <shape xmlns:android="http://schemas.android.com/apk/res/android"
        android:shape="rectangle">
-    <solid android:color="?android:attr/colorBackgroundFloating" />
+    <solid android:color="?oemColorSurfaceContainerHigh" />
     <corners
-        android:bottomLeftRadius="@*android:dimen/car_radius_3"
+        android:bottomLeftRadius="?oemShapeCornerSmall"
         android:topLeftRadius="0dp"
-        android:bottomRightRadius="@*android:dimen/car_radius_3"
+        android:bottomRightRadius="?oemShapeCornerSmall"
         android:topRightRadius="0dp"
         />
 </shape>
diff --git a/res/drawable/car_seekbar_thumb.xml b/res/drawable/car_seekbar_thumb.xml
index 2649a005..c9306fdb 100644
--- a/res/drawable/car_seekbar_thumb.xml
+++ b/res/drawable/car_seekbar_thumb.xml
@@ -23,12 +23,12 @@
                 android:left="@*android:dimen/car_padding_1"
                 android:right="@*android:dimen/car_padding_1"
                 android:top="@*android:dimen/car_padding_1"/>
-            <solid android:color="@android:color/black"/>
+            <solid android:color="?oemColorSurface"/>
         </shape>
     </item>
     <item>
         <shape android:shape="oval">
-            <solid android:color="@*android:color/car_accent"/>
+            <solid android:color="?oemColorPrimary"/>
             <size
                 android:width="@*android:dimen/car_seekbar_thumb_size"
                 android:height="@*android:dimen/car_seekbar_thumb_size"/>
diff --git a/res/drawable/car_stat_sys_data_bluetooth_indicator.xml b/res/drawable/car_stat_sys_data_bluetooth_indicator.xml
index 34578fe2..b372c44d 100644
--- a/res/drawable/car_stat_sys_data_bluetooth_indicator.xml
+++ b/res/drawable/car_stat_sys_data_bluetooth_indicator.xml
@@ -23,6 +23,6 @@ Copyright (C) 2018 The Android Open Source Project
         android:translateX="0.5" >
         <path
             android:pathData="M9.57,8.5l2.79,-2.78c0.3,-0.3 0.3,-0.8 0,-1.1L9.04,1.29L9.02,1.27C8.7,0.98 8.21,1 7.91,1.31C7.78,1.45 7.71,1.64 7.71,1.84v4.79L4.69,3.61c-0.3,-0.3 -0.79,-0.3 -1.09,0s-0.3,0.79 0,1.09L7.39,8.5L3.6,12.29c-0.3,0.3 -0.3,0.79 0,1.09s0.79,0.3 1.09,0l3.01,-3.01v4.8c0,0.42 0.35,0.77 0.77,0.77c0.19,0 0.39,-0.07 0.53,-0.21l0.04,-0.04l3.32,-3.32c0.3,-0.3 0.3,-0.8 0,-1.1L9.57,8.5zM9.19,6.77v-3.2l1.6,1.6L9.19,6.77zM9.19,13.42v-3.2l1.6,1.6L9.19,13.42zM4.03,9.29c-0.44,0.44 -1.15,0.44 -1.58,0C2.02,8.86 2.02,8.16 2.45,7.72l0.01,-0.01C2.89,7.27 3.59,7.27 4.02,7.7l0.01,0.01C4.47,8.15 4.47,8.85 4.03,9.29zM14.44,7.71c0.44,0.44 0.44,1.15 0,1.58c-0.44,0.44 -1.15,0.44 -1.58,0c-0.44,-0.43 -0.44,-1.13 -0.01,-1.57l0.01,-0.01C13.3,7.28 14,7.27 14.43,7.7C14.44,7.7 14.44,7.71 14.44,7.71z"
-            android:fillColor="#FFFFFF"/>
+            android:fillColor="?oemColorOnSurface"/>
     </group>
 </vector>
diff --git a/res/drawable/close.xml b/res/drawable/close.xml
new file mode 100644
index 00000000..fab4e2ef
--- /dev/null
+++ b/res/drawable/close.xml
@@ -0,0 +1,27 @@
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportHeight="24"
+    android:viewportWidth="24">
+    <group>
+        <clip-path android:pathData="M0,0h24v24h-24z" />
+        <path
+            android:fillColor="?oemColorOnSurface"
+            android:pathData="M6.4,19L5,17.6L10.6,12L5,6.4L6.4,5L12,10.6L17.6,5L19,6.4L13.4,12L19,17.6L17.6,19L12,13.4L6.4,19Z" />
+    </group>
+</vector>
diff --git a/res/drawable/displaycompat_arrow_back_32.xml b/res/drawable/displaycompat_arrow_back_32.xml
index f8bb32d5..d6d9337f 100644
--- a/res/drawable/displaycompat_arrow_back_32.xml
+++ b/res/drawable/displaycompat_arrow_back_32.xml
@@ -16,5 +16,5 @@
 <vector android:height="32dp" android:tint="@android:color/white"
     android:viewportHeight="24" android:viewportWidth="24"
     android:width="32dp" xmlns:android="http://schemas.android.com/apk/res/android">
-    <path android:fillColor="@android:color/white" android:pathData="M20,11H7.83l5.59,-5.59L12,4l-8,8 8,8 1.41,-1.41L7.83,13H20v-2z"/>
+    <path android:fillColor="?oemColorOnSurface" android:pathData="M20,11H7.83l5.59,-5.59L12,4l-8,8 8,8 1.41,-1.41L7.83,13H20v-2z"/>
 </vector>
diff --git a/res/drawable/displaycompat_fullscreen_32.xml b/res/drawable/displaycompat_fullscreen_32.xml
index c0fa74ec..1b178df0 100644
--- a/res/drawable/displaycompat_fullscreen_32.xml
+++ b/res/drawable/displaycompat_fullscreen_32.xml
@@ -16,5 +16,5 @@
 <vector android:height="32dp" android:tint="@android:color/white"
     android:viewportHeight="24" android:viewportWidth="24"
     android:width="32dp" xmlns:android="http://schemas.android.com/apk/res/android">
-    <path android:fillColor="@android:color/white" android:pathData="M7,14L5,14v5h5v-2L7,17v-3zM5,10h2L7,7h3L10,5L5,5v5zM17,17h-3v2h5v-5h-2v3zM14,5v2h3v3h2L19,5h-5z"/>
+    <path android:fillColor="?oemColorOnSurface" android:pathData="M7,14L5,14v5h5v-2L7,17v-3zM5,10h2L7,7h3L10,5L5,5v5zM17,17h-3v2h5v-5h-2v3zM14,5v2h3v3h2L19,5h-5z"/>
 </vector>
diff --git a/res/drawable/displaycompat_round_bg.xml b/res/drawable/displaycompat_round_bg.xml
index 3950529f..286e343b 100644
--- a/res/drawable/displaycompat_round_bg.xml
+++ b/res/drawable/displaycompat_round_bg.xml
@@ -18,8 +18,8 @@
     android:shape="oval">
 
     <gradient
-        android:startColor="#3C5D93"
-        android:endColor="#3C5D93"
+        android:startColor="?oemColorSurfaceContainer"
+        android:endColor="?oemColorSurfaceContainer"
         android:angle="0"/>
 
     <size
diff --git a/res/drawable/hvac_background.xml b/res/drawable/hvac_background.xml
index 73cb5bb2..a51e87ff 100644
--- a/res/drawable/hvac_background.xml
+++ b/res/drawable/hvac_background.xml
@@ -18,5 +18,5 @@
     <solid android:color="@color/hvac_background_color"/>
 
     <corners
-        android:radius="@dimen/hvac_panel_background_radius"/>
+        android:radius="?hvacPanelBackgroundRadius"/>
 </shape>
\ No newline at end of file
diff --git a/res/drawable/hvac_decrease_button.xml b/res/drawable/hvac_decrease_button.xml
index dc748b59..468b0aed 100644
--- a/res/drawable/hvac_decrease_button.xml
+++ b/res/drawable/hvac_decrease_button.xml
@@ -26,7 +26,7 @@
                     android:viewportWidth="960"
                     android:viewportHeight="960">
                 <path
-                    android:fillColor="@color/car_outline"
+                    android:fillColor="?oemColorOutline"
                     android:pathData="M200,520L200,440L760,440L760,520L200,520Z"/>
             </vector>
         </aapt:attr>
diff --git a/res/drawable/hvac_increase_button.xml b/res/drawable/hvac_increase_button.xml
index ea4f1393..d7e262f3 100644
--- a/res/drawable/hvac_increase_button.xml
+++ b/res/drawable/hvac_increase_button.xml
@@ -26,7 +26,7 @@
                     android:viewportWidth="960"
                     android:viewportHeight="960">
                 <path
-                    android:fillColor="@color/car_outline"
+                    android:fillColor="?oemColorOutline"
                     android:pathData="M440,520L200,520L200,440L440,440L440,200L520,200L520,440L760,440L760,520L520,520L520,760L440,760L440,520Z"/>
             </vector>
         </aapt:attr>
diff --git a/res/drawable/hvac_panel_button_bg.xml b/res/drawable/hvac_panel_button_bg.xml
index d1d6c63d..1d41e242 100644
--- a/res/drawable/hvac_panel_button_bg.xml
+++ b/res/drawable/hvac_panel_button_bg.xml
@@ -20,7 +20,7 @@
             <solid android:color="@color/car_ui_rotary_focus_pressed_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_pressed_stroke_width"
                 android:color="@color/car_ui_rotary_focus_pressed_stroke_color"/>
-            <corners android:radius="@dimen/hvac_panel_button_radius"/>
+            <corners android:radius="?hvacPanelButtonRadius"/>
         </shape>
     </item>
     <item android:state_focused="true">
@@ -28,7 +28,7 @@
             <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                 android:color="@color/car_ui_rotary_focus_stroke_color"/>
-            <corners android:radius="@dimen/hvac_panel_button_radius"/>
+            <corners android:radius="?hvacPanelButtonRadius"/>
         </shape>
     </item>
     <item>
@@ -36,13 +36,13 @@
             <item android:id="@android:id/mask">
                 <shape>
                     <solid android:color="@color/hvac_module_background_color"/>
-                    <corners android:radius="@dimen/hvac_panel_button_radius"/>
+                    <corners android:radius="?hvacPanelButtonRadius"/>
                 </shape>
             </item>
             <item android:id="@android:id/background">
                 <shape>
                     <solid android:color="@color/hvac_module_background_color"/>
-                    <corners android:radius="@dimen/hvac_panel_button_radius"/>
+                    <corners android:radius="?hvacPanelButtonRadius"/>
                 </shape>
             </item>
         </ripple>
diff --git a/res/drawable/ic_fan_speed_bg.xml b/res/drawable/ic_fan_speed_bg.xml
index 3afb251c..d6827321 100644
--- a/res/drawable/ic_fan_speed_bg.xml
+++ b/res/drawable/ic_fan_speed_bg.xml
@@ -16,5 +16,5 @@
   -->
 <shape xmlns:android="http://schemas.android.com/apk/res/android">
     <solid android:color="@color/hvac_fanspeed_bg_color"/>
-    <corners android:radius="@dimen/hvac_fan_speed_bar_corner_radius"/>
+    <corners android:radius="?hvacFanSpeedBarCornerRadius"/>
 </shape>
\ No newline at end of file
diff --git a/res/drawable/ic_status_wifi_disabled.xml b/res/drawable/ic_status_wifi_disabled.xml
index 00c9c729..b5f59c93 100644
--- a/res/drawable/ic_status_wifi_disabled.xml
+++ b/res/drawable/ic_status_wifi_disabled.xml
@@ -22,6 +22,6 @@
     android:viewportHeight="24.0"
     android:viewportWidth="24.0">
     <path
-        android:fillColor="@android:color/white"
+        android:fillColor="?oemColorOnSurface"
         android:pathData="M23.64,7c-0.45,-0.34 -4.93,-4 -11.64,-4 -1.5,0 -2.89,0.19 -4.15,0.48L18.18,13.8 23.64,7zM17.04,15.22L3.27,1.44 2,2.72l2.05,2.06C1.91,5.76 0.59,6.82 0.36,7l11.63,14.49 0.01,0.01 0.01,-0.01 3.9,-4.86 3.32,3.32 1.27,-1.27 -3.46,-3.46z"/>
 </vector>
\ No newline at end of file
diff --git a/res/drawable/ic_user_picker.xml b/res/drawable/ic_user_picker.xml
index 4929905a..295c682a 100644
--- a/res/drawable/ic_user_picker.xml
+++ b/res/drawable/ic_user_picker.xml
@@ -1,3 +1,3 @@
-<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="48dp" android:height="48dp" android:viewportWidth="48" android:viewportHeight="48" android:tint="?attr/colorControlNormal">
-<path android:fillColor="@android:color/white" android:pathData="M27,24Q29.45,24 31.175,22.275Q32.9,20.55 32.9,18.1Q32.9,15.65 31.175,13.925Q29.45,12.2 27,12.2Q24.55,12.2 22.825,13.925Q21.1,15.65 21.1,18.1Q21.1,20.55 22.825,22.275Q24.55,24 27,24ZM13,38Q11.75,38 10.875,37.125Q10,36.25 10,35V7Q10,5.75 10.875,4.875Q11.75,4 13,4H41Q42.25,4 43.125,4.875Q44,5.75 44,7V35Q44,36.25 43.125,37.125Q42.25,38 41,38ZM7,44Q5.75,44 4.875,43.125Q4,42.25 4,41V12.5H7V41Q7,41 7,41Q7,41 7,41H35.5V44ZM13,35H41Q38.45,31.75 34.8,29.875Q31.15,28 27,28Q22.85,28 19.2,29.875Q15.55,31.75 13,35Z"/>
+<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="48dp" android:height="48dp" android:viewportWidth="48" android:viewportHeight="48" android:tint="?oemColorOnSurfaceVariant">
+<path android:fillColor="?oemColorOnSurface" android:pathData="M27,24Q29.45,24 31.175,22.275Q32.9,20.55 32.9,18.1Q32.9,15.65 31.175,13.925Q29.45,12.2 27,12.2Q24.55,12.2 22.825,13.925Q21.1,15.65 21.1,18.1Q21.1,20.55 22.825,22.275Q24.55,24 27,24ZM13,38Q11.75,38 10.875,37.125Q10,36.25 10,35V7Q10,5.75 10.875,4.875Q11.75,4 13,4H41Q42.25,4 43.125,4.875Q44,5.75 44,7V35Q44,36.25 43.125,37.125Q42.25,38 41,38ZM7,44Q5.75,44 4.875,43.125Q4,42.25 4,41V12.5H7V41Q7,41 7,41Q7,41 7,41H35.5V44ZM13,35H41Q38.45,31.75 34.8,29.875Q31.15,28 27,28Q22.85,28 19.2,29.875Q15.55,31.75 13,35Z"/>
 </vector>
diff --git a/res/drawable/nav_bar_background.xml b/res/drawable/nav_bar_background.xml
new file mode 100644
index 00000000..f3169c66
--- /dev/null
+++ b/res/drawable/nav_bar_background.xml
@@ -0,0 +1,18 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="?oemColorSurface" />
+</shape>
diff --git a/res/drawable/nav_bar_button_background.xml b/res/drawable/nav_bar_button_background.xml
index a72b5df4..73c24029 100644
--- a/res/drawable/nav_bar_button_background.xml
+++ b/res/drawable/nav_bar_button_background.xml
@@ -26,7 +26,7 @@
                     <solid android:color="@color/car_ui_rotary_focus_pressed_fill_color"/>
                     <stroke android:width="@dimen/car_ui_rotary_focus_pressed_stroke_width"
                             android:color="@color/car_ui_rotary_focus_pressed_stroke_color"/>
-                    <corners android:radius="@dimen/car_nav_bar_button_selected_corner_radius"/>
+                    <corners android:radius="?hvacFanSpeedBarCornerRadius"/>
                 </shape>
             </item>
         </layer-list>
@@ -43,7 +43,7 @@
                     <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
                     <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                             android:color="@color/car_ui_rotary_focus_stroke_color"/>
-                    <corners android:radius="@dimen/car_nav_bar_button_selected_corner_radius"/>
+                    <corners android:radius="?hvacFanSpeedBarCornerRadius"/>
                 </shape>
             </item>
         </layer-list>
diff --git a/res/drawable/notification_handle_bar.xml b/res/drawable/notification_handle_bar.xml
index a3cd2128..8c2b2bf0 100644
--- a/res/drawable/notification_handle_bar.xml
+++ b/res/drawable/notification_handle_bar.xml
@@ -16,7 +16,7 @@
 -->
 <ripple
     xmlns:android="http://schemas.android.com/apk/res/android"
-    android:color="@android:color/white">
+    android:color="?oemColorOnSurface">
     <item>
         <shape android:shape="rectangle">
             <corners android:radius="@dimen/clear_all_button_radius"/>
diff --git a/res/drawable/notification_material_bg.xml b/res/drawable/notification_material_bg.xml
index a9c7eecb..eaee432e 100644
--- a/res/drawable/notification_material_bg.xml
+++ b/res/drawable/notification_material_bg.xml
@@ -18,7 +18,7 @@
     android:color="@color/notification_ripple_untinted_color">
     <item>
         <shape xmlns:android="http://schemas.android.com/apk/res/android">
-            <solid android:color="?android:attr/colorBackground"/>
+            <solid android:color="?oemColorSurface"/>
             <corners
                 android:radius="@dimen/notification_shadow_radius"/>
         </shape>
diff --git a/res/drawable/notification_material_bg_dim.xml b/res/drawable/notification_material_bg_dim.xml
index a9c7eecb..eaee432e 100644
--- a/res/drawable/notification_material_bg_dim.xml
+++ b/res/drawable/notification_material_bg_dim.xml
@@ -18,7 +18,7 @@
     android:color="@color/notification_ripple_untinted_color">
     <item>
         <shape xmlns:android="http://schemas.android.com/apk/res/android">
-            <solid android:color="?android:attr/colorBackground"/>
+            <solid android:color="?oemColorSurface"/>
             <corners
                 android:radius="@dimen/notification_shadow_radius"/>
         </shape>
diff --git a/res/drawable/privacy_chip_active_background_pill.xml b/res/drawable/privacy_chip_active_background_pill.xml
index b837f53f..090eb886 100644
--- a/res/drawable/privacy_chip_active_background_pill.xml
+++ b/res/drawable/privacy_chip_active_background_pill.xml
@@ -21,7 +21,7 @@
         <aapt:attr name="android:drawable">
             <shape android:shape="rectangle">
                 <solid android:color="@color/privacy_chip_indicator_color"/>
-                <corners android:radius="@dimen/system_bar_pill_radius"/>
+                <corners android:radius="?systemBarPillRadius"/>
             </shape>
         </aapt:attr>
     </item>
diff --git a/res/drawable/privacy_chip_active_background_pill_with_border.xml b/res/drawable/privacy_chip_active_background_pill_with_border.xml
index 38393436..fd8a1956 100644
--- a/res/drawable/privacy_chip_active_background_pill_with_border.xml
+++ b/res/drawable/privacy_chip_active_background_pill_with_border.xml
@@ -23,7 +23,7 @@
                 <stroke android:width="@dimen/privacy_chip_indicator_outside_stroke_width"
                         android:color="@color/privacy_chip_indicator_outside_stroke_color"/>
                 <solid android:color="@color/privacy_chip_indicator_color"/>
-                <corners android:radius="@dimen/system_bar_pill_radius"/>
+                <corners android:radius="?systemBarPillRadius"/>
             </shape>
         </aapt:attr>
     </item>
diff --git a/res/drawable/privacy_chip_inactive_background_pill.xml b/res/drawable/privacy_chip_inactive_background_pill.xml
index b865749f..b5e35ad3 100644
--- a/res/drawable/privacy_chip_inactive_background_pill.xml
+++ b/res/drawable/privacy_chip_inactive_background_pill.xml
@@ -20,7 +20,7 @@
     <item>
         <aapt:attr name="android:drawable">
             <shape android:shape="rectangle">
-                <corners android:radius="@dimen/system_bar_pill_radius"/>
+                <corners android:radius="?systemBarPillRadius"/>
             </shape>
         </aapt:attr>
     </item>
diff --git a/res/drawable/privacy_chip_inactive_selected_background_pill.xml b/res/drawable/privacy_chip_inactive_selected_background_pill.xml
index 1d8c293b..c4f2095f 100644
--- a/res/drawable/privacy_chip_inactive_selected_background_pill.xml
+++ b/res/drawable/privacy_chip_inactive_selected_background_pill.xml
@@ -21,7 +21,7 @@
         <aapt:attr name="android:drawable">
             <shape android:shape="rectangle">
                 <solid android:color="@color/status_icon_selected_button_color"/>
-                <corners android:radius="@dimen/system_bar_pill_selected_radius"/>
+                <corners android:radius="?systemBarPillSelectedRadius"/>
             </shape>
         </aapt:attr>
     </item>
diff --git a/res/drawable/stat_sys_signal_null.xml b/res/drawable/stat_sys_signal_null.xml
index 2b487f9e..531705fe 100644
--- a/res/drawable/stat_sys_signal_null.xml
+++ b/res/drawable/stat_sys_signal_null.xml
@@ -20,6 +20,6 @@ Copyright (C) 2014 The Android Open Source Project
         android:viewportWidth="24.0"
         android:viewportHeight="24.0">
     <path
-        android:fillColor="?attr/backgroundColor"
+        android:fillColor="?oemColorSurface"
         android:pathData="M2.000000,22.000000l20.000000,0.000000L22.000000,2.000000L2.000000,22.000000zM20.000000,20.000000L6.800000,20.000000L20.000000,6.800000L20.000000,20.000000z"/>
 </vector>
diff --git a/res/drawable/status_bar_background.xml b/res/drawable/status_bar_background.xml
new file mode 100644
index 00000000..c739e18d
--- /dev/null
+++ b/res/drawable/status_bar_background.xml
@@ -0,0 +1,19 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="?oemColorSurface" />
+</shape>
+
diff --git a/res/drawable/status_icon_background.xml b/res/drawable/status_icon_background.xml
index f43c77f8..85e4d0df 100644
--- a/res/drawable/status_icon_background.xml
+++ b/res/drawable/status_icon_background.xml
@@ -25,7 +25,7 @@
             <item>
                 <shape android:shape="rectangle">
                     <solid android:color="@color/status_icon_selected_button_color"/>
-                    <corners android:radius="@dimen/system_bar_pill_selected_radius"/>
+                    <corners android:radius="?systemBarPillSelectedRadius"/>
                 </shape>
             </item>
             <item android:drawable="@drawable/system_bar_pill_rotary_background"/>
@@ -38,7 +38,7 @@
             <item>
                 <shape android:shape="rectangle">
                     <solid android:color="@color/system_bar_background_pill_color"/>
-                    <corners android:radius="@dimen/system_bar_pill_radius"/>
+                    <corners android:radius="?systemBarPillRadius"/>
                 </shape>
             </item>
             <item android:drawable="@drawable/system_bar_pill_rotary_background"/>
@@ -49,7 +49,7 @@
             <item>
                 <shape android:shape="rectangle">
                     <solid android:color="@color/status_icon_selected_button_color"/>
-                    <corners android:radius="@dimen/system_bar_pill_selected_radius"/>
+                    <corners android:radius="?systemBarPillSelectedRadius"/>
                 </shape>
             </item>
             <item android:drawable="@drawable/system_bar_pill_rotary_background"/>
diff --git a/res/drawable/status_icon_panel_bg.xml b/res/drawable/status_icon_panel_bg.xml
index d8226e48..fc3ea3ec 100644
--- a/res/drawable/status_icon_panel_bg.xml
+++ b/res/drawable/status_icon_panel_bg.xml
@@ -18,7 +18,7 @@
     <solid android:color="@color/status_icon_panel_bg_color"/>
 
     <corners
-        android:radius="@dimen/car_status_icon_panel_border_radius"/>
+        android:radius="?carStatusIconPanelBorderRadius"/>
 
     <padding
         android:bottom="@dimen/car_status_icon_panel_padding_bottom"
diff --git a/res/drawable/system_bar_background_pill.xml b/res/drawable/system_bar_background_pill.xml
index bf0cb121..b70c9c32 100644
--- a/res/drawable/system_bar_background_pill.xml
+++ b/res/drawable/system_bar_background_pill.xml
@@ -21,7 +21,7 @@
         <aapt:attr name="android:drawable">
             <shape android:shape="rectangle">
                 <solid android:color="@color/system_bar_background_pill_color"/>
-                <corners android:radius="@dimen/system_bar_pill_radius"/>
+                <corners android:radius="?systemBarPillRadius"/>
             </shape>
         </aapt:attr>
     </item>
diff --git a/res/drawable/system_bar_pill_rotary_background.xml b/res/drawable/system_bar_pill_rotary_background.xml
index f49d74c7..b40941b0 100644
--- a/res/drawable/system_bar_pill_rotary_background.xml
+++ b/res/drawable/system_bar_pill_rotary_background.xml
@@ -20,7 +20,7 @@
             <solid android:color="@color/car_ui_rotary_focus_pressed_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_pressed_stroke_width"
                     android:color="@color/car_ui_rotary_focus_pressed_stroke_color"/>
-            <corners android:radius="@dimen/system_bar_pill_selected_radius"/>
+            <corners android:radius="?systemBarPillSelectedRadius"/>
         </shape>
     </item>
     <item android:state_focused="true" android:state_pressed="true">
@@ -28,7 +28,7 @@
             <solid android:color="@color/car_ui_rotary_focus_pressed_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_pressed_stroke_width"
                     android:color="@color/car_ui_rotary_focus_pressed_stroke_color"/>
-            <corners android:radius="@dimen/system_bar_pill_radius"/>
+            <corners android:radius="?systemBarPillRadius"/>
         </shape>
     </item>
     <item android:state_focused="true" android:state_selected="true">
@@ -36,7 +36,7 @@
             <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                     android:color="@color/car_ui_rotary_focus_stroke_color"/>
-            <corners android:radius="@dimen/system_bar_pill_selected_radius"/>
+            <corners android:radius="?systemBarPillSelectedRadius"/>
         </shape>
     </item>
     <item android:state_focused="true">
@@ -44,15 +44,15 @@
             <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                     android:color="@color/car_ui_rotary_focus_stroke_color"/>
-            <corners android:radius="@dimen/system_bar_pill_radius"/>
+            <corners android:radius="?systemBarPillRadius"/>
         </shape>
     </item>
     <item>
         <ripple android:color="@color/car_ui_ripple_color">
             <item android:id="@android:id/mask">
                 <shape android:shape="rectangle">
-                    <solid android:color="?android:colorAccent"/>
-                    <corners android:radius="@dimen/system_bar_pill_radius"/>
+                    <solid android:color="?oemColorPrimary"/>
+                    <corners android:radius="?systemBarPillRadius"/>
                 </shape>
             </item>
         </ripple>
diff --git a/res/drawable/temperature_bar_background.xml b/res/drawable/temperature_bar_background.xml
index 8f57e908..31baf5dd 100644
--- a/res/drawable/temperature_bar_background.xml
+++ b/res/drawable/temperature_bar_background.xml
@@ -15,5 +15,5 @@
   -->
 
 <shape xmlns:android="http://schemas.android.com/apk/res/android">
-    <corners android:radius="@dimen/temperature_bar_bg_radius"/>
+    <corners android:radius="?temperatureBarBgRadius"/>
 </shape>
\ No newline at end of file
diff --git a/res/drawable/userpicker_ic_background.xml b/res/drawable/userpicker_ic_background.xml
index cdeafc55..f402802b 100644
--- a/res/drawable/userpicker_ic_background.xml
+++ b/res/drawable/userpicker_ic_background.xml
@@ -18,7 +18,7 @@
     <item>
         <shape android:shape="rectangle">
             <solid android:color="@color/user_picker_background_pill_color"/>
-            <corners android:radius="@dimen/user_picker_pill_radius"/>
+            <corners android:radius="?userPickerPillRadius"/>
         </shape>
     </item>
     <item>
@@ -28,7 +28,7 @@
                     <solid android:color="@color/car_ui_rotary_focus_pressed_fill_color"/>
                     <stroke android:width="@dimen/car_ui_rotary_focus_pressed_stroke_width"
                             android:color="@color/car_ui_rotary_focus_pressed_stroke_color"/>
-                    <corners android:radius="@dimen/user_picker_pill_radius"/>
+                    <corners android:radius="?userPickerPillRadius"/>
                 </shape>
             </item>
             <item android:state_focused="true">
@@ -36,7 +36,7 @@
                     <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
                     <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                             android:color="@color/car_ui_rotary_focus_stroke_color"/>
-                    <corners android:radius="@dimen/user_picker_pill_radius"/>
+                    <corners android:radius="?userPickerPillRadius"/>
                 </shape>
             </item>
             <item>
@@ -44,7 +44,7 @@
                     <item android:id="@android:id/mask">
                         <shape android:shape="rectangle">
                             <solid android:color="?android:colorAccent"/>
-                            <corners android:radius="@dimen/user_picker_pill_radius"/>
+                            <corners android:radius="?userPickerPillRadius"/>
                         </shape>
                     </item>
                 </ripple>
diff --git a/res/drawable/volume_dialog_background.xml b/res/drawable/volume_dialog_background.xml
index fa3ca8f2..e0595ea7 100644
--- a/res/drawable/volume_dialog_background.xml
+++ b/res/drawable/volume_dialog_background.xml
@@ -15,7 +15,7 @@
   ~ limitations under the License
   -->
 <shape xmlns:android="http://schemas.android.com/apk/res/android">
-    <solid android:color="?android:attr/colorBackgroundFloating"/>
+    <solid android:color="?oemColorSurfaceContainerHigh"/>
     <padding
         android:bottom="5dp"
         android:left="5dp"
diff --git a/res/layout/activity_blocking.xml b/res/layout/activity_blocking.xml
index fff08358..a03c486f 100644
--- a/res/layout/activity_blocking.xml
+++ b/res/layout/activity_blocking.xml
@@ -47,7 +47,7 @@
             android:layout_height="wrap_content"
             android:gravity="center"
             android:text="@string/activity_blocked_text"
-            android:textAppearance="@style/ActivityBlockingActivityText" />
+            style="@style/ActivityBlockingActivityText" />
 
         <LinearLayout
             android:id="@+id/action_button_container"
@@ -74,7 +74,7 @@
             android:id="@+id/debug_info"
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
-            android:textAppearance="@style/ActivityBlockingActivityText"
+            style="@style/ActivityBlockingActivityText"
             android:visibility="gone" />
 
     </LinearLayout>
diff --git a/res/layout/activity_continuous_blank.xml b/res/layout/activity_continuous_blank.xml
index 1cce6085..fc6117a7 100644
--- a/res/layout/activity_continuous_blank.xml
+++ b/res/layout/activity_continuous_blank.xml
@@ -19,6 +19,6 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:orientation="vertical"
-    android:background="@android:color/black"
+    android:background="?oemColorBackground"
     android:gravity="center">
 </LinearLayout>
diff --git a/res/layout/caption_window_decor.xml b/res/layout/caption_window_decor.xml
new file mode 100644
index 00000000..a672eb0d
--- /dev/null
+++ b/res/layout/caption_window_decor.xml
@@ -0,0 +1,43 @@
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
+<com.android.wm.shell.windowdecor.WindowDecorLinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/caption"
+    style="@style/CaptionBarStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content">
+
+    <Button
+        android:id="@+id/back_button"
+        style="@style/CaptionButtonStyle"
+        android:background="@drawable/arrow_back"
+        android:contentDescription="@string/back_button_text"
+        android:duplicateParentState="true" />
+
+    <Space
+        android:layout_width="wrap_content"
+        android:layout_height="match_parent"
+        android:layout_weight="1"
+        android:elevation="2dp" />
+
+    <Button
+        android:id="@+id/close_window"
+        style="@style/CaptionButtonStyle"
+        android:background="@drawable/close"
+        android:contentDescription="@string/close_button_text"
+        android:duplicateParentState="true" />
+</com.android.wm.shell.windowdecor.WindowDecorLinearLayout>
diff --git a/res/layout/car_bottom_system_bar.xml b/res/layout/car_bottom_system_bar.xml
index 43292a7a..2f8f1c98 100644
--- a/res/layout/car_bottom_system_bar.xml
+++ b/res/layout/car_bottom_system_bar.xml
@@ -24,136 +24,113 @@
     android:gravity="center"
     android:orientation="horizontal">
 
-    <RelativeLayout
+    <LinearLayout
         android:id="@+id/nav_buttons"
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
-        android:layoutDirection="ltr">
+        android:layout_marginHorizontal="@dimen/car_nav_buttons_margin"
+        android:layoutDirection="ltr"
+        android:gravity="center">
+
+        <com.android.systemui.car.systembar.CarSystemBarButton
+            android:id="@+id/home"
+            android:contentDescription="@string/system_bar_home_label"
+            style="@style/SystemBarButton"
+            systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
+            systemui:highlightWhenSelected="true"
+            systemui:icon="@drawable/car_ic_home"
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
+
+        <com.android.systemui.car.systembar.CarSystemBarButton
+            android:id="@+id/passenger_home"
+            android:contentDescription="@string/system_bar_home_label"
+            android:visibility="gone"
+            style="@style/SystemBarButton"
+            systemui:highlightWhenSelected="true"
+            systemui:icon="@drawable/car_ic_home"
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.PassengerHomeButtonController"/>
+
+        <Space
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="1"/>
 
         <com.android.systemui.car.hvac.TemperatureControlView
             android:id="@+id/driver_hvac"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            android:gravity="center_vertical"
+            style="@style/TemperatureControlView"
             systemui:hvacAreaId="49"
             systemui:controller="com.android.systemui.car.hvac.TemperatureControlViewController">
             <include layout="@layout/adjustable_temperature_view"/>
         </com.android.systemui.car.hvac.TemperatureControlView>
 
-        <LinearLayout
+        <Space
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="1"/>
+
+        <com.android.systemui.car.systembar.AppGridButton
+            android:id="@+id/grid_nav"
+            android:contentDescription="@string/system_bar_applications_label"
+            style="@style/SystemBarButton"
+            systemui:componentNames="@string/config_appGridComponentName"
+            systemui:highlightWhenSelected="true"
+            systemui:icon="@drawable/car_ic_apps"
+            systemui:intent="@string/system_bar_app_drawer_intent"
+            systemui:clearBackStack="@bool/config_enableClearBackStack"
+            systemui:systemBarDisableFlags="home"/>
+
+        <com.android.systemui.car.systembar.element.layout.CarSystemBarFrameLayout
             android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginHorizontal="@dimen/dock_container_margin"
+            systemui:controller="com.android.systemui.car.systembar.DockViewControllerWrapper">
+            <com.android.car.docklib.view.DockView
+                android:id="@+id/dock"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content" />
+        </com.android.systemui.car.systembar.element.layout.CarSystemBarFrameLayout>
+
+        <com.android.systemui.car.systembar.CarSystemBarButton
+            android:id="@+id/control_center_nav"
+            android:contentDescription="@string/system_bar_control_center_label"
+            style="@style/SystemBarButton"
+            android:visibility="gone"
+            systemui:highlightWhenSelected="true"
+            systemui:icon="@drawable/car_ic_control_center"
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;package=com.android.car.multidisplay.controlcenter;component=com.android.car.multidisplay.controlcenter/.ControlCenterActivity;B.BOTTOM_BAR_LAUNCH=true;end"
+            systemui:componentNames="com.android.car.multidisplay.controlcenter/.ControlCenterActivity"
+            systemui:controller="com.android.systemui.car.systembar.ControlCenterButtonController"/>
+
+        <Space
+            android:layout_width="0dp"
             android:layout_height="match_parent"
-            android:layout_centerInParent="true"
-            android:layout_weight="1"
-            android:gravity="center"
-            android:layoutDirection="ltr"
-            android:paddingEnd="@dimen/system_bar_button_group_padding"
-            android:paddingStart="@dimen/system_bar_button_group_padding">
-
-            <Space
-                android:layout_width="0dp"
-                android:layout_height="match_parent"
-                android:layout_weight="1"/>
-
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/home"
-                android:contentDescription="@string/system_bar_home_label"
-                style="@style/SystemBarButton"
-                systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
-                systemui:highlightWhenSelected="true"
-                systemui:icon="@drawable/car_ic_home"
-                systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
-                systemui:systemBarDisableFlags="home"
-                systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
-
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/passenger_home"
-                android:contentDescription="@string/system_bar_home_label"
-                android:visibility="gone"
-                style="@style/SystemBarButton"
-                systemui:highlightWhenSelected="true"
-                systemui:icon="@drawable/car_ic_home"
-                systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
-                systemui:systemBarDisableFlags="home"
-                systemui:controller="com.android.systemui.car.systembar.PassengerHomeButtonController"/>
-
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/phone_nav"
-                android:contentDescription="@string/system_bar_phone_label"
-                style="@style/SystemBarButton"
-                systemui:highlightWhenSelected="true"
-                systemui:icon="@drawable/car_ic_phone"
-                systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.LAUNCHER;package=com.android.car.dialer;launchFlags=0x10000000;end"
-                systemui:packages="com.android.car.dialer"
-                systemui:clearBackStack="true"
-                systemui:disableForLockTaskModeLocked="true"/>
-
-            <com.android.systemui.car.systembar.AppGridButton
-                android:id="@+id/grid_nav"
-                android:contentDescription="@string/system_bar_applications_label"
-                style="@style/SystemBarButton"
-                systemui:componentNames="@string/config_appGridComponentName"
-                systemui:highlightWhenSelected="true"
-                systemui:icon="@drawable/car_ic_apps"
-                systemui:intent="@string/system_bar_app_drawer_intent"
-                systemui:clearBackStack="true"
-                systemui:systemBarDisableFlags="home"/>
-
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/hvac"
-                android:contentDescription="@string/system_bar_climate_control_label"
-                style="@style/SystemBarButton"
-                systemui:highlightWhenSelected="true"
-                systemui:icon="@drawable/car_ic_hvac"
-                systemui:broadcast="true"
-                systemui:controller="com.android.systemui.car.hvac.HvacButtonController"/>
-
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/control_center_nav"
-                android:contentDescription="@string/system_bar_control_center_label"
-                style="@style/SystemBarButton"
-                android:visibility="gone"
-                systemui:highlightWhenSelected="true"
-                systemui:icon="@drawable/car_ic_control_center"
-                systemui:intent="intent:#Intent;action=android.intent.action.MAIN;package=com.android.car.multidisplay.controlcenter;component=com.android.car.multidisplay.controlcenter/.ControlCenterActivity;B.BOTTOM_BAR_LAUNCH=true;end"
-                systemui:componentNames="com.android.car.multidisplay.controlcenter/.ControlCenterActivity"
-                systemui:controller="com.android.systemui.car.systembar.ControlCenterButtonController"/>
-
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/notifications"
-                android:contentDescription="@string/system_bar_notifications_label"
-                style="@style/SystemBarButton"
-                systemui:highlightWhenSelected="true"
-                systemui:icon="@drawable/car_ic_notification"
-                systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"
-                systemui:systemBarDisableFlags="notificationIcons"
-                systemui:controller="com.android.systemui.car.notification.NotificationButtonController"/>
-
-            <com.android.systemui.car.systembar.AssistantButton
-                android:id="@+id/assistant"
-                android:contentDescription="@string/system_bar_assistant_label"
-                style="@style/SystemBarButton"
-                systemui:highlightWhenSelected="true"
-                systemui:icon="@drawable/ic_mic_light"/>
-
-            <Space
-                android:layout_width="0dp"
-                android:layout_height="match_parent"
-                android:layout_weight="1"/>
-        </LinearLayout>
+            android:layout_weight="1"/>
 
         <com.android.systemui.car.hvac.TemperatureControlView
             android:id="@+id/passenger_hvac"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            android:layout_alignParentEnd="true"
-            android:gravity="center_vertical"
+            style="@style/TemperatureControlView"
             systemui:hvacAreaId="68"
             systemui:controller="com.android.systemui.car.hvac.TemperatureControlViewController">
             <include layout="@layout/adjustable_temperature_view"/>
         </com.android.systemui.car.hvac.TemperatureControlView>
 
-    </RelativeLayout>
+        <Space
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="1"/>
+
+        <com.android.systemui.car.systembar.AssistantButton
+            android:id="@+id/assistant"
+            android:contentDescription="@string/system_bar_assistant_label"
+            style="@style/SystemBarButton"
+            systemui:highlightWhenSelected="true"
+            systemui:icon="@drawable/ic_mic_light"/>
+
+    </LinearLayout>
 
     <LinearLayout
         android:id="@+id/lock_screen_nav_buttons"
diff --git a/res/layout/car_bottom_system_bar_dock.xml b/res/layout/car_bottom_system_bar_dock.xml
deleted file mode 100644
index df556e82..00000000
--- a/res/layout/car_bottom_system_bar_dock.xml
+++ /dev/null
@@ -1,167 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-  ~ Copyright (C) 2023 The Android Open Source Project.
-  ~
-  ~ Licensed under the Apache License, Version 2.0 (the "License");
-  ~ you may not use this file except in compliance with the License.
-  ~ You may obtain a copy of the License at
-  ~
-  ~      http://www.apache.org/licenses/LICENSE-2.0
-  ~
-  ~ Unless required by applicable law or agreed to in writing, software
-  ~ distributed under the License is distributed on an "AS IS" BASIS,
-  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  ~ See the License for the specific language governing permissions and
-  ~ limitations under the License.
-  -->
-
-<com.android.systemui.car.systembar.CarSystemBarView
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:systemui="http://schemas.android.com/apk/res-auto"
-    android:layout_width="match_parent"
-    android:layout_height="match_parent"
-    android:background="@drawable/nav_bar_background"
-    android:gravity="center"
-    android:orientation="horizontal">
-
-    <LinearLayout
-        android:id="@+id/nav_buttons"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:layout_marginHorizontal="@dimen/car_nav_buttons_margin"
-        android:layoutDirection="ltr"
-        android:gravity="center">
-
-        <com.android.systemui.car.systembar.CarSystemBarButton
-            android:id="@+id/home"
-            android:contentDescription="@string/system_bar_home_label"
-            style="@style/SystemBarButtonWithDock"
-            systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
-            systemui:highlightWhenSelected="true"
-            systemui:icon="@drawable/car_ic_home"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
-            systemui:systemBarDisableFlags="home"
-            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
-
-        <com.android.systemui.car.systembar.CarSystemBarButton
-            android:id="@+id/passenger_home"
-            android:contentDescription="@string/system_bar_home_label"
-            android:visibility="gone"
-            style="@style/SystemBarButtonWithDock"
-            systemui:highlightWhenSelected="true"
-            systemui:icon="@drawable/car_ic_home"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
-            systemui:systemBarDisableFlags="home"
-            systemui:controller="com.android.systemui.car.systembar.PassengerHomeButtonController"/>
-
-        <Space
-            android:layout_width="0dp"
-            android:layout_height="match_parent"
-            android:layout_weight="1"/>
-
-        <com.android.systemui.car.hvac.TemperatureControlView
-            android:id="@+id/driver_hvac"
-            style="@style/TemperatureControlView"
-            systemui:hvacAreaId="49"
-            systemui:controller="com.android.systemui.car.hvac.TemperatureControlViewController">
-            <include layout="@layout/adjustable_temperature_view"/>
-        </com.android.systemui.car.hvac.TemperatureControlView>
-
-        <Space
-            android:layout_width="0dp"
-            android:layout_height="match_parent"
-            android:layout_weight="1"/>
-
-        <com.android.systemui.car.systembar.AppGridButton
-            android:id="@+id/grid_nav"
-            android:contentDescription="@string/system_bar_applications_label"
-            style="@style/SystemBarButtonWithDock"
-            systemui:componentNames="@string/config_appGridComponentName"
-            systemui:highlightWhenSelected="true"
-            systemui:icon="@drawable/car_ic_apps"
-            systemui:intent="@string/system_bar_app_drawer_intent"
-            systemui:clearBackStack="true"
-            systemui:systemBarDisableFlags="home"/>
-
-        <com.android.systemui.car.systembar.element.layout.CarSystemBarFrameLayout
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:layout_marginHorizontal="@dimen/dock_container_margin"
-            systemui:controller="com.android.systemui.car.systembar.DockViewControllerWrapper">
-            <com.android.car.docklib.view.DockView
-                android:id="@+id/dock"
-                android:layout_width="wrap_content"
-                android:layout_height="wrap_content" />
-        </com.android.systemui.car.systembar.element.layout.CarSystemBarFrameLayout>
-
-        <com.android.systemui.car.systembar.CarSystemBarButton
-            android:id="@+id/control_center_nav"
-            android:contentDescription="@string/system_bar_control_center_label"
-            style="@style/SystemBarButton"
-            android:visibility="gone"
-            systemui:highlightWhenSelected="true"
-            systemui:icon="@drawable/car_ic_control_center"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;package=com.android.car.multidisplay.controlcenter;component=com.android.car.multidisplay.controlcenter/.ControlCenterActivity;B.BOTTOM_BAR_LAUNCH=true;end"
-            systemui:componentNames="com.android.car.multidisplay.controlcenter/.ControlCenterActivity"
-            systemui:controller="com.android.systemui.car.systembar.ControlCenterButtonController"/>
-
-        <Space
-            android:layout_width="0dp"
-            android:layout_height="match_parent"
-            android:layout_weight="1"/>
-
-        <com.android.systemui.car.hvac.TemperatureControlView
-            android:id="@+id/passenger_hvac"
-            style="@style/TemperatureControlView"
-            systemui:hvacAreaId="68"
-            systemui:controller="com.android.systemui.car.hvac.TemperatureControlViewController">
-            <include layout="@layout/adjustable_temperature_view"/>
-        </com.android.systemui.car.hvac.TemperatureControlView>
-
-        <Space
-            android:layout_width="0dp"
-            android:layout_height="match_parent"
-            android:layout_weight="1"/>
-
-        <com.android.systemui.car.systembar.AssistantButton
-            android:id="@+id/assistant"
-            android:contentDescription="@string/system_bar_assistant_label"
-            style="@style/SystemBarButtonWithDock"
-            systemui:highlightWhenSelected="true"
-            systemui:icon="@drawable/ic_mic_light"/>
-
-    </LinearLayout>
-
-    <LinearLayout
-        android:id="@+id/lock_screen_nav_buttons"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:layout_weight="1"
-        android:gravity="center"
-        android:layoutDirection="ltr"
-        android:paddingEnd="@dimen/car_keyline_1"
-        android:paddingStart="@dimen/car_keyline_1"
-        android:visibility="gone"/>
-
-    <LinearLayout
-        android:id="@+id/occlusion_buttons"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:layout_weight="1"
-        android:gravity="center"
-        android:layoutDirection="ltr"
-        android:paddingEnd="@dimen/car_keyline_1"
-        android:paddingStart="@dimen/car_keyline_1"
-        android:visibility="gone">
-        <com.android.systemui.car.systembar.CarSystemBarButton
-            android:id="@+id/home"
-            android:contentDescription="@string/system_bar_home_label"
-            style="@style/SystemBarButtonWithDock"
-            systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
-            systemui:highlightWhenSelected="true"
-            systemui:icon="@drawable/car_ic_home"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
-            systemui:systemBarDisableFlags="home"
-            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
-    </LinearLayout>
-</com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_top_system_bar.xml b/res/layout/car_top_system_bar.xml
index 86287d3f..0832926a 100644
--- a/res/layout/car_top_system_bar.xml
+++ b/res/layout/car_top_system_bar.xml
@@ -40,8 +40,8 @@
             android:id="@+id/clock_container"
             android:layout_width="wrap_content"
             android:layout_height="match_parent"
-            android:paddingStart="@dimen/car_padding_4"
-            android:paddingEnd="@dimen/car_padding_4"
+            android:paddingStart="@dimen/car_padding_2"
+            android:paddingEnd="@dimen/car_padding_2"
             android:layout_centerInParent="true">
             <com.android.systemui.statusbar.policy.Clock
                 android:id="@+id/clock"
@@ -50,9 +50,9 @@
                 android:layout_gravity="center"
                 android:elevation="5dp"
                 android:singleLine="true"
-                android:textAppearance="@style/TextAppearance.SystemBar.Clock"
+                style="@style/SystemBarClockText"
                 systemui:amPmStyle="gone"
-            />
+                />
         </FrameLayout>
 
         <include layout="@layout/read_only_status_icons"
@@ -61,6 +61,19 @@
             android:layout_centerVertical="true"
             android:layout_toRightOf="@id/clock_container"/>
 
+        <com.android.systemui.car.systembar.CarSystemBarButton
+            android:id="@+id/notifications"
+            android:contentDescription="@string/system_bar_notifications_label"
+            android:layout_width="wrap_content"
+            android:layout_height="match_parent"
+            style="@style/TopBarButton"
+            android:layout_toLeftOf="@id/camera_privacy_chip"
+            systemui:highlightWhenSelected="true"
+            systemui:icon="@drawable/car_ic_notification_dock"
+            systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"
+            systemui:systemBarDisableFlags="notificationIcons"
+            systemui:controller="com.android.systemui.car.notification.NotificationButtonController"/>
+
         <include layout="@layout/camera_privacy_chip"
             android:layout_width="wrap_content"
             android:layout_height="match_parent"
@@ -72,13 +85,11 @@
             android:layout_height="match_parent"
             android:layout_centerVertical="true"
             android:layout_toLeftOf="@id/user_name_container"
-            android:contentDescription="@string/system_bar_mic_privacy_chip"
-        />
+            android:contentDescription="@string/system_bar_mic_privacy_chip" />
 
         <include layout="@layout/user_name_container"
             android:layout_width="wrap_content"
             android:layout_height="match_parent"
             android:layout_alignParentEnd="true" />
     </RelativeLayout>
-
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_top_system_bar_dock.xml b/res/layout/car_top_system_bar_dock.xml
deleted file mode 100644
index 8b05b13c..00000000
--- a/res/layout/car_top_system_bar_dock.xml
+++ /dev/null
@@ -1,96 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-  ~ Copyright (C) 2023 The Android Open Source Project
-  ~
-  ~ Licensed under the Apache License, Version 2.0 (the "License");
-  ~ you may not use this file except in compliance with the License.
-  ~ You may obtain a copy of the License at
-  ~
-  ~      http://www.apache.org/licenses/LICENSE-2.0
-  ~
-  ~ Unless required by applicable law or agreed to in writing, software
-  ~ distributed under the License is distributed on an "AS IS" BASIS,
-  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  ~ See the License for the specific language governing permissions and
-  ~ limitations under the License
-  -->
-
-<!-- todo(b/304320644): update layout/car_top_system_bar -->
-<com.android.systemui.car.systembar.CarSystemBarView
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:systemui="http://schemas.android.com/apk/res-auto"
-    android:id="@+id/car_top_bar"
-    android:layout_width="match_parent"
-    android:layout_height="match_parent"
-    android:background="@drawable/status_bar_background"
-    android:orientation="vertical">
-
-    <RelativeLayout
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:layout_weight="1"
-        android:layoutDirection="ltr">
-
-        <include layout="@layout/qc_status_icons_horizontal"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            android:layout_centerVertical="true"
-            android:layout_alignParentStart="true" />
-
-        <FrameLayout
-            android:id="@+id/clock_container"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            android:paddingStart="@dimen/car_padding_2"
-            android:paddingEnd="@dimen/car_padding_2"
-            android:layout_centerInParent="true">
-            <com.android.systemui.statusbar.policy.Clock
-                android:id="@+id/clock"
-                android:layout_width="wrap_content"
-                android:layout_height="wrap_content"
-                android:layout_gravity="center"
-                android:elevation="5dp"
-                android:singleLine="true"
-                android:textAppearance="@style/TextAppearance.SystemBar.Clock"
-                systemui:amPmStyle="gone"
-                />
-        </FrameLayout>
-
-        <include layout="@layout/read_only_status_icons"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            android:layout_centerVertical="true"
-            android:layout_toRightOf="@id/clock_container"/>
-
-        <com.android.systemui.car.systembar.CarSystemBarButton
-            android:id="@+id/notifications"
-            android:contentDescription="@string/system_bar_notifications_label"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            style="@style/TopBarButton"
-            android:layout_toLeftOf="@id/camera_privacy_chip"
-            systemui:highlightWhenSelected="true"
-            systemui:icon="@drawable/car_ic_notification_dock"
-            systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"
-            systemui:systemBarDisableFlags="notificationIcons"
-            systemui:controller="com.android.systemui.car.notification.NotificationButtonController"/>
-
-        <include layout="@layout/camera_privacy_chip"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            android:layout_centerVertical="true"
-            android:layout_toLeftOf="@id/mic_privacy_chip" />
-
-        <include layout="@layout/mic_privacy_chip"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            android:layout_centerVertical="true"
-            android:layout_toLeftOf="@id/user_name_container"
-            android:contentDescription="@string/system_bar_mic_privacy_chip" />
-
-        <include layout="@layout/user_name_container"
-            android:layout_width="wrap_content"
-            android:layout_height="match_parent"
-            android:layout_alignParentEnd="true" />
-    </RelativeLayout>
-</com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_top_system_bar_unprovisioned.xml b/res/layout/car_top_system_bar_unprovisioned.xml
index 728ca151..1618fe36 100644
--- a/res/layout/car_top_system_bar_unprovisioned.xml
+++ b/res/layout/car_top_system_bar_unprovisioned.xml
@@ -48,7 +48,7 @@
                 android:layout_gravity="center"
                 android:elevation="5dp"
                 android:singleLine="true"
-                android:textAppearance="@style/TextAppearance.SystemBar.Clock"
+                style="@style/SystemBarClockText"
                 systemui:amPmStyle="gone"/>
         </com.android.systemui.car.systembar.CarSystemBarButton>
 
diff --git a/res/layout/data_subscription_popup_window.xml b/res/layout/data_subscription_popup_window.xml
index 7915d780..532f824c 100644
--- a/res/layout/data_subscription_popup_window.xml
+++ b/res/layout/data_subscription_popup_window.xml
@@ -24,7 +24,7 @@
     android:clickable="true"
     android:focusable="true"
     app:carUiArrowHeight="@dimen/data_subscription_pop_up_arrow_height"
-    app:carUiArrowRadius="@dimen/data_subscription_pop_up_arrow_radius"
+    app:carUiArrowRadius="?dataSubscriptionPopUpArrowRadius"
     app:carUiArrowWidth="@dimen/data_subscription_pop_up_arrow_width"
     app:carUiContentView="@id/pop_up_view"
     app:carUiContentViewDrawable="@drawable/bg_arrow_container_default"
diff --git a/res/layout/user_name_container.xml b/res/layout/user_name_container.xml
index 4a8d4d82..f1552906 100644
--- a/res/layout/user_name_container.xml
+++ b/res/layout/user_name_container.xml
@@ -56,7 +56,7 @@
                 android:layout_width="wrap_content"
                 android:layout_height="match_parent"
                 android:gravity="center_vertical"
-                android:textAppearance="@style/TextAppearance.SystemBar.Username"
+                style="@style/SystemBarUsernameText"
                 android:singleLine="true"
                 android:maxWidth="@dimen/car_system_bar_user_name_max_width"
                 android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
diff --git a/res/layout/user_picker.xml b/res/layout/user_picker.xml
index 73fbf0a6..92101788 100644
--- a/res/layout/user_picker.xml
+++ b/res/layout/user_picker.xml
@@ -46,8 +46,7 @@
             android:id="@+id/message"
             android:layout_width="wrap_content"
             android:layout_height="@dimen/user_picker_button_size"
-            android:textAppearance="?android:attr/textAppearanceLarge"
-            android:textColor="@android:color/white"
+            android:textAppearance="?oemTextAppearanceTitleLarge"
             android:gravity="center"
             android:visibility="gone"
             android:text="@string/header_bar_text_in_logged_out_state"
@@ -132,7 +131,7 @@
                 android:layout_gravity="center"
                 android:elevation="5dp"
                 android:singleLine="true"
-                android:textAppearance="@style/TextAppearance.SystemBar.Clock"
+                style="@style/SystemBarClockText"
                 app:layout_constraintRight_toRightOf="parent"
                 app:layout_constraintTop_toTopOf="parent"
                 app:layout_constraintBottom_toBottomOf="parent"
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index ea905b17..30efd900 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -81,7 +81,7 @@
     <string name="status_icon_sound_status" msgid="4923149230650995670">"Klankinstellings"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Rymodus"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Jy kan nie hierdie kenmerk gebruik terwyl jy bestuur nie"</string>
-    <string name="exit_button_close_application" msgid="112227710467017144">"Maak program toe"</string>
+    <string name="exit_button_close_application" msgid="112227710467017144">"Maak app toe"</string>
     <string name="exit_button_go_back" msgid="7988866855775300902">"Terug"</string>
     <string name="drive_mode_modes_comfort" msgid="628724737960743004">"Gemak"</string>
     <string name="drive_mode_modes_eco" msgid="7694931508925737653">"Eko"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 68feb13c..1650f319 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -120,7 +120,7 @@
     <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Forkert mønster"</string>
     <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Forkert pinkode"</string>
     <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Forkert adgangskode"</string>
-    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{For mange forkerte forsøg. Prøv igen om # sekund.}one{For mange forkerte forsøg. Prøv igen om # sekund.}other{For mange forkerte forsøg. Prøv igen om # sekunder.}}"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{For mange mislykkede forsøg. Prøv igen om # sekund.}one{For mange mislykkede forsøg. Prøv igen om # sekund.}other{For mange mislykkede forsøg. Prøv igen om # sekunder.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"chauffør"</string>
     <string name="seat_front" msgid="836133281052793377">"forside"</string>
     <string name="seat_rear" msgid="403133444964528577">"bagside"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 555a249a..ce37b35e 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -93,7 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Ցուցադրել կարգավորումները"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ձայնի կարգավորումներ"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Պրոֆիլների և հաշիվների կարգավորումներ"</string>
-    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Մշակողի ընտրանքներ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Ծրագրավորողի ընտրանքներ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Նախշը չի աջակցում պտտաշարժում. օգտագործեք հպում"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ձեր էկրանը կողպված է"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Ձեր էկրանը կողպվել է"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index ce6dbeb2..10a0d094 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -66,7 +66,7 @@
     <string name="system_bar_control_center_label" msgid="5269256399167811590">"Vadības centrs"</string>
     <string name="system_bar_assistant_label" msgid="7312821609046711200">"Asistents"</string>
     <string name="system_bar_mic_privacy_chip" msgid="2494035034004728597">"Mikrofona konfidencialitātes žetons"</string>
-    <string name="system_bar_user_avatar" msgid="4122817348016746322">"Lietotāja iemiesojums"</string>
+    <string name="system_bar_user_avatar" msgid="4122817348016746322">"Lietotāja avatārs"</string>
     <string name="system_bar_user_name_text" msgid="5859605302481171746">"Lietotājvārda teksts"</string>
     <string name="hvac_decrease_button_label" msgid="5628481079099995286">"Pazemināt temperatūru"</string>
     <string name="hvac_increase_button_label" msgid="2855688290787396792">"Paaugstināt temperatūru"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index e222e0c9..cf94c8b2 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -60,7 +60,7 @@
     <string name="system_bar_phone_label" msgid="5664288201806823777">"फोन"</string>
     <string name="system_bar_applications_label" msgid="7081862804211786227">"एपहरू"</string>
     <string name="system_bar_climate_control_label" msgid="4091187805919276017">"मौसमसम्बन्धी सेटिङ"</string>
-    <string name="system_bar_notifications_label" msgid="6039158514903928210">"सूचनाहरू"</string>
+    <string name="system_bar_notifications_label" msgid="6039158514903928210">"नोटिफिकेसनहरू"</string>
     <string name="system_bar_maps_label" msgid="7883864993280235380">"नक्सा"</string>
     <string name="system_bar_media_label" msgid="6156112139796274847">"मिडिया"</string>
     <string name="system_bar_control_center_label" msgid="5269256399167811590">"कन्ट्रोल सेन्टर"</string>
diff --git a/res/values/arrays.xml b/res/values/arrays.xml
index dac6c34f..32ab15ab 100644
--- a/res/values/arrays.xml
+++ b/res/values/arrays.xml
@@ -26,6 +26,6 @@
     <!-- Different colors to indicate different temperature levels. The upper bound for each color
     is defined in integers.xml (see hvac_temperature_control_levels). -->
     <array name="hvac_temperature_level_backgrounds">
-        <item>@color/car_primary</item>
+        <item>@color/hvac_temperature_level_1</item>
     </array>
 </resources>
diff --git a/res/values/attrs.xml b/res/values/attrs.xml
index 9894f054..3058a4fc 100644
--- a/res/values/attrs.xml
+++ b/res/values/attrs.xml
@@ -53,10 +53,24 @@
 
     <!-- Allow for custom attribs to be added to a nav button -->
     <declare-styleable name="CarSystemBarButton">
-        <!-- intent to start when button is click -->
+        <!-- Intent to start when button is clicked -->
         <attr name="intent" />
+        <!-- Intent to start when button is clicked in the selected state.
+             If not specified the "intent" attribute will be used. -->
+        <attr name="selectedIntent" format="string"/>
+        <!-- Intent to start when button is clicked in the unselected state.
+             If not specified the "intent" attribute will be used. -->
+        <attr name="unselectedIntent" format="string"/>
         <!-- intent to start when a long press has happened -->
         <attr name="longIntent" />
+        <!-- Event to fire when button is clicked -->
+        <attr name="event" format="string" />
+        <!-- Event to fire when button is clicked in the selected state.
+             If not specified the "event" attribute will be used. -->
+        <attr name="selectedEvent" format="string"/>
+        <!-- Event to fire when button is clicked in the unselected state.
+             If not specified the "event" attribute will be used. -->
+        <attr name="unselectedEvent" format="string"/>
         <!-- start the intent as a broad cast instead of an activity if true-->
         <attr name="broadcast" format="boolean"/>
         <!-- Alpha value to used when in selected state.  Defaults 1f  -->
@@ -73,6 +87,8 @@
         <attr name="packages" format="string" />
         <!-- componentName names that will be used for detecting selected state -->
         <attr name="componentNames" format="string" />
+        <!-- Panel names that will be used for detecting selected state -->
+        <attr name="panelNames" format="string" />
         <!-- whether to highlight the button when selected. Defaults false -->
         <attr name="showMoreWhenSelected" format="boolean" />
         <!-- whether to highlight the button when selected. Defaults false -->
@@ -251,4 +267,24 @@
         <attr name="launchTaskDisplayAreaFeatureId" format="integer" />
         <attr name="cornerRadius" format="integer" />
     </declare-styleable>
+
+    <attr name="carControlHighlight" format="color|reference"/>
+    <attr name="systemBarPillRadius" format="dimension"/>
+    <attr name="systemBarPillSelectedRadius" format="dimension"/>
+    <attr name="hvacPanelBackgroundRadius" format="dimension"/>
+    <attr name="carVolumeItemCornerRadius" format="dimension"/>
+    <attr name="notificationShadeHandleBarRadius" format="dimension"/>
+    <attr name="notificationShadowRadius" format="dimension"/>
+    <attr name="carStatusIconPanelBorderRadius" format="dimension"/>
+    <attr name="carNavBarButtonSelectedCornerRadius" format="dimension"/>
+    <attr name="hvacPanelHandleBarRadius" format="dimension"/>
+    <attr name="temperatureBarBgRadius" format="dimension"/>
+    <attr name="hvacPanelButtonRadius" format="dimension"/>
+    <attr name="hvacFanSpeedBarCornerRadius" format="dimension"/>
+    <attr name="activityBlockingActionButtonCornerRadius" format="dimension"/>
+    <attr name="displayInputLockBackgroundRadius" format="dimension"/>
+    <attr name="userPickerPillRadius" format="dimension"/>
+    <attr name="pinPadKeyRadius" format="dimension"/>
+    <attr name="dataSubscriptionPopUpRadius" format="dimension"/>
+    <attr name="dataSubscriptionPopUpArrowRadius" format="dimension"/>
 </resources>
diff --git a/res/values/colors.xml b/res/values/colors.xml
index e2d91a04..07374421 100644
--- a/res/values/colors.xml
+++ b/res/values/colors.xml
@@ -15,41 +15,7 @@
   ~ limitations under the License
   -->
 <resources xmlns:android="http://schemas.android.com/apk/res/android">
-    <!-- colors for user switcher -->
-    <color name="car_user_switcher_background_color">@color/car_background</color>
-    <color name="car_user_switcher_name_text_color">@color/car_on_surface</color>
-    <color name="car_user_switcher_add_user_background_color">@color/car_surface_variant</color>
-    <color name="car_user_switcher_add_user_add_sign_color">@color/car_on_surface_variant</color>
-    <color name="car_managed_device_icon_color">@color/car_on_background</color>
-    <!-- colors for volume dialog tint -->
-    <color name="car_volume_dialog_tint">@color/car_on_surface</color>
-
-    <color name="docked_divider_background">@color/car_on_background</color>
-    <color name="system_bar_background_opaque">@color/car_background</color>
-
-    <!-- colors for status bar -->
-    <color name="system_bar_background_pill_color">@color/car_surface_3</color>
-    <color name="privacy_chip_indicator_color">@color/car_green_tint</color>
-    <color name="privacy_chip_dark_icon_color">@color/car_surface</color>
     <color name="privacy_chip_light_icon_color">@color/car_nav_icon_fill_color_selected</color>
-    <color name="privacy_chip_indicator_outside_stroke_color">@android:color/black</color>
-    <color name="system_bar_icon_color">@android:color/white</color>
-    <color name="system_bar_icon_selected_color">@color/car_on_primary</color>
-    <color name="system_bar_text_color">@color/car_on_background</color>
-    <color name="system_bar_text_selected_color">@color/car_on_primary</color>
-    <drawable name="nav_bar_background">@android:color/black</drawable>
-    <drawable name="status_bar_background">@android:color/black</drawable>
-
-    <!-- colors for nav bar -->
-    <color name="car_nav_icon_fill_color">@color/car_on_surface</color>
-    <color name="car_nav_icon_background_color">@color/car_surface</color>
-    <color name="car_nav_icon_background_color_selected">@color/car_primary</color>
-
-    <!-- colors for quick controls entry points icon   -->
-    <color name="car_quick_controls_icon_drawable_color">@color/car_on_surface</color>
-
-    <!-- The background color of the notification shade -->
-    <color name="notification_shade_background_color">#D6000000</color>
 
     <!-- The background color of the car volume dialog -->
     <color name="car_volume_dialog_background_color">@color/system_bar_background_opaque</color>
@@ -57,95 +23,11 @@
     <!-- The color of the dividing line between grouped notifications. -->
     <color name="notification_divider_color">@*android:color/notification_action_list</color>
 
-    <!-- The color for the unseen indicator. -->
-    <color name="car_nav_unseen_indicator_color">@color/car_icon_indicator_color</color>
-
     <!-- The color of the ripples on the untinted notifications -->
     <color name="notification_ripple_untinted_color">@color/car_control_highlight</color>
 
-    <!-- The color of the notification handle bar -->
-    <color name="notification_handle_bar_color">@color/car_surface_variant</color>
-
-    <color name="keyguard_keypad_image_color">@android:color/white</color>
-
-    <color name="list_divider_color">@color/car_outline</color>
-    <color name="car_volume_item_divider_color">@color/car_outline</color>
-    <color name="car_volume_item_background_color">@color/car_surface</color>
-
-    <color name="car_user_switching_dialog_background_color">@color/car_surface</color>
-    <color name="car_user_switching_dialog_loading_text_color">@color/car_on_surface</color>
-
-    <!-- colors for the HVAC application. -->
-
-    <color name="hvac_panel_handle_bar_color">@color/car_surface_variant</color>
-
-    <color name="hvac_module_background_color">@color/car_secondary_container</color>
-
-    <color name="hvac_icon_color">@color/car_on_secondary_container</color>
-    <color name="hvac_master_switch_color">@color/hvac_icon_color</color>
-    <color name="hvac_icon_off_foreground_color">@color/car_on_secondary_container</color>
-    <color name="hvac_icon_on_foreground_color">@color/car_on_primary</color>
-    <color name="hvac_icon_on_background_color">@color/car_primary</color>
-    <color name="hvac_background_color">@color/car_background</color>
-    <color name="hvac_temperature_default_bg_color">@color/car_error</color>
-    <color name="hvac_temperature_off_text_bg_color">@color/car_primary</color>
-    <color name="hvac_fanspeed_bg_color">@color/car_surface</color>
-    <color name="hvac_fanspeed_segment_color">@color/car_primary</color>
-    <color name="hvac_seat_heat_level_drawable_off_fill_color">@color/car_surface_2</color>
-    <color name="hvac_seat_heat_level_drawable_on_fill_color">@color/car_primary</color>
-    <color name="hvac_temperature_control_icon_fill_color">@color/car_on_primary</color>
-    <color name="hvac_fanspeed_off_active_bg">@color/car_primary</color>
-    <color name="hvac_fanspeed_off_active_text_color">@color/car_on_primary</color> <!-- TODO: CHANGE -->
-    <color name="hvac_fanspeed_off_inactive_text_color">@color/car_secondary</color> <!-- TODO: CHANGE -->
-
-    <!-- Semi-transparent background color of blocking activity. -->
-    <color name="activity_blocking_activity_background">#c7000000</color>
-    <color name="activity_blocking_action_button_background_color">
-        @*android:color/car_grey_868
-    </color>
-
-    <!-- Color of text in blocking activity. -->
-    <color name="blocking_text">@android:color/white</color>
-    <color name="ic_ux_restricted_color">@android:color/white</color>
-
-    <!-- Color for status icon panel background. -->
-    <color name="status_icon_panel_bg_color">@color/car_background</color>
-
-    <!-- Color for highlighting the status icon button that is currently selected. -->
-    <color name="status_icon_selected_button_color">@color/car_primary</color>
-    <!-- Color for status icon that is currently highlighted. -->
-    <color name="status_icon_highlighted_color">@color/car_on_primary</color>
-    <!-- Color for status icon that is not highlighted. -->
-    <color name="status_icon_not_highlighted_color">@color/car_on_surface</color>
-
-    <!-- Color for clock text -->
-    <color name="system_bar_clock_text_color">@color/car_on_surface</color>
-
-    <!-- Colors for display input lock icon and text -->
-    <color name="display_input_lock_icon_color">@android:color/white</color>
-    <color name="display_input_lock_background_color">@*android:color/car_grey_868</color>
-
-    <!-- Color for user picker -->
-    <color name="user_picker_bottom_bar_color">@android:color/black</color>
-    <color name="user_picker_snack_bar_transparent_color">@android:color/white</color>
-    <color name="user_picker_snack_bar_background_color">@color/car_surface_3</color>
-    <color name="user_picker_user_name_color">@color/car_on_background</color>
-    <color name="user_picker_current_login_state_color">@color/car_primary</color>
-    <color name="user_picker_other_login_state_color">@color/car_on_background</color>
-    <color name="user_picker_background_pill_color">@color/car_surface_3</color>
     <drawable name="user_picker_splash_icon">@android:color/transparent</drawable>
 
-    <!-- Color for button background in the quick controls panel. -->
-    <color name="car_quick_controls_pill_button_background_color">@color/car_surface_5</color>
-
     <!-- Color for PIN Pad icon.-->
     <color name="pin_pad_icon_color">@color/car_ui_text_color_primary</color>
-
-    <!-- Color for unseen icon.-->
-    <color name="car_qc_unseen_indicator_color">@color/car_yellow_color</color>
-
-    <!-- Color for data subscription popup.-->
-    <color name="qc_pop_up_color">@color/car_surface_2</color>
-    <color name="qc_pop_up_text_color">@color/car_on_surface</color>
-
 </resources>
diff --git a/res/values/config.xml b/res/values/config.xml
index 624fac0a..d31fddfc 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -276,4 +276,37 @@
     -->
     <string-array name="config_debug_support_devices_exclude_car">
     </string-array>
+
+    <!--
+        Enable the clear back stack feature on the CarSystemBarButtons.  This feature should be
+        disabled when scalableUi feature is enabled.
+    -->
+    <bool name="config_enableClearBackStack">true</bool>
+
+    <!-- Enable the scalableUI feature. -->
+    <bool name="config_enableScalableUI">false</bool>
+
+    <!-- The entry point for panel definition of scalableUI feature.  -->
+    <array name="window_states">
+    </array>
+
+    <!--
+        List of activity names that should not be considered trimmable by the system.
+        Used when scalableUi feature is enabled.
+    -->
+    <string-array name="config_untrimmable_activities" translatable="false">
+    </string-array>
+
+    <!--
+        Specifies the default activities associated with different panel IDs.
+
+        This string array defines the default activity to launch for panels. Each item in the array
+        represents a mapping between a panel ID and its corresponding activity.
+        The format of each item is: "panel_id;activity_component_name".
+        - `panel_id`:  The ID of the panel (e.g., "app_grid_panel", "map_panel").
+        - `activity_component_name`: The fully qualified component name of the activity to launch
+           for that panel.
+    -->
+    <string-array name="config_default_activities" translatable="false">
+    </string-array>
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 368ecd8f..e4544432 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -65,10 +65,6 @@
     <dimen name="system_bar_button_margin">32dp</dimen>
     <!-- Padding between the system bar button and the icon within it -->
     <dimen name="system_bar_button_padding">16dp</dimen>
-    <!-- Radius for system bar pill buttons -->
-    <dimen name="system_bar_pill_radius">100dp</dimen>
-    <!-- Radius for system bar pill buttons when selected -->
-    <dimen name="system_bar_pill_selected_radius">16dp</dimen>
 
     <!-- The amount by which to scale up the status bar icons. -->
     <item name="status_bar_icon_scale_factor" format="float" type="dimen">1.75</item>
@@ -76,7 +72,6 @@
     <dimen name="car_primary_icon_size">@*android:dimen/car_primary_icon_size</dimen>
 
     <dimen name="hvac_container_padding">16dp</dimen>
-    <dimen name="hvac_panel_background_radius">48dp</dimen>
     <dimen name="hvac_temperature_bar_margin">32dp</dimen>
     <dimen name="hvac_temperature_text_size">44sp</dimen>
     <dimen name="hvac_temperature_text_padding">10dp</dimen>
@@ -145,13 +140,11 @@
     <dimen name="car_volume_item_divider_height">60dp</dimen>
     <dimen name="car_volume_item_divider_width">1dp</dimen>
     <dimen name="car_volume_item_divider_margin_end">@*android:dimen/car_padding_4</dimen>
-    <dimen name="car_volume_item_corner_radius">@*android:dimen/car_radius_3</dimen>
 
     <!-- Car notification shade-->
     <dimen name="notification_shade_handle_bar_frame_padding">10dp</dimen>
     <dimen name="notification_shade_handle_bar_width">64dp</dimen>
     <dimen name="notification_shade_handle_bar_height">10dp</dimen>
-    <dimen name="notification_shade_handle_bar_radius">20dp</dimen>
     <dimen name="notification_shade_list_padding_bottom">0dp</dimen>
 
     <!-- The alpha for the scrim behind the notification shade. This value is 1 so that the
@@ -199,9 +192,6 @@
     <!-- The bottom padding of the panel that holds the list of notifications. -->
     <dimen name="notification_panel_padding_bottom">@dimen/notification_divider_height</dimen>
 
-    <!-- The corner radius of the shadow behind the notification. -->
-    <dimen name="notification_shadow_radius">16dp</dimen>
-
     <!-- The amount of space below the notification list. This value is 0 so the list scrolls
          all the way to the bottom. -->
     <dimen name="notification_panel_margin_bottom">0dp</dimen>
@@ -286,7 +276,6 @@
     <dimen name="car_read_only_status_icon_height">24dp</dimen>
 
     <dimen name="car_status_icon_panel_default_width">800dp</dimen>
-    <dimen name="car_status_icon_panel_border_radius">32dp</dimen>
     <dimen name="car_status_icon_panel_padding_top">22dp</dimen>
     <dimen name="car_status_icon_panel_padding_bottom">32dp</dimen>
     <dimen name="car_status_icon_panel_margin_top">0dp</dimen>
@@ -299,8 +288,6 @@
     <dimen name="car_quick_controls_footer_button_horizontal_margin">33dp</dimen>
     <dimen name="car_quick_controls_footer_button_min_height">88dp</dimen>
 
-    <dimen name="car_nav_bar_button_selected_corner_radius">24dp</dimen>
-
     <!-- dimensions for HVAC   -->
 
     <dimen name="hvac_panel_full_expanded_height">500dp</dimen>
@@ -310,7 +297,6 @@
     <dimen name="hvac_panel_handle_bar_frame_padding">10dp</dimen>
     <dimen name="hvac_panel_handle_bar_width">64dp</dimen>
     <dimen name="hvac_panel_handle_bar_height">10dp</dimen>
-    <dimen name="hvac_panel_handle_bar_radius">20dp</dimen>
     <dimen name="hvac_panel_button_dimen">96dp</dimen>
 
     <dimen name="temperature_side_margin">32dp</dimen>
@@ -330,7 +316,6 @@
     <dimen name="temperature_bar_icon_margin">20dp</dimen>
     <dimen name="temperature_bar_close_icon_dimen">96dp</dimen>
 
-    <dimen name="temperature_bar_bg_radius">54dp</dimen>
     <dimen name="temperature_bar_floating_text_bottom_margin">50dp</dimen>
     <dimen name="temperature_bar_off_text_bottom_margin">56dp</dimen>
 
@@ -346,7 +331,6 @@
     <dimen name="hvac_panel_button_height">96dp</dimen>
     <dimen name="hvac_panel_button_width">96dp</dimen>
 
-    <dimen name="hvac_panel_button_radius">54dp</dimen>
     <dimen name="hvac_panel_group_height">244dp</dimen>
     <dimen name="hvac_panel_center_group_width">536dp</dimen>
     <dimen name="hvac_panel_center_group_margin">16dp</dimen>
@@ -354,7 +338,6 @@
     <dimen name="hvac_fan_speed_bar_height">72dp</dimen>
     <dimen name="hvac_fan_speed_bar_vertical_inset">8dp</dimen>
     <dimen name="hvac_fan_speed_bar_width">680dp</dimen>
-    <dimen name="hvac_fan_speed_bar_corner_radius">28dp</dimen>
     <dimen name="hvac_fan_speed_bar_end_button_margin">12dp</dimen>
     <dimen name="hvac_fan_speed_bar_segment_margin">4dp</dimen>
 
@@ -403,7 +386,6 @@
     <!-- Dimensions for the Buttons in ActivityBlockingActivity -->
     <dimen name="activity_blocking_action_button_height">76dp</dimen>
     <dimen name="activity_blocking_action_button_top_margin">48dp</dimen>
-    <dimen name="activity_blocking_action_button_corner_radius">38dp</dimen>
     <dimen name="activity_blocking_action_button_max_width">268dp</dimen>
     <dimen name="activity_blocking_action_button_min_width">@*android:dimen/car_button_min_width</dimen>
     <dimen name="activity_blocking_action_button_text_size">@*android:dimen/car_body3_size</dimen>
@@ -426,13 +408,11 @@
     <dimen name="display_input_lock_text_bottom_margin">24dp</dimen>
     <dimen name="display_input_lock_text_size">24sp</dimen>
     <dimen name="display_input_lock_text_width">642dp</dimen>
-    <dimen name="display_input_lock_background_radius">8dp</dimen>
 
     <!-- Dimensions for user picker -->
     <dimen name="user_picker_button_size">76dp</dimen>
     <dimen name="user_picker_pill_button_width">80dp</dimen>
     <dimen name="user_picker_pill_button_height">56dp</dimen>
-    <dimen name="user_picker_pill_radius">30dp</dimen>
     <dimen name="user_picker_pill_header_margin">20dp</dimen>
     <dimen name="user_picker_pill_padding_horizontal">22dp</dimen>
     <dimen name="user_picker_pill_padding_vertical">10dp</dimen>
@@ -466,14 +446,11 @@
     <dimen name="pin_pad_key_height">96dp</dimen>
     <dimen name="pin_pad_key_margin">10dp</dimen>
     <dimen name="pin_pad_icon_size">@*android:dimen/car_primary_icon_size</dimen>
-    <dimen name="pin_pad_key_radius">100dp</dimen>
 
     <dimen name="dock_container_margin">10dp</dimen>
 
-    <dimen name="data_subscription_pop_up_radius">24dp</dimen>
     <dimen name="data_subscription_pop_up_arrow_height">19dp</dimen>
     <dimen name="data_subscription_pop_up_arrow_width">38dp</dimen>
-    <dimen name="data_subscription_pop_up_arrow_radius">5dp</dimen>
     <dimen name="data_subscription_pop_up_arrow_offset">84dp</dimen>
     <dimen name="data_subscription_pop_up_vertical_padding">46dp</dimen>
     <dimen name="data_subscription_pop_up_horizontal_padding">@*android:dimen/car_padding_3</dimen>
@@ -487,4 +464,6 @@
     <!-- Dimensions for passenger keyguard -->
     <dimen name="passenger_keyguard_lockpattern_width">350dp</dimen>
     <dimen name="passenger_keyguard_lockpattern_height">350dp</dimen>
+
+    <dimen name="freeform_decor_caption_height">68dp</dimen>
 </resources>
diff --git a/res/values/integers.xml b/res/values/integers.xml
index 162aa0af..5c988d5c 100644
--- a/res/values/integers.xml
+++ b/res/values/integers.xml
@@ -63,4 +63,10 @@
 
     <!-- Timeout value for data subscription pop up in ms -->
     <integer name="data_subscription_pop_up_timeout">30000</integer>
+    <!-- The interval between 2 popup appearance in days-->
+    <integer name="data_subscription_pop_up_frequency">7</integer>
+    <!-- The number of startup cycles after which the popup is not shown anymore -->
+    <integer name="data_subscription_pop_up_startup_cycle_limit">3</integer>
+    <!-- The number of active days after which the popup is not shown anymore -->
+    <integer name="data_subscription_pop_up_active_days_limit">5</integer>
 </resources>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 54f73f59..50cc1687 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -26,41 +26,38 @@
         <item name="android:padding">22dp</item>
     </style>
 
-    <style name="TextAppearance.SystemBar.Clock"
-           parent="@*android:style/TextAppearance.StatusBar.Icon">
-        <item name="android:textSize">@dimen/car_body4_size</item>
+    <style name="SystemBarClockText">
+        <item name="android:textAppearance">?oemTextAppearanceTitleMedium</item>
         <item name="android:textColor">@color/system_bar_clock_text_color</item>
         <item name="android:textFontWeight">500</item>
     </style>
 
-    <style name="TextAppearance.SystemBar.ClockWithSelection"
-           parent="@*android:style/TextAppearance.StatusBar.Icon">
-        <item name="android:textSize">@dimen/car_body1_size</item>
+    <style name="SystemBarClockWithSelectionText">
+        <item name="android:textAppearance">?oemTextAppearanceTitleLarge</item>
         <item name="android:textColor">@color/system_bar_text_color_with_selection</item>
     </style>
 
-    <style name="TextAppearance.SystemBar.Username"
-           parent="@android:style/TextAppearance.DeviceDefault">
-        <item name="android:textSize">@dimen/car_body3_size</item>
+    <style name="SystemBarUsernameText">
+        <item name="android:textAppearance">?oemTextAppearanceTitleMedium</item>
         <item name="android:textColor">@color/system_bar_text_color_with_selection</item>
         <item name="android:fontFamily">sans-serif-medium</item>
-    </style>
-
-    <style name="TextAppearance.CarStatus" parent="@android:style/TextAppearance.DeviceDefault">
-        <item name="android:textSize">@*android:dimen/car_body2_size</item>
-        <item name="android:textColor">@color/system_bar_text_color</item>
+        <item name="android:textColorHint">?oemColorOnSurfaceInverse</item>
+        <item name="android:textColorHighlight">?oemColorOnSurfaceInverse</item>
+        <item name="android:textColorLink">?oemColorOnSurfaceInverse</item>
     </style>
 
     <!-- The style for a Toast. -->
-    <style name="TextAppearance.Toast" parent="@*android:style/TextAppearance.DeviceDefault">
-        <item name="android:textSize">@*android:dimen/car_body2_size</item>
-        <item name="android:textColor">@android:color/white</item>
+    <style name="ToastText">
+        <item name="android:textAppearance">?oemTextAppearanceTitleMedium</item>
+        <item name="fontFamily">@*android:string/config_bodyFontFamily</item>
+        <item name="lineHeight">20sp</item>
     </style>
 
     <style name="SystemBarButton">
         <item name="android:layout_height">@dimen/system_bar_button_size</item>
         <item name="android:layout_width">@dimen/system_bar_button_size</item>
-        <item name="android:layout_marginEnd">@dimen/system_bar_button_margin</item>
+        <item name="android:layout_marginEnd">0dp</item>
+        <item name="android:layout_centerVertical">true</item>
         <item name="android:padding">@dimen/system_bar_button_padding</item>
         <item name="android:gravity">center</item>
         <item name="android:background">@drawable/nav_bar_button_background</item>
@@ -71,19 +68,13 @@
         <item name="android:layout_marginBottom">@dimen/system_bar_button_margin</item>
     </style>
 
-    <!-- todo(b/304320644): update SystemBarButton -->
-    <style name="SystemBarButtonWithDock" parent="SystemBarButton">
-        <item name="android:layout_marginEnd">0dp</item>
-        <item name="android:layout_centerVertical">true</item>
-    </style>
-
     <style name="TemperatureControlView">
         <item name="android:layout_width">wrap_content</item>
         <item name="android:layout_height">wrap_content</item>
         <item name="android:layout_centerVertical">true</item>
     </style>
 
-<!--    Todo: update RB to work with these styles -->
+    <!--    Todo: update RB to work with these styles -->
     <style name="TopBarButton">
         <item name="android:layout_marginTop">@dimen/car_quick_controls_entry_points_button_margin_top</item>
         <item name="android:layout_marginBottom">@dimen/car_quick_controls_entry_points_button_margin_bottom</item>
@@ -111,7 +102,7 @@
 
     <style name="HvacTemperatureFont">
         <item name="android:textSize">@dimen/temperature_bar_text_size</item>
-        <item name="android:textColor">@color/car_on_primary</item>
+        <item name="android:textColor">?oemColorOnPrimary</item>
     </style>
 
     <style name="HvacTemperature" parent="HvacTemperatureFont">
@@ -170,7 +161,7 @@
     <style name="ActionButtonText" parent="android:TextAppearance.DeviceDefault">
         <item name="android:fontFamily">roboto-regular</item>
         <item name="android:textColor">@color/blocking_text</item>
-        <item name="android:textSize">@*android:dimen/car_body3_size</item>
+        <item name="android:textAppearance">?oemTextAppearanceTitleMedium</item>
     </style>
 
     <!-- Style for buttons in ActivityBlockingActivity. -->
@@ -188,7 +179,7 @@
     </style>
 
     <style name="QCFooterButtonStyle"
-           parent="android:Widget.DeviceDefault.Button">
+        parent="android:Widget.DeviceDefault.Button">
         <item name="android:layout_width">match_parent</item>
         <item name="android:layout_height">wrap_content</item>
         <item name="android:minHeight">@dimen/car_quick_controls_footer_button_min_height</item>
@@ -215,17 +206,15 @@
     <!-- Style for message text of user picker alert dialog. -->
     <style name="UserPickerDialogMessageNormalText">
         <item name="android:textStyle">normal</item>
-        <item name="android:textSize">@dimen/car_body4_size</item>
-        <item name="android:textColor">@*android:color/car_body4</item>
+        <item name="android:textAppearance">?oemTextAppearanceTitleSmall</item>
     </style>
     <style name="UserPickerDialogMessageLargeText">
         <item name="android:textStyle">normal</item>
-        <item name="android:textSize">@dimen/car_body2_size</item>
-        <item name="android:textColor">@*android:color/car_body4</item>
+        <item name="android:textAppearance">?oemTextAppearanceTitleMedium</item>
     </style>
     <!-- Style user picker snackbar. -->
     <style name="UserPickerSnackBarText" parent="Widget.MaterialComponents.Snackbar.TextView">
-        <item name="android:textSize">@dimen/car_body3_size</item>
+        <item name="android:textAppearance">?oemTextAppearanceTitleMedium</item>
         <item name="android:textColor">@color/car_ui_text_color_primary</item>
         <item name="android:textColorPrimary">@color/car_ui_text_color_primary</item>
         <item name="android:textColorLink">@color/car_ui_text_color_primary</item>
@@ -234,28 +223,60 @@
     </style>
 
     <!-- Biometrics -->
-    <style name="PinPadKey" parent="TextAppearance.Car.Headline.Medium">
+    <style name="PinPadKey">
         <item name="android:gravity">center</item>
         <item name="android:textStyle">normal</item>
-        <item name="android:textColor">@*android:color/car_body3</item>
-        <item name="android:tint">@*android:color/car_body3</item>
+        <item name="android:textColor">?oemColorSecondary</item>
+        <item name="android:tint">?oemColorSecondary</item>
         <item name="android:clickable">true</item>
     </style>
 
     <!-- Passenger Keyguard -->
     <style name="PassengerLockPattern">
-        <item name="*android:regularColor">@*android:color/car_body1</item>
-        <item name="*android:successColor">@*android:color/car_blue_500</item>
-        <item name="*android:errorColor">?android:attr/colorError</item>
+        <item name="*android:regularColor">?oemColorSurfaceContainerLow</item>
+        <item name="*android:successColor">?oemColorBlue</item>
+        <item name="*android:errorColor">?oemColorError</item>
     </style>
 
     <style name="PassengerPinPadKey">
         <item name="android:gravity">center</item>
         <item name="android:textStyle">normal</item>
-        <item name="android:textSize">@*android:dimen/car_body1_size</item>
-        <item name="android:textColor">@*android:color/car_body3</item>
-        <item name="android:tint">@*android:color/car_body3</item>
+        <item name="android:textAppearance">?oemTextAppearanceTitleLarge</item>
+        <item name="android:textColor">?oemColorSecondary</item>
+        <item name="android:tint">?oemColorSecondary</item>
         <item name="android:clickable">true</item>
         <item name="android:background">?android:attr/selectableItemBackground</item>
     </style>
+
+    <style name="CaptionBarStyle">
+        <item name="android:background">?oemColorSurface</item>
+        <item name="android:paddingStart">16dp</item>
+        <item name="android:paddingEnd">16dp</item>
+    </style>
+
+    <style name="CaptionButtonStyle">
+        <item name="android:layout_width">44dp</item>
+        <item name="android:layout_height">44dp</item>
+        <item name="android:layout_gravity">center</item>
+    </style>
+
+    <style name="CarSystemUIThemeOverlay">
+        <item name="systemBarPillRadius">?oemShapeCornerFull</item>
+        <item name="systemBarPillSelectedRadius">?oemShapeCornerSmall</item>
+        <item name="hvacPanelBackgroundRadius">?oemShapeCornerExtraLarge</item>
+        <item name="notificationShadeHandleBarRadius">?oemShapeCornerMedium</item>
+        <item name="notificationShadowRadius">?oemShapeCornerSmall</item>
+        <item name="carStatusIconPanelBorderRadius">?oemShapeCornerLarge</item>
+        <item name="carNavBarButtonSelectedCornerRadius">?oemShapeCornerMedium</item>
+        <item name="hvacPanelHandleBarRadius">?oemShapeCornerMedium</item>
+        <item name="temperatureBarBgRadius">?oemShapeCornerExtraLarge</item>
+        <item name="hvacPanelButtonRadius">?oemShapeCornerExtraLarge</item>
+        <item name="hvacFanSpeedBarCornerRadius">?oemShapeCornerLarge</item>
+        <item name="activityBlockingActionButtonCornerRadius">?oemShapeCornerLarge</item>
+        <item name="displayInputLockBackgroundRadius">?oemShapeCornerExtraSmall</item>
+        <item name="userPickerPillRadius">?oemShapeCornerLarge</item>
+        <item name="pinPadKeyRadius">?oemShapeCornerFull</item>
+        <item name="dataSubscriptionPopUpRadius">?oemShapeCornerMedium</item>
+        <item name="dataSubscriptionPopUpArrowRadius">?oemShapeCornerExtraSmall</item>
+    </style>
 </resources>
diff --git a/res/values/themes.xml b/res/values/themes.xml
index 6bb57e19..35d3ebf0 100644
--- a/res/values/themes.xml
+++ b/res/values/themes.xml
@@ -19,6 +19,10 @@
 
 <resources>
     <style name="Theme.Notification" parent="Theme.DeviceDefault.NoActionBar.Notification">
+    </style>
+    <style name="CarSystemBarButtonOverlay">
+        <item name="oemTokenOverrideEnabled">true</item>
+
     </style>
     <style name="Theme.UserPicker" parent="@style/Theme.CarUi.NoToolbar">
         <item name="android:windowSplashScreenAnimatedIcon">@drawable/user_picker_splash_icon</item>
@@ -29,10 +33,12 @@
         <item name="snackbarStyle">@style/Widget.MaterialComponents.Snackbar</item>
         <item name="snackbarButtonStyle">@style/Widget.MaterialComponents.Button.TextButton.Snackbar</item>
         <item name="snackbarTextViewStyle">@style/UserPickerSnackBarText</item>
+        <item name="oemTokenOverrideEnabled">true</item>
+        <item name="userPickerPillRadius">?oemShapeCornerLarge</item>
     </style>
 
     <!-- Used by the ActivityBlockingActivity to hide the splash screen icon -->
-    <style name="Theme.NoTitleBar.NoSplash" parent="@android:style/Theme.NoTitleBar">
+    <style name="Theme.ActivityBlockingActivity" parent="@android:style/Theme.Translucent.NoTitleBar">
         <item name="android:windowSplashScreenAnimatedIcon">@android:color/transparent</item>
         <item name="android:windowSplashScreenAnimationDuration">0</item>
         <!--
@@ -41,5 +47,21 @@
             ActivityBlockingActivity.
         -->
         <item name="android:windowIsTranslucent">true</item>
+        <item name="android:windowBackground">@color/activity_blocking_activity_background</item>
+        <item name="oemTokenOverrideEnabled">true</item>
+        <item name="activityBlockingActionButtonCornerRadius">?oemShapeCornerLarge</item>
+        <item name="displayInputLockBackgroundRadius">?oemShapeCornerExtraSmall</item>
+    </style>
+
+    <style name="Theme.ContinuousBlankActivity" parent="@android:style/Theme.NoTitleBar.Fullscreen">
+        <item name="oemTokenOverrideEnabled">true</item>
+        <item name="activityBlockingActionButtonCornerRadius">?oemShapeCornerLarge</item>
+        <item name="displayInputLockBackgroundRadius">?oemShapeCornerExtraSmall</item>
+    </style>
+
+    <style name="Theme.LaunchOnPrivateDisplayRouterActivity" parent="@android:style/Theme.Translucent.NoTitleBar">
+        <item name="oemTokenOverrideEnabled">true</item>
+        <item name="activityBlockingActionButtonCornerRadius">?oemShapeCornerLarge</item>
+        <item name="displayInputLockBackgroundRadius">?oemShapeCornerExtraSmall</item>
     </style>
 </resources>
diff --git a/src/com/android/systemui/CarSysUIComponent.java b/src/com/android/systemui/CarSysUIComponent.java
index 731159cb..5d72b529 100644
--- a/src/com/android/systemui/CarSysUIComponent.java
+++ b/src/com/android/systemui/CarSysUIComponent.java
@@ -16,6 +16,9 @@
 
 package com.android.systemui;
 
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.car.wm.scalableui.ScalableUIWMInitializer;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
 import com.android.systemui.dagger.DependencyProvider;
 import com.android.systemui.dagger.SysUIComponent;
 import com.android.systemui.dagger.SysUISingleton;
@@ -50,6 +53,24 @@ public interface CarSysUIComponent extends SysUIComponent {
         @BindsInstance
         Builder setRootTaskDisplayAreaOrganizer(Optional<RootTaskDisplayAreaOrganizer> r);
 
+        /**
+         * Sets an optional {@link ScalableUIWMInitializer} for the builder.
+         */
+        @BindsInstance
+        Builder setScalableUIWMInitializer(Optional<ScalableUIWMInitializer> initializer);
+
+        /**
+         * Sets the ScalableUI {@link TaskPanelInfoRepository} for the builder.
+         */
+        @BindsInstance
+        Builder setTaskPanelInfoRepository(TaskPanelInfoRepository repository);
+
+        /**
+         * Sets the ScalableUI {@link EventDispatcher} for the builder.
+         */
+        @BindsInstance
+        Builder setScalableUIEventDispatcher(EventDispatcher dispatcher);
+
         CarSysUIComponent build();
     }
 }
diff --git a/src/com/android/systemui/CarSystemUIApplication.java b/src/com/android/systemui/CarSystemUIApplication.java
index bcafdfc6..6139586c 100644
--- a/src/com/android/systemui/CarSystemUIApplication.java
+++ b/src/com/android/systemui/CarSystemUIApplication.java
@@ -18,10 +18,19 @@ package com.android.systemui;
 
 import static android.car.CarOccupantZoneManager.DISPLAY_TYPE_MAIN;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 import android.car.Car;
 import android.car.CarOccupantZoneManager;
+import android.content.Context;
+import android.content.res.Configuration;
+import android.os.Bundle;
+import android.os.UserHandle;
+import android.view.ContextThemeWrapper;
 import android.view.Display;
+import android.view.WindowManager;
 
+import com.android.car.oem.tokens.Token;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 
 /**
@@ -76,4 +85,32 @@ public class CarSystemUIApplication extends SystemUIApplication {
         }
         return super.shouldStartSecondaryUserServices();
     }
+
+    @Override
+    public void attachBaseContext(Context base) {
+        Context context = Token.createOemStyledContext(base);
+        context.getTheme().applyStyle(R.style.CarSystemUIThemeOverlay, true);
+        super.attachBaseContext(context);
+    }
+
+    @Override
+    public Context createContextAsUser(UserHandle user, @CreatePackageOptions int flags) {
+        Context context = super.createContextAsUser(user, flags);
+        return new ContextThemeWrapper(context, this.getTheme());
+    }
+
+    @Override
+    @NonNull
+    public Context createWindowContext(@WindowManager.LayoutParams.WindowType int type,
+        @Nullable Bundle options) {
+        Context context = super.createWindowContext(type, options);
+        return new ContextThemeWrapper(context, this.getTheme());
+    }
+
+    @Override
+    public Context createConfigurationContext(Configuration overrideConfiguration) {
+        Context context = super.createConfigurationContext(overrideConfiguration);
+        return new ContextThemeWrapper(context, this.getTheme());
+    }
+
 }
diff --git a/src/com/android/systemui/CarSystemUIBinder.java b/src/com/android/systemui/CarSystemUIBinder.java
index d45435d5..dd649228 100644
--- a/src/com/android/systemui/CarSystemUIBinder.java
+++ b/src/com/android/systemui/CarSystemUIBinder.java
@@ -22,6 +22,7 @@ import com.android.systemui.car.qc.QuickControlsModule;
 import com.android.systemui.car.statusicon.ui.QuickControlsEntryPointsModule;
 import com.android.systemui.car.systembar.CarSystemBarModule;
 import com.android.systemui.car.window.OverlayWindowModule;
+import com.android.systemui.car.wm.scalableui.systemevents.EventHandlerModule;
 import com.android.systemui.recents.RecentsModule;
 import com.android.systemui.statusbar.dagger.CentralSurfacesDependenciesModule;
 import com.android.systemui.statusbar.notification.dagger.NotificationsModule;
@@ -33,6 +34,6 @@ import dagger.Module;
 @Module(includes = {RecentsModule.class, CentralSurfacesDependenciesModule.class,
         NotificationsModule.class, NotificationRowModule.class, CarKeyguardModule.class,
         OverlayWindowModule.class, CarNotificationModule.class, QuickControlsModule.class,
-        QuickControlsEntryPointsModule.class, CarSystemBarModule.class})
+        QuickControlsEntryPointsModule.class, CarSystemBarModule.class, EventHandlerModule.class})
 public abstract class CarSystemUIBinder {
 }
diff --git a/src/com/android/systemui/CarSystemUIInitializer.java b/src/com/android/systemui/CarSystemUIInitializer.java
index d6125fc2..c7258a6f 100644
--- a/src/com/android/systemui/CarSystemUIInitializer.java
+++ b/src/com/android/systemui/CarSystemUIInitializer.java
@@ -50,7 +50,10 @@ public class CarSystemUIInitializer extends SystemUIInitializer {
         boolean isSystemUser = UserHandle.myUserId() == UserHandle.USER_SYSTEM;
         return ((CarSysUIComponent.Builder) sysUIBuilder).setRootTaskDisplayAreaOrganizer(
                         isSystemUser ? Optional.of(carWm.getRootTaskDisplayAreaOrganizer())
-                                : Optional.empty());
+                                : Optional.empty())
+                .setScalableUIWMInitializer(carWm.getScalableUIWMInitializer())
+                .setTaskPanelInfoRepository(carWm.getTaskPanelInfoRepository())
+                .setScalableUIEventDispatcher(carWm.getScalableUIEventDispatcher());
     }
 
     private void initWmComponents(CarWMComponent carWm) {
diff --git a/src/com/android/systemui/CarSystemUIModule.java b/src/com/android/systemui/CarSystemUIModule.java
index b087775a..f4768186 100644
--- a/src/com/android/systemui/CarSystemUIModule.java
+++ b/src/com/android/systemui/CarSystemUIModule.java
@@ -40,6 +40,7 @@ import com.android.systemui.car.statusbar.DozeServiceHost;
 import com.android.systemui.car.users.CarMultiUserUtilsModule;
 import com.android.systemui.car.volume.CarVolumeModule;
 import com.android.systemui.car.wm.activity.window.ActivityWindowModule;
+import com.android.systemui.communal.posturing.dagger.NoopPosturingModule;
 import com.android.systemui.dagger.GlobalRootComponent;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
@@ -60,6 +61,7 @@ import com.android.systemui.recents.RecentsImplementation;
 import com.android.systemui.recents.RecentsModule;
 import com.android.systemui.screenshot.ReferenceScreenshotModule;
 import com.android.systemui.settings.UserTracker;
+import com.android.systemui.settings.brightness.dagger.BrightnessSliderModule;
 import com.android.systemui.shade.ShadeEmptyImplModule;
 import com.android.systemui.statusbar.CommandQueue;
 import com.android.systemui.statusbar.NotificationLockscreenUserManager;
@@ -75,6 +77,7 @@ import com.android.systemui.statusbar.policy.SensorPrivacyController;
 import com.android.systemui.statusbar.policy.SensorPrivacyControllerImpl;
 import com.android.systemui.unfold.SysUIUnfoldStartableModule;
 import com.android.systemui.wallpapers.dagger.NoopWallpaperModule;
+import com.android.systemui.window.dagger.WindowRootViewBlurNotSupportedModule;
 
 import dagger.Binds;
 import dagger.Module;
@@ -91,6 +94,7 @@ import javax.inject.Named;
                 ActivityWindowModule.class,
                 AospPolicyModule.class,
                 BiometricsModule.class,
+                BrightnessSliderModule.class,
                 CarMultiUserUtilsModule.class,
                 CarVolumeModule.class,
                 ExternalDisplayController.StartableModule.class,
@@ -101,6 +105,7 @@ import javax.inject.Named;
                 MediaMuteAwaitConnectionCli.StartableModule.class,
                 NearbyMediaDevicesManager.StartableModule.class,
                 NoopNavigationBarControllerModule.class,
+                NoopPosturingModule.class,
                 NoopWallpaperModule.class,
                 PowerModule.class,
                 QSModule.class,
@@ -109,6 +114,7 @@ import javax.inject.Named;
                 ScreenDecorationsModule.class,
                 ShadeEmptyImplModule.class,
                 SysUIUnfoldStartableModule.class,
+                WindowRootViewBlurNotSupportedModule.class
         }
 )
 abstract class CarSystemUIModule {
diff --git a/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java b/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
index ac621422..87ba318f 100644
--- a/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
+++ b/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
@@ -39,7 +39,7 @@ import com.android.systemui.statusbar.events.PrivacyDotViewController;
 import com.android.systemui.statusbar.events.PrivacyDotViewControllerImpl;
 import com.android.systemui.statusbar.events.SystemStatusAnimationScheduler;
 import com.android.systemui.statusbar.events.ViewState;
-import com.android.systemui.statusbar.phone.StatusBarContentInsetsProvider;
+import com.android.systemui.statusbar.layout.StatusBarContentInsetsProvider;
 import com.android.systemui.statusbar.policy.ConfigurationController;
 import com.android.systemui.util.concurrency.DelayableExecutor;
 
diff --git a/src/com/android/systemui/car/displaycompat/CarDisplayCompatUtils.java b/src/com/android/systemui/car/displaycompat/CarDisplayCompatUtils.java
new file mode 100644
index 00000000..97355860
--- /dev/null
+++ b/src/com/android/systemui/car/displaycompat/CarDisplayCompatUtils.java
@@ -0,0 +1,71 @@
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
+package com.android.systemui.car.displaycompat;
+
+import static android.car.Car.PERMISSION_MANAGE_DISPLAY_COMPATIBILITY;
+
+import android.app.ActivityManager;
+import android.car.content.pm.CarPackageManager;
+import android.content.pm.PackageManager;
+import android.util.Log;
+
+import androidx.annotation.Nullable;
+import androidx.annotation.RequiresPermission;
+
+/**
+ * Utility class for display compatibility
+ */
+public class CarDisplayCompatUtils {
+    private static final String TAG = "CarDisplayCompatUtils";
+
+    /**
+     * @return the package name associated with the taskInfo
+     */
+    @Nullable
+    public static String getPackageName(ActivityManager.RunningTaskInfo taskInfo) {
+        if (taskInfo.topActivity != null) {
+            return taskInfo.topActivity.getPackageName();
+        }
+        if (taskInfo.baseIntent.getComponent() != null) {
+            return taskInfo.baseIntent.getComponent().getPackageName();
+        }
+        return null;
+    }
+
+    /**
+     * @return {@code true} if the {@code packageName} requires display compatibility
+     */
+    @RequiresPermission(allOf = {PERMISSION_MANAGE_DISPLAY_COMPATIBILITY,
+            android.Manifest.permission.QUERY_ALL_PACKAGES})
+    public static boolean requiresDisplayCompat(
+            @Nullable String packageName, int userId,
+            @Nullable CarPackageManager carPackageManager) {
+        if (packageName == null) {
+            return false;
+        }
+        if (carPackageManager == null) {
+            return false;
+        }
+        boolean result = false;
+        try {
+            result = carPackageManager.requiresDisplayCompatForUser(packageName, userId);
+        } catch (PackageManager.NameNotFoundException e) {
+            Log.v(TAG, e.toString());
+        }
+        return result;
+    }
+}
diff --git a/src/com/android/systemui/car/displaycompat/ToolbarControllerImpl.java b/src/com/android/systemui/car/displaycompat/ToolbarControllerImpl.java
index 13456ad8..61ea78fc 100644
--- a/src/com/android/systemui/car/displaycompat/ToolbarControllerImpl.java
+++ b/src/com/android/systemui/car/displaycompat/ToolbarControllerImpl.java
@@ -20,11 +20,13 @@ import static android.view.Display.DEFAULT_DISPLAY;
 import static android.view.View.GONE;
 import static android.view.View.VISIBLE;
 
+import static com.android.systemui.car.displaycompat.CarDisplayCompatUtils.getPackageName;
+import static com.android.systemui.car.displaycompat.CarDisplayCompatUtils.requiresDisplayCompat;
+
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.app.ActivityManager.RunningTaskInfo;
 import android.car.content.pm.CarPackageManager;
-import android.content.pm.PackageManager.NameNotFoundException;
 import android.hardware.input.InputManager;
 import android.hardware.input.InputManagerGlobal;
 import android.os.Handler;
@@ -72,8 +74,10 @@ public class ToolbarControllerImpl implements ToolbarController {
     private ImageButton mBackButton;
 
     @Inject
-    public ToolbarControllerImpl(@NonNull @Main Handler mainHandler,
-            CarServiceProvider carServiceProvider) {
+    public ToolbarControllerImpl(
+            @NonNull @Main Handler mainHandler,
+            CarServiceProvider carServiceProvider
+    ) {
         mMainHandler = mainHandler;
         mCarServiceProvider = carServiceProvider;
     }
@@ -133,7 +137,8 @@ public class ToolbarControllerImpl implements ToolbarController {
             Log.w(TAG, "init was not called");
             return;
         }
-        if (requiresDisplayCompat(getPackageName(taskInfo))
+        if (requiresDisplayCompat(
+                getPackageName(taskInfo), taskInfo.userId, mCarPackageManager)
                 && taskInfo.displayId == DEFAULT_DISPLAY) {
             mMainHandler.post(() -> show());
             return;
@@ -141,28 +146,6 @@ public class ToolbarControllerImpl implements ToolbarController {
         mMainHandler.post(() -> hide());
     }
 
-    private String getPackageName(RunningTaskInfo taskInfo) {
-        if (taskInfo.topActivity != null) {
-            return taskInfo.topActivity.getPackageName();
-        }
-        return taskInfo.baseIntent.getComponent().getPackageName();
-    }
-
-    @RequiresPermission(allOf = {PERMISSION_MANAGE_DISPLAY_COMPATIBILITY,
-            android.Manifest.permission.QUERY_ALL_PACKAGES})
-    private boolean requiresDisplayCompat(String packageName) {
-        boolean result = false;
-        if (mCarPackageManager != null) {
-            try {
-                result = mCarPackageManager.requiresDisplayCompat(packageName);
-            } catch (NameNotFoundException e) {
-            }
-        } else {
-            Log.w(TAG, "CarPackageManager is not set.");
-        }
-        return result;
-    }
-
     /**
      * Send both action down and up to be qualified as a back press. Set time for key events, so
      * they are not staled.
diff --git a/src/com/android/systemui/car/hvac/HvacButtonController.java b/src/com/android/systemui/car/hvac/HvacButtonController.java
index f79660c1..fc51dbf7 100644
--- a/src/com/android/systemui/car/hvac/HvacButtonController.java
+++ b/src/com/android/systemui/car/hvac/HvacButtonController.java
@@ -17,11 +17,13 @@ package com.android.systemui.car.hvac;
 
 import android.view.View;
 
+import com.android.systemui.car.systembar.ButtonSelectionStateController;
 import com.android.systemui.car.systembar.CarSystemBarButton;
 import com.android.systemui.car.systembar.CarSystemBarButtonController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.settings.UserTracker;
 
 import dagger.assisted.Assisted;
@@ -40,8 +42,10 @@ public class HvacButtonController extends CarSystemBarButtonController {
             CarSystemBarElementStatusBarDisableController disableController,
             CarSystemBarElementStateController stateController,
             HvacPanelOverlayViewController hvacPanelOverlayViewController,
-            UserTracker userTracker) {
-        super(hvacButton, disableController, stateController, userTracker);
+            UserTracker userTracker, EventDispatcher eventDispatcher,
+            ButtonSelectionStateController buttonSelectionStateController) {
+        super(hvacButton, disableController, stateController, userTracker, eventDispatcher,
+                buttonSelectionStateController);
 
         mHvacPanelOverlayViewController = hvacPanelOverlayViewController;
         mHvacPanelOverlayViewController.registerViewStateListener(hvacButton);
diff --git a/src/com/android/systemui/car/hvac/SeatTemperatureLevelButton.java b/src/com/android/systemui/car/hvac/SeatTemperatureLevelButton.java
index c45f71bb..65923a9b 100644
--- a/src/com/android/systemui/car/hvac/SeatTemperatureLevelButton.java
+++ b/src/com/android/systemui/car/hvac/SeatTemperatureLevelButton.java
@@ -185,10 +185,12 @@ public class SeatTemperatureLevelButton extends ImageButton implements HvacView
                             + "same length as R.integer.hvac_seat_heat_level_count");
         }
 
+        int[] drawableIds = new int[seatTemperatureIcons.length()];
         for (int i = 0; i < mTotalLevelCount; i++) {
-            mIcons.set(i, seatTemperatureIcons.getDrawable(i));
+            drawableIds[i] = seatTemperatureIcons.getResourceId(i, 0);
+            mIcons.set(i, mContext.getResources().getDrawable(drawableIds[i], mContext.getTheme()));
         }
-        seatTemperatureIcons.recycle();
         typedArray.recycle();
+        seatTemperatureIcons.recycle();
     }
 }
diff --git a/src/com/android/systemui/car/hvac/TemperatureControlView.java b/src/com/android/systemui/car/hvac/TemperatureControlView.java
index 19d7c464..d813d6a2 100644
--- a/src/com/android/systemui/car/hvac/TemperatureControlView.java
+++ b/src/com/android/systemui/car/hvac/TemperatureControlView.java
@@ -31,7 +31,6 @@ import android.widget.TextView;
 
 import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
-import androidx.core.content.ContextCompat;
 
 import com.android.systemui.R;
 import com.android.systemui.car.systembar.element.CarSystemBarElement;
@@ -93,9 +92,10 @@ public class TemperatureControlView extends LinearLayout implements HvacView, Ca
         mMinTempC = getResources().getFloat(R.dimen.hvac_min_value_celsius);
         mMinTempF = getResources().getFloat(R.dimen.hvac_min_value_fahrenheit);
         mMaxTempC = getResources().getFloat(R.dimen.hvac_max_value_celsius);
-        mAvailableTextColor = ContextCompat.getColor(getContext(), R.color.system_bar_text_color);
-        mUnavailableTextColor = ContextCompat.getColor(getContext(),
-                R.color.system_bar_text_unavailable_color);
+        mAvailableTextColor = getResources().getColor(R.color.system_bar_text_color,
+                getContext().getTheme());
+        mUnavailableTextColor = getResources().getColor(R.color.system_bar_text_unavailable_color,
+                getContext().getTheme());
 
         mElementControllerClassAttr =
                 CarSystemBarElementResolver.getElementControllerClassFromAttributes(context, attrs);
diff --git a/src/com/android/systemui/car/hvac/referenceui/BackgroundAdjustingTemperatureControlView.java b/src/com/android/systemui/car/hvac/referenceui/BackgroundAdjustingTemperatureControlView.java
index 6f8101ae..67145d1e 100644
--- a/src/com/android/systemui/car/hvac/referenceui/BackgroundAdjustingTemperatureControlView.java
+++ b/src/com/android/systemui/car/hvac/referenceui/BackgroundAdjustingTemperatureControlView.java
@@ -59,12 +59,14 @@ public class BackgroundAdjustingTemperatureControlView extends TemperatureContro
         TypedArray colorRes = res.obtainTypedArray(R.array.hvac_temperature_level_backgrounds);
         mTempColors = new int[colorRes.length()];
         for (int i = 0; i < colorRes.length(); i++) {
-            mTempColors[i] = colorRes.getColor(i,
-                    res.getColor(R.color.hvac_temperature_default_bg_color,
-                            getContext().getTheme()));
+            int color = res.getColor(colorRes.getResourceId(i,
+                    R.color.hvac_temperature_default_bg_color), getContext().getTheme());
+            mTempColors[i] = color;
         }
         colorRes.recycle();
-        mOffColor = res.getColor(R.color.hvac_temperature_off_text_bg_color, /* theme= */ null);
+
+        mOffColor = res.getColor(R.color.hvac_temperature_off_text_bg_color,
+                getContext().getTheme());
         // call super.onFinishInflate() last since it may trigger other methods like
         // updateTemperatureViewUiThread() which can't execute prior to these fixtures being set
         super.onFinishInflate();
diff --git a/src/com/android/systemui/car/hvac/referenceui/FanSpeedBar.java b/src/com/android/systemui/car/hvac/referenceui/FanSpeedBar.java
index 3a78f255..8a33611d 100644
--- a/src/com/android/systemui/car/hvac/referenceui/FanSpeedBar.java
+++ b/src/com/android/systemui/car/hvac/referenceui/FanSpeedBar.java
@@ -102,11 +102,15 @@ public class FanSpeedBar extends RelativeLayout implements HvacView {
         int insetHeight = res.getDimensionPixelSize(R.dimen.hvac_fan_speed_bar_vertical_inset);
         mCornerRadius = (float) (barHeight - 2 * insetHeight) / 2;
 
-        mFanOffActiveBgColor = res.getColor(R.color.hvac_fanspeed_off_active_bg);
-
-        mButtonActiveTextColor = res.getColor(R.color.hvac_fanspeed_off_active_text_color);
-        mButtonInactiveTextColor = res.getColor(R.color.hvac_fanspeed_off_inactive_text_color);
-        mFanMaxActiveBgColor = res.getColor(R.color.hvac_fanspeed_segment_color);
+        mFanOffActiveBgColor = res.getColor(R.color.hvac_fanspeed_off_active_bg,
+                getContext().getTheme());
+
+        mButtonActiveTextColor = res.getColor(R.color.hvac_fanspeed_off_active_text_color,
+                getContext().getTheme());
+        mButtonInactiveTextColor = res.getColor(R.color.hvac_fanspeed_off_inactive_text_color,
+                getContext().getTheme());
+        mFanMaxActiveBgColor = res.getColor(R.color.hvac_fanspeed_segment_color,
+                getContext().getTheme());
         mHvacGlobalAreaId = res.getInteger(R.integer.hvac_global_area_id);
         mMinFanSpeedSupportedByUi = res.getInteger(R.integer.hvac_min_fan_speed);
         mMaxFanSpeedSupportedByUi = res.getInteger(R.integer.hvac_max_fan_speed);
diff --git a/src/com/android/systemui/car/hvac/referenceui/FanSpeedBarSegment.java b/src/com/android/systemui/car/hvac/referenceui/FanSpeedBarSegment.java
index 501cd7bb..9d8cf3b3 100644
--- a/src/com/android/systemui/car/hvac/referenceui/FanSpeedBarSegment.java
+++ b/src/com/android/systemui/car/hvac/referenceui/FanSpeedBarSegment.java
@@ -114,7 +114,7 @@ public class FanSpeedBarSegment extends ImageView {
         mDotWidthExpandAnimator.addUpdateListener(mExpandListener);
 
         GradientDrawable dot = new GradientDrawable();
-        dot.setColor(res.getColor(R.color.hvac_fanspeed_segment_color));
+        dot.setColor(res.getColor(R.color.hvac_fanspeed_segment_color, getContext().getTheme()));
         dot.setSize(mDotSize, mDotSize);
         dot.setCornerRadius(mDotSize / 2);
         setImageDrawable(dot);
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardModule.java b/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
index 01e0f543..839af741 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
@@ -30,10 +30,7 @@ import com.android.keyguard.KeyguardDisplayManager;
 import com.android.keyguard.KeyguardUpdateMonitor;
 import com.android.keyguard.KeyguardViewController;
 import com.android.keyguard.ViewMediatorCallback;
-import com.android.keyguard.dagger.KeyguardQsUserSwitchComponent;
 import com.android.keyguard.dagger.KeyguardStatusBarViewComponent;
-import com.android.keyguard.dagger.KeyguardStatusViewComponent;
-import com.android.keyguard.dagger.KeyguardUserSwitcherComponent;
 import com.android.keyguard.mediator.ScreenOnCoordinator;
 import com.android.systemui.CoreStartable;
 import com.android.systemui.animation.ActivityTransitionAnimator;
@@ -42,6 +39,8 @@ import com.android.systemui.car.keyguard.passenger.PassengerKeyguardLoadingDialo
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.classifier.FalsingCollector;
 import com.android.systemui.classifier.FalsingModule;
+import com.android.systemui.communal.domain.interactor.CommunalSceneInteractor;
+import com.android.systemui.communal.domain.interactor.CommunalSettingsInteractor;
 import com.android.systemui.communal.ui.viewmodel.CommunalTransitionViewModel;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Application;
@@ -57,7 +56,9 @@ import com.android.systemui.keyguard.KeyguardUnlockAnimationController;
 import com.android.systemui.keyguard.KeyguardViewMediator;
 import com.android.systemui.keyguard.WindowManagerLockscreenVisibilityManager;
 import com.android.systemui.keyguard.WindowManagerOcclusionManager;
+import com.android.systemui.keyguard.dagger.GlanceableHubTransitionModule;
 import com.android.systemui.keyguard.dagger.KeyguardFaceAuthNotSupportedModule;
+import com.android.systemui.keyguard.dagger.PrimaryBouncerTransitionModule;
 import com.android.systemui.keyguard.data.repository.KeyguardRepositoryModule;
 import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor;
 import com.android.systemui.keyguard.domain.interactor.KeyguardTransitionBootInteractor;
@@ -106,14 +107,14 @@ import javax.inject.Provider;
  * Dagger Module providing keyguard.
  */
 @Module(subcomponents = {
-        KeyguardQsUserSwitchComponent.class,
-        KeyguardStatusBarViewComponent.class,
-        KeyguardStatusViewComponent.class,
-        KeyguardUserSwitcherComponent.class},
+        KeyguardStatusBarViewComponent.class
+        },
         includes = {
                 FalsingModule.class,
+                GlanceableHubTransitionModule.class,
                 KeyguardFaceAuthNotSupportedModule.class,
                 KeyguardRepositoryModule.class,
+                PrimaryBouncerTransitionModule.class,
                 StartKeyguardTransitionModule.class,
         })
 public interface CarKeyguardModule {
@@ -173,6 +174,8 @@ public interface CarKeyguardModule {
             SelectedUserInteractor selectedUserInteractor,
             KeyguardInteractor keyguardInteractor,
             KeyguardTransitionBootInteractor transitionBootInteractor,
+            Lazy<CommunalSceneInteractor> communalSceneInteractor,
+            Lazy<CommunalSettingsInteractor> communalSettingsInteractor,
             WindowManagerOcclusionManager wmOcclusionManager) {
         return new CarKeyguardViewMediator(
                 context,
@@ -224,6 +227,8 @@ public interface CarKeyguardModule {
                 selectedUserInteractor,
                 keyguardInteractor,
                 transitionBootInteractor,
+                communalSceneInteractor,
+                communalSettingsInteractor,
                 wmOcclusionManager);
     }
 
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardPINView.java b/src/com/android/systemui/car/keyguard/CarKeyguardPINView.java
index a0e7f0d8..ae0dcf7c 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardPINView.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardPINView.java
@@ -43,7 +43,8 @@ public class CarKeyguardPINView extends KeyguardPINView {
     public CarKeyguardPINView(Context context, AttributeSet attrs) {
         super(context, attrs);
 
-        mButtonImageColor = context.getColor(R.color.keyguard_keypad_image_color);
+        mButtonImageColor = context.getResources().getColor(R.color.keyguard_keypad_image_color,
+                context.getTheme());
     }
 
     @Override
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java b/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
index d18a5810..46311cbc 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
@@ -54,6 +54,7 @@ import com.android.systemui.car.window.SystemUIOverlayWindowController;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.keyguard.KeyguardWmStateRefactor;
+import com.android.systemui.keyguard.ui.viewmodel.GlanceableHubToPrimaryBouncerTransitionViewModel;
 import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToGoneTransitionViewModel;
 import com.android.systemui.log.BouncerLogger;
 import com.android.systemui.settings.UserTracker;
@@ -147,6 +148,8 @@ public class CarKeyguardViewController extends OverlayViewController implements
     private int mToastShowDurationMillisecond;
     private ViewGroup mKeyguardContainer;
     private PrimaryBouncerToGoneTransitionViewModel mPrimaryBouncerToGoneTransitionViewModel;
+    private GlanceableHubToPrimaryBouncerTransitionViewModel
+            mGlanceableHubToPrimaryBouncerTransitionViewModel;
     private final Optional<KeyguardSystemBarPresenter> mKeyguardSystemBarPresenter;
     private final StatusBarKeyguardViewManagerInteractor mStatusBarKeyguardViewManagerInteractor;
     private final JavaAdapter mJavaAdapter;
@@ -169,6 +172,8 @@ public class CarKeyguardViewController extends OverlayViewController implements
             KeyguardSecurityModel keyguardSecurityModel,
             KeyguardBouncerViewModel keyguardBouncerViewModel,
             PrimaryBouncerToGoneTransitionViewModel primaryBouncerToGoneTransitionViewModel,
+            GlanceableHubToPrimaryBouncerTransitionViewModel
+                    glanceableHubToPrimaryBouncerTransitionViewModel,
             KeyguardBouncerComponent.Factory keyguardBouncerComponentFactory,
             BouncerView bouncerView,
             KeyguardMessageAreaController.Factory messageAreaControllerFactory,
@@ -195,6 +200,8 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mKeyguardBouncerViewModel = keyguardBouncerViewModel;
         mKeyguardBouncerComponentFactory = keyguardBouncerComponentFactory;
         mPrimaryBouncerToGoneTransitionViewModel = primaryBouncerToGoneTransitionViewModel;
+        mGlanceableHubToPrimaryBouncerTransitionViewModel =
+                glanceableHubToPrimaryBouncerTransitionViewModel;
         mBouncerView = bouncerView;
         mSelectedUserInteractor = selectedUserInteractor;
 
@@ -238,6 +245,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mKeyguardContainer = getLayout().findViewById(R.id.keyguard_container);
         KeyguardBouncerViewBinder.bind(mKeyguardContainer,
                 mKeyguardBouncerViewModel, mPrimaryBouncerToGoneTransitionViewModel,
+                mGlanceableHubToPrimaryBouncerTransitionViewModel,
                 mKeyguardBouncerComponentFactory,
                 mMessageAreaControllerFactory,
                 mBouncerMessageInteractor,
@@ -252,11 +260,16 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mPrimaryBouncerInteractor.notifyKeyguardAuthenticatedBiometrics(strongAuth);
     }
 
+    @Override
+    public void readyForKeyguardDone() {
+        mViewMediatorCallback.readyForKeyguardDone();
+    }
+
     @Override
     @MainThread
-    public void showPrimaryBouncer(boolean scrimmed) {
+    public void showPrimaryBouncer(boolean scrimmed, String reason) {
         if (mShowing && !mPrimaryBouncerInteractor.isFullyShowing()) {
-            mPrimaryBouncerInteractor.show(/* isScrimmed= */ true);
+            mPrimaryBouncerInteractor.show(/* isScrimmed= */ true, reason);
         }
     }
 
@@ -281,7 +294,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
     public void hide(long startTime, long fadeoutDuration) {
         if (!mShowing || mIsSleeping) return;
 
-        mViewMediatorCallback.readyForKeyguardDone();
+        readyForKeyguardDone();
         mShowing = false;
         mKeyguardStateController.notifyKeyguardState(mShowing,
                 mKeyguardStateController.isOccluded());
@@ -557,7 +570,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mMainExecutor.execute(() -> {
             hideInternal();
             mPrimaryBouncerInteractor.hide();
-            mPrimaryBouncerInteractor.show(/* isScrimmed= */ true);
+            mPrimaryBouncerInteractor.show(/* isScrimmed= */ true, TAG + "#resetBouncer");
             revealKeyguardIfBouncerPrepared();
         });
     }
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java b/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
index 2415c376..30287f10 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
@@ -38,6 +38,8 @@ import com.android.systemui.animation.ActivityTransitionAnimator;
 import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.classifier.FalsingCollector;
+import com.android.systemui.communal.domain.interactor.CommunalSceneInteractor;
+import com.android.systemui.communal.domain.interactor.CommunalSettingsInteractor;
 import com.android.systemui.communal.ui.viewmodel.CommunalTransitionViewModel;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.dreams.DreamOverlayStateController;
@@ -76,10 +78,10 @@ import com.android.wm.shell.keyguard.KeyguardTransitions;
 
 import dagger.Lazy;
 
-import java.util.concurrent.Executor;
-
 import kotlinx.coroutines.CoroutineDispatcher;
 
+import java.util.concurrent.Executor;
+
 /**
  * Car customizations on top of {@link KeyguardViewMediator}. Please refer to that class for
  * more details on specific functionalities.
@@ -146,6 +148,8 @@ public class CarKeyguardViewMediator extends KeyguardViewMediator {
             SelectedUserInteractor selectedUserInteractor,
             KeyguardInteractor keyguardInteractor,
             KeyguardTransitionBootInteractor transitionBootInteractor,
+            Lazy<CommunalSceneInteractor> communalSceneInteractor,
+            Lazy<CommunalSettingsInteractor> communalSettingsInteractor,
             WindowManagerOcclusionManager wmOcclusionManager) {
         super(context, uiEventLogger, sessionTracker,
                 userTracker, falsingCollector, lockPatternUtils, broadcastDispatcher,
@@ -173,6 +177,8 @@ public class CarKeyguardViewMediator extends KeyguardViewMediator {
                 selectedUserInteractor,
                 keyguardInteractor,
                 transitionBootInteractor,
+                communalSceneInteractor,
+                communalSettingsInteractor,
                 wmOcclusionManager);
         mContext = context;
         mTrustManager = trustManager;
diff --git a/src/com/android/systemui/car/notification/NotificationButtonController.java b/src/com/android/systemui/car/notification/NotificationButtonController.java
index bc14d16d..5ca60b8b 100644
--- a/src/com/android/systemui/car/notification/NotificationButtonController.java
+++ b/src/com/android/systemui/car/notification/NotificationButtonController.java
@@ -17,11 +17,13 @@ package com.android.systemui.car.notification;
 
 import android.view.View;
 
+import com.android.systemui.car.systembar.ButtonSelectionStateController;
 import com.android.systemui.car.systembar.CarSystemBarButton;
 import com.android.systemui.car.systembar.CarSystemBarButtonController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.settings.UserTracker;
 
 import dagger.assisted.Assisted;
@@ -40,8 +42,10 @@ public class NotificationButtonController extends CarSystemBarButtonController {
             CarSystemBarElementStatusBarDisableController disableController,
             CarSystemBarElementStateController stateController,
             NotificationPanelViewController notificationPanelViewController,
-            UserTracker userTracker) {
-        super(notificationsButton, disableController, stateController, userTracker);
+            UserTracker userTracker, EventDispatcher eventDispatcher,
+            ButtonSelectionStateController buttonSelectionStateController) {
+        super(notificationsButton, disableController, stateController, userTracker,
+                eventDispatcher, buttonSelectionStateController);
 
         mNotificationPanelViewController = notificationPanelViewController;
         mNotificationPanelViewController.registerViewStateListener(notificationsButton);
diff --git a/src/com/android/systemui/car/qc/DataSubscriptionController.java b/src/com/android/systemui/car/qc/DataSubscriptionController.java
index aba58386..24820f8f 100644
--- a/src/com/android/systemui/car/qc/DataSubscriptionController.java
+++ b/src/com/android/systemui/car/qc/DataSubscriptionController.java
@@ -28,6 +28,7 @@ import android.app.TaskStackListener;
 import android.car.drivingstate.CarUxRestrictions;
 import android.content.Context;
 import android.content.Intent;
+import android.content.SharedPreferences;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
@@ -37,6 +38,7 @@ import android.net.Network;
 import android.net.NetworkCapabilities;
 import android.os.Build;
 import android.os.Handler;
+import android.text.TextUtils;
 import android.util.Log;
 import android.view.LayoutInflater;
 import android.view.MotionEvent;
@@ -50,6 +52,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.VisibleForTesting;
 
 import com.android.car.datasubscription.DataSubscription;
+import com.android.car.datasubscription.DataSubscriptionStatus;
 import com.android.car.ui.utils.CarUxRestrictionsUtil;
 import com.android.systemui.R;
 import com.android.systemui.car.qc.DataSubscriptionStatsLogHelper.DataSubscriptionMessageType;
@@ -58,6 +61,10 @@ import com.android.systemui.dagger.qualifiers.Background;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.settings.UserTracker;
 
+import java.time.LocalDate;
+import java.time.ZoneId;
+import java.time.format.DateTimeFormatter;
+import java.time.temporal.ChronoUnit;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.List;
@@ -77,6 +84,8 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
     private static final String TAG = DataSubscriptionController.class.toString();
     private static final String DATA_SUBSCRIPTION_ACTION =
             "android.intent.action.DATA_SUBSCRIPTION";
+    private static final String DATA_SUBSCRIPTION_SHARED_PREFERENCE_PATH =
+            "com.android.car.systemui.car.qc.DataSubscriptionController";
     // Timeout for network callback in ms
     private static final int CALLBACK_TIMEOUT_MS = 1000;
     private final Context mContext;
@@ -204,6 +213,24 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
     private CharSequence mTopLabel;
     private NetworkCapabilities mNetworkCapabilities;
     private boolean mIsUxRestrictionsListenerRegistered;
+    private SharedPreferences mSharedPreferences;
+    private SharedPreferences.Editor mEditor;
+    private int mCurrentInterval;
+    private int mCurrentCycle;
+    private int mCurrentActiveDays;
+
+    @VisibleForTesting
+    static final String KEY_PREV_POPUP_DATE =
+            "com.android.car.systemui.car.qc.PREV_DATE";
+    @VisibleForTesting
+    static final String KEY_PREV_POPUP_CYCLE =
+            "com.android.car.systemui.car.qc.PREV_CYCLE";
+    @VisibleForTesting
+    static final String KEY_PREV_POPUP_ACTIVE_DAYS =
+            "com.android.car.systemui.car.qc.PREV_ACTIVE_DAYS";
+    @VisibleForTesting
+    static final String KEY_PREV_POPUP_STATUS =
+            "com.android.car.systemui.car.qc.PREV_STATUS";
 
     @SuppressLint("MissingPermission")
     @Inject
@@ -271,9 +298,12 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
         } catch (Exception e) {
             Log.e(TAG, "error while registering TaskStackListener " + e);
         }
+        mSharedPreferences = mContext.getSharedPreferences(
+                DATA_SUBSCRIPTION_SHARED_PREFERENCE_PATH, Context.MODE_PRIVATE);
+        mEditor = mSharedPreferences.edit();
     }
 
-    private void updateShouldDisplayProactiveMsg() {
+    void updateShouldDisplayProactiveMsg() {
         if (mIsDistractionOptimizationRequired) {
             if (mPopupWindow != null && mPopupWindow.isShowing()) {
                 mPopupWindow.dismiss();
@@ -282,11 +312,17 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
         } else {
             // Determines whether a proactive message should be displayed
             mShouldDisplayProactiveMsg = !mWasProactiveMsgDisplayed
-                    && mSubscription.isDataSubscriptionInactive();
+                    && mSubscription.isDataSubscriptionInactive()
+                    && isValidTimeInterval()
+                    && isValidCycle()
+                    && isValidActiveDays();
             if (mShouldDisplayProactiveMsg && mPopupWindow != null
                     && !mPopupWindow.isShowing()) {
                 mIsProactiveMsg = true;
                 showPopUpWindow();
+                writeLatestPopupDate();
+                writeLatestPopupCycle();
+                writeLatestPopupActiveDays();
             }
         }
     }
@@ -361,6 +397,10 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
         mAnchorView = view;
         if (mAnchorView != null) {
             mSubscription.addDataSubscriptionListener(this);
+            updateCurrentStatus();
+            updateCurrentInterval();
+            updateCurrentCycle();
+            updateCurrentActiveDays();
             updateShouldDisplayProactiveMsg();
             if (!mIsUxRestrictionsListenerRegistered) {
                 CarUxRestrictionsUtil.getInstance(mContext).register(
@@ -398,6 +438,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
 
     @Override
     public void onChange(int value) {
+        updateCurrentStatus();
         updateShouldDisplayProactiveMsg();
     }
 
@@ -425,6 +466,78 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
         }
     }
 
+    private boolean isValidTimeInterval() {
+        return mCurrentInterval >= mContext.getResources().getInteger(
+                R.integer.data_subscription_pop_up_frequency);
+    }
+
+    private boolean isValidCycle() {
+        if (mCurrentCycle == 1) {
+            return true;
+        }
+        return mCurrentCycle <= mContext.getResources().getInteger(
+                R.integer.data_subscription_pop_up_startup_cycle_limit);
+    }
+
+    private boolean isValidActiveDays() {
+        if (mCurrentActiveDays == 1) {
+            return true;
+        }
+        return mCurrentActiveDays <= mContext.getResources().getInteger(
+                R.integer.data_subscription_pop_up_active_days_limit);
+    }
+
+    private void updateCurrentStatus() {
+        int prevStatus = mSharedPreferences.getInt(KEY_PREV_POPUP_STATUS, 0);
+        int currentStatus = mSubscription.getDataSubscriptionStatus();
+        if (prevStatus == DataSubscriptionStatus.INACTIVE && prevStatus != currentStatus) {
+            mEditor.clear();
+            mEditor.apply();
+        }
+        mEditor.putInt(KEY_PREV_POPUP_STATUS, currentStatus);
+        mEditor.apply();
+    }
+
+    private void updateCurrentInterval() {
+        mCurrentInterval = mContext.getResources().getInteger(
+                R.integer.data_subscription_pop_up_frequency);
+        String prevDate = mSharedPreferences.getString(KEY_PREV_POPUP_DATE, /* defValue=*/ "");
+        if (!TextUtils.isEmpty(prevDate)) {
+            mCurrentInterval = (int) ChronoUnit.DAYS.between(LocalDate.parse(prevDate),
+                    LocalDate.now(ZoneId.systemDefault()));
+        }
+    }
+
+    private void updateCurrentCycle() {
+        mCurrentCycle = mSharedPreferences.getInt(
+                KEY_PREV_POPUP_CYCLE, /* defValue=*/ 0);
+    }
+
+    private void updateCurrentActiveDays() {
+        mCurrentActiveDays = mSharedPreferences.getInt(
+                KEY_PREV_POPUP_ACTIVE_DAYS, /* defValue=*/ 0);
+    }
+
+    private void writeLatestPopupDate() {
+        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
+        LocalDate newDate = LocalDate.now(ZoneId.systemDefault());
+        String formattedNewDate = newDate.format(formatter);
+        mEditor.putString(KEY_PREV_POPUP_DATE, formattedNewDate);
+        mEditor.apply();
+    }
+
+    private void writeLatestPopupCycle() {
+        mEditor.putInt(KEY_PREV_POPUP_CYCLE, mSharedPreferences.getInt(
+                KEY_PREV_POPUP_CYCLE, /* defValue=*/ 1) + 1);
+        mEditor.apply();
+    }
+
+    private void writeLatestPopupActiveDays() {
+        mEditor.putInt(KEY_PREV_POPUP_ACTIVE_DAYS, mSharedPreferences.getInt(
+                KEY_PREV_POPUP_ACTIVE_DAYS, /* defValue=*/ 1) + 1);
+        mEditor.apply();
+    }
+
     @VisibleForTesting
     void setPopupWindow(PopupWindow popupWindow) {
         mPopupWindow = popupWindow;
@@ -490,6 +603,26 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
         mIsUxRestrictionsListenerRegistered = value;
     }
 
+    @VisibleForTesting
+    void setSharedPreference(SharedPreferences sharedPreference) {
+        mSharedPreferences = sharedPreference;
+    }
+
+    @VisibleForTesting
+    void setCurrentInterval(int currentInterval) {
+        mCurrentInterval = currentInterval;
+    }
+
+    @VisibleForTesting
+    void setCurrentCycle(int cycle) {
+        mCurrentCycle = cycle;
+    }
+
+    @VisibleForTesting
+    void setCurrentActiveDays(int activeDays) {
+        mCurrentActiveDays = activeDays;
+    }
+
     @VisibleForTesting
     void setWasProactiveMsgDisplayed(boolean value) {
         mWasProactiveMsgDisplayed = value;
diff --git a/src/com/android/systemui/car/qc/ProfileSwitcher.java b/src/com/android/systemui/car/qc/ProfileSwitcher.java
index c1920424..b45f377a 100644
--- a/src/com/android/systemui/car/qc/ProfileSwitcher.java
+++ b/src/com/android/systemui/car/qc/ProfileSwitcher.java
@@ -52,15 +52,12 @@ import android.widget.Toast;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.VisibleForTesting;
-import androidx.core.graphics.drawable.RoundedBitmapDrawable;
-import androidx.core.graphics.drawable.RoundedBitmapDrawableFactory;
 
 import com.android.car.internal.user.UserHelper;
 import com.android.car.qc.QCItem;
 import com.android.car.qc.QCList;
 import com.android.car.qc.QCRow;
 import com.android.car.qc.provider.BaseLocalQCProvider;
-import com.android.internal.util.UserIcons;
 import com.android.settingslib.utils.StringUtil;
 import com.android.systemui.R;
 import com.android.systemui.car.CarServiceProvider;
@@ -107,12 +104,13 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
 
     @Inject
     public ProfileSwitcher(Context context, UserTracker userTracker,
-            CarServiceProvider carServiceProvider, @Background Handler handler) {
+            CarServiceProvider carServiceProvider, @Background Handler handler,
+            UserIconProvider userIconProvider) {
         super(context);
         mUserTracker = userTracker;
         mUserManager = context.getSystemService(UserManager.class);
         mDevicePolicyManager = context.getSystemService(DevicePolicyManager.class);
-        mUserIconProvider = new UserIconProvider();
+        mUserIconProvider = userIconProvider;
         mHandler = handler;
         mCarServiceProvider = carServiceProvider;
         mCarServiceProvider.addListener(mCarServiceOnConnectedListener);
@@ -223,7 +221,7 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
         boolean isCurrentProfile = userInfo.id == mUserTracker.getUserId();
 
         return createProfileRow(userInfo.name,
-                mUserIconProvider.getDrawableWithBadge(mContext, userInfo), actionHandler,
+                mUserIconProvider.getDrawableWithBadge(userInfo.id), actionHandler,
                 isCurrentProfile);
     }
 
@@ -241,7 +239,7 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
                 && mUserTracker.getUserInfo().isGuest();
 
         return createProfileRow(mContext.getString(com.android.internal.R.string.guest_name),
-                mUserIconProvider.getRoundedGuestDefaultIcon(mContext),
+                mUserIconProvider.getRoundedGuestDefaultIcon(),
                 actionHandler, isCurrentProfile);
     }
 
@@ -258,7 +256,7 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
         };
 
         return createProfileRow(mContext.getString(R.string.car_add_user),
-                mUserIconProvider.getDrawableWithBadge(mContext, getCircularAddUserIcon()),
+                mUserIconProvider.getDrawableWithBadge(mUserIconProvider.getRoundedAddUserIcon()),
                 actionHandler);
     }
 
@@ -430,14 +428,6 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
         return mUserManager.getUserInfo(userCreationResult.getUser().getIdentifier());
     }
 
-    private RoundedBitmapDrawable getCircularAddUserIcon() {
-        RoundedBitmapDrawable circleIcon = RoundedBitmapDrawableFactory.create(
-                mContext.getResources(),
-                UserIcons.convertToBitmap(mContext.getDrawable(R.drawable.car_add_circle_round)));
-        circleIcon.setCircular(true);
-        return circleIcon;
-    }
-
     private boolean hasAddUserRestriction(UserHandle userHandle) {
         return mUserManager.hasUserRestrictionForUser(UserManager.DISALLOW_ADD_USER, userHandle);
     }
diff --git a/src/com/android/systemui/car/statusicon/ui/BluetoothStatusIconController.java b/src/com/android/systemui/car/statusicon/ui/BluetoothStatusIconController.java
index 3bd9bada..9e924247 100644
--- a/src/com/android/systemui/car/statusicon/ui/BluetoothStatusIconController.java
+++ b/src/com/android/systemui/car/statusicon/ui/BluetoothStatusIconController.java
@@ -60,11 +60,14 @@ public class BluetoothStatusIconController extends StatusIconViewController impl
         mBluetoothController = bluetoothController;
 
         mBluetoothOffDrawable = resources.getDrawable(
-                R.drawable.ic_bluetooth_status_off, /* theme= */ null);
+                R.drawable.ic_bluetooth_status_off,
+                /* theme= */ view.getContext().getTheme());
         mBluetoothOnDisconnectedDrawable = resources.getDrawable(
-                R.drawable.ic_bluetooth_status_on_disconnected, /* theme= */ null);
+                R.drawable.ic_bluetooth_status_on_disconnected,
+                /* theme= */ view.getContext().getTheme());
         mBluetoothOnConnectedDrawable = resources.getDrawable(
-                R.drawable.ic_bluetooth_status_on_connected, /* theme= */ null);
+                R.drawable.ic_bluetooth_status_on_connected,
+                /* theme= */ view.getContext().getTheme());
 
         mBluetoothOffContentDescription = resources.getString(
                 R.string.status_icon_bluetooth_off);
diff --git a/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconController.java b/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconController.java
index 5b8e40d3..c993c02f 100644
--- a/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconController.java
+++ b/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconController.java
@@ -89,10 +89,12 @@ public class MediaVolumeStatusIconController extends StatusIconViewController {
 
                     mCarAudioManager = (CarAudioManager) car.getCarManager(Car.AUDIO_SERVICE);
 
-                    mCarAudioManager.registerCarVolumeCallback(mVolumeChangeCallback);
-                    mGroupId = mCarAudioManager.getVolumeGroupIdForUsage(mZoneId, USAGE_MEDIA);
-                    mMaxMediaVolume = mCarAudioManager.getGroupMaxVolume(mZoneId, mGroupId);
-                    mMinMediaVolume = mCarAudioManager.getGroupMinVolume(mZoneId, mGroupId);
+                    if (mCarAudioManager != null) {
+                        mCarAudioManager.registerCarVolumeCallback(mVolumeChangeCallback);
+                        mGroupId = mCarAudioManager.getVolumeGroupIdForUsage(mZoneId, USAGE_MEDIA);
+                        mMaxMediaVolume = mCarAudioManager.getGroupMaxVolume(mZoneId, mGroupId);
+                        mMinMediaVolume = mCarAudioManager.getGroupMinVolume(mZoneId, mGroupId);
+                    }
                     updateStatus(mZoneId, mGroupId);
                 }
             };
@@ -130,7 +132,9 @@ public class MediaVolumeStatusIconController extends StatusIconViewController {
         super.onViewDetached();
         mCarServiceProvider.removeListener(mCarOnConnectedListener);
         mUserTracker.removeCallback(mUserTrackerCallback);
-        mCarAudioManager.unregisterCarVolumeCallback(mVolumeChangeCallback);
+        if (mCarAudioManager != null) {
+            mCarAudioManager.unregisterCarVolumeCallback(mVolumeChangeCallback);
+        }
     }
 
     @Override
diff --git a/src/com/android/systemui/car/systembar/AppGridButton.java b/src/com/android/systemui/car/systembar/AppGridButton.java
index 8df16784..22e425d1 100644
--- a/src/com/android/systemui/car/systembar/AppGridButton.java
+++ b/src/com/android/systemui/car/systembar/AppGridButton.java
@@ -17,7 +17,6 @@
 package com.android.systemui.car.systembar;
 
 import android.content.Context;
-import android.content.Intent;
 import android.content.res.TypedArray;
 import android.util.AttributeSet;
 
@@ -44,9 +43,8 @@ public class AppGridButton extends CarSystemBarButton {
     }
 
     @Override
-    protected OnClickListener getButtonClickListener(Intent toSend) {
-        return mRecentsButtonStateProvider.getButtonClickListener(toSend,
-                super::getButtonClickListener);
+    protected OnClickListener getButtonClickListener() {
+        return mRecentsButtonStateProvider.getButtonClickListener(super.getButtonClickListener());
     }
 
     @Override
diff --git a/src/com/android/systemui/car/systembar/ButtonSelectionStateController.java b/src/com/android/systemui/car/systembar/ButtonSelectionStateController.java
index 6efd347e..299f57f7 100644
--- a/src/com/android/systemui/car/systembar/ButtonSelectionStateController.java
+++ b/src/com/android/systemui/car/systembar/ButtonSelectionStateController.java
@@ -21,6 +21,11 @@ import static android.app.WindowConfiguration.WINDOWING_MODE_FULLSCREEN;
 import static android.app.WindowConfiguration.WINDOWING_MODE_MULTI_WINDOW;
 import static android.window.DisplayAreaOrganizer.FEATURE_DEFAULT_TASK_CONTAINER;
 
+import static com.android.systemui.car.Flags.scalableUi;
+import static com.android.wm.shell.Flags.enableAutoTaskStackController;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 import android.app.ActivityTaskManager;
 import android.app.ActivityTaskManager.RootTaskInfo;
 import android.content.ComponentName;
@@ -28,16 +33,23 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
+import android.os.Build;
 import android.os.RemoteException;
+import android.text.TextUtils;
 import android.util.Log;
 import android.view.View;
 import android.view.ViewGroup;
 
+import com.android.car.scalableui.manager.StateManager;
+import com.android.car.scalableui.model.PanelState;
+import com.android.systemui.R;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
 import com.android.systemui.dagger.SysUISingleton;
 
 import java.util.HashMap;
 import java.util.HashSet;
 import java.util.List;
+import java.util.Map;
 import java.util.Set;
 
 /**
@@ -51,18 +63,58 @@ import java.util.Set;
 @SysUISingleton
 public class ButtonSelectionStateController {
     private static final String TAG = ButtonSelectionStateController.class.getSimpleName();
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
 
     private final Set<CarSystemBarButton> mRegisteredViews = new HashSet<>();
 
     protected final Context mContext;
+    protected final TaskPanelInfoRepository mTaskPanelInfoRepository;
     protected ButtonMap mButtonsByCategory = new ButtonMap();
     protected ButtonMap mButtonsByPackage = new ButtonMap();
     protected ButtonMap mButtonsByComponentName = new ButtonMap();
     protected HashSet<CarSystemBarButton> mSelectedButtons;
+    protected HashSet<CarSystemBarButton> mSelectedButtonsForPanelApp;
+    protected HashSet<CarSystemBarButton> mSelectedButtonsForPanelVisibility;
+
+    private final TaskPanelInfoRepository.TaskPanelChangeListener mTaskPanelListener =
+            this::panelTaskChanged;
+
+    private final StateManager.PanelStateObserver mPanelStateObserver =
+            new StateManager.PanelStateObserver() {
+                @Override
+                public void onBeforePanelStateChanged(Set<String> changedPanelIds,
+                        Map<String, PanelState> panelStates) {
+                    if (DEBUG) {
+                        Log.d(TAG, "onBeforePanelStateChanged: changedPanelIds="
+                                + changedPanelIds + " panelStates=" + panelStates);
+                    }
+                    panelVisibilityChanged(panelStates);
+                    // also trigger task change since it depends on panel visibility
+                    panelTaskChanged();
+                }
+
+                @Override
+                public void onPanelStateChanged(Set<String> changedPanelIds,
+                        Map<String, PanelState> panelStates) {
+                    // handled opportunistically in before method
+                }
+            };
 
     public ButtonSelectionStateController(Context context) {
+        this(context, null);
+    }
+
+    public ButtonSelectionStateController(Context context,
+            TaskPanelInfoRepository taskPanelInfoRepository) {
         mContext = context;
+        mTaskPanelInfoRepository = taskPanelInfoRepository;
         mSelectedButtons = new HashSet<>();
+        mSelectedButtonsForPanelApp = new HashSet<>();
+        mSelectedButtonsForPanelVisibility = new HashSet<>();
+        if (isScalableUIEnabled() && mTaskPanelInfoRepository != null) {
+            mTaskPanelInfoRepository.addChangeListener(mTaskPanelListener);
+            StateManager.getInstance().addPanelStateObserver(mPanelStateObserver);
+        }
     }
 
     /**
@@ -84,13 +136,13 @@ public class ButtonSelectionStateController {
         }
     }
 
-    /** Removes all buttons from the button maps. */
-    protected void removeAll() {
-        mButtonsByCategory.clear();
-        mButtonsByPackage.clear();
-        mButtonsByComponentName.clear();
-        mSelectedButtons.clear();
-        mRegisteredViews.clear();
+    /** Removes a button from the button maps. */
+    protected void removeButton(CarSystemBarButton button) {
+        mButtonsByCategory.values().forEach(set -> set.remove(button));
+        mButtonsByPackage.values().forEach(set -> set.remove(button));
+        mButtonsByComponentName.values().forEach(set -> set.remove(button));
+        mSelectedButtons.remove(button);
+        mRegisteredViews.remove(button);
     }
 
     /**
@@ -105,8 +157,10 @@ public class ButtonSelectionStateController {
      * @param taskInfoList of the currently running application
      * @param validDisplay index of the valid display
      */
-
     protected void taskChanged(List<RootTaskInfo> taskInfoList, int validDisplay) {
+        if (isScalableUIEnabled()) {
+            return;
+        }
         RootTaskInfo validTaskInfo = null;
 
         for (RootTaskInfo taskInfo : taskInfoList) {
@@ -140,6 +194,143 @@ public class ButtonSelectionStateController {
         }
     }
 
+    /**
+     * This will unselect the currently selected CarSystemBarButtons and determine which one should
+     * be selected next. It does this by reading the properties on the CarSystemBarButton and
+     * seeing if they are a match based on panel visibility and task visibility on panels.
+     */
+    protected void panelTaskChanged() {
+        mSelectedButtonsForPanelApp.clear();
+        mButtonsByComponentName.keySet().forEach(componentName -> {
+            mButtonsByComponentName.get(componentName).forEach(button -> {
+                if (mTaskPanelInfoRepository.isComponentVisibleOnDisplay(
+                        ComponentName.unflattenFromString(componentName), button.getDisplayId())) {
+                    mSelectedButtonsForPanelApp.add(button);
+                }
+            });
+        });
+
+        mButtonsByPackage.keySet().forEach(packageName -> {
+            mButtonsByPackage.get(packageName).forEach(button -> {
+                if (mTaskPanelInfoRepository.isPackageVisibleOnDisplay(packageName,
+                        button.getDisplayId())) {
+                    mSelectedButtonsForPanelApp.add(button);
+                }
+            });
+        });
+
+        // TODO(b/409398038): handle categories for ScalableUI
+
+        updatePanelButtonsSelection();
+    }
+
+    /**
+     * Determine which CarSystemBarButtons should be selected based on the current panel state
+     */
+    protected void panelVisibilityChanged(Map<String, PanelState> panelStates) {
+        mSelectedButtonsForPanelVisibility.clear();
+        for (CarSystemBarButton button : mRegisteredViews) {
+            if (button.getPanelNames().length > 0) {
+                if (shouldSelectButtonForPanelStates(button, panelStates)) {
+                    mSelectedButtonsForPanelVisibility.add(button);
+                }
+            }
+        }
+        updatePanelButtonsSelection();
+    }
+
+    /**
+     * When adding a button to this controller, check the current panel and task state to determine
+     * if the button should be initially selected.
+     */
+    protected void selectForInitialPanelTaskState(CarSystemBarButton button) {
+        if (button.getPanelNames().length > 0) {
+            if (shouldSelectButtonForPanelStates(button, /* panelStates= */ null)) {
+                mSelectedButtonsForPanelVisibility.add(button);
+            } else {
+                mSelectedButtonsForPanelVisibility.remove(button);
+            }
+        }
+
+        boolean shouldSelectForApp = false;
+        String[] packages = button.getPackages();
+        for (int i = 0; i < packages.length; i++) {
+            if (mTaskPanelInfoRepository.isPackageVisibleOnDisplay(
+                    packages[i], button.getDisplayId())) {
+                shouldSelectForApp = true;
+                break;
+            }
+        }
+        String[] componentNames = button.getComponentName();
+        for (int i = 0; i < componentNames.length; i++) {
+            if (mTaskPanelInfoRepository.isComponentVisibleOnDisplay(
+                    ComponentName.unflattenFromString(componentNames[i]),
+                    button.getDisplayId())) {
+                shouldSelectForApp = true;
+                break;
+            }
+        }
+        // TODO(b/409398038): handle categories for ScalableUI
+        if (shouldSelectForApp) {
+            mSelectedButtonsForPanelApp.add(button);
+        } else {
+            mSelectedButtonsForPanelApp.remove(button);
+        }
+
+        updatePanelButtonsSelection();
+    }
+
+    private boolean shouldSelectButtonForPanelStates(@NonNull CarSystemBarButton button,
+            @Nullable Map<String, PanelState> panelStates) {
+        if (button.getPanelNames().length == 0) {
+            return false;
+        }
+        for (String panelString : button.getPanelNames()) {
+            if (TextUtils.isEmpty(panelString)) {
+                // not valid - don't select
+                return false;
+            }
+            boolean invertVisibility = panelString.charAt(0) == '-';
+            if (invertVisibility) {
+                panelString = panelString.substring(1);
+            }
+            PanelState state;
+            if (panelStates != null) {
+                state = panelStates.get(panelString);
+            } else {
+                state = StateManager.getPanelState(panelString);
+            }
+            if (!isPanelVisible(state, button.getDisplayId()) ^ invertVisibility) {
+                return false;
+            }
+        }
+        return true;
+    }
+
+    private boolean isPanelVisible(PanelState state, int displayId) {
+        if (state == null) {
+            return false;
+        }
+        return state.getDisplayId() == displayId
+                && state.getCurrentVariant() != null
+                && state.getCurrentVariant().isVisible();
+    }
+
+    protected void updatePanelButtonsSelection() {
+        mContext.getMainExecutor().execute(() -> {
+            mRegisteredViews.forEach(button -> {
+                if (mSelectedButtonsForPanelVisibility.contains(button)
+                        || mSelectedButtonsForPanelApp.contains(button)) {
+                    button.setSelected(true);
+                    mSelectedButtons.add(button);
+                } else {
+                    button.setSelected(false);
+                    mSelectedButtons.remove(button);
+                }
+            });
+        });
+    }
+
     protected void clearAllSelectedButtons(int displayId) {
         mRegisteredViews.forEach(carSystemBarButton -> {
             if (carSystemBarButton.getDisplayId() == displayId) {
@@ -180,6 +371,10 @@ public class ButtonSelectionStateController {
         }
 
         mRegisteredViews.add(carSystemBarButton);
+
+        if (isScalableUIEnabled() && mTaskPanelInfoRepository != null) {
+            selectForInitialPanelTaskState(carSystemBarButton);
+        }
     }
 
     private HashSet<CarSystemBarButton> findSelectedButtons(RootTaskInfo validTaskInfo) {
@@ -214,7 +409,7 @@ public class ButtonSelectionStateController {
                         ActivityTaskManager.getService().getRootTaskInfoOnDisplay(
                                 WINDOWING_MODE_FULLSCREEN, ACTIVITY_TYPE_UNDEFINED,
                                 validTaskInfo.displayId);
-                return rootTaskInfo.topActivity;
+                return rootTaskInfo == null ? null : rootTaskInfo.topActivity;
             } catch (RemoteException e) {
                 Log.e(TAG, "findSelectedButtons: Failed getting root task info", e);
             }
@@ -252,6 +447,11 @@ public class ButtonSelectionStateController {
         return null;
     }
 
+    private boolean isScalableUIEnabled() {
+        return scalableUi() && enableAutoTaskStackController()
+                && mContext.getResources().getBoolean(R.bool.config_enableScalableUI);
+    }
+
     // simple multi-map
     private static class ButtonMap extends HashMap<String, HashSet<CarSystemBarButton>> {
 
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarButton.java b/src/com/android/systemui/car/systembar/CarSystemBarButton.java
index e11718c3..3051ea50 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarButton.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarButton.java
@@ -48,6 +48,7 @@ import com.android.systemui.car.systembar.element.CarSystemBarElement;
 import com.android.systemui.car.systembar.element.CarSystemBarElementFlags;
 import com.android.systemui.car.systembar.element.CarSystemBarElementResolver;
 import com.android.systemui.car.window.OverlayViewController;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.AlphaOptimizedImageView;
 
@@ -79,12 +80,21 @@ public class CarSystemBarButton extends LinearLayout implements
     private final boolean mDisableForLockTaskModeLocked;
     @Nullable
     private UserTracker mUserTracker;
+    @Nullable
+    private EventDispatcher mEventDispatcher;
     private ViewGroup mIconContainer;
     private AlphaOptimizedImageView mIcon;
     private AlphaOptimizedImageView mMoreIcon;
     private ImageView mUnseenIcon;
-    private String mIntent;
+    /** The intent to be used while the button is selected. */
+    private Intent mSelectedIntent;
+    /** The intent to be used while the button is unselected. */
+    private Intent mUnselectedIntent;
     private String mLongIntent;
+    /** The event to be used while the button is selected. */
+    private String mSelectedEvent;
+    /** The event to be used while the button is unselected. */
+    private String mUnselectedEvent;
     private boolean mBroadcastIntent;
     /** Whether to clear the backstack (i.e. put the home activity directly behind) when pressed */
     private boolean mClearBackStack;
@@ -98,6 +108,7 @@ public class CarSystemBarButton extends LinearLayout implements
     private Drawable mAppIcon;
     private boolean mIsDefaultAppIconForRoleEnabled;
     private boolean mToggleSelectedState;
+    private String[] mPanelNames;
     private String[] mComponentNames;
     /** App categories that are to be used with this widget */
     private String[] mButtonCategories;
@@ -134,6 +145,7 @@ public class CarSystemBarButton extends LinearLayout implements
                 CarSystemBarElementFlags.getDisableForLockTaskModeLockedFromAttributes(context,
                         attrs);
 
+        setUpCategories(typedArray);
         setUpIntents(typedArray);
         setUpIcons(typedArray);
         typedArray.recycle();
@@ -241,6 +253,16 @@ public class CarSystemBarButton extends LinearLayout implements
         return mButtonPackages;
     }
 
+    /**
+     * @return The list of panel names that should be used for selection
+     */
+    public String[] getPanelNames() {
+        if (mPanelNames == null) {
+            return new String[0];
+        }
+        return mPanelNames;
+    }
+
     /**
      * @return The list of component names.
      */
@@ -305,38 +327,98 @@ public class CarSystemBarButton extends LinearLayout implements
     @VisibleForTesting
     protected float getIconAlpha() { return mIcon.getAlpha(); }
 
+    protected Intent getIntent() {
+        if (mSelected) {
+            return mSelectedIntent;
+        } else {
+            return mUnselectedIntent;
+        }
+    }
+
+    protected String getEvent() {
+        if (mSelected) {
+            return mSelectedEvent;
+        } else {
+            return mUnselectedEvent;
+        }
+    }
+
+    /**
+     * Sets up package, category and component names for the buttons.
+     * These properties can be used to control the selected state of buttons as a group.
+     */
+    protected void setUpCategories(TypedArray typedArray) {
+        String categoryString = typedArray.getString(R.styleable.CarSystemBarButton_categories);
+        String packageString = typedArray.getString(R.styleable.CarSystemBarButton_packages);
+        String componentNameString =
+                typedArray.getString(R.styleable.CarSystemBarButton_componentNames);
+        String panelNamesString =
+                typedArray.getString(R.styleable.CarSystemBarButton_panelNames);
+        if (packageString != null) {
+            mButtonPackages = packageString.split(BUTTON_FILTER_DELIMITER);
+        }
+        if (categoryString != null) {
+            mButtonCategories = categoryString.split(BUTTON_FILTER_DELIMITER);
+        }
+        if (componentNameString != null) {
+            mComponentNames = componentNameString.split(BUTTON_FILTER_DELIMITER);
+        }
+        if (panelNamesString != null) {
+            mPanelNames = panelNamesString.split(BUTTON_FILTER_DELIMITER);
+        }
+    }
+
     /**
      * Sets up intents for click, long touch, and broadcast.
      */
     protected void setUpIntents(TypedArray typedArray) {
-        mIntent = typedArray.getString(R.styleable.CarSystemBarButton_intent);
+        String intentString = typedArray.getString(R.styleable.CarSystemBarButton_intent);
+        String selectedIntentString =
+                typedArray.getString(R.styleable.CarSystemBarButton_selectedIntent);
+        selectedIntentString = selectedIntentString != null ? selectedIntentString : intentString;
+        String unselectedIntentString =
+                typedArray.getString(R.styleable.CarSystemBarButton_unselectedIntent);
+        unselectedIntentString =
+                unselectedIntentString != null ? unselectedIntentString : intentString;
         mLongIntent = typedArray.getString(R.styleable.CarSystemBarButton_longIntent);
         mBroadcastIntent = typedArray.getBoolean(R.styleable.CarSystemBarButton_broadcast, false);
 
+        String eventString = typedArray.getString(R.styleable.CarSystemBarButton_event);
+        String selectedEventString =
+                typedArray.getString(R.styleable.CarSystemBarButton_selectedEvent);
+        mSelectedEvent = selectedEventString != null ? selectedEventString : eventString;
+        String unselectedEventString =
+                typedArray.getString(R.styleable.CarSystemBarButton_unselectedEvent);
+        mUnselectedEvent =
+                unselectedEventString != null ? unselectedEventString : eventString;
+
         mClearBackStack = typedArray.getBoolean(R.styleable.CarSystemBarButton_clearBackStack,
                 false);
 
-        String categoryString = typedArray.getString(R.styleable.CarSystemBarButton_categories);
-        String packageString = typedArray.getString(R.styleable.CarSystemBarButton_packages);
-        String componentNameString =
-                typedArray.getString(R.styleable.CarSystemBarButton_componentNames);
-
         try {
-            if (mIntent != null) {
-                final Intent intent = Intent.parseUri(mIntent, Intent.URI_INTENT_SCHEME);
-                setOnClickListener(getButtonClickListener(intent));
-                if (packageString != null) {
-                    mButtonPackages = packageString.split(BUTTON_FILTER_DELIMITER);
-                    intent.putExtra(EXTRA_BUTTON_PACKAGES, mButtonPackages);
+            if (selectedIntentString != null) {
+                mSelectedIntent = Intent.parseUri(selectedIntentString, Intent.URI_INTENT_SCHEME);
+                if (mButtonPackages != null) {
+                    mSelectedIntent.putExtra(EXTRA_BUTTON_PACKAGES, mButtonPackages);
                 }
-                if (categoryString != null) {
-                    mButtonCategories = categoryString.split(BUTTON_FILTER_DELIMITER);
-                    intent.putExtra(EXTRA_BUTTON_CATEGORIES, mButtonCategories);
+                if (mButtonCategories != null) {
+                    mSelectedIntent.putExtra(EXTRA_BUTTON_CATEGORIES, mButtonCategories);
+                }
+            }
+
+            if (unselectedIntentString != null) {
+                mUnselectedIntent =
+                        Intent.parseUri(unselectedIntentString, Intent.URI_INTENT_SCHEME);
+                if (mButtonPackages != null) {
+                    mUnselectedIntent.putExtra(EXTRA_BUTTON_PACKAGES, mButtonPackages);
                 }
-                if (componentNameString != null) {
-                    mComponentNames = componentNameString.split(BUTTON_FILTER_DELIMITER);
+                if (mButtonCategories != null) {
+                    mUnselectedIntent.putExtra(EXTRA_BUTTON_CATEGORIES, mButtonCategories);
                 }
             }
+
+            setOnClickListener(getButtonClickListener());
+
         } catch (URISyntaxException e) {
             throw new RuntimeException("Failed to attach intent", e);
         }
@@ -353,7 +435,7 @@ public class CarSystemBarButton extends LinearLayout implements
     }
 
     /** Defines the behavior of a button click. */
-    protected OnClickListener getButtonClickListener(Intent toSend) {
+    protected OnClickListener getButtonClickListener() {
         return v -> {
             if (mDisabled) {
                 runOnClickWhileDisabled();
@@ -364,16 +446,24 @@ public class CarSystemBarButton extends LinearLayout implements
             intent.putExtra(EXTRA_DIALOG_CLOSE_REASON, DIALOG_CLOSE_REASON_CAR_SYSTEMBAR_BUTTON);
             mContext.sendBroadcastAsUser(intent, getCurrentUserHandle(mContext, mUserTracker));
 
+            if (getEvent() != null && mEventDispatcher != null) {
+                mEventDispatcher.executeTransaction(getEvent());
+            }
+
+            if (getIntent() == null) {
+                return;
+            }
+
             boolean intentLaunched = false;
             try {
                 if (mBroadcastIntent) {
-                    mContext.sendBroadcastAsUser(toSend,
+                    mContext.sendBroadcastAsUser(getIntent(),
                             getCurrentUserHandle(mContext, mUserTracker));
                     return;
                 }
                 ActivityOptions options = ActivityOptions.makeBasic();
                 options.setLaunchDisplayId(mContext.getDisplayId());
-                mContext.startActivityAsUser(toSend, options.toBundle(),
+                mContext.startActivityAsUser(getIntent(), options.toBundle(),
                         getCurrentUserHandle(mContext, mUserTracker));
                 intentLaunched = true;
             } catch (Exception e) {
@@ -424,6 +514,13 @@ public class CarSystemBarButton extends LinearLayout implements
         mUserTracker = userTracker;
     }
 
+    /**
+     * Set the EventDispatcher instance.
+     */
+    public void setEventDispatcher(EventDispatcher eventDispatcher) {
+        mEventDispatcher = eventDispatcher;
+    }
+
     /**
      * Initializes view-related aspects of the button.
      */
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarButtonController.java b/src/com/android/systemui/car/systembar/CarSystemBarButtonController.java
index fc738e16..92181046 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarButtonController.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarButtonController.java
@@ -20,6 +20,7 @@ import androidx.annotation.CallSuper;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.settings.UserTracker;
 
 import dagger.assisted.Assisted;
@@ -33,21 +34,39 @@ public class CarSystemBarButtonController
         extends CarSystemBarElementController<CarSystemBarButton> {
 
     private final UserTracker mUserTracker;
+    private final EventDispatcher mEventDispatcher;
+    private final ButtonSelectionStateController mButtonSelectionStateController;
 
     @AssistedInject
     public CarSystemBarButtonController(@Assisted CarSystemBarButton barButton,
             CarSystemBarElementStatusBarDisableController disableController,
             CarSystemBarElementStateController stateController,
-            UserTracker userTracker) {
+            UserTracker userTracker, EventDispatcher eventDispatcher,
+            ButtonSelectionStateController buttonSelectionStateController) {
         super(barButton, disableController, stateController);
 
         mUserTracker = userTracker;
+        mEventDispatcher = eventDispatcher;
+        mButtonSelectionStateController = buttonSelectionStateController;
     }
 
     @Override
     @CallSuper
     protected void onInit() {
         mView.setUserTracker(mUserTracker);
+        mView.setEventDispatcher(mEventDispatcher);
+    }
+
+    @Override
+    protected void onViewAttached() {
+        super.onViewAttached();
+        mButtonSelectionStateController.addAllButtonsWithSelectionState(mView);
+    }
+
+    @Override
+    protected void onViewDetached() {
+        super.onViewDetached();
+        mButtonSelectionStateController.removeButton(mView);
     }
 
     @AssistedFactory
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java b/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
index 7877695c..989ad899 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
@@ -39,6 +39,7 @@ import android.graphics.Rect;
 import android.inputmethodservice.InputMethodService;
 import android.os.Build;
 import android.os.Bundle;
+import android.os.Handler;
 import android.os.PatternMatcher;
 import android.os.RemoteException;
 import android.util.ArraySet;
@@ -103,6 +104,10 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
 
     private static final String OVERLAY_FILTER_DATA_SCHEME = "package";
 
+    private static final int MAX_RETRIES_FOR_WINDOW_CONTEXT_UPDATE_CHECK = 3;
+
+    private static final long RETRY_DELAY_FOR_WINDOW_CONTEXT_UPDATE_CHECK = 500;
+
     private final Context mContext;
     private final CarSystemBarViewFactory mCarSystemBarViewFactory;
     private final SystemBarConfigs mSystemBarConfigs;
@@ -157,6 +162,7 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     // it's open.
     private boolean mDeviceIsSetUpForUser = true;
     private boolean mIsUserSetupInProgress = false;
+    private int mWindowContextUpdateCheckRetryCount = 0;
 
     private AppearanceRegion[] mAppearanceRegions = new AppearanceRegion[0];
     @BarTransitions.TransitionMode
@@ -165,11 +171,42 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     private int mSystemBarMode;
     private boolean mStatusBarTransientShown;
     private boolean mNavBarTransientShown;
+    private Handler mHandler;
 
     private boolean mIsUiModeNight = false;
 
     private Locale mCurrentLocale;
 
+    private final Runnable mWindowContextUpdateCheckRunnable = new Runnable() {
+        @Override
+        public void run() {
+            if (checkSystemBarWindowContextsAreUpdated()) {
+                // cache the current state
+                Map<Integer, Bundle> cachedSystemBarCurrentState = cacheSystemBarCurrentState();
+
+                resetSystemBarContent(/* isProvisionedStateChange= */ false);
+
+                // retrieve the previous state
+                restoreSystemBarSavedState(cachedSystemBarCurrentState);
+                mWindowContextUpdateCheckRetryCount = 0;
+            } else if (mWindowContextUpdateCheckRetryCount
+                    == MAX_RETRIES_FOR_WINDOW_CONTEXT_UPDATE_CHECK) {
+                resetSystemBarContext();
+
+                // cache the current state
+                Map<Integer, Bundle> cachedSystemBarCurrentState = cacheSystemBarCurrentState();
+
+                resetSystemBarContent(/* isProvisionedStateChange= */ false);
+
+                // retrieve the previous state
+                restoreSystemBarSavedState(cachedSystemBarCurrentState);
+            } else {
+                mWindowContextUpdateCheckRetryCount++;
+                mHandler.postDelayed(this, RETRY_DELAY_FOR_WINDOW_CONTEXT_UPDATE_CHECK);
+            }
+        }
+    };
+
     public CarSystemBarControllerImpl(Context context,
             UserTracker userTracker,
             CarSystemBarViewFactory carSystemBarViewFactory,
@@ -189,7 +226,8 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
             ConfigurationController configurationController,
             CarSystemBarRestartTracker restartTracker,
             DisplayTracker displayTracker,
-            @Nullable ToolbarController toolbarController) {
+            @Nullable ToolbarController toolbarController,
+            @Main Handler handler) {
         mContext = context;
         mUserTracker = userTracker;
         mCarSystemBarViewFactory = carSystemBarViewFactory;
@@ -210,6 +248,7 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         mConfigurationController = configurationController;
         mCarSystemBarRestartTracker = restartTracker;
         mDisplayCompatToolbarController = toolbarController;
+        mHandler = handler;
     }
 
     /**
@@ -405,7 +444,25 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
             mIsUiModeNight = isConfigNightMode;
         }
 
-        // cache the current state
+        if (mWindowContextUpdateCheckRunnable != null) {
+            mHandler.removeCallbacks(mWindowContextUpdateCheckRunnable);
+            mWindowContextUpdateCheckRetryCount = 0;
+        }
+        mHandler.post(mWindowContextUpdateCheckRunnable);
+    }
+
+
+    private boolean checkSystemBarWindowContextsAreUpdated() {
+        return mSystemBarConfigs.getSystemBarSidesByZOrder().stream().allMatch(side -> {
+            Configuration windowConfig = mSystemBarConfigs.getWindowContextBySide(
+                    side).getResources().getConfiguration();
+            Locale locale = windowConfig.getLocales().get(0);
+            return windowConfig.isNightModeActive() == mIsUiModeNight && (
+                    (locale != null && locale.equals(mCurrentLocale)) || locale == mCurrentLocale);
+        });
+    }
+
+    private Map<Integer, Bundle> cacheSystemBarCurrentState() {
         Map<Integer, Bundle> savedStates = mSystemBarConfigs.getSystemBarSidesByZOrder().stream()
                 .collect(HashMap::new,
                         (map, side) -> {
@@ -415,10 +472,10 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
                             map.put(side, bundle);
                         },
                         HashMap::putAll);
+        return savedStates;
+    }
 
-        resetSystemBarContent(/* isProvisionedStateChange= */ false);
-
-        // retrieve the previous state
+    private void restoreSystemBarSavedState(Map<Integer, Bundle> savedStates) {
         mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
             getBarViewController(side, isDeviceSetupForUser())
                     .onRestoreInstanceState(savedStates.get(side));
@@ -451,7 +508,7 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
      * {@code StatusBarManager.Disable2Flags}, lock task mode. When there is a change in state,
      * and refreshes the system bars.
      *
-     * @param state {@code StatusBarManager.DisableFlags}
+     * @param state  {@code StatusBarManager.DisableFlags}
      * @param state2 {@code StatusBarManager.Disable2Flags}
      */
     @VisibleForTesting
@@ -461,7 +518,7 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         if (diff == 0 && mLockTaskMode == lockTaskMode) {
             if (DEBUG) {
                 Log.d(TAG, "setSystemBarStates(): status bar states unchanged: state: "
-                        + state + " state2: " +  state2 + " lockTaskMode: " + mLockTaskMode);
+                        + state + " state2: " + state2 + " lockTaskMode: " + mLockTaskMode);
             }
             return;
         }
@@ -609,6 +666,13 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         readConfigs();
     }
 
+    /**
+     * Invalidate SystemBar window context and recreates from application context.
+     */
+    void resetSystemBarContext() {
+        mSystemBarConfigs.resetSystemBarWindowContext();
+    }
+
     protected void updateKeyboardVisibility(boolean isKeyboardVisible) {
         mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
             if (mHideBarForKeyboardMap.get(side)) {
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarModule.java b/src/com/android/systemui/car/systembar/CarSystemBarModule.java
index 4f80be71..b91e5369 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarModule.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarModule.java
@@ -24,7 +24,6 @@ import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
 import android.annotation.Nullable;
 import android.content.Context;
 import android.os.Handler;
-import android.view.IWindowManager;
 import android.view.WindowManager;
 
 import com.android.internal.statusbar.IStatusBarService;
@@ -40,6 +39,7 @@ import com.android.systemui.car.notification.NotificationButtonController;
 import com.android.systemui.car.statusicon.StatusIconPanelViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.plugins.DarkIconDispatcher;
@@ -116,11 +116,12 @@ public abstract class CarSystemBarModule {
     @SysUISingleton
     @Provides
     static ButtonSelectionStateController provideButtonSelectionStateController(Context context,
+            TaskPanelInfoRepository infoRepository,
             @CarSysUIDynamicOverride Optional<ButtonSelectionStateController> controller) {
         if (controller.isPresent()) {
             return controller.get();
         }
-        return new ButtonSelectionStateController(context);
+        return new ButtonSelectionStateController(context, infoRepository);
     }
 
     @BindsOptionalOf
@@ -136,7 +137,6 @@ public abstract class CarSystemBarModule {
     @SysUISingleton
     @Provides
     static CarSystemBarController provideCarSystemBarController(
-            IWindowManager iWindowManager,
             @Main Handler mainHandler,
             @CarSysUIDynamicOverride Optional<CarSystemBarController> carSystemBarController,
             Context context,
@@ -175,7 +175,7 @@ public abstract class CarSystemBarModule {
                 .getBoolean(R.bool.config_enableSecondaryUserRRO);
 
         if (isSecondaryMUMDSystemUI && isSecondaryUserRROsEnabled) {
-            return new MDSystemBarsControllerImpl(iWindowManager, mainHandler, context, userTracker,
+            return new MDSystemBarsControllerImpl(mainHandler, context, userTracker,
                     carSystemBarViewFactory, systemBarConfigs, lightBarController,
                     darkIconDispatcher, windowManager, deviceProvisionedController, commandQueue,
                     autoHideController, buttonSelectionStateListener, mainExecutor, barService,
@@ -187,7 +187,7 @@ public abstract class CarSystemBarModule {
                     deviceProvisionedController, commandQueue, autoHideController,
                     buttonSelectionStateListener, mainExecutor, barService,
                     keyguardStateControllerLazy, iconPolicyLazy, configurationController,
-                    restartTracker, displayTracker, toolbarController);
+                    restartTracker, displayTracker, toolbarController, mainHandler);
         }
     }
 
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarPanelButtonView.java b/src/com/android/systemui/car/systembar/CarSystemBarPanelButtonView.java
index 6515920f..4e2522c0 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarPanelButtonView.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarPanelButtonView.java
@@ -85,7 +85,7 @@ public class CarSystemBarPanelButtonView extends LinearLayout implements CarSyst
                 CarSystemBarElementFlags.getStatusBarManagerDisableFlagsFromAttributes(context,
                         attrs);
         mSystemBarDisable2Flags =
-                CarSystemBarElementFlags.getStatusBarManagerDisableFlagsFromAttributes(context,
+                CarSystemBarElementFlags.getStatusBarManagerDisable2FlagsFromAttributes(context,
                         attrs);
         mDisableForLockTaskModeLocked =
                 CarSystemBarElementFlags.getDisableForLockTaskModeLockedFromAttributes(context,
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java b/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java
index 1a2cdb47..6cd290aa 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java
@@ -59,7 +59,6 @@ public class CarSystemBarViewControllerImpl
     private final UserTracker mUserTracker;
     private final CarSystemBarElementInitializer mCarSystemBarElementInitializer;
     private final SystemBarConfigs mSystemBarConfigs;
-    private final ButtonSelectionStateController mButtonSelectionStateController;
     private final ButtonRoleHolderController mButtonRoleHolderController;
     private final Lazy<MicPrivacyChipViewController> mMicPrivacyChipViewControllerLazy;
     private final Lazy<CameraPrivacyChipViewController> mCameraPrivacyChipViewControllerLazy;
@@ -80,7 +79,6 @@ public class CarSystemBarViewControllerImpl
             CarSystemBarElementInitializer elementInitializer,
             SystemBarConfigs systemBarConfigs,
             ButtonRoleHolderController buttonRoleHolderController,
-            ButtonSelectionStateController buttonSelectionStateController,
             Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
             Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
             OverlayVisibilityMediator overlayVisibilityMediator,
@@ -93,7 +91,6 @@ public class CarSystemBarViewControllerImpl
         mCarSystemBarElementInitializer = elementInitializer;
         mSystemBarConfigs = systemBarConfigs;
         mButtonRoleHolderController = buttonRoleHolderController;
-        mButtonSelectionStateController = buttonSelectionStateController;
         mCameraPrivacyChipViewControllerLazy = cameraPrivacyChipViewControllerLazy;
         mMicPrivacyChipViewControllerLazy = micPrivacyChipViewControllerLazy;
         mSide = side;
@@ -209,7 +206,6 @@ public class CarSystemBarViewControllerImpl
     protected void onViewAttached() {
         mSystemBarConfigs.insetSystemBar(mSide, mView);
 
-        mButtonSelectionStateController.addAllButtonsWithSelectionState(mView);
         mButtonRoleHolderController.addAllButtonsWithRoleName(mView);
         mMicPrivacyChipViewControllerLazy.get().addPrivacyChipView(mView);
         mCameraPrivacyChipViewControllerLazy.get().addPrivacyChipView(mView);
@@ -217,7 +213,6 @@ public class CarSystemBarViewControllerImpl
 
     @Override
     protected void onViewDetached() {
-        mButtonSelectionStateController.removeAll();
         mButtonRoleHolderController.removeAll();
         mMicPrivacyChipViewControllerLazy.get().removeAll();
         mCameraPrivacyChipViewControllerLazy.get().removeAll();
diff --git a/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java b/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java
index 4f2381b2..1b3ffb03 100644
--- a/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java
+++ b/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java
@@ -59,7 +59,6 @@ public class CarTopSystemBarViewController extends CarSystemBarViewControllerImp
             CarSystemBarElementInitializer elementInitializer,
             SystemBarConfigs systemBarConfigs,
             ButtonRoleHolderController buttonRoleHolderController,
-            ButtonSelectionStateController buttonSelectionStateController,
             Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
             Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
             CarDeviceProvisionedController deviceProvisionedController,
@@ -71,7 +70,6 @@ public class CarTopSystemBarViewController extends CarSystemBarViewControllerImp
                 elementInitializer,
                 systemBarConfigs,
                 buttonRoleHolderController,
-                buttonSelectionStateController,
                 cameraPrivacyChipViewControllerLazy,
                 micPrivacyChipViewControllerLazy,
                 overlayVisibilityMediator,
diff --git a/src/com/android/systemui/car/systembar/ControlCenterButtonController.java b/src/com/android/systemui/car/systembar/ControlCenterButtonController.java
index 1f07f445..48eafb71 100644
--- a/src/com/android/systemui/car/systembar/ControlCenterButtonController.java
+++ b/src/com/android/systemui/car/systembar/ControlCenterButtonController.java
@@ -21,6 +21,7 @@ import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.settings.UserTracker;
 
 import dagger.assisted.Assisted;
@@ -36,8 +37,10 @@ public class ControlCenterButtonController extends CarSystemBarButtonController
     public ControlCenterButtonController(@Assisted CarSystemBarButton ccButton,
             CarSystemBarElementStatusBarDisableController disableController,
             CarSystemBarElementStateController stateController,
-            UserTracker userTracker) {
-        super(ccButton, disableController, stateController, userTracker);
+            UserTracker userTracker, EventDispatcher eventDispatcher,
+            ButtonSelectionStateController buttonSelectionStateController) {
+        super(ccButton, disableController, stateController, userTracker, eventDispatcher,
+                buttonSelectionStateController);
 
         ccButton.setVisibility(
                 CarSystemUIUserUtil.isMUMDSystemUI() ? View.VISIBLE : View.GONE);
diff --git a/src/com/android/systemui/car/systembar/DockViewControllerWrapper.java b/src/com/android/systemui/car/systembar/DockViewControllerWrapper.java
index 224167ff..20323f0e 100644
--- a/src/com/android/systemui/car/systembar/DockViewControllerWrapper.java
+++ b/src/com/android/systemui/car/systembar/DockViewControllerWrapper.java
@@ -34,7 +34,6 @@ import androidx.annotation.NonNull;
 import com.android.car.docklib.DockViewController;
 import com.android.car.docklib.data.DockProtoDataController;
 import com.android.car.docklib.view.DockView;
-import com.android.car.dockutil.Flags;
 import com.android.systemui.R;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
@@ -78,7 +77,6 @@ public class DockViewControllerWrapper extends
                     switch (event.getEventType()) {
                         case USER_LIFECYCLE_EVENT_TYPE_UNLOCKED -> {
                             if (event.getUserId() == mUserTracker.getUserId()) {
-                                mActiveUnlockedUserId = event.getUserId();
                                 setupDock();
                             }
                         }
@@ -147,14 +145,21 @@ public class DockViewControllerWrapper extends
     }
 
     private void setupDock() {
-        if (!Flags.dockFeature()) {
-            return;
-        }
         if (mDockViewController != null) {
+            if (mDockViewController.getUserContext().getUserId() == mUserTracker.getUserId()) {
+                if (DEBUG) {
+                    Log.d(TAG, "Dock already initialized for user: " + mUserTracker.getUserId());
+                }
+                return;
+            }
             if (DEBUG) {
-                Log.d(TAG, "Dock already initialized");
+                // This is unexpected. We should not have a leaked instance of
+                // DockViewController for a different user. This indicates a potential
+                // issue with how we're managing the DockViewController lifecycle.
+                Log.w(TAG, "DockViewController: Leaked instance detected for user "
+                        + mDockViewController.getUserContext().getUserId() + ". Destroying now.");
             }
-            return;
+            mDockViewController.destroy();
         }
         int currentDisplayId = mView.getDisplay() != null ? mView.getDisplay().getDisplayId()
                 : INVALID_DISPLAY;
@@ -184,6 +189,7 @@ public class DockViewControllerWrapper extends
                         mUserTracker.getUserId()
                 )
         );
+        mActiveUnlockedUserId = mUserTracker.getUserId();
     }
 
     private void destroyDock() {
diff --git a/src/com/android/systemui/car/systembar/HomeButtonController.java b/src/com/android/systemui/car/systembar/HomeButtonController.java
index a74ff8ef..8e3f5fe8 100644
--- a/src/com/android/systemui/car/systembar/HomeButtonController.java
+++ b/src/com/android/systemui/car/systembar/HomeButtonController.java
@@ -21,6 +21,7 @@ import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.settings.UserTracker;
 
 import dagger.assisted.Assisted;
@@ -36,8 +37,10 @@ public class HomeButtonController extends CarSystemBarButtonController  {
     public HomeButtonController(@Assisted CarSystemBarButton homeButton,
             CarSystemBarElementStatusBarDisableController disableController,
             CarSystemBarElementStateController stateController,
-            UserTracker userTracker) {
-        super(homeButton, disableController, stateController, userTracker);
+            UserTracker userTracker, EventDispatcher eventDispatcher,
+            ButtonSelectionStateController buttonSelectionStateController) {
+        super(homeButton, disableController, stateController, userTracker, eventDispatcher,
+                buttonSelectionStateController);
 
         homeButton.setVisibility(
                 CarSystemUIUserUtil.isSecondaryMUMDSystemUI() ? View.GONE : View.VISIBLE);
diff --git a/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java b/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
index e49eb143..4c3453d3 100644
--- a/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
+++ b/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
@@ -16,29 +16,15 @@
 
 package com.android.systemui.car.systembar;
 
-import android.annotation.NonNull;
 import android.annotation.Nullable;
-import android.content.ComponentName;
 import android.content.Context;
 import android.content.om.OverlayManager;
 import android.content.res.Configuration;
 import android.os.Build;
 import android.os.Handler;
-import android.os.RemoteException;
 import android.os.UserHandle;
 import android.util.Log;
-import android.view.Display;
-import android.view.IDisplayWindowInsetsController;
-import android.view.IWindowManager;
-import android.view.InsetsSource;
-import android.view.InsetsSourceControl;
-import android.view.InsetsState;
-import android.view.WindowInsets;
 import android.view.WindowManager;
-import android.view.inputmethod.ImeTracker;
-
-import androidx.annotation.BinderThread;
-import androidx.annotation.MainThread;
 
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.systemui.R;
@@ -59,41 +45,22 @@ import com.android.systemui.util.concurrency.DelayableExecutor;
 
 import dagger.Lazy;
 
-import java.util.HashSet;
-import java.util.Set;
-
 /**
- * b/259604616, This controller is created as a workaround for NavBar issues in concurrent
- * {@link CarSystemBar}/SystemUI.
- * Problem: CarSystemBar relies on {@link IStatusBarService},
- * which can register only one process to listen for the {@link CommandQueue} events.
- * Solution: {@link MDSystemBarsControllerImpl} intercepts Insets change event by registering the
- * {@link BinderThread} with
- * {@link IWindowManager#setDisplayWindowInsetsController(int, IDisplayWindowInsetsController)} and
- * notifies its listener for both Primary and Secondary SystemUI
- * process.
+ * Currently because of Bug:b/260206944, RROs are not applied to the secondary user.
+ * This class acts as a Mediator, which toggles the Overlay state of the RRO package,
+ * which in turn triggers onConfigurationChange. Only after this change start the
+ * CarSystemBar with overlaid resources.
  */
 public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
 
     private static final String TAG = MDSystemBarsControllerImpl.class.getSimpleName();
     private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
-    private Set<Listener> mListeners;
-    private int mDisplayId = Display.INVALID_DISPLAY;
-    private InsetsState mCurrentInsetsState;
-    private final IWindowManager mIWindowManager;
-    private final Handler mMainHandler;
     private final Context mContext;
-    private final Listener mListener = new Listener() {
-        @Override
-        public void onKeyboardVisibilityChanged(boolean show) {
-            MDSystemBarsControllerImpl.this.updateKeyboardVisibility(show);
-        }
-    };
     private final OverlayManager mOverlayManager;
 
     private boolean mInitialized = false;
 
-    public MDSystemBarsControllerImpl(IWindowManager wmService,
+    public MDSystemBarsControllerImpl(
             @Main Handler mainHandler,
             Context context,
             UserTracker userTracker,
@@ -133,9 +100,8 @@ public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
                 configurationController,
                 restartTracker,
                 displayTracker,
-                toolbarController);
-        mIWindowManager = wmService;
-        mMainHandler = mainHandler;
+                toolbarController,
+                mainHandler);
         mContext = context;
         mOverlayManager = context.getSystemService(OverlayManager.class);
     }
@@ -185,138 +151,7 @@ public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
         if (!CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
             super.createSystemBar();
         } else {
-            addListener(mListener);
             createNavBar();
         }
     }
-
-    /**
-     * Adds a listener for the display.
-     * Adding a listener to a Display, replaces previous binder callback to this
-     * displayId
-     * {@link IWindowManager#setDisplayWindowInsetsController(int, IDisplayWindowInsetsController)}
-     * A SystemUI process should only register to a single display with displayId
-     * {@link Context#getDisplayId()}
-     *
-     * Note: {@link  Context#getDisplayId()} will return the {@link Context#DEVICE_ID_DEFAULT}, if
-     * called in the constructor. As this component's constructor is called before the DisplayId
-     * gets assigned to the context.
-     *
-     * @param listener SystemBar Inset events
-     */
-    @MainThread
-    private void addListener(Listener listener) {
-        if (mDisplayId != Display.INVALID_DISPLAY && mDisplayId != mContext.getDisplayId()) {
-            Log.e(TAG, "Unexpected Display Id change");
-            mListeners = null;
-            mCurrentInsetsState = null;
-            unregisterWindowInsetController(mDisplayId);
-        }
-        if (mListeners != null) {
-            mListeners.add(listener);
-            return;
-        }
-        mDisplayId = mContext.getDisplayId();
-        mListeners = new HashSet<>();
-        mListeners.add(listener);
-        registerWindowInsetController(mDisplayId);
-    }
-
-    private void registerWindowInsetController(int displayId) {
-        if (DEBUG) {
-            Log.d(TAG, "Registering a WindowInsetController with Display: " + displayId);
-        }
-        try {
-            mIWindowManager.setDisplayWindowInsetsController(displayId,
-                    new DisplayWindowInsetsControllerImpl());
-        } catch (RemoteException e) {
-            Log.w(TAG, "Unable to set insets controller on display " + displayId);
-        }
-    }
-
-    private void unregisterWindowInsetController(int displayId) {
-        if (DEBUG) {
-            Log.d(TAG, "Unregistering a WindowInsetController with Display: " + displayId);
-        }
-        try {
-            mIWindowManager.setDisplayWindowInsetsController(displayId, null);
-        } catch (RemoteException e) {
-            Log.w(TAG, "Unable to remove insets controller on display " + displayId);
-        }
-    }
-
-    @BinderThread
-    private class DisplayWindowInsetsControllerImpl
-            extends IDisplayWindowInsetsController.Stub {
-        @Override
-        public void topFocusedWindowChanged(ComponentName component,
-                @WindowInsets.Type.InsetsType int requestedVisibleTypes) {
-            //no-op
-        }
-
-        @Override
-        public void insetsChanged(InsetsState insetsState) {
-            if (insetsState == null || insetsState.equals(mCurrentInsetsState)) {
-                return;
-            }
-            mCurrentInsetsState = insetsState;
-            if (mListeners == null) {
-                return;
-            }
-            boolean show = insetsState.isSourceOrDefaultVisible(InsetsSource.ID_IME,
-                    WindowInsets.Type.ime());
-            mMainHandler.post(() -> {
-                for (Listener l : mListeners) {
-                    l.onKeyboardVisibilityChanged(show);
-                }
-            });
-        }
-
-        @Override
-        public void insetsControlChanged(InsetsState insetsState,
-                InsetsSourceControl[] activeControls) {
-            //no-op
-        }
-
-        @Override
-        public void showInsets(@WindowInsets.Type.InsetsType int types, boolean fromIme,
-                @Nullable ImeTracker.Token statsToken) {
-            //no-op
-        }
-
-        @Override
-        public void hideInsets(@WindowInsets.Type.InsetsType int types, boolean fromIme,
-                @Nullable ImeTracker.Token statsToken) {
-            //no-op
-        }
-
-        @Override
-        public void setImeInputTargetRequestedVisibility(boolean visible,
-                @NonNull ImeTracker.Token statsToken) {
-            //no-op
-        }
-    }
-
-    /**
-     * Remove a listener for a display
-     *
-     * @param listener SystemBar Inset events Listener
-     * @return if set contains such a listener, returns {@code true} otherwise false
-     */
-    public boolean removeListener(Listener listener) {
-        if (mListeners == null) {
-            return false;
-        }
-        return mListeners.remove(listener);
-    }
-
-    /**
-     * Listener for SystemBar insets events
-     */
-    public interface Listener {
-        /**
-         * show/hide keyboard
-         */
-        void onKeyboardVisibilityChanged(boolean showing);
-    }
 }
diff --git a/src/com/android/systemui/car/systembar/PassengerHomeButtonController.java b/src/com/android/systemui/car/systembar/PassengerHomeButtonController.java
index e44f09c9..77304dc6 100644
--- a/src/com/android/systemui/car/systembar/PassengerHomeButtonController.java
+++ b/src/com/android/systemui/car/systembar/PassengerHomeButtonController.java
@@ -21,6 +21,7 @@ import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.settings.UserTracker;
 
 import dagger.assisted.Assisted;
@@ -36,8 +37,10 @@ public class PassengerHomeButtonController extends CarSystemBarButtonController
     public PassengerHomeButtonController(@Assisted CarSystemBarButton homeButton,
             CarSystemBarElementStatusBarDisableController disableController,
             CarSystemBarElementStateController stateController,
-            UserTracker userTracker) {
-        super(homeButton, disableController, stateController, userTracker);
+            UserTracker userTracker, EventDispatcher eventDispatcher,
+            ButtonSelectionStateController buttonSelectionStateController) {
+        super(homeButton, disableController, stateController, userTracker, eventDispatcher,
+                buttonSelectionStateController);
 
         homeButton.setVisibility(
                 CarSystemUIUserUtil.isSecondaryMUMDSystemUI() ? View.VISIBLE : View.GONE);
diff --git a/src/com/android/systemui/car/systembar/RecentsButtonStateProvider.java b/src/com/android/systemui/car/systembar/RecentsButtonStateProvider.java
index 068cab91..344204c7 100644
--- a/src/com/android/systemui/car/systembar/RecentsButtonStateProvider.java
+++ b/src/com/android/systemui/car/systembar/RecentsButtonStateProvider.java
@@ -19,7 +19,6 @@ package com.android.systemui.car.systembar;
 import android.app.ActivityManager;
 import android.content.ComponentName;
 import android.content.Context;
-import android.content.Intent;
 import android.content.res.TypedArray;
 import android.hardware.input.InputManager;
 import android.view.KeyEvent;
@@ -33,7 +32,6 @@ import com.android.systemui.shared.system.TaskStackChangeListeners;
 import com.android.systemui.statusbar.AlphaOptimizedImageView;
 
 import java.util.function.Consumer;
-import java.util.function.Function;
 
 /**
  * Used to add Recents state functionality to a {@link CarSystemBarButton}
@@ -105,23 +103,18 @@ public class RecentsButtonStateProvider {
      *
      * @param defaultGetButtonClickListener default function to be called for non Recents
      *                                      functionality.
-     * @see CarSystemBarButton#getButtonClickListener(Intent)
+     * @see CarSystemBarButton#getButtonClickListener()
      */
-    public View.OnClickListener getButtonClickListener(Intent toSend,
-            Function<Intent, View.OnClickListener> defaultGetButtonClickListener) {
+    public View.OnClickListener getButtonClickListener(
+            View.OnClickListener defaultGetButtonClickListener) {
         return v -> {
             if (mIsRecentsActive) {
                 toggleRecents();
                 return;
             }
-            if (defaultGetButtonClickListener == null) {
-                return;
-            }
-            View.OnClickListener onClickListener = defaultGetButtonClickListener.apply(toSend);
-            if (onClickListener == null) {
-                return;
+            if (defaultGetButtonClickListener != null) {
+                defaultGetButtonClickListener.onClick(v);
             }
-            onClickListener.onClick(v);
         };
     }
 
diff --git a/src/com/android/systemui/car/systembar/SystemBarConfigs.java b/src/com/android/systemui/car/systembar/SystemBarConfigs.java
index c2ff574c..34395689 100644
--- a/src/com/android/systemui/car/systembar/SystemBarConfigs.java
+++ b/src/com/android/systemui/car/systembar/SystemBarConfigs.java
@@ -27,7 +27,7 @@ import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
 import java.util.List;
 
 /**
- *  Interface for classes that provide system bar configurations.
+ * Interface for classes that provide system bar configurations.
  */
 public interface SystemBarConfigs {
 
@@ -41,6 +41,16 @@ public interface SystemBarConfigs {
      */
     void resetSystemBarConfigs();
 
+    /**
+     * Invalidates cached window context and creates a new window from application context.
+     *
+     * <p>
+     * This method should be called when the window context configurations are not in sync with
+     * application context configurations.
+     * </p>
+     */
+    void resetSystemBarWindowContext();
+
     /**
      * When creating system bars or overlay windows, use a WindowContext
      * for that particular window type to ensure proper display metrics.
@@ -98,12 +108,11 @@ public interface SystemBarConfigs {
 
     /**
      * @param index must be one of the following values
-     * STATUS_BAR = 0
-     * NAVIGATION_BAR = 1
-     * STATUS_BAR_EXTRA = 2
-     * NAVIGATION_BAR_EXTRA = 3
-     * see {@link #getSystemBarInsetTypeBySide(int)}
-     *
+     *              STATUS_BAR = 0
+     *              NAVIGATION_BAR = 1
+     *              STATUS_BAR_EXTRA = 2
+     *              NAVIGATION_BAR_EXTRA = 3
+     *              see {@link #getSystemBarInsetTypeBySide(int)}
      * @return The {@link InsetsFrameProvider}, or {@code null} if the side is unknown
      */
     InsetsFrameProvider getInsetsFrameProvider(int index);
diff --git a/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java b/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java
index 95b30205..0303563f 100644
--- a/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java
+++ b/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java
@@ -17,7 +17,6 @@ package com.android.systemui.car.systembar;
 
 import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
 
-import static com.android.car.dockutil.Flags.dockFeature;
 import static com.android.systemui.car.Flags.displayCompatibilityV2;
 import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
 import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
@@ -40,7 +39,6 @@ import android.view.ViewGroup;
 import android.view.WindowInsets;
 import android.view.WindowManager;
 
-import com.android.car.dockutil.Flags;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.systemui.R;
 import com.android.systemui.car.notification.BottomNotificationPanelViewMediator;
@@ -142,6 +140,14 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
         init();
     }
 
+    @Override
+    public void resetSystemBarWindowContext() {
+        for (int windowType : mWindowContexts.keySet()) {
+            Context context = mContext.createWindowContext(windowType, /* options= */ null);
+            mWindowContexts.put(windowType, context);
+        }
+    }
+
     @Override
     public Context getWindowContextBySide(@SystemBarSide int side) {
         SystemBarConfig config = mSystemBarConfigMap.get(side);
@@ -181,8 +187,6 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
             case TOP:
                 if (!isSetUp) {
                     return R.layout.car_top_system_bar_unprovisioned;
-                } else if (Flags.dockFeature()) {
-                    return R.layout.car_top_system_bar_dock;
                 } else {
                     return R.layout.car_top_system_bar;
                 }
@@ -195,8 +199,6 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
             case BOTTOM:
                 if (!isSetUp) {
                     return R.layout.car_bottom_system_bar_unprovisioned;
-                } else if (Flags.dockFeature()) {
-                    return R.layout.car_bottom_system_bar_dock;
                 } else {
                     return R.layout.car_bottom_system_bar;
                 }
@@ -426,14 +428,14 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
         mLeftNavBarEnabled = mResources.getBoolean(R.bool.config_enableLeftSystemBar);
         mRightNavBarEnabled = mResources.getBoolean(R.bool.config_enableRightSystemBar);
         mDisplayCompatToolbarState =
-            mResources.getInteger(R.integer.config_showDisplayCompatToolbarOnSystemBar);
+                mResources.getInteger(R.integer.config_showDisplayCompatToolbarOnSystemBar);
         mSystemBarConfigMap.clear();
 
         if ((mLeftNavBarEnabled && isLeftDisplayCompatToolbarEnabled())
                 || (mRightNavBarEnabled && isRightDisplayCompatToolbarEnabled())) {
             throw new IllegalStateException(
-                "Navigation Bar and Display Compat toolbar can't be "
-                    + "on the same side");
+                    "Navigation Bar and Display Compat toolbar can't be "
+                            + "on the same side");
         }
 
         if (mTopNavBarEnabled) {
@@ -713,7 +715,7 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
                             | WindowManager.LayoutParams.FLAG_SPLIT_TOUCH,
                     PixelFormat.TRANSLUCENT);
             lp.setTitle(BAR_TITLE_MAP.get(mSide));
-            lp.providedInsets = new InsetsFrameProvider[] {
+            lp.providedInsets = new InsetsFrameProvider[]{
                     BAR_PROVIDER_MAP[mBarType],
                     BAR_GESTURE_MAP.get(mSide)
             };
@@ -721,10 +723,8 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
             lp.windowAnimations = 0;
             lp.gravity = BAR_GRAVITY_MAP.get(mSide);
             lp.layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
-            if (dockFeature()) {
-                lp.privateFlags = lp.privateFlags
-                        | WindowManager.LayoutParams.PRIVATE_FLAG_INTERCEPT_GLOBAL_DRAG_AND_DROP;
-            }
+            lp.privateFlags = lp.privateFlags
+                    | WindowManager.LayoutParams.PRIVATE_FLAG_INTERCEPT_GLOBAL_DRAG_AND_DROP;
             return lp;
         }
 
diff --git a/src/com/android/systemui/car/systembar/SystemBarUtil.kt b/src/com/android/systemui/car/systembar/SystemBarUtil.kt
index b31d4bd0..de4e5f38 100644
--- a/src/com/android/systemui/car/systembar/SystemBarUtil.kt
+++ b/src/com/android/systemui/car/systembar/SystemBarUtil.kt
@@ -25,11 +25,8 @@ import android.provider.Settings
 import android.text.TextUtils
 import android.util.ArraySet
 import android.util.Log
-import android.view.WindowInsets.Type.navigationBars
-import android.view.WindowInsets.Type.statusBars
 import com.android.systemui.R
 import com.android.systemui.settings.UserTracker
-import com.android.systemui.wm.BarControlPolicy
 import java.net.URISyntaxException
 
 object SystemBarUtil {
@@ -116,49 +113,4 @@ object SystemBarUtil {
         }
         launchApp(context, tosIntent, userHandle)
     }
-
-    /**
-     * Helper function that returns {@code true} if the navigation bar is persistent on the display.
-     */
-    fun isNavBarPersistent(context: Context): Boolean {
-        val behavior = context.resources.getInteger(R.integer.config_systemBarPersistency)
-        val remoteInsetsControllerControlsSystemBars =
-            context.resources.getBoolean(
-                android.R.bool.config_remoteInsetsControllerControlsSystemBars
-            )
-        val navBarVisibleOnBarControlPolicy =
-            (behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) &&
-                    isBarVisibleOnBarControlPolicy(context, navigationBars())
-
-        return remoteInsetsControllerControlsSystemBars &&
-                (behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_NON_IMMERSIVE ||
-                        behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV ||
-                        navBarVisibleOnBarControlPolicy)
-    }
-
-    /**
-     * Helper function that returns {@code true} if the status bar is persistent on the display.
-     */
-    fun isStatusBarPersistent(context: Context): Boolean {
-        val behavior = context.resources.getInteger(R.integer.config_systemBarPersistency)
-        val remoteInsetsControllerControlsSystemBars =
-            context.resources.getBoolean(
-                android.R.bool.config_remoteInsetsControllerControlsSystemBars
-            )
-        val statusBarVisibleOnBarControlPolicy =
-            (behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) &&
-                    isBarVisibleOnBarControlPolicy(context, statusBars())
-
-        return remoteInsetsControllerControlsSystemBars &&
-                (behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_NON_IMMERSIVE ||
-                        statusBarVisibleOnBarControlPolicy)
-    }
-
-    private fun isBarVisibleOnBarControlPolicy(context: Context, type: Int): Boolean {
-        val showTypes =
-            BarControlPolicy.getBarVisibilities(
-                context.packageName
-            )[VISIBLE_BAR_VISIBILITIES_TYPES_INDEX]
-        return (showTypes and type) != 0
-    }
 }
diff --git a/src/com/android/systemui/car/systembar/UserNameImageViewController.java b/src/com/android/systemui/car/systembar/UserNameImageViewController.java
index 8d3eee5e..b3b237f3 100644
--- a/src/com/android/systemui/car/systembar/UserNameImageViewController.java
+++ b/src/com/android/systemui/car/systembar/UserNameImageViewController.java
@@ -17,9 +17,7 @@
 package com.android.systemui.car.systembar;
 
 import android.content.Context;
-import android.content.pm.UserInfo;
 import android.graphics.drawable.Drawable;
-import android.os.UserManager;
 
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -44,7 +42,6 @@ public final class UserNameImageViewController extends
     private final Context mContext;
     private final Executor mMainExecutor;
     private final UserTracker mUserTracker;
-    private final UserManager mUserManager;
     private final CarProfileIconUpdater mCarProfileIconUpdater;
     private final UserIconProvider mUserIconProvider;
     private boolean mUserLifecycleListenerRegistered;
@@ -63,13 +60,12 @@ public final class UserNameImageViewController extends
     protected UserNameImageViewController(@Assisted CarSystemBarImageView view,
             CarSystemBarElementStatusBarDisableController disableController,
             CarSystemBarElementStateController stateController, Context context,
-            @Main Executor mainExecutor, UserTracker userTracker, UserManager userManager,
+            @Main Executor mainExecutor, UserTracker userTracker,
             CarProfileIconUpdater carProfileIconUpdater, UserIconProvider userIconProvider) {
         super(view, disableController, stateController);
         mContext = context;
         mMainExecutor = mainExecutor;
         mUserTracker = userTracker;
-        mUserManager = userManager;
         mCarProfileIconUpdater = carProfileIconUpdater;
         mUserIconProvider = userIconProvider;
     }
@@ -109,9 +105,7 @@ public final class UserNameImageViewController extends
     }
 
     private void updateUser(int userId) {
-        UserInfo currentUserInfo = mUserManager.getUserInfo(userId);
-
-        Drawable circleIcon = mUserIconProvider.getRoundedUserIcon(currentUserInfo, mContext);
-        mView.setImageDrawable(circleIcon);
+        Drawable roundedUserIcon = mUserIconProvider.getRoundedUserIcon(userId);
+        mView.setImageDrawable(roundedUserIcon);
     }
 }
diff --git a/src/com/android/systemui/car/userpicker/SnackbarManager.java b/src/com/android/systemui/car/userpicker/SnackbarManager.java
index a09f19b6..1ee49825 100644
--- a/src/com/android/systemui/car/userpicker/SnackbarManager.java
+++ b/src/com/android/systemui/car/userpicker/SnackbarManager.java
@@ -53,7 +53,9 @@ final class SnackbarManager {
             mAnchorViewId = anchorViewId;
         }
         mDisplayId = context.getDisplayId();
-        mSnackbarBackgroundTint = context.getColor(R.color.user_picker_snack_bar_background_color);
+        mSnackbarBackgroundTint = context.getResources().getColor(
+                R.color.user_picker_snack_bar_background_color,
+                context.getTheme());
     }
 
     void showSnackbar(@NonNull String message) {
diff --git a/src/com/android/systemui/car/userpicker/UserEventManager.java b/src/com/android/systemui/car/userpicker/UserEventManager.java
index 0320576f..0dce136c 100644
--- a/src/com/android/systemui/car/userpicker/UserEventManager.java
+++ b/src/com/android/systemui/car/userpicker/UserEventManager.java
@@ -138,12 +138,12 @@ public final class UserEventManager {
 
     @Inject
     UserEventManager(Context context, CarServiceMediator carServiceMediator,
-            UserPickerSharedState userPickerSharedState) {
+            UserPickerSharedState userPickerSharedState, UserManager userManager) {
         mUpdateListeners = new SparseArray<>();
         mContext = context.getApplicationContext();
         mUserLifecycleReceiver = Executors.newSingleThreadExecutor();
         mMainHandler = new Handler(Looper.getMainLooper());
-        mUserManager = mContext.getSystemService(UserManager.class);
+        mUserManager = userManager;
         mUserPickerSharedState = userPickerSharedState;
         mCarServiceMediator = carServiceMediator;
         mCarServiceMediator.registerUserChangeEventsListener(mUserLifecycleReceiver, mFilter,
diff --git a/src/com/android/systemui/car/userpicker/UserPickerActivity.java b/src/com/android/systemui/car/userpicker/UserPickerActivity.java
index cb8313ed..574a16f7 100644
--- a/src/com/android/systemui/car/userpicker/UserPickerActivity.java
+++ b/src/com/android/systemui/car/userpicker/UserPickerActivity.java
@@ -29,6 +29,7 @@ import android.content.res.Configuration;
 import android.graphics.Insets;
 import android.os.Build;
 import android.os.Bundle;
+import android.os.UserManager;
 import android.util.Log;
 import android.util.Slog;
 import android.view.LayoutInflater;
@@ -47,9 +48,9 @@ import com.android.car.ui.recyclerview.CarUiRecyclerView;
 import com.android.systemui.Dumpable;
 import com.android.systemui.R;
 import com.android.systemui.car.CarServiceProvider;
-import com.android.systemui.car.systembar.SystemBarUtil;
 import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
 import com.android.systemui.car.userpicker.UserPickerController.Callbacks;
+import com.android.systemui.car.userswitcher.UserIconProvider;
 import com.android.systemui.dump.DumpManager;
 import com.android.systemui.settings.DisplayTracker;
 
@@ -105,16 +106,20 @@ public class UserPickerActivity extends Activity implements Dumpable {
     @Inject
     UserPickerActivity(
             Context context, //application context
+            UserManager userManager,
             DisplayTracker displayTracker,
             CarServiceProvider carServiceProvider,
-            UserPickerSharedState userPickerSharedState
+            UserPickerSharedState userPickerSharedState,
+            UserIconProvider userIconProvider
     ) {
         this();
         mUserPickerActivityComponent = DaggerUserPickerActivityComponent.builder()
                 .context(context)
+                .userManager(userManager)
                 .carServiceProvider(carServiceProvider)
                 .displayTracker(displayTracker)
                 .userPickerSharedState(userPickerSharedState)
+                .userIconProvider(userIconProvider)
                 .build();
         //Component.inject(this) is not working because constructor and activity itself is
         //scoped to SystemUiScope but the deps below are scoped to UserPickerScope
@@ -237,11 +242,11 @@ public class UserPickerActivity extends Activity implements Dumpable {
 
     // Avoid activity resizing due to dismissible system bars.
     private final View.OnApplyWindowInsetsListener mOnApplyWindowInsetsListener = (v, insets) -> {
-        if (!SystemBarUtil.INSTANCE.isStatusBarPersistent(this)) {
+        if (!insets.isVisible(WindowInsets.Type.statusBars())) {
             Insets statusBarInsets = insets.getInsets(WindowInsets.Type.statusBars());
             insets.inset(statusBarInsets);
         }
-        if (!SystemBarUtil.INSTANCE.isNavBarPersistent(/* context*/ this)) {
+        if (!insets.isVisible(WindowInsets.Type.navigationBars())) {
             Insets navBarInsets = insets.getInsets(WindowInsets.Type.navigationBars());
             insets.inset(navBarInsets);
         }
diff --git a/src/com/android/systemui/car/userpicker/UserPickerActivityComponent.java b/src/com/android/systemui/car/userpicker/UserPickerActivityComponent.java
index 85e4e5e4..48201ac2 100644
--- a/src/com/android/systemui/car/userpicker/UserPickerActivityComponent.java
+++ b/src/com/android/systemui/car/userpicker/UserPickerActivityComponent.java
@@ -17,8 +17,10 @@
 package com.android.systemui.car.userpicker;
 
 import android.content.Context;
+import android.os.UserManager;
 
 import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.userswitcher.UserIconProvider;
 import com.android.systemui.settings.DisplayTracker;
 
 import dagger.BindsInstance;
@@ -39,6 +41,9 @@ public interface UserPickerActivityComponent {
         @BindsInstance
         Builder context(Context context);
 
+        @BindsInstance
+        Builder userManager(UserManager userManager);
+
         @BindsInstance
         Builder carServiceProvider(CarServiceProvider carServiceProvider);
 
@@ -48,6 +53,9 @@ public interface UserPickerActivityComponent {
         @BindsInstance
         Builder userPickerSharedState(UserPickerSharedState userPickerSharedState);
 
+        @BindsInstance
+        Builder userIconProvider(UserIconProvider userIconProvider);
+
         UserPickerActivityComponent build();
     }
 
diff --git a/src/com/android/systemui/car/userpicker/UserPickerAdapter.java b/src/com/android/systemui/car/userpicker/UserPickerAdapter.java
index f58be587..fcff5a94 100644
--- a/src/com/android/systemui/car/userpicker/UserPickerAdapter.java
+++ b/src/com/android/systemui/car/userpicker/UserPickerAdapter.java
@@ -58,9 +58,10 @@ final class UserPickerAdapter extends Adapter<UserPickerAdapter.UserPickerAdapte
         mContext = context;
         mDisplayId = mContext.getDisplayId();
         mDisabledAlpha = mContext.getResources().getFloat(R.fraction.user_picker_disabled_alpha);
-        mCurrentUserSubtitleColor = mContext.getColor(
-                R.color.user_picker_current_login_state_color);
-        mOtherUserSubtitleColor = mContext.getColor(R.color.user_picker_other_login_state_color);
+        mCurrentUserSubtitleColor = mContext.getResources().getColor(
+                R.color.user_picker_current_login_state_color, mContext.getTheme());
+        mOtherUserSubtitleColor = mContext.getResources().getColor(
+                R.color.user_picker_other_login_state_color, mContext.getTheme());
         mVerticalSpacing = mContext.getResources().getDimensionPixelSize(
                 R.dimen.user_picker_vertical_space_between_users);
         mHorizontalSpacing = mContext.getResources().getDimensionPixelSize(
diff --git a/src/com/android/systemui/car/userpicker/UserPickerController.java b/src/com/android/systemui/car/userpicker/UserPickerController.java
index de32b161..90f9d39b 100644
--- a/src/com/android/systemui/car/userpicker/UserPickerController.java
+++ b/src/com/android/systemui/car/userpicker/UserPickerController.java
@@ -143,11 +143,12 @@ final class UserPickerController {
         runOnMainHandler(REQ_DISMISS_ADDING_DIALOG);
 
         if (result != null && result.isSuccess()) {
-            UserInfo newUserInfo = mUserEventManager.getUserInfo(result.getUser().getIdentifier());
+            int userId = result.getUser().getIdentifier();
+            UserInfo newUserInfo = mUserEventManager.getUserInfo(userId);
             UserRecord userRecord = UserRecord.create(newUserInfo, newUserInfo.name,
                     /* isStartGuestSession= */ false, /* isAddUser= */ false,
                     /* isForeground= */ false,
-                    /* icon= */ mUserIconProvider.getRoundedUserIcon(newUserInfo, mContext),
+                    /* icon= */ mUserIconProvider.getRoundedUserIcon(userId),
                     /* listenerMaker */ new OnClickListenerCreator());
             mIsUserPickerClickable = false;
             handleUserSelected(userRecord);
@@ -163,14 +164,14 @@ final class UserPickerController {
     UserPickerController(Context context, UserEventManager userEventManager,
             CarServiceMediator carServiceMediator, DialogManager dialogManager,
             SnackbarManager snackbarManager, DisplayTracker displayTracker,
-            UserPickerSharedState userPickerSharedState) {
+            UserPickerSharedState userPickerSharedState, UserIconProvider userIconProvider) {
         mContext = context;
         mUserEventManager = userEventManager;
         mCarServiceMediator = carServiceMediator;
         mDialogManager = dialogManager;
         mSnackbarManager = snackbarManager;
         mLockPatternUtils = new LockPatternUtils(mContext);
-        mUserIconProvider = new UserIconProvider();
+        mUserIconProvider = userIconProvider;
         mDisplayTracker = displayTracker;
         mUserPickerSharedState = userPickerSharedState;
         mWorker = Executors.newSingleThreadExecutor();
@@ -313,7 +314,7 @@ final class UserPickerController {
                 userRecords.add(UserRecord.create(foregroundUser, /* name= */ foregroundUser.name,
                         /* isStartGuestSession= */ false, /* isAddUser= */ false,
                         /* isForeground= */ true,
-                        /* icon= */ mUserIconProvider.getRoundedUserIcon(foregroundUser, mContext),
+                        /* icon= */ mUserIconProvider.getRoundedUserIcon(foregroundUser.id),
                         /* listenerMaker */ new OnClickListenerCreator(),
                         mLockPatternUtils.isSecure(foregroundUser.id),
                         /* isLoggedIn= */ true, /* loggedInDisplay= */ mDisplayId,
@@ -333,7 +334,7 @@ final class UserPickerController {
             UserRecord record = UserRecord.create(userInfo, /* name= */ userInfo.name,
                     /* isStartGuestSession= */ false, /* isAddUser= */ false,
                     /* isForeground= */ userInfo.id == foregroundUser.id,
-                    /* icon= */ mUserIconProvider.getRoundedUserIcon(userInfo, mContext),
+                    /* icon= */ mUserIconProvider.getRoundedUserIcon(userInfo.id),
                     /* listenerMaker */ new OnClickListenerCreator(),
                     /* isSecure= */ mLockPatternUtils.isSecure(userInfo.id),
                     /* isLoggedIn= */ loggedInDisplayId != INVALID_DISPLAY,
@@ -370,7 +371,7 @@ final class UserPickerController {
         return UserRecord.create(/* info= */ null, /* name= */ mDefaultGuestName,
                 /* isStartGuestSession= */ true, /* isAddUser= */ false,
                 /* isForeground= */ false,
-                /* icon= */ mUserIconProvider.getRoundedGuestDefaultIcon(mContext),
+                /* icon= */ mUserIconProvider.getRoundedGuestDefaultIcon(),
                 /* listenerMaker */ new OnClickListenerCreator(),
                 /* isSecure */ false,
                 loggedIn, loggedInDisplay,
diff --git a/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java b/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
index 8b91306c..dfa1a2bd 100644
--- a/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
+++ b/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
@@ -17,7 +17,7 @@
 package com.android.systemui.car.users;
 
 import static android.car.CarOccupantZoneManager.DISPLAY_TYPE_MAIN;
-import static android.hardware.display.DisplayManager.PRIVATE_EVENT_FLAG_DISPLAY_BRIGHTNESS;
+import static android.hardware.display.DisplayManager.PRIVATE_EVENT_TYPE_DISPLAY_BRIGHTNESS;
 
 import static com.android.systemui.car.users.CarSystemUIUserUtil.isCurrentSystemUIDisplay;
 import static com.android.systemui.car.users.CarSystemUIUserUtil.isMUMDSystemUI;
@@ -174,7 +174,7 @@ public class CarMUMDDisplayTrackerImpl implements DisplayTracker {
         synchronized (mBrightnessCallbacks) {
             if (mBrightnessCallbacks.isEmpty()) {
                 mDisplayManager.registerDisplayListener(mBrightnessChangedListener, mHandler,
-                        0, PRIVATE_EVENT_FLAG_DISPLAY_BRIGHTNESS);
+                        0, PRIVATE_EVENT_TYPE_DISPLAY_BRIGHTNESS);
             }
             mBrightnessCallbacks.add(new DisplayTrackerCallbackData(callback, executor));
         }
diff --git a/src/com/android/systemui/car/users/CarProfileIconUpdater.java b/src/com/android/systemui/car/users/CarProfileIconUpdater.java
index ed73cead..3e937989 100644
--- a/src/com/android/systemui/car/users/CarProfileIconUpdater.java
+++ b/src/com/android/systemui/car/users/CarProfileIconUpdater.java
@@ -110,7 +110,7 @@ public class CarProfileIconUpdater implements CoreStartable {
         // Update user icon with the first letter of the user name
         if (mLastUserName == null || !mLastUserName.equals(currentUserInfo.name)) {
             mLastUserName = currentUserInfo.name;
-            mUserIconProvider.setRoundedUserIcon(currentUserInfo, mContext);
+            mUserIconProvider.setRoundedUserIcon(userId);
             notifyCallbacks(userId);
         }
     }
diff --git a/src/com/android/systemui/car/userswitcher/FullScreenUserSwitcherViewController.java b/src/com/android/systemui/car/userswitcher/FullScreenUserSwitcherViewController.java
index 34c61fd4..72c880cb 100644
--- a/src/com/android/systemui/car/userswitcher/FullScreenUserSwitcherViewController.java
+++ b/src/com/android/systemui/car/userswitcher/FullScreenUserSwitcherViewController.java
@@ -51,6 +51,7 @@ public class FullScreenUserSwitcherViewController extends OverlayViewController
         implements ConfigurationController.ConfigurationListener {
     private final Context mContext;
     private final UserTracker mUserTracker;
+    private final UserIconProvider mUserIconProvider;
     private final Resources mResources;
     private final CarServiceProvider mCarServiceProvider;
     private final int mShortAnimationDuration;
@@ -65,6 +66,7 @@ public class FullScreenUserSwitcherViewController extends OverlayViewController
     public FullScreenUserSwitcherViewController(
             Context context,
             UserTracker userTracker,
+            UserIconProvider userIconProvider,
             @Main Resources resources,
             ConfigurationController configurationController,
             CarServiceProvider carServiceProvider,
@@ -72,6 +74,7 @@ public class FullScreenUserSwitcherViewController extends OverlayViewController
         super(R.id.fullscreen_user_switcher_stub, overlayViewGlobalStateController);
         mContext = context;
         mUserTracker = userTracker;
+        mUserIconProvider = userIconProvider;
         mResources = resources;
         mCarServiceProvider = carServiceProvider;
         mCarServiceProvider.addListener(car -> {
@@ -151,6 +154,7 @@ public class FullScreenUserSwitcherViewController extends OverlayViewController
                 mResources.getInteger(R.integer.user_fullscreen_switcher_num_col));
         mUserGridView.setLayoutManager(layoutManager);
         mUserGridView.setUserTracker(mUserTracker);
+        mUserGridView.setUserIconProvider(mUserIconProvider);
         mUserGridView.buildAdapter();
         mUserGridView.setUserSelectionListener(mUserSelectionListener);
         registerCarUserManagerIfPossible();
diff --git a/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java b/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
index a6fb5305..0bee7e83 100644
--- a/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
+++ b/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
@@ -57,14 +57,11 @@ import android.view.Window;
 import android.view.WindowManager;
 import android.widget.TextView;
 
-import androidx.core.graphics.drawable.RoundedBitmapDrawable;
-import androidx.core.graphics.drawable.RoundedBitmapDrawableFactory;
 import androidx.recyclerview.widget.GridLayoutManager;
 import androidx.recyclerview.widget.RecyclerView;
 
 import com.android.car.admin.ui.UserAvatarView;
 import com.android.car.internal.user.UserHelper;
-import com.android.internal.util.UserIcons;
 import com.android.settingslib.utils.StringUtil;
 import com.android.systemui.R;
 import com.android.systemui.settings.UserTracker;
@@ -108,7 +105,6 @@ public class UserGridRecyclerView extends RecyclerView {
         super(context, attrs);
         mContext = context;
         mUserManager = UserManager.get(mContext);
-        mUserIconProvider = new UserIconProvider();
         mWorker = Executors.newSingleThreadExecutor();
 
         addItemDecoration(new ItemSpacingDecoration(mContext.getResources().getDimensionPixelSize(
@@ -207,6 +203,10 @@ public class UserGridRecyclerView extends RecyclerView {
         mUserTracker = userTracker;
     }
 
+    public void setUserIconProvider(UserIconProvider userIconProvider) {
+        mUserIconProvider = userIconProvider;
+    }
+
     public void setUserSelectionListener(UserSelectionListener userSelectionListener) {
         mUserSelectionListener = userSelectionListener;
     }
@@ -300,15 +300,20 @@ public class UserGridRecyclerView extends RecyclerView {
         public void onBindViewHolder(UserAdapterViewHolder holder, int position) {
             UserRecord userRecord = mUsers.get(position);
 
-            Drawable circleIcon = getCircularUserRecordIcon(userRecord);
-
-            if (userRecord.mInfo != null) {
-                // User might have badges (like managed user)
-                holder.mUserAvatarImageView.setDrawableWithBadge(circleIcon, userRecord.mInfo.id);
+            Drawable roundedIcon = getRoundedUserRecordIcon(userRecord);
+            if (roundedIcon != null) {
+                if (userRecord.mInfo != null) {
+                    // User might have badges (like managed user)
+                    holder.mUserAvatarImageView.setDrawableWithBadge(roundedIcon,
+                            userRecord.mInfo.id);
+                } else {
+                    // Guest or "Add User" don't have badges
+                    holder.mUserAvatarImageView.setDrawable(roundedIcon);
+                }
             } else {
-                // Guest or "Add User" don't have badges
-                holder.mUserAvatarImageView.setDrawable(circleIcon);
+                Log.e(TAG, "Unable to get user icon");
             }
+
             holder.mUserNameTextView.setText(getUserRecordName(userRecord));
 
             holder.mView.setOnClickListener(v -> {
@@ -436,29 +441,24 @@ public class UserGridRecyclerView extends RecyclerView {
             }
         }
 
-        private Drawable getCircularUserRecordIcon(UserRecord userRecord) {
-            Drawable circleIcon;
+        private Drawable getRoundedUserRecordIcon(UserRecord userRecord) {
+            if (mUserIconProvider == null) {
+                return null;
+            }
+
+            Drawable roundedIcon;
             switch (userRecord.mType) {
                 case UserRecord.START_GUEST:
-                    circleIcon = mUserIconProvider
-                            .getRoundedGuestDefaultIcon(mContext);
+                    roundedIcon = mUserIconProvider.getRoundedGuestDefaultIcon();
                     break;
                 case UserRecord.ADD_USER:
-                    circleIcon = getCircularAddUserIcon();
+                    roundedIcon = mUserIconProvider.getRoundedAddUserIcon();
                     break;
                 default:
-                    circleIcon = mUserIconProvider.getRoundedUserIcon(userRecord.mInfo, mContext);
+                    roundedIcon = mUserIconProvider.getRoundedUserIcon(userRecord.mInfo.id);
                     break;
             }
-            return circleIcon;
-        }
-
-        private RoundedBitmapDrawable getCircularAddUserIcon() {
-            RoundedBitmapDrawable circleIcon =
-                    RoundedBitmapDrawableFactory.create(mRes, UserIcons.convertToBitmap(
-                    mContext.getDrawable(R.drawable.car_add_circle_round)));
-            circleIcon.setCircular(true);
-            return circleIcon;
+            return roundedIcon;
         }
 
         private String getUserRecordName(UserRecord userRecord) {
diff --git a/src/com/android/systemui/car/userswitcher/UserIconProvider.java b/src/com/android/systemui/car/userswitcher/UserIconProvider.java
index 3f063d1b..19da129d 100644
--- a/src/com/android/systemui/car/userswitcher/UserIconProvider.java
+++ b/src/com/android/systemui/car/userswitcher/UserIconProvider.java
@@ -18,7 +18,6 @@ package com.android.systemui.car.userswitcher;
 
 import android.annotation.UserIdInt;
 import android.content.Context;
-import android.content.pm.UserInfo;
 import android.content.res.Resources;
 import android.graphics.Bitmap;
 import android.graphics.drawable.BitmapDrawable;
@@ -27,48 +26,63 @@ import android.os.UserHandle;
 import android.os.UserManager;
 
 import androidx.core.graphics.drawable.RoundedBitmapDrawable;
+import androidx.core.graphics.drawable.RoundedBitmapDrawableFactory;
 
 import com.android.car.admin.ui.UserAvatarView;
 import com.android.car.internal.user.UserHelper;
+import com.android.internal.util.UserIcons;
 import com.android.systemui.R;
+import com.android.systemui.dagger.SysUISingleton;
 
 import javax.inject.Inject;
 
 /**
  * Simple class for providing icons for users.
  */
+@SysUISingleton
 public class UserIconProvider {
+    private final Context mContext;
+    private final UserManager mUserManager;
+
+    private final float mBadgeToIconSizeRatio;
+    private final float mBadgePadding;
 
     @Inject
-    public UserIconProvider() {
+    public UserIconProvider(Context context, UserManager userManager) {
+        mContext = context;
+        mUserManager = userManager;
+
+        mBadgeToIconSizeRatio =
+                mContext.getResources().getDimension(R.dimen.car_user_switcher_managed_badge_size)
+                        / mContext.getResources().getDimension(
+                        R.dimen.car_user_switcher_image_avatar_size);
+        mBadgePadding = mContext.getResources().getDimension(
+                R.dimen.car_user_switcher_managed_badge_margin);
     }
 
     /**
      * Sets a rounded icon with the first letter of the given user name.
      * This method will update UserManager to use that icon.
      *
-     * @param userInfo User for which the icon is requested.
-     * @param context Context to use for resources
+     * @param userId User for which the icon is requested.
      */
-    public void setRoundedUserIcon(UserInfo userInfo, Context context) {
-        UserHelper.assignDefaultIcon(context, userInfo.getUserHandle());
+    public void setRoundedUserIcon(@UserIdInt int userId) {
+        UserHelper.assignDefaultIcon(mContext, UserHandle.of(userId));
     }
 
     /**
      * Gets a scaled rounded icon for the given user.  If a user does not have an icon saved, this
      * method will default to a generic icon and update UserManager to use that icon.
      *
-     * @param userInfo User for which the icon is requested.
-     * @param context Context to use for resources
+     * @param userId User for which the icon is requested.
      * @return {@link RoundedBitmapDrawable} representing the icon for the user.
      */
-    public Drawable getRoundedUserIcon(UserInfo userInfo, Context context) {
-        UserManager userManager = context.getSystemService(UserManager.class);
-        Resources res = context.getResources();
-        Bitmap icon = userManager.getUserIcon(userInfo.id);
+    public Drawable getRoundedUserIcon(@UserIdInt int userId) {
+        Resources res = mContext.getResources();
+        Bitmap icon = mUserManager.getUserIcon(userId);
 
         if (icon == null) {
-            icon = UserHelper.assignDefaultIcon(context, userInfo.getUserHandle());
+            icon = UserHelper.assignDefaultIcon(mContext, UserHandle.of(userId));
         }
 
         return new BitmapDrawable(res, icon);
@@ -77,36 +91,28 @@ public class UserIconProvider {
     /**
      * Gets a user icon with badge if the user profile is managed.
      *
-     * @param context to use for the avatar view
-     * @param userInfo User for which the icon is requested and badge is set
+     * @param userId User for which the icon is requested and badge is set
      * @return {@link Drawable} with badge
      */
-    public Drawable getDrawableWithBadge(Context context, UserInfo userInfo) {
-        return addBadge(context, getRoundedUserIcon(userInfo, context), userInfo.id);
+    public Drawable getDrawableWithBadge(@UserIdInt int userId) {
+        return addBadge(getRoundedUserIcon(userId), userId);
     }
 
     /**
      * Gets an icon with badge if the device is managed.
      *
-     * @param context context
      * @param drawable icon without badge
      * @return {@link Drawable} with badge
      */
-    public Drawable getDrawableWithBadge(Context context, Drawable drawable) {
-        return addBadge(context, drawable, UserHandle.USER_NULL);
+    public Drawable getDrawableWithBadge(Drawable drawable) {
+        return addBadge(drawable, UserHandle.USER_NULL);
     }
 
-    private static Drawable addBadge(Context context, Drawable drawable, @UserIdInt int userId) {
+    private Drawable addBadge(Drawable drawable, @UserIdInt int userId) {
         int iconSize = drawable.getIntrinsicWidth();
-        UserAvatarView userAvatarView = new UserAvatarView(context);
-        float badgeToIconSizeRatio =
-                context.getResources().getDimension(R.dimen.car_user_switcher_managed_badge_size)
-                        / context.getResources().getDimension(
-                        R.dimen.car_user_switcher_image_avatar_size);
-        userAvatarView.setBadgeDiameter(iconSize * badgeToIconSizeRatio);
-        float badgePadding = context.getResources().getDimension(
-                R.dimen.car_user_switcher_managed_badge_margin);
-        userAvatarView.setBadgeMargin(badgePadding);
+        UserAvatarView userAvatarView = new UserAvatarView(mContext);
+        userAvatarView.setBadgeDiameter(iconSize * mBadgeToIconSizeRatio);
+        userAvatarView.setBadgeMargin(mBadgePadding);
         if (userId != UserHandle.USER_NULL) {
             // When the userId is valid, add badge if the user is managed.
             userAvatarView.setDrawableWithBadge(drawable, userId);
@@ -120,8 +126,17 @@ public class UserIconProvider {
     }
 
     /** Returns a scaled, rounded, default icon for the Guest user */
-    public Drawable getRoundedGuestDefaultIcon(Context context) {
-        Bitmap icon = UserHelper.getGuestDefaultIcon(context);
-        return new BitmapDrawable(context.getResources(), icon);
+    public Drawable getRoundedGuestDefaultIcon() {
+        Bitmap icon = UserHelper.getGuestDefaultIcon(mContext);
+        return new BitmapDrawable(mContext.getResources(), icon);
+    }
+
+    /** Returns a scaled, rounded, default icon for the add user entry. */
+    public Drawable getRoundedAddUserIcon() {
+        RoundedBitmapDrawable roundedIcon = RoundedBitmapDrawableFactory.create(
+                mContext.getResources(),
+                UserIcons.convertToBitmap(mContext.getDrawable(R.drawable.car_add_circle_round)));
+        roundedIcon.setCircular(true);
+        return roundedIcon;
     }
 }
diff --git a/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewController.java b/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewController.java
index abd2500a..ae70bc63 100644
--- a/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewController.java
+++ b/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewController.java
@@ -68,7 +68,7 @@ public class UserSwitchTransitionViewController extends OverlayViewController {
     private final UserManager mUserManager;
     private final IWindowManager mWindowManagerService;
     private final KeyguardManager mKeyguardManager;
-    private final UserIconProvider mUserIconProvider = new UserIconProvider();
+    private final UserIconProvider mUserIconProvider;
     private final int mWindowShownTimeoutMs;
     private final Runnable mWindowShownTimeoutCallback = () -> {
         if (DEBUG) {
@@ -100,6 +100,7 @@ public class UserSwitchTransitionViewController extends OverlayViewController {
             @Main DelayableExecutor delayableExecutor,
             ActivityManager activityManager,
             UserManager userManager,
+            UserIconProvider userIconProvider,
             IWindowManager windowManagerService,
             OverlayViewGlobalStateController overlayViewGlobalStateController) {
 
@@ -110,6 +111,7 @@ public class UserSwitchTransitionViewController extends OverlayViewController {
         mMainExecutor = delayableExecutor;
         mActivityManager = activityManager;
         mUserManager = userManager;
+        mUserIconProvider = userIconProvider;
         mWindowManagerService = windowManagerService;
         mKeyguardManager = context.getSystemService(KeyguardManager.class);
         mWindowShownTimeoutMs = mResources.getInteger(
@@ -213,8 +215,7 @@ public class UserSwitchTransitionViewController extends OverlayViewController {
     }
 
     private void drawUserIcon(int newUserId) {
-        Drawable userIcon = mUserIconProvider.getDrawableWithBadge(mContext,
-                mUserManager.getUserInfo(newUserId));
+        Drawable userIcon = mUserIconProvider.getDrawableWithBadge(newUserId);
         ((ImageView) getLayout().findViewById(R.id.user_loading_avatar))
                 .setImageDrawable(userIcon);
     }
@@ -232,7 +233,8 @@ public class UserSwitchTransitionViewController extends OverlayViewController {
                             previousUserId, newUserId));
         } else {
             // Show the switchingFromUserMessage if it was set.
-            String switchingFromUserMessage = mActivityManager.getSwitchingFromUserMessage();
+            String switchingFromUserMessage =
+                    mActivityManager.getSwitchingFromUserMessage(previousUserId);
             msgView.setText(switchingFromUserMessage != null ? switchingFromUserMessage
                     : mResources.getString(R.string.car_loading_profile));
         }
diff --git a/src/com/android/systemui/car/volume/CarVolumeDialogImpl.java b/src/com/android/systemui/car/volume/CarVolumeDialogImpl.java
index fbc18697..0ead6cad 100644
--- a/src/com/android/systemui/car/volume/CarVolumeDialogImpl.java
+++ b/src/com/android/systemui/car/volume/CarVolumeDialogImpl.java
@@ -614,7 +614,8 @@ public class CarVolumeDialogImpl
                         mCarAudioManager));
         carVolumeItem.setGroupId(volumeGroupId);
 
-        int color = mContext.getColor(R.color.car_volume_dialog_tint);
+        int color = mContext.getResources().getColor(R.color.car_volume_dialog_tint,
+                mContext.getTheme());
         Drawable primaryIcon = mContext.getDrawable(volumeItem.mIcon);
         primaryIcon.mutate().setTint(color);
         carVolumeItem.setPrimaryIcon(primaryIcon);
diff --git a/src/com/android/systemui/car/volume/CarVolumeItemAdapter.java b/src/com/android/systemui/car/volume/CarVolumeItemAdapter.java
index c79aa408..d9f15c61 100644
--- a/src/com/android/systemui/car/volume/CarVolumeItemAdapter.java
+++ b/src/com/android/systemui/car/volume/CarVolumeItemAdapter.java
@@ -50,8 +50,10 @@ public class CarVolumeItemAdapter extends
     @Override
     public void onBindViewHolder(CarVolumeItem.CarVolumeItemViewHolder holder, int position) {
         mItems.get(position).bind(holder);
-        int backgroundColor = mContext.getColor(R.color.car_volume_dialog_background_color);
-        int iconColor = mContext.getColor(R.color.car_volume_dialog_tint);
+        int backgroundColor = mContext.getResources().getColor(
+                R.color.car_volume_dialog_background_color, mContext.getTheme());
+        int iconColor = mContext.getResources().getColor(
+                R.color.car_volume_dialog_tint, mContext.getTheme());
         holder.itemView.setBackgroundColor(backgroundColor);
         holder.setIconDrawableColor(iconColor);
     }
diff --git a/src/com/android/systemui/car/wm/AutoDisplayCompatWindowDecorViewModel.java b/src/com/android/systemui/car/wm/AutoDisplayCompatWindowDecorViewModel.java
new file mode 100644
index 00000000..4a4f94c7
--- /dev/null
+++ b/src/com/android/systemui/car/wm/AutoDisplayCompatWindowDecorViewModel.java
@@ -0,0 +1,72 @@
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
+package com.android.systemui.car.wm;
+
+import static android.view.Display.DEFAULT_DISPLAY;
+
+import static com.android.systemui.car.Flags.displayCompatibilityCaptionBar;
+import static com.android.systemui.car.displaycompat.CarDisplayCompatUtils.getPackageName;
+import static com.android.systemui.car.displaycompat.CarDisplayCompatUtils.requiresDisplayCompat;
+
+import android.annotation.Nullable;
+import android.app.ActivityManager;
+import android.car.content.pm.CarPackageManager;
+import android.content.Context;
+
+import com.android.systemui.car.CarServiceProvider;
+import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.common.DisplayController;
+import com.android.wm.shell.common.DisplayInsetsController;
+import com.android.wm.shell.common.ShellExecutor;
+import com.android.wm.shell.common.SyncTransactionQueue;
+import com.android.wm.shell.shared.annotations.ShellBackgroundThread;
+import com.android.wm.shell.shared.annotations.ShellMainThread;
+import com.android.wm.shell.sysui.ShellInit;
+import com.android.wm.shell.transition.FocusTransitionObserver;
+import com.android.wm.shell.windowdecor.CarWindowDecorViewModel;
+import com.android.wm.shell.windowdecor.common.viewhost.WindowDecorViewHost;
+import com.android.wm.shell.windowdecor.common.viewhost.WindowDecorViewHostSupplier;
+
+public class AutoDisplayCompatWindowDecorViewModel extends CarWindowDecorViewModel {
+    @Nullable
+    private CarPackageManager mCarPackageManager;
+
+    public AutoDisplayCompatWindowDecorViewModel(Context context,
+            @ShellMainThread ShellExecutor mainExecutor,
+            @ShellBackgroundThread ShellExecutor bgExecutor,
+            ShellInit shellInit,
+            ShellTaskOrganizer taskOrganizer,
+            DisplayController displayController,
+            DisplayInsetsController displayInsetsController,
+            SyncTransactionQueue syncQueue,
+            FocusTransitionObserver focusTransitionObserver,
+            WindowDecorViewHostSupplier<WindowDecorViewHost> windowDecorViewHostSupplier,
+            CarServiceProvider carServiceProvider) {
+        super(context, mainExecutor, bgExecutor, shellInit, taskOrganizer, displayController,
+                displayInsetsController, syncQueue, focusTransitionObserver,
+                windowDecorViewHostSupplier);
+        carServiceProvider.addListener(
+                car -> mCarPackageManager = car.getCarManager(CarPackageManager.class));
+    }
+
+    @Override
+    protected boolean shouldShowWindowDecor(ActivityManager.RunningTaskInfo taskInfo) {
+        return displayCompatibilityCaptionBar()
+                && requiresDisplayCompat(
+                getPackageName(taskInfo), taskInfo.userId, mCarPackageManager)
+                && taskInfo.displayId == DEFAULT_DISPLAY;
+    }
+}
diff --git a/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java b/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
index 5f330ae5..ee390c76 100644
--- a/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
+++ b/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
@@ -27,6 +27,7 @@ import androidx.annotation.NonNull;
 
 import com.android.systemui.car.CarServiceProvider;
 import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.automotive.AutoTaskRepository;
 import com.android.wm.shell.common.SyncTransactionQueue;
 import com.android.wm.shell.fullscreen.FullscreenTaskListener;
 import com.android.wm.shell.recents.RecentTasksController;
@@ -57,42 +58,57 @@ public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
     static final String TAG = CarFullscreenTaskMonitorListener.class.getSimpleName();
     static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
     private final ShellTaskOrganizer mShellTaskOrganizer;
-    private final CarServiceTaskReporter mCarServiceTaskReporter;
+    // TODO(b/395767437): Add task listener for fullscreen and multi window mode in task repository
+    private final AutoTaskRepository mTaskRepository;
     @GuardedBy("mLock")
     private final ArraySet<OnTaskChangeListener> mTaskListeners = new ArraySet<>();
     private final Object mLock = new Object();
 
+    private final Optional<WindowDecorViewModel> mWindowDecorViewModelOptional;
     private final ShellTaskOrganizer.TaskListener mMultiWindowTaskListener =
             new ShellTaskOrganizer.TaskListener() {
                 @Override
                 public void onTaskAppeared(ActivityManager.RunningTaskInfo taskInfo,
                         SurfaceControl leash) {
-                    mCarServiceTaskReporter.reportTaskAppeared(taskInfo, leash);
+                    mTaskRepository.onTaskAppeared(taskInfo, leash);
                     synchronized (mLock) {
                         for (OnTaskChangeListener listener : mTaskListeners) {
                             listener.onTaskAppeared(taskInfo);
                         }
                     }
+                    if (mWindowDecorViewModelOptional.isPresent()) {
+                        SurfaceControl.Transaction t = new SurfaceControl.Transaction();
+                        mWindowDecorViewModelOptional.get().onTaskOpening(taskInfo, leash, t, t);
+                        t.apply();
+                    }
                 }
 
                 @Override
                 public void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
-                    mCarServiceTaskReporter.reportTaskInfoChanged(taskInfo);
+                    mTaskRepository.onTaskChanged(taskInfo);
                     synchronized (mLock) {
                         for (OnTaskChangeListener listener : mTaskListeners) {
                             listener.onTaskInfoChanged(taskInfo);
                         }
                     }
+
+                    if (mWindowDecorViewModelOptional.isPresent()) {
+                        mWindowDecorViewModelOptional.get().onTaskInfoChanged(taskInfo);
+                    }
                 }
 
                 @Override
                 public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
-                    mCarServiceTaskReporter.reportTaskVanished(taskInfo);
+                    mTaskRepository.onTaskVanished(taskInfo);
                     synchronized (mLock) {
                         for (OnTaskChangeListener listener : mTaskListeners) {
                             listener.onTaskVanished(taskInfo);
                         }
                     }
+
+                    if (mWindowDecorViewModelOptional.isPresent()) {
+                        mWindowDecorViewModelOptional.get().destroyWindowDecoration(taskInfo);
+                    }
                 }
             };
 
@@ -104,36 +120,43 @@ public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
             SyncTransactionQueue syncQueue,
             Optional<RecentTasksController> recentTasksOptional,
             Optional<WindowDecorViewModel> windowDecorViewModelOptional,
-            TaskViewTransitions taskViewTransitions) {
+            TaskViewTransitions taskViewTransitions,
+            AutoTaskRepository taskRepository) {
         super(shellInit, shellTaskOrganizer, syncQueue, recentTasksOptional,
-                windowDecorViewModelOptional);
+                windowDecorViewModelOptional, Optional.empty());
         mShellTaskOrganizer = shellTaskOrganizer;
-        mCarServiceTaskReporter = new CarServiceTaskReporter(context, carServiceProvider,
-                taskViewTransitions,
-                shellTaskOrganizer);
+        mTaskRepository = taskRepository;
 
         shellInit.addInitCallback(
                 () -> mShellTaskOrganizer.addListenerForType(mMultiWindowTaskListener,
                         ShellTaskOrganizer.TASK_LISTENER_TYPE_MULTI_WINDOW),
                 this);
+        mWindowDecorViewModelOptional = windowDecorViewModelOptional;
     }
 
     @Override
     public void onTaskAppeared(ActivityManager.RunningTaskInfo taskInfo,
             SurfaceControl leash) {
         super.onTaskAppeared(taskInfo, leash);
-        mCarServiceTaskReporter.reportTaskAppeared(taskInfo, leash);
+        mTaskRepository.onTaskAppeared(taskInfo, leash);
         synchronized (mLock) {
             for (OnTaskChangeListener listener : mTaskListeners) {
                 listener.onTaskAppeared(taskInfo);
             }
         }
+
+        // Show WindowDecor for display compat apps
+        if (mWindowDecorViewModelOptional.isPresent()) {
+            SurfaceControl.Transaction t = new SurfaceControl.Transaction();
+            mWindowDecorViewModelOptional.get().onTaskOpening(taskInfo, leash, t, t);
+            t.apply();
+        }
     }
 
     @Override
     public void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
         super.onTaskInfoChanged(taskInfo);
-        mCarServiceTaskReporter.reportTaskInfoChanged(taskInfo);
+        mTaskRepository.onTaskChanged(taskInfo);
         synchronized (mLock) {
             for (OnTaskChangeListener listener : mTaskListeners) {
                 listener.onTaskInfoChanged(taskInfo);
@@ -144,12 +167,15 @@ public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
     @Override
     public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
         super.onTaskVanished(taskInfo);
-        mCarServiceTaskReporter.reportTaskVanished(taskInfo);
+        mTaskRepository.onTaskVanished(taskInfo);
         synchronized (mLock) {
             for (OnTaskChangeListener listener : mTaskListeners) {
                 listener.onTaskVanished(taskInfo);
             }
         }
+        if (mWindowDecorViewModelOptional.isPresent()) {
+            mWindowDecorViewModelOptional.get().destroyWindowDecoration(taskInfo);
+        }
     }
 
     /**
@@ -183,6 +209,7 @@ public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
          * Gives the information of the task that just changed
          */
         void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo);
+
         /**
          * Gives the information of the task that just vanished
          */
diff --git a/src/com/android/systemui/car/wm/CarServiceTaskReporter.java b/src/com/android/systemui/car/wm/CarServiceTaskReporter.java
deleted file mode 100644
index 9e21552d..00000000
--- a/src/com/android/systemui/car/wm/CarServiceTaskReporter.java
+++ /dev/null
@@ -1,174 +0,0 @@
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
-
-package com.android.systemui.car.wm;
-
-import static com.android.systemui.car.wm.CarFullscreenTaskMonitorListener.DBG;
-import static com.android.systemui.car.wm.CarFullscreenTaskMonitorListener.TAG;
-
-import android.app.ActivityManager;
-import android.car.Car;
-import android.car.app.CarActivityManager;
-import android.content.Context;
-import android.hardware.display.DisplayManager;
-import android.util.Slog;
-import android.view.Display;
-import android.view.SurfaceControl;
-
-import com.android.systemui.car.CarServiceProvider;
-import com.android.wm.shell.ShellTaskOrganizer;
-import com.android.wm.shell.taskview.TaskViewTransitions;
-
-import java.util.ArrayList;
-import java.util.List;
-import java.util.concurrent.atomic.AtomicReference;
-
-/**
- * This class reports the task events to CarService using {@link CarActivityManager}.
- */
-final class CarServiceTaskReporter {
-    private final DisplayManager mDisplayManager;
-    private final AtomicReference<CarActivityManager> mCarActivityManagerRef =
-            new AtomicReference<>();
-    private final boolean mShouldConnectToCarActivityService;
-    private final TaskViewTransitions mTaskViewTransitions;
-    private final ShellTaskOrganizer mShellTaskOrganizer;
-
-    CarServiceTaskReporter(Context context, CarServiceProvider carServiceProvider,
-            TaskViewTransitions taskViewTransitions,
-            ShellTaskOrganizer shellTaskOrganizer) {
-        mDisplayManager = context.getSystemService(DisplayManager.class);
-        mTaskViewTransitions = taskViewTransitions;
-        // Rely on whether or not CarSystemUIProxy should be registered to account for these
-        // cases:
-        // 1. Legacy system where System UI + launcher both register a TaskOrganizer.
-        //    CarFullScreenTaskMonitorListener will not forward the task lifecycle to the car
-        //    service, as launcher has its own FullScreenTaskMonitorListener.
-        // 2. MUMD system where only System UI registers a TaskOrganizer but the user associated
-        //    with the current display is not a system user. CarSystemUIProxy will be registered
-        //    for system user alone and hence CarFullScreenTaskMonitorListener should be
-        //    registered only then.
-        mShouldConnectToCarActivityService = CarSystemUIProxyImpl.shouldRegisterCarSystemUIProxy(
-                context);
-        mShellTaskOrganizer = shellTaskOrganizer;
-
-        if (mShouldConnectToCarActivityService) {
-            carServiceProvider.addListener(this::onCarConnected);
-        }
-    }
-
-    public void reportTaskAppeared(ActivityManager.RunningTaskInfo taskInfo, SurfaceControl leash) {
-        if (!mShouldConnectToCarActivityService) {
-            if (DBG) {
-                Slog.w(TAG, "onTaskAppeared() handled in SystemUI as conditions not met for "
-                        + "connecting to car service.");
-            }
-            return;
-        }
-
-        if (mTaskViewTransitions.isTaskViewTask(taskInfo)) {
-            if (DBG) {
-                Slog.w(TAG, "not reporting onTaskAppeared for taskview task = " + taskInfo.taskId);
-            }
-            return;
-        }
-        CarActivityManager carAM = mCarActivityManagerRef.get();
-        if (carAM != null) {
-            carAM.onTaskAppeared(taskInfo, leash);
-        } else {
-            Slog.w(TAG, "CarActivityManager is null, skip onTaskAppeared: taskInfo=" + taskInfo);
-        }
-    }
-
-    public void reportTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
-        if (!mShouldConnectToCarActivityService) {
-            if (DBG) {
-                Slog.w(TAG, "onTaskInfoChanged() handled in SystemUI as conditions not met for "
-                        + "connecting to car service.");
-            }
-            return;
-        }
-
-        if (mTaskViewTransitions.isTaskViewTask(taskInfo)) {
-            if (DBG) {
-                Slog.w(TAG,
-                        "not reporting onTaskInfoChanged for taskview task = " + taskInfo.taskId);
-            }
-            return;
-        }
-
-        CarActivityManager carAM = mCarActivityManagerRef.get();
-        if (carAM != null) {
-            carAM.onTaskInfoChanged(taskInfo);
-        } else {
-            Slog.w(TAG, "CarActivityManager is null, skip onTaskInfoChanged: taskInfo=" + taskInfo);
-        }
-    }
-
-    public void reportTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
-        if (!mShouldConnectToCarActivityService) {
-            if (DBG) {
-                Slog.w(TAG, "onTaskVanished() handled in SystemUI as conditions not met for "
-                        + "connecting to car service.");
-            }
-            return;
-        }
-
-        if (mTaskViewTransitions.isTaskViewTask(taskInfo)) {
-            if (DBG) {
-                Slog.w(TAG, "not reporting onTaskVanished for taskview task = " + taskInfo.taskId);
-            }
-            return;
-        }
-
-        CarActivityManager carAM = mCarActivityManagerRef.get();
-        if (carAM != null) {
-            carAM.onTaskVanished(taskInfo);
-        } else {
-            Slog.w(TAG, "CarActivityManager is null, skip onTaskVanished: taskInfo=" + taskInfo);
-        }
-    }
-
-    private void onCarConnected(Car car) {
-        mCarActivityManagerRef.set(car.getCarManager(CarActivityManager.class));
-        // The tasks that have already appeared need to be reported to the CarActivityManager.
-        // The code uses null as the leash because there is no way to get the leash at the moment.
-        // And the leash is only required for mirroring cases. Those tasks will anyway appear
-        // after the car service is connected and hence will go via the {@link #onTaskAppeared}
-        // flow.
-        List<ActivityManager.RunningTaskInfo> runningTasks = getRunningNonTaskViewTasks();
-        for (ActivityManager.RunningTaskInfo runningTaskInfo : runningTasks) {
-            Slog.d(TAG, "Sending onTaskAppeared for an already existing task: "
-                    + runningTaskInfo.taskId);
-            mCarActivityManagerRef.get().onTaskAppeared(runningTaskInfo, /* leash = */ null);
-        }
-    }
-
-    private List<ActivityManager.RunningTaskInfo> getRunningNonTaskViewTasks() {
-        Display[] displays = mDisplayManager.getDisplays();
-        List<ActivityManager.RunningTaskInfo> tasksToReturn = new ArrayList<>();
-        for (int i = 0; i < displays.length; i++) {
-            List<ActivityManager.RunningTaskInfo> taskInfos = mShellTaskOrganizer.getRunningTasks(
-                    displays[i].getDisplayId());
-            for (ActivityManager.RunningTaskInfo taskInfo : taskInfos) {
-                if (!mTaskViewTransitions.isTaskViewTask(taskInfo)) {
-                    tasksToReturn.add(taskInfo);
-                }
-            }
-        }
-        return tasksToReturn;
-    }
-}
diff --git a/src/com/android/systemui/car/wm/CarSystemUIProxyImpl.java b/src/com/android/systemui/car/wm/CarSystemUIProxyImpl.java
index 516e598f..5edb826c 100644
--- a/src/com/android/systemui/car/wm/CarSystemUIProxyImpl.java
+++ b/src/com/android/systemui/car/wm/CarSystemUIProxyImpl.java
@@ -45,9 +45,11 @@ import com.android.wm.shell.ShellTaskOrganizer;
 import com.android.wm.shell.common.SyncTransactionQueue;
 import com.android.wm.shell.dagger.WMSingleton;
 import com.android.wm.shell.taskview.TaskViewTransitions;
+import com.android.wm.shell.windowdecor.WindowDecorViewModel;
 
 import java.io.PrintWriter;
 import java.util.List;
+import java.util.Optional;
 
 import javax.inject.Inject;
 
@@ -67,6 +69,7 @@ public final class CarSystemUIProxyImpl
     private final ArraySet<RemoteCarTaskViewServerImpl> mRemoteCarTaskViewServerSet =
             new ArraySet<>();
     private final DisplayManager mDisplayManager;
+    private final Optional<WindowDecorViewModel> mWindowDecorViewModelOptional;
 
     private boolean mConnected;
     private CarActivityManager mCarActivityManager;
@@ -92,17 +95,19 @@ public final class CarSystemUIProxyImpl
     }
 
     @Inject
-    CarSystemUIProxyImpl(
+    public CarSystemUIProxyImpl(
             Context context,
             CarServiceProvider carServiceProvider,
             SyncTransactionQueue syncTransactionQueue,
             ShellTaskOrganizer taskOrganizer,
             TaskViewTransitions taskViewTransitions,
-            DumpManager dumpManager) {
+            DumpManager dumpManager,
+            Optional<WindowDecorViewModel> windowDecorViewModelOptional) {
         mContext = context;
         mTaskOrganizer = taskOrganizer;
         mSyncQueue = syncTransactionQueue;
         mTaskViewTransitions = taskViewTransitions;
+        mWindowDecorViewModelOptional = windowDecorViewModelOptional;
         mDisplayManager = mContext.getSystemService(DisplayManager.class);
         dumpManager.registerDumpable(this);
 
@@ -143,7 +148,9 @@ public final class CarSystemUIProxyImpl
                         mSyncQueue,
                         carTaskViewClient,
                         this,
-                        mTaskViewTransitions, mCarActivityManager);
+                        mTaskViewTransitions,
+                        mCarActivityManager,
+                        mWindowDecorViewModelOptional);
         mRemoteCarTaskViewServerSet.add(remoteCarTaskViewServerImpl);
         return remoteCarTaskViewServerImpl.getHostImpl();
     }
@@ -159,7 +166,6 @@ public final class CarSystemUIProxyImpl
         removeExistingTaskViewTasks();
 
         mCarActivityManager = car.getCarManager(CarActivityManager.class);
-        mCarActivityManager.registerTaskMonitor();
         mCarActivityManager.registerCarSystemUIProxy(this);
     }
 
diff --git a/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java b/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
index efa5cd57..69659bc4 100644
--- a/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
+++ b/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
@@ -489,8 +489,9 @@ public class ActivityBlockingActivity extends FragmentActivity {
     @Override
     protected void onDestroy() {
         super.onDestroy();
-        mCar.disconnect();
-        mUxRManager.unregisterListener();
+        if (mUxRManager != null) {
+            mUxRManager.unregisterListener();
+        }
         mCarPackageManager.unregisterBlockingUiCommandListener(mBlockingUiCommandListener);
         if (mToggleDebug != null) {
             mToggleDebug.getViewTreeObserver().removeOnGlobalLayoutListener(
diff --git a/src/com/android/systemui/car/wm/activity/LaunchOnPrivateDisplayRouterActivity.java b/src/com/android/systemui/car/wm/activity/LaunchOnPrivateDisplayRouterActivity.java
index f5b4362e..e25670f4 100644
--- a/src/com/android/systemui/car/wm/activity/LaunchOnPrivateDisplayRouterActivity.java
+++ b/src/com/android/systemui/car/wm/activity/LaunchOnPrivateDisplayRouterActivity.java
@@ -32,7 +32,7 @@ import com.android.systemui.R;
 public class LaunchOnPrivateDisplayRouterActivity extends Activity {
     private static final String TAG = "LaunchRouterActivity";
     private static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
-    private static final String NAMESPACE_KEY = "com.android.car.app.private_display";
+    private static final String NAMESPACE_KEY = "com.android.car.app.launch_redirect";
     @VisibleForTesting
     static final String LAUNCH_ACTIVITY = NAMESPACE_KEY + ".launch_activity";
     @VisibleForTesting
diff --git a/src/com/android/systemui/car/wm/scalableui/AutoTaskStackHelper.java b/src/com/android/systemui/car/wm/scalableui/AutoTaskStackHelper.java
new file mode 100644
index 00000000..b26c6a22
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/AutoTaskStackHelper.java
@@ -0,0 +1,136 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui;
+
+import android.app.ActivityManager;
+import android.content.ComponentName;
+import android.content.Context;
+import android.util.Log;
+import android.window.WindowContainerTransaction;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.systemui.R;
+import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.dagger.WMSingleton;
+
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+
+import javax.inject.Inject;
+
+@WMSingleton
+public final class AutoTaskStackHelper {
+    private static final String TAG = AutoTaskStackHelper.class.getSimpleName();
+    private static final String DELIMITER = ";";
+    private final ShellTaskOrganizer mShellTaskOrganizer;
+    private final Context mContext;
+    private final Set<ComponentName> mNonTrimmableComponentSet;
+    private final Map<String, ComponentName> mDefaultComponentsMap;
+
+    @Inject
+    public AutoTaskStackHelper(Context context, ShellTaskOrganizer shellTaskOrganizer) {
+        mShellTaskOrganizer = shellTaskOrganizer;
+        mContext = context;
+        mNonTrimmableComponentSet = new HashSet<>();
+        mDefaultComponentsMap = new HashMap<>();
+        initUntrimmableTaskSet();
+        initDefaultTaskMap();
+    }
+
+    /**
+     * Checks if a given running task is trimmable.
+     *
+     * <p> A task is trimmable if it's configured in config_untrimmable_activities
+     */
+    private boolean isTrimmable(@NonNull ActivityManager.RunningTaskInfo task) {
+        return !mNonTrimmableComponentSet.contains(task.baseActivity);
+    }
+
+    /**
+     * Sets a task as trimmable or not - by default this will be true for tasks.
+     */
+    private void setTaskTrimmable(@NonNull ActivityManager.RunningTaskInfo task,
+            boolean trimmable) {
+        WindowContainerTransaction wct = new WindowContainerTransaction();
+        wct.setTaskTrimmableFromRecents(task.token, trimmable);
+        mShellTaskOrganizer.applyTransaction(wct);
+    }
+
+    /**
+     * Retrieves the default {@link ComponentName} associated with a given ID.
+     *
+     * <p> The relationship is defined in config_default_activities.
+     */
+    @Nullable
+    public ComponentName getDefaultIntent(String id) {
+        return mDefaultComponentsMap.get(id);
+    }
+
+    /**
+     * Initializes the default task map from the config_default_activities array.
+     *
+     * <p> The format of the array is as follows:
+     * 1. panel_id;componentname
+     * 2. panel_id;com.example.app/.activity
+     */
+    private void initDefaultTaskMap() {
+        String[] configStrings = mContext.getResources().getStringArray(
+                R.array.config_default_activities);
+        for (int i = configStrings.length - 1; i >= 0; i--) {
+            String[] parts = configStrings[i].split(DELIMITER);
+            if (parts.length == 2) {
+                String key = parts[0].trim(); // Trim whitespace
+                String value = parts[1].trim(); // Trim whitespace
+                mDefaultComponentsMap.put(key, ComponentName.unflattenFromString(value));
+            } else {
+                // Handle cases where the split doesn't result in two parts (e.g., malformed input)
+                Log.e(TAG, "Skipping malformed pair: " + configStrings[i]);
+                // You could choose to throw an exception here, or just continue.
+            }
+        }
+    }
+
+    /**
+     * Initializes the {@code mNonTrimmableComponentSet} tasks from the
+     * config_untrimmable_activities string array resource.
+     */
+    private void initUntrimmableTaskSet() {
+        String[] componentNameStrings = mContext.getResources().getStringArray(
+                R.array.config_untrimmable_activities);
+        for (int i = componentNameStrings.length - 1; i >= 0; i--) {
+            mNonTrimmableComponentSet.add(
+                    ComponentName.unflattenFromString(componentNameStrings[i]));
+        }
+    }
+
+    /**
+     * Sets the given task as untrimmable if it is not already trimmable.
+     *
+     * <p>This method checks if the provided {@link ActivityManager.RunningTaskInfo}
+     * is considered according to config_untrimmable_activities. If the task is *not*
+     * trimmable, it explicitly sets the task's trimmable state to `false`.
+     */
+    public void setTaskUntrimmableIfNeeded(@NonNull ActivityManager.RunningTaskInfo taskInfo) {
+        if (!isTrimmable(taskInfo)) {
+            setTaskTrimmable(taskInfo, /* trimmable= */ false);
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/EventDispatcher.java b/src/com/android/systemui/car/wm/scalableui/EventDispatcher.java
new file mode 100644
index 00000000..0346e0e0
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/EventDispatcher.java
@@ -0,0 +1,90 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui;
+
+import static com.android.systemui.car.Flags.scalableUi;
+import static com.android.wm.shell.Flags.enableAutoTaskStackController;
+
+import android.content.Context;
+
+import com.android.car.scalableui.manager.StateManager;
+import com.android.car.scalableui.model.Event;
+import com.android.car.scalableui.model.PanelTransaction;
+import com.android.systemui.R;
+import com.android.wm.shell.dagger.WMSingleton;
+
+import dagger.Lazy;
+
+import javax.inject.Inject;
+
+/**
+ * Class is responsible for dispatching events to the {@link StateManager} and then potentially
+ * executing the resulting transaction.
+ */
+@WMSingleton
+public class EventDispatcher {
+
+    private final Context mContext;
+    private final TaskPanelTransitionCoordinator mTaskPanelTransitionCoordinator;
+
+    @Inject
+    public EventDispatcher(Context context,
+            Lazy<TaskPanelTransitionCoordinator> taskPanelTransitionCoordinator) {
+        mContext = context;
+        if (isScalableUIEnabled()) {
+            mTaskPanelTransitionCoordinator = taskPanelTransitionCoordinator.get();
+        } else {
+            mTaskPanelTransitionCoordinator = null;
+        }
+    }
+
+    /**
+     * See {@link #getTransaction(Event)}
+     */
+    public static PanelTransaction getTransaction(String event) {
+        return getTransaction(new Event.Builder(event).build());
+    }
+
+    /**
+     * Retrieve a panel transaction describing the provided event parameter.
+     */
+    public static PanelTransaction getTransaction(Event event) {
+        return StateManager.handleEvent(event);
+    }
+
+    /**
+     * See {@link #executeTransaction(Event)}
+     */
+    public void executeTransaction(String event) {
+        executeTransaction(new Event.Builder(event).build());
+    }
+
+    /**
+     * Retrieve a panel transaction for a given event and then immediately execute this
+     * transaction.
+     */
+    public void executeTransaction(Event event) {
+        if (!isScalableUIEnabled()) {
+            throw new IllegalStateException("ScalableUI disabled - cannot execute transaction");
+        }
+        mTaskPanelTransitionCoordinator.startTransition(getTransaction(event));
+    }
+
+    private boolean isScalableUIEnabled() {
+        return scalableUi() && enableAutoTaskStackController()
+                && mContext.getResources().getBoolean(R.bool.config_enableScalableUI);
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegate.java b/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegate.java
new file mode 100644
index 00000000..491e94c5
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegate.java
@@ -0,0 +1,285 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui;
+
+import static android.app.WindowConfiguration.ACTIVITY_TYPE_HOME;
+import static android.view.WindowManager.TRANSIT_FLAG_AVOID_MOVE_TO_FRONT;
+
+import static com.android.systemui.car.Flags.scalableUi;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.COMPONENT_TOKEN_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.EMPTY_EVENT_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PANEL_TOKEN_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_HOME_EVENT_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_CLOSE_EVENT_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_OPEN_EVENT_ID;
+
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.graphics.Rect;
+import android.os.Build;
+import android.os.IBinder;
+import android.util.Log;
+import android.view.SurfaceControl;
+import android.window.TransitionInfo;
+import android.window.TransitionRequestInfo;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.car.internal.dep.Trace;
+import com.android.car.scalableui.model.Event;
+import com.android.car.scalableui.model.PanelTransaction;
+import com.android.car.scalableui.panel.Panel;
+import com.android.systemui.R;
+import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
+import com.android.wm.shell.automotive.AutoTaskStackController;
+import com.android.wm.shell.automotive.AutoTaskStackState;
+import com.android.wm.shell.automotive.AutoTaskStackTransaction;
+import com.android.wm.shell.automotive.AutoTaskStackTransitionHandlerDelegate;
+import com.android.wm.shell.shared.TransitionUtil;
+import com.android.wm.shell.transition.Transitions;
+
+import java.util.Map;
+
+import javax.inject.Inject;
+
+/**
+ * Delegate implementation for handling auto task stack transitions using {@link Panel}.
+ */
+public class PanelAutoTaskStackTransitionHandlerDelegate implements
+        AutoTaskStackTransitionHandlerDelegate {
+    private static final String TAG =
+            PanelAutoTaskStackTransitionHandlerDelegate.class.getSimpleName();
+
+    private static final Event EMPTY_EVENT = new Event.Builder(EMPTY_EVENT_ID).build();
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
+
+    private final AutoTaskStackController mAutoTaskStackController;
+    private final TaskPanelTransitionCoordinator mTaskPanelTransitionCoordinator;
+    private final Context mContext;
+    private final PanelUtils mPanelUtils;
+    private final TaskPanelInfoRepository mTaskPanelInfoRepository;
+
+    @Inject
+    public PanelAutoTaskStackTransitionHandlerDelegate(
+            Context context,
+            AutoTaskStackController autoTaskStackController,
+            TaskPanelTransitionCoordinator taskPanelTransitionCoordinator,
+            PanelUtils panelUtils,
+            TaskPanelInfoRepository taskPanelInfoRepository
+    ) {
+        mAutoTaskStackController = autoTaskStackController;
+        mTaskPanelTransitionCoordinator = taskPanelTransitionCoordinator;
+        mContext = context;
+        mPanelUtils = panelUtils;
+        mTaskPanelInfoRepository = taskPanelInfoRepository;
+    }
+
+    /**
+     * Init the {@link PanelAutoTaskStackTransitionHandlerDelegate}.
+     */
+    public void init() {
+        if (scalableUi() && mContext.getResources().getBoolean(R.bool.config_enableScalableUI)) {
+            Log.i(TAG, "ScalableUI is enabled");
+            mAutoTaskStackController.setAutoTransitionHandlerDelegate(this);
+        }
+    }
+
+    @Nullable
+    @Override
+    public AutoTaskStackTransaction handleRequest(@NonNull IBinder transition,
+            @NonNull TransitionRequestInfo request) {
+        Trace.beginSection(TAG + "#handleRequest");
+        if (DEBUG) {
+            Log.d(TAG, "handleRequest: " + request);
+        }
+
+        if (shouldHandleByPanels(request)) {
+            Event event = calculateEvent(request);
+            PanelTransaction panelTransaction = EventDispatcher.getTransaction(event);
+            AutoTaskStackTransaction wct =
+                    mTaskPanelTransitionCoordinator.createAutoTaskStackTransaction(transition,
+                            panelTransaction);
+            if (DEBUG) {
+                Log.d(TAG, "handleRequest: COMPLETED " + wct);
+            }
+            Trace.endSection();
+            return wct;
+        }
+        Trace.endSection();
+        return null;
+    }
+
+    private boolean shouldHandleByPanels(@NonNull TransitionRequestInfo request) {
+        if (request.getTriggerTask() == null) {
+            return false;
+        }
+        return mPanelUtils.handles(request.getTriggerTask().parentTaskId)
+                || request.getTriggerTask().topActivityType == ACTIVITY_TYPE_HOME;
+    }
+
+    @Override
+    public boolean startAnimation(@NonNull IBinder transition,
+            @NonNull Map<Integer, AutoTaskStackState> changedTaskStacks,
+            @NonNull TransitionInfo info,
+            @NonNull SurfaceControl.Transaction startTransaction,
+            @NonNull SurfaceControl.Transaction finishTransaction,
+            @NonNull Transitions.TransitionFinishCallback finishCallback) {
+        if (DEBUG) {
+            Log.d(TAG, "startAnimation INFO = " + info
+                    + ", changedTaskStacks=" + changedTaskStacks
+                    + ", start transaction=" + startTransaction.getId()
+                    + ", finishTransaction=" + finishTransaction.getId());
+        }
+
+        mTaskPanelTransitionCoordinator.maybeResolveConflict(changedTaskStacks, transition);
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+
+        Trace.beginSection(TAG + "#startAnimation");
+
+        calculateTransaction(startTransaction, info, /* isFinish= */ false);
+        calculateTransaction(finishTransaction, info, /* isFinish= */ true);
+        startTransaction.apply();
+
+        boolean animationStarted = mTaskPanelTransitionCoordinator.playPendingAnimations(transition,
+                finishCallback);
+        Trace.endSection();
+        return animationStarted;
+    }
+
+    private void calculateTransaction(SurfaceControl.Transaction transaction,
+            @NonNull TransitionInfo info, boolean isFinish) {
+        SurfaceControl leash = null;
+        Rect pos = null;
+        for (TransitionInfo.Change change : info.getChanges()) {
+            if (change.getTaskInfo() == null) {
+                continue;
+            }
+            TaskPanel taskPanel = mPanelUtils.getTaskPanel(
+                    tp -> tp.getRootTaskId() == change.getTaskInfo().taskId);
+            if (taskPanel == null) {
+                continue;
+            }
+
+            leash = change.getLeash();
+            if (isFinish) {
+                pos = change.getEndAbsBounds();
+            } else {
+                pos = change.getStartAbsBounds();
+            }
+            transaction.setPosition(leash, pos.left, pos.top);
+            transaction.setCornerRadius(leash, taskPanel.getCornerRadius());
+            taskPanel.setLeash(leash);
+
+            transaction.setLayer(leash, taskPanel.getLayer());
+        }
+    }
+
+    private Event calculateEvent(TransitionRequestInfo request) {
+        if (request.getTriggerTask() == null) {
+            return EMPTY_EVENT;
+        }
+
+        if (request.getTriggerTask().baseIntent.getCategories() != null
+                && request.getTriggerTask().baseIntent.getCategories().contains(
+                Intent.CATEGORY_HOME)) {
+            ComponentName component = request.getTriggerTask().baseActivity;
+            String componentString = component != null ? component.flattenToString() : null;
+            return new Event.Builder(SYSTEM_HOME_EVENT_ID).addToken(COMPONENT_TOKEN_ID,
+                    componentString).build();
+        }
+
+        if ((request.getFlags() & TRANSIT_FLAG_AVOID_MOVE_TO_FRONT)
+                == TRANSIT_FLAG_AVOID_MOVE_TO_FRONT) {
+            if (DEBUG) {
+                Log.d(TAG, "Launching activity to the background, no panel action needed.");
+            }
+            return EMPTY_EVENT;
+        }
+
+        ComponentName component;
+        if (TransitionUtil.isClosingType(request.getType())) {
+            // On a closing event, the baseActivity may be null but the realActivity will still
+            // return the component being closed.
+            component = request.getTriggerTask().realActivity;
+            if (DEBUG) {
+                Log.d(TAG, "Closing transition - using realActivity component=" + component);
+            }
+        } else {
+            component = request.getTriggerTask().baseActivity;
+            if (DEBUG) {
+                Log.d(TAG, "Open transition - using baseActivity component=" + component);
+            }
+        }
+        String componentString = component != null ? component.flattenToString() : null;
+        String panelId;
+        TaskPanel panel = null;
+        if (componentString != null) {
+            panel = mPanelUtils.getTaskPanel(tp -> tp.handles(component));
+        }
+        if (panel == null) {
+            panel = mPanelUtils.getTaskPanel(TaskPanel::isLaunchRoot);
+        }
+        if (panel != null) {
+            panelId = panel.getPanelId();
+        } else {
+            // There is no panel ready to handle this event
+            // TODO(b/392694590): determine if/how this case should be handled
+            Log.e(TAG, "No panel present to handle component " + component);
+            return EMPTY_EVENT;
+        }
+
+        if (TransitionUtil.isClosingType(request.getType())) {
+            return new Event.Builder(SYSTEM_TASK_CLOSE_EVENT_ID)
+                    .addToken(PANEL_TOKEN_ID, panelId)
+                    .addToken(COMPONENT_TOKEN_ID, componentString)
+                    .build();
+        }
+        return new Event.Builder(SYSTEM_TASK_OPEN_EVENT_ID)
+                .addToken(PANEL_TOKEN_ID, panelId)
+                .addToken(COMPONENT_TOKEN_ID, componentString)
+                .build();
+    }
+
+    @Override
+    public void onTransitionConsumed(@NonNull IBinder transition,
+            @NonNull Map<Integer, AutoTaskStackState> changedTaskStacks, boolean aborted,
+            @Nullable SurfaceControl.Transaction finishTransaction) {
+        if (DEBUG) {
+            Log.d(TAG, "onTransitionConsumed=" + aborted);
+        }
+        Trace.beginSection(TAG + "#onTransitionConsumed");
+        mTaskPanelTransitionCoordinator.stopRunningAnimations();
+        Trace.endSection();
+    }
+
+    @Override
+    public void mergeAnimation(@NonNull IBinder transition,
+            @NonNull Map<Integer, AutoTaskStackState> changedTaskStacks,
+            @NonNull TransitionInfo info, @NonNull SurfaceControl.Transaction t,
+            @NonNull IBinder mergeTarget,
+            @NonNull Transitions.TransitionFinishCallback finishCallback) {
+        if (DEBUG) {
+            Log.d(TAG, "mergeAnimation");
+        }
+        Trace.beginSection(TAG + "#mergeAnimation");
+        mTaskPanelTransitionCoordinator.stopRunningAnimations();
+        Trace.endSection();
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/PanelConfigReader.java b/src/com/android/systemui/car/wm/scalableui/PanelConfigReader.java
new file mode 100644
index 00000000..8bc71b9e
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/PanelConfigReader.java
@@ -0,0 +1,88 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui;
+
+import android.app.ActivityManager;
+import android.content.Context;
+import android.content.res.Resources;
+import android.content.res.TypedArray;
+import android.os.Build;
+import android.util.Log;
+
+import com.android.car.internal.dep.Trace;
+import com.android.car.scalableui.manager.StateManager;
+import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.panel.PanelPool;
+import com.android.systemui.R;
+import com.android.systemui.car.wm.scalableui.panel.DecorPanel;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
+import com.android.wm.shell.dagger.WMSingleton;
+
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+@WMSingleton
+public class PanelConfigReader {
+    private static final String TAG = PanelConfigReader.class.getSimpleName();
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
+    private final Context mContext;
+    private final TaskPanel.Factory mTaskPanelFactory;
+    private final DecorPanel.Factory mDecorPanelFactory;
+
+    public PanelConfigReader(Context context, TaskPanel.Factory taskPanelFactory,
+            DecorPanel.Factory decorPanelFactory) {
+        if (DEBUG) {
+            Log.d(TAG, "PanelConfig initialized user: " + ActivityManager.getCurrentUser());
+        }
+        mContext = context;
+        mTaskPanelFactory = taskPanelFactory;
+        mDecorPanelFactory = decorPanelFactory;
+    }
+
+    /**
+     * Init the Panels.
+     */
+    public void init() {
+        PanelPool.getInstance().clearPanels();
+        PanelPool.getInstance().setDelegate(id -> {
+            if (id.startsWith(PanelState.DECOR_PANEL_ID_PREFIX)) {
+                return mDecorPanelFactory.create(id);
+            } else {
+                return mTaskPanelFactory.create(id);
+            }
+        });
+
+        try {
+            Trace.beginSection(TAG + "#init");
+            Resources res = mContext.getResources();
+            StateManager.clearStates();
+            try (TypedArray states = res.obtainTypedArray(R.array.window_states)) {
+                for (int i = 0; i < states.length(); i++) {
+                    int xmlResId = states.getResourceId(i, 0);
+                    if (DEBUG) {
+                        Log.d(TAG, "PanelConfig adding state: " + xmlResId);
+                    }
+                    StateManager.addState(mContext, xmlResId);
+                }
+            }
+        } catch (XmlPullParserException | IOException e) {
+            throw new RuntimeException(e);
+        } finally {
+            Trace.endSection();
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/ScalableUIWMInitializer.java b/src/com/android/systemui/car/wm/scalableui/ScalableUIWMInitializer.java
new file mode 100644
index 00000000..a695464a
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/ScalableUIWMInitializer.java
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui;
+
+import com.android.wm.shell.dagger.WMSingleton;
+import com.android.wm.shell.sysui.ShellInit;
+
+/**
+ * Class to include ScalableUI constructs that need to be initialized on startup.
+ */
+@WMSingleton
+public class ScalableUIWMInitializer {
+    private final PanelConfigReader mPanelConfigReader;
+    private final PanelAutoTaskStackTransitionHandlerDelegate
+            mPanelAutoTaskStackTransitionHandlerDelegate;
+
+    public ScalableUIWMInitializer(ShellInit shellInit,
+            PanelConfigReader panelConfigReader,
+            PanelAutoTaskStackTransitionHandlerDelegate delegate) {
+        shellInit.addInitCallback(this::onInit, this);
+        mPanelConfigReader = panelConfigReader;
+        mPanelAutoTaskStackTransitionHandlerDelegate = delegate;
+    }
+
+    private void onInit() {
+        mPanelAutoTaskStackTransitionHandlerDelegate.init();
+        mPanelConfigReader.init();
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinator.java b/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinator.java
new file mode 100644
index 00000000..7a4e6962
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinator.java
@@ -0,0 +1,417 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui;
+
+import static android.view.WindowInsets.Type.systemOverlays;
+
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PANEL_TOKEN_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_CLOSE_EVENT_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_OPEN_EVENT_ID;
+
+import android.animation.Animator;
+import android.animation.AnimatorListenerAdapter;
+import android.animation.AnimatorSet;
+import android.animation.ValueAnimator;
+import android.graphics.Rect;
+import android.os.Build;
+import android.os.IBinder;
+import android.util.Log;
+import android.view.SurfaceControl;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
+
+import com.android.car.internal.dep.Trace;
+import com.android.car.scalableui.manager.StateManager;
+import com.android.car.scalableui.model.Event;
+import com.android.car.scalableui.model.PanelTransaction;
+import com.android.car.scalableui.model.Transition;
+import com.android.car.scalableui.model.Variant;
+import com.android.car.scalableui.panel.Panel;
+import com.android.car.scalableui.panel.PanelPool;
+import com.android.systemui.car.wm.scalableui.panel.DecorPanel;
+import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
+import com.android.wm.shell.automotive.AutoLayoutManager;
+import com.android.wm.shell.automotive.AutoSurfaceTransaction;
+import com.android.wm.shell.automotive.AutoSurfaceTransactionFactory;
+import com.android.wm.shell.automotive.AutoTaskStackController;
+import com.android.wm.shell.automotive.AutoTaskStackState;
+import com.android.wm.shell.automotive.AutoTaskStackTransaction;
+import com.android.wm.shell.dagger.WMSingleton;
+import com.android.wm.shell.transition.Transitions;
+
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+import javax.annotation.concurrent.GuardedBy;
+import javax.inject.Inject;
+
+/**
+ * Manages the state transitions of the UI panels.
+ * This class is responsible for creating AutoTaskStackTransaction and queuing up panel animations
+ * based on event triggers and then applying visual updates to panels based on their current state.
+ */
+@WMSingleton
+public class TaskPanelTransitionCoordinator {
+    private static final String TAG = TaskPanelTransitionCoordinator.class.getName();
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
+    private static final String DECOR_TRANSACTION = "DECOR_TRANSACTION";
+
+    private final AutoTaskStackController mAutoTaskStackController;
+    @GuardedBy("mPendingPanelTransactions")
+    private final HashMap<IBinder, PanelTransaction> mPendingPanelTransactions = new HashMap<>();
+    private AnimatorSet mRunningAnimatorSet = null;
+    private final AutoSurfaceTransactionFactory mAutoSurfaceTransactionFactory;
+    private final PanelUtils mPanelUtils;
+    private final AutoLayoutManager mAutoLayoutManager;
+
+    @Inject
+    public TaskPanelTransitionCoordinator(AutoTaskStackController autoTaskStackController,
+            AutoSurfaceTransactionFactory autoSurfaceTransactionFactory,
+            PanelUtils panelUtils, AutoLayoutManager autoLayoutManager) {
+        mAutoTaskStackController = autoTaskStackController;
+        mAutoSurfaceTransactionFactory = autoSurfaceTransactionFactory;
+        mPanelUtils = panelUtils;
+        mAutoLayoutManager = autoLayoutManager;
+    }
+
+    /**
+     * Start a new transition for a given {@link PanelTransaction}
+     */
+    public void startTransition(PanelTransaction transaction) {
+        synchronized (mPendingPanelTransactions) {
+            Log.d(TAG, "startTransition:" + transaction);
+            updateDecorPanelByTransition(transaction);
+            IBinder transition = mAutoTaskStackController.startTransition(
+                    createAutoTaskStackTransaction(transaction));
+            mPendingPanelTransactions.put(transition, transaction);
+        }
+    }
+
+    private void updateDecorPanelByTransition(PanelTransaction panelTransaction) {
+        AutoSurfaceTransaction autoSurfaceTransaction =
+                mAutoSurfaceTransactionFactory.createTransaction(DECOR_TRANSACTION);
+        for (Map.Entry<String, Transition> entry : panelTransaction.getPanelTransactionStates()) {
+            Panel panel = PanelPool.getInstance().getPanel(
+                    p -> p.getPanelId().equals(entry.getKey()));
+            if (panel == null) {
+                if (DEBUG) {
+                    Log.d(TAG, "Panel is null for " + entry.getKey());
+                }
+                continue;
+            }
+            Transition transition = entry.getValue();
+            Variant toVariant = transition.getToVariant();
+            if (panel instanceof DecorPanel decorPanel && decorPanel.getAutoDecor() != null) {
+                if (DEBUG) {
+                    Log.d(TAG, "move decorPanel=" + decorPanel.getPanelId() + " to"
+                            + toVariant.getBounds() + " layer=" + toVariant.getLayer()
+                            + " visible=" + toVariant.isVisible());
+                }
+                autoSurfaceTransaction.setBounds(decorPanel.getAutoDecor(), toVariant.getBounds());
+                autoSurfaceTransaction.setVisibility(decorPanel.getAutoDecor(),
+                        toVariant.isVisible());
+                autoSurfaceTransaction.setZOrder(decorPanel.getAutoDecor(), toVariant.getLayer());
+            }
+        }
+        autoSurfaceTransaction.apply();
+    }
+
+    /**
+     * This is a medium-term workaround to resolve the transition conflicts for cts purpose.
+     *
+     * <p>Transition conflicts arise when multiple intents occur rapidly, leading to
+     * {@code handleRequest} only processing the initial intent. Subsequent intents are handled
+     * directly by the Window Manager without invoking the {@code handleRequest} callback. Due to
+     * missing task info, window state corrections are limited to scenarios where the launch root
+     * task has changed. This change is interpreted as either a task open or close event, determined
+     * by the visibility change.
+     * TODO(b/397527431) : handle transition conflicts correctly after b/388067743.
+     */
+    public void maybeResolveConflict(Map<Integer, AutoTaskStackState> changedTaskStacks,
+            IBinder transition) {
+        PanelTransaction transaction = null;
+        synchronized (mPendingPanelTransactions) {
+            transaction = mPendingPanelTransactions.get(transition);
+        }
+
+        for (Map.Entry<Integer, AutoTaskStackState> entry : changedTaskStacks.entrySet()) {
+            int autoTaskStackId = entry.getKey();
+            TaskPanel tp = mPanelUtils.getTaskPanel(taskPanel ->
+                    taskPanel.getRootStack() != null
+                            && taskPanel.getRootStack().getId() == autoTaskStackId);
+            if (tp == null || !tp.isLaunchRoot()) {
+                if (DEBUG) {
+                    Log.d(TAG, "Panel is null or not launch root" + tp);
+                }
+                continue;
+            }
+
+            // If there is no recorded pending transaction for the changed rootTask, treat it as
+            // conflict.
+            AutoTaskStackState changedState = entry.getValue();
+            boolean findConflict = transaction == null
+                    || !isEqual(changedState,
+                    transaction.getPanelTransactionState(tp.getPanelId()));
+            if (findConflict) {
+                Log.e(TAG, "Transition conflicts found on launch root task - " + changedState);
+                Event event = new Event.Builder(
+                        changedState.getChildrenTasksVisible() ? SYSTEM_TASK_OPEN_EVENT_ID
+                                : SYSTEM_TASK_CLOSE_EVENT_ID)
+                        .addToken(PANEL_TOKEN_ID, tp.getPanelId())
+                        .build();
+                PanelTransaction panelTransaction = StateManager.handleEvent(event);
+                mAutoTaskStackController.startTransition(
+                        createAutoTaskStackTransaction(panelTransaction));
+            }
+        }
+    }
+
+    private boolean isEqual(@NonNull AutoTaskStackState changedState,
+            @Nullable Transition panelTransition) {
+        if (panelTransition == null) {
+            return false;
+        }
+        Variant toVariant = panelTransition.getToVariant();
+        return changedState.getChildrenTasksVisible() == toVariant.isVisible()
+                && changedState.getLayer() == toVariant.getLayer()
+                && changedState.getBounds().equals(toVariant.getBounds());
+    }
+
+    /**
+     * Create a AutoTaskStackTransaction for a given PanelTransaction and set the appropriate
+     * pending animators.
+     */
+    AutoTaskStackTransaction createAutoTaskStackTransaction(IBinder transition,
+            PanelTransaction panelTransaction) {
+        AutoTaskStackTransaction autoTaskStackTransaction = createAutoTaskStackTransaction(
+                panelTransaction);
+
+        synchronized (mPendingPanelTransactions) {
+            mPendingPanelTransactions.put(transition, panelTransaction);
+        }
+        return autoTaskStackTransaction;
+    }
+
+    /**
+     * Plays the animation in the pending list.
+     *
+     * @return true if any animations were started
+     */
+    boolean playPendingAnimations(IBinder transition,
+            @Nullable Transitions.TransitionFinishCallback finishCallback) {
+        PanelTransaction panelTransaction;
+        synchronized (mPendingPanelTransactions) {
+            panelTransaction = mPendingPanelTransactions.get(transition);
+        }
+        if (panelTransaction == null || panelTransaction.getAnimators().isEmpty()) {
+            if (DEBUG) {
+                Log.d(TAG, "No animations for transition " + transition);
+            }
+            return false;
+        }
+        if (DEBUG) {
+            Log.d(TAG, "playPendingAnimations: " + panelTransaction.getAnimators().size());
+        }
+        Trace.beginSection(TAG + "#playPendingAnimations");
+        stopRunningAnimations();
+
+        mRunningAnimatorSet = new AnimatorSet();
+
+        long totalDuration = Long.MIN_VALUE;
+        List<Animator> animationToRun = new ArrayList<>();
+        for (Map.Entry<String, Animator> entry : panelTransaction.getAnimators()) {
+            Animator animator = entry.getValue();
+            totalDuration = Math.max(totalDuration, animator.getTotalDuration());
+            animationToRun.add(animator);
+        }
+        animationToRun.add(createSurfaceAnimator(totalDuration, panelTransaction.getAnimators()));
+        mRunningAnimatorSet.playTogether(animationToRun);
+        mRunningAnimatorSet.addListener(new AnimatorListenerAdapter() {
+            @Override
+            public void onAnimationStart(Animator animation) {
+                Trace.beginSection(TAG + "#onAnimationStart");
+                super.onAnimationStart(animation);
+                if (panelTransaction.getAnimationStartCallbackRunnable() != null) {
+                    panelTransaction.getAnimationStartCallbackRunnable().run();
+                }
+                Trace.endSection();
+            }
+
+            @Override
+            public void onAnimationEnd(Animator animation) {
+                Trace.beginSection(TAG + "#onAnimationEnd");
+                super.onAnimationEnd(animation);
+                if (DEBUG) {
+                    Log.d(TAG, "Animation set finished " + finishCallback);
+                }
+                if (finishCallback != null) {
+                    if (DEBUG) {
+                        Log.d(TAG, "Finish the transition");
+                    }
+                    finishCallback.onTransitionFinished(/* wct= */ null);
+                }
+                synchronized (mPendingPanelTransactions) {
+                    mPendingPanelTransactions.remove(transition);
+                }
+                if (panelTransaction.getAnimationEndCallbackRunnable() != null) {
+                    panelTransaction.getAnimationEndCallbackRunnable().run();
+                }
+                Trace.endSection();
+            }
+        });
+        mRunningAnimatorSet.start();
+        Trace.endSection();
+        return true;
+    }
+
+    /**
+     * Ends any running animations associated with this instance.
+     */
+    void stopRunningAnimations() {
+        if (isAnimationRunning()) {
+            if (DEBUG) {
+                Log.d(TAG, "stopRunningAnimations: has running animatorSet "
+                        + mRunningAnimatorSet.getCurrentPlayTime());
+            }
+            mRunningAnimatorSet.end();
+        }
+    }
+
+    @VisibleForTesting
+    boolean isAnimationRunning() {
+        return mRunningAnimatorSet != null && mRunningAnimatorSet.isRunning();
+    }
+
+    @VisibleForTesting
+    PanelTransaction getPendingPanelTransaction(IBinder transition) {
+        synchronized (mPendingPanelTransactions) {
+            return mPendingPanelTransactions.get(transition);
+        }
+    }
+
+    private AutoTaskStackTransaction createAutoTaskStackTransaction(
+            PanelTransaction panelTransaction) {
+        AutoTaskStackTransaction autoTaskStackTransaction = new AutoTaskStackTransaction();
+
+        for (Map.Entry<String, Transition> entry :
+                panelTransaction.getPanelTransactionStates()) {
+            Transition transition = entry.getValue();
+            Variant toVariant = transition.getToVariant();
+            TaskPanel taskPanel = mPanelUtils.getTaskPanel(
+                    p -> p.getRootStack() != null && p.getPanelId().equals(entry.getKey()));
+            if (taskPanel == null) {
+                continue;
+            }
+            AutoTaskStackState autoTaskStackState = new AutoTaskStackState(
+                    toVariant.getBounds(),
+                    toVariant.isVisible(),
+                    toVariant.getLayer());
+            autoTaskStackTransaction.setTaskStackState(taskPanel.getRootStack().getId(),
+                    autoTaskStackState);
+        }
+
+        return autoTaskStackTransaction;
+    }
+
+    private ValueAnimator createSurfaceAnimator(long duration,
+            @NonNull Set<Map.Entry<String, Animator>> animators) {
+        ValueAnimator surfaceAnimator = ValueAnimator.ofFloat(0, 1f);
+        surfaceAnimator.setDuration(duration);
+        surfaceAnimator.addUpdateListener(animation -> {
+            Trace.beginSection(TAG + "#updatePanelSurface");
+            AutoSurfaceTransaction autoSurfaceTransaction =
+                    mAutoSurfaceTransactionFactory.createTransaction(DECOR_TRANSACTION);
+            SurfaceControl.Transaction tx = new SurfaceControl.Transaction();
+            for (Map.Entry<String, Animator> entry : animators) {
+                String id = entry.getKey();
+                if (DEBUG) {
+                    Log.d(TAG, "panelTransaction: " + id);
+                }
+                Panel panel = PanelPool.getInstance().getPanel(p -> p.getPanelId().equals(id));
+                if (panel instanceof TaskPanel taskPanel) {
+                    updatePanelSurface(taskPanel, tx);
+                } else if (panel instanceof DecorPanel decorPanel) {
+                    updateDecorPanelSurface(decorPanel, autoSurfaceTransaction);
+                }
+            }
+
+            //TODO(b/404959846): migrate to autoSurfaceTransaction here once api is added.
+            tx.apply();
+            autoSurfaceTransaction.apply();
+            Trace.endSection();
+        });
+        return surfaceAnimator;
+    }
+
+    private void updateDecorPanelSurface(DecorPanel decorPanel,
+            AutoSurfaceTransaction autoSurfaceTransaction) {
+        if (decorPanel.getAutoDecor() == null) {
+            Log.e(TAG, "AutoDecor is null for " + decorPanel);
+            return;
+        }
+        Log.d(TAG, "updateDecorPanelSurface:" + decorPanel);
+        autoSurfaceTransaction.setBounds(decorPanel.getAutoDecor(), decorPanel.getBounds());
+        autoSurfaceTransaction.setVisibility(decorPanel.getAutoDecor(), decorPanel.isVisible());
+        autoSurfaceTransaction.setZOrder(decorPanel.getAutoDecor(), decorPanel.getLayer());
+    }
+
+    private void updatePanelSurface(TaskPanel taskPanel, SurfaceControl.Transaction tx) {
+        SurfaceControl sc = taskPanel.getLeash();
+        if (sc == null) {
+            Log.e(TAG, "leash is null for " + taskPanel);
+            return;
+        }
+
+        if (DEBUG) {
+            Log.d(TAG, "updatePanelSurface:" + taskPanel);
+        }
+        tx.setVisibility(sc, taskPanel.isVisible());
+        tx.setAlpha(sc, taskPanel.getAlpha());
+        tx.setLayer(sc, taskPanel.getLayer());
+        tx.setPosition(sc, taskPanel.getBounds().left, taskPanel.getBounds().top);
+        tx.setWindowCrop(sc, taskPanel.getBounds().width(), taskPanel.getBounds().height());
+        tx.setCornerRadius(sc, taskPanel.getCornerRadius());
+        tx.apply();
+
+        Rect insets = taskPanel.getInsets().toRect();
+        mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(),
+                /* left */ 0, systemOverlays(),
+                new Rect(0, 0, insets.left, taskPanel.getBounds().bottom));
+        mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(),
+                /* top */ 1, systemOverlays(),
+                new Rect(0, 0, taskPanel.getBounds().right, insets.top));
+        mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(),
+                /* right */ 2, systemOverlays(),
+                new Rect(
+                        taskPanel.getBounds().right - insets.right,
+                        0,
+                        taskPanel.getBounds().right,
+                        taskPanel.getBounds().bottom));
+        mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(),
+                /* bottom */ 3, systemOverlays(),
+                new Rect(
+                        0,
+                        taskPanel.getBounds().bottom - insets.bottom,
+                        taskPanel.getBounds().right,
+                        taskPanel.getBounds().bottom));
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/BasePanel.java b/src/com/android/systemui/car/wm/scalableui/panel/BasePanel.java
new file mode 100644
index 00000000..8287eefc
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/panel/BasePanel.java
@@ -0,0 +1,188 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.panel;
+
+import android.content.Context;
+import android.graphics.Insets;
+import android.graphics.Rect;
+import android.os.Build;
+
+import androidx.annotation.NonNull;
+
+import com.android.car.scalableui.panel.Panel;
+
+/**
+ * Abstract base class for implementing a {@link Panel}.
+ *
+ * <p>Provides common functionality and state management for different types of panels
+ */
+public abstract class BasePanel implements Panel {
+    protected static final boolean DEBUG = Build.isDebuggable();
+
+    private final Context mContext;
+    private int mLayer = -1;
+
+    private int mRole = 0;
+    private Rect mBounds = null;
+    private boolean mIsVisible;
+    private String mId;
+    private float mAlpha;
+    private int mDisplayId;
+    private int mCornerRadius;
+    @NonNull
+    private Insets mInsets = Insets.NONE;
+
+    public BasePanel(@NonNull Context context, String id) {
+        mContext = context;
+        mId = id;
+    }
+
+    public Context getContext() {
+        return mContext;
+    }
+
+    public int getRole() {
+        return mRole;
+    }
+
+    public String getId() {
+        return mId;
+    }
+
+    @Override
+    public int getDisplayId() {
+        return mDisplayId;
+    }
+
+    @Override
+    @NonNull
+    public String getPanelId() {
+        return mId;
+    }
+
+    @Override
+    public int getLayer() {
+        return mLayer;
+    }
+
+    @Override
+    public void setLayer(int layer) {
+        this.mLayer = layer;
+    }
+
+    @Override
+    public int getX1() {
+        return mBounds.left;
+    }
+
+    @Override
+    public int getX2() {
+        return mBounds.right;
+    }
+
+    @Override
+    public int getY1() {
+        return mBounds.top;
+    }
+
+    @Override
+    public int getY2() {
+        return mBounds.bottom;
+    }
+
+    @Override
+    public void setX1(int x) {
+        setBounds(new Rect(x, getY1(), getX2(), getY2()));
+    }
+
+    @Override
+    public void setX2(int x) {
+        setBounds(new Rect(getX1(), getY1(), x, getY2()));
+    }
+
+    @Override
+    public void setY1(int y) {
+        setBounds(new Rect(getX1(), y, getX2(), getY2()));
+    }
+
+    @Override
+    public void setY2(int y) {
+        setBounds(new Rect(getX1(), getY1(), getX2(), y));
+    }
+
+    @Override
+    public boolean isVisible() {
+        return mIsVisible;
+    }
+
+    @Override
+    public void setVisibility(boolean isVisible) {
+        if (mIsVisible == isVisible) {
+            return;
+        }
+        mIsVisible = isVisible;
+    }
+
+    @Override
+    public float getAlpha() {
+        return mAlpha;
+    }
+
+    @Override
+    public void setAlpha(float alpha) {
+        mAlpha = alpha;
+    }
+
+    @Override
+    public void setCornerRadius(int radius) {
+        mCornerRadius = radius;
+    }
+
+    @Override
+    public int getCornerRadius() {
+        return mCornerRadius;
+    }
+
+    @Override
+    public void setDisplayId(int displayId) {
+        mDisplayId = displayId;
+    }
+
+    @Override
+    public Rect getBounds() {
+        return mBounds;
+    }
+
+    @Override
+    public void setBounds(Rect bounds) {
+        mBounds = bounds;
+    }
+
+    @Override
+    public void setRole(int role) {
+        mRole = role;
+    }
+
+    @Override
+    public void setInsets(Insets insets) {
+        mInsets = insets;
+    }
+
+    @Override
+    public Insets getInsets() {
+        return mInsets;
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/DecorPanel.java b/src/com/android/systemui/car/wm/scalableui/panel/DecorPanel.java
new file mode 100644
index 00000000..59c7a9c0
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/panel/DecorPanel.java
@@ -0,0 +1,132 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.panel;
+
+import android.content.Context;
+import android.util.Log;
+import android.view.LayoutInflater;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.car.scalableui.panel.Panel;
+import com.android.wm.shell.automotive.AutoDecor;
+import com.android.wm.shell.automotive.AutoDecorManager;
+import com.android.wm.shell.common.ShellExecutor;
+import com.android.wm.shell.shared.annotations.ExternalMainThread;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A {@link AutoDecor} based implementation of a {@link Panel}.
+ */
+public final class DecorPanel extends BasePanel {
+
+    private static final String ROLE_TYPE_LAYOUT = "layout";
+    private static final String TAG = DecorPanel.class.getSimpleName();
+
+    private final AutoDecorManager mAutoDecorManager;
+    private final PanelUtils mPanelUtils;
+    private final ShellExecutor mMainExecutor;
+    private AutoDecor mAutoDecor;
+
+    private View mDecorView;
+
+    @AssistedInject
+    public DecorPanel(@NonNull Context context,
+            AutoDecorManager autoDecorManager,
+            PanelUtils panelUtils,
+            @ExternalMainThread ShellExecutor mainExecutor,
+            @Assisted String id) {
+        super(context, id);
+        mAutoDecorManager = autoDecorManager;
+        mPanelUtils = panelUtils;
+        mMainExecutor = mainExecutor;
+    }
+
+    @Override
+    public void setRole(int role) {
+        if (getRole() == role) return;
+        super.setRole(role);
+    }
+
+    @Nullable
+    private View inflateDecorView() {
+        int role = getRole();
+        String roleTypeName = getContext().getResources().getResourceTypeName(getRole());
+        LayoutInflater inflater = LayoutInflater.from(getContext());
+
+        switch (roleTypeName) {
+            case ROLE_TYPE_LAYOUT:
+                return inflater.inflate(role, null);
+            default:
+                Log.e(TAG, "Unsupported view type" + roleTypeName);
+        }
+        return null;
+    }
+
+    @Override
+    public void init() {
+        if (mPanelUtils.isUserUnlocked()) {
+            reset();
+        }
+    }
+
+    @Override
+    public void reset() {
+        // Only modify the view and window on the main thread to prevent thread-based exceptions
+        mMainExecutor.execute(() -> {
+            // Remove existing autoDecor that holds the view.
+            if (mAutoDecor != null) {
+                mAutoDecorManager.removeAutoDecor(mAutoDecor);
+            }
+            // Reinflate and reattach the view.
+            mDecorView = inflateDecorView();
+            if (mDecorView == null) return;
+            mAutoDecor = mAutoDecorManager.createAutoDecor(mDecorView, getLayer(), getBounds(),
+                    getPanelId());
+            mAutoDecorManager.attachAutoDecorToDisplay(mAutoDecor, getDisplayId());
+        });
+    }
+
+    @Nullable
+    public AutoDecor getAutoDecor() {
+        return mAutoDecor;
+    }
+
+    @AssistedFactory
+    public interface Factory {
+        /** Create instance of {@link DecorPanel} with specified id */
+        DecorPanel create(String id);
+    }
+
+    @Override
+    public String toString() {
+        return "DecorPanel{"
+                + "mId='" + getPanelId() + '\''
+                + ", mLayer=" + getLayer()
+                + ", mRole=" + getRole()
+                + ", mBounds=" + getBounds()
+                + ", mIsVisible=" + isVisible()
+                + ", mAlpha=" + getAlpha()
+                + ", mDisplayId=" + getDisplayId()
+                + ", mCornerRadius=" + getCornerRadius()
+                + ", mDecorView=" + mDecorView + '}';
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/PanelUtils.java b/src/com/android/systemui/car/wm/scalableui/panel/PanelUtils.java
new file mode 100644
index 00000000..7df2501a
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/panel/PanelUtils.java
@@ -0,0 +1,79 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.panel;
+
+import android.app.ActivityManager;
+import android.content.Context;
+import android.os.UserManager;
+
+import androidx.annotation.Nullable;
+
+import com.android.car.scalableui.panel.PanelPool;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.wm.shell.dagger.WMSingleton;
+
+import java.util.function.Predicate;
+
+import javax.inject.Inject;
+
+/**
+ * This utility class provides helper methods for {@link TaskPanel}.
+ */
+@WMSingleton
+public class PanelUtils {
+    private static final String TAG = PanelUtils.class.getSimpleName();
+    private final Context mContext;
+    private final UserManager mUserManager;
+
+    @Inject
+    public PanelUtils(Context context) {
+        mContext = context;
+        mUserManager = mContext.getSystemService(UserManager.class);
+    }
+
+    /**
+     * Checks if any panel in the pool handles the given root task ID.
+     *
+     * @param rootTaskId The root task ID to check.
+     * @return True if a panel with the given root task ID exists in the pool, false otherwise.
+     */
+    public boolean handles(int rootTaskId) {
+        return getTaskPanel(panel -> panel.getRootTaskId() == rootTaskId) != null;
+    }
+
+    /**
+     * Retrieves a {@link TaskPanel} that satisfies the given {@link Predicate}.
+     *
+     * @param predicate The predicate to test against potential {@link TaskPanel} instances.
+     * @return The matching {@link TaskPanel}, or null if none is found.
+     */
+    @Nullable
+    public TaskPanel getTaskPanel(Predicate<TaskPanel> predicate) {
+        return (TaskPanel) PanelPool.getInstance().getPanel(
+                p -> (p instanceof TaskPanel tp) && predicate.test(tp));
+    }
+
+    /**
+     * Checks if the user is unlocked.
+     */
+    public boolean isUserUnlocked() {
+        int userId = CarSystemUIUserUtil.isSecondaryMUMDSystemUI()
+                ? mContext.getUserId()
+                : ActivityManager.getCurrentUser();
+
+        return mUserManager != null && mUserManager.isUserUnlocked(userId);
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/TaskPanel.java b/src/com/android/systemui/car/wm/scalableui/panel/TaskPanel.java
new file mode 100644
index 00000000..8b723003
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/panel/TaskPanel.java
@@ -0,0 +1,354 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.panel;
+
+
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PANEL_TOKEN_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_PANEL_EMPTY_EVENT_ID;
+
+import android.annotation.MainThread;
+import android.app.ActivityManager;
+import android.app.ActivityOptions;
+import android.app.PendingIntent;
+import android.car.app.CarActivityManager;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.os.Build;
+import android.os.UserHandle;
+import android.util.ArraySet;
+import android.util.Log;
+import android.view.SurfaceControl;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
+
+import com.android.car.internal.dep.Trace;
+
+import com.android.car.scalableui.model.Event;
+import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.panel.Panel;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.wm.scalableui.AutoTaskStackHelper;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.wm.shell.automotive.AutoTaskStackController;
+import com.android.wm.shell.automotive.AutoTaskStackState;
+import com.android.wm.shell.automotive.AutoTaskStackTransaction;
+import com.android.wm.shell.automotive.RootTaskStack;
+import com.android.wm.shell.automotive.RootTaskStackListener;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import java.util.Set;
+
+/**
+ * A {@link RootTaskStack} based implementation of a {@link Panel}.
+ */
+public final class TaskPanel extends BasePanel {
+    private static final String TAG = TaskPanel.class.getSimpleName();
+    private static final String ROLE_TYPE_STRING = "string";
+    private static final String ROLE_TYPE_ARRAY = "array";
+    private static final boolean DEBUG = Build.isDebuggable();
+
+    private final AutoTaskStackController mAutoTaskStackController;
+    private final CarServiceProvider mCarServiceProvider;
+    private final Set<ComponentName> mPersistedActivities;
+    private final AutoTaskStackHelper mAutoTaskStackHelper;
+    private final TaskPanelInfoRepository mTaskPanelInfoRepository;
+    private final EventDispatcher mEventDispatcher;
+
+    private CarActivityManager mCarActivityManager;
+    private int mRootTaskId = -1;
+    private SurfaceControl mLeash;
+    private boolean mIsLaunchRoot;
+    private RootTaskStack mRootTaskStack;
+    private PanelUtils mPanelUtils;
+
+    @AssistedInject
+    public TaskPanel(AutoTaskStackController autoTaskStackController,
+            @NonNull Context context,
+            CarServiceProvider carServiceProvider,
+            AutoTaskStackHelper autoTaskStackHelper,
+            PanelUtils panelUtils,
+            TaskPanelInfoRepository taskPanelInfoRepository,
+            EventDispatcher dispatcher,
+            @Assisted String id) {
+        super(context, id);
+        mAutoTaskStackController = autoTaskStackController;
+        mCarServiceProvider = carServiceProvider;
+        mAutoTaskStackHelper = autoTaskStackHelper;
+        mTaskPanelInfoRepository = taskPanelInfoRepository;
+        mEventDispatcher = dispatcher;
+        mPersistedActivities = new ArraySet<>();
+        mPanelUtils = panelUtils;
+    }
+
+    /**
+     * Initializes the panel with the RootTask. This must be called after the state has been set.
+     */
+    @Override
+    public void init() {
+        mCarServiceProvider.addListener(
+                car -> {
+                    mCarActivityManager = car.getCarManager(CarActivityManager.class);
+                    trySetPersistentActivity();
+                });
+
+        mAutoTaskStackController.createRootTaskStack(getDisplayId(), getPanelId(),
+                new RootTaskStackListener() {
+                    @Override
+                    public void onRootTaskStackCreated(@NonNull RootTaskStack rootTaskStack) {
+                        if (DEBUG) {
+                            Log.d(TAG, getPanelId() + ", onRootTaskStackCreated " + rootTaskStack);
+                        }
+                        mRootTaskStack = rootTaskStack;
+                        mRootTaskId = mRootTaskStack.getRootTaskInfo().taskId;
+                        trySetPersistentActivity();
+                        if (mIsLaunchRoot) {
+                            mAutoTaskStackController.setDefaultRootTaskStackOnDisplay(
+                                    getDisplayId(),
+                                    mRootTaskId);
+                        }
+
+                        if (mPanelUtils.isUserUnlocked()) {
+                            reset();
+                        }
+                    }
+
+                    @Override
+                    public void onRootTaskStackInfoChanged(@NonNull RootTaskStack rootTaskStack) {
+                        mRootTaskStack = rootTaskStack;
+                        mRootTaskId = mRootTaskStack.getRootTaskInfo().taskId;
+                    }
+
+                    @Override
+                    public void onRootTaskStackDestroyed(@NonNull RootTaskStack rootTaskStack) {
+                        mRootTaskStack = null;
+                        mRootTaskId = -1;
+                    }
+
+                    @Override
+                    public void onTaskAppeared(ActivityManager.RunningTaskInfo taskInfo,
+                            SurfaceControl leash) {
+                        mAutoTaskStackHelper.setTaskUntrimmableIfNeeded(taskInfo);
+                        mTaskPanelInfoRepository.onTaskAppearedOnPanel(getId(), taskInfo);
+                    }
+
+                    @Override
+                    public void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
+                        mTaskPanelInfoRepository.onTaskChangedOnPanel(getId(), taskInfo);
+                    }
+
+                    @Override
+                    public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
+                        mTaskPanelInfoRepository.onTaskVanishedOnPanel(getId(), taskInfo);
+                        if (mRootTaskStack != null
+                                && mRootTaskStack.getRootTaskInfo().numActivities == 0) {
+                            mEventDispatcher.executeTransaction(new Event.Builder(
+                                    SYSTEM_TASK_PANEL_EMPTY_EVENT_ID).addToken(PANEL_TOKEN_ID,
+                                    getPanelId()).build());
+                        }
+                    }
+                });
+    }
+
+    @Override
+    public void reset() {
+        if (getRootStack() == null) {
+            Log.e(TAG, "Cannot reset when root stack is null for panel" + getPanelId());
+            return;
+        }
+        AutoTaskStackTransaction autoTaskStackTransaction = new AutoTaskStackTransaction();
+        AutoTaskStackState autoTaskStackState = new AutoTaskStackState(getBounds(), isVisible(),
+                getLayer());
+        autoTaskStackTransaction.setTaskStackState(getRootStack().getId(), autoTaskStackState);
+        if (isVisible()) {
+            setBaseIntent(autoTaskStackTransaction);
+        }
+        mAutoTaskStackController.startTransition(autoTaskStackTransaction);
+    }
+
+    private void setBaseIntent(AutoTaskStackTransaction autoTaskStackTransaction) {
+        if (getDefaultIntent() == null || getRootStack().getRootTaskInfo() == null) {
+            return;
+        }
+        Trace.beginSection(TAG + "#setBaseIntent");
+        Intent defaultIntent = getDefaultIntent();
+        ActivityOptions options = ActivityOptions.makeBasic();
+        options.setPendingIntentBackgroundActivityStartMode(
+                ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOW_ALWAYS);
+        options.setLaunchRootTask(getRootStack().getRootTaskInfo().token);
+
+        PendingIntent pendingIntent = PendingIntent.getActivity(
+                getContext().createContextAsUser(UserHandle.CURRENT, 0), 0, defaultIntent,
+                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
+        autoTaskStackTransaction.sendPendingIntent(pendingIntent, defaultIntent,
+                options.toBundle());
+        Trace.endSection();
+    }
+
+    @Nullable
+    public RootTaskStack getRootStack() {
+        return mRootTaskStack;
+    }
+
+    /**
+     * Returns the task ID of the root task associated with this panel.
+     */
+    public int getRootTaskId() {
+        if (mRootTaskStack == null) {
+            return -1;
+        }
+        return mRootTaskStack.getRootTaskInfo().taskId;
+    }
+
+    /**
+     * Returns the default intent associated with this {@link TaskPanel}.
+     *
+     * <p>The default intent will be send right after the TaskPanel is ready.
+     */
+    @Nullable
+    public Intent getDefaultIntent() {
+        ComponentName componentName = mAutoTaskStackHelper.getDefaultIntent(getPanelId());
+        if (componentName == null) {
+            return null;
+        }
+        Intent defaultIntent = new Intent(Intent.ACTION_MAIN);
+        defaultIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        defaultIntent.setComponent(componentName);
+        return defaultIntent;
+    }
+
+    public SurfaceControl getLeash() {
+        return mLeash;
+    }
+
+    public void setLeash(SurfaceControl leash) {
+        mLeash = leash;
+    }
+
+    /**
+     * Return whether this panel is the launch root panel.
+     */
+    public boolean isLaunchRoot() {
+        return mIsLaunchRoot;
+    }
+
+    @Override
+    public void setRole(int role) {
+        if (getRole() == role) return;
+        super.setRole(role);
+        String roleTypeName = getContext().getResources().getResourceTypeName(getRole());
+        switch (roleTypeName) {
+            case ROLE_TYPE_STRING:
+                String roleString = getContext().getResources().getString(getRole());
+                if (PanelState.DEFAULT_ROLE.equals(roleString)) {
+                    mIsLaunchRoot = true;
+                    return;
+                }
+                mPersistedActivities.clear();
+                ComponentName componentName = ComponentName.unflattenFromString(roleString);
+                mPersistedActivities.add(componentName);
+                break;
+            case ROLE_TYPE_ARRAY:
+                mPersistedActivities.clear();
+                String[] componentNameStrings = getContext().getResources().getStringArray(
+                        getRole());
+                mPersistedActivities.addAll(convertToComponentNames(componentNameStrings));
+                break;
+            default: {
+                Log.e(TAG, "Role type is not supported " + roleTypeName);
+            }
+        }
+    }
+
+    private ArraySet<ComponentName> convertToComponentNames(String[] componentStrings) {
+        ArraySet<ComponentName> componentNames = new ArraySet<>(componentStrings.length);
+        for (int i = componentStrings.length - 1; i >= 0; i--) {
+            componentNames.add(ComponentName.unflattenFromString(componentStrings[i]));
+        }
+        return componentNames;
+    }
+
+    private void trySetPersistentActivity() {
+        if (mCarActivityManager == null || mRootTaskStack == null) {
+            if (DEBUG) {
+                Log.d(TAG,
+                        "mCarActivityManager or mRootTaskStack is null, [" + getId() + ","
+                                + mCarActivityManager + ", " + mRootTaskStack + "]");
+            }
+            return;
+        }
+
+        if (getRole() == 0) {
+            if (DEBUG) {
+                Log.d(TAG, "mRole is 0, [" + getPanelId() + "]");
+            }
+            return;
+        }
+
+        if (mIsLaunchRoot) {
+            if (DEBUG) {
+                Log.d(TAG, "mIsLaunchRoot is true, [" + getPanelId() + "]");
+            }
+            return;
+        }
+
+        mCarActivityManager.setPersistentActivitiesOnRootTask(
+                mPersistedActivities.stream().toList(),
+                mRootTaskStack.getRootTaskInfo().token.asBinder());
+    }
+
+    @VisibleForTesting
+    void setRootTaskStack(RootTaskStack rootTaskStack) {
+        mRootTaskStack = rootTaskStack;
+    }
+
+    @Override
+    public String toString() {
+        return "TaskPanel{"
+                + "mId='" + getPanelId() + '\''
+                + ", mAlpha=" + getAlpha()
+                + ", mIsVisible=" + isVisible()
+                + ", mBounds=" + getBounds()
+                + ", mRootTaskId=" + mRootTaskId
+                + ", mContext=" + getContext()
+                + ", mRole=" + getRole()
+                + ", mLayer=" + getLayer()
+                + ", mLeash=" + mLeash
+                + ", mRootTaskStack=" + mRootTaskStack
+                + ", mCornerRadius=" + getCornerRadius()
+                + ", mIsLaunchRoot=" + mIsLaunchRoot
+                + ", mDisplayId=" + getDisplayId()
+                + '}';
+    }
+
+    /**
+     * Checks if the activity with given {@link ComponentName} should show in current panel.
+     */
+    public boolean handles(@Nullable ComponentName componentName) {
+        return componentName != null && mPersistedActivities.contains(componentName);
+    }
+
+    @AssistedFactory
+    public interface Factory {
+        /** Create instance of TaskPanel with specified id */
+        TaskPanel create(String id);
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelInfoRepository.java b/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelInfoRepository.java
new file mode 100644
index 00000000..38ab3192
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelInfoRepository.java
@@ -0,0 +1,222 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.panel;
+
+import android.app.ActivityManager;
+import android.content.ComponentName;
+import android.util.ArraySet;
+
+import com.android.car.scalableui.panel.Panel;
+import com.android.car.scalableui.panel.PanelPool;
+import com.android.systemui.dagger.qualifiers.UiBackground;
+import com.android.wm.shell.dagger.WMSingleton;
+
+import java.util.HashMap;
+import java.util.LinkedHashMap;
+import java.util.Map;
+import java.util.Objects;
+import java.util.Set;
+import java.util.concurrent.Executor;
+
+import javax.annotation.concurrent.GuardedBy;
+import javax.inject.Inject;
+
+@WMSingleton
+public class TaskPanelInfoRepository {
+    private final Object mLock = new Object();
+    @GuardedBy("mLock")
+    private final Map<String, LinkedHashMap<Integer, ActivityManager.RunningTaskInfo>>
+            mPanelTaskMap = new HashMap<>();
+    @GuardedBy("mLock")
+    private final Set<TaskPanelChangeListener> mListeners = new ArraySet<>();
+    private final Executor mUiBackgroundExecutor;
+
+    @GuardedBy("mLock")
+    private boolean mHasPendingTaskChanges = false;
+
+    @Inject
+    public TaskPanelInfoRepository(@UiBackground Executor executor) {
+        mUiBackgroundExecutor = executor;
+    }
+
+    /**
+     * Add a change listener for all panels.
+     */
+    public void addChangeListener(TaskPanelChangeListener listener) {
+        synchronized (mLock) {
+            mListeners.add(listener);
+        }
+    }
+
+    /**
+     * Remove a change listener for all panels.
+     */
+    public void removeChangeListener(TaskPanelChangeListener listener) {
+        synchronized (mLock) {
+            mListeners.remove(listener);
+        }
+    }
+
+    /**
+     * Query if a specific package is currently visible on any panel.
+     */
+    public boolean isPackageVisible(String packageName) {
+        synchronized (mLock) {
+            for (String panelId : mPanelTaskMap.keySet()) {
+                if (mPanelTaskMap.get(panelId).lastEntry() != null
+                        && mPanelTaskMap.get(panelId).lastEntry().getValue().topActivity != null
+                        && Objects.equals(mPanelTaskMap.get(panelId).lastEntry().getValue()
+                        .topActivity.getPackageName(), packageName)) {
+                    return isPanelVisible(panelId);
+                }
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Query if a specific package is currently visible on a specific display.
+     */
+    public boolean isPackageVisibleOnDisplay(String packageName, int displayId) {
+        synchronized (mLock) {
+            for (String panelId : mPanelTaskMap.keySet()) {
+                if (mPanelTaskMap.get(panelId).lastEntry() != null) {
+                    ActivityManager.RunningTaskInfo taskInfo = mPanelTaskMap.get(
+                            panelId).lastEntry().getValue();
+                    if (taskInfo.topActivity != null && Objects.equals(
+                            taskInfo.topActivity.getPackageName(), packageName)
+                            && taskInfo.displayId == displayId) {
+                        return isPanelVisible(panelId);
+                    }
+                }
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Query if a specific component is currently visible.
+     */
+    public boolean isComponentVisible(ComponentName componentName) {
+        synchronized (mLock) {
+            for (String panelId : mPanelTaskMap.keySet()) {
+                if (mPanelTaskMap.get(panelId).lastEntry() != null && Objects.equals(
+                        mPanelTaskMap.get(
+                                panelId).lastEntry().getValue().topActivity, componentName)) {
+                    return isPanelVisible(panelId);
+                }
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Query if a specific component is currently visible on a specific display.
+     */
+    public boolean isComponentVisibleOnDisplay(ComponentName componentName, int displayId) {
+        synchronized (mLock) {
+            for (String panelId : mPanelTaskMap.keySet()) {
+                if (mPanelTaskMap.get(panelId).lastEntry() != null && Objects.equals(
+                        mPanelTaskMap.get(
+                                panelId).lastEntry().getValue().topActivity, componentName)
+                        && mPanelTaskMap.get(panelId).lastEntry().getValue().displayId
+                        == displayId) {
+                    return isPanelVisible(panelId);
+                }
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Query if a specific panel is currently visible.
+     */
+    private boolean isPanelVisible(String panelId) {
+        Panel panel = PanelPool.getInstance().getPanel(panelId);
+        if (panel == null) {
+            return false;
+        }
+        return panel.isVisible();
+    }
+
+    void onTaskAppearedOnPanel(String panelId, ActivityManager.RunningTaskInfo taskInfo) {
+        synchronized (mLock) {
+            if (!mPanelTaskMap.containsKey(panelId)) {
+                mPanelTaskMap.put(panelId, new LinkedHashMap<>());
+            }
+            mPanelTaskMap.get(panelId).put(taskInfo.taskId, taskInfo);
+            mHasPendingTaskChanges = true;
+        }
+    }
+
+    void onTaskChangedOnPanel(String panelId, ActivityManager.RunningTaskInfo taskInfo) {
+        synchronized (mLock) {
+            if (!mPanelTaskMap.containsKey(panelId)) {
+                return;
+            }
+            ActivityManager.RunningTaskInfo oldTask = mPanelTaskMap.get(panelId).get(
+                    taskInfo.taskId);
+            mPanelTaskMap.get(panelId).put(taskInfo.taskId, taskInfo);
+            if ((oldTask == null || !isTaskVisible(oldTask)
+                    || !Objects.equals(oldTask.topActivity, taskInfo.topActivity))
+                    && isTaskVisible(taskInfo)) {
+                mHasPendingTaskChanges = true;
+            }
+        }
+    }
+
+    void onTaskVanishedOnPanel(String panelId, ActivityManager.RunningTaskInfo taskInfo) {
+        synchronized (mLock) {
+            if (!mPanelTaskMap.containsKey(panelId)) {
+                return;
+            }
+            ActivityManager.RunningTaskInfo removed = mPanelTaskMap.get(panelId).remove(
+                    taskInfo.taskId);
+            if (removed == null) {
+                return;
+            }
+            mHasPendingTaskChanges = true;
+        }
+    }
+
+    /**
+     * Notify if the top task on any panel has changed. This should be called from startAnimation
+     * only since that is when the task stack is finalized and settled (to reduce
+     * over-notification).
+     */
+    public void maybeNotifyTopTaskOnPanelChanged() {
+        synchronized (mLock) {
+            if (!mHasPendingTaskChanges) {
+                return;
+            }
+            mHasPendingTaskChanges = false;
+            mListeners.forEach(listener -> mUiBackgroundExecutor.execute(
+                    listener::onTopTaskOnPanelChanged));
+        }
+    }
+
+    private boolean isTaskVisible(ActivityManager.RunningTaskInfo task) {
+        return task.isVisible && task.isRunning && !task.isSleeping;
+    }
+
+    public interface TaskPanelChangeListener {
+        /**
+         * Notify the top task on a panel has changed.
+         */
+        void onTopTaskOnPanelChanged();
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/systemevents/EventHandlerModule.java b/src/com/android/systemui/car/wm/scalableui/systemevents/EventHandlerModule.java
new file mode 100644
index 00000000..c50c7414
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/systemevents/EventHandlerModule.java
@@ -0,0 +1,36 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.systemevents;
+
+import com.android.systemui.CoreStartable;
+
+import dagger.Binds;
+import dagger.Module;
+import dagger.multibindings.ClassKey;
+import dagger.multibindings.IntoMap;
+
+/**
+ * Dagger injection module for {@link SystemEventHandler}
+ */
+@Module
+public abstract class EventHandlerModule {
+
+    /** Injects SystemEventHandler */
+    @Binds
+    @IntoMap
+    @ClassKey(SystemEventHandler.class)
+    public abstract CoreStartable bindUserSystemEventHandler(SystemEventHandler systemEventHandler);
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventConstants.java b/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventConstants.java
new file mode 100644
index 00000000..f75fa551
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventConstants.java
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.systemevents;
+
+public class SystemEventConstants {
+    /** Event IDs */
+    public static final String EMPTY_EVENT_ID = "empty_event";
+    public static final String SYSTEM_HOME_EVENT_ID = "_System_OnHomeEvent";
+    public static final String SYSTEM_TASK_OPEN_EVENT_ID = "_System_TaskOpenEvent";
+    public static final String SYSTEM_TASK_CLOSE_EVENT_ID = "_System_TaskCloseEvent";
+    public static final String SYSTEM_TASK_PANEL_EMPTY_EVENT_ID = "_System_TaskPanelEmptyEvent";
+    public static final String SYSTEM_ENTER_SUW_EVENT_ID = "_System_EnterSuwEvent";
+    public static final String SYSTEM_EXIST_SUW_EVENT_ID = "_System_ExitSuwEvent";
+
+    /** Token IDs */
+    public static final String PANEL_TOKEN_ID = "panelId";
+    public static final String COMPONENT_TOKEN_ID = "component";
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventHandler.java b/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventHandler.java
new file mode 100644
index 00000000..cd8ef422
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventHandler.java
@@ -0,0 +1,157 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.systemevents;
+
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_UNLOCKED;
+
+import static com.android.systemui.car.Flags.scalableUi;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_ENTER_SUW_EVENT_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_EXIST_SUW_EVENT_ID;
+import static com.android.wm.shell.Flags.enableAutoTaskStackController;
+
+import android.car.user.CarUserManager;
+import android.content.Context;
+import android.os.Build;
+import android.util.Log;
+
+import androidx.annotation.NonNull;
+
+import com.android.car.scalableui.manager.StateManager;
+import com.android.systemui.CoreStartable;
+import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
+import com.android.systemui.car.CarDeviceProvisionedListener;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.dagger.qualifiers.Background;
+import com.android.systemui.settings.UserTracker;
+
+import java.util.concurrent.Executor;
+
+import javax.inject.Inject;
+
+/**
+ * A system event handler that listens for user lifecycle events and device provisioning state
+ * changes.
+ *
+ * <p>This class dispatches events to the {@link StateManager} when a user is unlocked or when
+ * the device
+ * is being set up.
+ */
+@SysUISingleton
+public class SystemEventHandler implements CoreStartable {
+    private static final String TAG = SystemEventHandler.class.getSimpleName();
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
+
+    private final Context mContext;
+    private final CarServiceProvider mCarServiceProvider;
+    private final UserTracker mUserTracker;
+    private final Executor mBackgroundExecutor;
+    private final CarDeviceProvisionedController mCarDeviceProvisionedController;
+    private final EventDispatcher mEventDispatcher;
+
+    private CarUserManager mCarUserManager;
+    private boolean mIsUserSetupInProgress;
+
+    private final CarUserManager.UserLifecycleListener mUserLifecycleListener =
+            new CarUserManager.UserLifecycleListener() {
+                @Override
+                public void onEvent(@NonNull CarUserManager.UserLifecycleEvent event) {
+                    if (DEBUG) {
+                        Log.d(TAG, "on User event = " + event + ", mIsUserSetupInProgress="
+                                + mIsUserSetupInProgress);
+                    }
+                    if (mIsUserSetupInProgress) {
+                        return;
+                    }
+                    if (event.getUserHandle().isSystem()) {
+                        return;
+                    }
+
+                    if (event.getEventType() == USER_LIFECYCLE_EVENT_TYPE_UNLOCKED) {
+                        if (event.getUserId() == mUserTracker.getUserId()) {
+                            StateManager.handlePanelReset();
+                        }
+                    }
+                }
+            };
+
+    private final CarDeviceProvisionedListener mCarDeviceProvisionedListener =
+            new CarDeviceProvisionedListener() {
+                @Override
+                public void onUserSetupInProgressChanged() {
+                    updateUserSetupState();
+                }
+            };
+
+    @Inject
+    public SystemEventHandler(
+            Context context,
+            @Background Executor bgExecutor,
+            CarServiceProvider carServiceProvider,
+            UserTracker userTracker,
+            CarDeviceProvisionedController carDeviceProvisionedController,
+            EventDispatcher dispatcher
+    ) {
+        mContext = context;
+        mBackgroundExecutor = bgExecutor;
+        mCarServiceProvider = carServiceProvider;
+        mUserTracker = userTracker;
+        mCarDeviceProvisionedController = carDeviceProvisionedController;
+        mEventDispatcher = dispatcher;
+        mIsUserSetupInProgress = mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
+    }
+
+    private void updateUserSetupState() {
+        boolean isUserSetupInProgress =
+                mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
+        if (isUserSetupInProgress != mIsUserSetupInProgress) {
+            mIsUserSetupInProgress = isUserSetupInProgress;
+            if (mIsUserSetupInProgress) {
+                mEventDispatcher.executeTransaction(SYSTEM_ENTER_SUW_EVENT_ID);
+            } else {
+                mEventDispatcher.executeTransaction(SYSTEM_EXIST_SUW_EVENT_ID);
+            }
+        }
+    }
+
+    @Override
+    public void start() {
+        if (isScalableUIEnabled()) {
+            registerUserEventListener();
+            registerProvisionedStateListener();
+        }
+    }
+
+    private void registerProvisionedStateListener() {
+        mCarDeviceProvisionedController.addCallback(mCarDeviceProvisionedListener);
+    }
+
+    private void registerUserEventListener() {
+        mCarServiceProvider.addListener(car -> {
+            mCarUserManager = car.getCarManager(CarUserManager.class);
+            if (mCarUserManager != null) {
+                mCarUserManager.addListener(mBackgroundExecutor, mUserLifecycleListener);
+            }
+        });
+    }
+
+    private boolean isScalableUIEnabled() {
+        return scalableUi() && enableAutoTaskStackController()
+                && mContext.getResources().getBoolean(R.bool.config_enableScalableUI);
+    }
+}
diff --git a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
index 5d53d3a9..bb7c8d71 100644
--- a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
+++ b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
@@ -48,6 +48,9 @@ import com.android.wm.shell.common.SyncTransactionQueue;
 import com.android.wm.shell.taskview.TaskViewBase;
 import com.android.wm.shell.taskview.TaskViewTaskController;
 import com.android.wm.shell.taskview.TaskViewTransitions;
+import com.android.wm.shell.windowdecor.WindowDecorViewModel;
+
+import java.util.Optional;
 
 /** Server side implementation for {@code RemoteCarTaskView}. */
 public class RemoteCarTaskViewServerImpl implements TaskViewBase {
@@ -62,6 +65,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
     private final ShellTaskOrganizer mShellTaskOrganizer;
     private final CarActivityManager mCarActivityManager;
     private final TaskViewTransitions mTaskViewTransitions;
+    private final Optional<WindowDecorViewModel> mWindowDecorViewModelOptional;
 
     private RootTaskMediator mRootTaskMediator;
     private boolean mReleased;
@@ -100,7 +104,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
         @Override
         public void setWindowBounds(Rect bounds) {
             ensureManageSystemUIPermission(mContext);
-            mTaskViewTaskController.setWindowBounds(bounds);
+            mTaskViewTransitions.setTaskBounds(mTaskViewTaskController, bounds);
         }
 
         @Override
@@ -120,7 +124,8 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             // Need this for the pending intent to work under BAL hardening.
             opt.setPendingIntentBackgroundActivityStartMode(
                     ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOW_ALWAYS);
-            mTaskViewTaskController.startActivity(
+            mTaskViewTransitions.startActivity(
+                    mTaskViewTaskController,
                     pendingIntent,
                     fillInIntent,
                     opt,
@@ -141,10 +146,18 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             if (mRootTaskMediator != null) {
                 throw new IllegalStateException("Root task is already created for this task view.");
             }
-            mRootTaskMediator = new RootTaskMediator(displayId, /* isLaunchRoot= */ false,
-                    false, false, false, mShellTaskOrganizer,
-                    mTaskViewTaskController, RemoteCarTaskViewServerImpl.this,
-                    mCarActivityManager, mTaskViewTransitions);
+            mRootTaskMediator = new RootTaskMediator(
+                    displayId,
+                    /* isLaunchRoot= */ false,
+                    /* embedHomeTask= */ false,
+                    /* embedRecentsTask= */ false,
+                    /* embedAssistantTask= */ false,
+                    mShellTaskOrganizer,
+                    mTaskViewTaskController,
+                    RemoteCarTaskViewServerImpl.this,
+                    mCarActivityManager,
+                    mTaskViewTransitions,
+                    mWindowDecorViewModelOptional);
         }
 
         /**
@@ -168,10 +181,18 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             //  tasks are moved to an always visible window (surface) in SystemUI.
             mTaskViewTaskController.setHideTaskWithSurface(false);
 
-            mRootTaskMediator = new RootTaskMediator(displayId, /* isLaunchRoot= */ true,
-                    embedHomeTask, embedRecentsTask, embedAssistantTask, mShellTaskOrganizer,
-                    mTaskViewTaskController, RemoteCarTaskViewServerImpl.this,
-                    mCarActivityManager, mTaskViewTransitions);
+            mRootTaskMediator = new RootTaskMediator(
+                    displayId,
+                    /* isLaunchRoot= */ true,
+                    embedHomeTask,
+                    embedRecentsTask,
+                    embedAssistantTask,
+                    mShellTaskOrganizer,
+                    mTaskViewTaskController,
+                    RemoteCarTaskViewServerImpl.this,
+                    mCarActivityManager,
+                    mTaskViewTransitions,
+                    mWindowDecorViewModelOptional);
         }
 
         @Override
@@ -181,7 +202,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             if (taskInfo == null) {
                 return;
             }
-            if (mTaskViewTaskController.isUsingShellTransitions() && mTaskViewTransitions != null) {
+            if (mTaskViewTransitions.isUsingShellTransitions() && mTaskViewTransitions != null) {
                 mTaskViewTransitions.setTaskViewVisible(mTaskViewTaskController, /* visible= */
                         true, /* reorder= */ true);
                 return;
@@ -206,7 +227,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             if (taskInfo == null) {
                 return;
             }
-            if (mTaskViewTaskController.isUsingShellTransitions()) {
+            if (mTaskViewTransitions.isUsingShellTransitions()) {
                 mTaskViewTransitions.setTaskViewVisible(mTaskViewTaskController, visibility);
                 return;
             }
@@ -228,7 +249,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
                 return;
             }
 
-            if (mTaskViewTaskController.isUsingShellTransitions()) {
+            if (mTaskViewTransitions.isUsingShellTransitions()) {
                 mTaskViewTransitions.reorderTaskViewTask(mTaskViewTaskController, onTop);
                 return;
             }
@@ -287,13 +308,15 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             CarTaskViewClient carTaskViewClient,
             CarSystemUIProxyImpl carSystemUIProxy,
             TaskViewTransitions taskViewTransitions,
-            CarActivityManager carActivityManager) {
+            CarActivityManager carActivityManager,
+            Optional<WindowDecorViewModel> windowDecorViewModelOptional) {
         mContext = context;
         mCarTaskViewClient = carTaskViewClient;
         mCarSystemUIProxy = carSystemUIProxy;
         mShellTaskOrganizer = organizer;
         mCarActivityManager = carActivityManager;
         mTaskViewTransitions = taskViewTransitions;
+        mWindowDecorViewModelOptional = windowDecorViewModelOptional;
 
         mTaskViewTaskController =
                 new TaskViewTaskController(context, organizer, taskViewTransitions, syncQueue);
diff --git a/src/com/android/systemui/car/wm/taskview/RootTaskMediator.java b/src/com/android/systemui/car/wm/taskview/RootTaskMediator.java
index 2aa19386..ea34750f 100644
--- a/src/com/android/systemui/car/wm/taskview/RootTaskMediator.java
+++ b/src/com/android/systemui/car/wm/taskview/RootTaskMediator.java
@@ -36,11 +36,13 @@ import com.android.wm.shell.ShellTaskOrganizer;
 import com.android.wm.shell.taskview.TaskViewBase;
 import com.android.wm.shell.taskview.TaskViewTaskController;
 import com.android.wm.shell.taskview.TaskViewTransitions;
+import com.android.wm.shell.windowdecor.WindowDecorViewModel;
 
 import java.util.ArrayList;
 import java.util.Iterator;
 import java.util.LinkedHashMap;
 import java.util.List;
+import java.util.Optional;
 
 /**
  * A mediator to {@link RemoteCarTaskViewServerImpl} that encapsulates the root task related logic.
@@ -57,6 +59,7 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
     private final CarActivityManager mCarActivityManager;
     private final LinkedHashMap<Integer, TaskRecord> mTaskStack = new LinkedHashMap<>();
     private final TaskViewTransitions mTransitions;
+    private final Optional<WindowDecorViewModel> mWindowDecorViewModelOptional;
 
     private static class TaskRecord {
         private ActivityManager.RunningTaskInfo mTaskInfo;
@@ -70,7 +73,9 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
 
     private ActivityManager.RunningTaskInfo mRootTask;
 
-    public RootTaskMediator(int displayId, boolean isLaunchRoot,
+    public RootTaskMediator(
+            int displayId,
+            boolean isLaunchRoot,
             boolean embedHomeTask,
             boolean embedRecentsTask,
             boolean embedAssistantTask,
@@ -78,7 +83,8 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
             TaskViewTaskController taskViewTaskShellPart,
             TaskViewBase taskViewClientPart,
             CarActivityManager carActivityManager,
-            TaskViewTransitions transitions) {
+            TaskViewTransitions transitions,
+            Optional<WindowDecorViewModel> windowDecorViewModelOptional) {
         mDisplayId = displayId;
         mIsLaunchRoot = isLaunchRoot;
         mActivityTypes = createActivityArray(embedHomeTask, embedRecentsTask, embedAssistantTask);
@@ -87,6 +93,7 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
         mTaskViewClientPart = taskViewClientPart;
         mCarActivityManager = carActivityManager;
         mTransitions = transitions;
+        mWindowDecorViewModelOptional = windowDecorViewModelOptional;
 
         mShellTaskOrganizer.createRootTask(displayId,
                 WINDOWING_MODE_MULTI_WINDOW,
@@ -150,11 +157,11 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
             }
 
             // Attach the root task with the taskview shell part.
-            if (mTaskViewTaskShellPart.isUsingShellTransitions()) {
+            if (mTransitions.isUsingShellTransitions()) {
                 // Do not trigger onTaskAppeared on shell part directly as it is no longer the
                 // correct entry point for a new task in the task view.
                 // Shell part will eventually trigger onTaskAppeared on the client as well.
-                mTaskViewTaskShellPart.startRootTask(taskInfo, leash, wct);
+                mTransitions.startRootTask(mTaskViewTaskShellPart, taskInfo, leash, wct);
             } else {
                 if (wct != null) {
                     mShellTaskOrganizer.applyTransaction(wct);
@@ -173,6 +180,13 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
         if (mIsLaunchRoot) {
             mCarActivityManager.onTaskAppeared(taskInfo, leash);
         }
+
+        // Show WindowDecor for display compat apps
+        if (mWindowDecorViewModelOptional.isPresent()) {
+            SurfaceControl.Transaction t = new SurfaceControl.Transaction();
+            mWindowDecorViewModelOptional.get().onTaskOpening(taskInfo, leash, t, t);
+            t.apply();
+        }
     }
 
     @Override
@@ -197,6 +211,9 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
             task.mTaskInfo = taskInfo;
             mTaskStack.put(taskInfo.taskId, task);
         }
+        if (mWindowDecorViewModelOptional.isPresent()) {
+            mWindowDecorViewModelOptional.get().onTaskInfoChanged(taskInfo);
+        }
     }
 
     @Override
@@ -215,6 +232,10 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
             mCarActivityManager.onTaskVanished(taskInfo);
         }
         mTaskStack.remove(taskInfo.taskId);
+        if (mWindowDecorViewModelOptional.isPresent()) {
+            mWindowDecorViewModelOptional.get().onTaskVanished(taskInfo);
+            mWindowDecorViewModelOptional.get().destroyWindowDecoration(taskInfo);
+        }
     }
 
     @Override
@@ -235,7 +256,7 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
         // from mLaunchRootStack
         wct.removeTask(topTask.token);
 
-        if (mTaskViewTaskShellPart.isUsingShellTransitions()) {
+        if (mTransitions.isUsingShellTransitions()) {
             mTransitions.startInstantTransition(TRANSIT_CLOSE, wct);
         } else {
             mShellTaskOrganizer.applyTransaction(wct);
@@ -287,7 +308,7 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
         if (mIsLaunchRoot) {
             WindowContainerTransaction wct = new WindowContainerTransaction();
             wct.setLaunchRoot(mRootTask.token, null, null);
-            if (mTaskViewTaskShellPart.isUsingShellTransitions()) {
+            if (mTransitions.isUsingShellTransitions()) {
                 mTransitions.startInstantTransition(TRANSIT_CHANGE, wct);
             } else {
                 mShellTaskOrganizer.applyTransaction(wct);
diff --git a/src/com/android/systemui/wm/BarControlPolicy.java b/src/com/android/systemui/wm/BarControlPolicy.java
index c7a8daf9..a98398c2 100644
--- a/src/com/android/systemui/wm/BarControlPolicy.java
+++ b/src/com/android/systemui/wm/BarControlPolicy.java
@@ -16,6 +16,8 @@
 
 package com.android.systemui.wm;
 
+import static com.android.systemui.car.Flags.packageLevelSystemBarVisibility;
+
 import android.car.settings.CarSettings;
 import android.content.Context;
 import android.database.ContentObserver;
@@ -25,6 +27,7 @@ import android.provider.Settings;
 import android.util.ArraySet;
 import android.util.Slog;
 import android.view.WindowInsets;
+import android.view.WindowInsets.Type.InsetsType;
 
 import androidx.annotation.VisibleForTesting;
 
@@ -45,6 +48,9 @@ import java.io.StringWriter;
  *     "immersive.full=*"
  *   to force hide status bars for com.package1 but not com.package2:
  *     "immersive.status=com.package1,-com.package2"
+ *   to force hide navigation bar everywhere, and allow com.package1 to control visibility of both
+ *   system bar types:
+ *     "immersive.navigation=*,+com.package1"
  *
  * Separate multiple name-value pairs with ':'
  *   e.g. "immersive.status=com.package:immersive.navigation=*"
@@ -113,8 +119,13 @@ public class BarControlPolicy {
      * @return int[], where the first value is the inset types that should be shown, and the second
      *         is the inset types that should be hidden.
      */
-    @WindowInsets.Type.InsetsType
+    @InsetsType
     public static int[] getBarVisibilities(String packageName) {
+        if (packageLevelSystemBarVisibility()) {
+            throw new IllegalStateException("This method should only be called when "
+                    + "'package_level_system_bar_visibility' flag is disabled");
+        }
+
         int hideTypes = 0;
         int showTypes = 0;
         if (matchesStatusFilter(packageName)) {
@@ -131,6 +142,56 @@ public class BarControlPolicy {
         return new int[] {showTypes, hideTypes};
     }
 
+    /**
+     * Returns bar visibilities based on POLICY_CONTROL_AUTO filters, window policies and the
+     * requested visible system bar types.
+     *
+     * @return int[], where the first value is the inset types that should be shown, and the second
+     *         is the inset types that should be hidden.
+     */
+    @InsetsType
+    public static int[] getBarVisibilities(
+            String packageName, @InsetsType int requestedVisibleTypes) {
+        if (!packageLevelSystemBarVisibility()) {
+            throw new IllegalStateException("This method should only be called when "
+                    + "'package_level_system_bar_visibility' flag is enabled");
+        }
+
+        int hideTypes = 0;
+        int showTypes = 0;
+
+        boolean isStatusControlAllowed = sImmersiveStatusFilter != null
+                && sImmersiveStatusFilter.isControlAllowed(packageName);
+
+        if (isStatusControlAllowed) {
+            if ((requestedVisibleTypes & WindowInsets.Type.statusBars()) != 0) {
+                showTypes |= WindowInsets.Type.statusBars();
+            } else {
+                hideTypes |= WindowInsets.Type.statusBars();
+            }
+        } else if (matchesStatusFilter(packageName)) {
+            hideTypes |= WindowInsets.Type.statusBars();
+        } else {
+            showTypes |= WindowInsets.Type.statusBars();
+        }
+
+        boolean isNavigationControlAllowed = sImmersiveNavigationFilter != null
+                && sImmersiveNavigationFilter.isControlAllowed(packageName);
+        if (isNavigationControlAllowed) {
+            if ((requestedVisibleTypes & WindowInsets.Type.navigationBars()) != 0) {
+                showTypes |= WindowInsets.Type.navigationBars();
+            } else {
+                hideTypes |= WindowInsets.Type.navigationBars();
+            }
+        } else if (matchesNavigationFilter(packageName)) {
+            hideTypes |= WindowInsets.Type.navigationBars();
+        } else {
+            showTypes |= WindowInsets.Type.navigationBars();
+        }
+
+        return new int[] { showTypes, hideTypes };
+    }
+
     private static boolean matchesStatusFilter(String packageName) {
         return sImmersiveStatusFilter != null && sImmersiveStatusFilter.matches(packageName);
     }
@@ -174,10 +235,13 @@ public class BarControlPolicy {
 
         private final ArraySet<String> mToInclude;
         private final ArraySet<String> mToExclude;
+        private final ArraySet<String> mAllowControl;
 
-        private Filter(ArraySet<String> toInclude, ArraySet<String> toExclude) {
+        private Filter(ArraySet<String> toInclude, ArraySet<String> toExclude,
+                ArraySet<String> allowControl) {
             mToInclude = toInclude;
             mToExclude = toExclude;
+            mAllowControl = packageLevelSystemBarVisibility() ? allowControl : null;
         }
 
         boolean matches(String packageName) {
@@ -194,10 +258,24 @@ public class BarControlPolicy {
             return mToInclude.contains(ALL) || mToInclude.contains(packageName);
         }
 
+        boolean isControlAllowed(String packageName) {
+            return packageLevelSystemBarVisibility() && (mAllowControl.contains(ALL)
+                    || mAllowControl.contains(packageName));
+        }
+
         void dump(PrintWriter pw) {
             pw.print("Filter[");
-            dump("toInclude", mToInclude, pw); pw.print(',');
-            dump("toExclude", mToExclude, pw); pw.print(']');
+            dump("toInclude", mToInclude, pw);
+
+            pw.print(',');
+            dump("toExclude", mToExclude, pw);
+
+            if (packageLevelSystemBarVisibility()) {
+                pw.print(',');
+                dump("allowControl", mAllowControl, pw);
+            }
+
+            pw.print(']');
         }
 
         private void dump(String name, ArraySet<String> set, PrintWriter pw) {
@@ -221,18 +299,23 @@ public class BarControlPolicy {
         // e.g. "com.package1", or "com.android.systemui, com.android.keyguard" or "*"
         static Filter parse(String value) {
             if (value == null) return null;
-            ArraySet<String> toInclude = new ArraySet<String>();
-            ArraySet<String> toExclude = new ArraySet<String>();
+            ArraySet<String> toInclude = new ArraySet<>();
+            ArraySet<String> toExclude = new ArraySet<>();
+            ArraySet<String> allowControl =
+                    packageLevelSystemBarVisibility() ? new ArraySet<>() : null;
             for (String token : value.split(",")) {
                 token = token.trim();
                 if (token.startsWith("-") && token.length() > 1) {
                     token = token.substring(1);
                     toExclude.add(token);
+                } else if (allowControl != null && token.startsWith("+") && token.length() > 1) {
+                    token = token.substring(1);
+                    allowControl.add(token);
                 } else {
                     toInclude.add(token);
                 }
             }
-            return new Filter(toInclude, toExclude);
+            return new Filter(toInclude, toExclude, allowControl);
         }
     }
 
diff --git a/src/com/android/systemui/wm/DisplaySystemBarsController.java b/src/com/android/systemui/wm/DisplaySystemBarsController.java
index 07df7d1e..bc62b209 100644
--- a/src/com/android/systemui/wm/DisplaySystemBarsController.java
+++ b/src/com/android/systemui/wm/DisplaySystemBarsController.java
@@ -28,6 +28,7 @@ import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSIS
 import static com.android.systemui.car.systembar.SystemBarUtil.VISIBLE_BAR_VISIBILITIES_TYPES_INDEX;
 import static com.android.systemui.car.systembar.SystemBarUtil.INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX;
 import static com.android.systemui.car.users.CarSystemUIUserUtil.isSecondaryMUMDSystemUI;
+import static com.android.systemui.car.Flags.packageLevelSystemBarVisibility;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
@@ -235,7 +236,8 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
             String packageName = component != null ? component.getPackageName() : null;
 
             if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) {
-                if (Objects.equals(mPackageName, packageName)) {
+                if (Objects.equals(mPackageName, packageName) && (!packageLevelSystemBarVisibility()
+                        || mWindowRequestedVisibleTypes == requestedVisibleTypes)) {
                     return;
                 }
             } else {
@@ -344,7 +346,10 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
         private int[] getBarVisibilities(int immersiveState) {
             int[] barVisibilities;
             if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) {
-                barVisibilities = BarControlPolicy.getBarVisibilities(mPackageName);
+                barVisibilities = packageLevelSystemBarVisibility()
+                        ? BarControlPolicy.getBarVisibilities(
+                                mPackageName, mWindowRequestedVisibleTypes)
+                        : BarControlPolicy.getBarVisibilities(mPackageName);
             } else if (immersiveState == STATE_IMMERSIVE_WITH_NAV_BAR) {
                 barVisibilities = mImmersiveWithNavBarVisibilities;
             } else if (immersiveState == STATE_IMMERSIVE_WITH_STATUS_BAR) {
diff --git a/src/com/android/systemui/wmshell/CarWMComponent.java b/src/com/android/systemui/wmshell/CarWMComponent.java
index 296b9ab9..c2623980 100644
--- a/src/com/android/systemui/wmshell/CarWMComponent.java
+++ b/src/com/android/systemui/wmshell/CarWMComponent.java
@@ -18,14 +18,22 @@ package com.android.systemui.wmshell;
 
 import com.android.systemui.car.wm.CarSystemUIProxyImpl;
 import com.android.systemui.car.wm.displayarea.DaViewTransitions;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.car.wm.scalableui.ScalableUIWMInitializer;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
 import com.android.systemui.car.wm.taskview.RemoteCarTaskViewTransitions;
 import com.android.systemui.wm.DisplaySystemBarsController;
 import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
+import com.android.wm.shell.automotive.AutoDecorManager;
+import com.android.wm.shell.automotive.AutoLayoutManager;
+import com.android.wm.shell.automotive.AutoTaskStackController;
 import com.android.wm.shell.dagger.WMComponent;
 import com.android.wm.shell.dagger.WMSingleton;
 
 import dagger.Subcomponent;
 
+import java.util.Optional;
+
 /**
  * Dagger Subcomponent for WindowManager.
  */
@@ -60,10 +68,36 @@ public interface CarWMComponent extends WMComponent {
     @WMSingleton
     RemoteCarTaskViewTransitions getRemoteCarTaskViewTransitions();
 
+    /** Provides the {@link DaViewTransitions} used to animate DaViews. */
+    @WMSingleton
+    DaViewTransitions getDaViewTransitions();
+
     /**
-     * Provides the {@link DaViewTransitions}
-     * used to animate DaViews.
+     * Provides the {@link AutoTaskStackController} used to implement custom
+     * windowing behavior.
      */
     @WMSingleton
-    DaViewTransitions getDaViewTransitions();
+    AutoTaskStackController getAutoTaskStackController();
+
+    /**
+     * Optional {@link ScalableUIWMInitializer} component for initializing scalable ui
+     */
+    @WMSingleton
+    Optional<ScalableUIWMInitializer> getScalableUIWMInitializer();
+
+    /** Provides the {@link TaskPanelInfoRepository} used to dispatch ScalableUI task info. */
+    @WMSingleton
+    TaskPanelInfoRepository getTaskPanelInfoRepository();
+
+    /** Provides the {@link EventDispatcher} used to dispatch ScalableUI events. */
+    @WMSingleton
+    EventDispatcher getScalableUIEventDispatcher();
+
+    /** Provides the {@link AutoDecorManager} used to manage {@link AutoDecor}. */
+    @WMSingleton
+    AutoDecorManager getAutoDecorManager();
+
+    /** Provides the {@link AutoLayoutManager} used to set ScalableUI Insets. */
+    @WMSingleton
+    AutoLayoutManager getAutoLayoutManager();
 }
diff --git a/src/com/android/systemui/wmshell/CarWMShellModule.java b/src/com/android/systemui/wmshell/CarWMShellModule.java
index 992a906e..45df7a9f 100644
--- a/src/com/android/systemui/wmshell/CarWMShellModule.java
+++ b/src/com/android/systemui/wmshell/CarWMShellModule.java
@@ -16,17 +16,32 @@
 
 package com.android.systemui.wmshell;
 
+import static com.android.systemui.car.Flags.scalableUi;
+import static com.android.wm.shell.Flags.enableAutoTaskStackController;
+
 import android.content.Context;
 import android.os.Handler;
 import android.view.IWindowManager;
 
+import androidx.annotation.NonNull;
+
+import com.android.systemui.R;
 import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.wm.AutoDisplayCompatWindowDecorViewModel;
 import com.android.systemui.car.wm.CarFullscreenTaskMonitorListener;
+import com.android.systemui.car.wm.scalableui.PanelAutoTaskStackTransitionHandlerDelegate;
+import com.android.systemui.car.wm.scalableui.PanelConfigReader;
+import com.android.systemui.car.wm.scalableui.ScalableUIWMInitializer;
+import com.android.systemui.car.wm.scalableui.panel.DecorPanel;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.wm.DisplaySystemBarsController;
 import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.automotive.AutoShellModule;
+import com.android.wm.shell.automotive.AutoTaskRepository;
 import com.android.wm.shell.common.DisplayController;
 import com.android.wm.shell.common.DisplayInsetsController;
+import com.android.wm.shell.common.ShellExecutor;
 import com.android.wm.shell.common.SyncTransactionQueue;
 import com.android.wm.shell.dagger.DynamicOverride;
 import com.android.wm.shell.dagger.WMShellBaseModule;
@@ -34,18 +49,27 @@ import com.android.wm.shell.dagger.WMSingleton;
 import com.android.wm.shell.fullscreen.FullscreenTaskListener;
 import com.android.wm.shell.pip.Pip;
 import com.android.wm.shell.recents.RecentTasksController;
+import com.android.wm.shell.shared.annotations.ShellBackgroundThread;
+import com.android.wm.shell.shared.annotations.ShellMainThread;
 import com.android.wm.shell.sysui.ShellInit;
 import com.android.wm.shell.taskview.TaskViewTransitions;
+import com.android.wm.shell.transition.FocusTransitionObserver;
 import com.android.wm.shell.windowdecor.WindowDecorViewModel;
+import com.android.wm.shell.windowdecor.common.viewhost.DefaultWindowDecorViewHostSupplier;
+import com.android.wm.shell.windowdecor.common.viewhost.WindowDecorViewHost;
+import com.android.wm.shell.windowdecor.common.viewhost.WindowDecorViewHostSupplier;
 
 import dagger.BindsOptionalOf;
+import dagger.Lazy;
 import dagger.Module;
 import dagger.Provides;
 
+import kotlinx.coroutines.CoroutineScope;
+
 import java.util.Optional;
 
 /** Provides dependencies from {@link com.android.wm.shell} for CarSystemUI. */
-@Module(includes = WMShellBaseModule.class)
+@Module(includes = {WMShellBaseModule.class, AutoShellModule.class})
 public abstract class CarWMShellModule {
 
     @WMSingleton
@@ -71,7 +95,8 @@ public abstract class CarWMShellModule {
             SyncTransactionQueue syncQueue,
             Optional<RecentTasksController> recentTasksOptional,
             Optional<WindowDecorViewModel> windowDecorViewModelOptional,
-            TaskViewTransitions taskViewTransitions) {
+            TaskViewTransitions taskViewTransitions,
+            AutoTaskRepository taskRepository) {
         return new CarFullscreenTaskMonitorListener(context,
                 carServiceProvider,
                 shellInit,
@@ -79,6 +104,78 @@ public abstract class CarWMShellModule {
                 syncQueue,
                 recentTasksOptional,
                 windowDecorViewModelOptional,
-                taskViewTransitions);
+                taskViewTransitions,
+                taskRepository);
+    }
+
+    @WMSingleton
+    @Provides
+    static WindowDecorViewHostSupplier<WindowDecorViewHost> provideWindowDecorViewHostSupplier(
+            @ShellMainThread @NonNull CoroutineScope mainScope) {
+        return new DefaultWindowDecorViewHostSupplier(mainScope);
+    }
+
+    @WMSingleton
+    @Provides
+    static WindowDecorViewModel provideWindowDecorViewModel(
+            Context context,
+            @ShellMainThread ShellExecutor mainExecutor,
+            @ShellBackgroundThread ShellExecutor bgExecutor,
+            ShellInit shellInit,
+            ShellTaskOrganizer taskOrganizer,
+            DisplayController displayController,
+            DisplayInsetsController displayInsetsController,
+            SyncTransactionQueue syncQueue,
+            FocusTransitionObserver focusTransitionObserver,
+            WindowDecorViewHostSupplier<WindowDecorViewHost> windowDecorViewHostSupplier,
+            CarServiceProvider carServiceProvider
+    ) {
+        return new AutoDisplayCompatWindowDecorViewModel(
+                context,
+                mainExecutor,
+                bgExecutor,
+                shellInit,
+                taskOrganizer,
+                displayController,
+                displayInsetsController,
+                syncQueue,
+                focusTransitionObserver,
+                windowDecorViewHostSupplier,
+                carServiceProvider);
+    }
+
+    @WMSingleton
+    @Provides
+    static Optional<PanelConfigReader> providesPanelConfigReader(
+            Context context,
+            TaskPanel.Factory taskPanelFactory,
+            DecorPanel.Factory decorPanelFactory
+    ) {
+        if (isScalableUIEnabled(context)) {
+            return Optional.of(new PanelConfigReader(
+                    context,
+                    taskPanelFactory,
+                    decorPanelFactory));
+        }
+        return Optional.empty();
+    }
+
+    @WMSingleton
+    @Provides
+    static Optional<ScalableUIWMInitializer> provideScalableUIInitializer(ShellInit shellInit,
+            Context context,
+            Optional<PanelConfigReader> panelConfigReaderOptional,
+            Lazy<PanelAutoTaskStackTransitionHandlerDelegate> delegate) {
+        if (isScalableUIEnabled(context) && panelConfigReaderOptional.isPresent()) {
+            return Optional.of(
+                    new ScalableUIWMInitializer(shellInit, panelConfigReaderOptional.get(),
+                            delegate.get()));
+        }
+        return Optional.empty();
+    }
+
+    private static boolean isScalableUIEnabled(Context context) {
+        return scalableUi() && enableAutoTaskStackController()
+                && context.getResources().getBoolean(R.bool.config_enableScalableUI);
     }
 }
diff --git a/tests/Android.bp b/tests/Android.bp
index 2e617694..54a9fb54 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -25,7 +25,10 @@ package {
 android_test {
     name: "CarSystemUITests",
 
-    dxflags: ["--multi-dex"],
+    dxflags: [
+        "--multi-dex",
+        "-JXmx8192M", // TODO(b/301283770): Compiling CarSystemUI should not require -J-Xmx8192M
+    ],
     platform_apis: true,
     test_suites: [
         "device-tests",
@@ -43,7 +46,9 @@ android_test {
         "android.test.runner.stubs.system",
         "telephony-common",
         "android.test.base.stubs.system",
+        "token-shared-lib-prebuilt",
     ],
+    enforce_uses_libs: false,
     aaptflags: [
         "--extra-packages com.android.systemui",
     ],
diff --git a/tests/AndroidManifest.xml b/tests/AndroidManifest.xml
index af0ecfe9..67b64c77 100644
--- a/tests/AndroidManifest.xml
+++ b/tests/AndroidManifest.xml
@@ -29,13 +29,14 @@
         tools:node="remove" />
 
     <application
-        android:name="com.android.systemui.SystemUIApplication"
+        android:name="com.android.systemui.CarSystemUIApplication"
         android:debuggable="true"
         android:largeHeap="true"
         tools:replace="android:appComponentFactory"
         android:appComponentFactory="com.android.systemui.CarSystemUITestAppComponentFactory"
         android:testOnly="true">
         <uses-library android:name="android.test.runner"/>
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
 
         <activity android:name="com.android.systemui.car.userpicker.UserPickerDriverTestActivity"
                   android:exported="false"
diff --git a/tests/res/layout/car_system_bar_button_test.xml b/tests/res/layout/car_system_bar_button_test.xml
index e1caf7a4..501117b2 100644
--- a/tests/res/layout/car_system_bar_button_test.xml
+++ b/tests/res/layout/car_system_bar_button_test.xml
@@ -44,6 +44,48 @@
         systemui:highlightWhenSelected="true"
     />
 
+    <com.android.systemui.car.systembar.CarSystemBarButton
+        android:id="@+id/dialer_activity_toggle"
+        style="@style/SystemBarButton"
+        systemui:componentNames="com.android.car.dialer/.ui.TelecomActivity"
+        systemui:icon="@drawable/car_ic_apps"
+        systemui:unselectedIntent="intent:#Intent;component=com.android.car.dialer/.ui.TelecomActivity;launchFlags=0x24000000;end"
+        systemui:selectedIntent="intent:#Intent;component=com.android.car.carlauncher/.CarLauncher;launchFlags=0x24000000;end"
+        systemui:selectedIcon="@drawable/car_ic_apps_selected"
+        systemui:highlightWhenSelected="true"
+        />
+
+    <com.android.systemui.car.systembar.CarSystemBarButton
+        android:id="@+id/dialer_activity_toggle_missing_selected"
+        style="@style/SystemBarButton"
+        systemui:componentNames="com.android.car.dialer/.ui.TelecomActivity"
+        systemui:icon="@drawable/car_ic_apps"
+        systemui:intent="intent:#Intent;component=com.android.car.carlauncher/.CarLauncher;launchFlags=0x24000000;end"
+        systemui:unselectedIntent="intent:#Intent;component=com.android.car.dialer/.ui.TelecomActivity;launchFlags=0x24000000;end"
+        systemui:selectedIcon="@drawable/car_ic_apps_selected"
+        systemui:highlightWhenSelected="true"
+        />
+
+    <com.android.systemui.car.systembar.CarSystemBarButton
+        android:id="@+id/app_grid_button_with_selection_events"
+        style="@style/SystemBarButton"
+        systemui:icon="@drawable/car_ic_apps"
+        systemui:selectedEvent="close_app_grid"
+        systemui:unselectedEvent="open_app_grid"
+        systemui:selectedIcon="@drawable/car_ic_apps_selected"
+        systemui:highlightWhenSelected="true"
+        />
+
+    <com.android.systemui.car.systembar.CarSystemBarButton
+        android:id="@+id/app_grid_button_without_unselect_event"
+        style="@style/SystemBarButton"
+        systemui:icon="@drawable/car_ic_apps"
+        systemui:event="open_app_grid"
+        systemui:selectedEvent="close_app_grid"
+        systemui:selectedIcon="@drawable/car_ic_apps_selected"
+        systemui:highlightWhenSelected="true"
+        />
+
     <com.android.systemui.car.systembar.CarSystemBarButton
         android:id="@+id/dialer_activity_clear_backstack"
         style="@style/SystemBarButton"
diff --git a/tests/res/layout/car_top_system_bar.xml b/tests/res/layout/car_top_system_bar.xml
index 22790c37..1412db83 100644
--- a/tests/res/layout/car_top_system_bar.xml
+++ b/tests/res/layout/car_top_system_bar.xml
@@ -50,7 +50,7 @@
                 android:layout_gravity="center"
                 android:elevation="5dp"
                 android:singleLine="true"
-                android:textAppearance="@style/TextAppearance.SystemBar.Clock"
+                style="@style/SystemBarClockText"
                 systemui:amPmStyle="normal"
                 />
         </FrameLayout>
diff --git a/tests/src/com/android/systemui/CarSystemUITestInitializer.java b/tests/src/com/android/systemui/CarSystemUITestInitializer.java
index f68abe02..c616cde1 100644
--- a/tests/src/com/android/systemui/CarSystemUITestInitializer.java
+++ b/tests/src/com/android/systemui/CarSystemUITestInitializer.java
@@ -20,6 +20,9 @@ import static org.mockito.Mockito.mock;
 
 import android.content.Context;
 
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.car.wm.scalableui.ScalableUIWMInitializer;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
 import com.android.systemui.dagger.SysUIComponent;
 import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
 import com.android.wm.shell.dagger.WMComponent;
@@ -35,6 +38,9 @@ public class CarSystemUITestInitializer extends CarSystemUIInitializer {
     protected SysUIComponent.Builder prepareSysUIComponentBuilder(
             SysUIComponent.Builder sysUIBuilder, WMComponent wm) {
         return ((CarSysUIComponent.Builder) sysUIBuilder).setRootTaskDisplayAreaOrganizer(
-                Optional.of(mock(RootTaskDisplayAreaOrganizer.class)));
+                Optional.of(mock(RootTaskDisplayAreaOrganizer.class)))
+                .setScalableUIWMInitializer(Optional.of(mock(ScalableUIWMInitializer.class)))
+                .setTaskPanelInfoRepository(mock(TaskPanelInfoRepository.class))
+                .setScalableUIEventDispatcher(mock(EventDispatcher.class));
     }
 }
diff --git a/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt b/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
index 84cea9a7..ceb3856b 100644
--- a/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
+++ b/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
@@ -20,10 +20,10 @@ import android.testing.AndroidTestingRunner
 import android.testing.TestableLooper.RunWithLooper
 import android.view.Display
 import androidx.test.filters.SmallTest
-import com.android.systemui.SysuiTestCase
+import com.android.app.displaylib.DisplayRepository.PendingDisplay
+import com.android.systemui.CarSysuiTestCase
 import com.android.systemui.car.CarSystemUiTest
 import com.android.systemui.display.data.repository.DisplayRepository
-import com.android.systemui.display.data.repository.DisplayRepository.PendingDisplay
 import com.android.systemui.process.ProcessWrapper
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.cancelChildren
@@ -48,7 +48,7 @@ import org.mockito.kotlin.whenever
 @RunWith(AndroidTestingRunner::class)
 @RunWithLooper
 @SmallTest
-class ExternalDisplayControllerTest : SysuiTestCase() {
+class ExternalDisplayControllerTest : CarSysuiTestCase() {
 
     private val testScope = TestScope()
     private val bgDispatcher =
@@ -99,6 +99,8 @@ class FakeDisplayRepository(
     override val displayChangeEvent: Flow<Int> = emptyFlow(),
     override val displayAdditionEvent: Flow<Display?> = emptyFlow(),
     override val displayRemovalEvent: Flow<Int> = emptyFlow(),
+    override val displayIdsWithSystemDecorations: StateFlow<Set<Int>> =
+        MutableStateFlow(emptySet()),
     override val displays: StateFlow<Set<Display>> = MutableStateFlow(emptySet()),
     override val defaultDisplayOff: Flow<Boolean> = emptyFlow(),
     override val pendingDisplay: Flow<PendingDisplay?> = fakePendingDisplayFlow,
diff --git a/tests/src/com/android/systemui/car/drivemode/DriveModeThemeSwitcherTest.java b/tests/src/com/android/systemui/car/drivemode/DriveModeThemeSwitcherTest.java
index c0f8c555..38658b7b 100644
--- a/tests/src/com/android/systemui/car/drivemode/DriveModeThemeSwitcherTest.java
+++ b/tests/src/com/android/systemui/car/drivemode/DriveModeThemeSwitcherTest.java
@@ -30,7 +30,7 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.SysuiTestableContext;
 import com.android.systemui.car.CarSystemUiTest;
 
@@ -47,7 +47,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class DriveModeThemeSwitcherTest extends SysuiTestCase {
+public class DriveModeThemeSwitcherTest extends CarSysuiTestCase {
 
     private DriveModeThemeSwitcher mDriveModeThemeSwitcher;
     @Mock
diff --git a/tests/src/com/android/systemui/car/drivemode/InMemoryDriveModeManagerTest.java b/tests/src/com/android/systemui/car/drivemode/InMemoryDriveModeManagerTest.java
index 61c2417c..6f5513d6 100644
--- a/tests/src/com/android/systemui/car/drivemode/InMemoryDriveModeManagerTest.java
+++ b/tests/src/com/android/systemui/car/drivemode/InMemoryDriveModeManagerTest.java
@@ -25,7 +25,7 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.Before;
@@ -38,7 +38,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class InMemoryDriveModeManagerTest extends SysuiTestCase {
+public class InMemoryDriveModeManagerTest extends CarSysuiTestCase {
 
     private InMemoryDriveModeManager mDriveModeManager;
     @Mock
diff --git a/tests/src/com/android/systemui/car/hvac/FanDirectionButtonTest.java b/tests/src/com/android/systemui/car/hvac/FanDirectionButtonTest.java
index b45682d9..a55afd81 100644
--- a/tests/src/com/android/systemui/car/hvac/FanDirectionButtonTest.java
+++ b/tests/src/com/android/systemui/car/hvac/FanDirectionButtonTest.java
@@ -41,7 +41,7 @@ import android.widget.ImageView;
 import androidx.annotation.Nullable;
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.hvac.referenceui.FanDirectionButtons;
 import com.android.systemui.tests.R;
@@ -56,7 +56,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class FanDirectionButtonTest extends SysuiTestCase {
+public class FanDirectionButtonTest extends CarSysuiTestCase {
     private static final int GLOBAL_AREA_ID = 117;
     private static final int PROPERTY_ID = HVAC_FAN_DIRECTION;
 
diff --git a/tests/src/com/android/systemui/car/hvac/FanSpeedBarTest.java b/tests/src/com/android/systemui/car/hvac/FanSpeedBarTest.java
index f6c35eef..622ec192 100644
--- a/tests/src/com/android/systemui/car/hvac/FanSpeedBarTest.java
+++ b/tests/src/com/android/systemui/car/hvac/FanSpeedBarTest.java
@@ -33,7 +33,7 @@ import android.widget.TextView;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.hvac.referenceui.FanSpeedBar;
 import com.android.systemui.car.hvac.referenceui.FanSpeedBarSegment;
@@ -49,7 +49,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class FanSpeedBarTest extends SysuiTestCase {
+public class FanSpeedBarTest extends CarSysuiTestCase {
     private static final int GLOBAL_AREA_ID = 117;
     private static final int PROPERTY_ID = HVAC_FAN_SPEED;
 
diff --git a/tests/src/com/android/systemui/car/hvac/HvacControllerTest.java b/tests/src/com/android/systemui/car/hvac/HvacControllerTest.java
index 5777e820..2ebed0c8 100644
--- a/tests/src/com/android/systemui/car/hvac/HvacControllerTest.java
+++ b/tests/src/com/android/systemui/car/hvac/HvacControllerTest.java
@@ -45,7 +45,7 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.statusbar.policy.ConfigurationController;
@@ -63,7 +63,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class HvacControllerTest extends SysuiTestCase {
+public class HvacControllerTest extends CarSysuiTestCase {
 
     private static final int AREA_1 = 1;
     private static final int AREA_4 = 4;
diff --git a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
index eb410022..41ce6ebb 100644
--- a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
@@ -39,8 +39,8 @@ import android.widget.TextView;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.window.OverlayViewGlobalStateController;
@@ -61,7 +61,7 @@ import java.util.Collections;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class HvacPanelOverlayViewControllerTest extends SysuiTestCase {
+public class HvacPanelOverlayViewControllerTest extends CarSysuiTestCase {
     HvacPanelOverlayViewController mHvacPanelOverlayViewController;
     TestableResources mTestableResources;
 
diff --git a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediatorTest.java b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediatorTest.java
index 9b41fee4..e717572c 100644
--- a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediatorTest.java
+++ b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediatorTest.java
@@ -27,7 +27,7 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.CarSystemBarController;
@@ -43,7 +43,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class HvacPanelOverlayViewMediatorTest extends SysuiTestCase {
+public class HvacPanelOverlayViewMediatorTest extends CarSysuiTestCase {
 
     private HvacPanelOverlayViewMediator mHvacPanelOverlayViewMediator;
 
diff --git a/tests/src/com/android/systemui/car/hvac/HvacUtilsTest.java b/tests/src/com/android/systemui/car/hvac/HvacUtilsTest.java
index 2bae7bfc..da0d916a 100644
--- a/tests/src/com/android/systemui/car/hvac/HvacUtilsTest.java
+++ b/tests/src/com/android/systemui/car/hvac/HvacUtilsTest.java
@@ -25,7 +25,7 @@ import android.car.hardware.property.AreaIdConfig;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.Before;
@@ -37,7 +37,7 @@ import java.util.List;
 
 @CarSystemUiTest
 @SmallTest
-public class HvacUtilsTest extends SysuiTestCase {
+public class HvacUtilsTest extends CarSysuiTestCase {
     @Mock
     private CarPropertyConfig<Float> mFloatCarPropertyConfig;
     @Mock
diff --git a/tests/src/com/android/systemui/car/hvac/SeatTemperatureLevelButtonTest.java b/tests/src/com/android/systemui/car/hvac/SeatTemperatureLevelButtonTest.java
index c79b2952..69b942d2 100644
--- a/tests/src/com/android/systemui/car/hvac/SeatTemperatureLevelButtonTest.java
+++ b/tests/src/com/android/systemui/car/hvac/SeatTemperatureLevelButtonTest.java
@@ -31,7 +31,7 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.tests.R;
 
@@ -45,7 +45,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class SeatTemperatureLevelButtonTest extends SysuiTestCase {
+public class SeatTemperatureLevelButtonTest extends CarSysuiTestCase {
     private static final int GLOBAL_AREA_ID = 117;
     private static final int AREA_ID = 1;
     private static final int PROPERTY_ID = HVAC_SEAT_TEMPERATURE;
diff --git a/tests/src/com/android/systemui/car/hvac/TemperatureControlViewTest.java b/tests/src/com/android/systemui/car/hvac/TemperatureControlViewTest.java
index e49b02e9..a3e49693 100644
--- a/tests/src/com/android/systemui/car/hvac/TemperatureControlViewTest.java
+++ b/tests/src/com/android/systemui/car/hvac/TemperatureControlViewTest.java
@@ -42,7 +42,7 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.tests.R;
 
@@ -59,7 +59,7 @@ import java.util.List;
 @SmallTest
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
-public class TemperatureControlViewTest extends SysuiTestCase {
+public class TemperatureControlViewTest extends CarSysuiTestCase {
     private static final int GLOBAL_AREA_ID = 117;
     private static final int AREA_ID = 99;
     private static final int PROPERTY_ID = HVAC_TEMPERATURE_SET;
diff --git a/tests/src/com/android/systemui/car/hvac/referenceui/BackgroundAdjustingTemperatureControlViewTest.java b/tests/src/com/android/systemui/car/hvac/referenceui/BackgroundAdjustingTemperatureControlViewTest.java
index 7a257afd..858be790 100644
--- a/tests/src/com/android/systemui/car/hvac/referenceui/BackgroundAdjustingTemperatureControlViewTest.java
+++ b/tests/src/com/android/systemui/car/hvac/referenceui/BackgroundAdjustingTemperatureControlViewTest.java
@@ -28,7 +28,7 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.hvac.HvacPropertySetter;
 import com.android.systemui.tests.R;
@@ -43,7 +43,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class BackgroundAdjustingTemperatureControlViewTest extends SysuiTestCase {
+public class BackgroundAdjustingTemperatureControlViewTest extends CarSysuiTestCase {
     private static final int GLOBAL_AREA_ID = 117;
     private static final int AREA_ID = 99;
     private static final int PROPERTY_ID = HVAC_TEMPERATURE_SET;
diff --git a/tests/src/com/android/systemui/car/hvac/toggle/HvacBooleanToggleButtonTest.java b/tests/src/com/android/systemui/car/hvac/toggle/HvacBooleanToggleButtonTest.java
index c865b768..d523d33f 100644
--- a/tests/src/com/android/systemui/car/hvac/toggle/HvacBooleanToggleButtonTest.java
+++ b/tests/src/com/android/systemui/car/hvac/toggle/HvacBooleanToggleButtonTest.java
@@ -34,7 +34,7 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.hvac.HvacPropertySetter;
 import com.android.systemui.tests.R;
@@ -49,7 +49,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class HvacBooleanToggleButtonTest extends SysuiTestCase {
+public class HvacBooleanToggleButtonTest extends CarSysuiTestCase {
     private static final int GLOBAL_AREA_ID = 117;
     private static final int AREA_ID = 1;
     private static final int PROPERTY_ID = HVAC_AC_ON;
diff --git a/tests/src/com/android/systemui/car/hvac/toggle/HvacIntegerToggleButtonTest.java b/tests/src/com/android/systemui/car/hvac/toggle/HvacIntegerToggleButtonTest.java
index ba9df831..8ac870d7 100644
--- a/tests/src/com/android/systemui/car/hvac/toggle/HvacIntegerToggleButtonTest.java
+++ b/tests/src/com/android/systemui/car/hvac/toggle/HvacIntegerToggleButtonTest.java
@@ -33,7 +33,7 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.hvac.HvacPropertySetter;
 import com.android.systemui.tests.R;
@@ -48,7 +48,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class HvacIntegerToggleButtonTest extends SysuiTestCase {
+public class HvacIntegerToggleButtonTest extends CarSysuiTestCase {
     private static final int GLOBAL_AREA_ID = 117;
     private static final int AREA_ID = 1;
     private static final int PROPERTY_ID = HVAC_FAN_SPEED;
diff --git a/tests/src/com/android/systemui/car/input/DisplayInputSinkControllerTest.java b/tests/src/com/android/systemui/car/input/DisplayInputSinkControllerTest.java
index 348715ee..9d2517be 100644
--- a/tests/src/com/android/systemui/car/input/DisplayInputSinkControllerTest.java
+++ b/tests/src/com/android/systemui/car/input/DisplayInputSinkControllerTest.java
@@ -60,7 +60,7 @@ import android.view.MotionEvent;
 import androidx.annotation.NonNull;
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarServiceProvider.CarServiceOnConnectedListener;
 import com.android.systemui.car.CarSystemUiTest;
@@ -77,7 +77,7 @@ import org.mockito.quality.Strictness;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class DisplayInputSinkControllerTest extends SysuiTestCase {
+public class DisplayInputSinkControllerTest extends CarSysuiTestCase {
     private static final String TAG = DisplayInputSinkControllerTest.class.getSimpleName();
 
     private static final String EMPTY_SETTING_VALUE = "";
diff --git a/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java b/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
index b8d76e63..aa750247 100644
--- a/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
@@ -41,8 +41,8 @@ import com.android.keyguard.KeyguardSecurityModel;
 import com.android.keyguard.KeyguardUpdateMonitor;
 import com.android.keyguard.ViewMediatorCallback;
 import com.android.keyguard.dagger.KeyguardBouncerComponent;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.bouncer.domain.interactor.BouncerMessageInteractor;
 import com.android.systemui.bouncer.domain.interactor.PrimaryBouncerCallbackInteractor;
 import com.android.systemui.bouncer.domain.interactor.PrimaryBouncerInteractor;
@@ -51,6 +51,7 @@ import com.android.systemui.bouncer.ui.viewmodel.KeyguardBouncerViewModel;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.window.OverlayViewGlobalStateController;
 import com.android.systemui.car.window.SystemUIOverlayWindowController;
+import com.android.systemui.keyguard.ui.viewmodel.GlanceableHubToPrimaryBouncerTransitionViewModel;
 import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToGoneTransitionViewModel;
 import com.android.systemui.log.BouncerLogger;
 import com.android.systemui.settings.UserTracker;
@@ -77,7 +78,7 @@ import java.util.Optional;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class CarKeyguardViewControllerTest extends SysuiTestCase {
+public class CarKeyguardViewControllerTest extends CarSysuiTestCase {
 
     private CarKeyguardViewController mCarKeyguardViewController;
     private FakeExecutor mExecutor;
@@ -105,6 +106,9 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
     @Mock
     private PrimaryBouncerToGoneTransitionViewModel mPrimaryBouncerToGoneTransitionViewModel;
     @Mock
+    private GlanceableHubToPrimaryBouncerTransitionViewModel
+            mGlanceableHubToPrimaryBouncerTransitionViewModel;
+    @Mock
     private BouncerView mBouncerView;
     @Mock
     private KeyguardSystemBarPresenter mKeyguardSystemBarPresenter;
@@ -143,6 +147,7 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
                 mKeyguardSecurityModel,
                 mKeyguardBouncerViewModel,
                 mPrimaryBouncerToGoneTransitionViewModel,
+                mGlanceableHubToPrimaryBouncerTransitionViewModel,
                 mKeyguardBouncerComponentFactory,
                 mBouncerView,
                 mock(KeyguardMessageAreaController.Factory.class),
@@ -163,7 +168,8 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
         mCarKeyguardViewController.show(/* options= */ null);
         waitForDelayableExecutor();
 
-        verify(mPrimaryBouncerInteractor).show(/* isScrimmed= */ true);
+        verify(mPrimaryBouncerInteractor).show(/* isScrimmed= */ true,
+                "CarKeyguardViewController#resetBouncer");
     }
 
     @Test
@@ -241,7 +247,8 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
         mCarKeyguardViewController.setOccluded(/* occluded= */ false, /* animate= */ false);
         waitForDelayableExecutor();
 
-        verify(mPrimaryBouncerInteractor).show(/* isScrimmed= */ true);
+        verify(mPrimaryBouncerInteractor).show(/* isScrimmed= */ true,
+                "CarKeyguardViewController#resetBouncer");
     }
 
     @Test
diff --git a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java
index 928d8d68..ddcde34c 100644
--- a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java
@@ -34,7 +34,7 @@ import com.android.internal.widget.LockPatternChecker;
 import com.android.internal.widget.LockPatternUtils;
 import com.android.internal.widget.LockscreenCredential;
 import com.android.internal.widget.VerifyCredentialResponse;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.settings.UserTracker;
@@ -51,7 +51,7 @@ import org.mockito.quality.Strictness;
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @SmallTest
-public class PassengerKeyguardCredentialViewControllerTest extends SysuiTestCase {
+public class PassengerKeyguardCredentialViewControllerTest extends CarSysuiTestCase {
 
     private TestPassengerKeyguardCredentialViewController mController;
     private MockitoSession mSession;
diff --git a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialogTest.java b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialogTest.java
index d4e52d0c..f12a155d 100644
--- a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialogTest.java
+++ b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialogTest.java
@@ -50,7 +50,7 @@ import androidx.test.filters.SmallTest;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.internal.widget.LockPatternUtils;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
@@ -74,7 +74,7 @@ import java.util.concurrent.Executor;
 @TestableLooper.RunWithLooper
 @SmallTest
 @EnableFlags(Flags.FLAG_SUPPORTS_SECURE_PASSENGER_USERS)
-public class PassengerKeyguardLoadingDialogTest extends SysuiTestCase {
+public class PassengerKeyguardLoadingDialogTest extends CarSysuiTestCase {
     private static final int TEST_USER_ID = 1000;
     private static final int TEST_DRIVER_DISPLAY_ID = 100;
     private static final int TEST_PASSENGER_DISPLAY_ID = 101;
diff --git a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediatorTest.java b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediatorTest.java
index a75144ef..fe76c421 100644
--- a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediatorTest.java
+++ b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediatorTest.java
@@ -33,7 +33,7 @@ import androidx.test.filters.SmallTest;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.internal.widget.LockPatternUtils;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.settings.UserTracker;
@@ -51,7 +51,7 @@ import org.mockito.quality.Strictness;
 @RunWith(AndroidTestingRunner.class)
 @SmallTest
 @EnableFlags(Flags.FLAG_SUPPORTS_SECURE_PASSENGER_USERS)
-public class PassengerKeyguardOverlayViewMediatorTest extends SysuiTestCase {
+public class PassengerKeyguardOverlayViewMediatorTest extends CarSysuiTestCase {
     private static final int TEST_USER_ID = 1000;
 
     private PassengerKeyguardOverlayViewMediator mMediator;
diff --git a/tests/src/com/android/systemui/car/ndo/BlockerViewModelTest.java b/tests/src/com/android/systemui/car/ndo/BlockerViewModelTest.java
index 286d4a31..73417581 100644
--- a/tests/src/com/android/systemui/car/ndo/BlockerViewModelTest.java
+++ b/tests/src/com/android/systemui/car/ndo/BlockerViewModelTest.java
@@ -34,7 +34,7 @@ import androidx.lifecycle.LiveData;
 import androidx.test.filters.SmallTest;
 
 import com.android.car.telephony.calling.InCallServiceManager;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.telecom.InCallServiceImpl;
 import com.android.systemui.lifecycle.InstantTaskExecutorRule;
@@ -54,7 +54,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class BlockerViewModelTest extends SysuiTestCase {
+public class BlockerViewModelTest extends CarSysuiTestCase {
     private BlockerViewModel mBlockerViewModel;
     private static final String PROPERTY_IN_CALL_SERVICE = "PROPERTY_IN_CALL_SERVICE";
     private static final String BLOCKED_ACTIVITY_PKG_NAME = "com.blocked.activity";
diff --git a/tests/src/com/android/systemui/car/ndo/InCallLiveDataTest.java b/tests/src/com/android/systemui/car/ndo/InCallLiveDataTest.java
index 8f3d8e85..db0bcfe8 100644
--- a/tests/src/com/android/systemui/car/ndo/InCallLiveDataTest.java
+++ b/tests/src/com/android/systemui/car/ndo/InCallLiveDataTest.java
@@ -31,7 +31,7 @@ import android.testing.TestableLooper;
 import androidx.test.filters.SmallTest;
 
 import com.android.car.telephony.calling.InCallServiceManager;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.telecom.InCallServiceImpl;
 import com.android.systemui.lifecycle.InstantTaskExecutorRule;
@@ -50,7 +50,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class InCallLiveDataTest extends SysuiTestCase {
+public class InCallLiveDataTest extends CarSysuiTestCase {
     @Rule
     public TestRule rule = new InstantTaskExecutorRule();
 
diff --git a/tests/src/com/android/systemui/car/ndo/MediaSessionHelperTest.java b/tests/src/com/android/systemui/car/ndo/MediaSessionHelperTest.java
index b40fcd06..29aa787a 100644
--- a/tests/src/com/android/systemui/car/ndo/MediaSessionHelperTest.java
+++ b/tests/src/com/android/systemui/car/ndo/MediaSessionHelperTest.java
@@ -40,7 +40,7 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.lifecycle.InstantTaskExecutorRule;
 
@@ -58,7 +58,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class MediaSessionHelperTest extends SysuiTestCase {
+public class MediaSessionHelperTest extends CarSysuiTestCase {
 
     private MediaSessionHelper mMediaSessionHelper;
     private final UserHandle mUserHandle = UserHandle.CURRENT;
diff --git a/tests/src/com/android/systemui/car/notification/CarHeadsUpNotificationSystemContainerTest.java b/tests/src/com/android/systemui/car/notification/CarHeadsUpNotificationSystemContainerTest.java
index 19b7f7ba..17ba275f 100644
--- a/tests/src/com/android/systemui/car/notification/CarHeadsUpNotificationSystemContainerTest.java
+++ b/tests/src/com/android/systemui/car/notification/CarHeadsUpNotificationSystemContainerTest.java
@@ -28,7 +28,7 @@ import android.view.WindowManager;
 import androidx.test.filters.SmallTest;
 
 import com.android.car.notification.CarNotificationTypeItem;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.window.OverlayViewGlobalStateController;
@@ -43,7 +43,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CarHeadsUpNotificationSystemContainerTest extends SysuiTestCase {
+public class CarHeadsUpNotificationSystemContainerTest extends CarSysuiTestCase {
     private CarHeadsUpNotificationSystemContainer mCarHeadsUpNotificationSystemContainer;
     @Mock
     private CarDeviceProvisionedController mCarDeviceProvisionedController;
diff --git a/tests/src/com/android/systemui/car/notification/NotificationVisibilityLoggerTest.java b/tests/src/com/android/systemui/car/notification/NotificationVisibilityLoggerTest.java
index 4c3fae5c..b07e2adc 100644
--- a/tests/src/com/android/systemui/car/notification/NotificationVisibilityLoggerTest.java
+++ b/tests/src/com/android/systemui/car/notification/NotificationVisibilityLoggerTest.java
@@ -40,7 +40,7 @@ import com.android.car.notification.NotificationDataManager;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.statusbar.NotificationVisibility;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.util.concurrency.FakeExecutor;
@@ -61,7 +61,7 @@ import java.util.Collections;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class NotificationVisibilityLoggerTest extends SysuiTestCase {
+public class NotificationVisibilityLoggerTest extends CarSysuiTestCase {
 
     private static final String PKG = "package_1";
     private static final String OP_PKG = "OpPackage";
diff --git a/tests/src/com/android/systemui/car/privacy/CameraQcPanelTest.java b/tests/src/com/android/systemui/car/privacy/CameraQcPanelTest.java
index 73568044..90a22a4c 100644
--- a/tests/src/com/android/systemui/car/privacy/CameraQcPanelTest.java
+++ b/tests/src/com/android/systemui/car/privacy/CameraQcPanelTest.java
@@ -37,8 +37,8 @@ import androidx.test.filters.SmallTest;
 
 import com.android.car.qc.QCItem;
 import com.android.car.qc.QCList;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.CameraPrivacyChipViewController;
 import com.android.systemui.privacy.PrivacyDialog;
@@ -57,7 +57,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CameraQcPanelTest extends SysuiTestCase {
+public class CameraQcPanelTest extends CarSysuiTestCase {
     private static final String APP_LABEL_ACTIVE = "active";
     private static final String APP_LABEL_INACTIVE = "inactive";
     private static final String PACKAGE_NAME = "package";
diff --git a/tests/src/com/android/systemui/car/privacy/MicQcPanelTest.java b/tests/src/com/android/systemui/car/privacy/MicQcPanelTest.java
index d0ca1248..047cd9bc 100644
--- a/tests/src/com/android/systemui/car/privacy/MicQcPanelTest.java
+++ b/tests/src/com/android/systemui/car/privacy/MicQcPanelTest.java
@@ -37,8 +37,8 @@ import androidx.test.filters.SmallTest;
 
 import com.android.car.qc.QCItem;
 import com.android.car.qc.QCList;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.MicPrivacyChipViewController;
 import com.android.systemui.privacy.PrivacyDialog;
@@ -57,7 +57,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class MicQcPanelTest extends SysuiTestCase {
+public class MicQcPanelTest extends CarSysuiTestCase {
     private static final String APP_LABEL_ACTIVE = "active";
     private static final String APP_LABEL_INACTIVE = "inactive";
     private static final String PACKAGE_NAME = "package";
diff --git a/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java b/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java
index 59f0056f..ba0996f2 100644
--- a/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java
+++ b/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java
@@ -23,6 +23,8 @@ import static com.android.car.datasubscription.Flags.FLAG_DATA_SUBSCRIPTION_POP_
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
 
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
@@ -55,10 +57,13 @@ import android.widget.PopupWindow;
 import androidx.test.filters.SmallTest;
 
 import com.android.car.datasubscription.DataSubscription;
+import com.android.car.datasubscription.DataSubscriptionStatus;
 import com.android.car.ui.utils.CarUxRestrictionsUtil;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.R;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.settings.UserTracker;
+import com.android.systemui.util.FakeSharedPreferences;
 
 import org.junit.After;
 import org.junit.Assert;
@@ -78,7 +83,7 @@ import java.util.concurrent.Executor;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class DataSubscriptionControllerTest extends SysuiTestCase {
+public class DataSubscriptionControllerTest extends CarSysuiTestCase {
     @Mock
     private UserTracker mUserTracker;
     @Mock
@@ -103,6 +108,7 @@ public class DataSubscriptionControllerTest extends SysuiTestCase {
     private CarUxRestrictionsUtil mCarUxRestrictionsUtil;
     @Mock
     private DataSubscriptionStatsLogHelper mDataSubscriptionStatsLogHelper;
+    private final FakeSharedPreferences mSharedPreferences = new FakeSharedPreferences();
     private MockitoSession mMockingSession;
     private ActivityManager.RunningTaskInfo mRunningTaskInfoMock;
     private DataSubscriptionController mController;
@@ -124,6 +130,7 @@ public class DataSubscriptionControllerTest extends SysuiTestCase {
         mController.setSubscription(mDataSubscription);
         mController.setPopupWindow(mPopupWindow);
         mController.setConnectivityManager(mConnectivityManager);
+        mController.setSharedPreference(mSharedPreferences);
         mRunningTaskInfoMock = new ActivityManager.RunningTaskInfo();
         mRunningTaskInfoMock.topActivity = new ComponentName("testPkgName", "testClassName");
         mRunningTaskInfoMock.taskId = 1;
@@ -140,15 +147,128 @@ public class DataSubscriptionControllerTest extends SysuiTestCase {
 
     @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
     @Test
-    public void setAnchorView_viewNotNull_popUpDisplay() {
+    public void updateShouldDisplayProactiveMsg_noCachedTimeInterval_popUpDisplay() {
+        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
+                "2025-01-15");
         when(mPopupWindow.isShowing()).thenReturn(false);
         when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
 
-        mController.setAnchorView(mAnchorView);
+        mController.setWasProactiveMsgDisplayed(false);
+        mController.setCurrentInterval(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_frequency) + 1);
+
+        mController.updateShouldDisplayProactiveMsg();
+
+        assertTrue(mController.getShouldDisplayProactiveMsg());
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void updateShouldDisplayProactiveMsg_allConfigsAreValid_popUpDisplay() {
+        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
+                "2025-01-15");
+        when(mPopupWindow.isShowing()).thenReturn(false);
+        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
+
+        mController.setWasProactiveMsgDisplayed(false);
+        mController.setCurrentInterval(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_frequency));
+        mController.setCurrentCycle(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit));
+        mController.setCurrentActiveDays(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_active_days_limit));
+
+        mController.updateShouldDisplayProactiveMsg();
+
+        assertTrue(mController.getShouldDisplayProactiveMsg());
+    }
 
-        verify(mDataSubscription).addDataSubscriptionListener(any());
-        verify(mCarUxRestrictionsUtil).register(any());
-        verify(mAnchorView).post(any());
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void updateShouldDisplayProactiveMsg_invalidTimeInterval_popUpNotDisplay() {
+        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
+                "2025-01-15");
+        when(mPopupWindow.isShowing()).thenReturn(false);
+        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
+
+        mController.setWasProactiveMsgDisplayed(false);
+        mController.setCurrentInterval(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_frequency) - 1);
+        mController.setCurrentCycle(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit));
+
+        mController.updateShouldDisplayProactiveMsg();
+
+        assertFalse(mController.getShouldDisplayProactiveMsg());
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void updateShouldDisplayProactiveMsg_invalidCycle_popUpNotDisplay() {
+        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
+                "2025-01-15");
+        when(mPopupWindow.isShowing()).thenReturn(false);
+        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
+
+        mController.setWasProactiveMsgDisplayed(false);
+        mController.setCurrentInterval(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_frequency));
+        mController.setCurrentCycle(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit));
+        mController.setCurrentCycle(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit) + 1);
+
+        mController.updateShouldDisplayProactiveMsg();
+
+        assertFalse(mController.getShouldDisplayProactiveMsg());
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void updateShouldDisplayProactiveMsg_invalidActiveDays_popUpNotDisplay() {
+        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
+                "2025-01-15");
+        when(mPopupWindow.isShowing()).thenReturn(false);
+        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
+        mController.setWasProactiveMsgDisplayed(false);
+        mController.setCurrentInterval(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_frequency));
+        mController.setCurrentCycle(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit) + 1);
+
+        mController.updateShouldDisplayProactiveMsg();
+
+        assertFalse(mController.getShouldDisplayProactiveMsg());
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void updateShouldDisplayProactiveMsg_resetStatus_popUpDisplay() {
+        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
+                "2025-01-15");
+        when(mPopupWindow.isShowing()).thenReturn(false);
+        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
+        mSharedPreferences.edit().putInt(DataSubscriptionController.KEY_PREV_POPUP_STATUS,
+                DataSubscriptionStatus.INACTIVE);
+
+        mController.setWasProactiveMsgDisplayed(false);
+        mController.setCurrentInterval(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_frequency));
+        mController.setCurrentCycle(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit));
+        mController.setCurrentActiveDays(mContext.getResources()
+                .getInteger(R.integer.data_subscription_pop_up_active_days_limit) + 1);
+
+        mController.updateShouldDisplayProactiveMsg();
+
+        assertFalse(mController.getShouldDisplayProactiveMsg());
+
+        mSharedPreferences.edit().putInt(DataSubscriptionController.KEY_PREV_POPUP_STATUS,
+                DataSubscriptionStatus.PAID);
+
+        mController.setAnchorView(mAnchorView);
+        mController.updateShouldDisplayProactiveMsg();
+        assertTrue(mController.getShouldDisplayProactiveMsg());
     }
 
     @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
@@ -274,6 +394,8 @@ public class DataSubscriptionControllerTest extends SysuiTestCase {
         doReturn(mCarUxRestrictionsUtil).when(() -> CarUxRestrictionsUtil.getInstance(any()));
 
         when(mPopupWindow.isShowing()).thenReturn(true);
+        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
+                "2025-01-15");
         ArgumentCaptor<CarUxRestrictionsUtil.OnUxRestrictionsChangedListener> captor =
                 ArgumentCaptor.forClass(
                         CarUxRestrictionsUtil.OnUxRestrictionsChangedListener.class);
@@ -295,6 +417,8 @@ public class DataSubscriptionControllerTest extends SysuiTestCase {
         doReturn(mCarUxRestrictionsUtil).when(() -> CarUxRestrictionsUtil.getInstance(any()));
 
         when(mPopupWindow.isShowing()).thenReturn(true);
+        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
+                "2025-01-15");
         ArgumentCaptor<CarUxRestrictionsUtil.OnUxRestrictionsChangedListener> captor =
                 ArgumentCaptor.forClass(
                         CarUxRestrictionsUtil.OnUxRestrictionsChangedListener.class);
diff --git a/tests/src/com/android/systemui/car/qc/DriveModeQcPanelTest.java b/tests/src/com/android/systemui/car/qc/DriveModeQcPanelTest.java
index 88e9db98..de61f044 100644
--- a/tests/src/com/android/systemui/car/qc/DriveModeQcPanelTest.java
+++ b/tests/src/com/android/systemui/car/qc/DriveModeQcPanelTest.java
@@ -23,7 +23,7 @@ import androidx.test.filters.SmallTest;
 
 import com.android.car.qc.QCList;
 import com.android.car.qc.QCRow;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.drivemode.InMemoryDriveModeManager;
 
@@ -38,7 +38,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class DriveModeQcPanelTest extends SysuiTestCase {
+public class DriveModeQcPanelTest extends CarSysuiTestCase {
 
     private DriveModeQcPanel mPanel;
 
diff --git a/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java b/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
index 31412c11..b24f07e3 100644
--- a/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
+++ b/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
@@ -45,7 +45,6 @@ import android.car.user.UserStopResponse;
 import android.car.user.UserSwitchRequest;
 import android.car.user.UserSwitchResult;
 import android.car.util.concurrent.AsyncFuture;
-import android.content.Context;
 import android.content.Intent;
 import android.content.pm.UserInfo;
 import android.graphics.drawable.Drawable;
@@ -61,8 +60,8 @@ import com.android.car.qc.QCItem;
 import com.android.car.qc.QCList;
 import com.android.car.qc.QCRow;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.car.userswitcher.UserIconProvider;
@@ -86,7 +85,9 @@ import java.util.concurrent.TimeoutException;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class ProfileSwitcherTest extends SysuiTestCase {
+public class ProfileSwitcherTest extends CarSysuiTestCase {
+    private static final int TEST_USER_ID_1 = 1000;
+    private static final int TEST_USER_ID_2 = 1001;
 
     private MockitoSession mSession;
     private ProfileSwitcher mProfileSwitcher;
@@ -111,21 +112,20 @@ public class ProfileSwitcherTest extends SysuiTestCase {
                 .strictness(Strictness.LENIENT)
                 .startMocking();
 
-        when(mUserTracker.getUserId()).thenReturn(1000);
-        when(mUserTracker.getUserHandle()).thenReturn(UserHandle.of(1000));
+        when(mUserTracker.getUserId()).thenReturn(TEST_USER_ID_1);
+        when(mUserTracker.getUserHandle()).thenReturn(UserHandle.of(TEST_USER_ID_1));
         when(mUserManager.getAliveUsers()).thenReturn(mAliveUsers);
         when(mUserManager.getUserSwitchability(any())).thenReturn(SWITCHABILITY_STATUS_OK);
         when(mUserManager.isVisibleBackgroundUsersSupported()).thenReturn(false);
-        mockUmGetVisibleUsers(mUserManager, 1000);
+        mockUmGetVisibleUsers(mUserManager, TEST_USER_ID_1);
         when(mDevicePolicyManager.isDeviceManaged()).thenReturn(false);
         when(mDevicePolicyManager.isOrganizationOwnedDeviceWithManagedProfile()).thenReturn(false);
         doReturn(false).when(() -> CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
         Drawable testDrawable = mContext.getDrawable(R.drawable.ic_android);
-        when(mUserIconProvider.getDrawableWithBadge(any(Context.class), any(UserInfo.class)))
-                .thenReturn(testDrawable);
-        when(mUserIconProvider.getDrawableWithBadge(any(Context.class), any(Drawable.class)))
-                .thenReturn(testDrawable);
-        when(mUserIconProvider.getRoundedGuestDefaultIcon(any())).thenReturn(testDrawable);
+        when(mUserIconProvider.getDrawableWithBadge(anyInt())).thenReturn(testDrawable);
+        when(mUserIconProvider.getDrawableWithBadge(any(Drawable.class))).thenReturn(testDrawable);
+        when(mUserIconProvider.getRoundedGuestDefaultIcon()).thenReturn(testDrawable);
+        when(mUserIconProvider.getRoundedAddUserIcon()).thenReturn(testDrawable);
 
         AsyncFuture<UserSwitchResult> switchResultFuture = mock(AsyncFuture.class);
         UserSwitchResult switchResult = mock(UserSwitchResult.class);
@@ -146,8 +146,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
     }
 
     private void setUpLogout() {
-        UserInfo user1 = generateUser(1000, "User1");
-        UserInfo user2 = generateUser(1001, "User2");
+        UserInfo user1 = generateUser(TEST_USER_ID_1, "User1");
+        UserInfo user2 = generateUser(TEST_USER_ID_2, "User2");
         mAliveUsers.add(user1);
         mAliveUsers.add(user2);
         when(mDevicePolicyManager.isDeviceManaged()).thenReturn(true);
@@ -194,7 +194,7 @@ public class ProfileSwitcherTest extends SysuiTestCase {
         UserInfo currentUser = generateUser(mUserTracker.getUserId(), "Current User");
         mAliveUsers.add(currentUser);
         when(mUserManager.getUserInfo(mUserTracker.getUserId())).thenReturn(currentUser);
-        UserInfo otherUser = generateUser(1001, "Other User");
+        UserInfo otherUser = generateUser(TEST_USER_ID_2, "Other User");
         mAliveUsers.add(otherUser);
         List<QCRow> rows = getProfileRows();
         assertThat(rows).hasSize(1);
@@ -203,8 +203,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
 
     @Test
     public void switchAllowed_usersSwitchable_returnsAllRows() {
-        UserInfo user1 = generateUser(1000, "User1");
-        UserInfo user2 = generateUser(1001, "User2");
+        UserInfo user1 = generateUser(TEST_USER_ID_1, "User1");
+        UserInfo user2 = generateUser(TEST_USER_ID_2, "User2");
         mAliveUsers.add(user1);
         mAliveUsers.add(user2);
         List<QCRow> rows = getProfileRows();
@@ -220,8 +220,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
 
     @Test
     public void switchAllowed_orderUsersByCreationTime() {
-        UserInfo user1 = generateUser(1001, "User2");
-        UserInfo user2 = generateUser(1000, "User1");
+        UserInfo user1 = generateUser(TEST_USER_ID_2, "User2");
+        UserInfo user2 = generateUser(TEST_USER_ID_1, "User1");
         mAliveUsers.add(user1);
         mAliveUsers.add(user2);
         List<QCRow> rows = getProfileRows();
@@ -237,8 +237,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
 
     @Test
     public void switchAllowed_userNotSwitchable_returnsValidRows() {
-        UserInfo user1 = generateUser(1000, "User1");
-        UserInfo user2 = generateUser(1001, "User2", /* supportsSwitch= */ false,
+        UserInfo user1 = generateUser(TEST_USER_ID_1, "User1");
+        UserInfo user2 = generateUser(TEST_USER_ID_2, "User2", /* supportsSwitch= */ false,
                 /* isFull= */ true, /* isGuest= */ false);
         mAliveUsers.add(user1);
         mAliveUsers.add(user2);
@@ -254,8 +254,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
 
     @Test
     public void switchAllowed_userGuest_returnsValidRows() {
-        UserInfo user1 = generateUser(1000, "User1");
-        UserInfo user2 = generateUser(1001, "User2", /* supportsSwitch= */ true,
+        UserInfo user1 = generateUser(TEST_USER_ID_1, "User1");
+        UserInfo user2 = generateUser(TEST_USER_ID_2, "User2", /* supportsSwitch= */ true,
                 /* isFull= */ true, /* isGuest= */ true);
         mAliveUsers.add(user1);
         mAliveUsers.add(user2);
@@ -271,8 +271,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
 
     @Test
     public void switchAllowed_userNotFull_returnsValidRows() {
-        UserInfo user1 = generateUser(1000, "User1");
-        UserInfo user2 = generateUser(1001, "User2", /* supportsSwitch= */ true,
+        UserInfo user1 = generateUser(TEST_USER_ID_1, "User1");
+        UserInfo user2 = generateUser(TEST_USER_ID_2, "User2", /* supportsSwitch= */ true,
                 /* isFull= */ false, /* isGuest= */ false);
         mAliveUsers.add(user1);
         mAliveUsers.add(user2);
@@ -290,8 +290,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
     public void switchAllowed_addUserDisallowed_returnsValidRows() {
         when(mUserManager.hasUserRestrictionForUser(eq(UserManager.DISALLOW_ADD_USER),
                 any())).thenReturn(true);
-        UserInfo user1 = generateUser(1000, "User1");
-        UserInfo user2 = generateUser(1001, "User2");
+        UserInfo user1 = generateUser(TEST_USER_ID_1, "User1");
+        UserInfo user2 = generateUser(TEST_USER_ID_2, "User2");
         mAliveUsers.add(user1);
         mAliveUsers.add(user2);
         List<QCRow> rows = getProfileRows();
@@ -306,7 +306,7 @@ public class ProfileSwitcherTest extends SysuiTestCase {
     @Test
     public void switchAllowed_deviceManaged_returnsValidRows() {
         when(mDevicePolicyManager.isDeviceManaged()).thenReturn(true);
-        UserInfo user1 = generateUser(1000, "User1");
+        UserInfo user1 = generateUser(TEST_USER_ID_1, "User1");
         mAliveUsers.add(user1);
         List<QCRow> rows = getProfileRows();
         // Expect four rows - one for the device owner message, one for the user,
@@ -333,8 +333,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
 
     @Test
     public void onUserPressed_triggersSwitch() {
-        int currentUserId = 1000;
-        int otherUserId = 1001;
+        int currentUserId = TEST_USER_ID_1;
+        int otherUserId = TEST_USER_ID_2;
         UserInfo user1 = generateUser(currentUserId, "User1");
         UserInfo user2 = generateUser(otherUserId, "User2");
         mAliveUsers.add(user1);
@@ -363,8 +363,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
     @Test
     public void onGuestPressed_createsAndSwitches()
             throws ExecutionException, InterruptedException, TimeoutException {
-        int currentUserId = 1000;
-        int guestUserId = 1001;
+        int currentUserId = TEST_USER_ID_1;
+        int guestUserId = TEST_USER_ID_2;
         AsyncFuture<UserCreationResult> createResultFuture = mock(AsyncFuture.class);
         when(createResultFuture.get(anyLong(), any())).thenReturn(null);
         when(mCarUserManager.createGuest(any())).thenReturn(createResultFuture);
@@ -400,8 +400,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
     @Test
     public void onUserPressed_alreadyStartedUser_doesNothing() {
         when(mUserManager.isVisibleBackgroundUsersSupported()).thenReturn(true);
-        int currentUserId = 1000;
-        int secondaryUserId = 1001;
+        int currentUserId = TEST_USER_ID_1;
+        int secondaryUserId = TEST_USER_ID_2;
         UserInfo user1 = generateUser(currentUserId, "User1");
         UserInfo user2 = generateUser(secondaryUserId, "User2");
         mAliveUsers.add(user1);
@@ -422,8 +422,8 @@ public class ProfileSwitcherTest extends SysuiTestCase {
 
     @Test
     public void onUserPressed_secondaryUser_stopsAndStartsNewUser() {
-        int currentUserId = 1000;
-        int secondaryUserId = 1001;
+        int currentUserId = TEST_USER_ID_1;
+        int secondaryUserId = TEST_USER_ID_2;
         int newUserId = 1002;
         doReturn(true).when(() -> CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
         when(mUserManager.isVisibleBackgroundUsersSupported()).thenReturn(true);
diff --git a/tests/src/com/android/systemui/car/qc/QCFooterViewControllerTest.java b/tests/src/com/android/systemui/car/qc/QCFooterViewControllerTest.java
index e9fcce41..e5f9acb1 100644
--- a/tests/src/com/android/systemui/car/qc/QCFooterViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/qc/QCFooterViewControllerTest.java
@@ -37,7 +37,7 @@ import android.testing.TestableLooper;
 import androidx.test.filters.SmallTest;
 
 import com.android.car.ui.utils.CarUxRestrictionsUtil;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
@@ -56,7 +56,7 @@ import org.mockito.quality.Strictness;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class QCFooterViewControllerTest extends SysuiTestCase {
+public class QCFooterViewControllerTest extends CarSysuiTestCase {
     @Mock
     private CarUxRestrictionsUtil mCarUxRestrictionsUtil;
     @Mock
diff --git a/tests/src/com/android/systemui/car/qc/QCLogoutButtonControllerTest.java b/tests/src/com/android/systemui/car/qc/QCLogoutButtonControllerTest.java
index b99ee7bf..cfe540e9 100644
--- a/tests/src/com/android/systemui/car/qc/QCLogoutButtonControllerTest.java
+++ b/tests/src/com/android/systemui/car/qc/QCLogoutButtonControllerTest.java
@@ -47,7 +47,7 @@ import android.view.Display;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -71,7 +71,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class QCLogoutButtonControllerTest extends SysuiTestCase {
+public class QCLogoutButtonControllerTest extends CarSysuiTestCase {
     @Mock
     private AlertDialog mDialog;
     @Mock
diff --git a/tests/src/com/android/systemui/car/qc/QCScreenOffButtonControllerTest.java b/tests/src/com/android/systemui/car/qc/QCScreenOffButtonControllerTest.java
index c61e7157..8d1c395c 100644
--- a/tests/src/com/android/systemui/car/qc/QCScreenOffButtonControllerTest.java
+++ b/tests/src/com/android/systemui/car/qc/QCScreenOffButtonControllerTest.java
@@ -31,7 +31,7 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -49,7 +49,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class QCScreenOffButtonControllerTest extends SysuiTestCase {
+public class QCScreenOffButtonControllerTest extends CarSysuiTestCase {
     private QCFooterView mView;
     private QCScreenOffButtonController mController;
 
diff --git a/tests/src/com/android/systemui/car/qc/QCUserPickerButtonControllerTest.java b/tests/src/com/android/systemui/car/qc/QCUserPickerButtonControllerTest.java
index de4bca19..048107a2 100644
--- a/tests/src/com/android/systemui/car/qc/QCUserPickerButtonControllerTest.java
+++ b/tests/src/com/android/systemui/car/qc/QCUserPickerButtonControllerTest.java
@@ -31,7 +31,7 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -49,7 +49,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class QCUserPickerButtonControllerTest extends SysuiTestCase {
+public class QCUserPickerButtonControllerTest extends CarSysuiTestCase {
     @Mock
     private Car mCar;
     @Mock
diff --git a/tests/src/com/android/systemui/car/sideloaded/SideLoadedAppDetectorTest.java b/tests/src/com/android/systemui/car/sideloaded/SideLoadedAppDetectorTest.java
index 8e0a7378..5d49c27e 100644
--- a/tests/src/com/android/systemui/car/sideloaded/SideLoadedAppDetectorTest.java
+++ b/tests/src/com/android/systemui/car/sideloaded/SideLoadedAppDetectorTest.java
@@ -34,8 +34,8 @@ import android.testing.TestableResources;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 
@@ -49,7 +49,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class SideLoadedAppDetectorTest extends SysuiTestCase {
+public class SideLoadedAppDetectorTest extends CarSysuiTestCase {
 
     private static final String SAFE_VENDOR = "com.safe.vendor";
     private static final String UNSAFE_VENDOR = "com.unsafe.vendor";
diff --git a/tests/src/com/android/systemui/car/sideloaded/SideLoadedAppListenerTest.java b/tests/src/com/android/systemui/car/sideloaded/SideLoadedAppListenerTest.java
index a8390aeb..09d151e5 100644
--- a/tests/src/com/android/systemui/car/sideloaded/SideLoadedAppListenerTest.java
+++ b/tests/src/com/android/systemui/car/sideloaded/SideLoadedAppListenerTest.java
@@ -34,7 +34,7 @@ import android.view.DisplayInfo;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.Before;
@@ -51,7 +51,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class SideLoadedAppListenerTest extends SysuiTestCase {
+public class SideLoadedAppListenerTest extends CarSysuiTestCase {
 
     private static final String APP_PACKAGE_NAME = "com.test";
     private static final String APP_CLASS_NAME = ".TestClass";
diff --git a/tests/src/com/android/systemui/car/statusicon/StatusIconControllerTest.java b/tests/src/com/android/systemui/car/statusicon/StatusIconControllerTest.java
index 8830419e..914f6f91 100644
--- a/tests/src/com/android/systemui/car/statusicon/StatusIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/StatusIconControllerTest.java
@@ -30,8 +30,8 @@ import android.widget.ImageView;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.Before;
@@ -44,7 +44,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class StatusIconControllerTest extends SysuiTestCase {
+public class StatusIconControllerTest extends CarSysuiTestCase {
 
     private TestStatusIconController mTestStatusIconController;
 
diff --git a/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java b/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
index 98ef2c2b..d77de653 100644
--- a/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
@@ -41,8 +41,8 @@ import androidx.test.filters.SmallTest;
 
 import com.android.car.qc.QCItem;
 import com.android.car.ui.FocusParkingView;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
@@ -62,7 +62,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class StatusIconPanelViewControllerTest extends SysuiTestCase {
+public class StatusIconPanelViewControllerTest extends CarSysuiTestCase {
     private StatusIconPanelViewController mViewController;
     private ImageView mAnchorView;
     private UserHandle mUserHandle;
@@ -87,8 +87,10 @@ public class StatusIconPanelViewControllerTest extends SysuiTestCase {
         when(mUserTracker.getUserHandle()).thenReturn(mUserHandle);
 
         mAnchorView = spy(new ImageView(mContext));
-        mAnchorView.setImageDrawable(mContext.getDrawable(R.drawable.ic_bluetooth_status_off));
-        mAnchorView.setColorFilter(mContext.getColor(R.color.car_status_icon_color));
+        mAnchorView.setImageDrawable(mContext.getResources().getDrawable(
+                R.drawable.ic_bluetooth_status_off, mContext.getTheme()));
+        mAnchorView.setColorFilter(mContext.getResources().getColor(
+                R.color.car_status_icon_color, mContext.getTheme()));
         mViewController = new StatusIconPanelViewController.Builder(mContext, mUserTracker,
                 mBroadcastDispatcher, mConfigurationController, mDeviceProvisionedController,
                 mCarSystemBarElementInitializer).build(mAnchorView,
diff --git a/tests/src/com/android/systemui/car/statusicon/StatusIconViewControllerTest.java b/tests/src/com/android/systemui/car/statusicon/StatusIconViewControllerTest.java
index c5886092..7895a8c4 100644
--- a/tests/src/com/android/systemui/car/statusicon/StatusIconViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/StatusIconViewControllerTest.java
@@ -26,8 +26,8 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
@@ -42,7 +42,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class StatusIconViewControllerTest extends SysuiTestCase {
+public class StatusIconViewControllerTest extends CarSysuiTestCase {
 
     private TestStatusIconViewController mController;
 
diff --git a/tests/src/com/android/systemui/car/statusicon/ui/BluetoothStatusIconControllerTest.java b/tests/src/com/android/systemui/car/statusicon/ui/BluetoothStatusIconControllerTest.java
index fc039076..89ea3a0e 100644
--- a/tests/src/com/android/systemui/car/statusicon/ui/BluetoothStatusIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/ui/BluetoothStatusIconControllerTest.java
@@ -29,7 +29,7 @@ import android.testing.TestableLooper;
 import androidx.test.filters.SmallTest;
 
 import com.android.settingslib.bluetooth.CachedBluetoothDevice;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.statusicon.StatusIconView;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -49,7 +49,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class BluetoothStatusIconControllerTest extends SysuiTestCase {
+public class BluetoothStatusIconControllerTest extends CarSysuiTestCase {
 
     @Mock
     Resources mResources;
diff --git a/tests/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconControllerTest.java b/tests/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconControllerTest.java
index 0ae76ecd..3b047862 100644
--- a/tests/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconControllerTest.java
@@ -35,7 +35,7 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.statusicon.StatusIconView;
@@ -56,7 +56,7 @@ import org.mockito.quality.Strictness;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class MediaVolumeStatusIconControllerTest extends SysuiTestCase {
+public class MediaVolumeStatusIconControllerTest extends CarSysuiTestCase {
     @Mock
     Car mCar;
     @Mock
diff --git a/tests/src/com/android/systemui/car/statusicon/ui/MobileSignalStatusIconControllerTest.java b/tests/src/com/android/systemui/car/statusicon/ui/MobileSignalStatusIconControllerTest.java
index d313d1d5..049aef8b 100644
--- a/tests/src/com/android/systemui/car/statusicon/ui/MobileSignalStatusIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/ui/MobileSignalStatusIconControllerTest.java
@@ -26,8 +26,8 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.statusicon.StatusIconView;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -46,7 +46,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class MobileSignalStatusIconControllerTest extends SysuiTestCase {
+public class MobileSignalStatusIconControllerTest extends CarSysuiTestCase {
     @Mock
     NetworkController mNetworkController;
     @Mock
diff --git a/tests/src/com/android/systemui/car/statusicon/ui/SignalStatusIconControllerTest.java b/tests/src/com/android/systemui/car/statusicon/ui/SignalStatusIconControllerTest.java
index b6c4aa7a..1086d92f 100644
--- a/tests/src/com/android/systemui/car/statusicon/ui/SignalStatusIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/ui/SignalStatusIconControllerTest.java
@@ -27,8 +27,8 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.qc.DataSubscriptionController;
 import com.android.systemui.car.statusicon.StatusIconView;
@@ -49,7 +49,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class SignalStatusIconControllerTest extends SysuiTestCase {
+public class SignalStatusIconControllerTest extends CarSysuiTestCase {
 
     @Mock
     Resources mResources;
diff --git a/tests/src/com/android/systemui/car/statusicon/ui/WifiSignalStatusIconControllerTest.java b/tests/src/com/android/systemui/car/statusicon/ui/WifiSignalStatusIconControllerTest.java
index 699fb9dd..fede9822 100644
--- a/tests/src/com/android/systemui/car/statusicon/ui/WifiSignalStatusIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/ui/WifiSignalStatusIconControllerTest.java
@@ -28,8 +28,8 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.statusicon.StatusIconView;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -48,7 +48,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
 @SmallTest
-public class WifiSignalStatusIconControllerTest extends SysuiTestCase {
+public class WifiSignalStatusIconControllerTest extends CarSysuiTestCase {
     @Mock
     Resources mResources;
     @Mock
diff --git a/tests/src/com/android/systemui/car/systembar/ButtonRoleHolderControllerTest.java b/tests/src/com/android/systemui/car/systembar/ButtonRoleHolderControllerTest.java
index 3f2da15a..7a2c667a 100644
--- a/tests/src/com/android/systemui/car/systembar/ButtonRoleHolderControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/ButtonRoleHolderControllerTest.java
@@ -37,7 +37,7 @@ import android.widget.LinearLayout;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.tests.R;
@@ -54,7 +54,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class ButtonRoleHolderControllerTest extends SysuiTestCase {
+public class ButtonRoleHolderControllerTest extends CarSysuiTestCase {
     private static final String TEST_VALID_PACKAGE_NAME = "foo";
     private static final String TEST_INVALID_PACKAGE_NAME = "bar";
     private static final UserHandle TEST_CURRENT_USER = UserHandle.of(100);
diff --git a/tests/src/com/android/systemui/car/systembar/ButtonSelectionStateControllerTest.java b/tests/src/com/android/systemui/car/systembar/ButtonSelectionStateControllerTest.java
index 7352b575..eec13e13 100644
--- a/tests/src/com/android/systemui/car/systembar/ButtonSelectionStateControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/ButtonSelectionStateControllerTest.java
@@ -16,8 +16,16 @@
 
 package com.android.systemui.car.systembar;
 
+import static com.android.systemui.car.Flags.scalableUi;
+import static com.android.wm.shell.Flags.enableAutoTaskStackController;
+
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.junit.Assume.assumeFalse;
+import static org.junit.Assume.assumeTrue;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.Mockito.when;
+
 import android.app.ActivityTaskManager.RootTaskInfo;
 import android.content.ComponentName;
 import android.testing.AndroidTestingRunner;
@@ -27,13 +35,15 @@ import android.widget.LinearLayout;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
 import com.android.systemui.tests.R;
 
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
 import java.util.ArrayList;
@@ -43,7 +53,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class ButtonSelectionStateControllerTest extends SysuiTestCase {
+public class ButtonSelectionStateControllerTest extends CarSysuiTestCase {
 
     private static final String TEST_COMPONENT_NAME_PACKAGE = "com.android.car.carlauncher";
     private static final String TEST_COMPONENT_NAME_CLASS = ".CarLauncher";
@@ -57,18 +67,24 @@ public class ButtonSelectionStateControllerTest extends SysuiTestCase {
     private ButtonSelectionStateController mButtonSelectionStateController;
     private ComponentName mComponentName;
 
+    @Mock
+    private TaskPanelInfoRepository mTaskPanelInfoRepository;
+
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
 
         mTestView = (LinearLayout) LayoutInflater.from(mContext).inflate(
                 R.layout.car_button_selection_state_controller_test, /* root= */ null);
-        mButtonSelectionStateController = new ButtonSelectionStateController(mContext);
+        mButtonSelectionStateController = new ButtonSelectionStateController(mContext,
+                mTaskPanelInfoRepository);
         mButtonSelectionStateController.addAllButtonsWithSelectionState(mTestView);
     }
 
     @Test
     public void onTaskChanged_buttonDetectableByComponentName_selectsAssociatedButton() {
+        assumeFalse(isScalableUIEnabled());
+
         CarSystemBarButton testButton = mTestView.findViewById(R.id.detectable_by_component_name);
         mComponentName = new ComponentName(TEST_COMPONENT_NAME_PACKAGE, TEST_COMPONENT_NAME_CLASS);
         List<RootTaskInfo> testStack = createTestStack(mComponentName);
@@ -80,6 +96,8 @@ public class ButtonSelectionStateControllerTest extends SysuiTestCase {
 
     @Test
     public void onTaskChanged_buttonDetectableByCategory_selectsAssociatedButton() {
+        assumeFalse(isScalableUIEnabled());
+
         CarSystemBarButton testButton = mTestView.findViewById(R.id.detectable_by_category);
         mComponentName = new ComponentName(TEST_CATEGORY, TEST_CATEGORY_CLASS);
         List<RootTaskInfo> testStack = createTestStack(mComponentName);
@@ -91,6 +109,8 @@ public class ButtonSelectionStateControllerTest extends SysuiTestCase {
 
     @Test
     public void onTaskChanged_buttonDetectableByPackage_selectsAssociatedButton() {
+        assumeFalse(isScalableUIEnabled());
+
         CarSystemBarButton testButton = mTestView.findViewById(R.id.detectable_by_package);
         mComponentName = new ComponentName(TEST_PACKAGE, TEST_PACKAGE_CLASS);
         List<RootTaskInfo> testStack = createTestStack(mComponentName);
@@ -102,6 +122,8 @@ public class ButtonSelectionStateControllerTest extends SysuiTestCase {
 
     @Test
     public void onTaskChanged_deselectsPreviouslySelectedButton() {
+        assumeFalse(isScalableUIEnabled());
+
         CarSystemBarButton oldButton = mTestView.findViewById(R.id.detectable_by_component_name);
         mComponentName = new ComponentName(TEST_COMPONENT_NAME_PACKAGE, TEST_COMPONENT_NAME_CLASS);
         List<RootTaskInfo> oldStack = createTestStack(mComponentName);
@@ -115,6 +137,55 @@ public class ButtonSelectionStateControllerTest extends SysuiTestCase {
         assertButtonUnselected(oldButton);
     }
 
+    @Test
+    public void onPanelTaskChanged_buttonDetectableByComponentName_selectsAssociatedButton() {
+        assumeTrue(isScalableUIEnabled());
+
+        CarSystemBarButton testButton = mTestView.findViewById(R.id.detectable_by_component_name);
+        mComponentName = new ComponentName(TEST_COMPONENT_NAME_PACKAGE, TEST_COMPONENT_NAME_CLASS);
+        when(mTaskPanelInfoRepository.isPackageVisibleOnDisplay(mComponentName.getPackageName(),
+                anyInt())).thenReturn(true);
+        testButton.setSelected(false);
+        mButtonSelectionStateController.panelTaskChanged();
+
+        assertbuttonSelected(testButton);
+    }
+
+    @Test
+    public void onPanelTaskChanged_buttonDetectableByPackage_selectsAssociatedButton() {
+        assumeTrue(isScalableUIEnabled());
+
+        CarSystemBarButton testButton = mTestView.findViewById(R.id.detectable_by_package);
+        mComponentName = new ComponentName(TEST_PACKAGE, TEST_PACKAGE_CLASS);
+        when(mTaskPanelInfoRepository.isPackageVisibleOnDisplay(mComponentName.getPackageName(),
+                anyInt())).thenReturn(true);
+        testButton.setSelected(false);
+        mButtonSelectionStateController.panelTaskChanged();
+
+        assertbuttonSelected(testButton);
+    }
+
+    @Test
+    public void onPanelTaskChanged_deselectsPreviouslySelectedButton() {
+        assumeTrue(isScalableUIEnabled());
+
+        CarSystemBarButton oldButton = mTestView.findViewById(R.id.detectable_by_component_name);
+        mComponentName = new ComponentName(TEST_COMPONENT_NAME_PACKAGE, TEST_COMPONENT_NAME_CLASS);
+        when(mTaskPanelInfoRepository.isComponentVisibleOnDisplay(mComponentName, anyInt()))
+                .thenReturn(true);
+        oldButton.setSelected(false);
+        mButtonSelectionStateController.panelTaskChanged();
+
+        when(mTaskPanelInfoRepository.isComponentVisibleOnDisplay(mComponentName, anyInt()))
+                .thenReturn(false);
+        mComponentName = new ComponentName(TEST_PACKAGE, TEST_PACKAGE_CLASS);
+        when(mTaskPanelInfoRepository.isComponentVisibleOnDisplay(mComponentName, anyInt()))
+                .thenReturn(true);
+        mButtonSelectionStateController.panelTaskChanged();
+
+        assertButtonUnselected(oldButton);
+    }
+
     // Comparing alpha is a valid way to verify button selection state because all test buttons use
     // highlightWhenSelected = true.
     private void assertbuttonSelected(CarSystemBarButton button) {
@@ -135,4 +206,10 @@ public class ButtonSelectionStateControllerTest extends SysuiTestCase {
 
         return testStack;
     }
+
+    private boolean isScalableUIEnabled() {
+        return scalableUi() && enableAutoTaskStackController()
+                && mContext.getResources().getBoolean(
+                com.android.systemui.R.bool.config_enableScalableUI);
+    }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java b/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
index 47aeff09..97848cdf 100644
--- a/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
@@ -41,8 +41,8 @@ import android.widget.FrameLayout;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.privacy.CameraPrivacyChip;
 import com.android.systemui.privacy.PrivacyItem;
@@ -65,7 +65,7 @@ import java.util.concurrent.Executor;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CameraPrivacyChipViewControllerTest extends SysuiTestCase {
+public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
     private static final int TEST_USER_ID = 1001;
 
     private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarButtonTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarButtonTest.java
index ed3947ff..129ad717 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarButtonTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarButtonTest.java
@@ -46,8 +46,9 @@ import android.widget.LinearLayout;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.statusbar.AlphaOptimizedImageView;
 import com.android.systemui.tests.R;
 
@@ -55,15 +56,19 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentMatcher;
+import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @SmallTest
-public class CarSystemBarButtonTest extends SysuiTestCase {
+public class CarSystemBarButtonTest extends CarSysuiTestCase {
 
-    private static final String DIALER_BUTTON_ACTIVITY_NAME =
+    private static final String DIALER_ACTIVITY_NAME =
             "com.android.car.dialer/.ui.TelecomActivity";
+
+    private static final String LAUNCHER_ACTIVITY_NAME =
+            "com.android.car.carlauncher/.CarLauncher";
     private static final String BROADCAST_ACTION_NAME =
             "android.car.intent.action.TOGGLE_HVAC_CONTROLS";
 
@@ -73,6 +78,9 @@ public class CarSystemBarButtonTest extends SysuiTestCase {
     // Does not have any selection state which is the default configuration.
     private CarSystemBarButton mDefaultButton;
 
+    @Mock
+    private EventDispatcher mEventDispatcher;
+
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
@@ -262,7 +270,86 @@ public class CarSystemBarButtonTest extends SysuiTestCase {
         dialerButton.performClick();
         waitForIdleSync();
 
-        assertThat(getCurrentActivityName()).isEqualTo(DIALER_BUTTON_ACTIVITY_NAME);
+        assertThat(getCurrentActivityName()).isEqualTo(DIALER_ACTIVITY_NAME);
+    }
+
+    @Test
+    public void onClick_selectedIntentDefined_launchesIntentActivity() {
+        assumeFalse(hasSplitscreenMultitaskingFeature());
+
+        mDefaultButton.performClick();
+
+        CarSystemBarButton dialerButton = mTestView.findViewById(R.id.dialer_activity_toggle);
+        dialerButton.performClick();
+        waitForIdleSync();
+
+        assertThat(getCurrentActivityName()).isEqualTo(DIALER_ACTIVITY_NAME);
+
+        dialerButton.setSelected(true);
+        dialerButton.performClick();
+        waitForIdleSync();
+
+        assertThat(getCurrentActivityName()).isEqualTo(LAUNCHER_ACTIVITY_NAME);
+    }
+
+    @Test
+    public void onClick_selectedIntentMissing_launchesIntentActivity() {
+        assumeFalse(hasSplitscreenMultitaskingFeature());
+
+        mDefaultButton.performClick();
+
+        CarSystemBarButton dialerButton =
+                mTestView.findViewById(R.id.dialer_activity_toggle_missing_selected);
+        dialerButton.performClick();
+        waitForIdleSync();
+
+        assertThat(getCurrentActivityName()).isEqualTo(DIALER_ACTIVITY_NAME);
+
+        dialerButton.setSelected(true);
+        dialerButton.performClick();
+        waitForIdleSync();
+
+        assertThat(getCurrentActivityName()).isEqualTo(LAUNCHER_ACTIVITY_NAME);
+    }
+
+    @Test
+    public void onClick_selectionEventsDefined_firesEvents() {
+        mDefaultButton.performClick();
+
+        CarSystemBarButton appGridButton =
+                mTestView.findViewById(R.id.app_grid_button_with_selection_events);
+        appGridButton.setEventDispatcher(mEventDispatcher);
+        appGridButton.performClick();
+        waitForIdleSync();
+
+        verify(mEventDispatcher).executeTransaction("open_app_grid");
+
+        appGridButton.setSelected(true);
+        appGridButton.performClick();
+        waitForIdleSync();
+
+        verify(mEventDispatcher).executeTransaction("close_app_grid");
+    }
+
+    @Test
+    public void onClick_unselectEventMissing_firesEvents() {
+        assumeFalse(hasSplitscreenMultitaskingFeature());
+
+        mDefaultButton.performClick();
+
+        CarSystemBarButton appGridButton =
+                mTestView.findViewById(R.id.app_grid_button_without_unselect_event);
+        appGridButton.setEventDispatcher(mEventDispatcher);
+        appGridButton.performClick();
+        waitForIdleSync();
+
+        verify(mEventDispatcher).executeTransaction("open_app_grid");
+
+        appGridButton.setSelected(true);
+        appGridButton.performClick();
+        waitForIdleSync();
+
+        verify(mEventDispatcher).executeTransaction("close_app_grid");
     }
 
     @Test
@@ -276,7 +363,7 @@ public class CarSystemBarButtonTest extends SysuiTestCase {
                 R.id.long_click_dialer_activity);
         dialerButton.performLongClick();
 
-        assertThat(getCurrentActivityName()).isEqualTo(DIALER_BUTTON_ACTIVITY_NAME);
+        assertThat(getCurrentActivityName()).isEqualTo(DIALER_ACTIVITY_NAME);
     }
 
     @Test
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
index 76344fa9..df28c7de 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
@@ -36,6 +36,8 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.app.ActivityManager;
+import android.os.Handler;
+import android.os.HandlerThread;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.testing.TestableResources;
@@ -47,15 +49,14 @@ import android.view.WindowManager;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.car.dockutil.Flags;
 import com.android.car.ui.FocusParkingView;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.statusbar.LetterboxDetails;
 import com.android.internal.statusbar.RegisterStatusBarResult;
 import com.android.internal.view.AppearanceRegion;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.SysuiTestableContext;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
@@ -67,6 +68,7 @@ import com.android.systemui.car.systembar.element.CarSystemBarElementStateContro
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.car.window.OverlayVisibilityMediator;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.plugins.DarkIconDispatcher;
 import com.android.systemui.settings.FakeDisplayTracker;
 import com.android.systemui.settings.UserTracker;
@@ -102,7 +104,7 @@ import javax.inject.Provider;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CarSystemBarControllerTest extends SysuiTestCase {
+public class CarSystemBarControllerTest extends CarSysuiTestCase {
     private static final String TOP_NOTIFICATION_PANEL =
             "com.android.systemui.car.notification.TopNotificationPanelViewMediator";
     private static final String BOTTOM_NOTIFICATION_PANEL =
@@ -118,8 +120,6 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Mock
     private ActivityManager mActivityManager;
     @Mock
-    private ButtonSelectionStateController mButtonSelectionStateController;
-    @Mock
     private ButtonRoleHolderController mButtonRoleHolderController;
     @Mock
     private MicPrivacyChipViewController mMicPrivacyChipViewController;
@@ -157,6 +157,8 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     private OverlayVisibilityMediator mOverlayVisibilityMediator;
     private RegisterStatusBarResult mRegisterStatusBarResult;
     private SystemBarConfigs mSystemBarConfigs;
+    private HandlerThread mThread;
+    private Handler mHandler;
 
     @Before
     public void setUp() throws Exception {
@@ -181,7 +183,8 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
                         return new HomeButtonController(view,
                                 mock(CarSystemBarElementStatusBarDisableController.class),
                                 mock(CarSystemBarElementStateController.class),
-                                mUserTracker);
+                                mUserTracker, mock(EventDispatcher.class),
+                                mock(ButtonSelectionStateController.class));
                     }
                 };
         controllerFactoryMap.put(HomeButtonController.class, homeButtonControllerProvider);
@@ -192,7 +195,8 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
                         return new PassengerHomeButtonController(view,
                                 mock(CarSystemBarElementStatusBarDisableController.class),
                                 mock(CarSystemBarElementStateController.class),
-                                mUserTracker);
+                                mUserTracker, mock(EventDispatcher.class),
+                                mock(ButtonSelectionStateController.class));
                     }
                 };
         controllerFactoryMap.put(PassengerHomeButtonController.class,
@@ -201,13 +205,16 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
                 new CarSystemBarElementInitializer(controllerFactoryMap);
         mSystemBarConfigs =
                 new SystemBarConfigsImpl(mSpiedContext, mTestableResources.getResources());
+        mThread = new HandlerThread("TestThread");
+        mThread.start();
+        mHandler = Handler.createAsync(mThread.getLooper());
         CarSystemBarViewControllerFactory carSystemBarViewControllerFactory =
                 new CarSystemBarViewControllerImpl.Factory() {
                     public CarSystemBarViewControllerImpl create(@SystemBarSide int side,
                             ViewGroup view) {
                         return spy(new CarSystemBarViewControllerImpl(mSpiedContext, mUserTracker,
                                 carSystemBarElementInitializer, mSystemBarConfigs,
-                                mButtonRoleHolderController, mButtonSelectionStateController,
+                                mButtonRoleHolderController,
                                 () -> mCameraPrivacyChipViewController,
                                 () -> mMicPrivacyChipViewController, mOverlayVisibilityMediator,
                                 side, view));
@@ -239,6 +246,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         if (mSession != null) {
             mSession.finishMocking();
         }
+        if (mThread != null) {
+            mThread.quit();
+        }
     }
 
     private void initCarSystemBar() {
@@ -263,7 +273,8 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
                 mConfigurationController,
                 mCarSystemBarRestartTracker,
                 displayTracker,
-                null);
+                null,
+                mHandler);
     }
 
     @Test
@@ -730,12 +741,4 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
                 : ActivityManager.LOCK_TASK_MODE_NONE);
         mCarSystemBarController.setSystemBarStates(/* state= */ 0, /* state2= */ 0);
     }
-
-    private void enableSystemBarWithNotificationButton() {
-        if (Flags.dockFeature()) {
-            mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
-        } else {
-            mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        }
-    }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
index bc3920b9..115b5694 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
@@ -41,6 +41,7 @@ import static org.mockito.Mockito.when;
 import android.app.ActivityManager;
 import android.content.res.Configuration;
 import android.graphics.Rect;
+import android.os.Handler;
 import android.os.RemoteException;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
@@ -56,8 +57,8 @@ import androidx.test.filters.SmallTest;
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.statusbar.RegisterStatusBarResult;
 import com.android.internal.view.AppearanceRegion;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.SysuiTestableContext;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
@@ -78,6 +79,7 @@ import com.android.systemui.statusbar.policy.ConfigurationController;
 import com.android.systemui.statusbar.policy.KeyguardStateController;
 import com.android.systemui.util.concurrency.FakeExecutor;
 import com.android.systemui.util.time.FakeSystemClock;
+import com.android.systemui.utils.os.FakeHandler;
 
 import org.junit.Before;
 import org.junit.Test;
@@ -93,7 +95,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CarSystemBarTest extends SysuiTestCase {
+public class CarSystemBarTest extends CarSysuiTestCase {
 
     private TestableResources mTestableResources;
     private SysuiTestableContext mSpiedContext;
@@ -159,6 +161,7 @@ public class CarSystemBarTest extends SysuiTestCase {
     private AppearanceRegion[] mAppearanceRegions;
     private FakeExecutor mUiBgExecutor;
     private SystemBarConfigs mSystemBarConfigs;
+    private Handler mHandler;
 
     @Before
     public void setUp() {
@@ -166,6 +169,7 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources = mContext.getOrCreateTestableResources();
         mExecutor = new FakeExecutor(new FakeSystemClock());
         mUiBgExecutor = new FakeExecutor(new FakeSystemClock());
+        mHandler = new FakeHandler(TestableLooper.get(this).getLooper());
         mSpiedContext = spy(mContext);
         mSpiedContext.addMockSystemService(ActivityManager.class, mActivityManager);
         mSpiedContext.addMockSystemService(WindowManager.class, mWindowManager);
@@ -241,7 +245,8 @@ public class CarSystemBarTest extends SysuiTestCase {
                 mConfigurationController,
                 mCarSystemBarRestartTracker,
                 displayTracker,
-                null));
+                null,
+                mHandler));
     }
 
     @Test
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
index 0046472c..8226db5b 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
@@ -28,8 +28,8 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.notification.NotificationPanelViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
@@ -49,7 +49,7 @@ import java.util.Collections;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CarSystemBarViewTest extends SysuiTestCase {
+public class CarSystemBarViewTest extends CarSysuiTestCase {
 
     private CarSystemBarView mNavBarView;
 
@@ -66,8 +66,6 @@ public class CarSystemBarViewTest extends SysuiTestCase {
     @Mock
     private ButtonRoleHolderController mButtonRoleHolderController;
     @Mock
-    private ButtonSelectionStateController mButtonSelectionStateController;
-    @Mock
     private MicPrivacyChipViewController mMicPrivacyChipViewController;
     @Mock
     private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
@@ -142,7 +140,6 @@ public class CarSystemBarViewTest extends SysuiTestCase {
                 mCarSystemBarElementInitializer,
                 systemBarConfigs,
                 mButtonRoleHolderController,
-                mButtonSelectionStateController,
                 () -> mCameraPrivacyChipViewController,
                 () -> mMicPrivacyChipViewController,
                 mOverlayVisibilityMediator,
diff --git a/tests/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconControllerTest.java b/tests/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconControllerTest.java
index baf6cce1..830c4d0a 100644
--- a/tests/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconControllerTest.java
@@ -31,7 +31,7 @@ import android.testing.TestableLooper;
 import androidx.test.filters.SmallTest;
 
 import com.android.car.datasubscription.DataSubscription;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
@@ -48,7 +48,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class DataSubscriptionUnseenIconControllerTest extends SysuiTestCase {
+public class DataSubscriptionUnseenIconControllerTest extends CarSysuiTestCase {
     private DataSubscriptionUnseenIconController mController;
     @Mock
     private CarSystemBarImageView mView;
diff --git a/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java b/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
index 48a1ddb9..ef1707cb 100644
--- a/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
@@ -41,8 +41,8 @@ import android.widget.FrameLayout;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.privacy.MicPrivacyChip;
 import com.android.systemui.privacy.PrivacyItem;
@@ -65,7 +65,7 @@ import java.util.concurrent.Executor;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class MicPrivacyChipViewControllerTest extends SysuiTestCase {
+public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
     private static final int TEST_USER_ID = 1001;
 
     private MicPrivacyChipViewController mMicPrivacyChipViewController;
diff --git a/tests/src/com/android/systemui/car/systembar/RecentsButtonStateProviderTest.java b/tests/src/com/android/systemui/car/systembar/RecentsButtonStateProviderTest.java
index 95d271c9..534e76dd 100644
--- a/tests/src/com/android/systemui/car/systembar/RecentsButtonStateProviderTest.java
+++ b/tests/src/com/android/systemui/car/systembar/RecentsButtonStateProviderTest.java
@@ -42,8 +42,8 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.shared.system.TaskStackChangeListener;
 import com.android.systemui.statusbar.AlphaOptimizedImageView;
@@ -57,12 +57,11 @@ import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
 import java.util.function.Consumer;
-import java.util.function.Function;
 
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @SmallTest
-public class RecentsButtonStateProviderTest extends SysuiTestCase {
+public class RecentsButtonStateProviderTest extends CarSysuiTestCase {
     private static final String RECENTS_ACTIVITY_NAME =
             "com.android.car.carlauncher/.recents.CarRecentsActivity";
     private static final String DIALER_ACTIVITY_NAME = "com.android.car.dialer/.ui.TelecomActivity";
@@ -95,8 +94,6 @@ public class RecentsButtonStateProviderTest extends SysuiTestCase {
     @Mock
     private Intent mIntent;
     @Mock
-    private Function<Intent, View.OnClickListener> mIntentAndOnClickListenerFunction;
-    @Mock
     private Consumer<AlphaOptimizedImageView> mAlphaOptimizedImageViewConsumer;
     @Mock
     private View.OnClickListener mOnClickListener;
@@ -121,7 +118,7 @@ public class RecentsButtonStateProviderTest extends SysuiTestCase {
         when(mDialerBaseIntent.getComponent())
                 .thenReturn(ComponentName.unflattenFromString(DIALER_ACTIVITY_NAME));
         when(mCarSystemBarButton.getSelectedAlpha()).thenReturn(SELECTED_ALPHA);
-        when(mIntentAndOnClickListenerFunction.apply(any())).thenReturn(mOnClickListener);
+        when(mCarSystemBarButton.getIntent()).thenReturn(mIntent);
         mRecentsButtonStateProvider = new RecentsButtonStateProvider(mContext, mCarSystemBarButton);
         mTaskStackChangeListener = mRecentsButtonStateProvider.getTaskStackChangeListener();
     }
@@ -259,10 +256,10 @@ public class RecentsButtonStateProviderTest extends SysuiTestCase {
         mRecentsButtonStateProvider.setIsRecentsActive(false);
 
         View.OnClickListener onClickListener = mRecentsButtonStateProvider.getButtonClickListener(
-                mIntent, mIntentAndOnClickListenerFunction);
+                mOnClickListener);
         onClickListener.onClick(mCarSystemBarButton);
 
-        verify(mIntentAndOnClickListenerFunction, times(1)).apply(mIntent);
+        verify(mOnClickListener, times(1)).onClick(mCarSystemBarButton);
     }
 
     @Test
@@ -270,10 +267,10 @@ public class RecentsButtonStateProviderTest extends SysuiTestCase {
         mRecentsButtonStateProvider.setIsRecentsActive(true);
 
         View.OnClickListener onClickListener = mRecentsButtonStateProvider.getButtonClickListener(
-                mIntent, mIntentAndOnClickListenerFunction);
+                mOnClickListener);
         onClickListener.onClick(mCarSystemBarButton);
 
-        verify(mIntentAndOnClickListenerFunction, never()).apply(any());
+        verify(mOnClickListener, never()).onClick(any());
     }
 
     @Test
@@ -281,7 +278,7 @@ public class RecentsButtonStateProviderTest extends SysuiTestCase {
         mRecentsButtonStateProvider.setIsRecentsActive(false);
 
         View.OnClickListener onClickListener = mRecentsButtonStateProvider.getButtonClickListener(
-                mIntent, mIntentAndOnClickListenerFunction);
+                mOnClickListener);
         onClickListener.onClick(mCarSystemBarButton);
 
         verify(mInputManager, never()).injectInputEvent(argThat(this::isRecentsKeyEvent), anyInt());
@@ -292,7 +289,7 @@ public class RecentsButtonStateProviderTest extends SysuiTestCase {
         mRecentsButtonStateProvider.setIsRecentsActive(true);
 
         View.OnClickListener onClickListener = mRecentsButtonStateProvider.getButtonClickListener(
-                mIntent, mIntentAndOnClickListenerFunction);
+                mOnClickListener);
         onClickListener.onClick(mCarSystemBarButton);
 
         verify(mInputManager, times(1))
diff --git a/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java b/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
index 58647657..8ac98452 100644
--- a/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
+++ b/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
@@ -39,8 +39,8 @@ import android.view.WindowManager;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.notification.NotificationPanelViewController;
@@ -64,7 +64,7 @@ import java.util.Map;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class SystemBarConfigsTest extends SysuiTestCase {
+public class SystemBarConfigsTest extends CarSysuiTestCase {
     private static final int SYSTEM_BAR_GIRTH = 100;
 
     private SystemBarConfigsImpl mSystemBarConfigs;
diff --git a/tests/src/com/android/systemui/car/systembar/element/CarSystemBarElementControllerTest.java b/tests/src/com/android/systemui/car/systembar/element/CarSystemBarElementControllerTest.java
index ac7b794c..c0cdc935 100644
--- a/tests/src/com/android/systemui/car/systembar/element/CarSystemBarElementControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/element/CarSystemBarElementControllerTest.java
@@ -34,7 +34,7 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.Before;
@@ -47,7 +47,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CarSystemBarElementControllerTest extends SysuiTestCase {
+public class CarSystemBarElementControllerTest extends CarSysuiTestCase {
 
     private TestCarSystemBarElement mElement;
     private TestCarSystemBarElementController mController;
diff --git a/tests/src/com/android/systemui/car/systembar/element/CarSystemBarElementStatusBarDisableControllerTest.java b/tests/src/com/android/systemui/car/systembar/element/CarSystemBarElementStatusBarDisableControllerTest.java
index 413bd481..c1cf062f 100644
--- a/tests/src/com/android/systemui/car/systembar/element/CarSystemBarElementStatusBarDisableControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/element/CarSystemBarElementStatusBarDisableControllerTest.java
@@ -32,7 +32,7 @@ import android.view.Display;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.statusbar.CommandQueue;
 
@@ -47,7 +47,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CarSystemBarElementStatusBarDisableControllerTest extends SysuiTestCase {
+public class CarSystemBarElementStatusBarDisableControllerTest extends CarSysuiTestCase {
     private CarSystemBarElementStatusBarDisableController mController;
     @Mock
     private CommandQueue mCommandQueue;
diff --git a/tests/src/com/android/systemui/car/telecom/InCallServiceImplTest.java b/tests/src/com/android/systemui/car/telecom/InCallServiceImplTest.java
index 9cbc7dbf..e03ed0be 100644
--- a/tests/src/com/android/systemui/car/telecom/InCallServiceImplTest.java
+++ b/tests/src/com/android/systemui/car/telecom/InCallServiceImplTest.java
@@ -27,7 +27,7 @@ import android.testing.TestableLooper;
 import androidx.test.filters.SmallTest;
 
 import com.android.car.telephony.calling.InCallServiceManager;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.Before;
@@ -42,7 +42,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class InCallServiceImplTest extends SysuiTestCase {
+public class InCallServiceImplTest extends CarSysuiTestCase {
     private InCallServiceImpl mInCallService;
     @Mock
     private Call mMockCall;
diff --git a/tests/src/com/android/systemui/car/toast/CarToastUITest.java b/tests/src/com/android/systemui/car/toast/CarToastUITest.java
index c779664b..44f7a710 100644
--- a/tests/src/com/android/systemui/car/toast/CarToastUITest.java
+++ b/tests/src/com/android/systemui/car/toast/CarToastUITest.java
@@ -36,8 +36,8 @@ import android.view.View;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.CommandQueue;
@@ -56,7 +56,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class CarToastUITest extends SysuiTestCase {
+public class CarToastUITest extends CarSysuiTestCase {
     private static final int UID = 0;
     private static final int DURATION = 1000;
     private static final String PACKAGE_NAME = "PACKAGE_NAME";
diff --git a/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java b/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
index c6fe1d16..f4919b57 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
@@ -96,7 +96,8 @@ public class UserEventManagerTest extends UserPickerTestCase {
         doReturn(mMockCarUserManager).when(mMockCarServiceMediator).getCarUserManager();
 
         mUserEventManager =
-                new UserEventManager(mContext, mMockCarServiceMediator, mMockUserPickerSharedState);
+                new UserEventManager(mContext, mMockCarServiceMediator, mMockUserPickerSharedState,
+                        mMockUserManager);
         mUserEventManager.registerOnUpdateUsersListener(mMockOnUpdateUsersListener,
                 MAIN_DISPLAY_ID);
         spyOn(mUserEventManager);
diff --git a/tests/src/com/android/systemui/car/userpicker/UserPickerBottomBarTest.java b/tests/src/com/android/systemui/car/userpicker/UserPickerBottomBarTest.java
index c9619d88..34977bca 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserPickerBottomBarTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserPickerBottomBarTest.java
@@ -53,11 +53,11 @@ public class UserPickerBottomBarTest extends UserPickerTestCase {
 
     @Test
     public void checkBottomBarHeight_validDimension() {
-        float target_height = mContext.getResources()
-                .getDimension(R.dimen.car_bottom_system_bar_height);
+        int target_height = mContext.getResources()
+                .getDimensionPixelSize(R.dimen.car_bottom_system_bar_height);
         mActivityRule.getScenario().onActivity(activity -> {
             ConstraintLayout bottombar = activity.findViewById(R.id.user_picker_bottom_bar);
-            float height = bottombar.getLayoutParams().height;
+            int height = bottombar.getLayoutParams().height;
 
             assertThat(height).isEqualTo(target_height);
         });
diff --git a/tests/src/com/android/systemui/car/userpicker/UserPickerControllerTest.java b/tests/src/com/android/systemui/car/userpicker/UserPickerControllerTest.java
index 0f3a2c17..3a0909fc 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserPickerControllerTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserPickerControllerTest.java
@@ -44,6 +44,7 @@ import androidx.test.filters.SmallTest;
 import com.android.systemui.R;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.userpicker.UserPickerController.Callbacks;
+import com.android.systemui.car.userswitcher.UserIconProvider;
 import com.android.systemui.settings.DisplayTracker;
 
 import com.google.android.material.snackbar.Snackbar;
@@ -141,7 +142,7 @@ public class UserPickerControllerTest extends UserPickerTestCase {
 
         mUserPickerController = new UserPickerController(mContext, mMockUserEventManager,
                 mMockCarServiceMediator, mMockDialogManager, mSnackbarManager,
-                mMockDisplayTracker, mUserPickerSharedState);
+                mMockDisplayTracker, mUserPickerSharedState, mock(UserIconProvider.class));
         mUserPickerController.init(mMockCallbacks, displayId);
         mUserPickerController.onConfigurationChanged();
         AndroidMockitoHelper.mockAmGetCurrentUser(USER_ID_DRIVER);
diff --git a/tests/src/com/android/systemui/car/userpicker/UserPickerRecyclerViewTest.java b/tests/src/com/android/systemui/car/userpicker/UserPickerRecyclerViewTest.java
index 50e9f9d0..476d9b04 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserPickerRecyclerViewTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserPickerRecyclerViewTest.java
@@ -92,21 +92,21 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
         mDriver = UserRecord.create(mDriverUserInfo, /* mName= */ mDriverUserInfo.name,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ true,
-                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mDriverUserInfo, mContext),
+                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(USER_ID_DRIVER),
                 /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
                 /* mIsLoggedIn= */ true, /* mLoggedInDisplay= */ MAIN_DISPLAY_ID,
                 /* mSeatLocationName= */ USER_NAME_DRIVER, /* mIsStopping= */ false);
         mFront = UserRecord.create(mFrontUserInfo, /* mName= */ mFrontUserInfo.name,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
-                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mFrontUserInfo, mContext),
+                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(USER_ID_FRONT),
                 /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
                 /* mIsLoggedIn= */ true, /* mLoggedInDisplay= */ FRONT_PASSENGER_DISPLAY_ID,
                 /* mSeatLocationName= */ USER_NAME_FRONT, /* mIsStopping= */ false);
         mRear = UserRecord.create(mRearUserInfo, /* mName= */ mRearUserInfo.name,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
-                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
+                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(USER_ID_REAR),
                 /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
                 /* mIsLoggedIn= */ false, /* mLoggedInDisplay= */ INVALID_DISPLAY,
                 /* mSeatLocationName= */ "", /* mIsStopping= */ false);
@@ -156,7 +156,7 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
         UserRecord mGuest = UserRecord.create(/* mInfo= */ null, /* mName= */ mGuestLabel,
                 /* mIsStartGuestSession= */ true, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
-                mMockUserIconProvider.getRoundedGuestDefaultIcon(mContext),
+                mMockUserIconProvider.getRoundedGuestDefaultIcon(),
                 /* OnClickListenerMaker */ new OnClickListenerCreator(), false, false,
                 INVALID_DISPLAY, /* mSeatLocationName= */"", /* mIsStopping= */ false);
         UserRecord mAddUser = UserRecord.create(/* mInfo= */ null, /* mName= */ mAddLabel,
@@ -200,7 +200,7 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
         mFront = UserRecord.create(mFrontUserInfo, /* mName= */ mFrontUserInfo.name,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
-                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mFrontUserInfo, mContext),
+                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(USER_ID_FRONT),
                 /* OnClickListenerMaker */ new OnClickListenerCreator(),
                 /* mIsSecure= */ false, /* mIsLoggedIn= */ false,
                 /* mLoggedInDisplay= */ -1,
@@ -208,7 +208,7 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
         UserRecord mGuest = UserRecord.create(/* mInfo= */ null, /* mName= */ mGuestLabel,
                 /* mIsStartGuestSession= */ true, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
-                mMockUserIconProvider.getRoundedGuestDefaultIcon(mContext),
+                mMockUserIconProvider.getRoundedGuestDefaultIcon(),
                 /* OnClickListenerMaker */ new OnClickListenerCreator(), false, false,
                 INVALID_DISPLAY, /* mSeatLocationName= */"", /* mIsStopping= */ false);
         UserRecord mAddUser = UserRecord.create(/* mInfo= */ null, /* mName= */ mAddLabel,
@@ -255,7 +255,7 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
             UserRecord mNew = UserRecord.create(newUserInfo, /* mName= */ newUserInfo.name,
                     /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                     /* mIsForeground= */ false,
-                    /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(newUserInfo, mContext),
+                    /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(newUserInfo.id),
                     /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
                     /* mIsLoggedIn= */ false,
                     /* mLoggedInDisplay= */ INVALID_DISPLAY,
@@ -301,7 +301,7 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
             mRear = UserRecord.create(mRearUserInfo, /* mName= */ mRearUserInfo.name,
                     /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                     /* mIsForeground= */ false,
-                    /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
+                    /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(USER_ID_REAR),
                     /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
                     /* mIsLoggedIn= */ true,
                     /* mLoggedInDisplay= */ REAR_PASSENGER_DISPLAY_ID,
@@ -323,7 +323,7 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
         mRear = UserRecord.create(mRearUserInfo, /* mName= */ mRearUserInfo.name,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
-                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
+                /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(USER_ID_REAR),
                 /* OnClickListenerMaker */ new OnClickListenerCreator(),
                 /* mIsSecure= */ false, /* mIsLoggedIn= */ true,
                 /* mLoggedInDisplay= */ REAR_PASSENGER_DISPLAY_ID,
@@ -340,7 +340,7 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
             mRear = UserRecord.create(mRearUserInfo, /* mName= */ mRearUserInfo.name,
                     /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                     /* mIsForeground= */ false,
-                    /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
+                    /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(USER_ID_REAR),
                     /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
                     /* mIsLoggedIn= */ false,
                     /* mLoggedInDisplay= */ INVALID_DISPLAY,
@@ -370,7 +370,7 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
             mRear = UserRecord.create(mRearUserInfo, /* mName= */ mRearUserInfo.name,
                     /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                     /* mIsForeground= */ false,
-                    /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
+                    /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(USER_ID_REAR),
                     /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
                     /* mIsLoggedIn= */ false,
                     /* mLoggedInDisplay= */ INVALID_DISPLAY,
diff --git a/tests/src/com/android/systemui/car/userpicker/UserPickerTestCase.java b/tests/src/com/android/systemui/car/userpicker/UserPickerTestCase.java
index a8f2ab2b..f1623a83 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserPickerTestCase.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserPickerTestCase.java
@@ -37,12 +37,12 @@ import android.view.DisplayAdjustments;
 import android.view.DisplayInfo;
 import android.view.LayoutInflater;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 
 import org.junit.Before;
 
-public abstract class UserPickerTestCase extends SysuiTestCase {
+public abstract class UserPickerTestCase extends CarSysuiTestCase {
     static final int IDLE_TIMEOUT = 1_500;
 
     static final int USER_ID_DRIVER = 999;
diff --git a/tests/src/com/android/systemui/car/users/CarSystemUIUserUtilTest.java b/tests/src/com/android/systemui/car/users/CarSystemUIUserUtilTest.java
index b0aaf4e0..c604c012 100644
--- a/tests/src/com/android/systemui/car/users/CarSystemUIUserUtilTest.java
+++ b/tests/src/com/android/systemui/car/users/CarSystemUIUserUtilTest.java
@@ -31,7 +31,7 @@ import android.testing.AndroidTestingRunner;
 import androidx.test.filters.SmallTest;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.settings.UserTracker;
 
@@ -46,7 +46,7 @@ import org.mockito.quality.Strictness;
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @SmallTest
-public class CarSystemUIUserUtilTest extends SysuiTestCase {
+public class CarSystemUIUserUtilTest extends CarSysuiTestCase {
 
     private final UserHandle mUserHandle = UserHandle.of(1000);
     private final int mActivityManagerTestUser = 1001;
diff --git a/tests/src/com/android/systemui/car/userswitcher/UserIconProviderTest.java b/tests/src/com/android/systemui/car/userswitcher/UserIconProviderTest.java
index 80596697..ad5ab228 100644
--- a/tests/src/com/android/systemui/car/userswitcher/UserIconProviderTest.java
+++ b/tests/src/com/android/systemui/car/userswitcher/UserIconProviderTest.java
@@ -17,9 +17,6 @@
 package com.android.systemui.car.userswitcher;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.spyOn;
-
-import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.eq;
@@ -28,9 +25,7 @@ import static org.mockito.Mockito.when;
 
 import android.content.Context;
 import android.content.pm.UserInfo;
-import android.content.res.Resources;
 import android.graphics.Bitmap;
-import android.graphics.drawable.Drawable;
 import android.os.UserManager;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
@@ -39,7 +34,7 @@ import androidx.test.filters.SmallTest;
 
 import com.android.car.internal.user.UserHelper;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.After;
@@ -54,7 +49,7 @@ import org.mockito.quality.Strictness;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class UserIconProviderTest extends SysuiTestCase {
+public class UserIconProviderTest extends CarSysuiTestCase {
     private final UserInfo mUserInfo =
                 new UserInfo(/* id= */ 0, /* name= */ "User", /* flags= */ 0);
     private final UserInfo mGuestUserInfo =
@@ -63,33 +58,24 @@ public class UserIconProviderTest extends SysuiTestCase {
 
     private UserIconProvider mUserIconProvider;
     private MockitoSession mMockingSession;
-    private Resources mResources;
 
     @Mock
     private UserManager mUserManager;
     @Mock
-    private Drawable mDrawable;
-    @Mock
     private Bitmap mBitmap;
 
     @Before
     public void setUp() {
         mMockingSession = mockitoSession()
                 .initMocks(this)
-                .spyStatic(UserManager.class)
-                .spyStatic(UserHelper.class)
+                .mockStatic(UserHelper.class)
                 .strictness(Strictness.WARN)
                 .startMocking();
 
-        mContext.addMockSystemService(UserManager.class, mUserManager);
         when(mUserManager.getUserInfo(mUserInfo.id)).thenReturn(mUserInfo);
         when(mUserManager.getUserInfo(mGuestUserInfo.id)).thenReturn(mGuestUserInfo);
 
-        mUserIconProvider = new UserIconProvider();
-        spyOn(mUserIconProvider);
-
-        mResources = mContext.getResources();
-        spyOn(mResources);
+        mUserIconProvider = new UserIconProvider(mContext, mUserManager);
     }
 
     @After
@@ -100,17 +86,18 @@ public class UserIconProviderTest extends SysuiTestCase {
     }
 
     @Test
-    public void setRoundedUserIcon_existRoundedUserIcon() {
-        mUserIconProvider.setRoundedUserIcon(mUserInfo, mContext);
+    public void setRoundedUserIcon_assignDefaultIcon() {
+        mUserIconProvider.setRoundedUserIcon(mUserInfo.id);
 
-        assertThat(mUserIconProvider.getRoundedUserIcon(mUserInfo, mContext)).isNotNull();
+        ExtendedMockito.verify(() -> UserHelper.assignDefaultIcon(any(Context.class),
+                eq(mUserInfo.getUserHandle())));
     }
 
     @Test
     public void getRoundedUserIcon_notExistUserIcon_assignDefaultIcon() {
         when(mUserManager.getUserIcon(mUserInfo.id)).thenReturn(null);
 
-        mUserIconProvider.getRoundedUserIcon(mUserInfo, mContext);
+        mUserIconProvider.getRoundedUserIcon(mUserInfo.id);
 
         ExtendedMockito.verify(() -> UserHelper.assignDefaultIcon(any(Context.class),
                 eq(mUserInfo.getUserHandle())));
@@ -120,7 +107,7 @@ public class UserIconProviderTest extends SysuiTestCase {
     public void getRoundedUserIcon_existUserIcon_notAssignDefaultIcon() {
         when(mUserManager.getUserIcon(mUserInfo.id)).thenReturn(mBitmap);
 
-        mUserIconProvider.getRoundedUserIcon(mUserInfo, mContext);
+        mUserIconProvider.getRoundedUserIcon(mUserInfo.id);
 
         ExtendedMockito.verify(() -> UserHelper.assignDefaultIcon(any(Context.class),
                 eq(mUserInfo.getUserHandle())), never());
diff --git a/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewControllerTest.java b/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewControllerTest.java
index 902cceb6..73d53952 100644
--- a/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewControllerTest.java
@@ -46,8 +46,8 @@ import android.widget.TextView;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.window.OverlayViewGlobalStateController;
 import com.android.systemui.util.concurrency.FakeExecutor;
@@ -65,7 +65,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class UserSwitchTransitionViewControllerTest extends SysuiTestCase {
+public class UserSwitchTransitionViewControllerTest extends CarSysuiTestCase {
     private static final int TEST_USER_1 = 100;
     private static final int TEST_USER_2 = 110;
 
@@ -86,6 +86,8 @@ public class UserSwitchTransitionViewControllerTest extends SysuiTestCase {
     @Mock
     private UserManager mMockUserManager;
     @Mock
+    private UserIconProvider mUserIconProvider;
+    @Mock
     private KeyguardManager mKeyguardManager;
 
     @Before
@@ -102,6 +104,7 @@ public class UserSwitchTransitionViewControllerTest extends SysuiTestCase {
                 mExecutor,
                 mMockActivityManager,
                 mMockUserManager,
+                mUserIconProvider,
                 mWindowManagerService,
                 mOverlayViewGlobalStateController
         );
@@ -138,7 +141,7 @@ public class UserSwitchTransitionViewControllerTest extends SysuiTestCase {
     @Test
     public void onHandleShow_showsUserSwitchingMessage() {
         String message = "Hello world!";
-        when(mMockActivityManager.getSwitchingFromUserMessage()).thenReturn(message);
+        when(mMockActivityManager.getSwitchingFromUserMessage(anyInt())).thenReturn(message);
 
         mCarUserSwitchingDialogController.handleShow(/* newUserId= */ TEST_USER_1);
         mExecutor.advanceClockToLast();
diff --git a/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewMediatorTest.java b/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewMediatorTest.java
index dd040ca8..2215cd70 100644
--- a/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewMediatorTest.java
+++ b/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewMediatorTest.java
@@ -24,7 +24,7 @@ import android.testing.TestableLooper;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.settings.UserTracker;
@@ -39,7 +39,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class UserSwitchTransitionViewMediatorTest extends SysuiTestCase {
+public class UserSwitchTransitionViewMediatorTest extends CarSysuiTestCase {
     private static final int TEST_USER = 100;
 
     private UserSwitchTransitionViewMediator mUserSwitchTransitionViewMediator;
diff --git a/tests/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifierTest.java b/tests/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifierTest.java
index 4080b3c9..0759bf29 100644
--- a/tests/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifierTest.java
+++ b/tests/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifierTest.java
@@ -35,7 +35,7 @@ import android.testing.AndroidTestingRunner;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.util.concurrency.DelayableExecutor;
 
@@ -50,7 +50,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @SmallTest
 // TODO(b/162866441): Refactor to use the Executor pattern instead.
-public class ConnectedDeviceVoiceRecognitionNotifierTest extends SysuiTestCase {
+public class ConnectedDeviceVoiceRecognitionNotifierTest extends CarSysuiTestCase {
 
     // TODO(b/218911666): {@link BluetoothHeadsetClient.ACTION_AG_EVENT} is a hidden API.
     private static final String HEADSET_CLIENT_ACTION_AG_EVENT =
diff --git a/tests/src/com/android/systemui/car/window/OverlayPanelViewControllerTest.java b/tests/src/com/android/systemui/car/window/OverlayPanelViewControllerTest.java
index 43713eb9..9f5ad6b7 100644
--- a/tests/src/com/android/systemui/car/window/OverlayPanelViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/window/OverlayPanelViewControllerTest.java
@@ -37,7 +37,7 @@ import android.view.ViewGroup;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.tests.R;
@@ -57,7 +57,7 @@ import java.util.List;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class OverlayPanelViewControllerTest extends SysuiTestCase {
+public class OverlayPanelViewControllerTest extends CarSysuiTestCase {
     private TestOverlayPanelViewController mOverlayPanelViewController;
     private ViewGroup mBaseLayout;
 
diff --git a/tests/src/com/android/systemui/car/window/OverlayViewControllerTest.java b/tests/src/com/android/systemui/car/window/OverlayViewControllerTest.java
index 562ecdb7..80c77f75 100644
--- a/tests/src/com/android/systemui/car/window/OverlayViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/window/OverlayViewControllerTest.java
@@ -28,7 +28,7 @@ import android.view.ViewGroup;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.tests.R;
 
@@ -44,7 +44,7 @@ import org.mockito.MockitoAnnotations;
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class OverlayViewControllerTest extends SysuiTestCase {
+public class OverlayViewControllerTest extends CarSysuiTestCase {
     private TestOverlayViewController mOverlayViewController;
     private ViewGroup mBaseLayout;
 
diff --git a/tests/src/com/android/systemui/car/window/OverlayViewGlobalStateControllerTest.java b/tests/src/com/android/systemui/car/window/OverlayViewGlobalStateControllerTest.java
index 8526e72a..2398d5a4 100644
--- a/tests/src/com/android/systemui/car/window/OverlayViewGlobalStateControllerTest.java
+++ b/tests/src/com/android/systemui/car/window/OverlayViewGlobalStateControllerTest.java
@@ -37,7 +37,7 @@ import android.view.WindowInsetsController;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.tests.R;
 
@@ -51,7 +51,7 @@ import java.util.Arrays;
 
 @CarSystemUiTest
 @SmallTest
-public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
+public class OverlayViewGlobalStateControllerTest extends CarSysuiTestCase {
 
     private OverlayViewGlobalStateController mOverlayViewGlobalStateController;
     private ViewGroup mBaseLayout;
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegateTest.java b/tests/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegateTest.java
new file mode 100644
index 00000000..a8f6c6db
--- /dev/null
+++ b/tests/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegateTest.java
@@ -0,0 +1,171 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui;
+
+import static android.app.WindowConfiguration.ACTIVITY_TYPE_HOME;
+import static android.view.WindowManager.TRANSIT_OPEN;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.app.ActivityManager;
+import android.content.Intent;
+import android.os.IBinder;
+import android.view.SurfaceControl;
+import android.window.TransitionInfo;
+import android.window.TransitionRequestInfo;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
+import com.android.wm.shell.automotive.AutoTaskStackController;
+import com.android.wm.shell.automotive.AutoTaskStackState;
+import com.android.wm.shell.automotive.AutoTaskStackTransaction;
+import com.android.wm.shell.transition.Transitions;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.HashMap;
+import java.util.Map;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@SmallTest
+public class PanelAutoTaskStackTransitionHandlerDelegateTest extends CarSysuiTestCase {
+
+    private PanelAutoTaskStackTransitionHandlerDelegate mDelegate;
+
+    @Mock
+    private AutoTaskStackController mAutoTaskStackController;
+    @Mock
+    private TaskPanelTransitionCoordinator mTaskPanelTransitionCoordinator;
+    @Mock
+    private Transitions.TransitionFinishCallback mFinishCallback;
+    @Mock
+    private PanelUtils mPanelUtils;
+    @Mock
+    private TaskPanelInfoRepository mTaskPanelInfoRepository;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        when(mTaskPanelTransitionCoordinator.createAutoTaskStackTransaction(any(),
+                any())).thenReturn(new AutoTaskStackTransaction());
+        mDelegate = new PanelAutoTaskStackTransitionHandlerDelegate(mContext,
+                mAutoTaskStackController, mTaskPanelTransitionCoordinator, mPanelUtils,
+                mTaskPanelInfoRepository);
+    }
+
+    @Test
+    public void testHandleRequest_shouldHandleByPanels() {
+        TransitionRequestInfo request = mock(TransitionRequestInfo.class);
+        ActivityManager.RunningTaskInfo taskInfo = new ActivityManager.RunningTaskInfo();
+        taskInfo.topActivityType = ACTIVITY_TYPE_HOME;
+        taskInfo.baseIntent = new Intent();
+        taskInfo.baseIntent.addCategory(Intent.CATEGORY_HOME);
+        when(request.getType()).thenReturn(TRANSIT_OPEN);
+        when(request.getTriggerTask()).thenReturn(taskInfo);
+
+        AutoTaskStackTransaction autoTaskStackTransaction = mDelegate.handleRequest(
+                mock(IBinder.class), request);
+
+        assertThat(autoTaskStackTransaction).isNotNull();
+    }
+
+    @Test
+    public void testHandleRequest_shouldNotHandleByPanels() {
+        TransitionRequestInfo request = mock(TransitionRequestInfo.class);
+        when(request.getTriggerTask()).thenReturn(null);
+
+        AutoTaskStackTransaction autoTaskStackTransaction = mDelegate.handleRequest(
+                mock(IBinder.class), request);
+        assertThat(autoTaskStackTransaction).isNull();
+    }
+
+    @Test
+    public void testStartAnimation_withPendingAnimators() {
+        Map<Integer, AutoTaskStackState> changedTaskStacks = new HashMap<>();
+        TransitionInfo info = mock(TransitionInfo.class);
+        SurfaceControl.Transaction startTransaction = mock(SurfaceControl.Transaction.class);
+        SurfaceControl.Transaction finishTransaction = mock(SurfaceControl.Transaction.class);
+        when(mTaskPanelTransitionCoordinator.playPendingAnimations(any(), any())).thenReturn(true);
+
+        boolean result = mDelegate.startAnimation(
+                mock(IBinder.class),
+                changedTaskStacks,
+                info,
+                startTransaction,
+                finishTransaction,
+                mFinishCallback);
+
+        assertThat(result).isTrue();
+    }
+
+    @Test
+    public void testStartAnimation_withoutPendingAnimators() {
+        Map<Integer, AutoTaskStackState> changedTaskStacks = new HashMap<>();
+        TransitionInfo info = mock(TransitionInfo.class);
+        SurfaceControl.Transaction startTransaction = mock(SurfaceControl.Transaction.class);
+        SurfaceControl.Transaction finishTransaction = mock(SurfaceControl.Transaction.class);
+        when(mTaskPanelTransitionCoordinator.playPendingAnimations(any(), any())).thenReturn(false);
+
+        boolean result = mDelegate.startAnimation(
+                mock(IBinder.class),
+                changedTaskStacks,
+                info,
+                startTransaction,
+                finishTransaction,
+                mFinishCallback);
+
+        assertThat(result).isFalse();
+    }
+
+    @Test
+    public void testOnTransitionConsumed() {
+        mDelegate.onTransitionConsumed(
+                mock(IBinder.class),
+                mock(Map.class),
+                false,
+                mock(SurfaceControl.Transaction.class));
+
+        verify(mTaskPanelTransitionCoordinator).stopRunningAnimations();
+    }
+
+    @Test
+    public void testMergeAnimation() {
+        mDelegate.mergeAnimation(
+                mock(IBinder.class),
+                mock(Map.class),
+                mock(TransitionInfo.class),
+                mock(SurfaceControl.Transaction.class),
+                mock(IBinder.class),
+                mock(Transitions.TransitionFinishCallback.class));
+
+        verify(mTaskPanelTransitionCoordinator).stopRunningAnimations();
+    }
+}
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinatorTest.java b/tests/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinatorTest.java
new file mode 100644
index 00000000..3bdcbd03
--- /dev/null
+++ b/tests/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinatorTest.java
@@ -0,0 +1,181 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.Mockito.timeout;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.animation.Animator;
+import android.animation.AnimatorListenerAdapter;
+import android.animation.ValueAnimator;
+import android.os.Binder;
+import android.os.IBinder;
+import android.testing.TestableLooper;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+import androidx.test.platform.app.InstrumentationRegistry;
+
+import com.android.car.scalableui.model.PanelTransaction;
+import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
+import com.android.wm.shell.automotive.AutoLayoutManager;
+import com.android.wm.shell.automotive.AutoSurfaceTransaction;
+import com.android.wm.shell.automotive.AutoSurfaceTransactionFactory;
+import com.android.wm.shell.automotive.AutoTaskStackController;
+import com.android.wm.shell.transition.Transitions;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
+import java.util.concurrent.atomic.AtomicBoolean;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+public class TaskPanelTransitionCoordinatorTest extends CarSysuiTestCase {
+
+    private TaskPanelTransitionCoordinator mTaskPanelTransitionCoordinator;
+
+    @Mock
+    private Transitions.TransitionFinishCallback mFinishCallback;
+    @Mock
+    private AutoTaskStackController mAutoTaskStackController;
+    @Mock
+    private PanelUtils mPanelUtils;
+    @Mock
+    private AutoSurfaceTransactionFactory mAutoSurfaceTransactionFactory;
+    @Mock
+    private AutoSurfaceTransaction mAutoSurfaceTransaction;
+    @Mock
+    private AutoLayoutManager mAutoLayoutManager;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        mTaskPanelTransitionCoordinator = new TaskPanelTransitionCoordinator(
+                mAutoTaskStackController, mAutoSurfaceTransactionFactory, mPanelUtils,
+                mAutoLayoutManager);
+        when(mAutoSurfaceTransactionFactory.createTransaction(anyString())).thenReturn(
+                mAutoSurfaceTransaction);
+    }
+
+    @Test
+    public void testStartTransition_addsPendingTransaction() {
+        IBinder binder = new Binder();
+        Animator animator = new ValueAnimator();
+        when(mAutoTaskStackController.startTransition(any())).thenReturn(binder);
+        PanelTransaction panelTransaction = new PanelTransaction.Builder()
+                .addAnimator("testPanel", animator).build();
+
+        mTaskPanelTransitionCoordinator.startTransition(panelTransaction);
+
+        PanelTransaction pendingTransaction =
+                mTaskPanelTransitionCoordinator.getPendingPanelTransaction(binder);
+        assertThat(pendingTransaction).isNotNull();
+        assertThat(pendingTransaction.getAnimators().size()).isEqualTo(1);
+    }
+
+    @Test
+    public void testPlayPendingAnimations_noTransaction_returnsFalse() {
+        IBinder binder = new Binder();
+        AtomicBoolean animationStarted = new AtomicBoolean(false);
+
+        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
+            animationStarted.set(mTaskPanelTransitionCoordinator.playPendingAnimations(binder,
+                    mFinishCallback));
+        });
+
+        assertThat(animationStarted.get()).isFalse();
+    }
+
+    @Test
+    public void testPlayPendingAnimations() throws InterruptedException {
+        CountDownLatch latch = new CountDownLatch(1); // Latch for waiting
+        IBinder binder = new Binder();
+        ValueAnimator animator = ValueAnimator.ofFloat(0, 1);
+        animator.setDuration(1000L);
+        animator.addListener(new AnimatorListenerAdapter() {
+            @Override
+            public void onAnimationEnd(Animator animation) {
+                super.onAnimationEnd(animation);
+                latch.countDown();
+            }
+        });
+        PanelTransaction panelTransaction = new PanelTransaction.Builder()
+                .addAnimator("testPanel", animator).build();
+        mTaskPanelTransitionCoordinator.createAutoTaskStackTransaction(binder, panelTransaction);
+
+        AtomicBoolean animationStarted = new AtomicBoolean(false);
+        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
+            animationStarted.set(mTaskPanelTransitionCoordinator.playPendingAnimations(binder,
+                    mFinishCallback));
+        });
+
+        assertThat(animationStarted.get()).isTrue();
+        assertThat(latch.await(/* timeout= */ 5, TimeUnit.SECONDS)).isTrue();
+        assertThat(latch.getCount()).isEqualTo(0);
+        assertThat(mTaskPanelTransitionCoordinator.isAnimationRunning()).isFalse();
+        // There may be a slight delay between the Animator receiving onAnimationEnd and the
+        // AnimatorSet receiving onAnimationEnd.
+        verify(mFinishCallback, timeout(1000)).onTransitionFinished(null);
+    }
+
+    @Test
+    public void testStopRunningAnimations() throws InterruptedException {
+        CountDownLatch latch = new CountDownLatch(1); // Latch for waiting
+        IBinder binder = new Binder();
+        ValueAnimator animator = ValueAnimator.ofFloat(0, 1);
+        animator.setDuration(5000L);
+        animator.addListener(new AnimatorListenerAdapter() {
+            @Override
+            public void onAnimationEnd(Animator animation) {
+                super.onAnimationEnd(animation);
+                latch.countDown();
+            }
+        });
+        PanelTransaction panelTransaction = new PanelTransaction.Builder()
+                .addAnimator("testPanel", animator).build();
+        mTaskPanelTransitionCoordinator.createAutoTaskStackTransaction(binder, panelTransaction);
+
+        // Run the animation on the main looper
+        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
+            mTaskPanelTransitionCoordinator.playPendingAnimations(binder, mFinishCallback);
+        });
+
+        mTaskPanelTransitionCoordinator.stopRunningAnimations();
+        // onAnimationEnd should still be called when cancelled - wait for a small amount of time
+        // and expect animation end callback to execute
+        assertThat(latch.await(/* timeout= */ 1, TimeUnit.SECONDS)).isTrue();
+        assertThat(latch.getCount()).isEqualTo(0);
+        assertThat(mTaskPanelTransitionCoordinator.isAnimationRunning()).isFalse();
+        // There may be a slight delay between the Animator receiving onAnimationEnd and the
+        // AnimatorSet receiving onAnimationEnd.
+        verify(mFinishCallback, timeout(1000)).onTransitionFinished(null);
+    }
+}
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelInfoRepositoryTest.java b/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelInfoRepositoryTest.java
new file mode 100644
index 00000000..20732518
--- /dev/null
+++ b/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelInfoRepositoryTest.java
@@ -0,0 +1,266 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.panel;
+
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.app.ActivityManager;
+import android.content.ComponentName;
+import android.view.Display;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.car.scalableui.panel.Panel;
+import com.android.car.scalableui.panel.PanelPool;
+import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.util.concurrency.FakeExecutor;
+import com.android.systemui.util.time.FakeSystemClock;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.Mockito;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@SmallTest
+public class TaskPanelInfoRepositoryTest extends CarSysuiTestCase {
+    private static final String TEST_PANEL_ID = "test_panel";
+    private static final ComponentName TEST_COMPONENT_NAME_1 = new ComponentName("com.test.package",
+            "com.test.package.Activity1");
+    private static final ComponentName TEST_COMPONENT_NAME_2 = new ComponentName("com.test.package",
+            "com.test.package.Activity2");
+    private static final int TEST_TASK_ID_1 = 10000;
+    private TaskPanelInfoRepository mTaskPanelInfoRepository;
+    private FakeExecutor mFakeExecutor;
+
+    private MockitoSession mMockingSession;
+
+    @Mock
+    private TaskPanelInfoRepository.TaskPanelChangeListener mTaskPanelChangeListener;
+    @Mock
+    private PanelPool mPanelPool;
+    @Mock
+    private Panel mTestPanel;
+
+    @Before
+    public void setUp() {
+        mMockingSession = mockitoSession()
+                .initMocks(this)
+                .mockStatic(PanelPool.class)
+                .strictness(Strictness.WARN)
+                .startMocking();
+
+        mFakeExecutor = new FakeExecutor(new FakeSystemClock());
+        doReturn(mPanelPool).when(() -> PanelPool.getInstance());
+        when(mPanelPool.getPanel(TEST_PANEL_ID)).thenReturn(mTestPanel);
+        when(mTestPanel.isVisible()).thenReturn(true);
+        mTaskPanelInfoRepository = new TaskPanelInfoRepository(mFakeExecutor);
+        mTaskPanelInfoRepository.addChangeListener(mTaskPanelChangeListener);
+    }
+
+    @After
+    public void tearDown() {
+        if (mMockingSession != null) {
+            mMockingSession.finishMocking();
+        }
+        mTaskPanelInfoRepository.removeChangeListener(mTaskPanelChangeListener);
+    }
+
+    @Test
+    public void onTaskAppearedOnPanel_notifyChange() {
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        waitForDelayableExecutor();
+
+        verify(mTaskPanelChangeListener).onTopTaskOnPanelChanged();
+    }
+
+    @Test
+    public void onTaskChangedOnPanel_noChange_noNotifyChange() {
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        waitForDelayableExecutor();
+        Mockito.clearInvocations(mTaskPanelChangeListener);
+
+        mTaskPanelInfoRepository.onTaskChangedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+
+        verify(mTaskPanelChangeListener, never()).onTopTaskOnPanelChanged();
+    }
+
+    @Test
+    public void onTaskChangedOnPanel_topActivityChange_notifyChange() {
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        waitForDelayableExecutor();
+        Mockito.clearInvocations(mTaskPanelChangeListener);
+
+        mTaskPanelInfoRepository.onTaskChangedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_2, TEST_TASK_ID_1));
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        waitForDelayableExecutor();
+
+        verify(mTaskPanelChangeListener).onTopTaskOnPanelChanged();
+    }
+
+    @Test
+    public void onTaskChangedOnPanel_visibilityChange_notifyChange() {
+        ActivityManager.RunningTaskInfo taskInfo1 = createTaskInfo(TEST_COMPONENT_NAME_1,
+                TEST_TASK_ID_1);
+        taskInfo1.isVisible = false;
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID, taskInfo1);
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        waitForDelayableExecutor();
+        Mockito.clearInvocations(mTaskPanelChangeListener);
+
+        mTaskPanelInfoRepository.onTaskChangedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        waitForDelayableExecutor();
+
+        verify(mTaskPanelChangeListener).onTopTaskOnPanelChanged();
+    }
+
+    @Test
+    public void onTaskRemovedOnPanel_notifyChange() {
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        waitForDelayableExecutor();
+        Mockito.clearInvocations(mTaskPanelChangeListener);
+
+        mTaskPanelInfoRepository.onTaskVanishedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        waitForDelayableExecutor();
+
+        verify(mTaskPanelChangeListener).onTopTaskOnPanelChanged();
+    }
+
+    @Test
+    public void testIsPackageVisible() {
+        // start as not visible
+        assertThat(mTaskPanelInfoRepository.isPackageVisible(
+                TEST_COMPONENT_NAME_1.getPackageName())).isFalse();
+
+        // should be visible after task appeared
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        assertThat(mTaskPanelInfoRepository.isPackageVisible(
+                TEST_COMPONENT_NAME_1.getPackageName())).isTrue();
+
+        // should not be visible after task vanish
+        mTaskPanelInfoRepository.onTaskVanishedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        assertThat(mTaskPanelInfoRepository.isPackageVisible(
+                TEST_COMPONENT_NAME_1.getPackageName())).isFalse();
+    }
+
+    @Test
+    public void testIsPackageVisibleOnDisplay() {
+        // start as not visible
+        assertThat(mTaskPanelInfoRepository.isPackageVisibleOnDisplay(
+                TEST_COMPONENT_NAME_1.getPackageName(), Display.DEFAULT_DISPLAY)).isFalse();
+
+        // should be visible after task appeared only on default display
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        assertThat(mTaskPanelInfoRepository.isPackageVisibleOnDisplay(
+                TEST_COMPONENT_NAME_1.getPackageName(), Display.DEFAULT_DISPLAY)).isTrue();
+        assertThat(mTaskPanelInfoRepository.isPackageVisibleOnDisplay(
+                TEST_COMPONENT_NAME_1.getPackageName(), Display.DEFAULT_DISPLAY + 1)).isFalse();
+
+        // should not be visible after task vanish
+        mTaskPanelInfoRepository.onTaskVanishedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        assertThat(mTaskPanelInfoRepository.isPackageVisibleOnDisplay(
+                TEST_COMPONENT_NAME_1.getPackageName(), Display.DEFAULT_DISPLAY)).isFalse();
+    }
+
+    @Test
+    public void testIsComponentVisible() {
+        // start as not visible
+        assertThat(mTaskPanelInfoRepository.isComponentVisible(
+                TEST_COMPONENT_NAME_1)).isFalse();
+
+        // should be visible after task appeared
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        assertThat(mTaskPanelInfoRepository.isComponentVisible(
+                TEST_COMPONENT_NAME_1)).isTrue();
+
+        // should not be visible after task vanish
+        mTaskPanelInfoRepository.onTaskVanishedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        assertThat(mTaskPanelInfoRepository.isComponentVisible(
+                TEST_COMPONENT_NAME_1)).isFalse();
+    }
+
+    @Test
+    public void testIsComponentVisibleOnDisplay() {
+        // start as not visible
+        assertThat(mTaskPanelInfoRepository.isComponentVisibleOnDisplay(
+                TEST_COMPONENT_NAME_1, Display.DEFAULT_DISPLAY)).isFalse();
+
+        // should be visible after task appeared only on default display
+        mTaskPanelInfoRepository.onTaskAppearedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        assertThat(mTaskPanelInfoRepository.isComponentVisibleOnDisplay(
+                TEST_COMPONENT_NAME_1, Display.DEFAULT_DISPLAY)).isTrue();
+        assertThat(mTaskPanelInfoRepository.isComponentVisibleOnDisplay(
+                TEST_COMPONENT_NAME_1, Display.DEFAULT_DISPLAY + 1)).isFalse();
+
+        // should not be visible after task vanish
+        mTaskPanelInfoRepository.onTaskVanishedOnPanel(TEST_PANEL_ID,
+                createTaskInfo(TEST_COMPONENT_NAME_1, TEST_TASK_ID_1));
+        assertThat(mTaskPanelInfoRepository.isComponentVisibleOnDisplay(
+                TEST_COMPONENT_NAME_1, Display.DEFAULT_DISPLAY)).isFalse();
+    }
+
+    private ActivityManager.RunningTaskInfo createTaskInfo(ComponentName componentName, int id) {
+        ActivityManager.RunningTaskInfo taskInfo = new ActivityManager.RunningTaskInfo();
+        taskInfo.taskId = id;
+        taskInfo.displayId = Display.DEFAULT_DISPLAY;
+        taskInfo.topActivity = componentName;
+        taskInfo.isVisible = true;
+        taskInfo.isRunning = true;
+        taskInfo.isSleeping = false;
+
+        return taskInfo;
+    }
+
+    private void waitForDelayableExecutor() {
+        mFakeExecutor.advanceClockToLast();
+        mFakeExecutor.runAllReady();
+    }
+}
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelTest.java b/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelTest.java
new file mode 100644
index 00000000..52378182
--- /dev/null
+++ b/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelTest.java
@@ -0,0 +1,106 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui.car.wm.scalableui.panel;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.app.ActivityManager;
+import android.car.app.CarActivityManager;
+import android.graphics.Rect;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.wm.scalableui.AutoTaskStackHelper;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.wm.shell.automotive.AutoTaskStackController;
+import com.android.wm.shell.automotive.AutoTaskStackTransaction;
+import com.android.wm.shell.automotive.RootTaskStack;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@SmallTest
+public class TaskPanelTest extends CarSysuiTestCase{
+    private static final String TASK_PANEL_ID = "TASK_PANEL_ID";
+
+    private TaskPanel mTaskPanel;
+
+    @Mock
+    private AutoTaskStackController mAutoTaskStackController;
+    @Mock
+    private CarServiceProvider mCarServiceProvider;
+    @Mock
+    private AutoTaskStackHelper mAutoTaskStackHelper;
+    @Mock
+    private TaskPanel.Factory mFactory;
+    @Mock
+    private RootTaskStack mRootTaskStack;
+    @Mock
+    private CarActivityManager mCarActivityManager;
+    @Mock
+    private PanelUtils mPanelUtils;
+    @Mock
+    private TaskPanelInfoRepository mTaskPanelInfoRepository;
+    @Mock
+    private EventDispatcher mEventDispatcher;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        mTaskPanel = new TaskPanel(mAutoTaskStackController, mContext, mCarServiceProvider,
+                mAutoTaskStackHelper, mPanelUtils, mTaskPanelInfoRepository, mEventDispatcher,
+                TASK_PANEL_ID);
+        when(mFactory.create(any())).thenReturn(mTaskPanel);
+    }
+
+    @Test
+    public void testInit() {
+        mTaskPanel.setDisplayId(0);
+        mTaskPanel.init();
+
+        verify(mAutoTaskStackController).createRootTaskStack(anyInt(), anyString(), any());
+    }
+
+    @Test
+    public void testReset() {
+        mTaskPanel.setVisibility(true);
+        Rect bounds = new Rect(0, 0, 100, 100);
+        mTaskPanel.setBounds(bounds);
+        mTaskPanel.setLayer(1);
+        mTaskPanel.setRootTaskStack(mRootTaskStack);
+        when(mRootTaskStack.getRootTaskInfo()).thenReturn(
+                mock(ActivityManager.RunningTaskInfo.class));
+        when(mRootTaskStack.getId()).thenReturn(123);
+
+        mTaskPanel.reset();
+
+        verify(mAutoTaskStackController).startTransition(any(AutoTaskStackTransaction.class));
+    }
+}
diff --git a/tests/src/com/android/systemui/car/wm/taskview/RootTaskMediatorTest.java b/tests/src/com/android/systemui/car/wm/taskview/RootTaskMediatorTest.java
index 75c74f7b..93e42ccb 100644
--- a/tests/src/com/android/systemui/car/wm/taskview/RootTaskMediatorTest.java
+++ b/tests/src/com/android/systemui/car/wm/taskview/RootTaskMediatorTest.java
@@ -36,7 +36,7 @@ import android.window.WindowContainerToken;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.systemui.SysuiTestCase;
+import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.wm.shell.ShellTaskOrganizer;
 import com.android.wm.shell.taskview.TaskViewBase;
@@ -46,11 +46,13 @@ import com.android.wm.shell.taskview.TaskViewTransitions;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
+import java.util.Optional;
+
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public final class RootTaskMediatorTest extends SysuiTestCase {
+public final class RootTaskMediatorTest extends CarSysuiTestCase {
     private RootTaskMediator mMediator;
     private final ShellTaskOrganizer mShellTaskOrganizer = mock(ShellTaskOrganizer.class);
     private final TaskViewTaskController mTaskViewTaskController = mock(
@@ -91,7 +93,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ true, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo taskInfo = createTask(/* taskId= */ 1);
         mMediator.onTaskAppeared(taskInfo, null);
 
@@ -103,7 +106,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ true, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo rootTaskInfo = createTask(/* taskId= */ 1);
 
         mMediator.onTaskAppeared(rootTaskInfo, null);
@@ -116,7 +120,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ true, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo launchRootTask = createTask(/* taskId= */ 1);
         mMediator.onTaskAppeared(launchRootTask, null);
 
@@ -131,7 +136,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ false, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo rootTask = new ActivityManager.RunningTaskInfo();
         rootTask.taskId = 1;
         mMediator.onTaskAppeared(rootTask, null);
@@ -148,7 +154,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ false, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo taskInfo = createTask(/* taskId= */ 1);
         mMediator.onTaskAppeared(taskInfo, null);
 
@@ -162,7 +169,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ true, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo taskInfo = new ActivityManager.RunningTaskInfo();
         taskInfo.taskId = 1;
 
@@ -176,7 +184,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ true, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo rootTask = createTask(/* taskId= */ 99);
         mMediator.onTaskAppeared(rootTask, null);
         ActivityManager.RunningTaskInfo task1 = createTask(/* taskId= */ 1);
@@ -195,7 +204,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ false, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo taskInfo = createTask(/* taskId= */ 1);
         mMediator.onTaskAppeared(taskInfo, null);
 
@@ -209,7 +219,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ true, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */ true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo taskInfo = new ActivityManager.RunningTaskInfo();
         taskInfo.taskId = 1;
         mMediator.onTaskAppeared(taskInfo, null);
@@ -223,7 +234,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
     public void onTaskVanished_multipleExistingTasks_removesFromTaskStack() {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */true, false, false,
                 true, mShellTaskOrganizer, mTaskViewTaskController, mTaskViewClientPart,
-                mCarActivityManager, mTaskViewTransitions);
+                mCarActivityManager, mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo rootTask = createTask(/* taskId= */ 99);
         mMediator.onTaskAppeared(rootTask, null);
         ActivityManager.RunningTaskInfo task1 = createTask(/* taskId= */ 1);
@@ -242,7 +254,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ false, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */ true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo rootTask = new ActivityManager.RunningTaskInfo();
         rootTask.taskId = 1;
         mMediator.onTaskAppeared(rootTask, null);
@@ -257,7 +270,8 @@ public final class RootTaskMediatorTest extends SysuiTestCase {
         mMediator = new RootTaskMediator(1, /* isLaunchRoot= */ false, /* embedHomeTask= */ false,
                 /* embedRecentsTask= */ false, /* embedAssistantTask= */ true, mShellTaskOrganizer,
                 mTaskViewTaskController, mTaskViewClientPart, mCarActivityManager,
-                mTaskViewTransitions);
+                mTaskViewTransitions,
+                /* windowDecorViewModelOptional= */Optional.empty());
         ActivityManager.RunningTaskInfo rootTask = createTask(/* taskId= */ 1);
         mMediator.onTaskAppeared(rootTask, null);
         ActivityManager.RunningTaskInfo task = createTask(/* taskId= */ 2);
diff --git a/tests/utils/src/com/android/systemui/CarSysuiTestCase.java b/tests/utils/src/com/android/systemui/CarSysuiTestCase.java
new file mode 100644
index 00000000..60b2f70c
--- /dev/null
+++ b/tests/utils/src/com/android/systemui/CarSysuiTestCase.java
@@ -0,0 +1,93 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.systemui;
+
+import android.content.Context;
+import android.content.res.Resources;
+import android.os.Handler;
+import android.os.HandlerExecutor;
+import android.os.Looper;
+import android.test.mock.MockContext;
+import android.util.Singleton;
+
+import androidx.annotation.NonNull;
+import androidx.test.InstrumentationRegistry;
+
+import org.junit.Rule;
+import org.mockito.Mockito;
+
+import java.util.concurrent.Executor;
+
+public class CarSysuiTestCase extends SysuiTestCase {
+
+    @Rule
+    public SysuiTestableContext mContext = createTestableContext();
+
+    private SysuiTestableContext createTestableContext() {
+        SysuiTestableContext context = new SysuiTestableContext(
+                getTestableContextBase(), getLeakCheck());
+
+        if (isRobolectricTest()) {
+            // Manually associate a Display to context for Robolectric test. Similar to b/214297409
+            return context.createDefaultDisplayContext();
+        } else {
+            return context;
+        }
+    }
+
+    @NonNull
+    private Context getTestableContextBase() {
+        if (isRavenwoodTest()) {
+            // TODO(b/292141694): build out Ravenwood support for Context
+            // Ravenwood doesn't yet provide a Context, but many SysUI tests assume one exists;
+            // so here we construct just enough of a Context to be useful; this will be replaced
+            // as more of the Ravenwood environment is built out
+            return new MockContext() {
+                @Override
+                public void setTheme(int resid) {
+                    // TODO(b/318393625): build out Ravenwood support for Resources
+                    // until then, ignored as no-op
+                }
+
+                @Override
+                public Resources getResources() {
+                    // TODO(b/318393625): build out Ravenwood support for Resources
+                    return Mockito.mock(Resources.class);
+                }
+
+                private Singleton<Executor> mMainExecutor = new Singleton<>() {
+                    @Override
+                    protected Executor create() {
+                        return new HandlerExecutor(new Handler(Looper.getMainLooper()));
+                    }
+                };
+
+                @Override
+                public Executor getMainExecutor() {
+                    return mMainExecutor.get();
+                }
+            };
+        } else {
+            return InstrumentationRegistry.getContext().getApplicationContext();
+        }
+    }
+
+    @Override
+    public SysuiTestableContext getContext() {
+        return mContext;
+    }
+}
```

