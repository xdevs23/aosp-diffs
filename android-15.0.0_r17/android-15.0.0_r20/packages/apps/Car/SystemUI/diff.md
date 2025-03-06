```diff
diff --git a/Android.bp b/Android.bp
index 682c74e8..c9fe14fb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -18,14 +18,25 @@ package {
     default_team: "trendy_team_system_experience",
 }
 
-android_library {
-    name: "CarSystemUI-core",
+genrule {
+    name: "statslog-carsystemui-java-gen",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --java $(out) --module carsystemui" +
+        " --javaPackage com.android.systemui --javaClass CarSystemUIStatsLog",
+    out: ["com/android/systemui/car/CarSystemUIStatsLog.java"],
+}
 
-    srcs: [
-        "src/**/*.java",
-        "src/**/*.kt",
-        "src/**/I*.aidl",
-    ],
+carsystemui_srcs = [
+    "src/**/*.java",
+    "src/**/*.kt",
+    "src/**/I*.aidl",
+    ":statslog-carsystemui-java-gen",
+]
+
+java_defaults {
+    name: "CarSystemUI-core-defaults",
+
+    srcs: carsystemui_srcs,
 
     resource_dirs: [
         "res-keyguard",
@@ -74,6 +85,17 @@ android_library {
         "android.car",
     ],
 
+    // TODO(b/319708040): re-enable use_resource_processor
+    use_resource_processor: false,
+}
+
+android_library {
+    name: "CarSystemUI-core",
+
+    defaults: [
+        "CarSystemUI-core-defaults",
+    ],
+
     aaptflags: [
         "--no-resource-deduping",
     ],
@@ -85,12 +107,15 @@ android_library {
     plugins: ["dagger2-compiler"],
     // TODO(b/319708040): re-enable use_resource_processor
     use_resource_processor: false,
-
 }
 
 android_app {
     name: "CarSystemUI",
 
+    defaults: [
+        "wmshell_defaults",
+    ],
+
     static_libs: [
         "CarSystemUI-core",
     ],
@@ -141,6 +166,40 @@ android_app {
     use_resource_processor: false,
 }
 
+// Begin daggervis
+
+// Dropped from google3/java/com/google/android/libraries/docs/inject/daggerplugin/dot
+java_import_host {
+    name: "car-systemui-binding-graph-plugin-jar",
+    jars: ["daggervis/libdagger_binding_graph_plugin_lib.jar"],
+}
+
+// A java SPI plugin to visualize dagger dependency graph.
+java_plugin {
+    name: "car-systemui-binding-graph-plugin",
+    static_libs: [
+        "car-systemui-binding-graph-plugin-jar",
+        "dagger2-compiler-lib",
+        "auto_service_annotations",
+        "auto_value_annotations",
+        "auto_value_memoized_extension_annotations",
+    ],
+    processor_class: "dagger.internal.codegen.ComponentProcessor",
+}
+
+android_library {
+    name: "CarSystemUI-core-daggervis",
+    defaults: [
+        "CarSystemUI-core-defaults",
+    ],
+    plugins: [
+        "car-systemui-binding-graph-plugin",
+        "dagger2-compiler",
+    ],
+}
+
+// End daggervis
+
 // Resource lib
 // To be used ONLY for RROs of CarSystemUI
 android_library {
@@ -199,6 +258,7 @@ android_library {
         "src/**/*.java",
         "src/**/*.kt",
         "src/**/I*.aidl",
+        ":statslog-carsystemui-java-gen",
     ],
     static_libs: [
         "SystemUI-tests",
@@ -234,6 +294,7 @@ android_app {
     defaults: [
         "platform_app_defaults",
         "SystemUI_optimized_defaults",
+        "wmshell_defaults",
     ],
     manifest: "tests/AndroidManifest-base.xml",
 
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 066277c3..341ccf06 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -31,6 +31,7 @@
     <uses-permission android:name="android.car.permission.CAR_INSTRUMENT_CLUSTER_CONTROL" />
     <!-- This permission is required to use CarOccupantZoneManager. -->
     <uses-permission android:name="android.car.permission.CAR_CONTROL_AUDIO_SETTINGS" />
+    <uses-permission android:name="android.car.permission.CAR_IDENTIFICATION"/>
     <!-- This permission is required to get bluetooth broadcast. -->
     <uses-permission android:name="android.permission.BLUETOOTH" />
     <uses-permission android:name="android.permission.BLUETOOTH_ADMIN" />
@@ -69,6 +70,8 @@
     <uses-permission android:name="android.permission.MANAGE_ONGOING_CALLS"/>
     <!-- System permission to control media playback of the active session -->
     <uses-permission android:name="android.permission.MEDIA_CONTENT_CONTROL"/>
+    <uses-permission android:name="android.car.permission.CONTROL_CAR_APP_LAUNCH"/>
+
 
     <application
         tools:replace="android:name,android:appComponentFactory"
@@ -120,6 +123,20 @@
             </intent-filter>
             <meta-data android:name="distractionOptimized" android:value="true"/>
         </activity>
+
+        <!-- documentLaunchMode=always ensures that a new activity is launched in every display
+             area even when it already exists in some other DA.
+             Every DA will still have just one dag activity at a time because of noHistory=true -->
+        <activity android:name="com.android.systemui.car.wm.displayarea.DaHideActivity"
+            android:noHistory="true"
+            android:configChanges="screenSize|smallestScreenSize|screenLayout|orientation|locale|density|layoutDirection"
+            android:theme="@style/Theme.UserPicker"
+            android:showForAllUsers="true"
+            android:documentLaunchMode="always"
+            android:excludeFromRecents="true" >
+            <meta-data android:name="distractionOptimized" android:value="true"/>
+        </activity>
+
         <!-- The service needs to be directBootAware so that it can reflect the correct call state
          when the system boots up. -->
         <service android:name=".car.telecom.InCallServiceImpl"
diff --git a/TEST_MAPPING b/TEST_MAPPING
index d7dd1ab3..4013bbd0 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -12,16 +12,6 @@
       ]
     }
   ],
-  "auto-end-to-end-postsubmit": [
-    {
-      "name": "AndroidAutomotiveNotificationsTests",
-      "options" : [
-        {
-          "include-filter": "android.platform.tests.NotificationTest"
-        }
-      ]
-    }
-  ],
   "carsysui-presubmit": [
     {
       "name": "CarSystemUITests",
diff --git a/aconfig/carsystemui.aconfig b/aconfig/carsystemui.aconfig
index 08d9ef4a..4334e857 100644
--- a/aconfig/carsystemui.aconfig
+++ b/aconfig/carsystemui.aconfig
@@ -1,13 +1,6 @@
 package: "com.android.systemui.car"
 container: "system"
 
-flag {
-    name: "example_flag"
-    namespace: "car_sys_exp"
-    description: "An Example Flag"
-    bug: "304307370"
-}
-
 flag {
     name: "config_aware_systemui"
     namespace: "car_sys_exp"
@@ -56,3 +49,10 @@ flag {
     description: "This flag controls v2 development to enable display compatibility feature."
     bug: "364382110"
 }
+
+flag {
+    name: "scalable_ui"
+    namespace: "car_sys_exp"
+    description: "This flag controls the development to enable scalable UI feature."
+    bug: "382109339"
+}
\ No newline at end of file
diff --git a/daggervis/libdagger_binding_graph_plugin_lib.jar b/daggervis/libdagger_binding_graph_plugin_lib.jar
new file mode 100755
index 00000000..59d6c98b
Binary files /dev/null and b/daggervis/libdagger_binding_graph_plugin_lib.jar differ
diff --git a/daggervis/parser.py b/daggervis/parser.py
new file mode 100755
index 00000000..0a1fd5bb
--- /dev/null
+++ b/daggervis/parser.py
@@ -0,0 +1,118 @@
+#!/usr/bin/python3
+"""A script for parsing and filtering component dot file.
+Adapted from vendor/google_clockwork/packages/SystemUI/daggervis/parser.py
+
+Input: input_dot_file output_dot_file [beginning_nodes_filter]
+Output: create a new dot file with styles applied. The output dot file will only contain nodes
+reachable from the beginning_nodes_filter if it's specified.
+"""
+import sys
+import os
+try:
+  import pydot
+except ImportError as e:
+  print("Error: python3-pydot is not installed. Please run \"sudo apt install python3-pydot\" first.", file=sys.stderr)
+  sys.exit(1)
+
+def main():
+  # Parse args
+  if len(sys.argv) < 2:
+    print("Error: please specify an input dot file", file=sys.stderr)
+    sys.exit(1)
+  if len(sys.argv) < 3:
+    print("Error: please specify an output dot file", file=sys.stderr)
+    sys.exit(1)
+  input_path = sys.argv[1]
+  output_path = sys.argv[2]
+  if len(sys.argv) > 3:
+    beginning_nodes_filter= sys.argv[3]
+  else:
+    beginning_nodes_filter= None
+
+  # Load graph
+  try:
+    graph = pydot.graph_from_dot_file(input_path)[0]
+  except Exception as e:
+    print("Error: unable to load dot file \"" + input_path + "\"", file=sys.stderr)
+    sys.exit(1)
+  print("Loaded dot file from " + input_path)
+
+  # Trim graph
+  if beginning_nodes_filter!= None:
+    trim_graph(graph, beginning_nodes_filter)
+
+  # Add styles
+  style_graph(graph)
+
+  with open(output_path, "w") as f:
+    f.write(str(graph))
+    print("Saved output dot file " + output_path)
+
+"""
+Trim a graph by only keeping nodes/edges reachable from beginning nodes.
+"""
+def trim_graph(graph, beginning_nodes_filter):
+  beginning_node_names = set()
+  all_nodes = graph.get_nodes()
+  for n in all_nodes:
+    if beginning_nodes_filter in get_label(n):
+      beginning_node_names.add(n.get_name())
+  if len(beginning_node_names) == 0:
+    print("Error: unable to find nodes matching \"" + beginning_nodes_filter + "\"", file=sys.stderr)
+    sys.exit(1)
+  filtered_node_names = set()
+  all_edges = graph.get_edges()
+  for node_name in beginning_node_names:
+    dfs(all_edges, node_name, filtered_node_names)
+  cnt_trimmed_nodes = 0
+  for node in all_nodes:
+    if not node.get_name() in filtered_node_names:
+      graph.del_node(node.get_name())
+      cnt_trimmed_nodes += 1
+  cnt_trimmed_edges = 0
+  for edge in all_edges:
+    if not edge.get_source() in filtered_node_names:
+      graph.del_edge(edge.get_source(), edge.get_destination())
+      cnt_trimmed_edges += 1
+  print("Trimed " + str(cnt_trimmed_nodes) + " nodes and " + str(cnt_trimmed_edges) + " edges")
+
+def dfs(all_edges, node_name, filtered_node_names):
+  if node_name in filtered_node_names:
+    return
+  filtered_node_names.add(node_name)
+  for edge in all_edges:
+    if edge.get_source() == node_name:
+      dfs(all_edges, edge.get_destination(), filtered_node_names)
+
+"""
+Apply styles to the dot graph.
+"""
+def style_graph(graph):
+  for n in graph.get_nodes():
+    label = get_label(n)
+    # Style SystemUI nodes
+    if "com.android.systemui" in label:
+      n.obj_dict["attributes"]["color"] = "burlywood"
+      n.obj_dict["attributes"]["shape"] = "box"
+      n.add_style("filled")
+    # Style CarSystemUI nodes
+    elif ("car" in label):
+      n.obj_dict["attributes"]["color"] = "darkolivegreen1"
+      n.add_style("filled")
+
+    # Trim common labels
+    trim_replacements = [("java.util.", ""), ("javax.inject.", "") , ("com.", "c."),
+                         ("google.", "g."), ("android.", "a."), ("car.", "c."),
+                         ("java.lang.", ""), ("dagger.Lazy", "Lazy"), ("java.util.function.", "")]
+    for (before, after) in trim_replacements:
+      if before in label:
+         n.obj_dict["attributes"]["label"] = label = label.replace(before, after)
+
+def get_label(node):
+  try:
+    return node.obj_dict["attributes"]["label"]
+  except Exception:
+    return ""
+
+if __name__ == "__main__":
+    main()
\ No newline at end of file
diff --git a/daggervis/visualize_dagger_component.sh b/daggervis/visualize_dagger_component.sh
new file mode 100755
index 00000000..8832de8e
--- /dev/null
+++ b/daggervis/visualize_dagger_component.sh
@@ -0,0 +1,49 @@
+#!/bin/bash
+
+# Adapted from vendor/google_clockwork/packages/SystemUI/daggervis/visualize_dagger_component.sh
+# Usage: visualize_dagger_component.sh output_file component_name [filter]
+# Example: visualize_dagger_component.sh ~/CarSysUIComponent.svg CarSysUIComponent Keyguard
+if [ -z "$1" ]; then
+  echo "Error: please specify an output file path. Example: \"visualize_dagger_component.sh ~/CarSysUIComponent.svg CarSysUIComponent Keyguard\""
+  exit 1
+fi
+
+if [ -z "$2" ]; then
+  echo "Error: please specify a dagger component name. Example: \"visualize_dagger_component.sh CarSysUIComponent Keyguard\""
+  exit 1
+fi
+
+if [ -z "$ANDROID_BUILD_TOP" ]; then
+  echo "Error: cannot find ANDROID_BUILD_TOP. Please go to Android root folder and run \". build/envsetup.sh\" and lunch a target."
+  exit 1
+fi
+
+ARTIFACTS_FOLDER=$ANDROID_BUILD_TOP/out/target/common/obj/JAVA_LIBRARIES/CarSystemUI-core-daggervis_intermediates
+CLASSES_FILE=$ARTIFACTS_FOLDER/classes.jar
+if [ ! -f $CLASSES_FILE ]; then
+  echo "Error: cannot find CarSystemUI-core-daggervis artifacts. Please run \"m CarSystemUI-core-daggervis\" first."
+  exit 1
+fi
+
+DOT_FOLDER=$ARTIFACTS_FOLDER/dot
+rm -rf $DOT_FOLDER
+mkdir $DOT_FOLDER
+
+echo "Unzipping dot files ..."
+unzip -d $DOT_FOLDER/ $CLASSES_FILE "*.dot" > /dev/null
+
+DOT_FILE=$DOT_FOLDER/$2.dot
+if [ ! -f $DOT_FILE ]; then
+  echo "Error: can't find file $DOT_FILE. Did you forget to rebuild CarSystemUI-core-daggervis?"
+  exit 1
+fi
+
+echo "Parsing $DOT_FILE"
+PARSED_DOT_FILE=$DOT_FOLDER/$2_parsed.dot
+$ANDROID_BUILD_TOP/packages/apps/Car/SystemUI/daggervis/parser.py $DOT_FILE $PARSED_DOT_FILE $3
+if [[ $? -ne 0 ]]; then
+  exit 1
+fi
+
+echo "Visualizing $PARSED_DOT_FILE"
+dot -v -T svg $PARSED_DOT_FILE > $1
diff --git a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactoryTest.java b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactoryTest.java
new file mode 100644
index 00000000..2e39fc16
--- /dev/null
+++ b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactoryTest.java
@@ -0,0 +1,120 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_NONE;
+import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PASSWORD;
+import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PATTERN;
+import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PIN;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.when;
+
+import android.app.trust.TrustManager;
+import android.os.Handler;
+import android.view.LayoutInflater;
+import android.view.ViewGroup;
+import android.widget.FrameLayout;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.internal.widget.LockPatternUtils;
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.settings.UserTracker;
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
+public class PassengerKeyguardCredentialViewControllerFactoryTest extends SysuiTestCase {
+    private static final int TEST_USER_ID = 1000;
+
+    private PassengerKeyguardCredentialViewControllerFactory mFactory;
+    private ViewGroup mViewGroup;
+    private LayoutInflater mLayoutInflater;
+
+    @Mock
+    private LockPatternUtils mLockPatternUtils;
+    @Mock
+    private UserTracker mUserTracker;
+    @Mock
+    private TrustManager mTrustManager;
+    @Mock
+    private Handler mHandler;
+    @Mock
+    private CarServiceProvider mCarServiceProvider;
+    @Mock
+    private PassengerKeyguardLockoutHelper mLockoutHelper;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        mLayoutInflater = LayoutInflater.from(mContext);
+        mFactory = new PassengerKeyguardCredentialViewControllerFactory(mLayoutInflater,
+                mLockPatternUtils, mUserTracker, mTrustManager, mHandler, mCarServiceProvider,
+                mLockoutHelper);
+        mViewGroup = new FrameLayout(mContext);
+        when(mUserTracker.getUserId()).thenReturn(TEST_USER_ID);
+    }
+
+    @Test(expected = IllegalStateException.class)
+    public void onCreate_noCredential_throwsException() {
+        when(mLockPatternUtils.getCredentialTypeForUser(TEST_USER_ID)).thenReturn(
+                CREDENTIAL_TYPE_NONE);
+
+        mFactory.create(mViewGroup);
+    }
+
+    @Test
+    public void onCreate_pinCredential_inflatesAndCreatesController() {
+        when(mLockPatternUtils.getCredentialTypeForUser(TEST_USER_ID)).thenReturn(
+                CREDENTIAL_TYPE_PIN);
+
+        assertViewAndControllerCreated();
+    }
+
+    @Test
+    public void onCreate_patternCredential_inflatesAndCreatesController() {
+        when(mLockPatternUtils.getCredentialTypeForUser(TEST_USER_ID)).thenReturn(
+                CREDENTIAL_TYPE_PATTERN);
+
+        assertViewAndControllerCreated();
+    }
+
+    @Test
+    public void onCreate_passwordCredential_inflatesAndCreatesController() {
+        when(mLockPatternUtils.getCredentialTypeForUser(TEST_USER_ID)).thenReturn(
+                CREDENTIAL_TYPE_PASSWORD);
+
+        assertViewAndControllerCreated();
+    }
+
+    private void assertViewAndControllerCreated() {
+        PassengerKeyguardCredentialViewController controller = mFactory.create(mViewGroup);
+
+        assertThat(controller).isNotNull();
+    }
+}
diff --git a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelperTest.java b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelperTest.java
new file mode 100644
index 00000000..63c92636
--- /dev/null
+++ b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelperTest.java
@@ -0,0 +1,110 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.os.SystemClock;
+import android.testing.TestableLooper;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.internal.widget.LockPatternUtils;
+import com.android.settingslib.utils.StringUtil;
+import com.android.systemui.R;
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.settings.UserTracker;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+public class PassengerKeyguardLockoutHelperTest extends SysuiTestCase {
+    private static final int TEST_USER_ID = 1000;
+    private static final int TEST_TIMEOUT_LENGTH_MS = 1000; // 1 second
+
+    private PassengerKeyguardLockoutHelper mLockoutHelper;
+
+    @Mock
+    private PassengerKeyguardLockoutHelper.Callback mCallback;
+    @Mock
+    private LockPatternUtils mLockPatternUtils;
+    @Mock
+    private UserTracker mUserTracker;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        when(mUserTracker.getUserId()).thenReturn(TEST_USER_ID);
+        mLockoutHelper = new PassengerKeyguardLockoutHelper(mContext, mLockPatternUtils,
+                mUserTracker);
+        mLockoutHelper.setCallback(mCallback);
+    }
+
+    @Test
+    public void onUIShown_lockedOut_notifiesLockState() {
+        when(mLockPatternUtils.getLockoutAttemptDeadline(TEST_USER_ID)).thenReturn(1L);
+
+        mLockoutHelper.onUIShown();
+
+        verify(mCallback).refreshUI(true);
+    }
+
+    @Test
+    public void onUIShown_notLockedOut_notifiesLockState() {
+        when(mLockPatternUtils.getLockoutAttemptDeadline(TEST_USER_ID)).thenReturn(0L);
+
+        mLockoutHelper.onUIShown();
+
+        verify(mCallback).refreshUI(false);
+    }
+
+    @Test
+    public void onCheckCompletedWithTimeout_setsTimeout() {
+        int timeoutMs = (int) SystemClock.elapsedRealtime() + TEST_TIMEOUT_LENGTH_MS;
+        when(mLockPatternUtils.getLockoutAttemptDeadline(TEST_USER_ID))
+                .thenReturn((long) timeoutMs);
+
+        mLockoutHelper.onCheckCompletedWithTimeout(TEST_TIMEOUT_LENGTH_MS);
+
+        verify(mLockPatternUtils).setLockoutAttemptDeadline(TEST_USER_ID, TEST_TIMEOUT_LENGTH_MS);
+        verify(mCallback).refreshUI(true);
+    }
+
+    @Test
+    public void onCountdown_setsErrorMessage() {
+        int timeoutMs = (int) SystemClock.elapsedRealtime() + TEST_TIMEOUT_LENGTH_MS;
+        when(mLockPatternUtils.getLockoutAttemptDeadline(TEST_USER_ID))
+                .thenReturn((long) timeoutMs);
+
+        mLockoutHelper.onCheckCompletedWithTimeout(TEST_TIMEOUT_LENGTH_MS);
+        mLockoutHelper.getCountDownTimer().onTick(TEST_TIMEOUT_LENGTH_MS);
+
+        int testTimeoutLengthSeconds = TEST_TIMEOUT_LENGTH_MS / 1000;
+        verify(mCallback).setErrorText(StringUtil.getIcuPluralsString(mContext,
+                testTimeoutLengthSeconds, R.string.passenger_keyguard_too_many_failed_attempts));
+    }
+}
diff --git a/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadViewTest.java b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadViewTest.java
new file mode 100644
index 00000000..7a86a09d
--- /dev/null
+++ b/multivalentTests/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadViewTest.java
@@ -0,0 +1,145 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.verify;
+
+import android.content.Context;
+import android.os.Handler;
+import android.os.SystemClock;
+import android.testing.TestableLooper;
+import android.view.MotionEvent;
+import android.view.View;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.systemui.R;
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.Arrays;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+public class PassengerPinPadViewTest extends SysuiTestCase {
+    private static int[] sAllKeys =
+            Arrays.copyOf(PassengerPinPadView.PIN_PAD_DIGIT_KEYS, PassengerPinPadView.NUM_KEYS);
+
+    static {
+        sAllKeys[PassengerPinPadView.PIN_PAD_DIGIT_KEYS.length] = R.id.key_backspace;
+        sAllKeys[PassengerPinPadView.PIN_PAD_DIGIT_KEYS.length + 1] = R.id.key_enter;
+    }
+
+    private TestPassengerPinPadView mPinPadView;
+    private TestableLooper mTestableLooper;
+    private Handler mHandler;
+
+    @Mock
+    private PassengerPinPadView.PinPadClickListener mClickListener;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        mTestableLooper = TestableLooper.get(this);
+        mHandler = new Handler(mTestableLooper.getLooper());
+        mPinPadView = new TestPassengerPinPadView(mContext);
+        mPinPadView.setPinPadClickListener(mClickListener);
+    }
+
+    // Verify that when the pin pad is enabled or disabled, all the keys are in the same state.
+    @Test
+    public void testEnableDisablePinPad() {
+        mPinPadView.setEnabled(false);
+
+        for (int id : sAllKeys) {
+            View key = mPinPadView.findViewById(id);
+            assertThat(key.isEnabled()).isFalse();
+        }
+
+        mPinPadView.setEnabled(true);
+
+        for (int id : sAllKeys) {
+            View key = mPinPadView.findViewById(id);
+            assertThat(key.isEnabled()).isTrue();
+        }
+    }
+
+    // Verify that the click handler is called when the backspace key is clicked.
+    @Test
+    public void testBackspaceClickHandler() {
+        long downTime = SystemClock.uptimeMillis();
+        long eventTime = SystemClock.uptimeMillis();
+        MotionEvent downEvent = MotionEvent.obtain(downTime, eventTime, MotionEvent.ACTION_DOWN,
+                0, 0, 0);
+        downTime = SystemClock.uptimeMillis();
+        eventTime = SystemClock.uptimeMillis();
+        MotionEvent upEvent = MotionEvent.obtain(downTime, eventTime, MotionEvent.ACTION_UP,
+                0, 0, 0);
+
+        mPinPadView.findViewById(R.id.key_backspace).dispatchTouchEvent(downEvent);
+        waitForIdleSync();
+        mPinPadView.findViewById(R.id.key_backspace).dispatchTouchEvent(upEvent);
+        waitForIdleSync();
+
+        verify(mClickListener).onBackspaceClick();
+    }
+
+    // Verify that the click handler is called when the enter key is clicked.
+    @Test
+    public void testEnterKeyClickHandler() {
+        mPinPadView.findViewById(R.id.key_enter).performClick();
+
+        verify(mClickListener).onEnterKeyClick();
+    }
+
+    // Verify that the click handler is called with the right argument when a digit key is clicked.
+    @Test
+    public void testDigitKeyClickHandler() {
+        for (int i = 0; i < PassengerPinPadView.PIN_PAD_DIGIT_KEYS.length; ++i) {
+            mPinPadView.findViewById(PassengerPinPadView.PIN_PAD_DIGIT_KEYS[i]).performClick();
+            verify(mClickListener).onDigitKeyClick(String.valueOf(i));
+        }
+    }
+
+    @Override
+    protected void waitForIdleSync() {
+        mTestableLooper.processAllMessages();
+    }
+
+    private class TestPassengerPinPadView extends PassengerPinPadView {
+
+        TestPassengerPinPadView(Context context) {
+            super(context);
+        }
+
+        @Override
+        public Handler getHandler() {
+            return mHandler;
+        }
+    }
+}
diff --git a/multivalentTests/src/com/android/systemui/car/systembar/DebugPanelButtonViewControllerTest.java b/multivalentTests/src/com/android/systemui/car/systembar/DebugPanelButtonViewControllerTest.java
new file mode 100644
index 00000000..26b75254
--- /dev/null
+++ b/multivalentTests/src/com/android/systemui/car/systembar/DebugPanelButtonViewControllerTest.java
@@ -0,0 +1,88 @@
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
+package com.android.systemui.car.systembar;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.net.Uri;
+import android.os.Handler;
+import android.testing.TestableLooper;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.util.settings.GlobalSettings;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import javax.inject.Provider;
+
+// TODO(b/370766893): add more tests for various situations after finding ways to mock static
+//  functions.
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+public class DebugPanelButtonViewControllerTest extends SysuiTestCase {
+    @Mock
+    private CarSystemBarPanelButtonView mView;
+    @Mock
+    private CarSystemBarElementStatusBarDisableController mDisableController;
+    @Mock
+    private CarSystemBarElementStateController mStateController;
+    @Mock
+    private Provider<StatusIconPanelViewController.Builder> mStatusIconPanelBuilder;
+    @Mock
+    private Handler mMainHandler;
+    @Mock
+    private GlobalSettings mGlobalSettings;
+
+    private DebugPanelButtonViewController mController;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+
+        when(mView.getContext()).thenReturn(mContext);
+        mController = new DebugPanelButtonViewController(mView, mDisableController,
+                mStateController, mStatusIconPanelBuilder, mMainHandler, mGlobalSettings);
+        mController.onViewAttached();
+    }
+
+    @Test
+    public void onViewAttached_registerContentObserver() {
+        verify(mGlobalSettings).registerContentObserverAsync((Uri) any(), any());
+    }
+
+    @Test
+    public void onViewDetached_unregistersListeners() {
+        mController.onViewDetached();
+
+        verify(mGlobalSettings).unregisterContentObserverAsync(any());
+    }
+}
diff --git a/res-keyguard/layout/passenger_keyguard_loading_dialog.xml b/res-keyguard/layout/passenger_keyguard_loading_dialog.xml
new file mode 100644
index 00000000..6a6cb1cb
--- /dev/null
+++ b/res-keyguard/layout/passenger_keyguard_loading_dialog.xml
@@ -0,0 +1,30 @@
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
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:fillViewport="true"
+    android:background="@color/car_surface">
+    <ProgressBar
+        android:layout_width="350dp"
+        android:layout_height="50dp"
+        style="?android:attr/progressBarStyleHorizontal"
+        android:indeterminate="true"
+        android:indeterminateTint="@color/car_on_surface"
+        android:layout_gravity="center"/>
+</FrameLayout>
diff --git a/res-keyguard/layout/passenger_keyguard_overlay_window.xml b/res-keyguard/layout/passenger_keyguard_overlay_window.xml
new file mode 100644
index 00000000..f1467281
--- /dev/null
+++ b/res-keyguard/layout/passenger_keyguard_overlay_window.xml
@@ -0,0 +1,25 @@
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
+
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/passenger_keyguard_frame"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:fillViewport="true"
+    android:background="@color/car_surface">
+</FrameLayout>
\ No newline at end of file
diff --git a/res-keyguard/layout/passenger_keyguard_password_view.xml b/res-keyguard/layout/passenger_keyguard_password_view.xml
new file mode 100644
index 00000000..44e80ca1
--- /dev/null
+++ b/res-keyguard/layout/passenger_keyguard_password_view.xml
@@ -0,0 +1,59 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:layout_marginHorizontal="@dimen/car_ui_margin"
+    android:gravity="center"
+    android:orientation="vertical">
+
+    <EditText
+        android:id="@+id/password_entry"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginHorizontal="@*android:dimen/car_padding_3"
+        android:gravity="center"
+        android:inputType="textPassword"
+        android:maxLines="1"
+        android:textAppearance="?android:attr/textAppearanceLarge">
+        <requestFocus/>
+    </EditText>
+
+    <TextView
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:gravity="center"
+        android:text="@string/car_keyguard_enter_your_password"
+        android:textAppearance="?android:attr/textAppearanceLarge"/>
+
+    <TextView
+        android:id="@+id/message"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:freezesText="true"
+        android:gravity="center"
+        android:textAppearance="?android:attr/textAppearanceMedium"/>
+
+    <Button
+        android:id="@+id/cancel_button"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="@*android:dimen/car_padding_2"
+        android:layout_gravity="center"
+        android:text="@android:string/cancel"/>
+</LinearLayout>
diff --git a/res-keyguard/layout/passenger_keyguard_pattern_view.xml b/res-keyguard/layout/passenger_keyguard_pattern_view.xml
new file mode 100644
index 00000000..be6a4a81
--- /dev/null
+++ b/res-keyguard/layout/passenger_keyguard_pattern_view.xml
@@ -0,0 +1,55 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:gravity="center"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:layout_marginHorizontal="@dimen/car_ui_margin"
+    android:orientation="vertical">
+
+    <TextView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginBottom="@dimen/confirm_lock_message_vertical_spacing"
+        android:text="@string/car_keyguard_enter_your_pattern"
+        android:textAppearance="?android:attr/textAppearanceLarge"/>
+
+    <TextView
+        android:id="@+id/message"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginBottom="@dimen/confirm_lock_message_vertical_spacing"
+        android:gravity="center"
+        android:textAppearance="?android:attr/textAppearanceMedium"/>
+
+    <com.android.internal.widget.LockPatternView
+        android:id="@+id/lockPattern"
+        style="@style/PassengerLockPattern"
+        android:layout_width="@dimen/passenger_keyguard_lockpattern_width"
+        android:layout_height="@dimen/passenger_keyguard_lockpattern_height"/>
+
+    <Button
+        android:id="@+id/cancel_button"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="@*android:dimen/car_padding_2"
+        android:layout_gravity="center"
+        android:text="@android:string/cancel"/>
+
+</LinearLayout>
diff --git a/res-keyguard/layout/passenger_keyguard_pin_pad.xml b/res-keyguard/layout/passenger_keyguard_pin_pad.xml
new file mode 100644
index 00000000..caf4eb51
--- /dev/null
+++ b/res-keyguard/layout/passenger_keyguard_pin_pad.xml
@@ -0,0 +1,122 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<merge xmlns:android="http://schemas.android.com/apk/res/android">
+    <!-- Row 1 -->
+    <Button
+        android:id="@+id/key1"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="1"
+        android:text="@string/one"/>
+    <Button
+        android:id="@+id/key2"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="2"
+        android:text="@string/two"/>
+    <Button
+        android:id="@+id/key3"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="3"
+        android:text="@string/three"/>
+
+    <!-- Row 2 -->
+    <Button
+        android:id="@+id/key4"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="4"
+        android:text="@string/four"/>
+    <Button
+        android:id="@+id/key5"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="5"
+        android:text="@string/five"/>
+    <Button
+        android:id="@+id/key6"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="6"
+        android:text="@string/six"/>
+
+    <!-- Row 3 -->
+    <Button
+        android:id="@+id/key7"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="7"
+        android:text="@string/seven"/>
+    <Button
+        android:id="@+id/key8"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="8"
+        android:text="@string/eight"/>
+    <Button
+        android:id="@+id/key9"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="9"
+        android:text="@string/nine"/>
+
+    <!-- Row 4 -->
+    <ImageButton
+        android:id="@+id/key_backspace"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:contentDescription="@string/backspace_key"
+        android:src="@drawable/ic_backspace"/>
+    <Button
+        android:id="@+id/key0"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:tag="0"
+        android:text="@string/zero"/>
+    <ImageButton
+        android:id="@+id/key_enter"
+        style="@style/PassengerPinPadKey"
+        android:layout_width="@dimen/pin_pad_key_width"
+        android:layout_height="@dimen/pin_pad_key_height"
+        android:layout_margin="@dimen/pin_pad_key_margin"
+        android:contentDescription="@string/enter_key"
+        android:src="@drawable/ic_check"/>
+</merge>
diff --git a/res-keyguard/layout/passenger_keyguard_pin_view.xml b/res-keyguard/layout/passenger_keyguard_pin_view.xml
new file mode 100644
index 00000000..a5eb9698
--- /dev/null
+++ b/res-keyguard/layout/passenger_keyguard_pin_view.xml
@@ -0,0 +1,84 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:layout_marginHorizontal="@dimen/car_ui_margin"
+    android:orientation="horizontal"
+    android:baselineAligned="false">
+
+    <!-- Start side: lock PIN -->
+    <FrameLayout
+        android:layout_width="0dp"
+        android:layout_height="match_parent"
+        android:layout_weight="7"
+        android:gravity="center">
+
+        <com.android.systemui.car.keyguard.passenger.PassengerPinPadView
+            android:id="@+id/passenger_pin_pad"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_gravity="center"
+            android:columnCount="3"
+            android:layoutDirection="ltr"/>
+    </FrameLayout>
+
+    <!-- End side: pin entry field and messages -->
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_vertical"
+        android:layout_weight="5"
+        android:orientation="vertical">
+
+        <EditText
+            android:id="@+id/password_entry"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:layout_marginHorizontal="@dimen/pin_password_entry_padding_horizontal"
+            android:cursorVisible="false"
+            android:focusable="false"
+            android:gravity="center"
+            android:inputType="textPassword"
+            android:maxLines="1"
+            android:textAppearance="?android:attr/textAppearanceLarge"/>
+
+        <TextView
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/confirm_lock_message_vertical_spacing"
+            android:gravity="center"
+            android:text="@string/car_keyguard_enter_your_pin"
+            android:textAppearance="?android:attr/textAppearanceLarge"/>
+
+        <TextView
+            android:id="@+id/message"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="center"
+            android:textAppearance="?android:attr/textAppearanceMedium"/>
+
+        <Button
+            android:id="@+id/cancel_button"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginTop="@*android:dimen/car_padding_2"
+            android:layout_gravity="center"
+            android:text="@android:string/cancel"/>
+    </LinearLayout>
+</LinearLayout>
diff --git a/res/drawable/car_ic_debug.xml b/res/drawable/car_ic_debug.xml
index 6ff5103c..77ac1a97 100644
--- a/res/drawable/car_ic_debug.xml
+++ b/res/drawable/car_ic_debug.xml
@@ -19,10 +19,9 @@
         android:width="24dp"
         android:height="24dp"
         android:viewportWidth="24"
-        android:viewportHeight="24"
-        android:tint="?android:attr/colorControlNormal">
+        android:viewportHeight="24">
     <path
         android:pathData="m4.3301,20.7553c-0.9663,-0.9663 -0.9968,-1.0933 -0.9968,-4.1483 0,-3.2625 -0.1683,-3.7057 -1.5,-3.9507C0.6808,12.4444 0.8254,11.2374 2.0688,10.6903l1.0978,-0.483 0.1667,-3.2801c0.1577,-3.1043 0.218,-3.3242 1.1232,-4.1016 1.1668,-1.0022 2.7101,-0.9771 2.7101,0.0439 0,0.3936 -0.3717,0.8403 -0.9167,1.1015 -0.8964,0.4296 -0.9167,0.5037 -0.9167,3.347 0,2.0922 -0.1455,3.1154 -0.5189,3.6485 -0.4696,0.6705 -0.4696,0.8112 0,1.4817 0.3796,0.542 0.5189,1.5755 0.5189,3.8507v3.1098l1.0181,0.3549c0.7672,0.2674 0.9931,0.5301 0.9167,1.066 -0.1664,1.1666 -1.7368,1.127 -2.9379,-0.0742zM16.8889,21.485c-0.5444,-0.5444 -0.1586,-1.4014 0.7778,-1.7278l1,-0.3486v-3.1098c0,-2.2752 0.1393,-3.3087 0.5189,-3.8507 0.4696,-0.6705 0.4696,-0.8112 0,-1.4817 -0.3734,-0.5331 -0.5189,-1.5563 -0.5189,-3.6485 0,-2.8432 -0.0203,-2.9174 -0.9167,-3.347 -0.5449,-0.2612 -0.9167,-0.7079 -0.9167,-1.1015 0,-1.0211 1.5433,-1.0461 2.7101,-0.0439 0.9052,0.7775 0.9655,0.9974 1.1232,4.1016l0.1667,3.2801 1.0978,0.483c1.2434,0.5471 1.388,1.7541 0.2355,1.9661 -1.3317,0.2449 -1.5,0.6881 -1.5,3.9507 0,3.0388 -0.0349,3.1863 -0.9744,4.1259 -0.9044,0.9044 -2.2817,1.2739 -2.8034,0.7521z"
         android:strokeWidth="0.33333334"
-        android:fillColor="#000000"/>
+        android:fillColor="@color/car_quick_controls_icon_drawable_color"/>
 </vector>
diff --git a/res/layout/car_bottom_system_bar.xml b/res/layout/car_bottom_system_bar.xml
index c260f95b..43292a7a 100644
--- a/res/layout/car_bottom_system_bar.xml
+++ b/res/layout/car_bottom_system_bar.xml
@@ -35,7 +35,8 @@
             android:layout_width="wrap_content"
             android:layout_height="match_parent"
             android:gravity="center_vertical"
-            systemui:hvacAreaId="49">
+            systemui:hvacAreaId="49"
+            systemui:controller="com.android.systemui.car.hvac.TemperatureControlViewController">
             <include layout="@layout/adjustable_temperature_view"/>
         </com.android.systemui.car.hvac.TemperatureControlView>
 
@@ -61,7 +62,9 @@
                 systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
                 systemui:highlightWhenSelected="true"
                 systemui:icon="@drawable/car_ic_home"
-                systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
+                systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+                systemui:systemBarDisableFlags="home"
+                systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
 
             <com.android.systemui.car.systembar.CarSystemBarButton
                 android:id="@+id/passenger_home"
@@ -70,7 +73,9 @@
                 style="@style/SystemBarButton"
                 systemui:highlightWhenSelected="true"
                 systemui:icon="@drawable/car_ic_home"
-                systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
+                systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+                systemui:systemBarDisableFlags="home"
+                systemui:controller="com.android.systemui.car.systembar.PassengerHomeButtonController"/>
 
             <com.android.systemui.car.systembar.CarSystemBarButton
                 android:id="@+id/phone_nav"
@@ -80,7 +85,8 @@
                 systemui:icon="@drawable/car_ic_phone"
                 systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.LAUNCHER;package=com.android.car.dialer;launchFlags=0x10000000;end"
                 systemui:packages="com.android.car.dialer"
-                systemui:clearBackStack="true"/>
+                systemui:clearBackStack="true"
+                systemui:disableForLockTaskModeLocked="true"/>
 
             <com.android.systemui.car.systembar.AppGridButton
                 android:id="@+id/grid_nav"
@@ -90,7 +96,8 @@
                 systemui:highlightWhenSelected="true"
                 systemui:icon="@drawable/car_ic_apps"
                 systemui:intent="@string/system_bar_app_drawer_intent"
-                systemui:clearBackStack="true"/>
+                systemui:clearBackStack="true"
+                systemui:systemBarDisableFlags="home"/>
 
             <com.android.systemui.car.systembar.CarSystemBarButton
                 android:id="@+id/hvac"
@@ -98,7 +105,8 @@
                 style="@style/SystemBarButton"
                 systemui:highlightWhenSelected="true"
                 systemui:icon="@drawable/car_ic_hvac"
-                systemui:broadcast="true"/>
+                systemui:broadcast="true"
+                systemui:controller="com.android.systemui.car.hvac.HvacButtonController"/>
 
             <com.android.systemui.car.systembar.CarSystemBarButton
                 android:id="@+id/control_center_nav"
@@ -108,7 +116,8 @@
                 systemui:highlightWhenSelected="true"
                 systemui:icon="@drawable/car_ic_control_center"
                 systemui:intent="intent:#Intent;action=android.intent.action.MAIN;package=com.android.car.multidisplay.controlcenter;component=com.android.car.multidisplay.controlcenter/.ControlCenterActivity;B.BOTTOM_BAR_LAUNCH=true;end"
-                systemui:componentNames="com.android.car.multidisplay.controlcenter/.ControlCenterActivity"/>
+                systemui:componentNames="com.android.car.multidisplay.controlcenter/.ControlCenterActivity"
+                systemui:controller="com.android.systemui.car.systembar.ControlCenterButtonController"/>
 
             <com.android.systemui.car.systembar.CarSystemBarButton
                 android:id="@+id/notifications"
@@ -116,7 +125,9 @@
                 style="@style/SystemBarButton"
                 systemui:highlightWhenSelected="true"
                 systemui:icon="@drawable/car_ic_notification"
-                systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"/>
+                systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"
+                systemui:systemBarDisableFlags="notificationIcons"
+                systemui:controller="com.android.systemui.car.notification.NotificationButtonController"/>
 
             <com.android.systemui.car.systembar.AssistantButton
                 android:id="@+id/assistant"
@@ -137,7 +148,8 @@
             android:layout_height="match_parent"
             android:layout_alignParentEnd="true"
             android:gravity="center_vertical"
-            systemui:hvacAreaId="68">
+            systemui:hvacAreaId="68"
+            systemui:controller="com.android.systemui.car.hvac.TemperatureControlViewController">
             <include layout="@layout/adjustable_temperature_view"/>
         </com.android.systemui.car.hvac.TemperatureControlView>
 
@@ -171,6 +183,8 @@
             systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_home"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
     </LinearLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_bottom_system_bar_dock.xml b/res/layout/car_bottom_system_bar_dock.xml
index 5bc42a8f..df556e82 100644
--- a/res/layout/car_bottom_system_bar_dock.xml
+++ b/res/layout/car_bottom_system_bar_dock.xml
@@ -39,7 +39,9 @@
             systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_home"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
 
         <com.android.systemui.car.systembar.CarSystemBarButton
             android:id="@+id/passenger_home"
@@ -48,7 +50,9 @@
             style="@style/SystemBarButtonWithDock"
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_home"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.PassengerHomeButtonController"/>
 
         <Space
             android:layout_width="0dp"
@@ -58,7 +62,8 @@
         <com.android.systemui.car.hvac.TemperatureControlView
             android:id="@+id/driver_hvac"
             style="@style/TemperatureControlView"
-            systemui:hvacAreaId="49">
+            systemui:hvacAreaId="49"
+            systemui:controller="com.android.systemui.car.hvac.TemperatureControlViewController">
             <include layout="@layout/adjustable_temperature_view"/>
         </com.android.systemui.car.hvac.TemperatureControlView>
 
@@ -75,7 +80,8 @@
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_apps"
             systemui:intent="@string/system_bar_app_drawer_intent"
-            systemui:clearBackStack="true"/>
+            systemui:clearBackStack="true"
+            systemui:systemBarDisableFlags="home"/>
 
         <com.android.systemui.car.systembar.element.layout.CarSystemBarFrameLayout
             android:layout_width="wrap_content"
@@ -96,7 +102,8 @@
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_control_center"
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;package=com.android.car.multidisplay.controlcenter;component=com.android.car.multidisplay.controlcenter/.ControlCenterActivity;B.BOTTOM_BAR_LAUNCH=true;end"
-            systemui:componentNames="com.android.car.multidisplay.controlcenter/.ControlCenterActivity"/>
+            systemui:componentNames="com.android.car.multidisplay.controlcenter/.ControlCenterActivity"
+            systemui:controller="com.android.systemui.car.systembar.ControlCenterButtonController"/>
 
         <Space
             android:layout_width="0dp"
@@ -106,7 +113,8 @@
         <com.android.systemui.car.hvac.TemperatureControlView
             android:id="@+id/passenger_hvac"
             style="@style/TemperatureControlView"
-            systemui:hvacAreaId="68">
+            systemui:hvacAreaId="68"
+            systemui:controller="com.android.systemui.car.hvac.TemperatureControlViewController">
             <include layout="@layout/adjustable_temperature_view"/>
         </com.android.systemui.car.hvac.TemperatureControlView>
 
@@ -152,6 +160,8 @@
             systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_home"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
     </LinearLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_bottom_system_bar_unprovisioned.xml b/res/layout/car_bottom_system_bar_unprovisioned.xml
index 5bbca41d..0bfd9481 100644
--- a/res/layout/car_bottom_system_bar_unprovisioned.xml
+++ b/res/layout/car_bottom_system_bar_unprovisioned.xml
@@ -41,7 +41,8 @@
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
             systemui:selectedIcon="@drawable/car_ic_overview_selected"
             systemui:highlightWhenSelected="true"
-        />
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
     </LinearLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
 
diff --git a/res/layout/car_left_system_bar_default.xml b/res/layout/car_left_system_bar_default.xml
index 6b1c92f8..7fa011c6 100644
--- a/res/layout/car_left_system_bar_default.xml
+++ b/res/layout/car_left_system_bar_default.xml
@@ -87,7 +87,8 @@
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.LAUNCHER;package=com.android.car.dialer;launchFlags=0x10000000;end"
             systemui:packages="com.android.car.dialer"
             systemui:selectedIcon="@drawable/car_ic_phone_selected"
-            systemui:highlightWhenSelected="true"/>
+            systemui:highlightWhenSelected="true"
+            systemui:disableForLockTaskModeLocked="true"/>
     </LinearLayout>
     <LinearLayout
         android:id="@+id/extra_nav_buttons"
@@ -105,7 +106,9 @@
             systemui:icon="@drawable/car_ic_overview"
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
             systemui:selectedIcon="@drawable/car_ic_overview_selected"
-            systemui:highlightWhenSelected="true"/>
+            systemui:highlightWhenSelected="true"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
 
         <com.android.systemui.car.systembar.CarSystemBarButton
             android:id="@+id/grid_nav"
@@ -115,6 +118,7 @@
             systemui:icon="@drawable/car_ic_apps"
             systemui:intent="intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.carlauncher;launchFlags=0x24000000;end"
             systemui:selectedIcon="@drawable/car_ic_apps_selected"
-            systemui:highlightWhenSelected="true"/>
+            systemui:highlightWhenSelected="true"
+            systemui:systemBarDisableFlags="home"/>
     </LinearLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_left_system_bar_unprovisioned.xml b/res/layout/car_left_system_bar_unprovisioned.xml
index 0fae0612..e430d000 100644
--- a/res/layout/car_left_system_bar_unprovisioned.xml
+++ b/res/layout/car_left_system_bar_unprovisioned.xml
@@ -44,7 +44,9 @@
             android:paddingTop="30dp"
             android:paddingBottom="30dp"
             android:contentDescription="@string/system_bar_home_label"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
 
         <com.android.systemui.car.systembar.CarSystemBarButton
             android:id="@+id/hvac"
@@ -55,6 +57,7 @@
             android:paddingTop="30dp"
             android:paddingBottom="30dp"
             android:contentDescription="@string/system_bar_climate_control_label"
-            systemui:broadcast="true"/>
+            systemui:broadcast="true"
+            systemui:controller="com.android.systemui.car.hvac.HvacButtonController"/>
     </LinearLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_right_system_bar_default.xml b/res/layout/car_right_system_bar_default.xml
index fe2a90f0..be968776 100644
--- a/res/layout/car_right_system_bar_default.xml
+++ b/res/layout/car_right_system_bar_default.xml
@@ -88,7 +88,8 @@
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.LAUNCHER;package=com.android.car.dialer;launchFlags=0x10000000;end"
             systemui:packages="com.android.car.dialer"
             systemui:selectedIcon="@drawable/car_ic_phone_selected"
-            systemui:highlightWhenSelected="true"/>
+            systemui:highlightWhenSelected="true"
+            systemui:disableForLockTaskModeLocked="true"/>
     </LinearLayout>
 
     <LinearLayout
@@ -108,7 +109,9 @@
             systemui:icon="@drawable/car_ic_overview"
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
             systemui:selectedIcon="@drawable/car_ic_overview_selected"
-            systemui:highlightWhenSelected="true"/>
+            systemui:highlightWhenSelected="true"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
 
         <com.android.systemui.car.systembar.CarSystemBarButton
             android:id="@+id/grid_nav"
@@ -118,6 +121,7 @@
             systemui:icon="@drawable/car_ic_apps"
             systemui:intent="intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.carlauncher;launchFlags=0x24000000;end"
             systemui:selectedIcon="@drawable/car_ic_apps_selected"
-            systemui:highlightWhenSelected="true"/>
+            systemui:highlightWhenSelected="true"
+            systemui:systemBarDisableFlags="home"/>
     </LinearLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_right_system_bar_unprovisioned.xml b/res/layout/car_right_system_bar_unprovisioned.xml
index 0fae0612..e430d000 100644
--- a/res/layout/car_right_system_bar_unprovisioned.xml
+++ b/res/layout/car_right_system_bar_unprovisioned.xml
@@ -44,7 +44,9 @@
             android:paddingTop="30dp"
             android:paddingBottom="30dp"
             android:contentDescription="@string/system_bar_home_label"
-            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
 
         <com.android.systemui.car.systembar.CarSystemBarButton
             android:id="@+id/hvac"
@@ -55,6 +57,7 @@
             android:paddingTop="30dp"
             android:paddingBottom="30dp"
             android:contentDescription="@string/system_bar_climate_control_label"
-            systemui:broadcast="true"/>
+            systemui:broadcast="true"
+            systemui:controller="com.android.systemui.car.hvac.HvacButtonController"/>
     </LinearLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_top_system_bar_dock.xml b/res/layout/car_top_system_bar_dock.xml
index b7afa4af..8b05b13c 100644
--- a/res/layout/car_top_system_bar_dock.xml
+++ b/res/layout/car_top_system_bar_dock.xml
@@ -71,7 +71,9 @@
             android:layout_toLeftOf="@id/camera_privacy_chip"
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_notification_dock"
-            systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"/>
+            systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"
+            systemui:systemBarDisableFlags="notificationIcons"
+            systemui:controller="com.android.systemui.car.notification.NotificationButtonController"/>
 
         <include layout="@layout/camera_privacy_chip"
             android:layout_width="wrap_content"
diff --git a/res/layout/qc_debug_panel.xml b/res/layout/qc_debug_panel.xml
index 21e4e7c8..264581e7 100644
--- a/res/layout/qc_debug_panel.xml
+++ b/res/layout/qc_debug_panel.xml
@@ -45,11 +45,26 @@
                     android:layout_width="match_parent"
                     android:layout_height="wrap_content"
                     android:orientation="vertical">
+                    <com.android.systemui.car.qc.SystemUIQCView
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:gravity="center"
+                        app:remoteQCProvider="content://com.android.car.settings.qc/debug_driving_mode_toggle"/>
                     <com.android.systemui.car.qc.SystemUIQCView
                         android:layout_width="match_parent"
                         android:layout_height="wrap_content"
                         android:gravity="center"
                         app:remoteQCProvider="content://com.android.car.settings.qc/debug_layout_bounds_toggle"/>
+                    <com.android.systemui.car.qc.SystemUIQCView
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:gravity="center"
+                        app:remoteQCProvider="content://com.android.car.settings.qc/debug_force_rtl_toggle"/>
+                    <com.android.systemui.car.qc.SystemUIQCView
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:gravity="center"
+                        app:remoteQCProvider="content://com.android.car.settings.qc/debug_customization_overlay_toggle"/>
                 </LinearLayout>
             </ScrollView>
             <com.android.systemui.car.qc.QCFooterButton
diff --git a/res/layout/sensor_use_started_title.xml b/res/layout/sensor_use_started_title.xml
index b9d9540c..f308e599 100644
--- a/res/layout/sensor_use_started_title.xml
+++ b/res/layout/sensor_use_started_title.xml
@@ -17,13 +17,13 @@
 
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
               android:orientation="vertical"
-              android:gravity="center_vertical">
+              android:gravity="center_vertical|start">
     <LinearLayout
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
-        android:layout_margin="@dimen/car_alert_dialog_padding"
+        android:layout_marginBottom="@dimen/car_alert_dialog_padding"
         android:orientation="horizontal"
-        android:gravity="center">
+        android:gravity="center_vertical|start">
         <ImageView
             android:layout_width="@dimen/car_alert_dialog_icon_size"
             android:layout_height="@dimen/car_alert_dialog_icon_size"
@@ -41,8 +41,7 @@
     </LinearLayout>
     <com.android.internal.widget.DialogTitle
         android:id="@+id/sensor_use_started_title_message"
-        style="@android:style/TextAppearance.DeviceDefault.WindowTitle"
+        style="@android:style/TextAppearance.DeviceDefault.DialogWindowTitle"
         android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:textAlignment="center" />
+        android:layout_height="wrap_content"/>
 </LinearLayout>
\ No newline at end of file
diff --git a/res/layout/sysui_overlay_window.xml b/res/layout/sysui_overlay_window.xml
index 58c1c522..42badf01 100644
--- a/res/layout/sysui_overlay_window.xml
+++ b/res/layout/sysui_overlay_window.xml
@@ -37,6 +37,11 @@
               android:layout_height="match_parent"
               android:layout="@layout/keyguard_container"/>
 
+    <ViewStub android:id="@+id/passenger_keyguard_stub"
+              android:layout_width="match_parent"
+              android:layout_height="match_parent"
+              android:layout="@layout/passenger_keyguard_overlay_window"/>
+
     <ViewStub android:id="@+id/hvac_panel_stub"
               android:layout_width="match_parent"
               android:layout_height="@dimen/hvac_panel_full_expanded_height"
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 3a449fd0..ea905b17 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> word tans afgemeld. Probeer later weer."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Gebruiker is nie tans beskikbaar nie"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Kan nie veilige gebruiker op passasierskerm begin nie"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Verkeerde patroon"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Verkeerde PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Verkeerde wagwoord"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Te veel verkeerde pogings. Probeer weer oor # sekonde.}other{Te veel verkeerde pogings. Probeer weer oor # sekondes.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"bestuurder"</string>
     <string name="seat_front" msgid="836133281052793377">"voor"</string>
     <string name="seat_rear" msgid="403133444964528577">"agter"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index e8a472ff..765ae9a5 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ዘግተው እንዲውጡ እየተደረገ ነው። ቆይተው እንደገና ይሞክሩ።"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ተጠቃሚ በአሁኑ ጊዜ አይገኙም"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"በመንገደኛ ማሳያ ላይ ደህንነታቸው የተጠበቀ ተጠቃሚን ማስጀመር አልተቻለም"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"የተሳሳተ ሥርዓተ ጥለት"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"የተሳሳተ ፒን"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"የተሳሳተ የይለፍ ቃል"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{በጣም ብዙ የተሳሳቱ ሙከራዎች። በ# ሰከንድ ውስጥ እንደገና ይሞክሩ።}one{በጣም ብዙ የተሳሳቱ ሙከራዎች። በ# ሰከንድ ውስጥ እንደገና ይሞክሩ።}other{በጣም ብዙ የተሳሳቱ ሙከራዎች። በ# ሰከንዶች ውስጥ እንደገና ይሞክሩ።}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ነጂ"</string>
     <string name="seat_front" msgid="836133281052793377">"የፊት"</string>
     <string name="seat_rear" msgid="403133444964528577">"የኋላ"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index a6a02587..621359fc 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -26,7 +26,7 @@
     <string name="car_add_user" msgid="6182764665687382136">"إضافة ملف شخصي"</string>
     <string name="end_session" msgid="2765206020435441421">"إنهاء الجلسة"</string>
     <string name="car_new_user" msgid="6766334721724989964">"ملف شخصي جديد"</string>
-    <string name="user_add_profile_title" msgid="828371911076521952">"هل تريد إضافة ملف شخصي جديد؟"</string>
+    <string name="user_add_profile_title" msgid="828371911076521952">"هل المطلوب إنشاء ملف شخصي جديد؟"</string>
     <string name="user_add_user_message_setup" msgid="1639791240776969175">"بعد إضافة ملف شخصي جديد، يمكن لصاحب الحساب تخصيصه."</string>
     <string name="user_add_user_message_update" msgid="4507063398890966360">"يمكن لأي ملف شخصي تثبيت تحديثات التطبيقات، والتي تكون متاحة لاحقًا لجميع الملفات الشخصية."</string>
     <string name="profile_limit_reached_title" msgid="7891779218496729653">"تم بلوغ أقصى عدد للملفات الشخصية"</string>
@@ -61,12 +61,12 @@
     <string name="system_bar_applications_label" msgid="7081862804211786227">"التطبيقات"</string>
     <string name="system_bar_climate_control_label" msgid="4091187805919276017">"التحكُّم في المناخ"</string>
     <string name="system_bar_notifications_label" msgid="6039158514903928210">"الإشعارات"</string>
-    <string name="system_bar_maps_label" msgid="7883864993280235380">"خرائط Google"</string>
+    <string name="system_bar_maps_label" msgid="7883864993280235380">"خرائط"</string>
     <string name="system_bar_media_label" msgid="6156112139796274847">"الوسائط"</string>
     <string name="system_bar_control_center_label" msgid="5269256399167811590">"مركز التحكّم"</string>
     <string name="system_bar_assistant_label" msgid="7312821609046711200">"مساعد Google"</string>
     <string name="system_bar_mic_privacy_chip" msgid="2494035034004728597">"شريحة خصوصية الميكروفون"</string>
-    <string name="system_bar_user_avatar" msgid="4122817348016746322">"الصورة الرمزية للمستخدم"</string>
+    <string name="system_bar_user_avatar" msgid="4122817348016746322">"أفاتار المستخدم"</string>
     <string name="system_bar_user_name_text" msgid="5859605302481171746">"نص اسم المستخدم"</string>
     <string name="hvac_decrease_button_label" msgid="5628481079099995286">"خفض درجة الحرارة"</string>
     <string name="hvac_increase_button_label" msgid="2855688290787396792">"رفع درجة الحرارة"</string>
@@ -106,7 +106,7 @@
     <string name="user_adding_message" msgid="4700853604381151415">"جارٍ إضافة ملف شخصي جديد…"</string>
     <string name="max_user_limit_reached_title" msgid="7319012467112549458"></string>
     <string name="max_user_limit_reached_message" msgid="1445188223628919167">"يمكنك إضافة ما يصل إلى <xliff:g id="USER_LIMIT">%d</xliff:g> ملف شخصي."</string>
-    <string name="confirm_add_user_title" msgid="75853419607883551">"هل تريد إضافة ملف شخصي جديد؟"</string>
+    <string name="confirm_add_user_title" msgid="75853419607883551">"هل المطلوب إضافة ملف شخصي جديد؟"</string>
     <string name="already_logged_in_message" msgid="3657131706472825219">"للمتابعة، على \"<xliff:g id="USER_NAME">%1$s</xliff:g>\" تسجيل الخروج من شاشة <xliff:g id="SEAT_LOCATION">%2$s</xliff:g>."</string>
     <string name="header_bar_text_in_logged_out_state" msgid="3903097856063608991">"اختَر ملفًا شخصيًا للبدء"</string>
     <string name="logged_in_text" msgid="742324514947999718">"مسجّلٌ الدخول"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"يتم الآن تسجيل خروج \"<xliff:g id="USER_NAME">%s</xliff:g>\". يُرجى إعادة المحاولة لاحقًا."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"المستخدم غير متاح حاليًا"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"يتعذّر بدء تشغيل مستخدم آمن على شاشة الراكب"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"النقش غير صحيح"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"رقم التعريف الشخصي غير صحيح"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"كلمة المرور غير صحيحة"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{المحاولات غير الصحيحة كثيرة جدًا. أعِد المحاولة خلال ثانية واحدة.}zero{المحاولات غير الصحيحة كثيرة جدًا. أعِد المحاولة خلال # ثانية.}two{المحاولات غير الصحيحة كثيرة جدًا. أعِد المحاولة خلال ثانيتَين.}few{المحاولات غير الصحيحة كثيرة جدًا. أعِد المحاولة خلال # ثوانٍ.}many{المحاولات غير الصحيحة كثيرة جدًا. أعِد المحاولة خلال # ثانية.}other{المحاولات غير الصحيحة كثيرة جدًا. أعِد المحاولة خلال # ثانية.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"السائق"</string>
     <string name="seat_front" msgid="836133281052793377">"المقعد الأمامي"</string>
     <string name="seat_rear" msgid="403133444964528577">"المقعد الخلفي"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 3c1b13d8..cadd3af1 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>ক ছাইন আউট কৰাই থকা হৈছে। পাছত পুনৰ চেষ্টা কৰক।"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ব্যৱহাৰকাৰী বৰ্তমান উপলব্ধ নহয়"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"যাত্ৰীৰ ডিছপ্লে’ত ব্যৱহাৰকাৰী সুৰক্ষিত কৰক আৰম্ভ কৰিব পৰা নগ’ল"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ভুল আৰ্হি"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"ভুল পিন"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"ভুল পাছৱৰ্ড"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{অতি বেছিসংখ্যক অশুদ্ধ প্ৰয়াস। # ছেকেণ্ডৰ পাছত পুনৰ চেষ্টা কৰক।}one{অতি বেছিসংখ্যক অশুদ্ধ প্ৰয়াস। # ছেকেণ্ডৰ পাছত পুনৰ চেষ্টা কৰক।}other{অতি বেছিসংখ্যক অশুদ্ধ প্ৰয়াস। # ছেকেণ্ডৰ পাছত পুনৰ চেষ্টা কৰক।}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"চালকৰ আসন"</string>
     <string name="seat_front" msgid="836133281052793377">"সন্মুখৰ আসন"</string>
     <string name="seat_rear" msgid="403133444964528577">"পিছফালৰ আসন"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 799dc65a..095efed5 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> çıxır. Sonra cəhd edin."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"İstifadəçi hazırda əlçatan deyil"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Sərnişin ekranında təhlükəsiz istifadəçi seçimini işə salmaq olmur"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Yanlış model"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Yanlış PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Yanlış parol"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Çoxlu səhv cəhd edildi. # saniyə sonra yenidən cəhd edin.}other{Çoxlu səhv cəhd edildi. # saniyə sonra yenidən cəhd edin.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"sürücü"</string>
     <string name="seat_front" msgid="836133281052793377">"ön"</string>
     <string name="seat_rear" msgid="403133444964528577">"arxa"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 70d90d77..0ab254a5 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> se odjavljuje. Probajte ponovo kasnije."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Korisnik trenutno nije dostupan"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nije moguće pokrenuti bezbednog korisnika na ekranu putnika"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Pogrešan šablon"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Pogrešan PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Pogrešna lozinka"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Previše netačnih pokušaja. Probajte ponovo za # sekundu.}one{Previše netačnih pokušaja. Probajte ponovo za # sekundu.}few{Previše netačnih pokušaja. Probajte ponovo za # sekunde.}other{Previše netačnih pokušaja. Probajte ponovo za # sekundi.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vozač"</string>
     <string name="seat_front" msgid="836133281052793377">"prednje"</string>
     <string name="seat_rear" msgid="403133444964528577">"zadnje"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index c463f82f..772386ee 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> выходзіць з уліковага запісу. Паўтарыце спробу пазней."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Карыстальнік недаступны"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Не ўдалося ўключыць абаронены профіль карыстальніка на дысплэі пасажыра"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Няправільны ўзор"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Няправільны PIN-код"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Няправільны пароль"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Занадта шмат няўдалых спроб. Паўтарыце спробу праз # секунду.}one{Занадта шмат няўдалых спроб. Паўтарыце спробу праз # секунду.}few{Занадта шмат няўдалых спроб. Паўтарыце спробу праз # секунды.}many{Занадта шмат няўдалых спроб. Паўтарыце спробу праз # секунд.}other{Занадта шмат няўдалых спроб. Паўтарыце спробу праз # секунды.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"на месцы вадзіцеля"</string>
     <string name="seat_front" msgid="836133281052793377">"на пярэднім сядзенні"</string>
     <string name="seat_rear" msgid="403133444964528577">"на заднім сядзенні"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 5f6a47e1..0c66e8f7 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -92,7 +92,7 @@
     <string name="qc_footer_network_internet_settings" msgid="2480582764252681575">"Настройки за мрежата и интернет"</string>
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Настройки за дисплея"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Настройки за звука"</string>
-    <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Настройки за потр. профили и профилите"</string>
+    <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Настройки за потребители и профили"</string>
     <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Опции за програмисти"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Фигурата не поддържа ротация. Моля, докоснете"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Екранът ви е заключен"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> излиза от профила си. Опитайте отново по-късно."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Понастоящем потребителят не е налице"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"На екрана на пътника не може да се стартира надежден потребител"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Грешна фигура"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Грешен ПИН код"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Грешна парола"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Твърде много грешни опити. Опитайте отново след # секунда.}other{Твърде много грешни опити. Опитайте отново след # секунди.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"шофьорска"</string>
     <string name="seat_front" msgid="836133281052793377">"предна"</string>
     <string name="seat_rear" msgid="403133444964528577">"задна"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 27955b9c..c2ae3937 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> সাইন-আউট করছেন। পরে আবার চেষ্টা করুন।"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"বর্তমান ব্যবহারকারীর উপলভ্য নেই"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"যাত্রীর ডিসপ্লেতে ব্যবহারকারীর সুরক্ষিত প্রোফাইল চালু করা যায়নি"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ভুল প্যাটার্ন"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"ভুল পিন"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"ভুল পাসওয়ার্ড"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{অনেকবার ভুলভাবে চেষ্টা করেছেন। # সেকেন্ড পরে আবার চেষ্টা করুন।}one{অনেকবার ভুলভাবে চেষ্টা করেছেন। # সেকেন্ড পরে আবার চেষ্টা করুন।}other{অনেকবার ভুলভাবে চেষ্টা করেছেন। # সেকেন্ড পরে আবার চেষ্টা করুন।}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ড্রাইভার"</string>
     <string name="seat_front" msgid="836133281052793377">"সামনের দিক"</string>
     <string name="seat_rear" msgid="403133444964528577">"পিছন দিক"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index e1b6bd13..3f1f11d5 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -23,7 +23,7 @@
     <string name="fan_speed_off" msgid="3860115181014880798">"ISKLJUČENO"</string>
     <string name="hvac_temperature_off" msgid="8370977023494579242">"ISKLJUČENO"</string>
     <string name="voice_recognition_toast" msgid="7579725862117020349">"Prepoznavanjem glasa sada upravlja povezani Bluetooth uređaj"</string>
-    <string name="car_add_user" msgid="6182764665687382136">"Dodaj profil"</string>
+    <string name="car_add_user" msgid="6182764665687382136">"Dodajte profil"</string>
     <string name="end_session" msgid="2765206020435441421">"Završi sesiju"</string>
     <string name="car_new_user" msgid="6766334721724989964">"Novi profil"</string>
     <string name="user_add_profile_title" msgid="828371911076521952">"Dodati novi profil?"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> se odjavljuje. Pokušajte ponovo kasnije."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Korisnik trenutno nije dostupan"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nije moguće pokrenuti sigurni profil korisnika na ekranu putnika"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Pogrešan uzorak"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Pogrešan PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Pogrešna lozinka"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Previše pogrešnih pokušaja. Pokušajte ponovo za # sekundu.}one{Previše pogrešnih pokušaja. Pokušajte ponovo za # sekundu.}few{Previše pogrešnih pokušaja. Pokušajte ponovo za # sekunde.}other{Previše pogrešnih pokušaja. Pokušajte ponovo za # sekundi.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vozačevom"</string>
     <string name="seat_front" msgid="836133281052793377">"prednjem"</string>
     <string name="seat_rear" msgid="403133444964528577">"stražnjem"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 22f21268..d406e0e2 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"S\'està tancant la sessió de: <xliff:g id="USER_NAME">%s</xliff:g>. Torna-ho a provar més tard."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Actualment l\'usuari no està disponible"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"No es pot iniciar el mode d\'usuari segur a la pantalla del passatger"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Patró incorrecte"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN incorrecte"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Contrasenya incorrecta"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Massa intents incorrectes. Torna-ho a provar d\'aquí a # segon.}other{Massa intents incorrectes. Torna-ho a provar d\'aquí a # segons.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"del conductor"</string>
     <string name="seat_front" msgid="836133281052793377">"davanter"</string>
     <string name="seat_rear" msgid="403133444964528577">"posterior"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 9a116e1f..3db3a829 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Uživatel <xliff:g id="USER_NAME">%s</xliff:g> je odhlašován. Zkuste to později."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Uživatel teď není k dispozici"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Na displeji pasažéra se nepodařilo spustit bezpečného uživatele"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Nesprávné gesto"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Nesprávný kód PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Nesprávné heslo"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Příliš mnoho neplatných pokusů. Zkuste to znovu za # sekundu.}few{Příliš mnoho neplatných pokusů. Zkuste to znovu za # sekundy.}many{Příliš mnoho neplatných pokusů. Zkuste to znovu za # sekundy.}other{Příliš mnoho neplatných pokusů. Zkuste to znovu za # sekund.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"řidiče"</string>
     <string name="seat_front" msgid="836133281052793377">"vpředu"</string>
     <string name="seat_rear" msgid="403133444964528577">"vzadu"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index db6503f8..68feb13c 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> logges ud. Prøv igen senere."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Brugeren er ikke tilgængelig i øjeblikket"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Den sikre bruger kan ikke tilgå passagerskærmen"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Forkert mønster"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Forkert pinkode"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Forkert adgangskode"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{For mange forkerte forsøg. Prøv igen om # sekund.}one{For mange forkerte forsøg. Prøv igen om # sekund.}other{For mange forkerte forsøg. Prøv igen om # sekunder.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"chauffør"</string>
     <string name="seat_front" msgid="836133281052793377">"forside"</string>
     <string name="seat_rear" msgid="403133444964528577">"bagside"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 82d63f9a..6e3d3ffe 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> wird abgemeldet. Bitte versuche es später noch einmal."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Nutzer derzeit nicht verfügbar"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"„Geschützter Nutzer“ kann auf dem Display des Beifahrers nicht gestartet werden"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Falsches Muster"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Falsche PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Falsches Passwort"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Zu viele fehlgeschlagene Versuche. Versuche es in # Sekunde noch einmal.}other{Zu viele fehlgeschlagene Versuche. Versuche es in # Sekunden noch einmal.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"Fahrer"</string>
     <string name="seat_front" msgid="836133281052793377">"vorne"</string>
     <string name="seat_rear" msgid="403133444964528577">"hinten"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index ef3dd86f..e92e269f 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Γίνεται αποσύνδεση του χρήστη <xliff:g id="USER_NAME">%s</xliff:g>. Δοκιμάστε ξανά αργότερα."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Ο χρήστης δεν είναι διαθέσιμος προσωρινά"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Δεν είναι δυνατή η εκκίνηση του ασφαλούς χρήστη στην οθόνη επιβατών"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Λανθασμένο μοτίβο"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Λανθασμένο PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Λανθασμένος κωδικός πρόσβασης"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Πάρα πολλές ανεπιτυχείς προσπάθειες. Δοκιμάστε ξανά σε # δευτερόλεπτο.}other{Πάρα πολλές ανεπιτυχείς προσπάθειες. Δοκιμάστε ξανά σε # δευτερόλεπτα.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"οδηγός"</string>
     <string name="seat_front" msgid="836133281052793377">"μπροστά"</string>
     <string name="seat_rear" msgid="403133444964528577">"πίσω"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index a13496e6..eeff2460 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> is being signed out. Try again later."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"User currently unavailable"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Unable to start secure user on passenger display"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Wrong pattern"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Wrong PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Wrong password"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Too many incorrect attempts. Try again in # second.}other{Too many incorrect attempts. Try again in # seconds.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"front"</string>
     <string name="seat_rear" msgid="403133444964528577">"rear"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 2edb4c53..33baafbf 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> is being signed out. Try again later."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"User currently unavailable"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Unable to start secure user on passenger display"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Wrong pattern"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Wrong PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Wrong password"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Too many incorrect attempts. Try again in # second.}other{Too many incorrect attempts. Try again in # seconds.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"front"</string>
     <string name="seat_rear" msgid="403133444964528577">"rear"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index a13496e6..eeff2460 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> is being signed out. Try again later."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"User currently unavailable"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Unable to start secure user on passenger display"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Wrong pattern"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Wrong PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Wrong password"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Too many incorrect attempts. Try again in # second.}other{Too many incorrect attempts. Try again in # seconds.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"front"</string>
     <string name="seat_rear" msgid="403133444964528577">"rear"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index a13496e6..eeff2460 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> is being signed out. Try again later."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"User currently unavailable"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Unable to start secure user on passenger display"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Wrong pattern"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Wrong PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Wrong password"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Too many incorrect attempts. Try again in # second.}other{Too many incorrect attempts. Try again in # seconds.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"front"</string>
     <string name="seat_rear" msgid="403133444964528577">"rear"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 3cdb7798..e3a48707 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> está saliendo. Vuelve a intentarlo más tarde."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"El usuario no está disponible en este momento"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"No se puede iniciar la protección del usuario en la pantalla de pasajero"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Patrón incorrecto"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN incorrecto"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Contraseña incorrecta"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Demasiados intentos incorrectos. Vuelve a intentarlo en # segundo.}other{Demasiados intentos incorrectos. Vuelve a intentarlo en # segundos.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"conductor"</string>
     <string name="seat_front" msgid="836133281052793377">"parte frontal"</string>
     <string name="seat_rear" msgid="403133444964528577">"parte posterior"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 87b3bc5b..01d446ab 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> está cerrando sesión. Inténtalo de nuevo más tarde."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Usuario no disponible actualmente"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"No se puede iniciar el modo de usuario seguro en la pantalla del pasajero"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Patrón incorrecto"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN incorrecto"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Contraseña incorrecta"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Demasiados intentos incorrectos. Vuelve a intentarlo en # segundo.}other{Demasiados intentos incorrectos. Vuelve a intentarlo en # segundos.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"del conductor"</string>
     <string name="seat_front" msgid="836133281052793377">"delantero"</string>
     <string name="seat_rear" msgid="403133444964528577">"trasero"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 05407504..a1255f3f 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Kasutaja <xliff:g id="USER_NAME">%s</xliff:g> väljalogimine on pooleli. Proovige hiljem uuesti."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Kasutaja pole praegu saadaval"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Kõrvalistuja ekraanil ei saa turvalist kasutajaprofiili avada"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Vale muster"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Vale PIN-kood"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Vale parool"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Liiga palju valesid katseid. Proovige uuesti # sekundi pärast.}other{Liiga palju valesid katseid. Proovige uuesti # sekundi pärast.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"juht"</string>
     <string name="seat_front" msgid="836133281052793377">"eesmine"</string>
     <string name="seat_rear" msgid="403133444964528577">"tagumine"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index c953468e..1d7a01b7 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -22,7 +22,7 @@
     <string name="fan_speed_max" msgid="956683571700419211">"GEHIENEKOA"</string>
     <string name="fan_speed_off" msgid="3860115181014880798">"ITZALITA"</string>
     <string name="hvac_temperature_off" msgid="8370977023494579242">"DESAKTIBATUTA"</string>
-    <string name="voice_recognition_toast" msgid="7579725862117020349">"Konektatutako Bluetooth bidezko gailuak kudeatzen du ahotsa ezagutzeko eginbidea"</string>
+    <string name="voice_recognition_toast" msgid="7579725862117020349">"Konektatutako Bluetooth bidezko gailuak kudeatzen du ahots-ezagutzea"</string>
     <string name="car_add_user" msgid="6182764665687382136">"Gehitu profil bat"</string>
     <string name="end_session" msgid="2765206020435441421">"Amaitu saioa"</string>
     <string name="car_new_user" msgid="6766334721724989964">"Profil berria"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> erabiltzailearen saioa amaitzen. Saiatu berriro geroago."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Erabiltzailea ez dago erabilgarri une honetan"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Ezin izan da abiarazi erabiltzaile segurua bidaiariaren pantailan"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Eredua ez da zuzena"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PINa ez da zuzena"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Pasahitza ez da zuzena"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Saiakera oker gehiegi egin dituzu. Saiatu berriro # segundo barru.}other{Saiakera oker gehiegi egin dituzu. Saiatu berriro # segundo barru.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"gidaria"</string>
     <string name="seat_front" msgid="836133281052793377">"aurrekoa"</string>
     <string name="seat_rear" msgid="403133444964528577">"atzekoa"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 5f532703..cf959ef0 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> درحال خروج از سیستم است. بعداً دوباره امتحان کنید."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"کاربر فعلاً دردسترس نیست"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"کاربر ایمن در نمایشگر مسافر راه‌اندازی نشد"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"الگو اشتباه است"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"پین اشتباه است"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"گذرواژه اشتباه است"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{به سقف تلاش‌های اشتباه رسیده‌اید. ‫# ثانیه دیگر دوباره امتحان کنید.}one{به سقف تلاش‌های اشتباه رسیده‌اید. ‫# ثانیه دیگر دوباره امتحان کنید.}other{به سقف تلاش‌های اشتباه رسیده‌اید. ‫# ثانیه دیگر دوباره امتحان کنید.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"راننده"</string>
     <string name="seat_front" msgid="836133281052793377">"جلو"</string>
     <string name="seat_rear" msgid="403133444964528577">"عقب"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index fc02f91c..4d87388f 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> kirjataan ulos. Yritä myöhemmin uudelleen."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Käyttäjä ei juuri nyt saatavilla"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Suojattua käyttäjää ei voi valita matkustajan näytöltä"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Väärä kuvio"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Väärä PIN-koodi"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Väärä salasana"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Liian monta virheellistä yritystä. Yritä uudelleen # sekunnin kuluttua.}other{Liian monta virheellistä yritystä. Yritä uudelleen # sekunnin kuluttua.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"kuljettajan paikalla"</string>
     <string name="seat_front" msgid="836133281052793377">"edessä"</string>
     <string name="seat_rear" msgid="403133444964528577">"takana"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 58ec57bb..2f277ae8 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Déconnexion de <xliff:g id="USER_NAME">%s</xliff:g> en cours… Réessayez plus tard."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utilisateur actuellement inaccessible"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Impossible de lancer l\'utilisateur sécurisé sur l\'écran du passager"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Schéma incorrect"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"NIP incorrect"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Mot de passe incorrect"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Trop de tentatives erronées. Réessayez dans # seconde.}one{Trop de tentatives erronées. Réessayez dans # seconde.}other{Trop de tentatives erronées. Réessayez dans # secondes.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"conducteur"</string>
     <string name="seat_front" msgid="836133281052793377">"avant"</string>
     <string name="seat_rear" msgid="403133444964528577">"arrière"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 6e8efbf3..591c59b6 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> est en cours de déconnexion. Réessayez plus tard."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utilisateur actuellement indisponible"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Impossible de démarrer \"Utilisateur sécurisé\" sur l\'écran passager"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Schéma incorrect"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Code incorrect"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Mot de passe incorrect"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Trop de tentatives infructueuses. Réessayez dans # seconde.}one{Trop de tentatives infructueuses. Réessayez dans # seconde.}other{Trop de tentatives infructueuses. Réessayez dans # secondes.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"conducteur"</string>
     <string name="seat_front" msgid="836133281052793377">"avant"</string>
     <string name="seat_rear" msgid="403133444964528577">"arrière"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index ab670f77..77592874 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Estase pechando a sesión de <xliff:g id="USER_NAME">%s</xliff:g>. Volve tentalo máis tarde."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Usuario non dispoñible actualmente"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Non é posible iniciar o modo de usuario seguro na pantalla do pasaxeiro"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"O padrón é incorrecto"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"O PIN é incorrecto"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"O contrasinal é incorrecto"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Demasiados intentos incorrectos. Téntao de novo dentro de # segundo.}other{Demasiados intentos incorrectos. Téntao de novo dentro de # segundos.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"asento de conducir"</string>
     <string name="seat_front" msgid="836133281052793377">"diante"</string>
     <string name="seat_rear" msgid="403133444964528577">"detrás"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index fccbc2f4..dc1257a5 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> સાઇન આઉટ થઈ રહ્યાં છે. થોડા સમય પછી ફરી પ્રયાસ કરો."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"વપરાશકર્તા હાલમાં ઉપલબ્ધ નથી"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"મુસાફરના ડિસ્પ્લે પર સુરક્ષિત વપરાશકર્તા માટે શરૂઆત કરી શકતા નથી"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ખોટી પૅટર્ન"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"ખોટો પિન"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"ખોટો પાસવર્ડ"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{ઘણા બધા અયોગ્ય પ્રયાસો. # સેકન્ડમાં ફરી પ્રયાસ કરો.}one{ઘણા બધા અયોગ્ય પ્રયાસો. # સેકન્ડમાં ફરી પ્રયાસ કરો.}other{ઘણા બધા અયોગ્ય પ્રયાસો. # સેકન્ડમાં ફરી પ્રયાસ કરો.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ડ્રાઇવર"</string>
     <string name="seat_front" msgid="836133281052793377">"આગળ"</string>
     <string name="seat_rear" msgid="403133444964528577">"પાછળ"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 07c7edf6..8cd5fb6e 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> को साइन आउट किया जा रहा है. कुछ देर बाद कोशिश करें."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"फ़िलहाल, उपयोगकर्ता की प्रोफ़ाइल उपलब्ध नहीं है"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"पैसेंजर की डिसप्ले पर, उपयोगकर्ता की सुरक्षित प्रोफ़ाइल को चालू नहीं किया जा सका"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"आपने गलत पैटर्न डाला है"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"आपने गलत पिन डाला है"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"आपने गलत पासवर्ड डाला है"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{कई बार गलत पिन का इस्तेमाल किया गया है. # सेकंड बाद फिर से कोशिश करें.}one{कई बार गलत पिन का इस्तेमाल किया गया है. # सेकंड बाद फिर से कोशिश करें.}other{कई बार गलत पिन का इस्तेमाल किया गया है. # सेकंड बाद फिर से कोशिश करें.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ड्राइवर वाली सीट"</string>
     <string name="seat_front" msgid="836133281052793377">"सामने वाली सीट"</string>
     <string name="seat_rear" msgid="403133444964528577">"पीछे वाली सीट"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 9de25bce..15c0c6bf 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> se odjavljuje. Pokušajte ponovo kasnije."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Korisnik trenutačno nije dostupan"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nije moguće pokrenuti profil sigurnog korisnika na zaslonu putnika"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Pogrešan uzorak"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Pogrešan PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Pogrešna zaporka"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Previše netočnih pokušaja. Pokušajte ponovno za # s.}one{Previše netočnih pokušaja. Pokušajte ponovno za # s.}few{Previše netočnih pokušaja. Pokušajte ponovno za # s.}other{Previše netočnih pokušaja. Pokušajte ponovno za # s.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vozač"</string>
     <string name="seat_front" msgid="836133281052793377">"prednja"</string>
     <string name="seat_rear" msgid="403133444964528577">"stražnja"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 2da2ec07..0b70d881 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> kijelentkeztetése folyamatban van. Próbálja újra később."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"A felhasználó jelenleg nem áll rendelkezésre"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nem sikerült elindítani a biztonságos felhasználói munkamenetet az utaskijelzőn"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Helytelen minta"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Helytelen PIN-kód"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Helytelen jelszó"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Túl sok helytelen próbálkozás. Próbálja újra # másodperc múlva.}other{Túl sok helytelen próbálkozás. Próbálja újra # másodperc múlva.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"sofőr"</string>
     <string name="seat_front" msgid="836133281052793377">"elöl"</string>
     <string name="seat_rear" msgid="403133444964528577">"hátul"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 06d53e67..555a249a 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> օգտատերը դուրս է գրվում հաշվից։ Փորձեք ավելի ուշ։"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Օգտատերն այս պահին անհասանելի է"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Հնարավոր չէ օգտատիրոջ անվտանգ պրոֆիլ ակտիվացնել ուղևորի էկրանին"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Նախշը սխալ է"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN կոդը սխալ է"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Գաղտնաբառը սխալ է"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Չափից շատ սխալ փորձեր։ Նորից փորձեք # վայրկյանից։}one{Չափից շատ սխալ փորձեր։ Նորից փորձեք # վայրկյանից։}other{Չափից շատ սխալ փորձեր։ Նորից փորձեք # վայրկյանից։}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"վարորդի"</string>
     <string name="seat_front" msgid="836133281052793377">"առջևում նստած ուղևորի"</string>
     <string name="seat_rear" msgid="403133444964528577">"հետևում նստած ուղևորի"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index a3f6fbe7..f38982da 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> saat ini logout. Coba lagi nanti."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Pengguna tidak tersedia untuk saat ini"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Tidak dapat memulai pengguna aman di tampilan penumpang"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Pola salah"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN Salah"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Sandi salah"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Terlalu banyak upaya yang salah. Coba lagi setelah # detik.}other{Terlalu banyak upaya yang salah. Coba lagi setelah # detik.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"pengemudi"</string>
     <string name="seat_front" msgid="836133281052793377">"depan"</string>
     <string name="seat_rear" msgid="403133444964528577">"belakang"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 5220e8da..02736ceb 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Verið er að skrá „<xliff:g id="USER_NAME">%s</xliff:g>“ út. Reyndu aftur síðar."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Notandi ekki tiltækur sem stendur"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Ekki tókst að ræsa öruggan notanda á skjá farþega"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Rangt mynstur"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Rangt PIN-númer"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Rangt aðgangsorð"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Of margar misheppnaðar tilraunir. Reyndu aftur eftir # sekúndu.}one{Of margar misheppnaðar tilraunir. Reyndu aftur eftir # sekúndu.}other{Of margar misheppnaðar tilraunir. Reyndu aftur eftir # sekúndur.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ökumannssæti"</string>
     <string name="seat_front" msgid="836133281052793377">"framsæti"</string>
     <string name="seat_rear" msgid="403133444964528577">"í aftursæti"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 8cdb67cf..8be90c22 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> è in uscita. Riprova più tardi."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utente al momento non disponibile"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Impossibile avviare la protezione utente sul display del passeggero"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Sequenza errata"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN errato"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Password errata"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Troppi tentativi errati. Riprova tra # secondo.}other{Troppi tentativi errati. Riprova tra # secondi.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"conducente"</string>
     <string name="seat_front" msgid="836133281052793377">"anteriore"</string>
     <string name="seat_rear" msgid="403133444964528577">"posteriore"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 96024a6d..6fb5b11c 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -23,7 +23,7 @@
     <string name="fan_speed_off" msgid="3860115181014880798">"כבוי"</string>
     <string name="hvac_temperature_off" msgid="8370977023494579242">"כבויה"</string>
     <string name="voice_recognition_toast" msgid="7579725862117020349">"הזיהוי הקולי מתבצע עכשיו במכשיר Bluetooth מחובר"</string>
-    <string name="car_add_user" msgid="6182764665687382136">"להוספת פרופיל"</string>
+    <string name="car_add_user" msgid="6182764665687382136">"הוספת פרופיל"</string>
     <string name="end_session" msgid="2765206020435441421">"לסיום הסשן"</string>
     <string name="car_new_user" msgid="6766334721724989964">"פרופיל חדש"</string>
     <string name="user_add_profile_title" msgid="828371911076521952">"להוסיף פרופיל חדש?"</string>
@@ -92,7 +92,7 @@
     <string name="qc_footer_network_internet_settings" msgid="2480582764252681575">"הגדרות רשת ואינטרנט"</string>
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"הגדרות תצוגה"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"הגדרות צליל"</string>
-    <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"הגדרות פרופילים וחשבונות"</string>
+    <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"הגדרות של פרופילים וחשבונות"</string>
     <string name="qc_footer_debug_settings" msgid="7670720389183515925">"אפשרויות למפתחים"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"אין תמיכה בקו ביטול נעילה סיבובי. יש להשתמש במגע"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"המסך שלך נעול"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"מתבצעת יציאה מהמערכת של <xliff:g id="USER_NAME">%s</xliff:g>. צריך לנסות שוב מאוחר יותר."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"המשתמש לא זמין כרגע"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"אי אפשר להציג פרופיל של משתמש מאובטח במסך של הנוסע"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"קו ביטול הנעילה שגוי"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"קוד האימות שגוי"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"הסיסמה שגויה"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{יותר מדי ניסיונות נכשלו. אפשר לנסות שוב בעוד שנייה אחת.}one{יותר מדי ניסיונות נכשלו. אפשר לנסות שוב בעוד # שניות.}two{יותר מדי ניסיונות נכשלו. אפשר לנסות שוב בעוד # שניות.}other{יותר מדי ניסיונות נכשלו. אפשר לנסות שוב בעוד # שניות.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"נהג/ת"</string>
     <string name="seat_front" msgid="836133281052793377">"חלק קדמי"</string>
     <string name="seat_rear" msgid="403133444964528577">"חלק אחורי"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index a01bc0c4..d727defd 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -23,9 +23,9 @@
     <string name="fan_speed_off" msgid="3860115181014880798">"OFF"</string>
     <string name="hvac_temperature_off" msgid="8370977023494579242">"OFF"</string>
     <string name="voice_recognition_toast" msgid="7579725862117020349">"Bluetooth 接続デバイスで音声認識が処理されるようになりました"</string>
-    <string name="car_add_user" msgid="6182764665687382136">"プロファイルを追加"</string>
+    <string name="car_add_user" msgid="6182764665687382136">"プロフィールを追加"</string>
     <string name="end_session" msgid="2765206020435441421">"セッションを終了"</string>
-    <string name="car_new_user" msgid="6766334721724989964">"新しいプロファイル"</string>
+    <string name="car_new_user" msgid="6766334721724989964">"新しいプロフィール"</string>
     <string name="user_add_profile_title" msgid="828371911076521952">"新しいプロファイルの追加"</string>
     <string name="user_add_user_message_setup" msgid="1639791240776969175">"新しいプロファイルを追加すると、アカウント所有者がそのプロファイルをカスタマイズできます。"</string>
     <string name="user_add_user_message_update" msgid="4507063398890966360">"どのプロファイルでもアプリ アップデートをインストールでき、すべてのプロファイルに適用されます。"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> さんはログアウト中です。しばらくしてからもう一度お試しください。"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"現在、このユーザーは利用できません"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"助手席のディスプレイでセキュア ユーザーを開始できません"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"パターンが間違っています"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN が正しくありません"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"パスワードが正しくありません"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{誤った回数が多すぎます。# 秒後にもう一度お試しください。}other{誤った回数が多すぎます。# 秒後にもう一度お試しください。}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ドライバー"</string>
     <string name="seat_front" msgid="836133281052793377">"前"</string>
     <string name="seat_rear" msgid="403133444964528577">"後"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 2b9cc421..0ffca9fd 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> მიმდინარეობს გასვლა. სცადეთ მოგვიანებით."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"მომხმარებელი ამჟამად მიუწვდომელია"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"მგზავრის ეკრანზე უსაფრთხო მომხმარებლის გაშვება ვერ მოხერხდა"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ნიმუში არასწორია"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN-კოდი არასწორია"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"პაროლი არასწორია"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{ზედმეტად ბევრი არასწორი მცდელობა. ცადეთ ხელახლა # წამში.}other{ზედმეტად ბევრი არასწორი მცდელობა. ცადეთ ხელახლა # წამში.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"მძღოლი"</string>
     <string name="seat_front" msgid="836133281052793377">"წინა"</string>
     <string name="seat_rear" msgid="403133444964528577">"უკანა"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 3225c40e..f813b19c 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> аккаунттан шығып жатыр. Кейінірек қайталап көріңіз."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Пайдаланушы қазіргі уақытта қолжетімді емес."</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Жолаушы дисплейінде қауіпсіз пайдаланушыны іске қосу мүмкін емес."</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Өрнек қате."</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN коды қате."</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Құпия сөз қате."</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Тым көп рет қате тердіңіз. # секундтан кейін қайталап көріңіз.}other{Тым көп рет қате тердіңіз. # секундтан кейін қайталап көріңіз.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"жүргізуші"</string>
     <string name="seat_front" msgid="836133281052793377">"алдыңғы"</string>
     <string name="seat_rear" msgid="403133444964528577">"артқы"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 9e3b9cae..62c01a77 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> កំពុងចេញពីគណនី។ សូមព្យាយាមម្តងទៀតនៅពេលក្រោយ។"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"បច្ចុប្បន្ន មិនអាចជ្រើសរើសអ្នកប្រើប្រាស់នេះបានទេ"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"មិនអាចចាប់ផ្ដើមអ្នកប្រើប្រាស់ដែលមានការរក្សាសុវត្ថិភាពនៅលើផ្ទាំងអេក្រង់អ្នកដំណើរបានទេ"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"លំនាំមិនត្រឹមត្រូវទេ"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"កូដ PIN មិន​ត្រឹមត្រូវទេ"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"ពាក្យសម្ងាត់មិនត្រឹមត្រូវទេ"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{ការព្យាយាមមិនត្រឹមត្រូវច្រើនដងពេក។ ព្យាយាមម្តងទៀតក្នុងរយៈពេល # វិនាទីទៀត។}other{ការព្យាយាមមិនត្រឹមត្រូវច្រើនដងពេក។ ព្យាយាមម្តងទៀតក្នុងរយៈពេល # វិនាទីទៀត។}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"អ្នកបើកបរ"</string>
     <string name="seat_front" msgid="836133281052793377">"មុខ"</string>
     <string name="seat_rear" msgid="403133444964528577">"ក្រោយ"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 2df6c99b..962a8713 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -23,7 +23,7 @@
     <string name="fan_speed_off" msgid="3860115181014880798">"ಆಫ್"</string>
     <string name="hvac_temperature_off" msgid="8370977023494579242">"ಆಫ್"</string>
     <string name="voice_recognition_toast" msgid="7579725862117020349">"ಇದೀಗ ಕನೆಕ್ಟ್ ಆದ ಬ್ಲೂಟೂತ್ ಸಾಧನ ಧ್ವನಿ ಗುರುತಿಸುವಿಕೆ ನಿರ್ವಹಿಸಿದೆ"</string>
-    <string name="car_add_user" msgid="6182764665687382136">"ಒಂದು ಪ್ರೊಫೈಲ್ ಅನ್ನು ಸೇರಿಸಿ"</string>
+    <string name="car_add_user" msgid="6182764665687382136">"ಒಂದು ಪ್ರೊಫೈಲ್ ಸೇರಿಸಿ"</string>
     <string name="end_session" msgid="2765206020435441421">"ಸೆಷನ್ ಅಂತ್ಯಗೊಳಿಸಿ"</string>
     <string name="car_new_user" msgid="6766334721724989964">"ಹೊಸ ಪ್ರೊಫೈಲ್"</string>
     <string name="user_add_profile_title" msgid="828371911076521952">"ಹೊಸ ಪ್ರೊಫೈಲ್ ಅನ್ನು ಸೇರಿಸಬೇಕೇ?"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ಅವರ ಸೈನ್ ಔಟ್ ಆಗುತ್ತಿದ್ದಾರೆ. ನಂತರ ಪುನಃ ಪ್ರಯತ್ನಿಸಿ."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ಬಳಕೆದಾರರು ಪ್ರಸ್ತುತ ಲಭ್ಯವಿಲ್ಲ"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ಪ್ರಯಾಣಿಕರ ಡಿಸ್‌ಪ್ಲೇನಲ್ಲಿ ಸುರಕ್ಷಿತ ಬಳಕೆದಾರರನ್ನು ಪ್ರಾರಂಭಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ಪ್ಯಾಟರ್ನ್ ತಪ್ಪಾಗಿದೆ"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"ಪಿನ್‌ ತಪ್ಪಾಗಿದೆ"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"ಪಾಸ್‌ವರ್ಡ್ ತಪ್ಪಾಗಿದೆ"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{ಹಲವು ಬಾರಿ ತಪ್ಪಾಗಿ ಪ್ರಯತ್ನಿಸಲಾಗಿದೆ. # ಸೆಕೆಂಡ್‌ನಲ್ಲಿ ಪುನಃ ಪ್ರಯತ್ನಿಸಿ.}one{ಹಲವು ಬಾರಿ ತಪ್ಪಾಗಿ ಪ್ರಯತ್ನಿಸಲಾಗಿದೆ. # ಸೆಕೆಂಡ್‌ಗಳಲ್ಲಿ ಪುನಃ ಪ್ರಯತ್ನಿಸಿ.}other{ಹಲವು ಬಾರಿ ತಪ್ಪಾಗಿ ಪ್ರಯತ್ನಿಸಲಾಗಿದೆ. # ಸೆಕೆಂಡ್‌ಗಳಲ್ಲಿ ಪುನಃ ಪ್ರಯತ್ನಿಸಿ.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ಡ್ರೈವರ್"</string>
     <string name="seat_front" msgid="836133281052793377">"ಮುಂದೆ"</string>
     <string name="seat_rear" msgid="403133444964528577">"ಹಿಂಭಾಗ"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index a336088a..35f9dfd7 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>님이 로그아웃 중입니다. 나중에 다시 시도해 주세요."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"사용자를 현재 선택할 수 없음"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"승객 디스플레이에서 보안 사용자를 선택할 수 없음"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"잘못된 패턴"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"잘못된 PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"잘못된 비밀번호"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{잘못된 시도 횟수가 너무 많습니다. #초 후에 다시 시도하세요.}other{잘못된 시도 횟수가 너무 많습니다. #초 후에 다시 시도하세요.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"드라이버"</string>
     <string name="seat_front" msgid="836133281052793377">"전면"</string>
     <string name="seat_rear" msgid="403133444964528577">"후면"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 0fd4d833..c0eb9ee9 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> чыгып жатат. Кийинчерээк кайталап көрүңүз."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Учурда колдонуучу жеткиликсиз"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Жүргүнчүлөрдүн дисплейинде корголгон колдонуучуну ишке киргизүү мүмкүн эмес"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Графикалык ачкыч туура эмес"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN код туура эмес"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Сырсөз туура эмес"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Өтө көп жолу туура эмес аракет жасалды. # секунддан кийин кайталаңыз.}other{Өтө көп жолу туура эмес аракет жасалды. # секунддан кийин кайталаңыз.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"айдоочу"</string>
     <string name="seat_front" msgid="836133281052793377">"маңдайкы"</string>
     <string name="seat_rear" msgid="403133444964528577">"арткы"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 3f26a22b..34530c6e 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ກຳລັງຖືກໃຫ້ອອກຈາກລະບົບ. ກະລຸນາລອງໃໝ່ໃນພາຍຫຼັງ."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ຜູ້ໃຊ້ບໍ່ພ້ອມນຳໃຊ້ໃນຕອນນີ້"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ບໍ່ສາມາດເປີດນຳໃຊ້ຜູ້ໃຊ້ທີ່ປອດໄພຢູ່ຈໍສະແດງຜົນສຳລັບຜູ້ໂດຍສານໄດ້"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ຮູບແບບບໍ່ຖືກຕ້ອງ"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN ບໍ່ຖືກຕ້ອງ"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"ລະຫັດຜ່ານບໍ່ຖືກຕ້ອງ"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{ພະຍາຍາມບໍ່ສຳເລັດຫຼາຍເທື່ອເກີນໄປ. ກະລຸນາລອງໃໝ່ໃນອີກ # ວິນາທີ.}other{ພະຍາຍາມບໍ່ສຳເລັດຫຼາຍເທື່ອເກີນໄປ. ກະລຸນາລອງໃໝ່ໃນອີກ # ວິນາທີ.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ຄົນຂັບລົດ"</string>
     <string name="seat_front" msgid="836133281052793377">"ໜ້າ"</string>
     <string name="seat_rear" msgid="403133444964528577">"ທາງຫຼັງ"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 24abbbb0..edfc1f92 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> atsijungė. Vėliau bandykite dar kartą."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Naudotojas šiuo metu nepasiekiamas"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nepavyko pasiekti saugaus naudotojo keleivio ekrane"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Netinkamas atrakinimo piešinys"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Netinkamas PIN kodas"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Netinkamas slaptažodis"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Per daug klaidingų bandymų. Bandykite dar kartą po # sekundės.}one{Per daug klaidingų bandymų. Bandykite dar kartą po # sekundės.}few{Per daug klaidingų bandymų. Bandykite dar kartą po # sekundžių.}many{Per daug klaidingų bandymų. Bandykite dar kartą po # sekundės.}other{Per daug klaidingų bandymų. Bandykite dar kartą po # sekundžių.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vairuotojas"</string>
     <string name="seat_front" msgid="836133281052793377">"priekis"</string>
     <string name="seat_rear" msgid="403133444964528577">"galas"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 68bb24c0..ce6dbeb2 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Notiek lietotāja <xliff:g id="USER_NAME">%s</xliff:g> izrakstīšana. Vēlāk mēģiniet vēlreiz."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Lietotājs pašlaik nav pieejams"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Neizdodas izvēlēties drošu lietotāju pasažiera displejā."</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Nepareiza kombinācija"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Nepareizs PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Nepareiza parole"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Pārāk daudz nepareizu mēģinājumu. Mēģiniet vēlreiz pēc # sekundes.}zero{Pārāk daudz nepareizu mēģinājumu. Mēģiniet vēlreiz pēc # sekundēm.}one{Pārāk daudz nepareizu mēģinājumu. Mēģiniet vēlreiz pēc # sekundes.}other{Pārāk daudz nepareizu mēģinājumu. Mēģiniet vēlreiz pēc # sekundēm.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vadītāja sēdeklī"</string>
     <string name="seat_front" msgid="836133281052793377">"priekšējā sēdeklī"</string>
     <string name="seat_rear" msgid="403133444964528577">"aizmugurējā sēdeklī"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index d66d45b6..3b35ead5 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> се одјавува. Обидете се повторно подоцна."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Корисникот е недостапен во моментов"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Не може да се вклучи безбеден корисник на екранот на патниците"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Погрешна шема"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Погрешен PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Погрешна лозинка"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Премногу неточни обиди. Обидете се повторно по # секунда.}one{Премногу неточни обиди. Обидете се повторно по # секунда.}other{Премногу неточни обиди. Обидете се повторно по # секунди.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"возачкото"</string>
     <string name="seat_front" msgid="836133281052793377">"предното"</string>
     <string name="seat_rear" msgid="403133444964528577">"задното"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 86defd06..6382526f 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> സൈൻ ഔട്ട് ചെയ്‌തു. പിന്നീട് വീണ്ടും ശ്രമിക്കുക."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ഉപയോക്താവ് നിലവിൽ ലഭ്യമല്ല"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"പാസഞ്ചർ ഡിസ്‌പ്ലേയിൽ സുരക്ഷിത ഉപയോക്താവിനെ തിരഞ്ഞെടുക്കാനാകുന്നില്ല"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"പാറ്റേൺ തെറ്റാണ്"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"പിൻ തെറ്റാണ്"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"പാസ്‌വേഡ് തെറ്റാണ്"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{നിരവധി തെറ്റായ ശ്രമങ്ങൾ. # സെക്കൻഡിനുള്ളിൽ വീണ്ടും ശ്രമിക്കുക.}other{നിരവധി തെറ്റായ ശ്രമങ്ങൾ. # സെക്കൻഡിനുള്ളിൽ വീണ്ടും ശ്രമിക്കുക.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ഡ്രൈവർ"</string>
     <string name="seat_front" msgid="836133281052793377">"മുൻവശം"</string>
     <string name="seat_rear" msgid="403133444964528577">"പിൻഭാഗം"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index c7b37123..447e9e1b 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>-г гаргаж байна. Дараа дахин оролдоно уу."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Хэрэглэгч одоогоор боломжгүй"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Зорчигчийн дэлгэц дээр аюулгүй хэрэглэгчийг эхлүүлэх боломжгүй"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Хээ буруу байна"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"ПИН буруу байна"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Нууц үг буруу байна"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Хэт олон удаа буруу оролдлоо. # секундийн дараа дахин оролдоно уу.}other{Хэт олон удаа буруу оролдлоо. # секундийн дараа дахин оролдоно уу.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"жолооч"</string>
     <string name="seat_front" msgid="836133281052793377">"урд тал"</string>
     <string name="seat_rear" msgid="403133444964528577">"ар тал"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 863d0ea2..70c12300 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> यांना साइन आउट केले जात आहे. नंतर पुन्हा प्रयत्न करा."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"सध्या वापरकर्ता उपलब्ध नाही"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"प्रवासी डिस्प्लेवर सुरक्षित वापरकर्ता सुरू करता आला नाही"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"चुकीचा पॅटर्न"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"चुकीचा पिन"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"चुकीचा पासवर्ड"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{खूप जास्त चुकीचे प्रयत्न. # सेकंदाने पुन्हा प्रयत्न करा.}other{खूप जास्त चुकीचे प्रयत्न. # सेकंदांनी पुन्हा प्रयत्न करा.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ड्रायव्हर"</string>
     <string name="seat_front" msgid="836133281052793377">"समोरचा"</string>
     <string name="seat_rear" msgid="403133444964528577">"मागचा डबा"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index cf2bf135..06d76a2f 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> sedang dilog keluar. Cuba lagi nanti."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Pengguna tidak tersedia pada masa ini"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Tidak dapat memulakan pengguna pada paparan penumpang secara selamat"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Corak salah"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN salah"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Kata laluan salah"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Terlalu banyak percubaan yang salah. Cuba lagi selepas # saat.}other{Terlalu banyak percubaan yang salah. Cuba lagi selepas # saat.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"pemandu"</string>
     <string name="seat_front" msgid="836133281052793377">"hadapan"</string>
     <string name="seat_rear" msgid="403133444964528577">"belakang"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index f3605501..a219fa05 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ထွက်နေသည်။ နောက်မှ ထပ်စမ်းကြည့်ပါ။"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"အသုံးပြုသူကို လောလောဆယ် မရနိုင်ပါ"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ခရီးသည် ဖန်သားပြင်တွင် လုံခြုံသော အသုံးပြုသူကို စတင်၍မရပါ"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ပုံစံ မှားနေသည်"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"ပင်နံပါတ် မှားနေသည်"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"စကားဝှက် မှားနေသည်"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{မမှန်သည့် ကြိုးပမ်းမှုအကြိမ်ရေ များလွန်းသည်။ # စက္ကန့်အကြာတွင် ထပ်စမ်းကြည့်ပါ။}other{မမှန်သည့် ကြိုးပမ်းမှုအကြိမ်ရေ များလွန်းသည်။ # စက္ကန့်အကြာတွင် ထပ်စမ်းကြည့်ပါ။}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ယာဉ်မောင်းသူ"</string>
     <string name="seat_front" msgid="836133281052793377">"အရှေ့"</string>
     <string name="seat_rear" msgid="403133444964528577">"နောက်ဘက်"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index df1eb4dd..0d255b34 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> logges av. Prøv på nytt senere."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Brukeren er ikke tilgjengelig"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Kan ikke starte sikker bruker i passasjervisningen"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Feil mønster"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Feil PIN-kode"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Feil passord"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{For mange forsøk med feil. Prøv igjen om # sekund.}other{For mange forsøk med feil. Prøv igjen om # sekunder.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"for sjåføren"</string>
     <string name="seat_front" msgid="836133281052793377">"foran"</string>
     <string name="seat_rear" msgid="403133444964528577">"bak"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 06029088..e222e0c9 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -26,7 +26,7 @@
     <string name="car_add_user" msgid="6182764665687382136">"कुनै प्रोफाइल थप्नुहोस्"</string>
     <string name="end_session" msgid="2765206020435441421">"सत्र अन्त्य गर्नुहोस्"</string>
     <string name="car_new_user" msgid="6766334721724989964">"नयाँ प्रोफाइल"</string>
-    <string name="user_add_profile_title" msgid="828371911076521952">"नयाँ प्रोफाइल थप्ने हो?"</string>
+    <string name="user_add_profile_title" msgid="828371911076521952">"नयाँ प्रोफाइल हाल्ने हो?"</string>
     <string name="user_add_user_message_setup" msgid="1639791240776969175">"तपाईंले नयाँ प्रोफाइल हालेपछि खातावाला उक्त प्रोफाइल कस्टमाइज गर्न सक्नुहुन्छ।"</string>
     <string name="user_add_user_message_update" msgid="4507063398890966360">"जुनसुकै प्रोफाइलबाट एपको अपडेट इन्स्टल गर्न मिल्छ र अपडेट गरिएको एप सबै प्रोफाइलमा उपलब्ध हुन्छ।"</string>
     <string name="profile_limit_reached_title" msgid="7891779218496729653">"योभन्दा बढी प्रोफाइल थप्न मिल्दैन"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> को प्रोफाइल साइन आउट गरिँदै छ। पछि फेरि प्रयास गर्नुहोस्।"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"यी प्रयोगकर्ता हाल उपलब्ध हुनुहुन्न"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"यात्रुको जानकारी देखाइने डिस्प्लेमा \"सुरक्षित प्रयोगकर्ता\" सुरु गर्न सकिएन"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"गलत प्याटर्न"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"गलत PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"गलत पासवर्ड"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{अत्यन्तै धेरै पटक गलत तरिकाले अनलक गर्ने प्रयास गरियो। # सेकेन्डपछि फेरि प्रयास गर्नुहोस्।}other{अत्यन्तै धेरै पटक गलत तरिकाले अनलक गर्ने प्रयास गरियो। # सेकेन्डपछि फेरि प्रयास गर्नुहोस्।}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"चालकको सिट"</string>
     <string name="seat_front" msgid="836133281052793377">"अगाडिको सिट"</string>
     <string name="seat_rear" msgid="403133444964528577">"पछाडिको सिट"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index fa1ba5c1..a93f406c 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> wordt uitgelogd. Probeer het later opnieuw."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Gebruiker op dit moment niet beschikbaar"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Kan beveiligde gebruiker niet starten op scherm van passagier"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Onjuist patroon"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Onjuiste pincode"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Onjuist wachtwoord"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Te veel onjuiste pogingen. Probeer het over # seconde opnieuw.}other{Te veel onjuiste pogingen. Probeer het over # seconden opnieuw.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"bestuurder"</string>
     <string name="seat_front" msgid="836133281052793377">"voor"</string>
     <string name="seat_rear" msgid="403133444964528577">"achter"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 8e6c56a6..85137dd9 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>ଙ୍କୁ ସାଇନ ଆଉଟ କରାଯାଉଛି। ପରେ ପୁଣି ଚେଷ୍ଟା କରନ୍ତୁ।"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ୟୁଜର ବର୍ତ୍ତମାନ ଅନୁପଲବ୍ଧ"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ପାସେଞ୍ଜର ଡିସପ୍ଲେରେ ସୁରକ୍ଷିତ ୟୁଜର ଆରମ୍ଭ କରିବାକୁ ଅସମର୍ଥ"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ଭୁଲ ପାଟର୍ନ"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"ଭୁଲ PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"ଭୁଲ ପାସୱାର୍ଡ"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{ଅନେକଗୁଡ଼ିଏ ଭୁଲ ପ୍ରଚେଷ୍ଟା। # ସେକେଣ୍ଡ ପରେ ପୁଣି ଚେଷ୍ଟା କରନ୍ତୁ।}other{ଅନେକଗୁଡ଼ିଏ ଭୁଲ ପ୍ରଚେଷ୍ଟା। # ସେକେଣ୍ଡ ପରେ ପୁଣି ଚେଷ୍ଟା କରନ୍ତୁ।}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ଡ୍ରାଇଭର"</string>
     <string name="seat_front" msgid="836133281052793377">"ସାମ୍ନା"</string>
     <string name="seat_rear" msgid="403133444964528577">"ପଛ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 32280eb3..042c6a0c 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ਨੂੰ ਸਾਈਨ-ਆਊਟ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ। ਬਾਅਦ ਵਿੱਚ ਦੁਬਾਰਾ ਕੋਸ਼ਿਸ਼ ਕਰੋ।"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ਫ਼ਿਲਹਾਲ ਵਰਤੋਂਕਾਰ ਉਪਲਬਧ ਨਹੀਂ"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ਯਾਤਰੀ ਡਿਸਪਲੇ \'ਤੇ ਸੁਰੱਖਿਅਤ ਵਰਤੋਂਕਾਰ ਨੂੰ ਸ਼ੁਰੂ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਿਆ"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ਗਲਤ ਪੈਟਰਨ"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"ਗਲਤ ਪਿੰਨ"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"ਗਲਤ ਪਾਸਵਰਡ"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{ਬਹੁਤ ਸਾਰੀਆਂ ਗਲਤ ਕੋਸ਼ਿਸ਼ਾਂ। # ਸਕਿੰਟ ਵਿੱਚ ਦੁਬਾਰਾ ਕੋਸ਼ਿਸ਼ ਕਰੋ।}one{ਬਹੁਤ ਸਾਰੀਆਂ ਗਲਤ ਕੋਸ਼ਿਸ਼ਾਂ। # ਸਕਿੰਟ ਵਿੱਚ ਦੁਬਾਰਾ ਕੋਸ਼ਿਸ਼ ਕਰੋ।}other{ਬਹੁਤ ਸਾਰੀਆਂ ਗਲਤ ਕੋਸ਼ਿਸ਼ਾਂ। # ਸਕਿੰਟਾਂ ਵਿੱਚ ਦੁਬਾਰਾ ਕੋਸ਼ਿਸ਼ ਕਰੋ।}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ਡਰਾਈਵਰ"</string>
     <string name="seat_front" msgid="836133281052793377">"ਅਗਲਾ"</string>
     <string name="seat_rear" msgid="403133444964528577">"ਪਿਛਲਾ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 7a374d66..694d3421 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -88,7 +88,7 @@
     <string name="drive_mode_modes_sport" msgid="7664603138389270601">"Sport"</string>
     <string name="qc_drive_mode_active_subtitle" msgid="3667965966971747414">"Aktywny"</string>
     <string name="qc_footer_settings" msgid="5471523941092316743">"Ustawienia"</string>
-    <string name="qc_footer_bluetooth_settings" msgid="2870204430643762847">"Ustawienia Bluetooth"</string>
+    <string name="qc_footer_bluetooth_settings" msgid="2870204430643762847">"Ustawienia Bluetootha"</string>
     <string name="qc_footer_network_internet_settings" msgid="2480582764252681575">"Ustawienia sieci i internetu"</string>
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Ustawienia wyświetlacza"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ustawienia dźwięku"</string>
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> wylogowuje się. Spróbuj później."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Profil użytkownika jest w tej chwili niedostępny"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nie udało się uruchomić bezpiecznego profilu użytkownika na ekranie pasażera"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Nieprawidłowy wzór"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Nieprawidłowy kod PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Nieprawidłowe hasło"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Zbyt wiele nieudanych prób. Spróbuj ponownie za # sekundę.}few{Zbyt wiele nieudanych prób. Spróbuj ponownie za # sekundy.}many{Zbyt wiele nieudanych prób. Spróbuj ponownie za # sekund.}other{Zbyt wiele nieudanych prób. Spróbuj ponownie za # sekundy.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"kierowcy"</string>
     <string name="seat_front" msgid="836133281052793377">"przednim"</string>
     <string name="seat_rear" msgid="403133444964528577">"tylnym"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index b32c64bd..b513fd7f 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"A sessão de <xliff:g id="USER_NAME">%s</xliff:g> está a ser terminada. Tente mais tarde."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utilizador atualmente indisponível"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Não é possível iniciar o utilizador seguro no ecrã do passageiro"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Padrão incorreto"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN incorreto"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Palavra-passe incorreta"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Demasiadas tentativas incorretas. Tente novamente dentro de # segundo.}other{Demasiadas tentativas incorretas. Tente novamente dentro de # segundos.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"condutor"</string>
     <string name="seat_front" msgid="836133281052793377">"frente"</string>
     <string name="seat_rear" msgid="403133444964528577">"traseira"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 007c82fa..d3d244d0 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> está saindo. Tente novamente mais tarde."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Usuário indisponível no momento"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Não é possível acessar perfis de usuário protegidos na tela do passageiro"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Padrão incorreto"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN incorreto"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Senha incorreta"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Muitas tentativas incorretas. Tente outra vez em # segundo.}one{Muitas tentativas incorretas. Tente outra vez em # segundo.}other{Muitas tentativas incorretas. Tente outra vez em # segundos.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"do motorista"</string>
     <string name="seat_front" msgid="836133281052793377">"dianteiro"</string>
     <string name="seat_rear" msgid="403133444964528577">"traseiro"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 520a03c5..05218f16 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> se deconectează. Încearcă din nou mai târziu."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utilizator indisponibil momentan"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nu se poate porni utilizatorul securizat pe ecranul pentru pasageri"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Model greșit"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Cod PIN greșit"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Parolă greșită"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Prea multe încercări incorecte. Reîncearcă peste # secundă.}few{Prea multe încercări incorecte. Reîncearcă peste # secunde.}other{Prea multe încercări incorecte. Reîncearcă peste # de secunde.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"locul șoferului"</string>
     <string name="seat_front" msgid="836133281052793377">"locul din față"</string>
     <string name="seat_rear" msgid="403133444964528577">"locul din spate"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 775bab49..6619b425 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Сейчас выходит пользователь <xliff:g id="USER_NAME">%s</xliff:g>. Повторите попытку позже."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Пользователь сейчас недоступен"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Не удается выбрать защищенного пользователя на экране пассажира."</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Неверный графический ключ."</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Неверный PIN-код."</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Неверный пароль."</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Вы ввели неверный PIN-код слишком много раз. Повторите попытку через # секунду.}one{Вы ввели неверный PIN-код слишком много раз. Повторите попытку через # секунду.}few{Вы ввели неверный PIN-код слишком много раз. Повторите попытку через # секунды.}many{Вы ввели неверный PIN-код слишком много раз. Повторите попытку через # секунд.}other{Вы ввели неверный PIN-код слишком много раз. Повторите попытку через # секунды.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"на водительском сиденье"</string>
     <string name="seat_front" msgid="836133281052793377">"на переднем сиденье"</string>
     <string name="seat_rear" msgid="403133444964528577">"на заднем сиденье"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 153bae16..aa394f10 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> වරනය වෙමින් පවතී. පසුව නැවත උත්සාහ කරන්න."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"පරිශීලක දැනට නොමැත"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"මගී සංදර්ශකය මත සුරක්ෂිත පරිශීලකයා ආරම්භ කළ නොහැකි වේ"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"වැරදි රටාවකි"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN එක වැරදියි"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"වැරදි මුරපදයකි"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{වැරදි උත්සාහ කිරීම් ගණන වැඩියි. තත්පර #කින් නැවත උත්සාහ කරන්න.}one{වැරදි උත්සාහ කිරීම් ගණන වැඩියි. තත්පර #කින් නැවත උත්සාහ කරන්න.}other{වැරදි උත්සාහ කිරීම් ගණන වැඩියි. තත්පර #කින් නැවත උත්සාහ කරන්න.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"රියදුරු"</string>
     <string name="seat_front" msgid="836133281052793377">"ඉදිරිපස"</string>
     <string name="seat_rear" msgid="403133444964528577">"පසුපස"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 5da4c824..1f56c1f7 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> sa odhlasuje. Skúste to znova neskôr."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Používateľ momentálne nie je k dispozícii"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Na obrazovke pasažiera sa nepodarilo spustiť bezpečného používateľa"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Nesprávny vzor"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Nesprávny kód PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Nesprávne heslo"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Príliš veľa chybných pokusov. Skúste to znova o # sekundu.}few{Príliš veľa chybných pokusov. Skúste to znova o # sekundy.}many{Príliš veľa chybných pokusov. Skúste to znova o # sekundy.}other{Príliš veľa chybných pokusov. Skúste to znova o # sekúnd.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vodič"</string>
     <string name="seat_front" msgid="836133281052793377">"predná časť"</string>
     <string name="seat_rear" msgid="403133444964528577">"zadná časť"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 8d8ff6d8..cc42b201 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Poteka odjava uporabnika <xliff:g id="USER_NAME">%s</xliff:g>. Poskusite znova pozneje."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Uporabnik trenutno ni na voljo"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Prikaza varnega uporabnika na zaslonu sopotnika ni mogoče začeti"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Napačen vzorec"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Napačna koda PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Napačno geslo"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Preveč napačnih poskusov. Poskusite znova čez # sekundo.}one{Preveč napačnih poskusov. Poskusite znova čez # sekundo.}two{Preveč napačnih poskusov. Poskusite znova čez # sekundi.}few{Preveč napačnih poskusov. Poskusite znova čez # sekunde.}other{Preveč napačnih poskusov. Poskusite znova čez # sekund.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"voznikov sedež"</string>
     <string name="seat_front" msgid="836133281052793377">"sprednji sedež"</string>
     <string name="seat_rear" msgid="403133444964528577">"zadnji sedež"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 48491464..64b8d3f8 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> po del. Provo përsëri më vonë."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Përdoruesi nuk disponohet aktualisht"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Përdoruesi i sigurt nuk mund të niset në ekranin e pasagjerit"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Motiv i gabuar"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Kod PIN i gabuar"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Fjalëkalim i gabuar"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Shumë përpjekje të pasakta. Provo sërish pas # sekonde.}other{Shumë përpjekje të pasakta. Provo sërish pas # sekondash.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"drejtuesi"</string>
     <string name="seat_front" msgid="836133281052793377">"ana e përparme"</string>
     <string name="seat_rear" msgid="403133444964528577">"ana e pasme"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 0527bd3c..a85595a3 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> се одјављује. Пробајте поново касније."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Корисник тренутно није доступан"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Није могуће покренути безбедног корисника на екрану путника"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Погрешан шаблон"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Погрешан PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Погрешна лозинка"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Превише нетачних покушаја. Пробајте поново за # секунду.}one{Превише нетачних покушаја. Пробајте поново за # секунду.}few{Превише нетачних покушаја. Пробајте поново за # секунде.}other{Превише нетачних покушаја. Пробајте поново за # секунди.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"возач"</string>
     <string name="seat_front" msgid="836133281052793377">"предње"</string>
     <string name="seat_rear" msgid="403133444964528577">"задње"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 13aeff04..20ff69e1 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> loggas ut. Försök igen senare."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Användaren är inte tillgänglig just nu"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Det går inte att starta den säkra användaren på passagerarskärmen"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Fel mönster"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Fel pinkod"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Fel lösenord"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{För många felaktiga försök. Försök igen om # sekund.}other{För många felaktiga försök. Försök igen om # sekunder.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"förarsätet"</string>
     <string name="seat_front" msgid="836133281052793377">"framsätet"</string>
     <string name="seat_rear" msgid="403133444964528577">"baksätet"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 1dc8b93e..6c36e57f 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> anaondolewa katika akaunti. Jaribu tena baadaye."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Mtumiaji hapatikani kwa sasa"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Imeshindwa kuanzisha hali ya mtumiaji salama kwenye skrini ya abiria"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Mchoro si sahihi"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN si sahihi"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Nenosiri si sahihi"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Umejaribu mara nyingi mno bila kufaulu. Jaribu tena baada ya sekunde #.}other{Umejaribu mara nyingi mno bila kufaulu. Jaribu tena baada ya sekunde #.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"dereva"</string>
     <string name="seat_front" msgid="836133281052793377">"mbele"</string>
     <string name="seat_rear" msgid="403133444964528577">"nyuma"</string>
diff --git a/res/values-sw600dp/dimens.xml b/res/values-sw600dp/dimens.xml
new file mode 100644
index 00000000..77da6695
--- /dev/null
+++ b/res/values-sw600dp/dimens.xml
@@ -0,0 +1,20 @@
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
+  ~ limitations under the License
+  -->
+<resources>
+    <!-- Width of the disabled microphone dialog -->
+    <dimen name="large_dialog_width">1056dp</dimen>
+</resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index a5e4e23a..756f4967 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> வெளியேறுகிறார். பிறகு மீண்டும் முயலவும்."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"தற்சமயம் பயனர் இல்லை"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"பயணியின் திரையில் பயனரைப் பாதுகாத்தலைத் தொடங்க முடியவில்லை"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"தவறான பேட்டர்ன்"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"தவறான பின்"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"தவறான கடவுச்சொல்"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{பல தவறான முயற்சிகள். # வினாடியில் மீண்டும் முயலவும்.}other{பல தவறான முயற்சிகள். # வினாடிகளில் மீண்டும் முயலவும்.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ஓட்டுநர்"</string>
     <string name="seat_front" msgid="836133281052793377">"முன்புறம்"</string>
     <string name="seat_rear" msgid="403133444964528577">"பின்புறம்"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 22508185..eac7891e 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> సైన్ అవుట్ చేయబడుతున్నారు. తర్వాత మళ్లీ ట్రై చేయండి."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"యూజర్ ప్రస్తుతం అందుబాటులో లేరు"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ప్యాసింజర్ డిస్‌ప్లేలో సురక్షిత యూజర్‌ను ప్రారంభించడం సాధ్యం కాలేదు"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"ఆకృతిని తప్పుగా ఎంటర్ చేశారు"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PINను తప్పుగా ఎంటర్ చేశారు"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"పాస్‌వర్డ్‌ను తప్పుగా ఎంటర్ చేశారు"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{చాలా సార్లు తప్పుగా ప్రయత్నించారు. # సెకనులో మళ్లీ ట్రై చేయండి.}other{చాలా సార్లు తప్పుగా ప్రయత్నించారు. # సెకన్లలో మళ్లీ ట్రై చేయండి.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"డ్రైవర్"</string>
     <string name="seat_front" msgid="836133281052793377">"ముందువైపు"</string>
     <string name="seat_rear" msgid="403133444964528577">"వెనుక భాగం"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 7aa21101..0e1ddb04 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> กำลังออกจากระบบ ลองอีกครั้งในภายหลัง"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ผู้ใช้ไม่พร้อมใช้งานในขณะนี้"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"เปิดใช้งานผู้ใช้ที่ปลอดภัยบนจอแสดงผลสำหรับผู้โดยสารไม่ได้"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"รูปแบบไม่ถูกต้อง"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN ไม่ถูกต้อง"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"รหัสผ่านไม่ถูกต้อง"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{ลองผิดหลายครั้งมากเกินไป ลองใหม่ในอีก # วินาที}other{ลองผิดหลายครั้งมากเกินไป ลองใหม่ในอีก # วินาที}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"คนขับ"</string>
     <string name="seat_front" msgid="836133281052793377">"ด้านหน้า"</string>
     <string name="seat_rear" msgid="403133444964528577">"ด้านหลัง"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 3c74e0da..1f8fd945 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Sina-sign out si <xliff:g id="USER_NAME">%s</xliff:g>. Subukan ulit sa ibang pagkakataon."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Kasalukuyang hindi available ang user"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Hindi masimulan ang secure na user sa screen ng pasahero"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Maling pattern"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Maling PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Maling password"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Masyadong maraming maling pagsubok. Subukan ulit pagkalipas ng # segundo.}one{Masyadong maraming maling pagsubok. Subukan ulit pagkalipas ng # segundo.}other{Masyadong maraming maling pagsubok. Subukan ulit pagkalipas ng # na segundo.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"harap"</string>
     <string name="seat_rear" msgid="403133444964528577">"likod"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 81011d08..2700333d 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> oturumu kapatılıyor. Daha sonra tekrar deneyin."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Kullanıcı şu anda kullanılamıyor"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Yolcu ekranında güvenli kullanıcı başlatılamadı"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Yanlış desen"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Yanlış PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Yanlış şifre"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Çok fazla sayıda yanlış deneme yapıldı. # saniye içinde tekrar deneyin.}other{Çok fazla sayıda yanlış deneme yapıldı. # saniye içinde tekrar deneyin.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"sürücü"</string>
     <string name="seat_front" msgid="836133281052793377">"ön"</string>
     <string name="seat_rear" msgid="403133444964528577">"arka"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 7163c960..6fc72a84 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Користувач <xliff:g id="USER_NAME">%s</xliff:g> виходить з облікового запису. Спробуйте пізніше."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Профіль користувача зараз недоступний"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Неможливо запустити захищений профіль користувача на дисплеї пасажира"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Неправильний ключ"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Неправильний PIN-код"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Неправильний пароль"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Забагато невдалих спроб. Повторіть спробу через # секунду.}one{Забагато невдалих спроб. Повторіть спробу через # секунду.}few{Забагато невдалих спроб. Повторіть спробу через # секунди.}many{Забагато невдалих спроб. Повторіть спробу через # секунд.}other{Забагато невдалих спроб. Повторіть спробу через # секунди.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"водій"</string>
     <string name="seat_front" msgid="836133281052793377">"спереду"</string>
     <string name="seat_rear" msgid="403133444964528577">"ззаду"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 567784ee..cb2ded37 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> سائن آؤٹ ہو رہا ہے۔ بعد میں دوبارہ کوشش کریں۔"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"صارف فی الحال دستیاب نہیں ہے"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"مسافر ڈسپلے پر صارف کی محفوظ پروفائل شروع کرنے سے قاصر ہے"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"غلط پیٹرن"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"غلط PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"غلط پاس ورڈ"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{کافی زیادہ غلط کوششیں کی گئیں۔ ‫# سیکنڈ میں دوبارہ کوشش کریں۔}other{کافی زیادہ غلط کوششیں کی گئیں۔ ‫# سیکنڈ میں دوبارہ کوشش کریں۔}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ڈرائیور"</string>
     <string name="seat_front" msgid="836133281052793377">"فرنٹ"</string>
     <string name="seat_rear" msgid="403133444964528577">"پیچھے"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index e45aee9c..de0b5890 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> hisobidan chiqadi. Keyinroq qayta urining."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Foydalanuvchi ishlamaydi"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Yoʻlovchi ekranida xavfsiz foydalanuvchini ishga tushirish imkonsiz"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Grafik kalit xato"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN kod xato"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Parol xato"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Koʻp marta xato urinildi. # soniyadan keyin qaytadan urining.}other{Koʻp marta xato urinildi. # soniyadan keyin qayta urining.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"haydovchi"</string>
     <string name="seat_front" msgid="836133281052793377">"old"</string>
     <string name="seat_rear" msgid="403133444964528577">"orqa"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 2d5004a6..61dfdcca 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> đang đăng xuất. Hãy thử lại sau."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Hiện không có người dùng này"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Không thể khởi động chế độ người dùng bảo mật trên màn hình của hành khách"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Sai hình mở khoá"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Sai mã PIN"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Sai mật khẩu"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Nhập sai quá nhiều lần. Hãy thử lại sau # giây.}other{Nhập sai quá nhiều lần. Hãy thử lại sau # giây.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"tài xế"</string>
     <string name="seat_front" msgid="836133281052793377">"trước"</string>
     <string name="seat_rear" msgid="403133444964528577">"sau"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 61d8f8af..96db2780 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>正在退出账号。请稍后重试。"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"目前无法启动用户"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"无法在乘客显示屏上启动安全用户"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"解锁图案错误"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN 码错误"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"密码错误"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{错误的尝试次数过多。请在 # 秒后重试。}other{错误的尝试次数过多。请在 # 秒后重试。}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"驾驶员"</string>
     <string name="seat_front" msgid="836133281052793377">"前排"</string>
     <string name="seat_rear" msgid="403133444964528577">"后排"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 53e86bcb..7967974f 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"正在將 <xliff:g id="USER_NAME">%s</xliff:g> 登出。請稍後再試。"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"目前無法連接使用者"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"無法開始在乘客顯示屏中鎖定使用者"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"圖案錯誤"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN 錯誤"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"密碼錯誤"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{錯誤嘗試次數過多。請在 # 秒後再試一次。}other{錯誤嘗試次數過多。請在 # 秒後再試一次。}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"司機座位"</string>
     <string name="seat_front" msgid="836133281052793377">"前排座位"</string>
     <string name="seat_rear" msgid="403133444964528577">"車尾座位"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index f758c1d8..8d7d5668 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"正在將<xliff:g id="USER_NAME">%s</xliff:g>登出，請稍後再試。"</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"目前無法啟動使用者"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"無法在乘客螢幕上啟動安全使用者"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"解鎖圖案錯誤"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"PIN 碼錯誤"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"密碼錯誤"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{錯誤次數過多，請於 # 秒後再試一次。}other{錯誤次數過多，請於 # 秒後再試一次。}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"駕駛座"</string>
     <string name="seat_front" msgid="836133281052793377">"前方座位"</string>
     <string name="seat_rear" msgid="403133444964528577">"後方座位"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 1ec83f28..ab5fc6e8 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -117,6 +117,10 @@
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"U-<xliff:g id="USER_NAME">%s</xliff:g> ukhishiwe. Zama futhi ngemuva kwesikhathi."</string>
     <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Umsebenzisi akatholakali okwamanje"</string>
     <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Ayikwazi ukuqala umsebenzisi ovikelekile esibonisini somgibeli"</string>
+    <string name="passenger_keyguard_wrong_pattern" msgid="2581060250152895646">"Iphethini engalungile"</string>
+    <string name="passenger_keyguard_wrong_pin" msgid="8061593500590667531">"Iphinikhodi engalungile"</string>
+    <string name="passenger_keyguard_wrong_password" msgid="3742711889441714581">"Iphasiwedi engalungile"</string>
+    <string name="passenger_keyguard_too_many_failed_attempts" msgid="2948335020152945468">"{count,plural, =1{Kunemizamo eminingi kakhulu engalungile. Zama futhi ngomzuzwana ongu-#.}one{Kunemizamo eminingi kakhulu engalungile. Zama futhi emizuzwaneni engu-#.}other{Kunemizamo eminingi kakhulu engalungile. Zama futhi emizuzwaneni engu-#.}}"</string>
     <string name="seat_driver" msgid="4502591979520445677">"umshayeli"</string>
     <string name="seat_front" msgid="836133281052793377">"phambili"</string>
     <string name="seat_rear" msgid="403133444964528577">"ingemuva"</string>
diff --git a/res/values/attrs.xml b/res/values/attrs.xml
index 6b657684..9894f054 100644
--- a/res/values/attrs.xml
+++ b/res/values/attrs.xml
@@ -245,4 +245,10 @@
             <enum name="right" value="2"/>
         </attr>
     </declare-styleable>
+
+    <declare-styleable name="DisplayAreaView">
+        <attr name="displayAreaFeatureId" format="integer" />
+        <attr name="launchTaskDisplayAreaFeatureId" format="integer" />
+        <attr name="cornerRadius" format="integer" />
+    </declare-styleable>
 </resources>
diff --git a/res/values/config.xml b/res/values/config.xml
index 09c0983e..624fac0a 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -119,6 +119,7 @@
         <item>@string/config_notificationPanelViewMediator</item>
         <item>com.android.systemui.car.hvac.HvacPanelOverlayViewMediator</item>
         <item>com.android.systemui.car.keyguard.CarKeyguardOverlayViewMediator</item>
+        <item>com.android.systemui.car.keyguard.passenger.PassengerKeyguardOverlayViewMediator</item>
         <item>com.android.systemui.car.systemdialogs.SystemDialogsViewMediator</item>
         <item>com.android.systemui.car.userswitcher.FullscreenUserSwitcherViewMediator</item>
         <item>com.android.systemui.car.userswitcher.UserSwitchTransitionViewMediator</item>
@@ -262,4 +263,17 @@
         <item>com.android.car.settings</item>
         <item>com.android.car.carlauncher</item>
     </string-array>
+
+    <!--
+       The devices that certain debug features should be shown on.
+       Emulators are included by default.
+   -->
+    <string-array name="config_debug_support_devices">
+    </string-array>
+    <!--
+        The devices that certain debug features should be shown on, but the builds on real vehicles
+        should be excluded.
+    -->
+    <string-array name="config_debug_support_devices_exclude_car">
+    </string-array>
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 8e06e8a0..368ecd8f 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -483,4 +483,8 @@
     <dimen name="data_subscription_pop_up_horizontal_margin">15dp</dimen>
     <dimen name="data_subscription_pop_up_horizontal_offset">92dp</dimen>
     <dimen name="data_subscription_pop_up_vertical_offset">6dp</dimen>
+
+    <!-- Dimensions for passenger keyguard -->
+    <dimen name="passenger_keyguard_lockpattern_width">350dp</dimen>
+    <dimen name="passenger_keyguard_lockpattern_height">350dp</dimen>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 2dfa2254..eb9129ef 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -232,6 +232,21 @@
     <!-- User Picker: snack bar message when clicking unavailable secure user -->
     <string name="unavailable_secure_user_message">Unable to start secure user on passenger display</string>
 
+    <!-- Passenger Keyguard -->
+    <!-- Passenger keyguard error message when the user-entered pattern doesn't match what is stored -->
+    <string name="passenger_keyguard_wrong_pattern">Wrong pattern</string>
+    <!-- Passenger keyguard error message when the user-entered PIN doesn't match what is stored -->
+    <string name="passenger_keyguard_wrong_pin">Wrong PIN</string>
+    <!-- Passenger keyguard error message when the user-entered password doesn't match what is stored -->
+    <string name="passenger_keyguard_wrong_password">Wrong password</string>
+    <!-- Message shown after too many incorrect attempts to unlock passenger keyguard -->
+    <string name="passenger_keyguard_too_many_failed_attempts">
+        {count, plural,
+        =1    {Too many incorrect attempts. Try again in # second.}
+        other {Too many incorrect attempts. Try again in # seconds.}
+        }
+    </string>
+
     <!-- User Picker: seat string -->
     <string name="seat_driver">driver</string>
     <string name="seat_front">front</string>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index c68ad24f..54f73f59 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -233,7 +233,6 @@
         <item name="android:maxLines">2</item>
     </style>
 
-
     <!-- Biometrics -->
     <style name="PinPadKey" parent="TextAppearance.Car.Headline.Medium">
         <item name="android:gravity">center</item>
@@ -242,4 +241,21 @@
         <item name="android:tint">@*android:color/car_body3</item>
         <item name="android:clickable">true</item>
     </style>
+
+    <!-- Passenger Keyguard -->
+    <style name="PassengerLockPattern">
+        <item name="*android:regularColor">@*android:color/car_body1</item>
+        <item name="*android:successColor">@*android:color/car_blue_500</item>
+        <item name="*android:errorColor">?android:attr/colorError</item>
+    </style>
+
+    <style name="PassengerPinPadKey">
+        <item name="android:gravity">center</item>
+        <item name="android:textStyle">normal</item>
+        <item name="android:textSize">@*android:dimen/car_body1_size</item>
+        <item name="android:textColor">@*android:color/car_body3</item>
+        <item name="android:tint">@*android:color/car_body3</item>
+        <item name="android:clickable">true</item>
+        <item name="android:background">?android:attr/selectableItemBackground</item>
+    </style>
 </resources>
diff --git a/res/values/themes.xml b/res/values/themes.xml
index 3538cc06..6bb57e19 100644
--- a/res/values/themes.xml
+++ b/res/values/themes.xml
@@ -35,5 +35,11 @@
     <style name="Theme.NoTitleBar.NoSplash" parent="@android:style/Theme.NoTitleBar">
         <item name="android:windowSplashScreenAnimatedIcon">@android:color/transparent</item>
         <item name="android:windowSplashScreenAnimationDuration">0</item>
+        <!--
+            A translucent window is required to take a screenshot of the blocked app to create
+            a blurred effect. Translucency is disabled after creating the blurred surface in the
+            ActivityBlockingActivity.
+        -->
+        <item name="android:windowIsTranslucent">true</item>
     </style>
 </resources>
diff --git a/src/com/android/systemui/CarSystemUIInitializer.java b/src/com/android/systemui/CarSystemUIInitializer.java
index 98f80f43..d6125fc2 100644
--- a/src/com/android/systemui/CarSystemUIInitializer.java
+++ b/src/com/android/systemui/CarSystemUIInitializer.java
@@ -16,14 +16,16 @@
 
 package com.android.systemui;
 
+import static com.android.systemui.car.Flags.daviewBasedWindowing;
+
 import android.content.Context;
 import android.os.Process;
 import android.os.UserHandle;
 
 import com.android.systemui.dagger.GlobalRootComponent;
 import com.android.systemui.dagger.SysUIComponent;
-import com.android.systemui.dagger.WMComponent;
 import com.android.systemui.wmshell.CarWMComponent;
+import com.android.wm.shell.dagger.WMComponent;
 
 import java.util.Optional;
 
@@ -56,6 +58,9 @@ public class CarSystemUIInitializer extends SystemUIInitializer {
         if (Process.myUserHandle().isSystem()) {
             carWm.getCarSystemUIProxy();
             carWm.getRemoteCarTaskViewTransitions();
+            if (daviewBasedWindowing()) {
+                carWm.getDaViewTransitions();
+            }
         }
     }
 }
diff --git a/src/com/android/systemui/CarSystemUIModule.java b/src/com/android/systemui/CarSystemUIModule.java
index 87739912..b087775a 100644
--- a/src/com/android/systemui/CarSystemUIModule.java
+++ b/src/com/android/systemui/CarSystemUIModule.java
@@ -66,9 +66,9 @@ import com.android.systemui.statusbar.NotificationLockscreenUserManager;
 import com.android.systemui.statusbar.NotificationLockscreenUserManagerImpl;
 import com.android.systemui.statusbar.NotificationShadeWindowController;
 import com.android.systemui.statusbar.events.PrivacyDotViewController;
+import com.android.systemui.statusbar.notification.headsup.HeadsUpEmptyImplModule;
 import com.android.systemui.statusbar.policy.AospPolicyModule;
 import com.android.systemui.statusbar.policy.DeviceProvisionedController;
-import com.android.systemui.statusbar.policy.HeadsUpEmptyImplModule;
 import com.android.systemui.statusbar.policy.IndividualSensorPrivacyController;
 import com.android.systemui.statusbar.policy.IndividualSensorPrivacyControllerImpl;
 import com.android.systemui.statusbar.policy.SensorPrivacyController;
diff --git a/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java b/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
index cbb09d65..ac621422 100644
--- a/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
+++ b/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
@@ -27,6 +27,7 @@ import androidx.annotation.UiThread;
 import com.android.internal.statusbar.LetterboxDetails;
 import com.android.internal.view.AppearanceRegion;
 import com.android.systemui.R;
+import com.android.systemui.ScreenDecorationsThread;
 import com.android.systemui.car.systembar.SystemBarConfigs;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Application;
@@ -35,25 +36,26 @@ import com.android.systemui.plugins.statusbar.StatusBarStateController;
 import com.android.systemui.privacy.PrivacyType;
 import com.android.systemui.statusbar.CommandQueue;
 import com.android.systemui.statusbar.events.PrivacyDotViewController;
+import com.android.systemui.statusbar.events.PrivacyDotViewControllerImpl;
 import com.android.systemui.statusbar.events.SystemStatusAnimationScheduler;
 import com.android.systemui.statusbar.events.ViewState;
 import com.android.systemui.statusbar.phone.StatusBarContentInsetsProvider;
 import com.android.systemui.statusbar.policy.ConfigurationController;
 import com.android.systemui.util.concurrency.DelayableExecutor;
 
+import kotlinx.coroutines.CoroutineScope;
+
 import org.jetbrains.annotations.NotNull;
 
 import java.util.concurrent.Executor;
 
 import javax.inject.Inject;
 
-import kotlinx.coroutines.CoroutineScope;
-
 /**
  * Subclass of {@link PrivacyDotViewController}.
  */
 @SysUISingleton
-public class CarPrivacyChipViewController extends PrivacyDotViewController
+public class CarPrivacyChipViewController extends PrivacyDotViewControllerImpl
         implements CommandQueue.Callbacks {
     private static final String TAG = CarPrivacyChipViewController.class.getSimpleName();
     private boolean mAreaVisible;
@@ -70,13 +72,15 @@ public class CarPrivacyChipViewController extends PrivacyDotViewController
             @NotNull ConfigurationController configurationController,
             @NotNull StatusBarContentInsetsProvider contentInsetsProvider,
             @NotNull SystemStatusAnimationScheduler animationScheduler,
-            CommandQueue commandQueue) {
+            @NotNull @ScreenDecorationsThread DelayableExecutor uiExecutor,
+            CommandQueue commandQueue,
+            SystemBarConfigs systemBarConfigs) {
         super(mainExecutor, scope, stateController, configurationController, contentInsetsProvider,
-                animationScheduler, null);
+                animationScheduler, null, uiExecutor);
         commandQueue.addCallback(this);
         mAnimationHelper = new CarPrivacyChipAnimationHelper(context);
-        mBarType = SystemBarConfigs.BAR_PROVIDER_MAP[context.getResources().getInteger(
-                R.integer.config_privacyIndicatorLocation)].getType();
+        mBarType = systemBarConfigs.getInsetsFrameProvider(context.getResources().getInteger(
+                R.integer.config_privacyIndicatorLocation)).getType();
     }
 
     @Override
diff --git a/src/com/android/systemui/car/hvac/HvacButtonController.java b/src/com/android/systemui/car/hvac/HvacButtonController.java
new file mode 100644
index 00000000..f79660c1
--- /dev/null
+++ b/src/com/android/systemui/car/hvac/HvacButtonController.java
@@ -0,0 +1,60 @@
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
+package com.android.systemui.car.hvac;
+
+import android.view.View;
+
+import com.android.systemui.car.systembar.CarSystemBarButton;
+import com.android.systemui.car.systembar.CarSystemBarButtonController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A CarSystemBarElementController for handling notification button interactions.
+ */
+public class HvacButtonController extends CarSystemBarButtonController {
+
+    private final HvacPanelOverlayViewController mHvacPanelOverlayViewController;
+
+    @AssistedInject
+    public HvacButtonController(@Assisted CarSystemBarButton hvacButton,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            HvacPanelOverlayViewController hvacPanelOverlayViewController,
+            UserTracker userTracker) {
+        super(hvacButton, disableController, stateController, userTracker);
+
+        mHvacPanelOverlayViewController = hvacPanelOverlayViewController;
+        mHvacPanelOverlayViewController.registerViewStateListener(hvacButton);
+        hvacButton.setOnClickListener(this::onHvacClick);
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarButton,
+                    HvacButtonController> {
+    }
+
+    private void onHvacClick(View v) {
+        mHvacPanelOverlayViewController.toggle();
+    }
+}
diff --git a/src/com/android/systemui/car/hvac/HvacController.java b/src/com/android/systemui/car/hvac/HvacController.java
index c091dbdd..1c5902f3 100644
--- a/src/com/android/systemui/car/hvac/HvacController.java
+++ b/src/com/android/systemui/car/hvac/HvacController.java
@@ -142,27 +142,31 @@ public class HvacController implements HvacPropertySetter,
                 }
             };
 
-    @UiBackground
     @VisibleForTesting
     final CarServiceProvider.CarServiceOnConnectedListener mCarServiceLifecycleListener =
             car -> {
-                try {
-                    mExecutor.execute(() -> {
+                mExecutor.execute(() -> {
+                    try {
                         mIsConnectedToCar = true;
                         mCarPropertyManager =
                                 (CarPropertyManager) car.getCarManager(Car.PROPERTY_SERVICE);
                         CarPropertyConfig hvacPowerOnConfig =
                                 mCarPropertyManager.getCarPropertyConfig(HVAC_POWER_ON);
-                        mHvacPowerDependentProperties = hvacPowerOnConfig != null
-                                ? hvacPowerOnConfig.getConfigArray() : new ArrayList<>();
+                        if (hvacPowerOnConfig != null
+                                && hvacPowerOnConfig.getConfigArray() != null) {
+                            mHvacPowerDependentProperties = hvacPowerOnConfig.getConfigArray();
+                        } else {
+                            Log.w(TAG, "CarPropertyConfig#getConfigArray is null");
+                            mHvacPowerDependentProperties = new ArrayList<>();
+                        }
                         registerHvacPropertyEventListeners();
                         mViewsToInit.forEach(this::registerHvacViews);
                         mViewsToInit.clear();
-                    });
-                } catch (Exception e) {
-                    Log.e(TAG, "Failed to connect to HVAC", e);
-                    mIsConnectedToCar = false;
-                }
+                    } catch (Exception e) {
+                        Log.e(TAG, "Failed to connect to HVAC", e);
+                        mIsConnectedToCar = false;
+                    }
+                });
             };
 
     @Inject
@@ -171,9 +175,7 @@ public class HvacController implements HvacPropertySetter,
             @Main Resources resources,
             ConfigurationController configurationController) {
         mExecutor = executor;
-        if (!mIsConnectedToCar) {
-            carServiceProvider.addListener(mCarServiceLifecycleListener);
-        }
+        carServiceProvider.addListener(mCarServiceLifecycleListener);
         configurationController.addCallback(this);
     }
 
@@ -279,83 +281,86 @@ public class HvacController implements HvacPropertySetter,
     /**
      * Registers all {@link HvacView}s in the {@code rootView} and its descendents.
      */
-    @UiBackground
     public void registerHvacViews(View rootView) {
-        if (!mIsConnectedToCar) {
-            mExecutor.execute(() -> mViewsToInit.add(rootView));
-            return;
-        }
-
-        if (rootView instanceof HvacView) {
-            try {
-                HvacView hvacView = (HvacView) rootView;
-                @HvacProperty Integer propId = hvacView.getHvacPropertyToView();
-                @AreaId Integer targetAreaId = hvacView.getAreaId();
-
-                CarPropertyConfig carPropertyConfig =
-                        mCarPropertyManager.getCarPropertyConfig(propId);
-                if (carPropertyConfig == null) {
-                    throw new IllegalArgumentException(
-                            "Cannot register hvac view for property: "
-                            + VehiclePropertyIds.toString(propId)
-                            + " because property is not implemented.");
-                }
+        mExecutor.execute(() -> {
+            if (!mIsConnectedToCar) {
+                mViewsToInit.add(rootView);
+                return;
+            }
 
-                hvacView.setHvacPropertySetter(this);
-                hvacView.setConfigInfo(carPropertyConfig);
-                hvacView.setDisableViewIfPowerOff(mHvacPowerDependentProperties.contains(propId));
+            if (rootView instanceof HvacView) {
+                try {
+                    HvacView hvacView = (HvacView) rootView;
+                    @HvacProperty Integer propId = hvacView.getHvacPropertyToView();
+                    @AreaId Integer targetAreaId = hvacView.getAreaId();
+
+                    CarPropertyConfig carPropertyConfig =
+                            mCarPropertyManager.getCarPropertyConfig(propId);
+                    if (carPropertyConfig == null) {
+                        throw new IllegalArgumentException(
+                                "Cannot register hvac view for property: "
+                                + VehiclePropertyIds.toString(propId)
+                                + " because property is not implemented.");
+                    }
 
-                ArrayList<Integer> supportedAreaIds = getAreaIdsFromTargetAreaId(propId.intValue(),
-                        targetAreaId.intValue());
-                for (Integer areaId : supportedAreaIds) {
-                    addHvacViewToMap(propId.intValue(), areaId.intValue(), hvacView);
-                }
+                    hvacView.setHvacPropertySetter(this);
+                    hvacView.setConfigInfo(carPropertyConfig);
+                    hvacView.setDisableViewIfPowerOff(
+                            mHvacPowerDependentProperties.contains(propId));
 
-                if (mCarPropertyManager != null) {
-                    CarPropertyValue<Integer> hvacTemperatureDisplayUnitsValue =
-                            (CarPropertyValue<Integer>) getPropertyValueOrNull(
-                                    HVAC_TEMPERATURE_DISPLAY_UNITS, GLOBAL_AREA_ID);
+                    ArrayList<Integer> supportedAreaIds =
+                            getAreaIdsFromTargetAreaId(propId.intValue(), targetAreaId.intValue());
                     for (Integer areaId : supportedAreaIds) {
-                        CarPropertyValue initValueOrNull = getPropertyValueOrNull(propId, areaId);
-
-                        // Initialize the view with the initial value.
-                        if (initValueOrNull != null) {
-                            hvacView.onPropertyChanged(initValueOrNull);
-                        }
-                        if (hvacTemperatureDisplayUnitsValue != null) {
-                            boolean usesFahrenheit = hvacTemperatureDisplayUnitsValue.getValue()
-                                    == VehicleUnit.FAHRENHEIT;
-                            hvacView.onHvacTemperatureUnitChanged(usesFahrenheit);
-                        }
-
-                        if (carPropertyConfig.getAreaType() != VEHICLE_AREA_TYPE_SEAT) {
-                            continue;
-                        }
+                        addHvacViewToMap(propId.intValue(), areaId.intValue(), hvacView);
+                    }
 
-                        for (int propToGetOnInitId : HVAC_PROPERTIES_TO_GET_ON_INIT) {
-                            int[] propToGetOnInitSupportedAreaIds = getSupportedAreaIds(
-                                    propToGetOnInitId);
+                    if (mCarPropertyManager != null) {
+                        CarPropertyValue<Integer> hvacTemperatureDisplayUnitsValue =
+                                (CarPropertyValue<Integer>) getPropertyValueOrNull(
+                                        HVAC_TEMPERATURE_DISPLAY_UNITS, GLOBAL_AREA_ID);
+                        for (Integer areaId : supportedAreaIds) {
+                            CarPropertyValue initValueOrNull =
+                                    getPropertyValueOrNull(propId, areaId);
+
+                            // Initialize the view with the initial value.
+                            if (initValueOrNull != null) {
+                                hvacView.onPropertyChanged(initValueOrNull);
+                            }
+                            if (hvacTemperatureDisplayUnitsValue != null) {
+                                boolean usesFahrenheit = hvacTemperatureDisplayUnitsValue.getValue()
+                                        == VehicleUnit.FAHRENHEIT;
+                                hvacView.onHvacTemperatureUnitChanged(usesFahrenheit);
+                            }
 
-                            int areaIdToFind = areaId.intValue();
+                            if (carPropertyConfig.getAreaType() != VEHICLE_AREA_TYPE_SEAT) {
+                                continue;
+                            }
 
-                            for (int supportedAreaId : propToGetOnInitSupportedAreaIds) {
-                                if ((supportedAreaId & areaIdToFind) == areaIdToFind) {
-                                    CarPropertyValue propToGetOnInitValueOrNull =
-                                            getPropertyValueOrNull(propToGetOnInitId,
-                                                    supportedAreaId);
-                                    if (propToGetOnInitValueOrNull != null) {
-                                        hvacView.onPropertyChanged(propToGetOnInitValueOrNull);
+                            for (int propToGetOnInitId : HVAC_PROPERTIES_TO_GET_ON_INIT) {
+                                int[] propToGetOnInitSupportedAreaIds = getSupportedAreaIds(
+                                        propToGetOnInitId);
+
+                                int areaIdToFind = areaId.intValue();
+
+                                for (int supportedAreaId : propToGetOnInitSupportedAreaIds) {
+                                    if ((supportedAreaId & areaIdToFind) == areaIdToFind) {
+                                        CarPropertyValue propToGetOnInitValueOrNull =
+                                                getPropertyValueOrNull(propToGetOnInitId,
+                                                        supportedAreaId);
+                                        if (propToGetOnInitValueOrNull != null) {
+                                            hvacView.onPropertyChanged(propToGetOnInitValueOrNull);
+                                        }
+                                        break;
                                     }
-                                    break;
                                 }
                             }
                         }
                     }
+                } catch (IllegalArgumentException ex) {
+                    Log.e(TAG, "Can't register HVAC view", ex);
                 }
-            } catch (IllegalArgumentException ex) {
-                Log.e(TAG, "Can't register HVAC view", ex);
             }
-        }
+        });
 
         if (rootView instanceof ViewGroup) {
             ViewGroup viewGroup = (ViewGroup) rootView;
@@ -369,21 +374,23 @@ public class HvacController implements HvacPropertySetter,
      * Unregisters all {@link HvacView}s in the {@code rootView} and its descendents.
      */
     public void unregisterViews(View rootView) {
-        if (!mIsConnectedToCar) {
-            mViewsToInit.remove(rootView);
-            return;
-        }
-        if (rootView instanceof HvacView) {
-            HvacView hvacView = (HvacView) rootView;
-            @HvacProperty Integer propId = hvacView.getHvacPropertyToView();
-            @AreaId Integer targetAreaId = hvacView.getAreaId();
-
-            ArrayList<Integer> supportedAreaIds = getAreaIdsFromTargetAreaId(propId.intValue(),
-                    targetAreaId.intValue());
-            for (Integer areaId : supportedAreaIds) {
-                removeHvacViewFromMap(propId.intValue(), areaId.intValue(), hvacView);
+        mExecutor.execute(() -> {
+            if (!mIsConnectedToCar) {
+                mViewsToInit.remove(rootView);
+                return;
             }
-        }
+            if (rootView instanceof HvacView) {
+                HvacView hvacView = (HvacView) rootView;
+                @HvacProperty Integer propId = hvacView.getHvacPropertyToView();
+                @AreaId Integer targetAreaId = hvacView.getAreaId();
+
+                ArrayList<Integer> supportedAreaIds = getAreaIdsFromTargetAreaId(propId.intValue(),
+                        targetAreaId.intValue());
+                for (Integer areaId : supportedAreaIds) {
+                    removeHvacViewFromMap(propId.intValue(), areaId.intValue(), hvacView);
+                }
+            }
+        });
 
         if (rootView instanceof ViewGroup) {
             ViewGroup viewGroup = (ViewGroup) rootView;
diff --git a/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediator.java b/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediator.java
index 348d11d3..05ad303c 100644
--- a/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediator.java
+++ b/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediator.java
@@ -98,22 +98,6 @@ public class HvacPanelOverlayViewMediator implements OverlayViewMediator {
         mCarSystemBarController.registerBarTouchListener(RIGHT,
                 mHvacPanelOverlayViewController.getDragCloseTouchListener());
 
-        mCarSystemBarController.registerHvacPanelController(
-                new HvacPanelController() {
-                    @Override
-                    public void togglePanel() {
-                        mHvacPanelOverlayViewController.toggle();
-                    }
-
-                    @Override
-                    public boolean isHvacPanelOpen() {
-                        return mHvacPanelOverlayViewController.isPanelExpanded();
-                    }
-                });
-
-        mCarSystemBarController.registerHvacPanelOverlayViewController(
-                mHvacPanelOverlayViewController);
-
         mBroadcastDispatcher.registerReceiver(mBroadcastReceiver,
                 new IntentFilter(Intent.ACTION_CLOSE_SYSTEM_DIALOGS), /* executor= */ null,
                 mUserTracker.getUserHandle());
diff --git a/src/com/android/systemui/car/hvac/TemperatureControlView.java b/src/com/android/systemui/car/hvac/TemperatureControlView.java
index 0aa5bd5b..19d7c464 100644
--- a/src/com/android/systemui/car/hvac/TemperatureControlView.java
+++ b/src/com/android/systemui/car/hvac/TemperatureControlView.java
@@ -34,10 +34,13 @@ import androidx.annotation.VisibleForTesting;
 import androidx.core.content.ContextCompat;
 
 import com.android.systemui.R;
+import com.android.systemui.car.systembar.element.CarSystemBarElement;
+import com.android.systemui.car.systembar.element.CarSystemBarElementFlags;
+import com.android.systemui.car.systembar.element.CarSystemBarElementResolver;
 
 import java.util.List;
 
-public class TemperatureControlView extends LinearLayout implements HvacView {
+public class TemperatureControlView extends LinearLayout implements HvacView, CarSystemBarElement {
     protected static final int BUTTON_REPEAT_INTERVAL_MS = 500;
     protected TextView mTempTextView;
     protected View mIncreaseButton;
@@ -53,6 +56,11 @@ public class TemperatureControlView extends LinearLayout implements HvacView {
     private final int mAvailableTextColor;
     private final int mUnavailableTextColor;
 
+    private final Class<?> mElementControllerClassAttr;
+    private final int mSystemBarDisableFlags;
+    private final int mSystemBarDisable2Flags;
+    private final boolean mDisableForLockTaskModeLocked;
+
     private boolean mPowerOn = false;
     private boolean mDisableViewIfPowerOff = false;
     private boolean mTemperatureSetAvailable = false;
@@ -88,6 +96,18 @@ public class TemperatureControlView extends LinearLayout implements HvacView {
         mAvailableTextColor = ContextCompat.getColor(getContext(), R.color.system_bar_text_color);
         mUnavailableTextColor = ContextCompat.getColor(getContext(),
                 R.color.system_bar_text_unavailable_color);
+
+        mElementControllerClassAttr =
+                CarSystemBarElementResolver.getElementControllerClassFromAttributes(context, attrs);
+        mSystemBarDisableFlags =
+                CarSystemBarElementFlags.getStatusBarManagerDisableFlagsFromAttributes(context,
+                        attrs);
+        mSystemBarDisable2Flags =
+                CarSystemBarElementFlags.getStatusBarManagerDisable2FlagsFromAttributes(context,
+                        attrs);
+        mDisableForLockTaskModeLocked =
+                CarSystemBarElementFlags.getDisableForLockTaskModeLockedFromAttributes(context,
+                        attrs);
     }
 
     @Override
@@ -174,6 +194,29 @@ public class TemperatureControlView extends LinearLayout implements HvacView {
         mTempTextView.setOnClickListener(onClickListener);
     }
 
+    @Override
+    public Class<?> getElementControllerClass() {
+        if (mElementControllerClassAttr != null) {
+            return mElementControllerClassAttr;
+        }
+        return null;
+    }
+
+    @Override
+    public int getSystemBarDisableFlags() {
+        return mSystemBarDisableFlags;
+    }
+
+    @Override
+    public int getSystemBarDisable2Flags() {
+        return mSystemBarDisable2Flags;
+    }
+
+    @Override
+    public boolean disableForLockTaskModeLocked() {
+        return mDisableForLockTaskModeLocked;
+    }
+
     /**
      * Updates the temperature view logic on the UI thread.
      */
diff --git a/src/com/android/systemui/car/hvac/TemperatureControlViewController.java b/src/com/android/systemui/car/hvac/TemperatureControlViewController.java
new file mode 100644
index 00000000..ec16d076
--- /dev/null
+++ b/src/com/android/systemui/car/hvac/TemperatureControlViewController.java
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
+package com.android.systemui.car.hvac;
+
+import android.view.View;
+
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A CarSystemBarElementController for handling hvac button interactions.
+ */
+public class TemperatureControlViewController extends
+            CarSystemBarElementController<TemperatureControlView> {
+
+    private final HvacPanelOverlayViewController mHvacPanelOverlayViewController;
+    private final HvacController mHvacController;
+
+    @AssistedInject
+    public TemperatureControlViewController(@Assisted TemperatureControlView hvacButton,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            HvacPanelOverlayViewController hvacPanelOverlayViewController,
+            HvacController hvacController) {
+        super(hvacButton, disableController, stateController);
+
+        mHvacPanelOverlayViewController = hvacPanelOverlayViewController;
+        hvacButton.setTemperatureTextClickListener(this::onHvacClick);
+        mHvacController = hvacController;
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<TemperatureControlView,
+                    TemperatureControlViewController> {
+    }
+
+    @Override
+    protected void onViewAttached() {
+        super.onViewAttached();
+        mHvacController.registerHvacViews(mView);
+    }
+
+    @Override
+    protected void onViewDetached() {
+        super.onViewDetached();
+        mHvacController.unregisterViews(mView);
+    }
+
+    private void onHvacClick(View v) {
+        mHvacPanelOverlayViewController.toggle();
+    }
+}
diff --git a/src/com/android/systemui/car/input/DisplayInputSinkController.java b/src/com/android/systemui/car/input/DisplayInputSinkController.java
index 5b346d66..cb9a321b 100644
--- a/src/com/android/systemui/car/input/DisplayInputSinkController.java
+++ b/src/com/android/systemui/car/input/DisplayInputSinkController.java
@@ -100,6 +100,8 @@ public final class DisplayInputSinkController implements CoreStartable {
     private CarOccupantZoneManager mOccupantZoneManager;
     private CarPowerManager mCarPowerManager;
 
+    private final SparseArray<Toast> mDisplayInputLockToasts = new SparseArray<>();
+
     @VisibleForTesting
     final DisplayManager.DisplayListener mDisplayListener =
             new DisplayManager.DisplayListener() {
@@ -107,6 +109,7 @@ public final class DisplayInputSinkController implements CoreStartable {
         @MainThread
         public void onDisplayAdded(int displayId) {
             mayUpdatePassengerDisplayOnAdded(displayId);
+            fetchCurrentDisplayInputLockSetting();
             refreshDisplayInputSink(displayId, "onDisplayAdded");
         }
 
@@ -173,6 +176,10 @@ public final class DisplayInputSinkController implements CoreStartable {
 
     @Override
     public void start() {
+        if (!UserManager.isVisibleBackgroundUsersEnabled()) {
+            Slog.i(TAG, "Disable DisplayInputSinkController for non MUMD system");
+            return;
+        }
         if (UserHandle.myUserId() != UserHandle.USER_SYSTEM
                 && UserManager.isHeadlessSystemUserMode()) {
             Slog.i(TAG, "Disable DisplayInputSinkController for non system user "
@@ -199,6 +206,10 @@ public final class DisplayInputSinkController implements CoreStartable {
 
     // Assumes that all main displays for passengers are static.
     private void initPassengerDisplays() {
+        if (mOccupantZoneManager == null) {
+            Slog.w(TAG, "CarOccupantZoneManager isn't connected yet");
+            return;
+        }
         List<OccupantZoneInfo> allZones = mOccupantZoneManager.getAllOccupantZones();
         for (int i = allZones.size() - 1; i >= 0; --i) {
             OccupantZoneInfo zone = allZones.get(i);
@@ -241,13 +252,17 @@ public final class DisplayInputSinkController implements CoreStartable {
     // Start/stop display input locks from the current global setting.
     @VisibleForTesting
     void refreshDisplayInputLockSetting() {
+        fetchCurrentDisplayInputLockSetting();
+        for (int i = mPassengerDisplays.size() - 1; i >= 0; --i) {
+            decideDisplayInputSink(i);
+        }
+    }
+
+    private void fetchCurrentDisplayInputLockSetting() {
         String settingValue = getDisplayInputLockSettingValue();
         parseDisplayInputLockSettingValue(CarSettings.Global.DISPLAY_INPUT_LOCK, settingValue);
         if (DBG) {
-            Slog.d(TAG, "refreshDisplayInputLock: settingValue=" + settingValue);
-        }
-        for (int i = mPassengerDisplays.size() - 1; i >= 0; --i) {
-            decideDisplayInputSink(i);
+            Slog.d(TAG, "Display input lock: settingValue=" + settingValue);
         }
     }
 
@@ -351,9 +366,8 @@ public final class DisplayInputSinkController implements CoreStartable {
         };
         mDisplayInputSinks.put(displayId, new DisplayInputSink(display, callback));
         // Now that the display input lock is started, let's inform the user of it.
-        mHandler.post(() -> Toast.makeText(displayContext, R.string.display_input_lock_started_text,
-                Toast.LENGTH_SHORT).show());
-
+        showDisplayInputLockToast(displayId, displayContext,
+                R.string.display_input_lock_started_text);
     }
 
     private void mayStartDisplayInputMonitor(Display display) {
@@ -385,12 +399,43 @@ public final class DisplayInputSinkController implements CoreStartable {
             return;
         }
         Slog.i(TAG, "Stop input lock for display#" + displayId);
-        mHandler.post(() -> Toast.makeText(mContext.createDisplayContext(display),
-                R.string.display_input_lock_stopped_text, Toast.LENGTH_SHORT).show());
+        showDisplayInputLockToast(displayId, mContext.createDisplayContext(display),
+                R.string.display_input_lock_stopped_text);
         removeDisplayInputSink(displayId);
         mDisplayInputLockedDisplays.remove(displayId);
     }
 
+    /**
+     * Shows a toast message for display input lock events.
+     * <p>
+     * This method ensures that only one toast is displayed at a time for each display.
+     * If a toast is already showing for the given displayId, it will be canceled before
+     * the new toast is shown.
+     *
+     * @param displayId    The ID of the display for which to show the toast.
+     * @param context      The Context object associated with the display.
+     * @param messageResId The resource ID of the toast message to display.
+     */
+    private void showDisplayInputLockToast(int displayId, Context context, int messageResId) {
+        mHandler.post(() -> {
+            // Check if a Toast already exists for this displayId
+            int index = mDisplayInputLockToasts.indexOfKey(displayId);
+            if (index >= 0) {
+                // If a Toast exists, cancel it before showing a new one
+                Toast previousToast = mDisplayInputLockToasts.valueAt(index);
+                Slog.d(TAG, "Cancel previous displayInput lock message");
+                previousToast.cancel();
+                mDisplayInputLockToasts.removeAt(index);
+            }
+
+            Toast newToast = Toast.makeText(context,
+                    messageResId,
+                    Toast.LENGTH_SHORT);
+            mDisplayInputLockToasts.put(displayId, newToast);
+            newToast.show();
+        });
+    }
+
     private void mayStopDisplayInputMonitor(int displayId) {
         if (!isDisplayInputMonitorStarted(displayId)) {
             if (DBG) Slog.d(TAG, "There is no input monitor started for display#" + displayId);
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java b/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java
index f54c79f6..252f9e52 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java
@@ -21,14 +21,20 @@ import android.content.Context;
 import com.android.keyguard.ConnectedDisplayKeyguardPresentation;
 import com.android.keyguard.KeyguardDisplayManager;
 import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.dagger.qualifiers.Application;
 import com.android.systemui.navigationbar.NavigationBarController;
 import com.android.systemui.settings.DisplayTracker;
+import com.android.systemui.shade.data.repository.ShadeDisplaysRepository;
 import com.android.systemui.statusbar.policy.KeyguardStateController;
 
 import dagger.Lazy;
 
 import java.util.concurrent.Executor;
 
+import javax.inject.Provider;
+
+import kotlinx.coroutines.CoroutineScope;
+
 /**
  * Implementation of the {@link KeyguardDisplayManager} that provides different display tracker
  * implementations depending on the system.
@@ -47,9 +53,12 @@ public class CarKeyguardDisplayManager extends KeyguardDisplayManager {
             KeyguardDisplayManager.DeviceStateHelper deviceStateHelper,
             KeyguardStateController keyguardStateController,
             ConnectedDisplayKeyguardPresentation.Factory
-                    connectedDisplayKeyguardPresentationFactory) {
+                    connectedDisplayKeyguardPresentationFactory,
+            Provider<ShadeDisplaysRepository> shadeDisplaysRepositoryProvider,
+            @Application CoroutineScope appScope) {
         super(context, navigationBarControllerLazy, displayTracker, mainExecutor, uiBgExecutor,
                 deviceStateHelper, keyguardStateController,
-                connectedDisplayKeyguardPresentationFactory);
+                connectedDisplayKeyguardPresentationFactory, shadeDisplaysRepositoryProvider,
+                appScope);
     }
 }
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardModule.java b/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
index ec597b82..01e0f543 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
@@ -38,11 +38,13 @@ import com.android.keyguard.mediator.ScreenOnCoordinator;
 import com.android.systemui.CoreStartable;
 import com.android.systemui.animation.ActivityTransitionAnimator;
 import com.android.systemui.broadcast.BroadcastDispatcher;
+import com.android.systemui.car.keyguard.passenger.PassengerKeyguardLoadingDialog;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.classifier.FalsingCollector;
 import com.android.systemui.classifier.FalsingModule;
 import com.android.systemui.communal.ui.viewmodel.CommunalTransitionViewModel;
 import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.dagger.qualifiers.Application;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.dagger.qualifiers.UiBackground;
 import com.android.systemui.dreams.DreamOverlayStateController;
@@ -58,6 +60,8 @@ import com.android.systemui.keyguard.WindowManagerOcclusionManager;
 import com.android.systemui.keyguard.dagger.KeyguardFaceAuthNotSupportedModule;
 import com.android.systemui.keyguard.data.repository.KeyguardRepositoryModule;
 import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor;
+import com.android.systemui.keyguard.domain.interactor.KeyguardTransitionBootInteractor;
+import com.android.systemui.keyguard.domain.interactor.StartKeyguardTransitionModule;
 import com.android.systemui.log.SessionTracker;
 import com.android.systemui.navigationbar.NavigationBarController;
 import com.android.systemui.navigationbar.NavigationModeController;
@@ -66,6 +70,7 @@ import com.android.systemui.settings.DisplayTracker;
 import com.android.systemui.settings.DisplayTrackerImpl;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.shade.ShadeController;
+import com.android.systemui.shade.data.repository.ShadeDisplaysRepository;
 import com.android.systemui.statusbar.NotificationShadeDepthController;
 import com.android.systemui.statusbar.NotificationShadeWindowController;
 import com.android.systemui.statusbar.SysuiStatusBarStateController;
@@ -91,9 +96,12 @@ import dagger.multibindings.ClassKey;
 import dagger.multibindings.IntoMap;
 
 import kotlinx.coroutines.CoroutineDispatcher;
+import kotlinx.coroutines.CoroutineScope;
 
 import java.util.concurrent.Executor;
 
+import javax.inject.Provider;
+
 /**
  * Dagger Module providing keyguard.
  */
@@ -106,6 +114,7 @@ import java.util.concurrent.Executor;
                 FalsingModule.class,
                 KeyguardFaceAuthNotSupportedModule.class,
                 KeyguardRepositoryModule.class,
+                StartKeyguardTransitionModule.class,
         })
 public interface CarKeyguardModule {
 
@@ -163,6 +172,7 @@ public interface CarKeyguardModule {
             Lazy<WindowManagerLockscreenVisibilityManager> wmLockscreenVisibilityManager,
             SelectedUserInteractor selectedUserInteractor,
             KeyguardInteractor keyguardInteractor,
+            KeyguardTransitionBootInteractor transitionBootInteractor,
             WindowManagerOcclusionManager wmOcclusionManager) {
         return new CarKeyguardViewMediator(
                 context,
@@ -213,6 +223,7 @@ public interface CarKeyguardModule {
                 wmLockscreenVisibilityManager,
                 selectedUserInteractor,
                 keyguardInteractor,
+                transitionBootInteractor,
                 wmOcclusionManager);
     }
 
@@ -234,13 +245,16 @@ public interface CarKeyguardModule {
             KeyguardDisplayManager.DeviceStateHelper deviceStateHelper,
             KeyguardStateController keyguardStateController,
             ConnectedDisplayKeyguardPresentation.Factory
-                    connectedDisplayKeyguardPresentationFactory) {
+                    connectedDisplayKeyguardPresentationFactory,
+            Provider<ShadeDisplaysRepository> shadeDisplaysRepositoryProvider,
+            @Application CoroutineScope appScope) {
         DisplayTracker finalDisplayTracker =
                 CarSystemUIUserUtil.isDriverMUMDSystemUI() ? displayTrackerImpl.get()
                         : defaultDisplayTracker;
         return new CarKeyguardDisplayManager(context, navigationBarControllerLazy,
                 finalDisplayTracker, mainExecutor, uiBgExecutor, deviceStateHelper,
-                keyguardStateController, connectedDisplayKeyguardPresentationFactory);
+                keyguardStateController, connectedDisplayKeyguardPresentationFactory,
+                shadeDisplaysRepositoryProvider, appScope);
     }
 
     /** Binds {@link KeyguardUpdateMonitor} as a {@link CoreStartable}. */
@@ -248,4 +262,10 @@ public interface CarKeyguardModule {
     @IntoMap
     @ClassKey(KeyguardUpdateMonitor.class)
     CoreStartable bindsKeyguardUpdateMonitor(KeyguardUpdateMonitor keyguardUpdateMonitor);
+
+    /** Binds {@link PassengerKeyguardLoadingDialog} as a {@link CoreStartable}. */
+    @Binds
+    @IntoMap
+    @ClassKey(PassengerKeyguardLoadingDialog.class)
+    CoreStartable bindsPassengerKeyguardLoadingDialog(PassengerKeyguardLoadingDialog dialog);
 }
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java b/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
index e17fbe27..d18a5810 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
@@ -53,11 +53,14 @@ import com.android.systemui.car.window.OverlayViewGlobalStateController;
 import com.android.systemui.car.window.SystemUIOverlayWindowController;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.keyguard.KeyguardWmStateRefactor;
 import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToGoneTransitionViewModel;
 import com.android.systemui.log.BouncerLogger;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.shade.ShadeExpansionStateManager;
 import com.android.systemui.shade.domain.interactor.ShadeLockscreenInteractor;
+import com.android.systemui.statusbar.domain.interactor.OccludedState;
+import com.android.systemui.statusbar.domain.interactor.StatusBarKeyguardViewManagerInteractor;
 import com.android.systemui.statusbar.phone.BiometricUnlockController;
 import com.android.systemui.statusbar.phone.CentralSurfaces;
 import com.android.systemui.statusbar.policy.KeyguardStateController;
@@ -65,6 +68,7 @@ import com.android.systemui.toast.SystemUIToast;
 import com.android.systemui.toast.ToastFactory;
 import com.android.systemui.user.domain.interactor.SelectedUserInteractor;
 import com.android.systemui.util.concurrency.DelayableExecutor;
+import com.android.systemui.util.kotlin.JavaAdapter;
 
 import dagger.Lazy;
 
@@ -144,6 +148,8 @@ public class CarKeyguardViewController extends OverlayViewController implements
     private ViewGroup mKeyguardContainer;
     private PrimaryBouncerToGoneTransitionViewModel mPrimaryBouncerToGoneTransitionViewModel;
     private final Optional<KeyguardSystemBarPresenter> mKeyguardSystemBarPresenter;
+    private final StatusBarKeyguardViewManagerInteractor mStatusBarKeyguardViewManagerInteractor;
+    private final JavaAdapter mJavaAdapter;
 
     @Inject
     public CarKeyguardViewController(
@@ -169,7 +175,9 @@ public class CarKeyguardViewController extends OverlayViewController implements
             BouncerLogger bouncerLogger,
             BouncerMessageInteractor bouncerMessageInteractor,
             SelectedUserInteractor selectedUserInteractor,
-            Optional<KeyguardSystemBarPresenter> keyguardSystemBarPresenter) {
+            Optional<KeyguardSystemBarPresenter> keyguardSystemBarPresenter,
+            StatusBarKeyguardViewManagerInteractor statusBarKeyguardViewManagerInteractor,
+            JavaAdapter javaAdapter) {
         super(R.id.keyguard_stub, overlayViewGlobalStateController);
 
         mContext = context;
@@ -197,6 +205,22 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mBouncerMessageInteractor = bouncerMessageInteractor;
         primaryBouncerCallbackInteractor.addBouncerExpansionCallback(mExpansionCallback);
         mKeyguardSystemBarPresenter = keyguardSystemBarPresenter;
+        mStatusBarKeyguardViewManagerInteractor = statusBarKeyguardViewManagerInteractor;
+        mJavaAdapter = javaAdapter;
+
+        if (KeyguardWmStateRefactor.isEnabled()) {
+            // Show the keyguard views whenever we've told WM that the lockscreen is visible.
+            mJavaAdapter.alwaysCollectFlow(
+                    mStatusBarKeyguardViewManagerInteractor.getKeyguardViewVisibility(),
+                    this::consumeShowStatusBarKeyguardView);
+            mJavaAdapter.alwaysCollectFlow(
+                    mStatusBarKeyguardViewManagerInteractor.getKeyguardViewOcclusionState(),
+                    this::consumeOcclusionState);
+        }
+    }
+
+    protected void consumeOcclusionState(OccludedState occludedState) {
+        setOccluded(occludedState.getOccluded(), false);
     }
 
     @Override
@@ -218,7 +242,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
                 mMessageAreaControllerFactory,
                 mBouncerMessageInteractor,
                 mBouncerLogger,
-                mSelectedUserInteractor);
+                mSelectedUserInteractor, null /* plugins */);
         mBiometricUnlockControllerLazy.get().setKeyguardViewController(this);
     }
 
@@ -295,6 +319,11 @@ public class CarKeyguardViewController extends OverlayViewController implements
 
     @Override
     public void hideAlternateBouncer(boolean forceUpdateScrim) {
+        hideAlternateBouncer(forceUpdateScrim, true);
+    }
+
+    @Override
+    public void hideAlternateBouncer(boolean forceUpdateScrim, boolean clearDismissAction) {
         // no-op
     }
 
@@ -453,7 +482,14 @@ public class CarKeyguardViewController extends OverlayViewController implements
             ShadeExpansionStateManager shadeExpansionStateManager,
             BiometricUnlockController biometricUnlockController,
             View notificationContainer) {
-        // no-op
+    }
+
+    private void consumeShowStatusBarKeyguardView(boolean show) {
+        if (show) {
+            show(/* options= */ null);
+        } else {
+            hide(/* startTime = */ 0, /* fadeoutDuration= */ 0);
+        }
     }
 
     /**
@@ -465,11 +501,19 @@ public class CarKeyguardViewController extends OverlayViewController implements
         getLayout().setVisibility(View.INVISIBLE);
     }
 
+    @Override
+    public void onWindowFocusableChanged(boolean focusable) {
+        super.onWindowFocusableChanged(focusable);
+        if (focusable && mBouncerView.getDelegate() != null) {
+            mBouncerView.getDelegate().resume();
+        }
+    }
+
     @Override
     public boolean setAllowRotaryFocus(boolean allowRotaryFocus) {
         boolean changed = super.setAllowRotaryFocus(allowRotaryFocus);
         if (changed && allowRotaryFocus && mBouncerView.getDelegate() != null) {
-            // Resume the view so it can regain focus
+            // Resume the view so it can gain rotary focus
             mBouncerView.getDelegate().resume();
         }
         return changed;
@@ -521,7 +565,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
     private void makeOverlayToast(int stringId) {
         Resources res = mContext.getResources();
 
-        SystemUIToast systemUIToast = mToastFactory.createToast(mContext,
+        SystemUIToast systemUIToast = mToastFactory.createToast(mContext, mContext,
                 res.getString(stringId), mContext.getPackageName(), UserHandle.myUserId(),
                 res.getConfiguration().orientation);
 
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java b/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
index 10279e03..2415c376 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
@@ -51,6 +51,7 @@ import com.android.systemui.keyguard.KeyguardViewMediator;
 import com.android.systemui.keyguard.WindowManagerLockscreenVisibilityManager;
 import com.android.systemui.keyguard.WindowManagerOcclusionManager;
 import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor;
+import com.android.systemui.keyguard.domain.interactor.KeyguardTransitionBootInteractor;
 import com.android.systemui.log.SessionTracker;
 import com.android.systemui.navigationbar.NavigationModeController;
 import com.android.systemui.process.ProcessWrapper;
@@ -144,6 +145,7 @@ public class CarKeyguardViewMediator extends KeyguardViewMediator {
             Lazy<WindowManagerLockscreenVisibilityManager> wmLockscreenVisibilityManager,
             SelectedUserInteractor selectedUserInteractor,
             KeyguardInteractor keyguardInteractor,
+            KeyguardTransitionBootInteractor transitionBootInteractor,
             WindowManagerOcclusionManager wmOcclusionManager) {
         super(context, uiEventLogger, sessionTracker,
                 userTracker, falsingCollector, lockPatternUtils, broadcastDispatcher,
@@ -170,6 +172,7 @@ public class CarKeyguardViewMediator extends KeyguardViewMediator {
                 wmLockscreenVisibilityManager,
                 selectedUserInteractor,
                 keyguardInteractor,
+                transitionBootInteractor,
                 wmOcclusionManager);
         mContext = context;
         mTrustManager = trustManager;
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewController.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewController.java
new file mode 100644
index 00000000..44e5c4ca
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewController.java
@@ -0,0 +1,203 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import android.app.trust.TrustManager;
+import android.car.Car;
+import android.car.SyncResultCallback;
+import android.car.user.CarUserManager;
+import android.car.user.UserStopRequest;
+import android.car.user.UserStopResponse;
+import android.os.Handler;
+import android.text.TextUtils;
+import android.util.Log;
+import android.view.View;
+import android.widget.Button;
+import android.widget.TextView;
+
+import androidx.annotation.CallSuper;
+
+import com.android.internal.widget.LockPatternChecker;
+import com.android.internal.widget.LockPatternUtils;
+import com.android.internal.widget.LockscreenCredential;
+import com.android.systemui.R;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.settings.UserTracker;
+import com.android.systemui.util.ViewController;
+
+/**
+ * Base ViewController for PassengerKeyguard credential views.
+ */
+public abstract class PassengerKeyguardCredentialViewController extends ViewController<View> {
+    private static final String TAG = PassengerKeyguardCredentialViewController.class.getName();
+    private final LockPatternUtils mLockPatternUtils;
+    private final UserTracker mUserTracker;
+    private final TrustManager mTrustManager;
+    private final Handler mMainHandler;
+    private final CarServiceProvider mCarServiceProvider;
+    private final PassengerKeyguardLockoutHelper mLockoutHelper;
+
+    private OnAuthSucceededCallback mCallback;
+    private LockscreenCredential mEnteredPassword;
+    private TextView mErrorMessageView;
+    private Button mCancelButton;
+
+    private CarUserManager mCarUserManager;
+    private final CarServiceProvider.CarServiceOnConnectedListener mCarConnectedListener =
+            new CarServiceProvider.CarServiceOnConnectedListener() {
+                @Override
+                public void onConnected(Car car) {
+                    mCarUserManager = car.getCarManager(CarUserManager.class);
+                }
+            };
+
+    protected PassengerKeyguardCredentialViewController(View view,
+            LockPatternUtils lockPatternUtils, UserTracker userTracker, TrustManager trustManager,
+            Handler mainHandler, CarServiceProvider carServiceProvider,
+            PassengerKeyguardLockoutHelper lockoutHelper) {
+        super(view);
+        mLockPatternUtils = lockPatternUtils;
+        mUserTracker = userTracker;
+        mTrustManager = trustManager;
+        mMainHandler = mainHandler;
+        mCarServiceProvider = carServiceProvider;
+        mLockoutHelper = lockoutHelper;
+    }
+
+    @CallSuper
+    @Override
+    protected void onInit() {
+        super.onInit();
+        mErrorMessageView = mView.findViewById(R.id.message);
+        mCancelButton = mView.findViewById(R.id.cancel_button);
+        if (mCancelButton != null) {
+            mCancelButton.setOnClickListener(v -> stopUser());
+        }
+    }
+
+    @Override
+    protected void onViewAttached() {
+        mCarServiceProvider.addListener(mCarConnectedListener);
+        mLockoutHelper.setCallback(new PassengerKeyguardLockoutHelper.Callback() {
+            @Override
+            public void setErrorText(String text) {
+                mMainHandler.post(() -> setErrorMessage(text));
+            }
+
+            @Override
+            public void refreshUI(boolean isLockedOut) {
+                mMainHandler.post(() -> onLockedOutChanged(isLockedOut));
+            }
+        });
+        mLockoutHelper.onUIShown();
+    }
+
+    @Override
+    protected void onViewDetached() {
+        mCarServiceProvider.removeListener(mCarConnectedListener);
+        mLockoutHelper.setCallback(null);
+        mCarUserManager = null;
+    }
+
+    protected abstract LockscreenCredential getCurrentCredential();
+
+    protected abstract void onLockedOutChanged(boolean isLockedOut);
+
+    protected final void verifyCredential(Runnable onFailureUiRunnable) {
+        mEnteredPassword = getCurrentCredential();
+        if (mEnteredPassword.isNone()) {
+            Log.e(TAG, "Expected to verify real credential but got none");
+            return;
+        }
+        LockPatternChecker.verifyCredential(mLockPatternUtils, mEnteredPassword,
+                mUserTracker.getUserId(), /* flags= */ 0,
+                (response, throttleTimeoutMs) -> {
+                    if (response.isMatched()) {
+                        mTrustManager.reportEnabledTrustAgentsChanged(mUserTracker.getUserId());
+                        if (mCallback != null) {
+                            mCallback.onAuthSucceeded();
+                        }
+                    } else {
+                        if (throttleTimeoutMs > 0) {
+                            mMainHandler.post(() -> mLockoutHelper.onCheckCompletedWithTimeout(
+                                    throttleTimeoutMs));
+                        } else {
+                            mMainHandler.post(onFailureUiRunnable);
+                        }
+                    }
+                });
+    }
+
+    protected final void setErrorMessage(String message) {
+        if (mErrorMessageView != null) {
+            mErrorMessageView.setText(message);
+        }
+    }
+
+    protected final void clearError() {
+        if (mErrorMessageView != null && !TextUtils.isEmpty(mErrorMessageView.getText())) {
+            mErrorMessageView.setText("");
+        }
+    }
+
+    /**
+     * Clear all credential data from memory. Subclasses should override and clear any necessary
+     * fields and then call super.
+     */
+    @CallSuper
+    protected void clearAllCredentials() {
+        if (mEnteredPassword != null) {
+            mEnteredPassword.zeroize();
+        }
+
+        System.gc();
+        System.runFinalization();
+        System.gc();
+    }
+
+    private void stopUser() {
+        if (mCarUserManager == null) {
+            return;
+        }
+
+        SyncResultCallback<UserStopResponse> userStopCallback = new SyncResultCallback<>();
+        mCarUserManager.stopUser(
+                new UserStopRequest.Builder(mUserTracker.getUserHandle()).withDelayedLocking(
+                        false).build(), getContext().getMainExecutor(), userStopCallback);
+    }
+
+    /**
+     * Notify the controller that the hosting overlay has been hidden. This is needed because the
+     * View may not always be detached on hide since the window is still present (just not visible).
+     */
+    public final void onOverlayHidden() {
+        mLockoutHelper.onUIHidden();
+        clearAllCredentials();
+    }
+
+    /**
+     * Set callback to be called when authentication has succeeded.
+     */
+    public final void setAuthSucceededCallback(OnAuthSucceededCallback callback) {
+        mCallback = callback;
+    }
+
+    public interface OnAuthSucceededCallback {
+        /** Called when passenger keyguard authentication has succeeded. */
+        void onAuthSucceeded();
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactory.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactory.java
new file mode 100644
index 00000000..ab074074
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerFactory.java
@@ -0,0 +1,95 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PASSWORD;
+import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PATTERN;
+import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PIN;
+
+import android.app.trust.TrustManager;
+import android.os.Handler;
+import android.view.LayoutInflater;
+import android.view.View;
+import android.view.ViewGroup;
+
+import com.android.internal.widget.LockPatternUtils;
+import com.android.systemui.R;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.settings.UserTracker;
+
+import javax.inject.Inject;
+
+/**
+ * Factory class to create credential ViewControllers based on the current user's lock type.
+ */
+@SysUISingleton
+public class PassengerKeyguardCredentialViewControllerFactory {
+    private final LayoutInflater mInflater;
+    private final LockPatternUtils mLockPatternUtils;
+    private final UserTracker mUserTracker;
+    private final TrustManager mTrustManager;
+    private final Handler mMainHandler;
+    private final CarServiceProvider mCarServiceProvider;
+    private final PassengerKeyguardLockoutHelper mLockoutHelper;
+
+    @Inject
+    public PassengerKeyguardCredentialViewControllerFactory(LayoutInflater inflater,
+            LockPatternUtils lockPatternUtils, UserTracker userTracker, TrustManager trustManager,
+            @Main Handler mainHandler, CarServiceProvider carServiceProvider,
+            PassengerKeyguardLockoutHelper lockoutHelper) {
+        mInflater = inflater;
+        mLockPatternUtils = lockPatternUtils;
+        mUserTracker = userTracker;
+        mTrustManager = trustManager;
+        mMainHandler = mainHandler;
+        mCarServiceProvider = carServiceProvider;
+        mLockoutHelper = lockoutHelper;
+    }
+
+    /**
+     * Inflate a pin, password, or pattern view (depending on the user's currently set credential)
+     * and attach the relevant controller. Note that this should only be called for users that have
+     * a credential set - otherwise it will throw an exception.
+     */
+    public PassengerKeyguardCredentialViewController create(ViewGroup root) {
+        @LockPatternUtils.CredentialType int credentialType =
+                mLockPatternUtils.getCredentialTypeForUser(mUserTracker.getUserId());
+        PassengerKeyguardCredentialViewController controller = null;
+        if (credentialType == CREDENTIAL_TYPE_PIN) {
+            View v = mInflater.inflate(R.layout.passenger_keyguard_pin_view, root, true);
+            controller = new PassengerKeyguardPinViewController(v, mLockPatternUtils, mUserTracker,
+                    mTrustManager, mMainHandler, mCarServiceProvider, mLockoutHelper);
+        } else if (credentialType == CREDENTIAL_TYPE_PASSWORD) {
+            View v = mInflater.inflate(R.layout.passenger_keyguard_password_view, root, true);
+            controller = new PassengerKeyguardPasswordViewController(v, mLockPatternUtils,
+                    mUserTracker, mTrustManager, mMainHandler, mCarServiceProvider, mLockoutHelper);
+        } else if (credentialType == CREDENTIAL_TYPE_PATTERN) {
+            View v = mInflater.inflate(R.layout.passenger_keyguard_pattern_view, root, true);
+            controller = new PassengerKeyguardPatternViewController(v, mLockPatternUtils,
+                    mUserTracker, mTrustManager, mMainHandler, mCarServiceProvider, mLockoutHelper);
+        }
+
+        if (controller != null) {
+            controller.init();
+            return controller;
+        }
+
+        throw new IllegalStateException("Unknown credential type=" + credentialType);
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialog.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialog.java
new file mode 100644
index 00000000..41989daf
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialog.java
@@ -0,0 +1,247 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static android.car.CarOccupantZoneManager.DISPLAY_TYPE_MAIN;
+import static android.car.CarOccupantZoneManager.INVALID_USER_ID;
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_STARTING;
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_STOPPED;
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_UNLOCKED;
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_VISIBLE;
+import static android.view.WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG;
+
+import android.app.ActivityManager;
+import android.app.Presentation;
+import android.car.CarOccupantZoneManager;
+import android.car.feature.Flags;
+import android.car.user.CarUserManager;
+import android.content.Context;
+import android.hardware.display.DisplayManager;
+import android.os.Bundle;
+import android.os.Handler;
+import android.os.UserHandle;
+import android.os.UserManager;
+import android.util.Log;
+import android.view.Display;
+
+import androidx.annotation.MainThread;
+import androidx.annotation.NonNull;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.widget.LockPatternUtils;
+import com.android.systemui.CoreStartable;
+import com.android.systemui.R;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.dagger.qualifiers.Background;
+import com.android.systemui.dagger.qualifiers.Main;
+
+import java.util.HashMap;
+import java.util.Map;
+import java.util.concurrent.Executor;
+
+import javax.inject.Inject;
+
+/**
+ * Loading presentation to be shown while the passenger keyguard is initializing.
+ */
+public class PassengerKeyguardLoadingDialog implements CoreStartable {
+    private static final String TAG = PassengerKeyguardLoadingDialog.class.getName();
+    private static final boolean DEBUG = false;
+    private final Context mContext;
+    private final CarServiceProvider mCarServiceProvider;
+    private final Executor mBackgroundExecutor;
+    private final Handler mMainHandler;
+    private final Handler mBackgroundHandler;
+    private final LockPatternUtils mLockPatternUtils;
+    private final UserManager mUserManager;
+    private final DisplayManager mDisplayManager;
+    /** UserId -> Presentation mapping*/
+    @VisibleForTesting
+    final Map<Integer, LoadingPresentation> mPresentations = new HashMap<>();
+
+    private boolean mStarted = false;
+    private CarUserManager mCarUserManager;
+    private CarOccupantZoneManager mCarOccupantZoneManager;
+
+    private final CarUserManager.UserLifecycleListener mUserLifecycleListener =
+            new CarUserManager.UserLifecycleListener() {
+                @Override
+                public void onEvent(@NonNull CarUserManager.UserLifecycleEvent event) {
+                    if (event.getUserId() == ActivityManager.getCurrentUser()
+                            || event.getUserHandle().isSystem()) {
+                        // don't show for foreground or system user
+                        return;
+                    }
+
+                    if (event.getEventType() == USER_LIFECYCLE_EVENT_TYPE_STARTING
+                            || event.getEventType() == USER_LIFECYCLE_EVENT_TYPE_VISIBLE) {
+                        handleUserStarting(event.getUserHandle());
+                    } else if (event.getEventType() == USER_LIFECYCLE_EVENT_TYPE_UNLOCKED
+                            || event.getEventType() == USER_LIFECYCLE_EVENT_TYPE_STOPPED) {
+                        mMainHandler.post(() -> hideDialog(event.getUserId()));
+                    }
+                }
+            };
+
+    private final DisplayManager.DisplayListener mDisplayListener =
+            new DisplayManager.DisplayListener() {
+                @Override
+                public void onDisplayAdded(int displayId) {
+                    // no-op
+                }
+
+                @Override
+                public void onDisplayRemoved(int displayId) {
+                    if (mCarOccupantZoneManager == null) {
+                        return;
+                    }
+                    int userId = mCarOccupantZoneManager.getUserForDisplayId(displayId);
+                    if (userId != INVALID_USER_ID) {
+                        mMainHandler.post(() -> hideDialog(userId));
+                    }
+                }
+
+                @Override
+                public void onDisplayChanged(int displayId) {
+                    // no-op
+                }
+            };
+
+    @Inject
+    public PassengerKeyguardLoadingDialog(Context context, CarServiceProvider carServiceProvider,
+            @Background Executor bgExecutor, @Main Handler mainHandler,
+            @Background Handler bgHandler, LockPatternUtils lockPatternUtils) {
+        mContext = context;
+        mCarServiceProvider = carServiceProvider;
+        mBackgroundExecutor = bgExecutor;
+        mMainHandler = mainHandler;
+        mBackgroundHandler = bgHandler;
+        mLockPatternUtils = lockPatternUtils;
+        mUserManager = mContext.getSystemService(UserManager.class);
+        mDisplayManager = mContext.getSystemService(DisplayManager.class);
+    }
+
+    @Override
+    public void start() {
+        if (!Flags.supportsSecurePassengerUsers()) {
+            return;
+        }
+
+        if (!CarSystemUIUserUtil.isDriverMUMDSystemUI()) {
+            // only start for user 0 SysUI on MUMD system
+            return;
+        }
+
+        mCarServiceProvider.addListener(car -> {
+            mCarUserManager = car.getCarManager(CarUserManager.class);
+            mCarOccupantZoneManager = car.getCarManager(CarOccupantZoneManager.class);
+
+            if (mCarUserManager != null && mCarOccupantZoneManager != null) {
+                mCarUserManager.addListener(mBackgroundExecutor, mUserLifecycleListener);
+
+                if (mStarted) {
+                    return;
+                }
+
+                // In the case of a SystemUI restart, re-show dialogs for any user that is not
+                // unlocked.
+                mUserManager.getVisibleUsers().forEach(userHandle -> {
+                    if (userHandle.isSystem()
+                            || userHandle.getIdentifier() == ActivityManager.getCurrentUser()) {
+                        return;
+                    }
+                    handleUserStarting(userHandle);
+                });
+                mStarted = true;
+            }
+        });
+        mDisplayManager.registerDisplayListener(mDisplayListener, mBackgroundHandler);
+    }
+
+    private void handleUserStarting(UserHandle userHandle) {
+        if (mCarOccupantZoneManager == null) {
+            Log.w(TAG, "CarOccupantZoneManager is unexpectedly null");
+            return;
+        }
+
+        int userId = userHandle.getIdentifier();
+        if (!mLockPatternUtils.isSecure(userId) || mUserManager.isUserUnlocked(userId)) {
+            return;
+        }
+
+        int driverDisplayId = mCarOccupantZoneManager.getDisplayIdForDriver(DISPLAY_TYPE_MAIN);
+        CarOccupantZoneManager.OccupantZoneInfo zoneInfo =
+                mCarOccupantZoneManager.getOccupantZoneForUser(userHandle);
+        if (zoneInfo == null) {
+            Log.w(TAG, "unable to get zone info for user=" + userHandle.getIdentifier());
+            return;
+        }
+        Display displayForUser = mCarOccupantZoneManager.getDisplayForOccupant(zoneInfo,
+                DISPLAY_TYPE_MAIN);
+        if (displayForUser == null || displayForUser.getDisplayId() == driverDisplayId) {
+            return;
+        }
+
+        mMainHandler.post(() -> showDialog(displayForUser, userId));
+    }
+
+    @MainThread
+    private void showDialog(Display display, int userId) {
+        if (mPresentations.containsKey(userId)) {
+            return;
+        }
+        if (DEBUG) {
+            Log.d(TAG, "showing presentation on display=" + display + " for user=" + userId);
+        }
+        LoadingPresentation presentation = createLoadingPresentation(display);
+        mPresentations.put(userId, presentation);
+        presentation.show();
+    }
+
+    @MainThread
+    private void hideDialog(int userId) {
+        if (!mPresentations.containsKey(userId)) {
+            return;
+        }
+        if (DEBUG) {
+            Log.d(TAG, "removing presentation for user " + userId);
+        }
+        LoadingPresentation presentation = mPresentations.remove(userId);
+        if (presentation != null) {
+            presentation.dismiss();
+        }
+    }
+
+    @VisibleForTesting
+    LoadingPresentation createLoadingPresentation(Display display) {
+        return new LoadingPresentation(mContext, display);
+    }
+
+    @VisibleForTesting
+    static class LoadingPresentation extends Presentation {
+        LoadingPresentation(Context outerContext, Display display) {
+            super(outerContext, display, /* theme= */ 0, TYPE_SYSTEM_DIALOG);
+        }
+
+        @Override
+        protected void onCreate(Bundle savedInstanceState) {
+            super.onCreate(savedInstanceState);
+            setContentView(R.layout.passenger_keyguard_loading_dialog);
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelper.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelper.java
new file mode 100644
index 00000000..1a142d6c
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLockoutHelper.java
@@ -0,0 +1,146 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import android.annotation.Nullable;
+import android.content.Context;
+import android.os.CountDownTimer;
+import android.os.SystemClock;
+
+import com.android.internal.annotations.GuardedBy;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.widget.LockPatternUtils;
+import com.android.settingslib.utils.StringUtil;
+import com.android.systemui.R;
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.settings.UserTracker;
+
+import javax.inject.Inject;
+
+/**
+ * Helper class to handle the locked out state of the passenger keyguard.
+ */
+@SysUISingleton
+public class PassengerKeyguardLockoutHelper {
+    private final Context mContext;
+    private final LockPatternUtils mLockPatternUtils;
+    private final int mUserId;
+    private final Object mLock = new Object();
+    private CountDownTimer mCountDownTimer;
+    @Nullable
+    @GuardedBy("mLock")
+    private Callback mCallback;
+
+    @Inject
+    public PassengerKeyguardLockoutHelper(Context context, LockPatternUtils lockPatternUtils,
+            UserTracker userTracker) {
+        mContext = context;
+        mLockPatternUtils = lockPatternUtils;
+        mUserId = userTracker.getUserId();
+    }
+
+    void setCallback(@Nullable Callback callback) {
+        synchronized (mLock) {
+            mCallback = callback;
+        }
+    }
+
+    /** Called when lock UI is shown */
+    void onUIShown() {
+        if (isLockedOut()) {
+            handleAttemptLockout(mLockPatternUtils.getLockoutAttemptDeadline(mUserId));
+        } else {
+            notifyRefresh(isLockedOut());
+        }
+    }
+
+    /** Called when lock UI is hidden */
+    void onUIHidden() {
+        if (mCountDownTimer != null) {
+            mCountDownTimer.cancel();
+        }
+        notifyErrorText("");
+    }
+
+    /** Handles when the lock check is completed but returns a timeout. */
+    void onCheckCompletedWithTimeout(int timeoutMs) {
+        if (timeoutMs <= 0) {
+            return;
+        }
+
+        long deadline = mLockPatternUtils.setLockoutAttemptDeadline(mUserId, timeoutMs);
+        handleAttemptLockout(deadline);
+    }
+
+    private void handleAttemptLockout(long deadline) {
+        long elapsedRealtime = SystemClock.elapsedRealtime();
+        notifyRefresh(isLockedOut());
+        mCountDownTimer = newCountDownTimer(deadline - elapsedRealtime).start();
+    }
+
+    private boolean isLockedOut() {
+        return mLockPatternUtils.getLockoutAttemptDeadline(mUserId) != 0;
+    }
+
+    private void notifyRefresh(boolean isLockedOut) {
+        synchronized (mLock) {
+            if (mCallback != null) {
+                mCallback.refreshUI(isLockedOut);
+            }
+        }
+    }
+
+    private void notifyErrorText(String msg) {
+        synchronized (mLock) {
+            if (mCallback != null) {
+                mCallback.setErrorText(msg);
+            }
+        }
+    }
+
+    private CountDownTimer newCountDownTimer(long countDownMillis) {
+        return new CountDownTimer(countDownMillis,
+                LockPatternUtils.FAILED_ATTEMPT_COUNTDOWN_INTERVAL_MS) {
+            @Override
+            public void onTick(long millisUntilFinished) {
+                int secondsCountdown = (int) (millisUntilFinished / 1000);
+                notifyErrorText(StringUtil.getIcuPluralsString(mContext, secondsCountdown,
+                        R.string.passenger_keyguard_too_many_failed_attempts));
+            }
+
+            @Override
+            public void onFinish() {
+                notifyRefresh(false);
+                notifyErrorText("");
+            }
+        };
+    }
+
+    @VisibleForTesting
+    @Nullable
+    CountDownTimer getCountDownTimer() {
+        return mCountDownTimer;
+    }
+
+    /** Interface for controlling the associated lock timeout UI. */
+    public interface Callback {
+        /** Sets the error text with the given string. */
+        void setErrorText(String text);
+        /** Refreshes the UI based on the locked out state. */
+        void refreshUI(boolean isLockedOut);
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewController.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewController.java
new file mode 100644
index 00000000..8ecdaa1e
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewController.java
@@ -0,0 +1,57 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import com.android.systemui.R;
+import com.android.systemui.car.window.OverlayViewController;
+import com.android.systemui.car.window.OverlayViewGlobalStateController;
+import com.android.systemui.dagger.SysUISingleton;
+
+import javax.inject.Inject;
+
+/**
+ * Controller for the instantiation and visibility of the passenger keyguard overlay.
+ */
+@SysUISingleton
+public class PassengerKeyguardOverlayViewController extends OverlayViewController {
+    private final PassengerKeyguardCredentialViewControllerFactory mCredentialViewFactory;
+
+    private PassengerKeyguardCredentialViewController mCredentialViewController;
+
+    @Inject
+    public PassengerKeyguardOverlayViewController(
+            OverlayViewGlobalStateController overlayViewGlobalStateController,
+            PassengerKeyguardCredentialViewControllerFactory credentialViewFactory) {
+        super(R.id.passenger_keyguard_stub, overlayViewGlobalStateController);
+        mCredentialViewFactory = credentialViewFactory;
+    }
+
+    @Override
+    protected void onFinishInflate() {
+        mCredentialViewController = mCredentialViewFactory.create(
+                getLayout().requireViewById(R.id.passenger_keyguard_frame));
+        mCredentialViewController.setAuthSucceededCallback(this::stop);
+    }
+
+    @Override
+    protected void hideInternal() {
+        super.hideInternal();
+        if (mCredentialViewController != null) {
+            mCredentialViewController.onOverlayHidden();
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediator.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediator.java
new file mode 100644
index 00000000..416e4432
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediator.java
@@ -0,0 +1,68 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import android.app.trust.TrustManager;
+import android.car.feature.Flags;
+
+import com.android.internal.widget.LockPatternUtils;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.car.window.OverlayViewMediator;
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.settings.UserTracker;
+
+import javax.inject.Inject;
+
+/**
+ * Mediator for Passenger Keyguard overlay. This is the entry point to all other relevant elements.
+ */
+@SysUISingleton
+public class PassengerKeyguardOverlayViewMediator implements OverlayViewMediator {
+    private final PassengerKeyguardOverlayViewController mViewController;
+    private final UserTracker mUserTracker;
+    private final LockPatternUtils mLockPatternUtils;
+    private final TrustManager mTrustManager;
+
+    @Inject
+    public PassengerKeyguardOverlayViewMediator(
+            PassengerKeyguardOverlayViewController viewController, UserTracker userTracker,
+            LockPatternUtils lockPatternUtils, TrustManager trustManager) {
+        mViewController = viewController;
+        mUserTracker = userTracker;
+        mLockPatternUtils = lockPatternUtils;
+        mTrustManager = trustManager;
+    }
+
+    @Override
+    public void registerListeners() {
+        // no-op
+    }
+
+    @Override
+    public void setUpOverlayContentViewControllers() {
+        if (!CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
+            return;
+        }
+        if (!mLockPatternUtils.isSecure(mUserTracker.getUserId())) {
+            mTrustManager.reportEnabledTrustAgentsChanged(mUserTracker.getUserId());
+            return;
+        }
+        if (Flags.supportsSecurePassengerUsers()) {
+            mViewController.start();
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPasswordViewController.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPasswordViewController.java
new file mode 100644
index 00000000..4d924544
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPasswordViewController.java
@@ -0,0 +1,120 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static android.view.WindowInsets.Type.all;
+
+import android.annotation.NonNull;
+import android.app.trust.TrustManager;
+import android.graphics.Insets;
+import android.os.Handler;
+import android.text.Editable;
+import android.text.TextWatcher;
+import android.view.View;
+import android.view.WindowInsets;
+import android.view.inputmethod.EditorInfo;
+import android.widget.EditText;
+
+import com.android.internal.widget.LockPatternUtils;
+import com.android.internal.widget.LockscreenCredential;
+import com.android.systemui.R;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.settings.UserTracker;
+
+/**
+ * Credential ViewController for the password credential type.
+ */
+public class PassengerKeyguardPasswordViewController extends
+        PassengerKeyguardCredentialViewController {
+    private EditText mPasswordField;
+
+    protected PassengerKeyguardPasswordViewController(View view,
+            LockPatternUtils lockPatternUtils,
+            UserTracker userTracker,
+            TrustManager trustManager, Handler mainHandler,
+            CarServiceProvider carServiceProvider,
+            PassengerKeyguardLockoutHelper lockoutHelper) {
+        super(view, lockPatternUtils, userTracker, trustManager, mainHandler, carServiceProvider,
+                lockoutHelper);
+    }
+
+    @Override
+    protected void onInit() {
+        super.onInit();
+        mView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
+            @NonNull
+            @Override
+            public WindowInsets onApplyWindowInsets(@NonNull View v, @NonNull WindowInsets insets) {
+                // apply insets for the IME - use all() insets type for the case of the IME
+                // affecting other insets (such as the navigation bar)
+                Insets allInsets = insets.getInsets(all());
+                v.setPadding(allInsets.left, allInsets.top, allInsets.right, allInsets.bottom);
+                return insets;
+            }
+        });
+
+        mPasswordField = mView.requireViewById(R.id.password_entry);
+
+        mPasswordField.setOnEditorActionListener((textView, actionId, keyEvent) -> {
+            // Check if this was the result of hitting the enter or "done" key.
+            if (actionId == EditorInfo.IME_NULL
+                    || actionId == EditorInfo.IME_ACTION_DONE
+                    || actionId == EditorInfo.IME_ACTION_NEXT) {
+
+                verifyCredential(() -> {
+                    mPasswordField.setText("");
+                    setErrorMessage(
+                            getContext().getString(R.string.passenger_keyguard_wrong_password));
+                });
+                return true;
+            }
+            return false;
+        });
+
+        mPasswordField.addTextChangedListener(new TextWatcher() {
+            @Override
+            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
+            }
+
+            @Override
+            public void onTextChanged(CharSequence s, int start, int before, int count) {
+            }
+
+            @Override
+            public void afterTextChanged(Editable s) {
+                clearError();
+            }
+        });
+    }
+
+    @Override
+    protected LockscreenCredential getCurrentCredential() {
+        return LockscreenCredential.createPasswordOrNone(mPasswordField.getText());
+    }
+
+    @Override
+    protected void onLockedOutChanged(boolean isLockedOut) {
+        mPasswordField.setEnabled(!isLockedOut);
+        mPasswordField.setText("");
+    }
+
+    @Override
+    public void clearAllCredentials() {
+        mPasswordField.setText("");
+        super.clearAllCredentials();
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPatternViewController.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPatternViewController.java
new file mode 100644
index 00000000..860a3b7a
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPatternViewController.java
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
+package com.android.systemui.car.keyguard.passenger;
+
+import android.app.trust.TrustManager;
+import android.os.Handler;
+import android.view.View;
+
+import com.android.internal.widget.LockPatternUtils;
+import com.android.internal.widget.LockPatternView;
+import com.android.internal.widget.LockscreenCredential;
+import com.android.systemui.R;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.settings.UserTracker;
+
+import java.util.List;
+
+/**
+ * Credential ViewController for the pattern credential type.
+ */
+public class PassengerKeyguardPatternViewController extends
+        PassengerKeyguardCredentialViewController {
+    private static final long CLEAR_WRONG_PATTERN_ATTEMPT_TIMEOUT_MS = 1500L;
+
+    private final LockPatternUtils mLockPatternUtils;
+    private final UserTracker mUserTracker;
+
+    private LockPatternView mLockPatternView;
+    private List<LockPatternView.Cell> mPattern;
+
+    private final Runnable mClearPatternErrorRunnable = () -> {
+        if (mLockPatternView != null) {
+            mLockPatternView.setEnabled(true);
+            mLockPatternView.clearPattern();
+        }
+        clearError();
+    };
+
+    protected PassengerKeyguardPatternViewController(View view,
+            LockPatternUtils lockPatternUtils,
+            UserTracker userTracker,
+            TrustManager trustManager, Handler mainHandler,
+            CarServiceProvider carServiceProvider,
+            PassengerKeyguardLockoutHelper lockoutHelper) {
+        super(view, lockPatternUtils, userTracker, trustManager, mainHandler, carServiceProvider,
+                lockoutHelper);
+        mLockPatternUtils = lockPatternUtils;
+        mUserTracker = userTracker;
+    }
+
+    @Override
+    protected void onInit() {
+        super.onInit();
+        mLockPatternView = mView.requireViewById(R.id.lockPattern);
+
+        mLockPatternView.setFadePattern(false);
+        mLockPatternView.setInStealthMode(
+                !mLockPatternUtils.isVisiblePatternEnabled(mUserTracker.getUserId()));
+        mLockPatternView.setOnPatternListener(new LockPatternView.OnPatternListener() {
+            @Override
+            public void onPatternStart() {
+                mLockPatternView.removeCallbacks(mClearPatternErrorRunnable);
+                clearError();
+            }
+
+            @Override
+            public void onPatternCleared() {
+                mLockPatternView.removeCallbacks(mClearPatternErrorRunnable);
+                mPattern = null;
+            }
+
+            @Override
+            public void onPatternCellAdded(List<LockPatternView.Cell> pattern) {
+            }
+
+            @Override
+            public void onPatternDetected(List<LockPatternView.Cell> pattern) {
+                mLockPatternView.setEnabled(false);
+                mPattern = pattern;
+
+                verifyCredential(() -> {
+                    setErrorMessage(
+                            getContext().getString(R.string.passenger_keyguard_wrong_pattern));
+                    mLockPatternView.removeCallbacks(mClearPatternErrorRunnable);
+                    mLockPatternView.postDelayed(mClearPatternErrorRunnable,
+                            CLEAR_WRONG_PATTERN_ATTEMPT_TIMEOUT_MS);
+                });
+            }
+        });
+    }
+
+    @Override
+    protected LockscreenCredential getCurrentCredential() {
+        if (mPattern != null) {
+            return LockscreenCredential.createPattern(mPattern);
+        }
+        return LockscreenCredential.createNone();
+    }
+
+    @Override
+    protected void onLockedOutChanged(boolean isLockedOut) {
+        mLockPatternView.setEnabled(!isLockedOut);
+        mLockPatternView.clearPattern();
+    }
+
+    @Override
+    public void clearAllCredentials() {
+        mLockPatternView.clearPattern();
+        super.clearAllCredentials();
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPinViewController.java b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPinViewController.java
new file mode 100644
index 00000000..938f3ef4
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardPinViewController.java
@@ -0,0 +1,99 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import android.app.trust.TrustManager;
+import android.os.Handler;
+import android.text.TextUtils;
+import android.view.View;
+import android.widget.EditText;
+
+import com.android.internal.widget.LockPatternUtils;
+import com.android.internal.widget.LockscreenCredential;
+import com.android.systemui.R;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.settings.UserTracker;
+
+/**
+ * Credential ViewController for the pin credential type.
+ */
+public class PassengerKeyguardPinViewController extends PassengerKeyguardCredentialViewController {
+    private PassengerPinPadView mPinPad;
+    private EditText mPasswordField;
+
+    protected PassengerKeyguardPinViewController(View view,
+            LockPatternUtils lockPatternUtils,
+            UserTracker userTracker,
+            TrustManager trustManager, Handler mainHandler,
+            CarServiceProvider carServiceProvider,
+            PassengerKeyguardLockoutHelper lockoutHelper) {
+        super(view, lockPatternUtils, userTracker, trustManager, mainHandler, carServiceProvider,
+                lockoutHelper);
+    }
+
+    @Override
+    protected void onInit() {
+        super.onInit();
+        mPasswordField = mView.requireViewById(R.id.password_entry);
+        mPinPad = mView.requireViewById(R.id.passenger_pin_pad);
+
+        mPinPad.setPinPadClickListener(
+                new PassengerPinPadView.PinPadClickListener() {
+                    @Override
+                    public void onDigitKeyClick(String digit) {
+                        clearError();
+                        mPasswordField.append(digit);
+                    }
+
+                    @Override
+                    public void onBackspaceClick() {
+                        clearError();
+                        if (!TextUtils.isEmpty(mPasswordField.getText())) {
+                            mPasswordField.getText().delete(mPasswordField.getSelectionEnd() - 1,
+                                    mPasswordField.getSelectionEnd());
+                        }
+                    }
+
+                    @Override
+                    public void onEnterKeyClick() {
+                        verifyCredential(() -> {
+                            mPinPad.setEnabled(true);
+                            mPasswordField.setText("");
+                            setErrorMessage(
+                                    getContext().getString(R.string.passenger_keyguard_wrong_pin));
+                        });
+                    }
+                });
+    }
+
+    @Override
+    protected LockscreenCredential getCurrentCredential() {
+        return LockscreenCredential.createPinOrNone(mPasswordField.getText());
+    }
+
+    @Override
+    protected void onLockedOutChanged(boolean isLockedOut) {
+        mPinPad.setEnabled(!isLockedOut);
+        mPasswordField.setText("");
+    }
+
+    @Override
+    public void clearAllCredentials() {
+        mPasswordField.setText("");
+        super.clearAllCredentials();
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadView.java b/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadView.java
new file mode 100644
index 00000000..50a810cc
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/passenger/PassengerPinPadView.java
@@ -0,0 +1,175 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import android.content.Context;
+import android.util.AttributeSet;
+import android.view.KeyEvent;
+import android.view.LayoutInflater;
+import android.view.MotionEvent;
+import android.view.View;
+import android.widget.GridLayout;
+import android.widget.ImageButton;
+import android.widget.TextView;
+
+import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
+
+import com.android.systemui.R;
+
+import java.util.ArrayList;
+import java.util.List;
+
+/**
+ * Rectangular pin pad entry view for passenger keyguard.
+ */
+public class PassengerPinPadView extends GridLayout {
+    // Number of keys in the pin pad, 0-9 plus backspace and enter keys.
+    @VisibleForTesting
+    static final int NUM_KEYS = 12;
+
+    @VisibleForTesting
+    static final int[] PIN_PAD_DIGIT_KEYS = {R.id.key0, R.id.key1, R.id.key2, R.id.key3,
+            R.id.key4, R.id.key5, R.id.key6, R.id.key7, R.id.key8, R.id.key9};
+
+    /**
+     * The delay in milliseconds between character deletion when the user continuously holds the
+     * backspace key.
+     */
+    private static final int LONG_CLICK_DELAY_MILLS = 100;
+
+    private final List<View> mPinKeys = new ArrayList<>(NUM_KEYS);
+    private final Runnable mOnBackspaceLongClick = new Runnable() {
+        public void run() {
+            if (mOnClickListener != null) {
+                mOnClickListener.onBackspaceClick();
+                getHandler().postDelayed(this, LONG_CLICK_DELAY_MILLS);
+            }
+        }
+    };
+
+    private PinPadClickListener mOnClickListener;
+    private ImageButton mEnterKey;
+
+    public PassengerPinPadView(Context context) {
+        super(context);
+        init();
+    }
+
+    public PassengerPinPadView(Context context, AttributeSet attrs) {
+        super(context, attrs);
+        init();
+    }
+
+    public PassengerPinPadView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
+        super(context, attrs, defStyleAttr);
+        init();
+    }
+
+    public PassengerPinPadView(Context context, @Nullable AttributeSet attrs, int defStyleAttr,
+            int defStyleRes) {
+        super(context, attrs, defStyleAttr, defStyleRes);
+        init();
+    }
+
+    /**
+     * Set the call back for key click.
+     *
+     * @param pinPadClickListener The call back.
+     */
+    public void setPinPadClickListener(PinPadClickListener pinPadClickListener) {
+        mOnClickListener = pinPadClickListener;
+    }
+
+    @Override
+    public void setEnabled(boolean enabled) {
+        super.setEnabled(enabled);
+        for (View key : mPinKeys) {
+            key.setEnabled(enabled);
+        }
+    }
+
+    private void init() {
+        LayoutInflater inflater = LayoutInflater.from(getContext());
+        inflater.inflate(R.layout.passenger_keyguard_pin_pad, this, true);
+
+        for (int keyId : PIN_PAD_DIGIT_KEYS) {
+            TextView key = requireViewById(keyId);
+            String digit = key.getTag().toString();
+            key.setOnClickListener(v -> mOnClickListener.onDigitKeyClick(digit));
+            mPinKeys.add(key);
+        }
+
+        ImageButton backspace = requireViewById(R.id.key_backspace);
+        backspace.setOnTouchListener((v, event) -> {
+            switch (event.getAction()) {
+                case MotionEvent.ACTION_DOWN:
+                    getHandler().post(mOnBackspaceLongClick);
+                    // Must return false so that ripple can show
+                    return false;
+                case MotionEvent.ACTION_UP:
+                    getHandler().removeCallbacks(mOnBackspaceLongClick);
+                    // Must return false so that ripple can show
+                    return false;
+                default:
+                    return false;
+            }
+        });
+
+        backspace.setOnKeyListener((v, code, event) -> {
+            if (code != KeyEvent.KEYCODE_DPAD_CENTER) {
+                return false;
+            }
+            switch (event.getAction()) {
+                case KeyEvent.ACTION_DOWN:
+                    getHandler().post(mOnBackspaceLongClick);
+                    // Must return false so that ripple can show
+                    return false;
+                case KeyEvent.ACTION_UP:
+                    getHandler().removeCallbacks(mOnBackspaceLongClick);
+                    // Must return false so that ripple can show
+                    return false;
+                default:
+                    return false;
+            }
+        });
+
+        mPinKeys.add(backspace);
+        mEnterKey = requireViewById(R.id.key_enter);
+        mEnterKey.setOnClickListener(v -> mOnClickListener.onEnterKeyClick());
+        mPinKeys.add(mEnterKey);
+    }
+    /**
+     * The call back interface for onClick event in the view.
+     */
+    public interface PinPadClickListener {
+        /**
+         * One of the digit key has been clicked.
+         *
+         * @param digit A String representing a digit between 0 and 9.
+         */
+        void onDigitKeyClick(String digit);
+        /**
+         * The backspace key has been clicked.
+         */
+        void onBackspaceClick();
+        /**
+         * The enter key has been clicked.
+         */
+        void onEnterKeyClick();
+    }
+}
diff --git a/src/com/android/systemui/car/ndo/InCallLiveData.java b/src/com/android/systemui/car/ndo/InCallLiveData.java
index d80d47b1..49aa61af 100644
--- a/src/com/android/systemui/car/ndo/InCallLiveData.java
+++ b/src/com/android/systemui/car/ndo/InCallLiveData.java
@@ -47,26 +47,6 @@ public class InCallLiveData extends MediatorLiveData<Call> implements
         mBlockedActivity = packageName;
     }
 
-    private final Call.Callback mCallStateChangedCallback = new Call.Callback() {
-        @Override
-        public void onStateChanged(Call call, int state) {
-            Slog.d(TAG, "onStateChanged: " + call);
-            update();
-        }
-
-        @Override
-        public void onParentChanged(Call call, Call parent) {
-            Slog.d(TAG, "onParentChanged: " + call);
-            update();
-        }
-
-        @Override
-        public void onChildrenChanged(Call call, List<Call> children) {
-            Slog.d(TAG, "onChildrenChanged: " + call);
-            update();
-        }
-    };
-
     @Override
     protected void onActive() {
         super.onActive();
@@ -87,14 +67,30 @@ public class InCallLiveData extends MediatorLiveData<Call> implements
     @Override
     public void onCallAdded(Call call) {
         Slog.d(TAG, "Call added: " + call);
-        call.registerCallback(mCallStateChangedCallback);
         update();
     }
 
     @Override
     public void onCallRemoved(Call call) {
         Slog.d(TAG, "Call removed: " + call);
-        call.unregisterCallback(mCallStateChangedCallback);
+        update();
+    }
+
+    @Override
+    public void onStateChanged(Call call, int state) {
+        Slog.d(TAG, "onStateChanged: " + call + " state: " + state);
+        update();
+    }
+
+    @Override
+    public void onParentChanged(Call call, Call parent) {
+        Slog.d(TAG, "onParentChanged: " + call);
+        update();
+    }
+
+    @Override
+    public void onChildrenChanged(Call call, List<Call> children) {
+        Slog.d(TAG, "onChildrenChanged: " + call);
         update();
     }
 
diff --git a/src/com/android/systemui/car/notification/BottomNotificationPanelViewMediator.java b/src/com/android/systemui/car/notification/BottomNotificationPanelViewMediator.java
index c581de72..0469d4b1 100644
--- a/src/com/android/systemui/car/notification/BottomNotificationPanelViewMediator.java
+++ b/src/com/android/systemui/car/notification/BottomNotificationPanelViewMediator.java
@@ -21,7 +21,6 @@ import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
 import android.content.Context;
 
 import com.android.systemui.broadcast.BroadcastDispatcher;
-import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.systembar.CarSystemBarController;
 import com.android.systemui.car.window.OverlayPanelViewController;
 import com.android.systemui.dagger.SysUISingleton;
@@ -45,16 +44,13 @@ public class BottomNotificationPanelViewMediator extends NotificationPanelViewMe
             PowerManagerHelper powerManagerHelper,
             BroadcastDispatcher broadcastDispatcher,
             UserTracker userTracker,
-            CarDeviceProvisionedController carDeviceProvisionedController,
-            ConfigurationController configurationController
-    ) {
+            ConfigurationController configurationController) {
         super(context,
                 carSystemBarController,
                 notificationPanelViewController,
                 powerManagerHelper,
                 broadcastDispatcher,
                 userTracker,
-                carDeviceProvisionedController,
                 configurationController);
         notificationPanelViewController.setOverlayDirection(
                 OverlayPanelViewController.OVERLAY_FROM_BOTTOM_BAR);
diff --git a/src/com/android/systemui/car/notification/NotificationButtonController.java b/src/com/android/systemui/car/notification/NotificationButtonController.java
new file mode 100644
index 00000000..bc14d16d
--- /dev/null
+++ b/src/com/android/systemui/car/notification/NotificationButtonController.java
@@ -0,0 +1,76 @@
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
+package com.android.systemui.car.notification;
+
+import android.view.View;
+
+import com.android.systemui.car.systembar.CarSystemBarButton;
+import com.android.systemui.car.systembar.CarSystemBarButtonController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A CarSystemBarElementController for handling notification button interactions.
+ */
+public class NotificationButtonController extends CarSystemBarButtonController {
+
+    private final NotificationPanelViewController mNotificationPanelViewController;
+
+    @AssistedInject
+    public NotificationButtonController(@Assisted CarSystemBarButton notificationsButton,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            NotificationPanelViewController notificationPanelViewController,
+            UserTracker userTracker) {
+        super(notificationsButton, disableController, stateController, userTracker);
+
+        mNotificationPanelViewController = notificationPanelViewController;
+        mNotificationPanelViewController.registerViewStateListener(notificationsButton);
+        mNotificationPanelViewController.setOnUnseenCountUpdateListener(unseenNotificationCount -> {
+            toggleNotificationUnseenIndicator(unseenNotificationCount > 0);
+        });
+        notificationsButton.setOnClickListener(this::onNotificationsClick);
+    }
+
+    /**
+     * Toggles the notification unseen indicator on/off.
+     *
+     * @param hasUnseen true if the unseen notification count is great than 0.
+     */
+    private void toggleNotificationUnseenIndicator(boolean hasUnseen) {
+        mView.setUnseen(hasUnseen);
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarButton,
+                    NotificationButtonController> {
+    }
+
+    private void onNotificationsClick(View v) {
+        if (mView.getDisabled()) {
+            mView.runOnClickWhileDisabled();
+            return;
+        }
+        mNotificationPanelViewController.toggle();
+    }
+}
diff --git a/src/com/android/systemui/car/notification/NotificationPanelViewController.java b/src/com/android/systemui/car/notification/NotificationPanelViewController.java
index ac68b2b8..16e87837 100644
--- a/src/com/android/systemui/car/notification/NotificationPanelViewController.java
+++ b/src/com/android/systemui/car/notification/NotificationPanelViewController.java
@@ -241,6 +241,11 @@ public class NotificationPanelViewController extends OverlayPanelViewController
 
     // OverlayViewController
 
+    @Override
+    public boolean shouldPanelConsumeSystemBarTouch() {
+        return true;
+    }
+
     @Override
     protected void onFinishInflate() {
         reinflate();
diff --git a/src/com/android/systemui/car/notification/NotificationPanelViewMediator.java b/src/com/android/systemui/car/notification/NotificationPanelViewMediator.java
index ff579d65..5802f176 100644
--- a/src/com/android/systemui/car/notification/NotificationPanelViewMediator.java
+++ b/src/com/android/systemui/car/notification/NotificationPanelViewMediator.java
@@ -33,7 +33,6 @@ import androidx.annotation.CallSuper;
 import androidx.annotation.NonNull;
 
 import com.android.systemui.broadcast.BroadcastDispatcher;
-import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.systembar.CarSystemBarController;
 import com.android.systemui.car.window.OverlayViewMediator;
 import com.android.systemui.dagger.SysUISingleton;
@@ -59,7 +58,6 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
     private final PowerManagerHelper mPowerManagerHelper;
     private final BroadcastDispatcher mBroadcastDispatcher;
     private final UserTracker mUserTracker;
-    private final CarDeviceProvisionedController mCarDeviceProvisionedController;
     private final ConfigurationController mConfigurationController;
 
     private final BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
@@ -100,16 +98,13 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
             PowerManagerHelper powerManagerHelper,
             BroadcastDispatcher broadcastDispatcher,
             UserTracker userTracker,
-            CarDeviceProvisionedController carDeviceProvisionedController,
-            ConfigurationController configurationController
-    ) {
+            ConfigurationController configurationController) {
         mContext = context;
         mCarSystemBarController = carSystemBarController;
         mNotificationPanelViewController = notificationPanelViewController;
         mPowerManagerHelper = powerManagerHelper;
         mBroadcastDispatcher = broadcastDispatcher;
         mUserTracker = userTracker;
-        mCarDeviceProvisionedController = carDeviceProvisionedController;
         mConfigurationController = configurationController;
     }
 
@@ -121,22 +116,6 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
         registerLeftBarTouchListener();
         registerRightBarTouchListener();
 
-        mCarSystemBarController.registerNotificationController(
-                new NotificationsShadeController() {
-                    @Override
-                    public void togglePanel() {
-                        mNotificationPanelViewController.toggle();
-                    }
-
-                    @Override
-                    public boolean isNotificationPanelOpen() {
-                        return mNotificationPanelViewController.isPanelExpanded();
-                    }
-                });
-
-        mCarSystemBarController.registerNotificationPanelViewController(
-                mNotificationPanelViewController);
-
         mBroadcastDispatcher.registerReceiver(mBroadcastReceiver,
                 new IntentFilter(Intent.ACTION_CLOSE_SYSTEM_DIALOGS), null,
                 mUserTracker.getUserHandle());
@@ -145,12 +124,6 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
 
     @Override
     public void setUpOverlayContentViewControllers() {
-        mNotificationPanelViewController.setOnUnseenCountUpdateListener(unseenNotificationCount -> {
-            boolean hasUnseen = unseenNotificationCount > 0;
-            mCarSystemBarController.toggleAllNotificationsUnseenIndicator(
-                    mCarDeviceProvisionedController.isCurrentUserFullySetup(), hasUnseen);
-        });
-
         mPowerManagerHelper.setCarPowerStateListener(state -> {
             if (state == CarPowerManager.STATE_ON) {
                 mNotificationPanelViewController.onCarPowerStateOn();
diff --git a/src/com/android/systemui/car/notification/NotificationsShadeController.java b/src/com/android/systemui/car/notification/NotificationsShadeController.java
deleted file mode 100644
index 8ed74887..00000000
--- a/src/com/android/systemui/car/notification/NotificationsShadeController.java
+++ /dev/null
@@ -1,25 +0,0 @@
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
-package com.android.systemui.car.notification;
-
-/** Interface for controlling the notifications shade. */
-public interface NotificationsShadeController {
-    /** Toggles the visibility of the notifications shade. */
-    void togglePanel();
-
-    /** Returns {@code true} if the panel is open. */
-    boolean isNotificationPanelOpen();
-}
diff --git a/src/com/android/systemui/car/notification/TopNotificationPanelViewMediator.java b/src/com/android/systemui/car/notification/TopNotificationPanelViewMediator.java
index 291426bf..141eac3c 100644
--- a/src/com/android/systemui/car/notification/TopNotificationPanelViewMediator.java
+++ b/src/com/android/systemui/car/notification/TopNotificationPanelViewMediator.java
@@ -21,7 +21,6 @@ import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
 import android.content.Context;
 
 import com.android.systemui.broadcast.BroadcastDispatcher;
-import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.systembar.CarSystemBarController;
 import com.android.systemui.car.window.OverlayPanelViewController;
 import com.android.systemui.dagger.SysUISingleton;
@@ -45,16 +44,13 @@ public class TopNotificationPanelViewMediator extends NotificationPanelViewMedia
             PowerManagerHelper powerManagerHelper,
             BroadcastDispatcher broadcastDispatcher,
             UserTracker userTracker,
-            CarDeviceProvisionedController carDeviceProvisionedController,
-            ConfigurationController configurationController
-    ) {
+            ConfigurationController configurationController) {
         super(context,
                 carSystemBarController,
                 notificationPanelViewController,
                 powerManagerHelper,
                 broadcastDispatcher,
                 userTracker,
-                carDeviceProvisionedController,
                 configurationController);
         notificationPanelViewController.setOverlayDirection(
                 OverlayPanelViewController.OVERLAY_FROM_TOP_BAR);
diff --git a/src/com/android/systemui/car/qc/DataSubscriptionController.java b/src/com/android/systemui/car/qc/DataSubscriptionController.java
index d0dae30c..aba58386 100644
--- a/src/com/android/systemui/car/qc/DataSubscriptionController.java
+++ b/src/com/android/systemui/car/qc/DataSubscriptionController.java
@@ -52,6 +52,7 @@ import androidx.annotation.VisibleForTesting;
 import com.android.car.datasubscription.DataSubscription;
 import com.android.car.ui.utils.CarUxRestrictionsUtil;
 import com.android.systemui.R;
+import com.android.systemui.car.qc.DataSubscriptionStatsLogHelper.DataSubscriptionMessageType;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Background;
 import com.android.systemui.dagger.qualifiers.Main;
@@ -93,6 +94,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
     private Set<String> mPackagesBlocklist;
     private CountDownLatch mLatch;
     private boolean mIsNetworkCallbackRegistered;
+    private final DataSubscriptionStatsLogHelper mDataSubscriptionStatsLogHelper;
     private final TaskStackListener mTaskStackListener = new TaskStackListener() {
         @SuppressLint("MissingPermission")
         @Override
@@ -152,9 +154,6 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
                         if (mNetworkCallback.mNetwork == null) {
                             mNetworkCapabilities = null;
                             updateShouldDisplayReactiveMsg();
-                            if (mShouldDisplayReactiveMsg) {
-                                showPopUpWindow();
-                            }
                         }
                     }
                 });
@@ -176,6 +175,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
                                 && mPopupWindow != null
                                 && mPopupWindow.isShowing()) {
                             mPopupWindow.dismiss();
+                            mDataSubscriptionStatsLogHelper.logSessionFinished();
                         }
                     } else {
                         if (mIsDistractionOptimizationRequired && mPopupWindow != null) {
@@ -210,12 +210,14 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
     public DataSubscriptionController(Context context,
             UserTracker userTracker,
             @Main Handler mainHandler,
-            @Background Executor backgroundExecutor) {
+            @Background Executor backgroundExecutor,
+            DataSubscriptionStatsLogHelper dataSubscriptionStatsLogHelper) {
         mContext = context;
         mSubscription = new DataSubscription(context);
         mUserTracker = userTracker;
         mMainHandler = mainHandler;
         mBackGroundExecutor = backgroundExecutor;
+        mDataSubscriptionStatsLogHelper = dataSubscriptionStatsLogHelper;
         mIntent = new Intent(DATA_SUBSCRIPTION_ACTION);
         mIntent.setPackage(mContext.getString(
                 R.string.connectivity_flow_app));
@@ -239,6 +241,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
                     if (!mWasProactiveMsgDisplayed) {
                         mWasProactiveMsgDisplayed = true;
                     }
+                    mDataSubscriptionStatsLogHelper.logSessionFinished();
                 }
                 return true;
             }
@@ -247,8 +250,9 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
         mExplorationButton = mPopupView.findViewById(
                 R.id.data_subscription_explore_options_button);
         mExplorationButton.setOnClickListener(v -> {
-            mContext.startActivityAsUser(mIntent, mUserTracker.getUserHandle());
             mPopupWindow.dismiss();
+            mContext.startActivityAsUser(mIntent, mUserTracker.getUserHandle());
+            mDataSubscriptionStatsLogHelper.logButtonClicked();
         });
         mConnectivityManager = mContext.getSystemService(ConnectivityManager.class);
         mNetworkCallback = new DataSubscriptionNetworkCallback();
@@ -273,6 +277,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
         if (mIsDistractionOptimizationRequired) {
             if (mPopupWindow != null && mPopupWindow.isShowing()) {
                 mPopupWindow.dismiss();
+                mDataSubscriptionStatsLogHelper.logSessionFinished();
             }
         } else {
             // Determines whether a proactive message should be displayed
@@ -304,6 +309,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
             } else {
                 if (mPopupWindow != null && mPopupWindow.isShowing()) {
                     mPopupWindow.dismiss();
+                    mDataSubscriptionStatsLogHelper.logSessionFinished();
                 }
             }
         }
@@ -319,8 +325,12 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
                     if (popUpPrompt != null) {
                         if (mIsProactiveMsg) {
                             popUpPrompt.setText(R.string.data_subscription_proactive_msg_prompt);
+                            mDataSubscriptionStatsLogHelper.logSessionStarted(
+                                    DataSubscriptionMessageType.PROACTIVE);
                         } else {
                             popUpPrompt.setText(getReactiveMsg());
+                            mDataSubscriptionStatsLogHelper.logSessionStarted(
+                                    DataSubscriptionMessageType.REACTIVE);
                         }
                     }
                     int xOffsetInPx = mContext.getResources().getDimensionPixelSize(
@@ -331,11 +341,14 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
                     mAnchorView.getHandler().postDelayed(new Runnable() {
 
                         public void run() {
-                            mPopupWindow.dismiss();
-                            mWasProactiveMsgDisplayed = true;
-                            // after the proactive msg dismisses, it won't get displayed again hence
-                            // the msg from now on will just be reactive
-                            mIsProactiveMsg = false;
+                            if (mPopupWindow.isShowing()) {
+                                mPopupWindow.dismiss();
+                                mWasProactiveMsgDisplayed = true;
+                                // after the proactive msg dismisses, it won't get displayed again
+                                // hence the msg from now on will just be reactive
+                                mIsProactiveMsg = false;
+                                mDataSubscriptionStatsLogHelper.logSessionFinished();
+                            }
                         }
                     }, mPopUpTimeOut);
                 }
@@ -409,9 +422,6 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
             mNetwork = network;
             mNetworkCapabilities = networkCapabilities;
             updateShouldDisplayReactiveMsg();
-            if (mShouldDisplayReactiveMsg) {
-                showPopUpWindow();
-            }
         }
     }
 
diff --git a/src/com/android/systemui/car/qc/DataSubscriptionStatsLogHelper.java b/src/com/android/systemui/car/qc/DataSubscriptionStatsLogHelper.java
new file mode 100644
index 00000000..16a23ebf
--- /dev/null
+++ b/src/com/android/systemui/car/qc/DataSubscriptionStatsLogHelper.java
@@ -0,0 +1,149 @@
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
+package com.android.systemui.car.qc;
+
+import android.annotation.IntDef;
+import android.os.Build;
+import android.util.Log;
+
+import com.android.systemui.CarSystemUIStatsLog;
+import com.android.systemui.dagger.SysUISingleton;
+
+import java.util.UUID;
+
+import javax.inject.Inject;
+
+/**
+ * Helper class that directly interacts with {@link CarSystemUIStatsLog}, a generated class that
+ * contains logging methods for DataSubscriptionController.
+ */
+@SysUISingleton
+public class DataSubscriptionStatsLogHelper {
+
+    private static final String TAG = DataSubscriptionStatsLogHelper.class.getSimpleName();
+    private long mSessionId;
+    private int mCurrentMessageType;
+
+    /**
+     * IntDef representing enum values of CarSystemUiDataSubscriptionEventReported.event_type.
+     */
+    @IntDef({
+            DataSubscriptionEventType.UNSPECIFIED_EVENT_TYPE,
+            DataSubscriptionEventType.SESSION_STARTED,
+            DataSubscriptionEventType.SESSION_FINISHED,
+            DataSubscriptionEventType.BUTTON_CLICKED,
+    })
+
+    public @interface DataSubscriptionEventType {
+        int UNSPECIFIED_EVENT_TYPE =
+                CarSystemUIStatsLog
+                        .CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED__EVENT_TYPE__UNSPECIFIED_EVENT_TYPE;
+        int SESSION_STARTED =
+                CarSystemUIStatsLog
+                        .CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED__EVENT_TYPE__SESSION_STARTED;
+        int SESSION_FINISHED =
+                CarSystemUIStatsLog
+                        .CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED__EVENT_TYPE__SESSION_FINISHED;
+        int BUTTON_CLICKED =
+                CarSystemUIStatsLog
+                        .CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED__EVENT_TYPE__BUTTON_CLICKED;
+    }
+
+    /**
+     * IntDef representing enum values of CarSystemUiDataSubscriptionEventReported.message_type.
+     */
+    @IntDef({
+            DataSubscriptionMessageType.UNSPECIFIED_MESSAGE_TYPE,
+            DataSubscriptionMessageType.PROACTIVE,
+            DataSubscriptionMessageType.REACTIVE,
+    })
+
+    public @interface DataSubscriptionMessageType {
+
+        int UNSPECIFIED_MESSAGE_TYPE =
+                CarSystemUIStatsLog
+                        .CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED__MESSAGE_TYPE__UNSPECIFIED_MESSAGE_TYPE;
+        int PROACTIVE =
+                CarSystemUIStatsLog
+                        .CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED__MESSAGE_TYPE__PROACTIVE;
+        int REACTIVE =
+                CarSystemUIStatsLog
+                        .CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED__MESSAGE_TYPE__REACTIVE;
+    }
+
+    /**
+     * Construct logging instance of DataSubscriptionStatsLogHelper.
+     */
+    @Inject
+    public DataSubscriptionStatsLogHelper() {}
+
+    /**
+     * Logs that a new Data Subscription session has started.
+     * Additionally, resets measurements and IDs such as
+     * session ID and start time.
+     */
+    public void logSessionStarted(@DataSubscriptionMessageType int messageType) {
+        mSessionId = UUID.randomUUID().getMostSignificantBits();
+        mCurrentMessageType = messageType;
+        writeDataSubscriptionEventReported(DataSubscriptionEventType.SESSION_STARTED, messageType);
+    }
+
+    /**
+     * Logs that the current Data Subscription session has finished.
+     */
+    public void logSessionFinished() {
+        writeDataSubscriptionEventReported(DataSubscriptionEventType.SESSION_FINISHED);
+    }
+
+    /**
+     * Logs that the "See plans" button is clicked. This method should be called after
+     * logSessionStarted() is called.
+     */
+    public void logButtonClicked() {
+        writeDataSubscriptionEventReported(DataSubscriptionEventType.BUTTON_CLICKED);
+    }
+
+    /**
+     * Writes to CarSystemUiDataSubscriptionEventReported atom with {@code messageType} as the only
+     * field, and log all other fields as unspecified.
+     *
+     * @param eventType one of {@link DataSubscriptionEventType}
+     */
+    private void writeDataSubscriptionEventReported(int eventType) {
+        writeDataSubscriptionEventReported(
+                eventType, /* messageType */ mCurrentMessageType);
+    }
+
+    /**
+     * Writes to CarSystemUiDataSubscriptionEventReported atom with all the optional fields filled.
+     *
+     * @param eventType   one of {@link DataSubscriptionEventType}
+     * @param messageType one of {@link DataSubscriptionMessageType}
+     */
+    private void writeDataSubscriptionEventReported(int eventType, int messageType) {
+        if (Build.isDebuggable()) {
+            Log.v(TAG, "writing CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED. sessionId="
+                    + mSessionId + ", eventType= " + eventType
+                    + ", messageType=" + messageType);
+        }
+        CarSystemUIStatsLog.write(
+                /* atomId */ CarSystemUIStatsLog.CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED,
+                /* sessionId */ mSessionId,
+                /* eventType */ eventType,
+                /* messageType */ messageType);
+    }
+}
diff --git a/src/com/android/systemui/car/qc/SystemUIQCView.java b/src/com/android/systemui/car/qc/SystemUIQCView.java
index f783d1c6..911746b0 100644
--- a/src/com/android/systemui/car/qc/SystemUIQCView.java
+++ b/src/com/android/systemui/car/qc/SystemUIQCView.java
@@ -35,8 +35,8 @@ import com.android.systemui.car.systembar.element.CarSystemBarElementResolver;
  * attributes. This is then retrieved by a {@link SystemUIQCViewController} to be bound and
  * controlled.
  *
- * @attr ref R.styleable#SystemUIQCView_remoteQCProvider
- * @attr ref R.styleable#SystemUIQCView_localQCProvider
+ * @attr ref android.R.styleable#SystemUIQCView_remoteQCProvider
+ * @attr ref android.R.styleable#SystemUIQCView_localQCProvider
  */
 public class SystemUIQCView extends QCView implements CarSystemBarElement {
     private Class<?> mElementControllerClassAttr;
diff --git a/src/com/android/systemui/car/systembar/BuildInfoUtil.java b/src/com/android/systemui/car/systembar/BuildInfoUtil.java
new file mode 100644
index 00000000..a6e305a5
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/BuildInfoUtil.java
@@ -0,0 +1,108 @@
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
+package com.android.systemui.car.systembar;
+
+import android.car.Car;
+import android.car.VehicleAreaType;
+import android.car.VehiclePropertyIds;
+import android.car.hardware.CarPropertyValue;
+import android.car.hardware.property.CarPropertyManager;
+import android.content.Context;
+import android.os.Build;
+import android.text.TextUtils;
+
+import androidx.annotation.ArrayRes;
+
+import com.android.systemui.R;
+
+import java.util.Set;
+
+/**
+ * Contains utility functions for build info.
+ */
+// TODO(b/371116800): move this class to car-apps-common library
+public class BuildInfoUtil {
+
+    private BuildInfoUtil() {
+    }
+
+    /**
+     * Returns true for builds that are for testing for developers.
+     */
+    public static boolean isDevTesting(Context context) {
+        return (Build.IS_ENG || Build.IS_USERDEBUG) && isSupportedBenchOrEmulator(context);
+    }
+
+    /**
+     * Returns true for builds that are on benches or emulators.
+     */
+    public static boolean isSupportedBenchOrEmulator(Context context) {
+        return isEmulator() || isSupportedDebugDevice(context) || isSupportedDebugDeviceExcludeCar(
+                context);
+    }
+
+    private static boolean isEmulator() {
+        return Build.IS_EMULATOR;
+    }
+
+    private static boolean isSupportedDebugDevice(Context context) {
+        return isDebugDeviceIncluded(context, R.array.config_debug_support_devices);
+    }
+
+    private static boolean isDebugDeviceIncluded(Context context, @ArrayRes int resId) {
+        Set<String> supportedDevices = Set.of(context.getResources().getStringArray(resId));
+        return supportedDevices.contains(Build.DEVICE);
+    }
+
+    private static boolean isSupportedDebugDeviceExcludeCar(Context context) {
+        return isDebugDeviceIncluded(context, R.array.config_debug_support_devices_exclude_car)
+                && !isRealCar(context);
+    }
+
+    /**
+     * Please make sure the VIN numbers on the benches are reset before using this function,
+     * follow the instructions in b/267517048.
+     */
+    private static boolean isRealCar(Context context) {
+        Car car = Car.createCar(context);
+        CarPropertyManager carPropertyManager = null;
+        if (car != null) {
+            carPropertyManager = (CarPropertyManager) car.getCarManager(Car.PROPERTY_SERVICE);
+        }
+        if (carPropertyManager != null) {
+            try {
+                CarPropertyValue carPropertyValue = carPropertyManager.getProperty(
+                        VehiclePropertyIds.INFO_VIN, VehicleAreaType.VEHICLE_AREA_TYPE_GLOBAL);
+                if (carPropertyValue != null && carPropertyValue.getPropertyStatus()
+                        == CarPropertyValue.STATUS_AVAILABLE) {
+                    if (TextUtils.isDigitsOnly((CharSequence) carPropertyValue.getValue())) {
+                        return Long.valueOf((String) carPropertyValue.getValue()) != 0;
+                    } else {
+                        return true;
+                    }
+                }
+            } catch (Exception e) {
+                // For the situations where there are exceptions, the status of the device is
+                // uncertain, so it will be treated as a real car in order to avoid showing the
+                // debug only features.
+                return true;
+            }
+        }
+        // Normally a real car should always have the proper service setup.
+        return false;
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarButton.java b/src/com/android/systemui/car/systembar/CarSystemBarButton.java
index 9e69d54f..e11718c3 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarButton.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarButton.java
@@ -44,6 +44,9 @@ import androidx.annotation.Nullable;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.systemui.R;
+import com.android.systemui.car.systembar.element.CarSystemBarElement;
+import com.android.systemui.car.systembar.element.CarSystemBarElementFlags;
+import com.android.systemui.car.systembar.element.CarSystemBarElementResolver;
 import com.android.systemui.car.window.OverlayViewController;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.AlphaOptimizedImageView;
@@ -56,7 +59,7 @@ import java.net.URISyntaxException;
  * code.
  */
 public class CarSystemBarButton extends LinearLayout implements
-        OverlayViewController.OverlayViewStateListener {
+        OverlayViewController.OverlayViewStateListener, CarSystemBarElement {
 
     private static final String TAG = "CarSystemBarButton";
     private static final String BUTTON_FILTER_DELIMITER = ";";
@@ -70,6 +73,10 @@ public class CarSystemBarButton extends LinearLayout implements
 
     private final Context mContext;
     private final ActivityManager mActivityManager;
+    private final Class<?> mElementControllerClassAttr;
+    private final int mSystemBarDisableFlags;
+    private final int mSystemBarDisable2Flags;
+    private final boolean mDisableForLockTaskModeLocked;
     @Nullable
     private UserTracker mUserTracker;
     private ViewGroup mIconContainer;
@@ -115,6 +122,18 @@ public class CarSystemBarButton extends LinearLayout implements
         TypedArray typedArray = context.obtainStyledAttributes(attrs,
                 R.styleable.CarSystemBarButton);
 
+        mElementControllerClassAttr =
+                CarSystemBarElementResolver.getElementControllerClassFromAttributes(context, attrs);
+        mSystemBarDisableFlags =
+                CarSystemBarElementFlags.getStatusBarManagerDisableFlagsFromAttributes(context,
+                        attrs);
+        mSystemBarDisable2Flags =
+                CarSystemBarElementFlags.getStatusBarManagerDisable2FlagsFromAttributes(context,
+                        attrs);
+        mDisableForLockTaskModeLocked =
+                CarSystemBarElementFlags.getDisableForLockTaskModeLockedFromAttributes(context,
+                        attrs);
+
         setUpIntents(typedArray);
         setUpIcons(typedArray);
         typedArray.recycle();
@@ -401,7 +420,7 @@ public class CarSystemBarButton extends LinearLayout implements
         };
     }
 
-    void setUserTracker(UserTracker userTracker) {
+    public void setUserTracker(UserTracker userTracker) {
         mUserTracker = userTracker;
     }
 
@@ -468,4 +487,27 @@ public class CarSystemBarButton extends LinearLayout implements
     protected UserTracker getUserTracker() {
         return mUserTracker;
     }
+
+    @Override
+    public Class<?> getElementControllerClass() {
+        if (mElementControllerClassAttr != null) {
+            return mElementControllerClassAttr;
+        }
+        return CarSystemBarButtonController.class;
+    }
+
+    @Override
+    public int getSystemBarDisableFlags() {
+        return mSystemBarDisableFlags;
+    }
+
+    @Override
+    public int getSystemBarDisable2Flags() {
+        return mSystemBarDisable2Flags;
+    }
+
+    @Override
+    public boolean disableForLockTaskModeLocked() {
+        return mDisableForLockTaskModeLocked;
+    }
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarButtonController.java b/src/com/android/systemui/car/systembar/CarSystemBarButtonController.java
new file mode 100644
index 00000000..fc738e16
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/CarSystemBarButtonController.java
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
+package com.android.systemui.car.systembar;
+
+import androidx.annotation.CallSuper;
+
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A generic CarSystemBarElementController for handling CarSystemBarButton button interactions.
+ */
+public class CarSystemBarButtonController
+        extends CarSystemBarElementController<CarSystemBarButton> {
+
+    private final UserTracker mUserTracker;
+
+    @AssistedInject
+    public CarSystemBarButtonController(@Assisted CarSystemBarButton barButton,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            UserTracker userTracker) {
+        super(barButton, disableController, stateController);
+
+        mUserTracker = userTracker;
+    }
+
+    @Override
+    @CallSuper
+    protected void onInit() {
+        mView.setUserTracker(mUserTracker);
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarButton,
+                    CarSystemBarButtonController> {
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarController.java b/src/com/android/systemui/car/systembar/CarSystemBarController.java
index 031682e0..32202ab8 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarController.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarController.java
@@ -17,19 +17,8 @@
 package com.android.systemui.car.systembar;
 
 import android.annotation.IntDef;
-import android.app.StatusBarManager.Disable2Flags;
-import android.app.StatusBarManager.DisableFlags;
 import android.view.View;
-import android.view.ViewGroup;
-import android.view.WindowInsets.Type.InsetsType;
-import android.view.WindowInsetsController;
 
-import com.android.internal.statusbar.LetterboxDetails;
-import com.android.internal.view.AppearanceRegion;
-import com.android.systemui.car.hvac.HvacPanelController;
-import com.android.systemui.car.hvac.HvacPanelOverlayViewController;
-import com.android.systemui.car.notification.NotificationPanelViewController;
-import com.android.systemui.car.notification.NotificationsShadeController;
 import com.android.systemui.statusbar.policy.ConfigurationController;
 
 import java.lang.annotation.ElementType;
@@ -58,91 +47,8 @@ public interface CarSystemBarController extends ConfigurationController.Configur
      */
     void init();
 
-    /**
-     * See {@code CommandQueue.Callback#setImeWindowStatus}
-     */
-    void setImeWindowStatus(int displayId, int vis, int backDisposition,
-                boolean showImeSwitcher);
-
-    /**
-     * See {@code CommandQueue.Callback#onSystemBarAttributesChanged}
-     */
-    void onSystemBarAttributesChanged(
-                int displayId,
-                @WindowInsetsController.Appearance int appearance,
-                AppearanceRegion[] appearanceRegions,
-                boolean navbarColorManagedByIme,
-                @WindowInsetsController.Behavior int behavior,
-                @InsetsType int requestedVisibleTypes,
-                String packageName,
-                LetterboxDetails[] letterboxDetails);
-
-    /**
-     * See {@code CommandQueue.Callback#showTransient}
-     */
-    void showTransient(int displayId, @InsetsType int types, boolean isGestureOnSystemBar);
-
-    /**
-     * See {@code CommandQueue.Callback#abortTransient}
-     */
-    void abortTransient(int displayId, @InsetsType int types);
-
-    /**
-     * See {@code CommandQueue.Callback#disable}
-     */
-    void disable(int displayId, @DisableFlags int state1, @Disable2Flags int state2,
-                boolean animate);
-
-    /**
-     * See {@code CommandQueue.Callback#setSystemBarStates}
-     */
-    void setSystemBarStates(@DisableFlags int state, @DisableFlags int state2);
-
-    /**
-     * Changes window visibility of the given system bar side.
-     */
-    boolean setBarVisibility(@SystemBarSide int side, @View.Visibility int visibility);
-
-    /**
-     * Returns the window of the given system bar side.
-     */
-    ViewGroup getBarWindow(@SystemBarSide int side);
-
-    /**
-     * Returns the view of the given system bar side.
-     */
-    CarSystemBarView getBarView(@SystemBarSide int side, boolean isSetUp);
-
     /**
      * Registers a touch listener callbar for the given system bar side.
      */
     void registerBarTouchListener(@SystemBarSide int side, View.OnTouchListener listener);
-
-    /**
-     * Toggles all notification unseen indicator.
-     */
-    void toggleAllNotificationsUnseenIndicator(boolean isSetUp, boolean hasUnseen);
-
-    /**
-     * Registers a {@link HvacPanelController}
-     */
-    void registerHvacPanelController(HvacPanelController hvacPanelController);
-
-    /**
-     * Registers a {@link HvacPanelOverlayViewController}
-     */
-    void registerHvacPanelOverlayViewController(
-            HvacPanelOverlayViewController hvacPanelOverlayViewController);
-
-    /**
-     * Registers a {@link NotificationsShadeController}
-     */
-    void registerNotificationController(
-            NotificationsShadeController notificationsShadeController);
-
-    /**
-     * Registers a {@link NotificationPanelViewController}
-     */
-    void registerNotificationPanelViewController(
-            NotificationPanelViewController notificationPanelViewController);
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java b/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
index c5cee380..7877695c 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
@@ -19,18 +19,15 @@ package com.android.systemui.car.systembar;
 import static android.content.Intent.ACTION_OVERLAY_CHANGED;
 import static android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS;
 
-import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
-import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
-import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
-import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
 import static com.android.systemui.car.Flags.configAwareSystemui;
+import static com.android.systemui.car.systembar.CarSystemBarViewController.BUTTON_TYPE_KEYGUARD;
+import static com.android.systemui.car.systembar.CarSystemBarViewController.BUTTON_TYPE_NAVIGATION;
+import static com.android.systemui.car.systembar.CarSystemBarViewController.BUTTON_TYPE_OCCLUSION;
 import static com.android.systemui.shared.statusbar.phone.BarTransitions.MODE_SEMI_TRANSPARENT;
 import static com.android.systemui.shared.statusbar.phone.BarTransitions.MODE_TRANSPARENT;
 
-import android.annotation.LayoutRes;
 import android.app.ActivityManager;
 import android.app.ActivityManager.RunningTaskInfo;
-import android.app.StatusBarManager;
 import android.app.StatusBarManager.Disable2Flags;
 import android.app.StatusBarManager.DisableFlags;
 import android.content.BroadcastReceiver;
@@ -41,11 +38,13 @@ import android.content.res.Configuration;
 import android.graphics.Rect;
 import android.inputmethodservice.InputMethodService;
 import android.os.Build;
+import android.os.Bundle;
 import android.os.PatternMatcher;
 import android.os.RemoteException;
 import android.util.ArraySet;
 import android.util.Log;
-import android.view.Gravity;
+import android.util.SparseArray;
+import android.util.SparseBooleanArray;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.WindowInsets;
@@ -54,28 +53,19 @@ import android.view.WindowInsetsController;
 import android.view.WindowManager;
 import android.widget.Toast;
 
-import androidx.annotation.IdRes;
 import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 
-import com.android.car.ui.FocusParkingView;
-import com.android.car.ui.utils.ViewUtils;
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.statusbar.LetterboxDetails;
 import com.android.internal.statusbar.RegisterStatusBarResult;
 import com.android.internal.view.AppearanceRegion;
-import com.android.systemui.R;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarDeviceProvisionedListener;
 import com.android.systemui.car.displaycompat.ToolbarController;
-import com.android.systemui.car.hvac.HvacController;
-import com.android.systemui.car.hvac.HvacPanelController;
 import com.android.systemui.car.hvac.HvacPanelOverlayViewController;
 import com.android.systemui.car.keyguard.KeyguardSystemBarPresenter;
 import com.android.systemui.car.notification.NotificationPanelViewController;
-import com.android.systemui.car.notification.NotificationsShadeController;
-import com.android.systemui.car.statusicon.StatusIconPanelViewController;
-import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.plugins.DarkIconDispatcher;
@@ -97,12 +87,11 @@ import com.android.systemui.util.concurrency.DelayableExecutor;
 import dagger.Lazy;
 
 import java.util.ArrayList;
-import java.util.List;
+import java.util.HashMap;
 import java.util.Locale;
+import java.util.Map;
 import java.util.Set;
 
-import javax.inject.Provider;
-
 /** A single class which controls the system bar views. */
 @SysUISingleton
 public class CarSystemBarControllerImpl implements CarSystemBarController,
@@ -116,14 +105,8 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
 
     private final Context mContext;
     private final CarSystemBarViewFactory mCarSystemBarViewFactory;
-    private final ButtonSelectionStateController mButtonSelectionStateController;
-    private final ButtonRoleHolderController mButtonRoleHolderController;
-    private final Provider<StatusIconPanelViewController.Builder> mPanelControllerBuilderProvider;
-    private final Lazy<MicPrivacyChipViewController> mMicPrivacyChipViewControllerLazy;
-    private final Lazy<CameraPrivacyChipViewController> mCameraPrivacyChipViewControllerLazy;
     private final SystemBarConfigs mSystemBarConfigs;
     private final SysuiDarkIconDispatcher mStatusBarIconController;
-    private final WindowManager mWindowManager;
     private final CarDeviceProvisionedController mCarDeviceProvisionedController;
     private final CommandQueue mCommandQueue;
     private final AutoHideController mAutoHideController;
@@ -133,28 +116,17 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     private final DisplayTracker mDisplayTracker;
     private final Lazy<KeyguardStateController> mKeyguardStateControllerLazy;
     private final Lazy<PhoneStatusBarPolicy> mIconPolicyLazy;
-    private final HvacController mHvacController;
     private final ConfigurationController mConfigurationController;
     private final CarSystemBarRestartTracker mCarSystemBarRestartTracker;
     private final int mDisplayId;
     @Nullable
     private final ToolbarController mDisplayCompatToolbarController;
-    private final Set<View.OnTouchListener> mTopBarTouchListeners = new ArraySet<>();
-    private final Set<View.OnTouchListener> mBottomBarTouchListeners = new ArraySet<>();
-    private final Set<View.OnTouchListener> mLeftBarTouchListeners = new ArraySet<>();
-    private final Set<View.OnTouchListener> mRightBarTouchListeners = new ArraySet<>();
 
     protected final UserTracker mUserTracker;
 
-    private NotificationsShadeController mNotificationsShadeController;
-    private HvacPanelController mHvacPanelController;
-    private StatusIconPanelViewController mMicPanelController;
-    private StatusIconPanelViewController mCameraPanelController;
-    private StatusIconPanelViewController mProfilePanelController;
     private HvacPanelOverlayViewController mHvacPanelOverlayViewController;
     private NotificationPanelViewController mNotificationPanelViewController;
 
-    private int mPrivacyChipXOffset;
     // Saved StatusBarManager.DisableFlags
     private int mStatusBarState;
     // Saved StatusBarManager.Disable2Flags
@@ -162,36 +134,24 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     private int mLockTaskMode;
 
     // If the nav bar should be hidden when the soft keyboard is visible.
-    private boolean mHideTopBarForKeyboard;
-    private boolean mHideLeftBarForKeyboard;
-    private boolean mHideRightBarForKeyboard;
-    private boolean mHideBottomBarForKeyboard;
-
-    // Nav bar views.
-    private ViewGroup mTopSystemBarWindow;
-    private ViewGroup mBottomSystemBarWindow;
-    private ViewGroup mLeftSystemBarWindow;
-    private ViewGroup mRightSystemBarWindow;
-    private CarSystemBarView mTopView;
-    private CarSystemBarView mBottomView;
-    private CarSystemBarView mLeftView;
-    private CarSystemBarView mRightView;
-    private boolean mTopSystemBarAttached;
-    private boolean mBottomSystemBarAttached;
-    private boolean mLeftSystemBarAttached;
-    private boolean mRightSystemBarAttached;
-    @IdRes
-    private int mTopFocusedViewId;
-    @IdRes
-    private int mBottomFocusedViewId;
-    @IdRes
-    private int mLeftFocusedViewId;
-    @IdRes
-    private int mRightFocusedViewId;
-    private boolean mShowTop;
-    private boolean mShowBottom;
-    private boolean mShowLeft;
-    private boolean mShowRight;
+    // contains: Map<@SystemBarSide Integer, Boolean>
+    private final SparseBooleanArray mHideBarForKeyboardMap = new SparseBooleanArray();
+    // System bar windows.
+    // contains: Map<@SystemBarSide Integer, ViewGroup>
+    private final SparseArray<ViewGroup> mSystemBarWindowMap = new SparseArray<>();
+    // System bar views.
+    // contains: Map<@SystemBarSide Integer, CarSystemBarViewController>
+    private final SparseArray<CarSystemBarViewController> mSystemBarViewControllerMap =
+            new SparseArray<>();
+    // If the system bar is attached to the window or not.
+    // contains: Map<@SystemBarSide Integer, Boolean>
+    private final SparseBooleanArray mSystemBarAttachedMap = new SparseBooleanArray();
+    // If the system bar is enabled or not.
+    // contains: Map<@SystemBarSide Integer, Boolean>
+    private final SparseBooleanArray mSystemBarEnabledMap = new SparseBooleanArray();
+    // Set of View.OnTouchListener on each system bar.
+    // contains: Map<@SystemBarSide Integer, Set<View.OnTouchListener>>
+    private final SparseArray<Set<View.OnTouchListener>> mBarTouchListenersMap = new SparseArray();
 
     // To be attached to the navigation bars such that they can close the notification panel if
     // it's open.
@@ -213,12 +173,7 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     public CarSystemBarControllerImpl(Context context,
             UserTracker userTracker,
             CarSystemBarViewFactory carSystemBarViewFactory,
-            ButtonSelectionStateController buttonSelectionStateController,
-            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
-            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
-            ButtonRoleHolderController buttonRoleHolderController,
             SystemBarConfigs systemBarConfigs,
-            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider,
             // TODO(b/156052638): Should not need to inject LightBarController
             LightBarController lightBarController,
             DarkIconDispatcher darkIconDispatcher,
@@ -231,7 +186,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
             IStatusBarService barService,
             Lazy<KeyguardStateController> keyguardStateControllerLazy,
             Lazy<PhoneStatusBarPolicy> iconPolicyLazy,
-            HvacController hvacController,
             ConfigurationController configurationController,
             CarSystemBarRestartTracker restartTracker,
             DisplayTracker displayTracker,
@@ -239,14 +193,8 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         mContext = context;
         mUserTracker = userTracker;
         mCarSystemBarViewFactory = carSystemBarViewFactory;
-        mButtonSelectionStateController = buttonSelectionStateController;
-        mMicPrivacyChipViewControllerLazy = micPrivacyChipViewControllerLazy;
-        mCameraPrivacyChipViewControllerLazy = cameraPrivacyChipViewControllerLazy;
-        mButtonRoleHolderController = buttonRoleHolderController;
-        mPanelControllerBuilderProvider = panelControllerBuilderProvider;
         mSystemBarConfigs = systemBarConfigs;
         mStatusBarIconController = (SysuiDarkIconDispatcher) darkIconDispatcher;
-        mWindowManager = windowManager;
         mCarDeviceProvisionedController = deviceProvisionedController;
         mCommandQueue = commandQueue;
         mAutoHideController = autoHideController;
@@ -255,7 +203,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         mBarService = barService;
         mKeyguardStateControllerLazy = keyguardStateControllerLazy;
         mIconPolicyLazy = iconPolicyLazy;
-        mHvacController = hvacController;
         mDisplayId = context.getDisplayId();
         mDisplayTracker = displayTracker;
         mIsUiModeNight = mContext.getResources().getConfiguration().isNightModeActive();
@@ -272,14 +219,10 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
 
         resetSystemBarConfigs();
 
-        mPrivacyChipXOffset = -mContext.getResources()
-                .getDimensionPixelOffset(R.dimen.privacy_chip_horizontal_padding);
-
         // Set initial state.
-        mHideTopBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(TOP);
-        mHideBottomBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(BOTTOM);
-        mHideLeftBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(LEFT);
-        mHideRightBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(RIGHT);
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            mHideBarForKeyboardMap.put(side, mSystemBarConfigs.getHideForKeyboardBySide(side));
+        });
 
         // Connect into the status bar manager service
         mCommandQueue.addCallback(this);
@@ -347,11 +290,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
                 mButtonSelectionStateListener);
         TaskStackChangeListeners.getInstance().registerTaskStackListener(
                 new TaskStackChangeListener() {
-                    @Override
-                    public void onLockTaskModeChanged(int mode) {
-                        refreshSystemBar();
-                    }
-
                     @Override
                     public void onTaskMovedToFront(RunningTaskInfo taskInfo) {
                         if (mDisplayCompatToolbarController != null) {
@@ -409,7 +347,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
             mAppearanceRegions = appearanceRegions;
             updateStatusBarAppearance();
         }
-        refreshSystemBar();
     }
 
     @Override
@@ -469,118 +406,34 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         }
 
         // cache the current state
-        // The focused view will be destroyed during re-layout, causing the framework to adjust
-        // the focus unexpectedly. To avoid that, move focus to a view that won't be
-        // destroyed during re-layout and has no focus highlight (the FocusParkingView), then
-        // move focus back to the previously focused view after re-layout.
-        cacheAndHideFocus();
-        View profilePickerView = null;
-        boolean isProfilePickerOpen = false;
-        if (mTopView != null) {
-            profilePickerView = mTopView.findViewById(R.id.user_name);
-        }
-        if (profilePickerView != null) isProfilePickerOpen = profilePickerView.isSelected();
-        if (isProfilePickerOpen) {
-            profilePickerView.callOnClick();
-        }
+        Map<Integer, Bundle> savedStates = mSystemBarConfigs.getSystemBarSidesByZOrder().stream()
+                .collect(HashMap::new,
+                        (map, side) -> {
+                            Bundle bundle = new Bundle();
+                            getBarViewController(side, isDeviceSetupForUser())
+                                    .onSaveInstanceState(bundle);
+                            map.put(side, bundle);
+                        },
+                        HashMap::putAll);
 
         resetSystemBarContent(/* isProvisionedStateChange= */ false);
 
         // retrieve the previous state
-        if (isProfilePickerOpen) {
-            if (mTopView != null) {
-                profilePickerView = mTopView.findViewById(R.id.user_name);
-            }
-            if (profilePickerView != null) profilePickerView.callOnClick();
-        }
-
-        restoreFocus();
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            getBarViewController(side, isDeviceSetupForUser())
+                    .onRestoreInstanceState(savedStates.get(side));
+        });
     }
 
     private void readConfigs() {
-        mShowTop = mSystemBarConfigs.getEnabledStatusBySide(TOP);
-        mShowBottom = mSystemBarConfigs.getEnabledStatusBySide(BOTTOM);
-        mShowLeft = mSystemBarConfigs.getEnabledStatusBySide(LEFT);
-        mShowRight = mSystemBarConfigs.getEnabledStatusBySide(RIGHT);
-    }
-
-    /**
-     * Hides all system bars.
-     */
-    public void hideBars() {
-        setTopWindowVisibility(View.GONE);
-        setBottomWindowVisibility(View.GONE);
-        setLeftWindowVisibility(View.GONE);
-        setRightWindowVisibility(View.GONE);
-    }
-
-    /**
-     * Shows all system bars.
-     */
-    public void showBars() {
-        setTopWindowVisibility(View.VISIBLE);
-        setBottomWindowVisibility(View.VISIBLE);
-        setLeftWindowVisibility(View.VISIBLE);
-        setRightWindowVisibility(View.VISIBLE);
-    }
-
-    /** Clean up */
-    public void removeAll() {
-        mButtonSelectionStateController.removeAll();
-        mButtonRoleHolderController.removeAll();
-        mMicPrivacyChipViewControllerLazy.get().removeAll();
-        mCameraPrivacyChipViewControllerLazy.get().removeAll();
-
-        mMicPanelController = null;
-        mCameraPanelController = null;
-        mProfilePanelController = null;
-    }
-
-    /** Gets the top window if configured to do so. */
-    @Nullable
-    public ViewGroup getTopWindow() {
-        return mShowTop ? mCarSystemBarViewFactory.getTopWindow() : null;
-    }
-
-    /** Gets the bottom window if configured to do so. */
-    @Nullable
-    public ViewGroup getBottomWindow() {
-        return mShowBottom ? mCarSystemBarViewFactory.getBottomWindow() : null;
-    }
-
-    /** Gets the left window if configured to do so. */
-    @Nullable
-    public ViewGroup getLeftWindow() {
-        return mShowLeft ? mCarSystemBarViewFactory.getLeftWindow() : null;
-    }
-
-    /** Gets the right window if configured to do so. */
-    @Nullable
-    public ViewGroup getRightWindow() {
-        return mShowRight ? mCarSystemBarViewFactory.getRightWindow() : null;
-    }
-
-    /** Toggles the top nav bar visibility. */
-    public boolean setTopWindowVisibility(@View.Visibility int visibility) {
-        return setWindowVisibility(getTopWindow(), visibility);
-    }
-
-    /** Toggles the bottom nav bar visibility. */
-    public boolean setBottomWindowVisibility(@View.Visibility int visibility) {
-        return setWindowVisibility(getBottomWindow(), visibility);
-    }
-
-    /** Toggles the left nav bar visibility. */
-    public boolean setLeftWindowVisibility(@View.Visibility int visibility) {
-        return setWindowVisibility(getLeftWindow(), visibility);
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            mSystemBarEnabledMap.put(side, mSystemBarConfigs.getEnabledStatusBySide(side));
+        });
     }
 
     /** Toggles the right nav bar visibility. */
-    public boolean setRightWindowVisibility(@View.Visibility int visibility) {
-        return setWindowVisibility(getRightWindow(), visibility);
-    }
-
-    private boolean setWindowVisibility(ViewGroup window, @View.Visibility int visibility) {
+    @VisibleForTesting
+    boolean setWindowVisibility(ViewGroup window, @View.Visibility int visibility) {
         if (window == null) {
             return false;
         }
@@ -601,7 +454,8 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
      * @param state {@code StatusBarManager.DisableFlags}
      * @param state2 {@code StatusBarManager.Disable2Flags}
      */
-    public void setSystemBarStates(int state, int state2) {
+    @VisibleForTesting
+    void setSystemBarStates(int state, int state2) {
         int diff = (state ^ mStatusBarState) | (state2 ^ mStatusBarState2);
         int lockTaskMode = getLockTaskModeState();
         if (diff == 0 && mLockTaskMode == lockTaskMode) {
@@ -614,74 +468,22 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         mStatusBarState = state;
         mStatusBarState2 = state2;
         mLockTaskMode = lockTaskMode;
-        refreshSystemBar();
     }
 
     @VisibleForTesting
-    protected int getStatusBarState() {
+    int getStatusBarState() {
         return mStatusBarState;
     }
 
     @VisibleForTesting
-    protected int getStatusBarState2() {
+    int getStatusBarState2() {
         return mStatusBarState2;
     }
 
-    @VisibleForTesting
-    protected int getLockTaskMode() {
-        return mLockTaskMode;
-    }
-
-    /**
-     * Refreshes system bar views and sets the visibility of certain components based on
-     * {@link StatusBarManager} flags and lock task mode.
-     * <ul>
-     * <li>Home button will be disabled when {@code StatusBarManager.DISABLE_HOME} is set.
-     * <li>Phone call button will be disable in lock task mode.
-     * <li>App grid button will be disable when {@code StatusBarManager.DISABLE_HOME} is set.
-     * <li>Notification button will be disable when
-     * {@code StatusBarManager.DISABLE_NOTIFICATION_ICONS} is set.
-     * <li>Quick settings and user switcher will be hidden when in lock task mode or when
-     * {@code StatusBarManager.DISABLE2_QUICK_SETTINGS} is set.
-     * </ul>
-     */
-    public void refreshSystemBar() {
-        boolean homeDisabled = ((mStatusBarState & StatusBarManager.DISABLE_HOME) > 0);
-        boolean notificationDisabled =
-                ((mStatusBarState & StatusBarManager.DISABLE_NOTIFICATION_ICONS) > 0);
-        boolean locked = (mLockTaskMode == ActivityManager.LOCK_TASK_MODE_LOCKED);
-        boolean qcDisabled =
-                ((mStatusBarState2 & StatusBarManager.DISABLE2_QUICK_SETTINGS) > 0) || locked;
-        boolean systemIconsDisabled =
-                ((mStatusBarState2 & StatusBarManager.DISABLE2_SYSTEM_ICONS) > 0) || locked;
-
-        setDisabledSystemBarButton(R.id.home, homeDisabled, "home");
-        setDisabledSystemBarButton(R.id.passenger_home, homeDisabled, "passenger_home");
-        setDisabledSystemBarButton(R.id.phone_nav, locked, "phone_nav");
-        setDisabledSystemBarButton(R.id.grid_nav, homeDisabled, "grid_nav");
-        setDisabledSystemBarButton(R.id.notifications, notificationDisabled, "notifications");
-
-        if (DEBUG) {
-            Log.d(TAG, "refreshSystemBar: locked?: " + locked
-                    + " homeDisabled: " + homeDisabled
-                    + " notificationDisabled: " + notificationDisabled
-                    + " qcDisabled: " + qcDisabled
-                    + " systemIconsDisabled: " + systemIconsDisabled);
-        }
-    }
-
     private int getLockTaskModeState() {
         return mContext.getSystemService(ActivityManager.class).getLockTaskModeState();
     }
 
-    private void setDisabledSystemBarButton(int viewId, boolean disabled,
-                @Nullable String buttonName) {
-        for (CarSystemBarView barView : getAllAvailableSystemBarViews()) {
-            barView.setDisabledSystemBarButton(viewId, disabled,
-                    () -> showAdminSupportDetailsDialog(), buttonName);
-        }
-    }
-
     private void showAdminSupportDetailsDialog() {
         // TODO(b/205891123): launch AdminSupportDetailsDialog after moving
         // AdminSupportDetailsDialog out of CarSettings since CarSettings is not and should not
@@ -690,292 +492,40 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
                 Toast.LENGTH_LONG).show();
     }
 
-    @Override
-    public boolean setBarVisibility(@SystemBarSide int side, @View.Visibility int visibility) {
-        switch (side) {
-            case BOTTOM:
-                return setBottomWindowVisibility(visibility);
-            case LEFT:
-                return setLeftWindowVisibility(visibility);
-            case RIGHT:
-                return setRightWindowVisibility(visibility);
-            case TOP:
-                return setTopWindowVisibility(visibility);
-            default:
-                return false;
-        }
-    }
-
-    @Override
-    @Nullable
-    public ViewGroup getBarWindow(@SystemBarSide int side) {
-        switch (side) {
-            case BOTTOM:
-                return getBottomWindow();
-            case LEFT:
-                return getLeftWindow();
-            case RIGHT:
-                return getRightWindow();
-            case TOP:
-                return getTopWindow();
-            default:
-                return null;
-        }
-    }
-
-    @Override
-    @Nullable
-    public CarSystemBarView getBarView(@SystemBarSide int side, boolean isSetUp) {
-        switch (side) {
-            case BOTTOM:
-                return getBottomBar(isSetUp);
-            case LEFT:
-                return getLeftBar(isSetUp);
-            case RIGHT:
-                return getRightBar(isSetUp);
-            case TOP:
-                return getTopBar(isSetUp);
-            default:
-                return null;
-        }
-    }
-
-    @Override
-    public void registerBarTouchListener(@SystemBarSide int side, View.OnTouchListener listener) {
-        switch (side) {
-            case BOTTOM:
-                registerBottomBarTouchListener(listener);
-                break;
-            case LEFT:
-                registerLeftBarTouchListener(listener);
-                break;
-            case RIGHT:
-                registerRightBarTouchListener(listener);
-                break;
-            case TOP:
-                registerTopBarTouchListener(listener);
-                break;
-            default:
-                break;
-        }
-    }
-
-    /** Gets the top navigation bar with the appropriate listeners set. */
-    @Nullable
-    public CarSystemBarView getTopBar(boolean isSetUp) {
-        if (!mShowTop) {
-            return null;
-        }
-
-        mTopView = mCarSystemBarViewFactory.getTopBar(isSetUp);
-        setupBar(mTopView, mTopBarTouchListeners, mNotificationsShadeController,
-                mHvacPanelController, mHvacPanelOverlayViewController,
-                mNotificationPanelViewController);
-
-        if (isSetUp) {
-            // We do not want the privacy chips or the profile picker to be clickable in
-            // unprovisioned mode.
-            mMicPanelController = setupSensorQcPanel(mMicPanelController, R.id.mic_privacy_chip,
-                    R.layout.qc_mic_panel);
-            mCameraPanelController = setupSensorQcPanel(mCameraPanelController,
-                    R.id.camera_privacy_chip, R.layout.qc_camera_panel);
-            setupProfilePanel();
-        }
-
-        return mTopView;
-    }
-
-    /** Gets the bottom navigation bar with the appropriate listeners set. */
+    @VisibleForTesting
     @Nullable
-    public CarSystemBarView getBottomBar(boolean isSetUp) {
-        if (!mShowBottom) {
-            return null;
-        }
-
-        mBottomView = mCarSystemBarViewFactory.getBottomBar(isSetUp);
-        setupBar(mBottomView, mBottomBarTouchListeners, mNotificationsShadeController,
-                mHvacPanelController, mHvacPanelOverlayViewController,
-                mNotificationPanelViewController);
-
-        return mBottomView;
+    ViewGroup getBarWindow(@SystemBarSide int side) {
+        return mSystemBarEnabledMap.get(side) ? mCarSystemBarViewFactory
+                .getSystemBarWindow(side) : null;
     }
 
-    /** Gets the left navigation bar with the appropriate listeners set. */
+    @VisibleForTesting
     @Nullable
-    public CarSystemBarView getLeftBar(boolean isSetUp) {
-        if (!mShowLeft) {
-            return null;
-        }
-
-        mLeftView = mCarSystemBarViewFactory.getLeftBar(isSetUp);
-        setupBar(mLeftView, mLeftBarTouchListeners, mNotificationsShadeController,
-                mHvacPanelController, mHvacPanelOverlayViewController,
-                mNotificationPanelViewController);
-        return mLeftView;
-    }
+    CarSystemBarViewController getBarViewController(@SystemBarSide int side, boolean isSetUp) {
 
-    /** Gets the right navigation bar with the appropriate listeners set. */
-    @Nullable
-    public CarSystemBarView getRightBar(boolean isSetUp) {
-        if (!mShowRight) {
+        if (!mSystemBarEnabledMap.get(side)) {
             return null;
         }
 
-        mRightView = mCarSystemBarViewFactory.getRightBar(isSetUp);
-        setupBar(mRightView, mRightBarTouchListeners, mNotificationsShadeController,
-                mHvacPanelController, mHvacPanelOverlayViewController,
-                mNotificationPanelViewController);
-        return mRightView;
-    }
+        CarSystemBarViewController viewController = mCarSystemBarViewFactory
+                .getSystemBarViewController(side, isSetUp);
+        Set<View.OnTouchListener> statusBarTouchListeners = mBarTouchListenersMap.get(side);
+        viewController.setSystemBarTouchListeners(
+                statusBarTouchListeners != null ? statusBarTouchListeners : new ArraySet<>());
 
-    private void setupBar(CarSystemBarView view, Set<View.OnTouchListener> statusBarTouchListeners,
-            NotificationsShadeController notifShadeController,
-            HvacPanelController hvacPanelController,
-            HvacPanelOverlayViewController hvacPanelOverlayViewController,
-            NotificationPanelViewController notificationPanelViewController) {
-        view.updateHomeButtonVisibility(CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
-        view.setStatusBarWindowTouchListeners(statusBarTouchListeners);
-        view.setNotificationsPanelController(notifShadeController);
-        view.registerNotificationPanelViewController(notificationPanelViewController);
-        view.setHvacPanelController(hvacPanelController);
-        view.registerHvacPanelOverlayViewController(hvacPanelOverlayViewController);
-        view.updateControlCenterButtonVisibility(CarSystemUIUserUtil.isMUMDSystemUI());
-        mButtonSelectionStateController.addAllButtonsWithSelectionState(view);
-        mButtonRoleHolderController.addAllButtonsWithRoleName(view);
-        mMicPrivacyChipViewControllerLazy.get().addPrivacyChipView(view);
-        mCameraPrivacyChipViewControllerLazy.get().addPrivacyChipView(view);
+        mSystemBarViewControllerMap.put(side, viewController);
+        return viewController;
     }
 
-    private StatusIconPanelViewController setupSensorQcPanel(
-            @Nullable StatusIconPanelViewController panelController, int chipId,
-            @LayoutRes int panelLayoutRes) {
-        if (panelController == null) {
-            View privacyChip = mTopView.findViewById(chipId);
-            if (privacyChip != null) {
-                panelController = mPanelControllerBuilderProvider.get()
-                        .setXOffset(mPrivacyChipXOffset)
-                        .setGravity(Gravity.TOP | Gravity.END)
-                        .build(privacyChip, panelLayoutRes, R.dimen.car_sensor_qc_panel_width);
-                panelController.init();
-            }
-        }
-        return panelController;
-    }
-
-    private void setupProfilePanel() {
-        View profilePickerView = mTopView.findViewById(R.id.user_name);
-        if (mProfilePanelController == null && profilePickerView != null) {
-            boolean profilePanelDisabledWhileDriving = mContext.getResources().getBoolean(
-                    R.bool.config_profile_panel_disabled_while_driving);
-            mProfilePanelController = mPanelControllerBuilderProvider.get()
-                    .setGravity(Gravity.TOP | Gravity.END)
-                    .setDisabledWhileDriving(profilePanelDisabledWhileDriving)
-                    .build(profilePickerView, R.layout.qc_profile_switcher,
-                            R.dimen.car_profile_quick_controls_panel_width);
-            mProfilePanelController.init();
-        }
-    }
-
-    /** Sets a touch listener for the top navigation bar. */
-    public void registerTopBarTouchListener(View.OnTouchListener listener) {
-        boolean setModified = mTopBarTouchListeners.add(listener);
-        if (setModified && mTopView != null) {
-            mTopView.setStatusBarWindowTouchListeners(mTopBarTouchListeners);
-        }
-    }
-
-    /** Sets a touch listener for the bottom navigation bar. */
-    public void registerBottomBarTouchListener(View.OnTouchListener listener) {
-        boolean setModified = mBottomBarTouchListeners.add(listener);
-        if (setModified && mBottomView != null) {
-            mBottomView.setStatusBarWindowTouchListeners(mBottomBarTouchListeners);
-        }
-    }
-
-    /** Sets a touch listener for the left navigation bar. */
-    public void registerLeftBarTouchListener(View.OnTouchListener listener) {
-        boolean setModified = mLeftBarTouchListeners.add(listener);
-        if (setModified && mLeftView != null) {
-            mLeftView.setStatusBarWindowTouchListeners(mLeftBarTouchListeners);
-        }
-    }
-
-    /** Sets a touch listener for the right navigation bar. */
-    public void registerRightBarTouchListener(View.OnTouchListener listener) {
-        boolean setModified = mRightBarTouchListeners.add(listener);
-        if (setModified && mRightView != null) {
-            mRightView.setStatusBarWindowTouchListeners(mRightBarTouchListeners);
-        }
-    }
-
-    /** Sets a notification controller which toggles the notification panel. */
-    public void registerNotificationController(
-            NotificationsShadeController notificationsShadeController) {
-        mNotificationsShadeController = notificationsShadeController;
-        if (mTopView != null) {
-            mTopView.setNotificationsPanelController(mNotificationsShadeController);
-        }
-        if (mBottomView != null) {
-            mBottomView.setNotificationsPanelController(mNotificationsShadeController);
-        }
-        if (mLeftView != null) {
-            mLeftView.setNotificationsPanelController(mNotificationsShadeController);
-        }
-        if (mRightView != null) {
-            mRightView.setNotificationsPanelController(mNotificationsShadeController);
-        }
-    }
-
-    /** Sets the NotificationPanelViewController for views to listen to the panel's state. */
-    public void registerNotificationPanelViewController(
-            NotificationPanelViewController notificationPanelViewController) {
-        mNotificationPanelViewController = notificationPanelViewController;
-        if (mTopView != null) {
-            mTopView.registerNotificationPanelViewController(mNotificationPanelViewController);
-        }
-        if (mBottomView != null) {
-            mBottomView.registerNotificationPanelViewController(mNotificationPanelViewController);
-        }
-        if (mLeftView != null) {
-            mLeftView.registerNotificationPanelViewController(mNotificationPanelViewController);
-        }
-        if (mRightView != null) {
-            mRightView.registerNotificationPanelViewController(mNotificationPanelViewController);
-        }
-    }
-
-    /** Sets an HVAC controller which toggles the HVAC panel. */
-    public void registerHvacPanelController(HvacPanelController hvacPanelController) {
-        mHvacPanelController = hvacPanelController;
-        if (mTopView != null) {
-            mTopView.setHvacPanelController(mHvacPanelController);
-        }
-        if (mBottomView != null) {
-            mBottomView.setHvacPanelController(mHvacPanelController);
-        }
-        if (mLeftView != null) {
-            mLeftView.setHvacPanelController(mHvacPanelController);
-        }
-        if (mRightView != null) {
-            mRightView.setHvacPanelController(mHvacPanelController);
-        }
-    }
-
-    /** Sets the HVACPanelOverlayViewController for views to listen to the panel's state. */
-    public void registerHvacPanelOverlayViewController(
-            HvacPanelOverlayViewController hvacPanelOverlayViewController) {
-        mHvacPanelOverlayViewController = hvacPanelOverlayViewController;
-        if (mTopView != null) {
-            mTopView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
-        }
-        if (mBottomView != null) {
-            mBottomView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
-        }
-        if (mLeftView != null) {
-            mLeftView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
+    @Override
+    public void registerBarTouchListener(@SystemBarSide int side, View.OnTouchListener listener) {
+        if (mBarTouchListenersMap.get(side) == null) {
+            mBarTouchListenersMap.put(side, new ArraySet<>());
         }
-        if (mRightView != null) {
-            mRightView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
+        boolean setModified = mBarTouchListenersMap.get(side).add(listener);
+        if (setModified && mSystemBarViewControllerMap.get(side) != null) {
+            mSystemBarViewControllerMap.get(side)
+                    .setSystemBarTouchListeners(mBarTouchListenersMap.get(side));
         }
     }
 
@@ -984,24 +534,19 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
      */
     @Override
     public void showAllNavigationButtons() {
-        showAllNavigationButtons(true);
+        showAllNavigationButtons(isDeviceSetupForUser());
     }
 
     // TODO(b/368407601): can we remove this?
-    protected void showAllNavigationButtons(boolean isSetup) {
+    @VisibleForTesting
+    void showAllNavigationButtons(boolean isSetup) {
         checkAllBars(isSetup);
-        if (mTopView != null) {
-            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
-        }
-        if (mBottomView != null) {
-            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
-        }
-        if (mLeftView != null) {
-            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
-        }
-        if (mRightView != null) {
-            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
-        }
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            if (mSystemBarViewControllerMap.get(side) != null) {
+                mSystemBarViewControllerMap.get(side)
+                        .showButtonsOfType(BUTTON_TYPE_NAVIGATION);
+            }
+        });
     }
 
     /**
@@ -1010,25 +555,19 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
      */
     @Override
     public void showAllKeyguardButtons() {
-        showAllKeyguardButtons(true);
+        showAllKeyguardButtons(isDeviceSetupForUser());
     }
 
-    @VisibleForTesting
     // TODO(b/368407601): can we remove this?
-    protected void showAllKeyguardButtons(boolean isSetUp) {
+    @VisibleForTesting
+    void showAllKeyguardButtons(boolean isSetUp) {
         checkAllBars(isSetUp);
-        if (mTopView != null) {
-            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
-        }
-        if (mBottomView != null) {
-            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
-        }
-        if (mLeftView != null) {
-            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
-        }
-        if (mRightView != null) {
-            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
-        }
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            if (mSystemBarViewControllerMap.get(side) != null) {
+                mSystemBarViewControllerMap.get(side)
+                        .showButtonsOfType(BUTTON_TYPE_KEYGUARD);
+            }
+        });
     }
 
     /**
@@ -1037,134 +576,46 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
      */
     @Override
     public void showAllOcclusionButtons() {
-        showAllOcclusionButtons(true);
+        showAllOcclusionButtons(isDeviceSetupForUser());
     }
 
     // TODO(b/368407601): can we remove this?
-    protected void showAllOcclusionButtons(boolean isSetUp) {
-        checkAllBars(isSetUp);
-        if (mTopView != null) {
-            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
-        }
-        if (mBottomView != null) {
-            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
-        }
-        if (mLeftView != null) {
-            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
-        }
-        if (mRightView != null) {
-            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
-        }
-    }
-
-    /** Toggles whether the notifications icon has an unseen indicator or not. */
-    public void toggleAllNotificationsUnseenIndicator(boolean isSetUp, boolean hasUnseen) {
+    @VisibleForTesting
+    void showAllOcclusionButtons(boolean isSetUp) {
         checkAllBars(isSetUp);
-        if (mTopView != null) {
-            mTopView.toggleNotificationUnseenIndicator(hasUnseen);
-        }
-        if (mBottomView != null) {
-            mBottomView.toggleNotificationUnseenIndicator(hasUnseen);
-        }
-        if (mLeftView != null) {
-            mLeftView.toggleNotificationUnseenIndicator(hasUnseen);
-        }
-        if (mRightView != null) {
-            mRightView.toggleNotificationUnseenIndicator(hasUnseen);
-        }
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            if (mSystemBarViewControllerMap.get(side) != null) {
+                mSystemBarViewControllerMap.get(side)
+                        .showButtonsOfType(BUTTON_TYPE_OCCLUSION);
+            }
+        });
     }
 
     private void checkAllBars(boolean isSetUp) {
-        mTopView = getTopBar(isSetUp);
-        mBottomView = getBottomBar(isSetUp);
-        mLeftView = getLeftBar(isSetUp);
-        mRightView = getRightBar(isSetUp);
-    }
-
-    private List<CarSystemBarView> getAllAvailableSystemBarViews() {
-        List<CarSystemBarView> barViews = new ArrayList<>();
-        if (mTopView != null) {
-            barViews.add(mTopView);
-        }
-        if (mBottomView != null) {
-            barViews.add(mBottomView);
-        }
-        if (mLeftView != null) {
-            barViews.add(mLeftView);
-        }
-        if (mRightView != null) {
-            barViews.add(mRightView);
-        }
-        return barViews;
-    }
-
-    /** Resets the cached Views. */
-    protected void resetViewCache() {
-        mCarSystemBarViewFactory.resetSystemBarViewCache();
+        mSystemBarViewControllerMap.clear();
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            mSystemBarViewControllerMap.put(side, getBarViewController(side, isSetUp));
+        });
     }
 
     /**
      * Invalidate SystemBarConfigs and fetch again from Resources.
      * TODO(): b/260206944, Can remove this after we have a fix for overlaid resources not applied.
      */
-    protected void resetSystemBarConfigs() {
+    @VisibleForTesting
+    void resetSystemBarConfigs() {
         mSystemBarConfigs.resetSystemBarConfigs();
         mCarSystemBarViewFactory.resetSystemBarWindowCache();
         readConfigs();
     }
 
-    /** Stores the ID of the View that is currently focused and hides the focus. */
-    protected void cacheAndHideFocus() {
-        mTopFocusedViewId = cacheAndHideFocus(mTopView);
-        if (mTopFocusedViewId != View.NO_ID) return;
-        mBottomFocusedViewId = cacheAndHideFocus(mBottomView);
-        if (mBottomFocusedViewId != View.NO_ID) return;
-        mLeftFocusedViewId = cacheAndHideFocus(mLeftView);
-        if (mLeftFocusedViewId != View.NO_ID) return;
-        mRightFocusedViewId = cacheAndHideFocus(mRightView);
-    }
-
-    @VisibleForTesting
-    int cacheAndHideFocus(@Nullable View rootView) {
-        if (rootView == null) return View.NO_ID;
-        View focusedView = rootView.findFocus();
-        if (focusedView == null || focusedView instanceof FocusParkingView) return View.NO_ID;
-        int focusedViewId = focusedView.getId();
-        ViewUtils.hideFocus(rootView);
-        return focusedViewId;
-    }
-
-    /** Requests focus on the View that matches the cached ID. */
-    protected void restoreFocus() {
-        if (restoreFocus(mTopView, mTopFocusedViewId)) return;
-        if (restoreFocus(mBottomView, mBottomFocusedViewId)) return;
-        if (restoreFocus(mLeftView, mLeftFocusedViewId)) return;
-        restoreFocus(mRightView, mRightFocusedViewId);
-    }
-
-    private boolean restoreFocus(@Nullable View rootView, @IdRes int viewToFocusId) {
-        if (rootView == null || viewToFocusId == View.NO_ID) return false;
-        View focusedView = rootView.findViewById(viewToFocusId);
-        if (focusedView == null) return false;
-        focusedView.requestFocus();
-        return true;
-    }
-
     protected void updateKeyboardVisibility(boolean isKeyboardVisible) {
-        if (mHideTopBarForKeyboard) {
-            setTopWindowVisibility(isKeyboardVisible ? View.GONE : View.VISIBLE);
-        }
-
-        if (mHideBottomBarForKeyboard) {
-            setBottomWindowVisibility(isKeyboardVisible ? View.GONE : View.VISIBLE);
-        }
-
-        if (mHideLeftBarForKeyboard) {
-            setLeftWindowVisibility(isKeyboardVisible ? View.GONE : View.VISIBLE);
-        }
-        if (mHideRightBarForKeyboard) {
-            setRightWindowVisibility(isKeyboardVisible ? View.GONE : View.VISIBLE);
-        }
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            if (mHideBarForKeyboardMap.get(side)) {
+                setWindowVisibility(getBarWindow(side),
+                        isKeyboardVisible ? View.GONE : View.VISIBLE);
+            }
+        });
     }
 
     protected void createSystemBar() {
@@ -1206,130 +657,60 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     }
 
     private void buildNavBarWindows() {
-        mTopSystemBarWindow = getTopWindow();
-        mBottomSystemBarWindow = getBottomWindow();
-        mLeftSystemBarWindow = getLeftWindow();
-        mRightSystemBarWindow = getRightWindow();
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            mSystemBarWindowMap.put(side, getBarWindow(side));
+        });
 
         if (mDisplayCompatToolbarController != null) {
             if (mSystemBarConfigs
                     .isLeftDisplayCompatToolbarEnabled()) {
-                mDisplayCompatToolbarController.init(mLeftSystemBarWindow);
+                mDisplayCompatToolbarController.init(mSystemBarWindowMap.get(LEFT));
             } else if (mSystemBarConfigs
                     .isRightDisplayCompatToolbarEnabled()) {
-                mDisplayCompatToolbarController.init(mRightSystemBarWindow);
+                mDisplayCompatToolbarController.init(mSystemBarWindowMap.get(RIGHT));
             }
         }
     }
 
     private void buildNavBarContent() {
-        mTopView = getTopBar(isDeviceSetupForUser());
-        if (mTopView != null) {
-            mSystemBarConfigs.insetSystemBar(TOP, mTopView);
-            mHvacController.registerHvacViews(mTopView);
-            mTopSystemBarWindow.addView(mTopView);
-        }
-
-        mBottomView = getBottomBar(isDeviceSetupForUser());
-        if (mBottomView != null) {
-            mSystemBarConfigs.insetSystemBar(BOTTOM, mBottomView);
-            mHvacController.registerHvacViews(mBottomView);
-            mBottomSystemBarWindow.addView(mBottomView);
-        }
-
-        mLeftView = getLeftBar(isDeviceSetupForUser());
-        if (mLeftView != null) {
-            mSystemBarConfigs.insetSystemBar(LEFT, mLeftView);
-            mHvacController.registerHvacViews(mLeftView);
-            mLeftSystemBarWindow.addView(mLeftView);
-        }
-
-        mRightView = getRightBar(isDeviceSetupForUser());
-        if (mRightView != null) {
-            mSystemBarConfigs.insetSystemBar(RIGHT, mRightView);
-            mHvacController.registerHvacViews(mRightView);
-            mRightSystemBarWindow.addView(mRightView);
-        }
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            CarSystemBarViewController viewController = getBarViewController(side,
+                    isDeviceSetupForUser());
+            ViewGroup systemBarWindow = mSystemBarWindowMap.get(side);
+            if (viewController != null && systemBarWindow != null) {
+                systemBarWindow.addView(viewController.getView());
+            }
+        });
     }
 
     private void attachNavBarWindows() {
-        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(this::attachNavBarBySide);
-    }
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            ViewGroup barWindow = mSystemBarWindowMap.get(side);
+            boolean isBarAttached = mSystemBarAttachedMap.get(side);
+            boolean isBarEnabled = mSystemBarConfigs.getEnabledStatusBySide(side);
+            if (DEBUG) {
+                Log.d(TAG, "Side = " + side
+                        + ", SystemBarWindow = " + barWindow
+                        + ", SystemBarAttached=" + isBarAttached
+                        + ", enabled=" + isBarEnabled);
+            }
+            if (barWindow != null && !isBarAttached && isBarEnabled) {
+                WindowManager wm = getWindowManagerForSide(side);
+                if (wm != null) {
+                    wm.addView(barWindow, mSystemBarConfigs.getLayoutParamsBySide(side));
+                    mSystemBarAttachedMap.put(side, true);
+                }
 
-    @VisibleForTesting
-    ViewGroup getSystemBarWindowBySide(int side) {
-        switch (side) {
-            case TOP:
-                return mTopSystemBarWindow;
-            case BOTTOM:
-                return mBottomSystemBarWindow;
-            case LEFT:
-                return mLeftSystemBarWindow;
-            case RIGHT:
-                return mRightSystemBarWindow;
-            default:
-                return null;
-        }
+            }
+        });
     }
 
-    private void attachNavBarBySide(int side) {
-        switch (side) {
-            case TOP:
-                if (DEBUG) {
-                    Log.d(TAG, "mTopSystemBarWindow = " + mTopSystemBarWindow
-                            + ", mTopSystemBarAttached=" + mTopSystemBarAttached
-                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(TOP));
-                }
-                if (mTopSystemBarWindow != null && !mTopSystemBarAttached
-                        && mSystemBarConfigs.getEnabledStatusBySide(TOP)) {
-                    mWindowManager.addView(mTopSystemBarWindow,
-                            mSystemBarConfigs.getLayoutParamsBySide(TOP));
-                    mTopSystemBarAttached = true;
-                }
-                break;
-            case BOTTOM:
-                if (DEBUG) {
-                    Log.d(TAG, "mBottomSystemBarWindow = " + mBottomSystemBarWindow
-                            + ", mBottomSystemBarAttached=" + mBottomSystemBarAttached
-                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(BOTTOM));
-                }
-                if (mBottomSystemBarWindow != null && !mBottomSystemBarAttached
-                        && mSystemBarConfigs.getEnabledStatusBySide(BOTTOM)) {
-                    mWindowManager.addView(mBottomSystemBarWindow,
-                            mSystemBarConfigs.getLayoutParamsBySide(BOTTOM));
-                    mBottomSystemBarAttached = true;
-                }
-                break;
-            case LEFT:
-                if (DEBUG) {
-                    Log.d(TAG, "mLeftSystemBarWindow = " + mLeftSystemBarWindow
-                            + ", mLeftSystemBarAttached=" + mLeftSystemBarAttached
-                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(LEFT));
-                }
-                if (mLeftSystemBarWindow != null && !mLeftSystemBarAttached
-                        && mSystemBarConfigs.getEnabledStatusBySide(LEFT)) {
-                    mWindowManager.addView(mLeftSystemBarWindow,
-                            mSystemBarConfigs.getLayoutParamsBySide(LEFT));
-                    mLeftSystemBarAttached = true;
-                }
-                break;
-            case RIGHT:
-                if (DEBUG) {
-                    Log.d(TAG, "mRightSystemBarWindow = " + mRightSystemBarWindow
-                            + ", mRightSystemBarAttached=" + mRightSystemBarAttached
-                            + ", "
-                            + "enabled=" + mSystemBarConfigs.getEnabledStatusBySide(RIGHT));
-                }
-                if (mRightSystemBarWindow != null && !mRightSystemBarAttached
-                        && mSystemBarConfigs.getEnabledStatusBySide(RIGHT)) {
-                    mWindowManager.addView(mRightSystemBarWindow,
-                            mSystemBarConfigs.getLayoutParamsBySide(RIGHT));
-                    mRightSystemBarAttached = true;
-                }
-                break;
-            default:
-                return;
+    private WindowManager getWindowManagerForSide(@SystemBarSide int side) {
+        Context windowContext = mSystemBarConfigs.getWindowContextBySide(side);
+        if (windowContext == null) {
+            return null;
         }
+        return windowContext.getSystemService(WindowManager.class);
     }
 
     private void registerOverlayChangeBroadcastReceiver() {
@@ -1346,9 +727,11 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         BroadcastReceiver receiver = new BroadcastReceiver() {
             @Override
             public void onReceive(Context context, Intent intent) {
-                if (mTopSystemBarAttached || mBottomSystemBarAttached || mLeftSystemBarAttached
-                        || mRightSystemBarAttached) {
-                    restartSystemBars();
+                for (int i = 0; i < mSystemBarAttachedMap.size(); i++) {
+                    if (mSystemBarAttachedMap.valueAt(i)) {
+                        restartSystemBars();
+                        break;
+                    }
                 }
             }
         };
@@ -1377,11 +760,8 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
                 isProvisionedStateChange);
 
         if (!isProvisionedStateChange) {
-            resetViewCache();
+            mCarSystemBarViewFactory.resetSystemBarViewCache();
         }
-        // remove and reattach all components such that we don't keep a reference to unused ui
-        // elements
-        removeAll();
         clearSystemBarWindow(/* removeUnusedWindow= */ false);
 
         buildNavBarContent();
@@ -1467,7 +847,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         mCarSystemBarRestartTracker.notifyPendingRestart(/* recreateWindows= */ true,
                 /* provisionedStateChanged= */ false);
 
-        removeAll();
         resetSystemBarConfigs();
         clearSystemBarWindow(/* removeUnusedWindow= */ true);
         buildNavBarWindows();
@@ -1479,45 +858,20 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     }
 
     private void clearSystemBarWindow(boolean removeUnusedWindow) {
-        if (mTopSystemBarWindow != null) {
-            mTopSystemBarWindow.removeAllViews();
-            mHvacController.unregisterViews(mTopView);
-            if (removeUnusedWindow) {
-                mWindowManager.removeViewImmediate(mTopSystemBarWindow);
-                mTopSystemBarAttached = false;
-            }
-            mTopView = null;
-        }
-
-        if (mBottomSystemBarWindow != null) {
-            mBottomSystemBarWindow.removeAllViews();
-            mHvacController.unregisterViews(mBottomView);
-            if (removeUnusedWindow) {
-                mWindowManager.removeViewImmediate(mBottomSystemBarWindow);
-                mBottomSystemBarAttached = false;
-            }
-            mBottomView = null;
-        }
-
-        if (mLeftSystemBarWindow != null) {
-            mLeftSystemBarWindow.removeAllViews();
-            mHvacController.unregisterViews(mLeftView);
-            if (removeUnusedWindow) {
-                mWindowManager.removeViewImmediate(mLeftSystemBarWindow);
-                mLeftSystemBarAttached = false;
-            }
-            mLeftView = null;
-        }
-
-        if (mRightSystemBarWindow != null) {
-            mRightSystemBarWindow.removeAllViews();
-            mHvacController.unregisterViews(mRightView);
-            if (removeUnusedWindow) {
-                mWindowManager.removeViewImmediate(mRightSystemBarWindow);
-                mRightSystemBarAttached = false;
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
+            ViewGroup barWindow = getBarWindow(side);
+            if (barWindow != null) {
+                barWindow.removeAllViews();
+                if (removeUnusedWindow) {
+                    WindowManager wm = getWindowManagerForSide(side);
+                    if (wm != null) {
+                        wm.removeViewImmediate(barWindow);
+                    }
+                    mSystemBarAttachedMap.put(side, false);
+                }
+                mSystemBarViewControllerMap.remove(side);
             }
-            mRightView = null;
-        }
+        });
     }
 
     @VisibleForTesting
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarModule.java b/src/com/android/systemui/car/systembar/CarSystemBarModule.java
index e42fad7d..4f80be71 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarModule.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarModule.java
@@ -16,6 +16,11 @@
 
 package com.android.systemui.car.systembar;
 
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+
 import android.annotation.Nullable;
 import android.content.Context;
 import android.os.Handler;
@@ -28,8 +33,10 @@ import com.android.systemui.R;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.dagger.CarSysUIDynamicOverride;
 import com.android.systemui.car.displaycompat.ToolbarController;
-import com.android.systemui.car.hvac.HvacController;
+import com.android.systemui.car.hvac.HvacButtonController;
+import com.android.systemui.car.hvac.TemperatureControlViewController;
 import com.android.systemui.car.keyguard.KeyguardSystemBarPresenter;
+import com.android.systemui.car.notification.NotificationButtonController;
 import com.android.systemui.car.statusicon.StatusIconPanelViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
@@ -53,6 +60,7 @@ import dagger.Lazy;
 import dagger.Module;
 import dagger.Provides;
 import dagger.multibindings.ClassKey;
+import dagger.multibindings.IntKey;
 import dagger.multibindings.IntoMap;
 import dagger.multibindings.IntoSet;
 import dagger.multibindings.Multibinds;
@@ -152,7 +160,6 @@ public abstract class CarSystemBarModule {
             IStatusBarService barService,
             Lazy<KeyguardStateController> keyguardStateControllerLazy,
             Lazy<PhoneStatusBarPolicy> iconPolicyLazy,
-            HvacController hvacController,
             ConfigurationController configurationController,
             CarSystemBarRestartTracker restartTracker,
             DisplayTracker displayTracker,
@@ -169,23 +176,18 @@ public abstract class CarSystemBarModule {
 
         if (isSecondaryMUMDSystemUI && isSecondaryUserRROsEnabled) {
             return new MDSystemBarsControllerImpl(iWindowManager, mainHandler, context, userTracker,
-                    carSystemBarViewFactory, buttonSelectionStateController,
-                    micPrivacyChipViewControllerLazy, cameraPrivacyChipViewControllerLazy,
-                    buttonRoleHolderController, systemBarConfigs, panelControllerBuilderProvider,
-                    lightBarController, darkIconDispatcher, windowManager,
-                    deviceProvisionedController, commandQueue, autoHideController,
-                    buttonSelectionStateListener, mainExecutor, barService,
-                    keyguardStateControllerLazy, iconPolicyLazy, hvacController,
-                    configurationController, restartTracker, displayTracker, toolbarController);
-        } else {
-            return new CarSystemBarControllerImpl(context, userTracker, carSystemBarViewFactory,
-                    buttonSelectionStateController, micPrivacyChipViewControllerLazy,
-                    cameraPrivacyChipViewControllerLazy, buttonRoleHolderController,
-                    systemBarConfigs, panelControllerBuilderProvider, lightBarController,
+                    carSystemBarViewFactory, systemBarConfigs, lightBarController,
                     darkIconDispatcher, windowManager, deviceProvisionedController, commandQueue,
                     autoHideController, buttonSelectionStateListener, mainExecutor, barService,
-                    keyguardStateControllerLazy, iconPolicyLazy, hvacController,
-                    configurationController, restartTracker, displayTracker, toolbarController);
+                    keyguardStateControllerLazy, iconPolicyLazy, configurationController,
+                    restartTracker, displayTracker, toolbarController);
+        } else {
+            return new CarSystemBarControllerImpl(context, userTracker, carSystemBarViewFactory,
+                    systemBarConfigs, lightBarController, darkIconDispatcher, windowManager,
+                    deviceProvisionedController, commandQueue, autoHideController,
+                    buttonSelectionStateListener, mainExecutor, barService,
+                    keyguardStateControllerLazy, iconPolicyLazy, configurationController,
+                    restartTracker, displayTracker, toolbarController);
         }
     }
 
@@ -240,7 +242,7 @@ public abstract class CarSystemBarModule {
     /** Injects KeyguardSystemBarPresenter */
     @SysUISingleton
     @Provides
-    static Optional<KeyguardSystemBarPresenter> bindKeyguardSystemBarPresenter(
+    static Optional<KeyguardSystemBarPresenter> provideKeyguardSystemBarPresenter(
              CarSystemBarController controller) {
         if (controller instanceof KeyguardSystemBarPresenter) {
             return Optional.of((KeyguardSystemBarPresenter) controller);
@@ -255,4 +257,93 @@ public abstract class CarSystemBarModule {
     @ClassKey(DebugPanelButtonViewController.class)
     public abstract CarSystemBarElementController.Factory bindDebugPanelButtonViewController(
             DebugPanelButtonViewController.Factory factory);
+
+    /** Injects CarSystemBarViewFactory */
+    @SysUISingleton
+    @Binds
+    public abstract CarSystemBarViewFactory bindCarSystemBarViewFactory(
+            CarSystemBarViewFactoryImpl impl);
+
+    /** Injects CarSystemBarViewController for @SystemBarSide LEFT */
+    @Binds
+    @IntoMap
+    @IntKey(LEFT)
+    public abstract CarSystemBarViewControllerFactory bindLeftCarSystemBarViewFactory(
+            CarSystemBarViewControllerImpl.Factory factory);
+
+    /** Injects CarSystemBarViewController for @SystemBarSide TOP */
+    @Binds
+    @IntoMap
+    @IntKey(TOP)
+    public abstract CarSystemBarViewControllerFactory bindTopCarSystemBarViewFactory(
+            CarTopSystemBarViewController.Factory factory);
+
+    /** Injects CarSystemBarViewController for @SystemBarSide RIGHT */
+    @Binds
+    @IntoMap
+    @IntKey(RIGHT)
+    public abstract CarSystemBarViewControllerFactory bindRightCarSystemBarViewFactory(
+            CarSystemBarViewControllerImpl.Factory factory);
+
+    /** Injects CarSystemBarViewController for @SystemBarSide BOTTOM */
+    @Binds
+    @IntoMap
+    @IntKey(BOTTOM)
+    public abstract CarSystemBarViewControllerFactory bindBottomCarSystemBarViewFactory(
+            CarSystemBarViewControllerImpl.Factory factory);
+
+    /** Injects CarSystemBarButtonController */
+    @Binds
+    @IntoMap
+    @ClassKey(CarSystemBarButtonController.class)
+    public abstract CarSystemBarElementController.Factory bindCarSystemBarButtonControllerFactory(
+            CarSystemBarButtonController.Factory factory);
+
+    /** Injects NotificationButtonController */
+    @Binds
+    @IntoMap
+    @ClassKey(NotificationButtonController.class)
+    public abstract CarSystemBarElementController.Factory bindNotificationButtonControllerFactory(
+            NotificationButtonController.Factory factory);
+
+    /** Injects HvacButtonController */
+    @Binds
+    @IntoMap
+    @ClassKey(HvacButtonController.class)
+    public abstract CarSystemBarElementController.Factory bindHvacButtonControllerFactory(
+            HvacButtonController.Factory factory);
+
+    /** Injects TemperatureControlViewController */
+    @Binds
+    @IntoMap
+    @ClassKey(TemperatureControlViewController.class)
+    public abstract CarSystemBarElementController.Factory
+            bindTemperatureControlViewControllerFactory(
+                    TemperatureControlViewController.Factory factory);
+
+    /** Injects HomeButtonController */
+    @Binds
+    @IntoMap
+    @ClassKey(HomeButtonController.class)
+    public abstract CarSystemBarElementController.Factory bindHomeButtonControllerFactory(
+            HomeButtonController.Factory factory);
+
+    /** Injects PassengerHomeButtonController */
+    @Binds
+    @IntoMap
+    @ClassKey(PassengerHomeButtonController.class)
+    public abstract CarSystemBarElementController.Factory bindPassengerHomeButtonControllerFactory(
+            PassengerHomeButtonController.Factory factory);
+
+    /** Injects ControlCenterButtonController */
+    @Binds
+    @IntoMap
+    @ClassKey(ControlCenterButtonController.class)
+    public abstract CarSystemBarElementController.Factory bindControlCenterButtonControllerFactory(
+            ControlCenterButtonController.Factory factory);
+
+    /** Injects SystemBarConfigs */
+    @SysUISingleton
+    @Binds
+    public abstract SystemBarConfigs bindSystemBarConfigs(SystemBarConfigsImpl impl);
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarView.java b/src/com/android/systemui/car/systembar/CarSystemBarView.java
index 8871bc40..97fa5d00 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarView.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarView.java
@@ -16,29 +16,10 @@
 
 package com.android.systemui.car.systembar;
 
-import android.annotation.IntDef;
-import android.annotation.Nullable;
 import android.content.Context;
 import android.util.AttributeSet;
-import android.util.Log;
-import android.view.MotionEvent;
-import android.view.View;
-import android.view.ViewGroup;
 import android.widget.LinearLayout;
 
-import com.android.systemui.R;
-import com.android.systemui.car.hvac.HvacPanelController;
-import com.android.systemui.car.hvac.HvacPanelOverlayViewController;
-import com.android.systemui.car.hvac.HvacView;
-import com.android.systemui.car.hvac.TemperatureControlView;
-import com.android.systemui.car.notification.NotificationPanelViewController;
-import com.android.systemui.car.notification.NotificationsShadeController;
-import com.android.systemui.settings.UserTracker;
-
-import java.lang.annotation.ElementType;
-import java.lang.annotation.Target;
-import java.util.Set;
-
 /**
  * A custom system bar for the automotive use case.
  * <p>
@@ -47,318 +28,7 @@ import java.util.Set;
  */
 public class CarSystemBarView extends LinearLayout {
 
-    @IntDef(value = {BUTTON_TYPE_NAVIGATION, BUTTON_TYPE_KEYGUARD, BUTTON_TYPE_OCCLUSION})
-    @Target({ElementType.TYPE_PARAMETER, ElementType.TYPE_USE})
-    private @interface ButtonsType {
-    }
-
-    private static final String TAG = CarSystemBarView.class.getSimpleName();
-    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
-
-    public static final int BUTTON_TYPE_NAVIGATION = 0;
-    public static final int BUTTON_TYPE_KEYGUARD = 1;
-    public static final int BUTTON_TYPE_OCCLUSION = 2;
-
-    private final boolean mConsumeTouchWhenPanelOpen;
-    private final boolean mButtonsDraggable;
-    private CarSystemBarButton mHomeButton;
-    private CarSystemBarButton mPassengerHomeButton;
-    private View mNavButtons;
-    private CarSystemBarButton mNotificationsButton;
-    private CarSystemBarButton mHvacButton;
-    private HvacView mDriverHvacView;
-    private HvacView mPassengerHvacView;
-    private NotificationsShadeController mNotificationsShadeController;
-    private HvacPanelController mHvacPanelController;
-    private View mLockScreenButtons;
-    private View mOcclusionButtons;
-    // used to wire in open/close gestures for overlay panels
-    private Set<OnTouchListener> mStatusBarWindowTouchListeners;
-    private HvacPanelOverlayViewController mHvacPanelOverlayViewController;
-    private NotificationPanelViewController mNotificationPanelViewController;
-    private CarSystemBarButton mControlCenterButton;
-
     public CarSystemBarView(Context context, AttributeSet attrs) {
         super(context, attrs);
-        mConsumeTouchWhenPanelOpen = getResources().getBoolean(
-                R.bool.config_consumeSystemBarTouchWhenNotificationPanelOpen);
-        mButtonsDraggable = getResources().getBoolean(R.bool.config_systemBarButtonsDraggable);
-    }
-
-    @Override
-    public void onFinishInflate() {
-        mHomeButton = findViewById(R.id.home);
-        mPassengerHomeButton = findViewById(R.id.passenger_home);
-        mNavButtons = findViewById(R.id.nav_buttons);
-        mLockScreenButtons = findViewById(R.id.lock_screen_nav_buttons);
-        mOcclusionButtons = findViewById(R.id.occlusion_buttons);
-        mNotificationsButton = findViewById(R.id.notifications);
-        mHvacButton = findViewById(R.id.hvac);
-        mDriverHvacView = findViewById(R.id.driver_hvac);
-        mPassengerHvacView = findViewById(R.id.passenger_hvac);
-        mControlCenterButton = findViewById(R.id.control_center_nav);
-        if (mNotificationsButton != null) {
-            mNotificationsButton.setOnClickListener(this::onNotificationsClick);
-        }
-        setupHvacButton();
-        // Needs to be clickable so that it will receive ACTION_MOVE events.
-        setClickable(true);
-        // Needs to not be focusable so rotary won't highlight the entire nav bar.
-        setFocusable(false);
-    }
-
-    void updateHomeButtonVisibility(boolean isPassenger) {
-        if (!isPassenger) {
-            return;
-        }
-        if (mPassengerHomeButton != null) {
-            if (mHomeButton != null) {
-                mHomeButton.setVisibility(GONE);
-            }
-            mPassengerHomeButton.setVisibility(VISIBLE);
-        }
-    }
-
-    void setupHvacButton() {
-        if (mHvacButton != null) {
-            mHvacButton.setOnClickListener(this::onHvacClick);
-        }
-
-        if (com.android.car.dockutil.Flags.dockFeature()) {
-            if (mDriverHvacView instanceof TemperatureControlView) {
-                ((TemperatureControlView) mDriverHvacView).setTemperatureTextClickListener(
-                        this::onHvacClick);
-            }
-            if (mPassengerHvacView instanceof TemperatureControlView) {
-                ((TemperatureControlView) mPassengerHvacView).setTemperatureTextClickListener(
-                        this::onHvacClick);
-            }
-        }
-    }
-
-    void setupSystemBarButtons(UserTracker userTracker) {
-        setupSystemBarButtons(this, userTracker);
-    }
-
-    private void setupSystemBarButtons(View v, UserTracker userTracker) {
-        if (v instanceof CarSystemBarButton) {
-            ((CarSystemBarButton) v).setUserTracker(userTracker);
-        } else if (v instanceof ViewGroup) {
-            ViewGroup viewGroup = (ViewGroup) v;
-            for (int i = 0; i < viewGroup.getChildCount(); i++) {
-                setupSystemBarButtons(viewGroup.getChildAt(i), userTracker);
-            }
-        }
-    }
-
-    void updateControlCenterButtonVisibility(boolean isMumd) {
-        if (mControlCenterButton != null) {
-            mControlCenterButton.setVisibility(isMumd ? VISIBLE : GONE);
-        }
-    }
-
-    // Used to forward touch events even if the touch was initiated from a child component
-    @Override
-    public boolean onInterceptTouchEvent(MotionEvent ev) {
-        if (mStatusBarWindowTouchListeners != null && !mStatusBarWindowTouchListeners.isEmpty()) {
-            if (!mButtonsDraggable) {
-                return false;
-            }
-            boolean shouldConsumeEvent = mNotificationsShadeController == null ? false
-                    : mNotificationsShadeController.isNotificationPanelOpen();
-
-            // Forward touch events to the status bar window so it can drag
-            // windows if required (ex. Notification shade)
-            triggerAllTouchListeners(this, ev);
-
-            if (mConsumeTouchWhenPanelOpen && shouldConsumeEvent) {
-                return true;
-            }
-        }
-        return super.onInterceptTouchEvent(ev);
-    }
-
-    /** Sets the notifications panel controller. */
-    public void setNotificationsPanelController(NotificationsShadeController controller) {
-        mNotificationsShadeController = controller;
-    }
-
-    /** Sets the HVAC panel controller. */
-    public void setHvacPanelController(HvacPanelController controller) {
-        mHvacPanelController = controller;
-    }
-
-    /** Gets the notifications panel controller. */
-    public NotificationsShadeController getNotificationsPanelController() {
-        return mNotificationsShadeController;
-    }
-
-    /** Gets the HVAC panel controller. */
-    public HvacPanelController getHvacPanelController() {
-        return mHvacPanelController;
-    }
-
-    /**
-     * Sets the touch listeners that will be called from onInterceptTouchEvent and onTouchEvent
-     *
-     * @param statusBarWindowTouchListeners List of listeners to call from touch and intercept touch
-     */
-    public void setStatusBarWindowTouchListeners(
-            Set<OnTouchListener> statusBarWindowTouchListeners) {
-        mStatusBarWindowTouchListeners = statusBarWindowTouchListeners;
-    }
-
-    /** Gets the touch listeners that will be called from onInterceptTouchEvent and onTouchEvent. */
-    public Set<OnTouchListener> getStatusBarWindowTouchListeners() {
-        return mStatusBarWindowTouchListeners;
-    }
-
-    @Override
-    public boolean onTouchEvent(MotionEvent event) {
-        triggerAllTouchListeners(this, event);
-        return super.onTouchEvent(event);
-    }
-
-    protected void onNotificationsClick(View v) {
-        if (mNotificationsButton != null
-                && mNotificationsButton.getDisabled()) {
-            mNotificationsButton.runOnClickWhileDisabled();
-            return;
-        }
-        if (mNotificationsShadeController != null) {
-            // If the notification shade is about to open, close the hvac panel
-            if (!mNotificationsShadeController.isNotificationPanelOpen()
-                    && mHvacPanelController != null
-                    && mHvacPanelController.isHvacPanelOpen()) {
-                mHvacPanelController.togglePanel();
-            }
-            mNotificationsShadeController.togglePanel();
-        }
-    }
-
-    protected void onHvacClick(View v) {
-        if (mHvacPanelController != null) {
-            // If the hvac panel is about to open, close the notification shade
-            if (!mHvacPanelController.isHvacPanelOpen()
-                    && mNotificationsShadeController != null
-                    && mNotificationsShadeController.isNotificationPanelOpen()) {
-                mNotificationsShadeController.togglePanel();
-            }
-            mHvacPanelController.togglePanel();
-        }
-    }
-
-    /**
-     * Shows buttons of the specified {@link ButtonsType}.
-     *
-     * NOTE: Only one type of buttons can be shown at a time, so showing buttons of one type will
-     * hide all buttons of other types.
-     *
-     * @param buttonsType
-     */
-    public void showButtonsOfType(@ButtonsType int buttonsType) {
-        switch(buttonsType) {
-            case BUTTON_TYPE_NAVIGATION:
-                setNavigationButtonsVisibility(View.VISIBLE);
-                setKeyguardButtonsVisibility(View.GONE);
-                setOcclusionButtonsVisibility(View.GONE);
-                break;
-            case BUTTON_TYPE_KEYGUARD:
-                setNavigationButtonsVisibility(View.GONE);
-                setKeyguardButtonsVisibility(View.VISIBLE);
-                setOcclusionButtonsVisibility(View.GONE);
-                break;
-            case BUTTON_TYPE_OCCLUSION:
-                setNavigationButtonsVisibility(View.GONE);
-                setKeyguardButtonsVisibility(View.GONE);
-                setOcclusionButtonsVisibility(View.VISIBLE);
-                break;
-        }
-    }
-
-    /**
-     * Sets the system bar view's disabled state and runnable when disabled.
-     */
-    public void setDisabledSystemBarButton(int viewId, boolean disabled, Runnable runnable,
-                @Nullable String buttonName) {
-        CarSystemBarButton button = findViewById(viewId);
-        if (button != null) {
-            if (DEBUG) {
-                Log.d(TAG, "setDisabledSystemBarButton for: " + buttonName + " to: " + disabled);
-            }
-            button.setDisabled(disabled, runnable);
-        }
-    }
-
-    /**
-     * Sets the system bar specific View container's visibility. ViewName is used just for
-     * debugging.
-     */
-    public void setVisibilityByViewId(int viewId, @Nullable String viewName,
-                @View.Visibility int visibility) {
-        View v = findViewById(viewId);
-        if (v != null) {
-            if (DEBUG) Log.d(TAG, "setVisibilityByViewId for: " + viewName + " to: " + visibility);
-            v.setVisibility(visibility);
-        }
-    }
-
-    /**
-     * Sets the HvacPanelOverlayViewController and adds HVAC button listeners
-     */
-    public void registerHvacPanelOverlayViewController(HvacPanelOverlayViewController controller) {
-        mHvacPanelOverlayViewController = controller;
-        if (mHvacPanelOverlayViewController != null && mHvacButton != null) {
-            mHvacPanelOverlayViewController.registerViewStateListener(mHvacButton);
-        }
-    }
-
-    /**
-     * Sets the NotificationPanelViewController and adds button listeners
-     */
-    public void registerNotificationPanelViewController(
-            NotificationPanelViewController controller) {
-        mNotificationPanelViewController = controller;
-        if (mNotificationPanelViewController != null && mNotificationsButton != null) {
-            mNotificationPanelViewController.registerViewStateListener(mNotificationsButton);
-        }
-    }
-
-    private void setNavigationButtonsVisibility(@View.Visibility int visibility) {
-        if (mNavButtons != null) {
-            mNavButtons.setVisibility(visibility);
-        }
-    }
-
-    private void setKeyguardButtonsVisibility(@View.Visibility int visibility) {
-        if (mLockScreenButtons != null) {
-            mLockScreenButtons.setVisibility(visibility);
-        }
-    }
-
-    private void setOcclusionButtonsVisibility(@View.Visibility int visibility) {
-        if (mOcclusionButtons != null) {
-            mOcclusionButtons.setVisibility(visibility);
-        }
-    }
-
-    private void triggerAllTouchListeners(View view, MotionEvent event) {
-        if (mStatusBarWindowTouchListeners == null) {
-            return;
-        }
-        for (OnTouchListener listener : mStatusBarWindowTouchListeners) {
-            listener.onTouch(view, event);
-        }
-    }
-
-    /**
-     * Toggles the notification unseen indicator on/off.
-     *
-     * @param hasUnseen true if the unseen notification count is great than 0.
-     */
-    public void toggleNotificationUnseenIndicator(Boolean hasUnseen) {
-        if (mNotificationsButton == null) return;
-
-        mNotificationsButton.setUnseen(hasUnseen);
     }
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarViewController.java b/src/com/android/systemui/car/systembar/CarSystemBarViewController.java
new file mode 100644
index 00000000..2987eef8
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/CarSystemBarViewController.java
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
+package com.android.systemui.car.systembar;
+
+import android.annotation.IntDef;
+import android.os.Bundle;
+import android.view.View;
+import android.view.ViewGroup;
+
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Target;
+import java.util.Set;
+
+/**
+ * A controller for initializing the system bar views.
+ */
+public interface CarSystemBarViewController {
+    @IntDef(value = {BUTTON_TYPE_NAVIGATION, BUTTON_TYPE_KEYGUARD, BUTTON_TYPE_OCCLUSION})
+    @Target({ElementType.TYPE_PARAMETER, ElementType.TYPE_USE})
+    @interface ButtonsType {
+    }
+    int BUTTON_TYPE_NAVIGATION = 0;
+    int BUTTON_TYPE_KEYGUARD = 1;
+    int BUTTON_TYPE_OCCLUSION = 2;
+
+    /**
+     * Call to initialize the internal state.
+     */
+    void init();
+
+    /**
+     * Call to save the internal state.
+     */
+    void onSaveInstanceState(Bundle outState);
+
+    /**
+     * Call to restore the internal state.
+     */
+    void onRestoreInstanceState(Bundle savedInstanceState);
+
+    /**
+     * Only visible so that this view can be attached to the window.
+     */
+    ViewGroup getView();
+
+    /**
+     * Sets the touch listeners that will be called from onInterceptTouchEvent and onTouchEvent
+     *
+     * @param statusBarWindowTouchListeners List of listeners to call from touch and intercept touch
+     */
+    void setSystemBarTouchListeners(Set<View.OnTouchListener> statusBarWindowTouchListeners);
+
+    /**
+     * Shows buttons of the specified {@link ButtonsType}.
+     *
+     * NOTE: Only one type of buttons can be shown at a time, so showing buttons of one type will
+     * hide all buttons of other types.
+     *
+     * @param buttonsType see {@link ButtonsType}
+     */
+    void showButtonsOfType(@ButtonsType int buttonsType);
+}
diff --git a/src/com/android/systemui/car/hvac/HvacPanelController.java b/src/com/android/systemui/car/systembar/CarSystemBarViewControllerFactory.java
similarity index 51%
rename from src/com/android/systemui/car/hvac/HvacPanelController.java
rename to src/com/android/systemui/car/systembar/CarSystemBarViewControllerFactory.java
index ba4a1624..731d0500 100644
--- a/src/com/android/systemui/car/hvac/HvacPanelController.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarViewControllerFactory.java
@@ -13,13 +13,19 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.systemui.car.hvac;
+package com.android.systemui.car.systembar;
 
-/** Interface for controlling the HVAC panel. */
-public interface HvacPanelController {
-    /** Toggles the visibility of the HVAC shade. */
-    void togglePanel();
+import android.view.ViewGroup;
 
-    /** Returns {@code true} if the panel is open. */
-    boolean isHvacPanelOpen();
+import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
+
+/**
+ * A controller for initializing the system bar views.
+ *
+ * @param <T> type of the controller that will be created by this factory. needs to conform to
+ * {@link CarSystemBarViewController} interface.
+ */
+public interface CarSystemBarViewControllerFactory<T extends CarSystemBarViewController> {
+    /** Create instance of CarSystemBarViewController for the system bar view */
+    T create(@SystemBarSide int side, ViewGroup view);
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java b/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java
new file mode 100644
index 00000000..1a2cdb47
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java
@@ -0,0 +1,314 @@
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
+package com.android.systemui.car.systembar;
+
+import android.annotation.Nullable;
+import android.content.Context;
+import android.os.Bundle;
+import android.view.MotionEvent;
+import android.view.View;
+import android.view.ViewGroup;
+import android.widget.FrameLayout;
+
+import androidx.annotation.IdRes;
+import androidx.annotation.VisibleForTesting;
+
+import com.android.car.ui.FocusParkingView;
+import com.android.car.ui.utils.ViewUtils;
+import com.android.systemui.Gefingerpoken;
+import com.android.systemui.R;
+import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
+import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
+import com.android.systemui.car.window.OverlayPanelViewController;
+import com.android.systemui.car.window.OverlayViewController;
+import com.android.systemui.car.window.OverlayVisibilityMediator;
+import com.android.systemui.settings.UserTracker;
+import com.android.systemui.util.ViewController;
+
+import dagger.Lazy;
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import java.util.Set;
+
+/**
+ * A controller for initializing the system bar views.
+ */
+public class CarSystemBarViewControllerImpl
+        extends ViewController<CarSystemBarViewControllerImpl.TouchInterceptingFrameLayout>
+        implements CarSystemBarViewController, Gefingerpoken {
+
+    private static final String LAST_FOCUSED_VIEW_ID = "last_focused_view_id";
+
+    protected final Context mContext;
+
+    private final UserTracker mUserTracker;
+    private final CarSystemBarElementInitializer mCarSystemBarElementInitializer;
+    private final SystemBarConfigs mSystemBarConfigs;
+    private final ButtonSelectionStateController mButtonSelectionStateController;
+    private final ButtonRoleHolderController mButtonRoleHolderController;
+    private final Lazy<MicPrivacyChipViewController> mMicPrivacyChipViewControllerLazy;
+    private final Lazy<CameraPrivacyChipViewController> mCameraPrivacyChipViewControllerLazy;
+    private final @SystemBarSide int mSide;
+    private final OverlayVisibilityMediator mOverlayVisibilityMediator;
+
+    private final boolean mConsumeTouchWhenPanelOpen;
+    private final boolean mButtonsDraggable;
+    private View mNavButtons;
+    private View mLockScreenButtons;
+    private View mOcclusionButtons;
+    // used to wire in open/close gestures for overlay panels
+    private Set<View.OnTouchListener> mSystemBarTouchListeners;
+
+    @AssistedInject
+    public CarSystemBarViewControllerImpl(Context context,
+            UserTracker userTracker,
+            CarSystemBarElementInitializer elementInitializer,
+            SystemBarConfigs systemBarConfigs,
+            ButtonRoleHolderController buttonRoleHolderController,
+            ButtonSelectionStateController buttonSelectionStateController,
+            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
+            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
+            OverlayVisibilityMediator overlayVisibilityMediator,
+            @Assisted @SystemBarSide int side,
+            @Assisted ViewGroup systemBarView) {
+        super(new TouchInterceptingFrameLayout(context, systemBarView));
+
+        mContext = context;
+        mUserTracker = userTracker;
+        mCarSystemBarElementInitializer = elementInitializer;
+        mSystemBarConfigs = systemBarConfigs;
+        mButtonRoleHolderController = buttonRoleHolderController;
+        mButtonSelectionStateController = buttonSelectionStateController;
+        mCameraPrivacyChipViewControllerLazy = cameraPrivacyChipViewControllerLazy;
+        mMicPrivacyChipViewControllerLazy = micPrivacyChipViewControllerLazy;
+        mSide = side;
+        mOverlayVisibilityMediator = overlayVisibilityMediator;
+
+        mConsumeTouchWhenPanelOpen = getResources().getBoolean(
+                R.bool.config_consumeSystemBarTouchWhenNotificationPanelOpen);
+        mButtonsDraggable = getResources().getBoolean(R.bool.config_systemBarButtonsDraggable);
+    }
+
+    @Override
+    protected void onInit() {
+        // Include a FocusParkingView at the beginning. The rotary controller "parks" the focus here
+        // when the user navigates to another window. This is also used to prevent wrap-around.
+        mView.addView(new FocusParkingView(mContext), 0);
+        mView.setTouchListener(this);
+
+        setupSystemBarButtons(mView, mUserTracker);
+        mCarSystemBarElementInitializer.initializeCarSystemBarElements(mView);
+
+        mNavButtons = mView.findViewById(R.id.nav_buttons);
+        mLockScreenButtons = mView.findViewById(R.id.lock_screen_nav_buttons);
+        mOcclusionButtons = mView.findViewById(R.id.occlusion_buttons);
+        // Needs to be clickable so that it will receive ACTION_MOVE events.
+        mView.setClickable(true);
+        // Needs to not be focusable so rotary won't highlight the entire nav bar.
+        mView.setFocusable(false);
+    }
+
+    @Override
+    public void onSaveInstanceState(Bundle outState) {
+        // The focused view will be destroyed during re-layout, causing the framework to adjust
+        // the focus unexpectedly. To avoid that, move focus to a view that won't be
+        // destroyed during re-layout and has no focus highlight (the FocusParkingView), then
+        // move focus back to the previously focused view after re-layout.
+        outState.putInt(LAST_FOCUSED_VIEW_ID, cacheAndHideFocus(mView));
+    }
+
+    @Override
+    public void onRestoreInstanceState(Bundle savedInstanceState) {
+        restoreFocus(mView, savedInstanceState.getInt(LAST_FOCUSED_VIEW_ID, View.NO_ID));
+    }
+
+    @Override
+    public ViewGroup getView() {
+        return mView;
+    }
+
+    @Override
+    public void setSystemBarTouchListeners(
+            Set<View.OnTouchListener> systemBarTouchListeners) {
+        mSystemBarTouchListeners = systemBarTouchListeners;
+    }
+
+    @Override
+    public void showButtonsOfType(@ButtonsType int buttonsType) {
+        switch(buttonsType) {
+            case BUTTON_TYPE_NAVIGATION:
+                setNavigationButtonsVisibility(View.VISIBLE);
+                setKeyguardButtonsVisibility(View.GONE);
+                setOcclusionButtonsVisibility(View.GONE);
+                break;
+            case BUTTON_TYPE_KEYGUARD:
+                setNavigationButtonsVisibility(View.GONE);
+                setKeyguardButtonsVisibility(View.VISIBLE);
+                setOcclusionButtonsVisibility(View.GONE);
+                break;
+            case BUTTON_TYPE_OCCLUSION:
+                setNavigationButtonsVisibility(View.GONE);
+                setKeyguardButtonsVisibility(View.GONE);
+                setOcclusionButtonsVisibility(View.VISIBLE);
+                break;
+        }
+    }
+
+    /**
+     * Used to forward touch events even if the touch was initiated from a child component
+     */
+    @Override
+    public boolean onInterceptTouchEvent(MotionEvent ev) {
+        if (mSystemBarTouchListeners != null && !mSystemBarTouchListeners.isEmpty()) {
+            if (!mButtonsDraggable) {
+                return false;
+            }
+
+            OverlayViewController topOverlay =
+                    mOverlayVisibilityMediator.getHighestZOrderOverlayViewController();
+            boolean shouldConsumeEvent = topOverlay instanceof OverlayPanelViewController
+                    ? ((OverlayPanelViewController) topOverlay).shouldPanelConsumeSystemBarTouch()
+                    : false;
+
+            // Forward touch events to the status bar window so it can drag
+            // windows if required (ex. Notification shade)
+            triggerAllTouchListeners(mView, ev);
+
+            if (mConsumeTouchWhenPanelOpen && shouldConsumeEvent) {
+                return true;
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Used for forwarding onTouch events on the systembar.
+     */
+    @Override
+    public boolean onTouchEvent(MotionEvent event) {
+        triggerAllTouchListeners(mView, event);
+        return false;
+    }
+
+    @Override
+    protected void onViewAttached() {
+        mSystemBarConfigs.insetSystemBar(mSide, mView);
+
+        mButtonSelectionStateController.addAllButtonsWithSelectionState(mView);
+        mButtonRoleHolderController.addAllButtonsWithRoleName(mView);
+        mMicPrivacyChipViewControllerLazy.get().addPrivacyChipView(mView);
+        mCameraPrivacyChipViewControllerLazy.get().addPrivacyChipView(mView);
+    }
+
+    @Override
+    protected void onViewDetached() {
+        mButtonSelectionStateController.removeAll();
+        mButtonRoleHolderController.removeAll();
+        mMicPrivacyChipViewControllerLazy.get().removeAll();
+        mCameraPrivacyChipViewControllerLazy.get().removeAll();
+    }
+
+    @AssistedFactory
+    public interface Factory
+            extends CarSystemBarViewControllerFactory<CarSystemBarViewControllerImpl> {
+    }
+
+    private void setupSystemBarButtons(View v, UserTracker userTracker) {
+        if (v instanceof CarSystemBarButton) {
+            ((CarSystemBarButton) v).setUserTracker(userTracker);
+        } else if (v instanceof ViewGroup) {
+            ViewGroup viewGroup = (ViewGroup) v;
+            for (int i = 0; i < viewGroup.getChildCount(); i++) {
+                setupSystemBarButtons(viewGroup.getChildAt(i), userTracker);
+            }
+        }
+    }
+
+    private void setNavigationButtonsVisibility(@View.Visibility int visibility) {
+        if (mNavButtons != null) {
+            mNavButtons.setVisibility(visibility);
+        }
+    }
+
+    private void setKeyguardButtonsVisibility(@View.Visibility int visibility) {
+        if (mLockScreenButtons != null) {
+            mLockScreenButtons.setVisibility(visibility);
+        }
+    }
+
+    private void setOcclusionButtonsVisibility(@View.Visibility int visibility) {
+        if (mOcclusionButtons != null) {
+            mOcclusionButtons.setVisibility(visibility);
+        }
+    }
+
+    private void triggerAllTouchListeners(View view, MotionEvent event) {
+        if (mSystemBarTouchListeners == null) {
+            return;
+        }
+        for (View.OnTouchListener listener : mSystemBarTouchListeners) {
+            listener.onTouch(view, event);
+        }
+    }
+
+    @VisibleForTesting
+    static int cacheAndHideFocus(@Nullable View rootView) {
+        if (rootView == null) return View.NO_ID;
+        View focusedView = rootView.findFocus();
+        if (focusedView == null || focusedView instanceof FocusParkingView) return View.NO_ID;
+        int focusedViewId = focusedView.getId();
+        ViewUtils.hideFocus(rootView);
+        return focusedViewId;
+    }
+
+    private static boolean restoreFocus(@Nullable View rootView, @IdRes int viewToFocusId) {
+        if (rootView == null || viewToFocusId == View.NO_ID) return false;
+        View focusedView = rootView.findViewById(viewToFocusId);
+        if (focusedView == null) return false;
+        focusedView.requestFocus();
+        return true;
+    }
+
+    static class TouchInterceptingFrameLayout extends FrameLayout {
+        @Nullable
+        private Gefingerpoken mTouchListener;
+
+        TouchInterceptingFrameLayout(Context context, ViewGroup content) {
+            super(context);
+            addView(content);
+        }
+
+        void setTouchListener(@Nullable Gefingerpoken listener) {
+            mTouchListener = listener;
+        }
+
+        /** Called when a touch is being intercepted in a ViewGroup. */
+        @Override
+        public boolean onInterceptTouchEvent(MotionEvent ev) {
+            return (mTouchListener != null && mTouchListener
+                    .onInterceptTouchEvent(ev)) ? true : super.onInterceptTouchEvent(ev);
+        }
+
+        /** Called when a touch is being handled by a view. */
+        @Override
+        public boolean onTouchEvent(MotionEvent ev) {
+            return (mTouchListener != null && mTouchListener
+                    .onTouchEvent(ev)) ? true : super.onTouchEvent(ev);
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarViewFactory.java b/src/com/android/systemui/car/systembar/CarSystemBarViewFactory.java
index ece8ebe5..adf6215b 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarViewFactory.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarViewFactory.java
@@ -13,207 +13,29 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.systemui.car.systembar;
 
-import android.annotation.IdRes;
-import android.content.Context;
-import android.util.ArrayMap;
-import android.util.Log;
-import android.view.View;
 import android.view.ViewGroup;
 
-import androidx.annotation.LayoutRes;
-
-import com.android.car.dockutil.Flags;
-import com.android.car.ui.FocusParkingView;
-import com.android.systemui.R;
-import com.android.systemui.car.systembar.element.CarSystemBarElementController;
-import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
-import com.android.systemui.dagger.SysUISingleton;
-import com.android.systemui.flags.FeatureFlags;
-import com.android.systemui.settings.UserTracker;
+import androidx.annotation.NonNull;
 
-import java.util.ArrayList;
-import java.util.List;
+import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
 
-import javax.inject.Inject;
 
 /** A factory that creates and caches views for navigation bars. */
-@SysUISingleton
-public class CarSystemBarViewFactory {
-
-    private static final String TAG = CarSystemBarViewFactory.class.getSimpleName();
-    private static final ArrayMap<Type, Integer> sLayoutMap = setupLayoutMapping();
-
-    private static ArrayMap<Type, Integer> setupLayoutMapping() {
-        ArrayMap<Type, Integer> map = new ArrayMap<>();
-        map.put(Type.TOP, R.layout.car_top_system_bar);
-        map.put(Type.TOP_WITH_DOCK, R.layout.car_top_system_bar_dock);
-        map.put(Type.TOP_UNPROVISIONED, R.layout.car_top_system_bar_unprovisioned);
-        map.put(Type.BOTTOM, R.layout.car_bottom_system_bar);
-        map.put(Type.BOTTOM_WITH_DOCK, R.layout.car_bottom_system_bar_dock);
-        map.put(Type.BOTTOM_UNPROVISIONED, R.layout.car_bottom_system_bar_unprovisioned);
-        map.put(Type.LEFT, R.layout.car_left_system_bar);
-        map.put(Type.LEFT_UNPROVISIONED, R.layout.car_left_system_bar_unprovisioned);
-        map.put(Type.RIGHT, R.layout.car_right_system_bar);
-        map.put(Type.RIGHT_UNPROVISIONED, R.layout.car_right_system_bar_unprovisioned);
-        return map;
-    }
-
-    private final Context mContext;
-    private final ArrayMap<Type, CarSystemBarView> mCachedViewMap = new ArrayMap<>(
-            Type.values().length);
-    private final ArrayMap<Type, ViewGroup> mCachedContainerMap = new ArrayMap<>();
-    private final FeatureFlags mFeatureFlags;
-    private final UserTracker mUserTracker;
-    private final CarSystemBarElementInitializer mCarSystemBarElementInitializer;
-    private final List<CarSystemBarElementController> mCarSystemBarElementControllers =
-            new ArrayList<>();
-
-    /** Type of navigation bar to be created. */
-    private enum Type {
-        TOP,
-        TOP_WITH_DOCK,
-        TOP_UNPROVISIONED,
-        BOTTOM,
-        BOTTOM_WITH_DOCK,
-        BOTTOM_UNPROVISIONED,
-        LEFT,
-        LEFT_UNPROVISIONED,
-        RIGHT,
-        RIGHT_UNPROVISIONED
-    }
-
-    @Inject
-    public CarSystemBarViewFactory(
-            Context context,
-            FeatureFlags featureFlags,
-            UserTracker userTracker,
-            CarSystemBarElementInitializer elementInitializer
-    ) {
-        mContext = context;
-        mFeatureFlags = featureFlags;
-        mUserTracker = userTracker;
-        mCarSystemBarElementInitializer = elementInitializer;
-    }
-
-    /** Gets the top window. */
-    public ViewGroup getTopWindow() {
-        return getWindowCached(Type.TOP);
-    }
-
-    /** Gets the bottom window. */
-    public ViewGroup getBottomWindow() {
-        return getWindowCached(Type.BOTTOM);
-    }
-
-    /** Gets the left window. */
-    public ViewGroup getLeftWindow() {
-        return getWindowCached(Type.LEFT);
-    }
-
-    /** Gets the right window. */
-    public ViewGroup getRightWindow() {
-        return getWindowCached(Type.RIGHT);
-    }
-
-    /** Gets the top bar. */
-    public CarSystemBarView getTopBar(boolean isSetUp) {
-        if (Flags.dockFeature()) {
-            return getBar(isSetUp, Type.TOP_WITH_DOCK, Type.TOP_UNPROVISIONED);
-        }
-        return getBar(isSetUp, Type.TOP, Type.TOP_UNPROVISIONED);
-    }
-
-    /** Gets the bottom bar. */
-    public CarSystemBarView getBottomBar(boolean isSetUp) {
-        if (Flags.dockFeature()) {
-            return getBar(isSetUp, Type.BOTTOM_WITH_DOCK, Type.BOTTOM_UNPROVISIONED);
-        }
-        return getBar(isSetUp, Type.BOTTOM, Type.BOTTOM_UNPROVISIONED);
-    }
-
-    /** Gets the left bar. */
-    public CarSystemBarView getLeftBar(boolean isSetUp) {
-        return getBar(isSetUp, Type.LEFT, Type.LEFT_UNPROVISIONED);
-    }
-
-    /** Gets the right bar. */
-    public CarSystemBarView getRightBar(boolean isSetUp) {
-        return getBar(isSetUp, Type.RIGHT, Type.RIGHT_UNPROVISIONED);
-    }
-
-    private ViewGroup getWindowCached(Type type) {
-        if (mCachedContainerMap.containsKey(type)) {
-            return mCachedContainerMap.get(type);
-        }
-
-        ViewGroup window = (ViewGroup) View.inflate(mContext,
-                R.layout.navigation_bar_window, /* root= */ null);
-        window.setId(getWindowId(type));
-        mCachedContainerMap.put(type, window);
-        return mCachedContainerMap.get(type);
-    }
-
-    @IdRes
-    private int getWindowId(Type type) {
-        return switch (type) {
-            case TOP -> R.id.car_top_bar_window;
-            case BOTTOM -> R.id.car_bottom_bar_window;
-            case LEFT -> R.id.car_left_bar_window;
-            case RIGHT -> R.id.car_right_bar_window;
-            default -> throw new IllegalArgumentException("unknown system bar window type " + type);
-        };
-    }
-
-    private CarSystemBarView getBar(boolean isSetUp, Type provisioned, Type unprovisioned) {
-        CarSystemBarView view = getBarCached(isSetUp, provisioned, unprovisioned);
-
-        if (view == null) {
-            String name = isSetUp ? provisioned.name() : unprovisioned.name();
-            Log.e(TAG, "CarStatusBar failed inflate for " + name);
-            throw new RuntimeException(
-                    "Unable to build " + name + " nav bar due to missing layout");
-        }
-        return view;
-    }
-
-    private CarSystemBarView getBarCached(boolean isSetUp, Type provisioned, Type unprovisioned) {
-        Type type = isSetUp ? provisioned : unprovisioned;
-        if (mCachedViewMap.containsKey(type)) {
-            return mCachedViewMap.get(type);
-        }
-
-        Integer barLayoutInteger = sLayoutMap.get(type);
-        if (barLayoutInteger == null) {
-            return null;
-        }
-        @LayoutRes int barLayout = barLayoutInteger;
-        CarSystemBarView view = (CarSystemBarView) View.inflate(mContext, barLayout,
-                /* root= */ null);
-
-        view.setupHvacButton();
-        view.setupSystemBarButtons(mUserTracker);
-        mCarSystemBarElementControllers.addAll(
-                mCarSystemBarElementInitializer.initializeCarSystemBarElements(view));
+public interface CarSystemBarViewFactory {
 
-        // Include a FocusParkingView at the beginning. The rotary controller "parks" the focus here
-        // when the user navigates to another window. This is also used to prevent wrap-around.
-        view.addView(new FocusParkingView(mContext), 0);
+    /** Gets the window by side. */
+    @NonNull
+    ViewGroup getSystemBarWindow(@SystemBarSide int side);
 
-        mCachedViewMap.put(type, view);
-        return mCachedViewMap.get(type);
-    }
+    /** Gets the bar view by side. */
+    @NonNull
+    CarSystemBarViewController getSystemBarViewController(@SystemBarSide int side, boolean isSetUp);
 
     /** Resets the cached system bar views. */
-    protected void resetSystemBarViewCache() {
-        mCachedViewMap.clear();
-    }
+    void resetSystemBarViewCache();
 
     /** Resets the cached system bar windows and system bar views. */
-    protected void resetSystemBarWindowCache() {
-        resetSystemBarViewCache();
-        mCachedContainerMap.clear();
-    }
+    void resetSystemBarWindowCache();
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarViewFactoryImpl.java b/src/com/android/systemui/car/systembar/CarSystemBarViewFactoryImpl.java
new file mode 100644
index 00000000..8f990693
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/CarSystemBarViewFactoryImpl.java
@@ -0,0 +1,114 @@
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
+package com.android.systemui.car.systembar;
+
+import android.content.Context;
+import android.util.ArrayMap;
+import android.util.Log;
+import android.util.Pair;
+import android.util.SparseArray;
+import android.view.ViewGroup;
+
+import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
+
+import java.util.Map;
+
+import javax.inject.Inject;
+
+/** A factory that creates and caches views for navigation bars. */
+public class CarSystemBarViewFactoryImpl implements CarSystemBarViewFactory {
+
+    private static final String TAG = CarSystemBarViewFactory.class.getSimpleName();
+
+    private final Context mContext;
+    // Map<Pair<@SystemBarSide Integer, Boolean>, CarSystemBarViewController>
+    private final Map<Pair<Integer, Boolean>, CarSystemBarViewController>
+            mCachedViewControllerMap = new ArrayMap<>();
+    // Map<@SystemBarSide Integer, ViewGroup>
+    private final SparseArray<ViewGroup> mCachedWindowMap = new SparseArray<>();
+    private final Map<@SystemBarSide Integer,
+            CarSystemBarViewControllerFactory> mFactoriesMap;
+    private final SystemBarConfigs mSystemBarConfigs;
+
+    @Inject
+    public CarSystemBarViewFactoryImpl(
+            Context context,
+            Map<@SystemBarSide Integer,
+                    CarSystemBarViewControllerFactory> factoriesMap,
+            SystemBarConfigs systemBarConfigs) {
+        mContext = context;
+        mFactoriesMap = factoriesMap;
+        mSystemBarConfigs = systemBarConfigs;
+    }
+
+    /** Gets the top window by side. */
+    @Override
+    public ViewGroup getSystemBarWindow(@SystemBarSide int side) {
+        return getWindowCached(side);
+    }
+
+    /** Gets the bar by side. */
+    @Override
+    public CarSystemBarViewController getSystemBarViewController(@SystemBarSide int side,
+            boolean isSetUp) {
+        CarSystemBarViewController controller = getBarCached(side, isSetUp);
+
+        if (controller == null) {
+            Log.e(TAG, "system bar failed inflate for side " + side + " setup " + isSetUp);
+            throw new RuntimeException(
+                    "Unable to inflate system bar for side " + side + " setup " + isSetUp
+                    + " due to missing layout");
+        }
+        return controller;
+    }
+
+    private ViewGroup getWindowCached(@SystemBarSide int side) {
+        if (mCachedWindowMap.get(side) != null) {
+            return mCachedWindowMap.get(side);
+        }
+
+        ViewGroup window = mSystemBarConfigs.getWindowLayoutBySide(side);
+        mCachedWindowMap.put(side, window);
+        return window;
+    }
+
+    private CarSystemBarViewController getBarCached(@SystemBarSide int side, boolean isSetUp) {
+        Pair key = new Pair<>(side, isSetUp);
+        if (mCachedViewControllerMap.get(key) != null) {
+            return mCachedViewControllerMap.get(key);
+        }
+
+        ViewGroup barView = mSystemBarConfigs.getSystemBarLayoutBySide(side, isSetUp);
+        CarSystemBarViewController controller = mFactoriesMap.get(side).create(side, barView);
+        controller.init();
+
+        mCachedViewControllerMap.put(key, controller);
+        return controller;
+    }
+
+    /** Resets the cached system bar views. */
+    @Override
+    public void resetSystemBarViewCache() {
+        mCachedViewControllerMap.clear();
+    }
+
+    /** Resets the cached system bar windows and system bar views. */
+    @Override
+    public void resetSystemBarWindowCache() {
+        resetSystemBarViewCache();
+        mCachedWindowMap.clear();
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java b/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java
new file mode 100644
index 00000000..4f2381b2
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java
@@ -0,0 +1,135 @@
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
+package com.android.systemui.car.systembar;
+
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
+
+import android.annotation.LayoutRes;
+import android.content.Context;
+import android.view.Gravity;
+import android.view.View;
+import android.view.ViewGroup;
+
+import androidx.annotation.Nullable;
+
+import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
+import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
+import com.android.systemui.car.window.OverlayVisibilityMediator;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.Lazy;
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import javax.inject.Provider;
+
+/**
+ * A controller for initializing the TOP CarSystemBarView.
+ * TODO(b/373710798): remove privacy chip related code when they are migrated to flexible ui.
+ */
+public class CarTopSystemBarViewController extends CarSystemBarViewControllerImpl {
+
+    private final CarDeviceProvisionedController mCarDeviceProvisionedController;
+    private final Provider<StatusIconPanelViewController.Builder> mPanelControllerBuilderProvider;
+
+    private int mPrivacyChipXOffset;
+    private StatusIconPanelViewController mMicPanelController;
+    private StatusIconPanelViewController mCameraPanelController;
+
+    @AssistedInject
+    public CarTopSystemBarViewController(Context context,
+            UserTracker userTracker,
+            CarSystemBarElementInitializer elementInitializer,
+            SystemBarConfigs systemBarConfigs,
+            ButtonRoleHolderController buttonRoleHolderController,
+            ButtonSelectionStateController buttonSelectionStateController,
+            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
+            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
+            CarDeviceProvisionedController deviceProvisionedController,
+            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider,
+            OverlayVisibilityMediator overlayVisibilityMediator,
+            @Assisted ViewGroup systemBarView) {
+        super(context,
+                userTracker,
+                elementInitializer,
+                systemBarConfigs,
+                buttonRoleHolderController,
+                buttonSelectionStateController,
+                cameraPrivacyChipViewControllerLazy,
+                micPrivacyChipViewControllerLazy,
+                overlayVisibilityMediator,
+                TOP,
+                systemBarView);
+        mCarDeviceProvisionedController = deviceProvisionedController;
+        mPanelControllerBuilderProvider = panelControllerBuilderProvider;
+
+        mPrivacyChipXOffset = -context.getResources()
+                .getDimensionPixelOffset(R.dimen.privacy_chip_horizontal_padding);
+    }
+
+    @Override
+    protected void onInit() {
+        super.onInit();
+
+        if (isDeviceSetupForUser()) {
+            // We do not want the privacy chips or the profile picker to be clickable in
+            // unprovisioned mode.
+            mMicPanelController = setupSensorQcPanel(mMicPanelController, R.id.mic_privacy_chip,
+                    R.layout.qc_mic_panel);
+            mCameraPanelController = setupSensorQcPanel(mCameraPanelController,
+                    R.id.camera_privacy_chip, R.layout.qc_camera_panel);
+        }
+    }
+
+    private StatusIconPanelViewController setupSensorQcPanel(
+            @Nullable StatusIconPanelViewController panelController, int chipId,
+            @LayoutRes int panelLayoutRes) {
+        if (panelController == null) {
+            View privacyChip = mView.findViewById(chipId);
+            if (privacyChip != null) {
+                panelController = mPanelControllerBuilderProvider.get()
+                        .setXOffset(mPrivacyChipXOffset)
+                        .setGravity(Gravity.TOP | Gravity.END)
+                        .build(privacyChip, panelLayoutRes, R.dimen.car_sensor_qc_panel_width);
+                panelController.init();
+            }
+        }
+        return panelController;
+    }
+
+    private boolean isDeviceSetupForUser() {
+        return mCarDeviceProvisionedController.isCurrentUserSetup()
+                && !mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
+    }
+
+    @AssistedFactory
+    public interface Factory extends CarSystemBarViewControllerImpl.Factory {
+        @Override
+        default CarSystemBarViewControllerImpl create(@SystemBarSide int side, ViewGroup view) {
+            if (side == TOP) {
+                return create(view);
+            }
+            throw new UnsupportedOperationException("Side not supported");
+        }
+
+        /** Create instance of CarTopSystemBarViewController for system bar views */
+        CarTopSystemBarViewController create(ViewGroup view);
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/ControlCenterButtonController.java b/src/com/android/systemui/car/systembar/ControlCenterButtonController.java
new file mode 100644
index 00000000..1f07f445
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/ControlCenterButtonController.java
@@ -0,0 +1,56 @@
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
+package com.android.systemui.car.systembar;
+
+import android.view.View;
+
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A CarSystemBarElementController for handling ControlCenter button interactions.
+ */
+public class ControlCenterButtonController extends CarSystemBarButtonController {
+
+    @AssistedInject
+    public ControlCenterButtonController(@Assisted CarSystemBarButton ccButton,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            UserTracker userTracker) {
+        super(ccButton, disableController, stateController, userTracker);
+
+        ccButton.setVisibility(
+                CarSystemUIUserUtil.isMUMDSystemUI() ? View.VISIBLE : View.GONE);
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarButton,
+                    ControlCenterButtonController> {
+    }
+
+    @Override
+    protected boolean shouldBeVisible() {
+        return CarSystemUIUserUtil.isMUMDSystemUI();
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/DebugPanelButtonViewController.java b/src/com/android/systemui/car/systembar/DebugPanelButtonViewController.java
index 84f4b896..c2bbfff8 100644
--- a/src/com/android/systemui/car/systembar/DebugPanelButtonViewController.java
+++ b/src/com/android/systemui/car/systembar/DebugPanelButtonViewController.java
@@ -20,7 +20,6 @@ import static android.provider.Settings.Global.DEVELOPMENT_SETTINGS_ENABLED;
 
 import android.database.ContentObserver;
 import android.net.Uri;
-import android.os.Build;
 import android.os.Handler;
 
 import com.android.settingslib.development.DevelopmentSettingsEnabler;
@@ -41,7 +40,6 @@ import javax.inject.Provider;
  * A controller for the debug panel button.
  */
 public class DebugPanelButtonViewController extends CarSystemBarPanelButtonViewController {
-    private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
     private final GlobalSettings mGlobalSettings;
     private final Uri mDevelopEnabled;
     private final ContentObserver mDeveloperSettingsObserver;
@@ -85,6 +83,7 @@ public class DebugPanelButtonViewController extends CarSystemBarPanelButtonViewC
 
     @Override
     protected boolean shouldBeVisible() {
-        return DEBUG && DevelopmentSettingsEnabler.isDevelopmentSettingsEnabled(getContext());
+        return BuildInfoUtil.isDevTesting(getContext())
+                && DevelopmentSettingsEnabler.isDevelopmentSettingsEnabled(getContext());
     }
 }
diff --git a/src/com/android/systemui/car/systembar/DockViewControllerWrapper.java b/src/com/android/systemui/car/systembar/DockViewControllerWrapper.java
index 60875ee1..224167ff 100644
--- a/src/com/android/systemui/car/systembar/DockViewControllerWrapper.java
+++ b/src/com/android/systemui/car/systembar/DockViewControllerWrapper.java
@@ -18,6 +18,9 @@ package com.android.systemui.car.systembar;
 
 import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_SWITCHING;
 import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_UNLOCKED;
+import static android.view.Display.INVALID_DISPLAY;
+
+import static com.android.car.dockutil.events.DockCompatUtils.isDockSupportedOnDisplay;
 
 import android.car.Car;
 import android.car.user.CarUserManager;
@@ -153,6 +156,13 @@ public class DockViewControllerWrapper extends
             }
             return;
         }
+        int currentDisplayId = mView.getDisplay() != null ? mView.getDisplay().getDisplayId()
+                : INVALID_DISPLAY;
+        if (!isDockSupportedOnDisplay(mContext, currentDisplayId)) {
+            Log.e(TAG, "Dock cannot be initialised: Tried to launch on unsupported display "
+                    + currentDisplayId);
+            return;
+        }
         DockView dockView = mView.findViewById(R.id.dock);
         if (dockView == null) {
             if (DEBUG) {
diff --git a/src/com/android/systemui/car/systembar/HomeButtonController.java b/src/com/android/systemui/car/systembar/HomeButtonController.java
new file mode 100644
index 00000000..a74ff8ef
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/HomeButtonController.java
@@ -0,0 +1,56 @@
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
+package com.android.systemui.car.systembar;
+
+import android.view.View;
+
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A CarSystemBarElementController for handling Home button interactions.
+ */
+public class HomeButtonController extends CarSystemBarButtonController  {
+
+    @AssistedInject
+    public HomeButtonController(@Assisted CarSystemBarButton homeButton,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            UserTracker userTracker) {
+        super(homeButton, disableController, stateController, userTracker);
+
+        homeButton.setVisibility(
+                CarSystemUIUserUtil.isSecondaryMUMDSystemUI() ? View.GONE : View.VISIBLE);
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarButton,
+                    HomeButtonController> {
+    }
+
+    @Override
+    protected boolean shouldBeVisible() {
+        return !CarSystemUIUserUtil.isSecondaryMUMDSystemUI();
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java b/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
index 5e41196b..e49eb143 100644
--- a/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
+++ b/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
@@ -16,6 +16,7 @@
 
 package com.android.systemui.car.systembar;
 
+import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.content.ComponentName;
 import android.content.Context;
@@ -43,8 +44,6 @@ import com.android.internal.statusbar.IStatusBarService;
 import com.android.systemui.R;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.displaycompat.ToolbarController;
-import com.android.systemui.car.hvac.HvacController;
-import com.android.systemui.car.statusicon.StatusIconPanelViewController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.plugins.DarkIconDispatcher;
@@ -63,8 +62,6 @@ import dagger.Lazy;
 import java.util.HashSet;
 import java.util.Set;
 
-import javax.inject.Provider;
-
 /**
  * b/259604616, This controller is created as a workaround for NavBar issues in concurrent
  * {@link CarSystemBar}/SystemUI.
@@ -101,12 +98,7 @@ public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
             Context context,
             UserTracker userTracker,
             CarSystemBarViewFactory carSystemBarViewFactory,
-            ButtonSelectionStateController buttonSelectionStateController,
-            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
-            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
-            ButtonRoleHolderController buttonRoleHolderController,
             SystemBarConfigs systemBarConfigs,
-            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider,
             // TODO(b/156052638): Should not need to inject LightBarController
             LightBarController lightBarController,
             DarkIconDispatcher darkIconDispatcher,
@@ -119,7 +111,6 @@ public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
             IStatusBarService barService,
             Lazy<KeyguardStateController> keyguardStateControllerLazy,
             Lazy<PhoneStatusBarPolicy> iconPolicyLazy,
-            HvacController hvacController,
             ConfigurationController configurationController,
             CarSystemBarRestartTracker restartTracker,
             DisplayTracker displayTracker,
@@ -127,12 +118,7 @@ public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
         super(context,
                 userTracker,
                 carSystemBarViewFactory,
-                buttonSelectionStateController,
-                micPrivacyChipViewControllerLazy,
-                cameraPrivacyChipViewControllerLazy,
-                buttonRoleHolderController,
                 systemBarConfigs,
-                panelControllerBuilderProvider,
                 lightBarController,
                 darkIconDispatcher,
                 windowManager,
@@ -144,7 +130,6 @@ public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
                 barService,
                 keyguardStateControllerLazy,
                 iconPolicyLazy,
-                hvacController,
                 configurationController,
                 restartTracker,
                 displayTracker,
@@ -306,7 +291,8 @@ public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
         }
 
         @Override
-        public void setImeInputTargetRequestedVisibility(boolean visible) {
+        public void setImeInputTargetRequestedVisibility(boolean visible,
+                @NonNull ImeTracker.Token statsToken) {
             //no-op
         }
     }
diff --git a/src/com/android/systemui/car/systembar/PassengerHomeButtonController.java b/src/com/android/systemui/car/systembar/PassengerHomeButtonController.java
new file mode 100644
index 00000000..e44f09c9
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/PassengerHomeButtonController.java
@@ -0,0 +1,56 @@
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
+package com.android.systemui.car.systembar;
+
+import android.view.View;
+
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A CarSystemBarElementController for handling passenger Home button interactions.
+ */
+public class PassengerHomeButtonController extends CarSystemBarButtonController {
+
+    @AssistedInject
+    public PassengerHomeButtonController(@Assisted CarSystemBarButton homeButton,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            UserTracker userTracker) {
+        super(homeButton, disableController, stateController, userTracker);
+
+        homeButton.setVisibility(
+                CarSystemUIUserUtil.isSecondaryMUMDSystemUI() ? View.VISIBLE : View.GONE);
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarButton,
+                    PassengerHomeButtonController> {
+    }
+
+    @Override
+    protected boolean shouldBeVisible() {
+        return CarSystemUIUserUtil.isSecondaryMUMDSystemUI();
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/PrivacyChipViewController.java b/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
index a4785644..ee92a03d 100644
--- a/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
+++ b/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
@@ -208,10 +208,6 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
      * Cleans up the controller and removes callbacks.
      */
     public void removeAll() {
-        if (mPrivacyChip != null) {
-            mPrivacyChip.setOnClickListener(null);
-        }
-
         mIsPrivacyChipVisible = false;
         mPrivacyItemController.removeCallback(mPicCallback);
         mSensorPrivacyManager.removeSensorPrivacyListener(getChipSensor(),
diff --git a/src/com/android/systemui/car/systembar/SystemBarConfigs.java b/src/com/android/systemui/car/systembar/SystemBarConfigs.java
index bacfb854..c2ff574c 100644
--- a/src/com/android/systemui/car/systembar/SystemBarConfigs.java
+++ b/src/com/android/systemui/car/systembar/SystemBarConfigs.java
@@ -13,647 +13,108 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.systemui.car.systembar;
 
-import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
-
-import static com.android.car.dockutil.Flags.dockFeature;
-import static com.android.systemui.car.Flags.displayCompatibilityV2;
-import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
-import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
-import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
-import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
-
-import android.content.res.Resources;
-import android.graphics.PixelFormat;
-import android.os.Binder;
-import android.util.ArrayMap;
-import android.util.ArraySet;
-import android.util.Log;
-import android.view.Gravity;
+import android.content.Context;
 import android.view.InsetsFrameProvider;
 import android.view.ViewGroup;
-import android.view.WindowInsets;
 import android.view.WindowManager;
 
-import com.android.internal.annotations.VisibleForTesting;
-import com.android.systemui.R;
-import com.android.systemui.car.notification.BottomNotificationPanelViewMediator;
-import com.android.systemui.car.notification.TopNotificationPanelViewMediator;
+import androidx.annotation.Nullable;
+
 import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
-import com.android.systemui.dagger.SysUISingleton;
-import com.android.systemui.dagger.qualifiers.Main;
 
-import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.Comparator;
 import java.util.List;
-import java.util.Map;
-import java.util.Set;
-
-import javax.inject.Inject;
 
 /**
- * Reads configs for system bars for each side (TOP, BOTTOM, LEFT, and RIGHT) and returns the
- * corresponding {@link android.view.WindowManager.LayoutParams} per the configuration.
+ *  Interface for classes that provide system bar configurations.
  */
-@SysUISingleton
-public class SystemBarConfigs {
-
-    private static final String TAG = SystemBarConfigs.class.getSimpleName();
-    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
-
-    // The z-order from which system bars will start to appear on top of HUN's.
-    private static final int HUN_ZORDER = 10;
-
-    private static final Binder INSETS_OWNER = new Binder();
-
-    /*
-        NOTE: The elements' order in the map below must be preserved as-is since the correct
-        corresponding values are obtained by the index.
-     */
-    public static final InsetsFrameProvider[] BAR_PROVIDER_MAP = {
-            new InsetsFrameProvider(
-                    INSETS_OWNER, 0 /* index */, WindowInsets.Type.statusBars()),
-            new InsetsFrameProvider(
-                    INSETS_OWNER, 0 /* index */, WindowInsets.Type.navigationBars()),
-            new InsetsFrameProvider(
-                    INSETS_OWNER, 1 /* index */, WindowInsets.Type.statusBars()),
-            new InsetsFrameProvider(
-                    INSETS_OWNER, 1 /* index */, WindowInsets.Type.navigationBars()),
-    };
-
-    private static final Map<@SystemBarSide Integer, Integer> BAR_GRAVITY_MAP = new ArrayMap<>();
-    private static final Map<@SystemBarSide Integer, String> BAR_TITLE_MAP = new ArrayMap<>();
-    private static final Map<@SystemBarSide Integer, InsetsFrameProvider> BAR_GESTURE_MAP =
-            new ArrayMap<>();
-
-    private final Resources mResources;
-    private final Map<@SystemBarSide Integer, SystemBarConfig> mSystemBarConfigMap =
-            new ArrayMap<>();
-    private final List<@SystemBarSide Integer> mSystemBarSidesByZOrder = new ArrayList<>();
-
-    private boolean mTopNavBarEnabled;
-    private boolean mBottomNavBarEnabled;
-    private boolean mLeftNavBarEnabled;
-    private boolean mRightNavBarEnabled;
-    private int mDisplayCompatToolbarState = 0;
-
-    @Inject
-    public SystemBarConfigs(@Main Resources resources) {
-        mResources = resources;
-        init();
-    }
-
-    private void init() {
-        populateMaps();
-        readConfigs();
-
-        checkOnlyOneDisplayCompatIsEnabled();
-        checkEnabledBarsHaveUniqueBarTypes();
-        checkAllOverlappingBarsHaveDifferentZOrders();
-        checkSystemBarEnabledForNotificationPanel();
-        checkHideBottomBarForKeyboardConfigSync();
-
-        setInsetPaddingsForOverlappingCorners();
-        sortSystemBarTypesByZOrder();
-    }
+public interface SystemBarConfigs {
 
     /**
      * Invalidate cached resources and fetch from resources config file.
-     * TODO: b/260206944, Can remove this after we have a fix for overlaid resources not applied.
+     *
      * <p>
-     * Since SystemBarConfig is a Scoped(Dagger Singleton Annotation), We will have stale values, of
-     * all the resources after the RRO is applied.
-     * Another way is to remove the Scope(Singleton), but the downside is that it will be re-created
-     * everytime.
+     * This method should be called when the system bar configurations need to be refreshed,
+     * such as when an RRO (Runtime Resource Overlay) is applied.
      * </p>
      */
-    void resetSystemBarConfigs() {
-        init();
-    }
-
-    protected WindowManager.LayoutParams getLayoutParamsBySide(@SystemBarSide int side) {
-        return mSystemBarConfigMap.get(side) != null
-                ? mSystemBarConfigMap
-                .get(side).getLayoutParams()
-                : null;
-    }
-
-    protected boolean getEnabledStatusBySide(@SystemBarSide int side) {
-        switch (side) {
-            case TOP:
-                return mTopNavBarEnabled;
-            case BOTTOM:
-                return mBottomNavBarEnabled;
-            case LEFT:
-                return mLeftNavBarEnabled || isLeftDisplayCompatToolbarEnabled();
-            case RIGHT:
-                return mRightNavBarEnabled || isRightDisplayCompatToolbarEnabled();
-            default:
-                return false;
-        }
-    }
-
-    protected boolean getHideForKeyboardBySide(@SystemBarSide int side) {
-        return mSystemBarConfigMap.get(side) != null
-                && mSystemBarConfigMap.get(side).getHideForKeyboard();
-    }
-
-    protected void insetSystemBar(@SystemBarSide int side, CarSystemBarView view) {
-        if (mSystemBarConfigMap.get(side) == null) return;
-
-        int[] paddings = mSystemBarConfigMap.get(side).getPaddings();
-        if (DEBUG) {
-            Log.d(TAG, "Set padding to side = " + side + ", to " + Arrays.toString(paddings));
-        }
-        view.setPadding(paddings[LEFT], paddings[TOP], paddings[RIGHT], paddings[BOTTOM]);
-    }
-
-    protected List<Integer> getSystemBarSidesByZOrder() {
-        return mSystemBarSidesByZOrder;
-    }
-
-    @VisibleForTesting
-    void updateInsetPaddings(@SystemBarSide int side,
-            Map<@SystemBarSide Integer, Boolean> barVisibilities) {
-        SystemBarConfig currentConfig = mSystemBarConfigMap.get(side);
-
-        if (currentConfig == null) return;
-
-        int defaultLeftPadding = 0;
-        int defaultRightPadding = 0;
-        int defaultTopPadding = 0;
-        int defaultBottomPadding = 0;
-
-        switch (side) {
-            case LEFT: {
-                defaultLeftPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_left_system_bar_left_padding);
-                defaultRightPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_left_system_bar_right_padding);
-                defaultTopPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_left_system_bar_top_padding);
-                defaultBottomPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_left_system_bar_bottom_padding);
-                break;
-            }
-            case RIGHT: {
-                defaultLeftPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_right_system_bar_left_padding);
-                defaultRightPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_right_system_bar_right_padding);
-                defaultTopPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_right_system_bar_top_padding);
-                defaultBottomPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_right_system_bar_bottom_padding);
-                break;
-            }
-            case TOP: {
-                defaultLeftPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_top_system_bar_left_padding);
-                defaultRightPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_top_system_bar_right_padding);
-                defaultTopPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_top_system_bar_top_padding);
-                defaultBottomPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_top_system_bar_bottom_padding);
-                break;
-            }
-            case BOTTOM: {
-                defaultLeftPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_bottom_system_bar_left_padding);
-                defaultRightPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_bottom_system_bar_right_padding);
-                defaultTopPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_bottom_system_bar_top_padding);
-                defaultBottomPadding = mResources
-                        .getDimensionPixelSize(R.dimen.car_bottom_system_bar_bottom_padding);
-                break;
-            }
-            default:
-        }
-
-        currentConfig.setPaddingBySide(LEFT, defaultLeftPadding);
-        currentConfig.setPaddingBySide(RIGHT, defaultRightPadding);
-        currentConfig.setPaddingBySide(TOP, defaultTopPadding);
-        currentConfig.setPaddingBySide(BOTTOM, defaultBottomPadding);
-
-        if (isHorizontalBar(side)) {
-            if (mLeftNavBarEnabled && currentConfig.getZOrder() < mSystemBarConfigMap.get(
-                    LEFT).getZOrder()) {
-                currentConfig.setPaddingBySide(LEFT,
-                        barVisibilities.get(LEFT)
-                                ? mSystemBarConfigMap.get(LEFT).getGirth()
-                                : defaultLeftPadding);
-            }
-            if (mRightNavBarEnabled && currentConfig.getZOrder() < mSystemBarConfigMap.get(
-                    RIGHT).getZOrder()) {
-                currentConfig.setPaddingBySide(RIGHT,
-                        barVisibilities.get(RIGHT)
-                                ? mSystemBarConfigMap.get(RIGHT).getGirth()
-                                : defaultRightPadding);
-            }
-        }
-        if (isVerticalBar(side)) {
-            if (mTopNavBarEnabled && currentConfig.getZOrder() < mSystemBarConfigMap.get(
-                    TOP).getZOrder()) {
-                currentConfig.setPaddingBySide(TOP,
-                        barVisibilities.get(TOP)
-                                ? mSystemBarConfigMap.get(TOP).getGirth()
-                                : defaultTopPadding);
-            }
-            if (mBottomNavBarEnabled && currentConfig.getZOrder() < mSystemBarConfigMap.get(
-                    BOTTOM).getZOrder()) {
-                currentConfig.setPaddingBySide(BOTTOM,
-                        barVisibilities.get(BOTTOM)
-                                ? mSystemBarConfigMap.get(BOTTOM).getGirth()
-                                : defaultBottomPadding);
-            }
-
-        }
-        if (DEBUG) {
-            Log.d(TAG, "Update padding for side = " + side + " to "
-                    + Arrays.toString(currentConfig.getPaddings()));
-        }
-    }
-
-    @VisibleForTesting
-    static int getHunZOrder() {
-        return HUN_ZORDER;
-    }
-
-    private static void populateMaps() {
-        BAR_GRAVITY_MAP.put(TOP, Gravity.TOP);
-        BAR_GRAVITY_MAP.put(BOTTOM, Gravity.BOTTOM);
-        BAR_GRAVITY_MAP.put(LEFT, Gravity.LEFT);
-        BAR_GRAVITY_MAP.put(RIGHT, Gravity.RIGHT);
-
-        BAR_TITLE_MAP.put(TOP, "TopCarSystemBar");
-        BAR_TITLE_MAP.put(BOTTOM, "BottomCarSystemBar");
-        BAR_TITLE_MAP.put(LEFT, "LeftCarSystemBar");
-        BAR_TITLE_MAP.put(RIGHT, "RightCarSystemBar");
-
-        BAR_GESTURE_MAP.put(TOP, new InsetsFrameProvider(
-                INSETS_OWNER, 0 /* index */, WindowInsets.Type.mandatorySystemGestures()));
-        BAR_GESTURE_MAP.put(BOTTOM, new InsetsFrameProvider(
-                INSETS_OWNER, 1 /* index */, WindowInsets.Type.mandatorySystemGestures()));
-        BAR_GESTURE_MAP.put(LEFT, new InsetsFrameProvider(
-                INSETS_OWNER, 2 /* index */, WindowInsets.Type.mandatorySystemGestures()));
-        BAR_GESTURE_MAP.put(RIGHT, new InsetsFrameProvider(
-                INSETS_OWNER, 3 /* index */, WindowInsets.Type.mandatorySystemGestures()));
-    }
-
-    private void readConfigs() {
-        mTopNavBarEnabled = mResources.getBoolean(R.bool.config_enableTopSystemBar);
-        mBottomNavBarEnabled = mResources.getBoolean(R.bool.config_enableBottomSystemBar);
-        mLeftNavBarEnabled = mResources.getBoolean(R.bool.config_enableLeftSystemBar);
-        mRightNavBarEnabled = mResources.getBoolean(R.bool.config_enableRightSystemBar);
-        mDisplayCompatToolbarState =
-            mResources.getInteger(R.integer.config_showDisplayCompatToolbarOnSystemBar);
-        mSystemBarConfigMap.clear();
-
-        if ((mLeftNavBarEnabled && isLeftDisplayCompatToolbarEnabled())
-                || (mRightNavBarEnabled && isRightDisplayCompatToolbarEnabled())) {
-            throw new IllegalStateException(
-                "Navigation Bar and Display Compat toolbar can't be "
-                    + "on the same side");
-        }
-
-        if (mTopNavBarEnabled) {
-            SystemBarConfig topBarConfig =
-                    new SystemBarConfigBuilder()
-                            .setSide(TOP)
-                            .setGirth(mResources.getDimensionPixelSize(
-                                    R.dimen.car_top_system_bar_height))
-                            .setBarType(
-                                    mResources.getInteger(R.integer.config_topSystemBarType))
-                            .setZOrder(
-                                    mResources.getInteger(R.integer.config_topSystemBarZOrder))
-                            .setHideForKeyboard(mResources.getBoolean(
-                                    R.bool.config_hideTopSystemBarForKeyboard))
-                            .build();
-            mSystemBarConfigMap.put(TOP, topBarConfig);
-        }
-
-        if (mBottomNavBarEnabled) {
-            SystemBarConfig bottomBarConfig =
-                    new SystemBarConfigBuilder()
-                            .setSide(BOTTOM)
-                            .setGirth(mResources.getDimensionPixelSize(
-                                    R.dimen.car_bottom_system_bar_height))
-                            .setBarType(
-                                    mResources.getInteger(R.integer.config_bottomSystemBarType))
-                            .setZOrder(
-                                    mResources.getInteger(
-                                            R.integer.config_bottomSystemBarZOrder))
-                            .setHideForKeyboard(mResources.getBoolean(
-                                    R.bool.config_hideBottomSystemBarForKeyboard))
-                            .build();
-            mSystemBarConfigMap.put(BOTTOM, bottomBarConfig);
-        }
-
-        if (mLeftNavBarEnabled || isLeftDisplayCompatToolbarEnabled()) {
-            SystemBarConfig leftBarConfig =
-                    new SystemBarConfigBuilder()
-                            .setSide(LEFT)
-                            .setGirth(mResources.getDimensionPixelSize(
-                                    R.dimen.car_left_system_bar_width))
-                            .setBarType(
-                                    mResources.getInteger(R.integer.config_leftSystemBarType))
-                            .setZOrder(
-                                    mResources.getInteger(R.integer.config_leftSystemBarZOrder))
-                            .setHideForKeyboard(mResources.getBoolean(
-                                    R.bool.config_hideLeftSystemBarForKeyboard))
-                            .build();
-            mSystemBarConfigMap.put(LEFT, leftBarConfig);
-        }
-
-        if (mRightNavBarEnabled || isRightDisplayCompatToolbarEnabled()) {
-            SystemBarConfig rightBarConfig =
-                    new SystemBarConfigBuilder()
-                            .setSide(RIGHT)
-                            .setGirth(mResources.getDimensionPixelSize(
-                                    R.dimen.car_right_system_bar_width))
-                            .setBarType(
-                                    mResources.getInteger(R.integer.config_rightSystemBarType))
-                            .setZOrder(mResources.getInteger(
-                                    R.integer.config_rightSystemBarZOrder))
-                            .setHideForKeyboard(mResources.getBoolean(
-                                    R.bool.config_hideRightSystemBarForKeyboard))
-                            .build();
-            mSystemBarConfigMap.put(RIGHT, rightBarConfig);
-        }
-    }
-
-    private void checkOnlyOneDisplayCompatIsEnabled() throws IllegalStateException {
-        boolean useRemoteLaunchTaskView =
-                mResources.getBoolean(R.bool.config_useRemoteLaunchTaskView);
-        int displayCompatEnabled =
-                mResources.getInteger(R.integer.config_showDisplayCompatToolbarOnSystemBar);
-        if (useRemoteLaunchTaskView && displayCompatEnabled != 0) {
-            throw new IllegalStateException("config_useRemoteLaunchTaskView is enabled but "
-                    + "config_showDisplayCompatToolbarOnSystemBar is non-zero");
-        }
-    }
-
-    private void checkEnabledBarsHaveUniqueBarTypes() throws RuntimeException {
-        Set<Integer> barTypesUsed = new ArraySet<>();
-        int enabledNavBarCount = mSystemBarConfigMap.size();
-
-        for (SystemBarConfig systemBarConfig : mSystemBarConfigMap.values()) {
-            barTypesUsed.add(systemBarConfig.getBarType());
-        }
-
-        // The number of bar types used cannot be fewer than that of enabled system bars.
-        if (barTypesUsed.size() < enabledNavBarCount) {
-            throw new RuntimeException("Each enabled system bar must have a unique bar type. Check "
-                    + "the configuration in config.xml");
-        }
-    }
-
-    private void checkAllOverlappingBarsHaveDifferentZOrders() {
-        checkOverlappingBarsHaveDifferentZOrders(TOP, LEFT);
-        checkOverlappingBarsHaveDifferentZOrders(TOP, RIGHT);
-        checkOverlappingBarsHaveDifferentZOrders(BOTTOM, LEFT);
-        checkOverlappingBarsHaveDifferentZOrders(BOTTOM, RIGHT);
-    }
-
-    private void checkSystemBarEnabledForNotificationPanel() throws RuntimeException {
-        String notificationPanelMediatorName =
-                mResources.getString(R.string.config_notificationPanelViewMediator);
-        if (notificationPanelMediatorName == null) {
-            return;
-        }
-
-        Class<?> notificationPanelMediatorUsed = null;
-        try {
-            notificationPanelMediatorUsed = Class.forName(notificationPanelMediatorName);
-        } catch (ClassNotFoundException e) {
-            e.printStackTrace();
-        }
-
-        if (!mTopNavBarEnabled && TopNotificationPanelViewMediator.class.isAssignableFrom(
-                notificationPanelMediatorUsed)) {
-            throw new RuntimeException(
-                    "Top System Bar must be enabled to use " + notificationPanelMediatorName);
-        }
+    void resetSystemBarConfigs();
 
-        if (!mBottomNavBarEnabled && BottomNotificationPanelViewMediator.class.isAssignableFrom(
-                notificationPanelMediatorUsed)) {
-            throw new RuntimeException("Bottom System Bar must be enabled to use "
-                    + notificationPanelMediatorName);
-        }
-    }
-
-    private void checkHideBottomBarForKeyboardConfigSync() throws RuntimeException {
-        if (mBottomNavBarEnabled) {
-            boolean actual = mResources.getBoolean(R.bool.config_hideBottomSystemBarForKeyboard);
-            boolean expected = mResources.getBoolean(
-                    com.android.internal.R.bool.config_hideNavBarForKeyboard);
-
-            if (actual != expected) {
-                throw new RuntimeException("config_hideBottomSystemBarForKeyboard must not be "
-                        + "overlaid directly and should always refer to"
-                        + "config_hideNavBarForKeyboard. However, their values "
-                        + "currently do not sync. Set config_hideBottomSystemBarForKeyguard to "
-                        + "@*android:bool/config_hideNavBarForKeyboard. To change its "
-                        + "value, overlay config_hideNavBarForKeyboard in "
-                        + "framework/base/core/res/res.");
-            }
-        }
-    }
-
-    private void setInsetPaddingsForOverlappingCorners() {
-        Map<@SystemBarSide Integer, Boolean> systemBarVisibilityOnInit =
-                getSystemBarsVisibilityOnInit();
-        updateInsetPaddings(TOP, systemBarVisibilityOnInit);
-        updateInsetPaddings(BOTTOM, systemBarVisibilityOnInit);
-        updateInsetPaddings(LEFT, systemBarVisibilityOnInit);
-        updateInsetPaddings(RIGHT, systemBarVisibilityOnInit);
-    }
-
-    private void sortSystemBarTypesByZOrder() {
-        List<SystemBarConfig> systemBarsByZOrder = new ArrayList<>(mSystemBarConfigMap.values());
-
-        systemBarsByZOrder.sort(new Comparator<SystemBarConfig>() {
-            @Override
-            public int compare(SystemBarConfig o1, SystemBarConfig o2) {
-                return o1.getZOrder() - o2.getZOrder();
-            }
-        });
-
-        mSystemBarSidesByZOrder.clear();
-        systemBarsByZOrder.forEach(systemBarConfig -> {
-            mSystemBarSidesByZOrder.add(systemBarConfig.getSide());
-        });
-    }
-
-    // On init, system bars are visible as long as they are enabled.
-    private Map<@SystemBarSide Integer, Boolean> getSystemBarsVisibilityOnInit() {
-        ArrayMap<@SystemBarSide Integer, Boolean> visibilityMap = new ArrayMap<>();
-        visibilityMap.put(TOP, mTopNavBarEnabled);
-        visibilityMap.put(BOTTOM, mBottomNavBarEnabled);
-        visibilityMap.put(LEFT, mLeftNavBarEnabled || isLeftDisplayCompatToolbarEnabled());
-        visibilityMap.put(RIGHT, mRightNavBarEnabled || isRightDisplayCompatToolbarEnabled());
-        return visibilityMap;
-    }
-
-    private void checkOverlappingBarsHaveDifferentZOrders(@SystemBarSide int horizontalSide,
-            @SystemBarSide int verticalSide) {
-
-        if (isVerticalBar(horizontalSide) || isHorizontalBar(verticalSide)) {
-            Log.w(TAG, "configureBarPaddings: Returning immediately since the horizontal and "
-                    + "vertical sides were not provided correctly.");
-            return;
-        }
-
-        SystemBarConfig horizontalBarConfig = mSystemBarConfigMap.get(horizontalSide);
-        SystemBarConfig verticalBarConfig = mSystemBarConfigMap.get(verticalSide);
-
-        if (verticalBarConfig != null && horizontalBarConfig != null) {
-            int horizontalBarZOrder = horizontalBarConfig.getZOrder();
-            int verticalBarZOrder = verticalBarConfig.getZOrder();
-
-            if (horizontalBarZOrder == verticalBarZOrder) {
-                throw new RuntimeException(
-                        BAR_TITLE_MAP.get(horizontalSide) + " " + BAR_TITLE_MAP.get(verticalSide)
-                                + " have the same Z-Order, and so their placing order cannot be "
-                                + "determined. Determine which bar should be placed on top of the "
-                                + "other bar and change the Z-order in config.xml accordingly."
-                );
-            }
-        }
-    }
-
-    private static boolean isHorizontalBar(@SystemBarSide int side) {
-        return side == TOP || side == BOTTOM;
-    }
-
-    private static boolean isVerticalBar(@SystemBarSide int side) {
-        return side == LEFT || side == RIGHT;
-    }
-    boolean isLeftDisplayCompatToolbarEnabled() {
-        return displayCompatibilityV2() && mDisplayCompatToolbarState == 1;
-    }
-
-    boolean isRightDisplayCompatToolbarEnabled() {
-        return displayCompatibilityV2() && mDisplayCompatToolbarState == 2;
-    }
-
-    private static final class SystemBarConfig {
-        private final int mSide;
-        private final int mBarType;
-        private final int mGirth;
-        private final int mZOrder;
-        private final boolean mHideForKeyboard;
-
-        private int[] mPaddings = new int[]{0, 0, 0, 0};
-
-        private SystemBarConfig(@SystemBarSide int side, int barType, int girth, int zOrder,
-                boolean hideForKeyboard) {
-            mSide = side;
-            mBarType = barType;
-            mGirth = girth;
-            mZOrder = zOrder;
-            mHideForKeyboard = hideForKeyboard;
-        }
-
-        private int getSide() {
-            return mSide;
-        }
-
-        private int getBarType() {
-            return mBarType;
-        }
-
-        private int getGirth() {
-            return mGirth;
-        }
-
-        private int getZOrder() {
-            return mZOrder;
-        }
-
-        private boolean getHideForKeyboard() {
-            return mHideForKeyboard;
-        }
+    /**
+     * When creating system bars or overlay windows, use a WindowContext
+     * for that particular window type to ensure proper display metrics.
+     */
+    Context getWindowContextBySide(@SystemBarSide int side);
 
-        private int[] getPaddings() {
-            return mPaddings;
-        }
+    /**
+     * @return The system bar view for the given side. {@code null} if side is unknown.
+     */
+    @Nullable
+    ViewGroup getSystemBarLayoutBySide(@SystemBarSide int side, boolean isSetUp);
 
-        private WindowManager.LayoutParams getLayoutParams() {
-            WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
-                    isHorizontalBar(mSide) ? ViewGroup.LayoutParams.MATCH_PARENT : mGirth,
-                    isHorizontalBar(mSide) ? mGirth : ViewGroup.LayoutParams.MATCH_PARENT,
-                    mapZOrderToBarType(mZOrder),
-                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
-                            | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
-                            | WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH
-                            | WindowManager.LayoutParams.FLAG_SPLIT_TOUCH,
-                    PixelFormat.TRANSLUCENT);
-            lp.setTitle(BAR_TITLE_MAP.get(mSide));
-            lp.providedInsets = new InsetsFrameProvider[] {
-                    BAR_PROVIDER_MAP[mBarType],
-                    BAR_GESTURE_MAP.get(mSide)
-            };
-            lp.setFitInsetsTypes(0);
-            lp.windowAnimations = 0;
-            lp.gravity = BAR_GRAVITY_MAP.get(mSide);
-            lp.layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
-            if (dockFeature()) {
-                lp.privateFlags = lp.privateFlags
-                        | WindowManager.LayoutParams.PRIVATE_FLAG_INTERCEPT_GLOBAL_DRAG_AND_DROP;
-            }
-            return lp;
-        }
+    /**
+     * @return the systembar window for the given side. {@code null} if side is unknown.
+     */
+    @Nullable
+    ViewGroup getWindowLayoutBySide(@SystemBarSide int side);
 
-        private int mapZOrderToBarType(int zOrder) {
-            return zOrder >= HUN_ZORDER ? WindowManager.LayoutParams.TYPE_NAVIGATION_BAR_PANEL
-                    : WindowManager.LayoutParams.TYPE_STATUS_BAR_ADDITIONAL;
-        }
+    /**
+     * @return The {@link WindowManager.LayoutParams}, or {@code null} if the side is unknown
+     * or the system bar is not enabled.
+     */
+    WindowManager.LayoutParams getLayoutParamsBySide(@SystemBarSide int side);
 
-        private void setPaddingBySide(@SystemBarSide int side, int padding) {
-            mPaddings[side] = padding;
-        }
-    }
+    /**
+     * @return {@code true} if the system bar is enabled, {@code false} otherwise.
+     */
+    boolean getEnabledStatusBySide(@SystemBarSide int side);
 
-    private static final class SystemBarConfigBuilder {
-        private int mSide;
-        private int mBarType;
-        private int mGirth;
-        private int mZOrder;
-        private boolean mHideForKeyboard;
+    /**
+     * @return {@code true} if the system bar should be hidden, {@code false} otherwise.
+     */
+    boolean getHideForKeyboardBySide(@SystemBarSide int side);
 
-        private SystemBarConfigBuilder setSide(@SystemBarSide int side) {
-            mSide = side;
-            return this;
-        }
+    /**
+     * Applies padding to the given system bar view.
+     *
+     * @param view The system bar view
+     */
+    void insetSystemBar(@SystemBarSide int side, ViewGroup view);
 
-        private SystemBarConfigBuilder setBarType(int type) {
-            mBarType = type;
-            return this;
-        }
+    /**
+     * @return A list of system bar sides sorted by their Z order.
+     */
+    List<@SystemBarSide Integer> getSystemBarSidesByZOrder();
 
-        private SystemBarConfigBuilder setGirth(int girth) {
-            mGirth = girth;
-            return this;
-        }
+    /**
+     * @return one of the following values, or {@code -1} if the side is unknown
+     * STATUS_BAR = 0
+     * NAVIGATION_BAR = 1
+     * STATUS_BAR_EXTRA = 2
+     * NAVIGATION_BAR_EXTRA = 3
+     */
+    int getSystemBarInsetTypeBySide(@SystemBarSide int side);
 
-        private SystemBarConfigBuilder setZOrder(int zOrder) {
-            mZOrder = zOrder;
-            return this;
-        }
+    /**
+     * @param index must be one of the following values
+     * STATUS_BAR = 0
+     * NAVIGATION_BAR = 1
+     * STATUS_BAR_EXTRA = 2
+     * NAVIGATION_BAR_EXTRA = 3
+     * see {@link #getSystemBarInsetTypeBySide(int)}
+     *
+     * @return The {@link InsetsFrameProvider}, or {@code null} if the side is unknown
+     */
+    InsetsFrameProvider getInsetsFrameProvider(int index);
 
-        private SystemBarConfigBuilder setHideForKeyboard(boolean hide) {
-            mHideForKeyboard = hide;
-            return this;
-        }
+    /**
+     * @return whether the left toolbar is used for display compat.
+     */
+    boolean isLeftDisplayCompatToolbarEnabled();
 
-        private SystemBarConfig build() {
-            return new SystemBarConfig(mSide, mBarType, mGirth, mZOrder, mHideForKeyboard);
-        }
-    }
+    /**
+     * @return whether the right toolbar is used for display compat.
+     */
+    boolean isRightDisplayCompatToolbarEnabled();
 }
diff --git a/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java b/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java
new file mode 100644
index 00000000..95b30205
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java
@@ -0,0 +1,777 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+package com.android.systemui.car.systembar;
+
+import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
+
+import static com.android.car.dockutil.Flags.dockFeature;
+import static com.android.systemui.car.Flags.displayCompatibilityV2;
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
+
+import android.annotation.IdRes;
+import android.annotation.SuppressLint;
+import android.content.Context;
+import android.content.res.Resources;
+import android.graphics.PixelFormat;
+import android.os.Binder;
+import android.util.ArrayMap;
+import android.util.ArraySet;
+import android.util.Log;
+import android.view.Gravity;
+import android.view.InsetsFrameProvider;
+import android.view.View;
+import android.view.ViewGroup;
+import android.view.WindowInsets;
+import android.view.WindowManager;
+
+import com.android.car.dockutil.Flags;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.systemui.R;
+import com.android.systemui.car.notification.BottomNotificationPanelViewMediator;
+import com.android.systemui.car.notification.TopNotificationPanelViewMediator;
+import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
+import com.android.systemui.dagger.qualifiers.Main;
+
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Comparator;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+import javax.inject.Inject;
+
+/**
+ * Reads configs for system bars for each side (TOP, BOTTOM, LEFT, and RIGHT) and returns the
+ * corresponding {@link android.view.WindowManager.LayoutParams} per the configuration.
+ */
+public class SystemBarConfigsImpl implements SystemBarConfigs {
+
+    private static final String TAG = SystemBarConfigs.class.getSimpleName();
+    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
+
+    // The z-order from which system bars will start to appear on top of HUN's.
+    @VisibleForTesting
+    static final int HUN_Z_ORDER = 10;
+
+    private static final Binder INSETS_OWNER = new Binder();
+
+    /*
+        NOTE: The elements' order in the map below must be preserved as-is since the correct
+        corresponding values are obtained by the index.
+     */
+    private static final InsetsFrameProvider[] BAR_PROVIDER_MAP = {
+            new InsetsFrameProvider(
+                    INSETS_OWNER, 0 /* index */, WindowInsets.Type.statusBars()),
+            new InsetsFrameProvider(
+                    INSETS_OWNER, 0 /* index */, WindowInsets.Type.navigationBars()),
+            new InsetsFrameProvider(
+                    INSETS_OWNER, 1 /* index */, WindowInsets.Type.statusBars()),
+            new InsetsFrameProvider(
+                    INSETS_OWNER, 1 /* index */, WindowInsets.Type.navigationBars()),
+    };
+
+    private static final Map<@SystemBarSide Integer, Integer> BAR_GRAVITY_MAP = new ArrayMap<>();
+    private static final Map<@SystemBarSide Integer, String> BAR_TITLE_MAP = new ArrayMap<>();
+    private static final Map<@SystemBarSide Integer, InsetsFrameProvider> BAR_GESTURE_MAP =
+            new ArrayMap<>();
+
+    private final Context mContext;
+    private final Resources mResources;
+    private final Map<@SystemBarSide Integer, SystemBarConfig> mSystemBarConfigMap =
+            new ArrayMap<>();
+    private final List<@SystemBarSide Integer> mSystemBarSidesByZOrder = new ArrayList<>();
+    /** Maps @WindowManager.LayoutParams.WindowType to window contexts for that type. */
+    private final Map<Integer, Context> mWindowContexts = new ArrayMap<>();
+
+    private boolean mTopNavBarEnabled;
+    private boolean mBottomNavBarEnabled;
+    private boolean mLeftNavBarEnabled;
+    private boolean mRightNavBarEnabled;
+    private int mDisplayCompatToolbarState = 0;
+
+    @Inject
+    public SystemBarConfigsImpl(Context context, @Main Resources resources) {
+        mContext = context;
+        mResources = resources;
+        init();
+    }
+
+    private void init() {
+        populateMaps();
+        readConfigs();
+
+        checkOnlyOneDisplayCompatIsEnabled();
+        checkEnabledBarsHaveUniqueBarTypes();
+        checkAllOverlappingBarsHaveDifferentZOrders();
+        checkSystemBarEnabledForNotificationPanel();
+        checkHideBottomBarForKeyboardConfigSync();
+
+        setInsetPaddingsForOverlappingCorners();
+        sortSystemBarTypesByZOrder();
+    }
+
+    /**
+     * Invalidate cached resources and fetch from resources config file.
+     * TODO: b/260206944, Can remove this after we have a fix for overlaid resources not applied.
+     * <p>
+     * Since SystemBarConfig is a Scoped(Dagger Singleton Annotation), We will have stale values, of
+     * all the resources after the RRO is applied.
+     * Another way is to remove the Scope(Singleton), but the downside is that it will be re-created
+     * everytime.
+     * </p>
+     */
+    @Override
+    public void resetSystemBarConfigs() {
+        init();
+    }
+
+    @Override
+    public Context getWindowContextBySide(@SystemBarSide int side) {
+        SystemBarConfig config = mSystemBarConfigMap.get(side);
+        if (config == null) {
+            return null;
+        }
+        int windowType = config.mapZOrderToBarType(config.getZOrder());
+        if (mWindowContexts.containsKey(windowType)) {
+            return mWindowContexts.get(windowType);
+        }
+        Context context = mContext.createWindowContext(windowType, /* options= */ null);
+        mWindowContexts.put(windowType, context);
+        return context;
+    }
+
+    /**
+     * Returns the system bar layout for the given side. {@code null} if side is unknown.
+     */
+    @Override
+    public ViewGroup getSystemBarLayoutBySide(@SystemBarSide int side, boolean isSetUp) {
+        int layoutId = getSystemBarLayoutResBySide(side, isSetUp);
+        if (layoutId == 0) {
+            return null;
+        }
+
+        return (ViewGroup) View.inflate(getWindowContextBySide(side), layoutId, /* root= */ null);
+    }
+
+    private int getSystemBarLayoutResBySide(@SystemBarSide int side, boolean isSetUp) {
+        switch (side) {
+            case LEFT:
+                if (!isSetUp) {
+                    return R.layout.car_left_system_bar_unprovisioned;
+                } else {
+                    return R.layout.car_left_system_bar;
+                }
+            case TOP:
+                if (!isSetUp) {
+                    return R.layout.car_top_system_bar_unprovisioned;
+                } else if (Flags.dockFeature()) {
+                    return R.layout.car_top_system_bar_dock;
+                } else {
+                    return R.layout.car_top_system_bar;
+                }
+            case RIGHT:
+                if (!isSetUp) {
+                    return R.layout.car_right_system_bar_unprovisioned;
+                } else {
+                    return R.layout.car_right_system_bar;
+                }
+            case BOTTOM:
+                if (!isSetUp) {
+                    return R.layout.car_bottom_system_bar_unprovisioned;
+                } else if (Flags.dockFeature()) {
+                    return R.layout.car_bottom_system_bar_dock;
+                } else {
+                    return R.layout.car_bottom_system_bar;
+                }
+            default:
+                return 0;
+        }
+    }
+
+    /**
+     * Returns the system bar window for the given side.
+     */
+    @Override
+    public ViewGroup getWindowLayoutBySide(@SystemBarSide int side) {
+        int windowId = getWindowIdBySide(side);
+        if (windowId == 0) {
+            return null;
+        }
+        ViewGroup window = (ViewGroup) View.inflate(getWindowContextBySide(side),
+                R.layout.navigation_bar_window, /* root= */ null);
+        // Setting a new id to each window because we're inflating the same layout and that layout
+        // already has an id. and we don't want to have the same id on all the system bar windows.
+        window.setId(windowId);
+        return window;
+    }
+
+    /**
+     * Returns an id for the given side that can be set on the system bar window.
+     * 0 means the side is unknown.
+     */
+    @IdRes
+    private int getWindowIdBySide(@SystemBarSide int side) {
+        return switch (side) {
+            case TOP -> R.id.car_top_bar_window;
+            case BOTTOM -> R.id.car_bottom_bar_window;
+            case LEFT -> R.id.car_left_bar_window;
+            case RIGHT -> R.id.car_right_bar_window;
+            default -> 0;
+        };
+    }
+
+    @Override
+    public WindowManager.LayoutParams getLayoutParamsBySide(@SystemBarSide int side) {
+        return mSystemBarConfigMap.get(side) != null
+                ? mSystemBarConfigMap
+                .get(side).getLayoutParams()
+                : null;
+    }
+
+    @Override
+    public boolean getEnabledStatusBySide(@SystemBarSide int side) {
+        switch (side) {
+            case TOP:
+                return mTopNavBarEnabled;
+            case BOTTOM:
+                return mBottomNavBarEnabled;
+            case LEFT:
+                return mLeftNavBarEnabled || isLeftDisplayCompatToolbarEnabled();
+            case RIGHT:
+                return mRightNavBarEnabled || isRightDisplayCompatToolbarEnabled();
+            default:
+                return false;
+        }
+    }
+
+    @Override
+    public boolean getHideForKeyboardBySide(@SystemBarSide int side) {
+        return mSystemBarConfigMap.get(side) != null
+                && mSystemBarConfigMap.get(side).getHideForKeyboard();
+    }
+
+    @Override
+    public void insetSystemBar(@SystemBarSide int side, ViewGroup view) {
+        if (mSystemBarConfigMap.get(side) == null) return;
+
+        int[] paddings = mSystemBarConfigMap.get(side).getPaddings();
+        if (DEBUG) {
+            Log.d(TAG, "Set padding to side = " + side + ", to " + Arrays.toString(paddings));
+        }
+        view.setPadding(paddings[LEFT], paddings[TOP], paddings[RIGHT], paddings[BOTTOM]);
+    }
+
+    @Override
+    public List<@SystemBarSide Integer> getSystemBarSidesByZOrder() {
+        return mSystemBarSidesByZOrder;
+    }
+
+    @Override
+    public int getSystemBarInsetTypeBySide(@SystemBarSide int side) {
+        return mSystemBarConfigMap.get(side) != null
+                ? mSystemBarConfigMap.get(side).getBarType() : -1;
+    }
+
+    @Override
+    public InsetsFrameProvider getInsetsFrameProvider(int index) {
+        return BAR_PROVIDER_MAP[index];
+    }
+
+    @VisibleForTesting
+    void updateInsetPaddings(@SystemBarSide int side,
+            Map<@SystemBarSide Integer, Boolean> barVisibilities) {
+        SystemBarConfig currentConfig = mSystemBarConfigMap.get(side);
+
+        if (currentConfig == null) return;
+
+        int defaultLeftPadding = 0;
+        int defaultRightPadding = 0;
+        int defaultTopPadding = 0;
+        int defaultBottomPadding = 0;
+
+        switch (side) {
+            case LEFT: {
+                defaultLeftPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_left_system_bar_left_padding);
+                defaultRightPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_left_system_bar_right_padding);
+                defaultTopPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_left_system_bar_top_padding);
+                defaultBottomPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_left_system_bar_bottom_padding);
+                break;
+            }
+            case RIGHT: {
+                defaultLeftPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_right_system_bar_left_padding);
+                defaultRightPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_right_system_bar_right_padding);
+                defaultTopPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_right_system_bar_top_padding);
+                defaultBottomPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_right_system_bar_bottom_padding);
+                break;
+            }
+            case TOP: {
+                defaultLeftPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_top_system_bar_left_padding);
+                defaultRightPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_top_system_bar_right_padding);
+                defaultTopPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_top_system_bar_top_padding);
+                defaultBottomPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_top_system_bar_bottom_padding);
+                break;
+            }
+            case BOTTOM: {
+                defaultLeftPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_bottom_system_bar_left_padding);
+                defaultRightPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_bottom_system_bar_right_padding);
+                defaultTopPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_bottom_system_bar_top_padding);
+                defaultBottomPadding = mResources
+                        .getDimensionPixelSize(R.dimen.car_bottom_system_bar_bottom_padding);
+                break;
+            }
+            default:
+        }
+
+        currentConfig.setPaddingBySide(LEFT, defaultLeftPadding);
+        currentConfig.setPaddingBySide(RIGHT, defaultRightPadding);
+        currentConfig.setPaddingBySide(TOP, defaultTopPadding);
+        currentConfig.setPaddingBySide(BOTTOM, defaultBottomPadding);
+
+        if (isHorizontalBar(side)) {
+            if (mLeftNavBarEnabled && currentConfig.getZOrder() < mSystemBarConfigMap.get(
+                    LEFT).getZOrder()) {
+                currentConfig.setPaddingBySide(LEFT,
+                        barVisibilities.get(LEFT)
+                                ? mSystemBarConfigMap.get(LEFT).getGirth()
+                                : defaultLeftPadding);
+            }
+            if (mRightNavBarEnabled && currentConfig.getZOrder() < mSystemBarConfigMap.get(
+                    RIGHT).getZOrder()) {
+                currentConfig.setPaddingBySide(RIGHT,
+                        barVisibilities.get(RIGHT)
+                                ? mSystemBarConfigMap.get(RIGHT).getGirth()
+                                : defaultRightPadding);
+            }
+        }
+        if (isVerticalBar(side)) {
+            if (mTopNavBarEnabled && currentConfig.getZOrder() < mSystemBarConfigMap.get(
+                    TOP).getZOrder()) {
+                currentConfig.setPaddingBySide(TOP,
+                        barVisibilities.get(TOP)
+                                ? mSystemBarConfigMap.get(TOP).getGirth()
+                                : defaultTopPadding);
+            }
+            if (mBottomNavBarEnabled && currentConfig.getZOrder() < mSystemBarConfigMap.get(
+                    BOTTOM).getZOrder()) {
+                currentConfig.setPaddingBySide(BOTTOM,
+                        barVisibilities.get(BOTTOM)
+                                ? mSystemBarConfigMap.get(BOTTOM).getGirth()
+                                : defaultBottomPadding);
+            }
+
+        }
+        if (DEBUG) {
+            Log.d(TAG, "Update padding for side = " + side + " to "
+                    + Arrays.toString(currentConfig.getPaddings()));
+        }
+    }
+
+    @SuppressLint("RtlHardcoded")
+    private static void populateMaps() {
+        BAR_GRAVITY_MAP.put(TOP, Gravity.TOP);
+        BAR_GRAVITY_MAP.put(BOTTOM, Gravity.BOTTOM);
+        BAR_GRAVITY_MAP.put(LEFT, Gravity.LEFT);
+        BAR_GRAVITY_MAP.put(RIGHT, Gravity.RIGHT);
+
+        BAR_TITLE_MAP.put(TOP, "TopCarSystemBar");
+        BAR_TITLE_MAP.put(BOTTOM, "BottomCarSystemBar");
+        BAR_TITLE_MAP.put(LEFT, "LeftCarSystemBar");
+        BAR_TITLE_MAP.put(RIGHT, "RightCarSystemBar");
+
+        BAR_GESTURE_MAP.put(TOP, new InsetsFrameProvider(
+                INSETS_OWNER, 0 /* index */, WindowInsets.Type.mandatorySystemGestures()));
+        BAR_GESTURE_MAP.put(BOTTOM, new InsetsFrameProvider(
+                INSETS_OWNER, 1 /* index */, WindowInsets.Type.mandatorySystemGestures()));
+        BAR_GESTURE_MAP.put(LEFT, new InsetsFrameProvider(
+                INSETS_OWNER, 2 /* index */, WindowInsets.Type.mandatorySystemGestures()));
+        BAR_GESTURE_MAP.put(RIGHT, new InsetsFrameProvider(
+                INSETS_OWNER, 3 /* index */, WindowInsets.Type.mandatorySystemGestures()));
+    }
+
+    private void readConfigs() {
+        mTopNavBarEnabled = mResources.getBoolean(R.bool.config_enableTopSystemBar);
+        mBottomNavBarEnabled = mResources.getBoolean(R.bool.config_enableBottomSystemBar);
+        mLeftNavBarEnabled = mResources.getBoolean(R.bool.config_enableLeftSystemBar);
+        mRightNavBarEnabled = mResources.getBoolean(R.bool.config_enableRightSystemBar);
+        mDisplayCompatToolbarState =
+            mResources.getInteger(R.integer.config_showDisplayCompatToolbarOnSystemBar);
+        mSystemBarConfigMap.clear();
+
+        if ((mLeftNavBarEnabled && isLeftDisplayCompatToolbarEnabled())
+                || (mRightNavBarEnabled && isRightDisplayCompatToolbarEnabled())) {
+            throw new IllegalStateException(
+                "Navigation Bar and Display Compat toolbar can't be "
+                    + "on the same side");
+        }
+
+        if (mTopNavBarEnabled) {
+            SystemBarConfig topBarConfig =
+                    new SystemBarConfigBuilder()
+                            .setSide(TOP)
+                            .setGirth(mResources.getDimensionPixelSize(
+                                    R.dimen.car_top_system_bar_height))
+                            .setBarType(
+                                    mResources.getInteger(R.integer.config_topSystemBarType))
+                            .setZOrder(
+                                    mResources.getInteger(R.integer.config_topSystemBarZOrder))
+                            .setHideForKeyboard(mResources.getBoolean(
+                                    R.bool.config_hideTopSystemBarForKeyboard))
+                            .build();
+            mSystemBarConfigMap.put(TOP, topBarConfig);
+        }
+
+        if (mBottomNavBarEnabled) {
+            SystemBarConfig bottomBarConfig =
+                    new SystemBarConfigBuilder()
+                            .setSide(BOTTOM)
+                            .setGirth(mResources.getDimensionPixelSize(
+                                    R.dimen.car_bottom_system_bar_height))
+                            .setBarType(
+                                    mResources.getInteger(R.integer.config_bottomSystemBarType))
+                            .setZOrder(
+                                    mResources.getInteger(
+                                            R.integer.config_bottomSystemBarZOrder))
+                            .setHideForKeyboard(mResources.getBoolean(
+                                    R.bool.config_hideBottomSystemBarForKeyboard))
+                            .build();
+            mSystemBarConfigMap.put(BOTTOM, bottomBarConfig);
+        }
+
+        if (mLeftNavBarEnabled || isLeftDisplayCompatToolbarEnabled()) {
+            SystemBarConfig leftBarConfig =
+                    new SystemBarConfigBuilder()
+                            .setSide(LEFT)
+                            .setGirth(mResources.getDimensionPixelSize(
+                                    R.dimen.car_left_system_bar_width))
+                            .setBarType(
+                                    mResources.getInteger(R.integer.config_leftSystemBarType))
+                            .setZOrder(
+                                    mResources.getInteger(R.integer.config_leftSystemBarZOrder))
+                            .setHideForKeyboard(mResources.getBoolean(
+                                    R.bool.config_hideLeftSystemBarForKeyboard))
+                            .build();
+            mSystemBarConfigMap.put(LEFT, leftBarConfig);
+        }
+
+        if (mRightNavBarEnabled || isRightDisplayCompatToolbarEnabled()) {
+            SystemBarConfig rightBarConfig =
+                    new SystemBarConfigBuilder()
+                            .setSide(RIGHT)
+                            .setGirth(mResources.getDimensionPixelSize(
+                                    R.dimen.car_right_system_bar_width))
+                            .setBarType(
+                                    mResources.getInteger(R.integer.config_rightSystemBarType))
+                            .setZOrder(mResources.getInteger(
+                                    R.integer.config_rightSystemBarZOrder))
+                            .setHideForKeyboard(mResources.getBoolean(
+                                    R.bool.config_hideRightSystemBarForKeyboard))
+                            .build();
+            mSystemBarConfigMap.put(RIGHT, rightBarConfig);
+        }
+    }
+
+    private void checkOnlyOneDisplayCompatIsEnabled() throws IllegalStateException {
+        boolean useRemoteLaunchTaskView =
+                mResources.getBoolean(R.bool.config_useRemoteLaunchTaskView);
+        int displayCompatEnabled =
+                mResources.getInteger(R.integer.config_showDisplayCompatToolbarOnSystemBar);
+        if (useRemoteLaunchTaskView && displayCompatEnabled != 0) {
+            throw new IllegalStateException("config_useRemoteLaunchTaskView is enabled but "
+                    + "config_showDisplayCompatToolbarOnSystemBar is non-zero");
+        }
+    }
+
+    private void checkEnabledBarsHaveUniqueBarTypes() throws RuntimeException {
+        Set<Integer> barTypesUsed = new ArraySet<>();
+        int enabledNavBarCount = mSystemBarConfigMap.size();
+
+        for (SystemBarConfig systemBarConfig : mSystemBarConfigMap.values()) {
+            barTypesUsed.add(systemBarConfig.getBarType());
+        }
+
+        // The number of bar types used cannot be fewer than that of enabled system bars.
+        if (barTypesUsed.size() < enabledNavBarCount) {
+            throw new RuntimeException("Each enabled system bar must have a unique bar type. Check "
+                    + "the configuration in config.xml");
+        }
+    }
+
+    private void checkAllOverlappingBarsHaveDifferentZOrders() {
+        checkOverlappingBarsHaveDifferentZOrders(TOP, LEFT);
+        checkOverlappingBarsHaveDifferentZOrders(TOP, RIGHT);
+        checkOverlappingBarsHaveDifferentZOrders(BOTTOM, LEFT);
+        checkOverlappingBarsHaveDifferentZOrders(BOTTOM, RIGHT);
+    }
+
+    private void checkSystemBarEnabledForNotificationPanel() throws RuntimeException {
+        String notificationPanelMediatorName =
+                mResources.getString(R.string.config_notificationPanelViewMediator);
+        if (notificationPanelMediatorName == null) {
+            return;
+        }
+
+        Class<?> notificationPanelMediatorUsed = null;
+        try {
+            notificationPanelMediatorUsed = Class.forName(notificationPanelMediatorName);
+        } catch (ClassNotFoundException e) {
+            Log.e(TAG, "notification panel mediator class not found", e);
+        }
+
+        if (!mTopNavBarEnabled && TopNotificationPanelViewMediator.class.isAssignableFrom(
+                notificationPanelMediatorUsed)) {
+            throw new RuntimeException(
+                    "Top System Bar must be enabled to use " + notificationPanelMediatorName);
+        }
+
+        if (!mBottomNavBarEnabled && BottomNotificationPanelViewMediator.class.isAssignableFrom(
+                notificationPanelMediatorUsed)) {
+            throw new RuntimeException("Bottom System Bar must be enabled to use "
+                    + notificationPanelMediatorName);
+        }
+    }
+
+    private void checkHideBottomBarForKeyboardConfigSync() throws RuntimeException {
+        if (mBottomNavBarEnabled) {
+            boolean actual = mResources.getBoolean(R.bool.config_hideBottomSystemBarForKeyboard);
+            boolean expected = mResources.getBoolean(
+                    com.android.internal.R.bool.config_hideNavBarForKeyboard);
+
+            if (actual != expected) {
+                throw new RuntimeException("config_hideBottomSystemBarForKeyboard must not be "
+                        + "overlaid directly and should always refer to"
+                        + "config_hideNavBarForKeyboard. However, their values "
+                        + "currently do not sync. Set config_hideBottomSystemBarForKeyguard to "
+                        + "@*android:bool/config_hideNavBarForKeyboard. To change its "
+                        + "value, overlay config_hideNavBarForKeyboard in "
+                        + "framework/base/core/res/res.");
+            }
+        }
+    }
+
+    private void setInsetPaddingsForOverlappingCorners() {
+        Map<@SystemBarSide Integer, Boolean> systemBarVisibilityOnInit =
+                getSystemBarsVisibilityOnInit();
+        updateInsetPaddings(TOP, systemBarVisibilityOnInit);
+        updateInsetPaddings(BOTTOM, systemBarVisibilityOnInit);
+        updateInsetPaddings(LEFT, systemBarVisibilityOnInit);
+        updateInsetPaddings(RIGHT, systemBarVisibilityOnInit);
+    }
+
+    private void sortSystemBarTypesByZOrder() {
+        List<SystemBarConfig> systemBarsByZOrder = new ArrayList<>(mSystemBarConfigMap.values());
+
+        systemBarsByZOrder.sort(new Comparator<SystemBarConfig>() {
+            @Override
+            public int compare(SystemBarConfig o1, SystemBarConfig o2) {
+                return o1.getZOrder() - o2.getZOrder();
+            }
+        });
+
+        mSystemBarSidesByZOrder.clear();
+        systemBarsByZOrder.forEach(systemBarConfig -> {
+            mSystemBarSidesByZOrder.add(systemBarConfig.getSide());
+        });
+    }
+
+    // On init, system bars are visible as long as they are enabled.
+    private Map<@SystemBarSide Integer, Boolean> getSystemBarsVisibilityOnInit() {
+        ArrayMap<@SystemBarSide Integer, Boolean> visibilityMap = new ArrayMap<>();
+        visibilityMap.put(TOP, mTopNavBarEnabled);
+        visibilityMap.put(BOTTOM, mBottomNavBarEnabled);
+        visibilityMap.put(LEFT, mLeftNavBarEnabled || isLeftDisplayCompatToolbarEnabled());
+        visibilityMap.put(RIGHT, mRightNavBarEnabled || isRightDisplayCompatToolbarEnabled());
+        return visibilityMap;
+    }
+
+    private void checkOverlappingBarsHaveDifferentZOrders(@SystemBarSide int horizontalSide,
+            @SystemBarSide int verticalSide) {
+
+        if (isVerticalBar(horizontalSide) || isHorizontalBar(verticalSide)) {
+            Log.w(TAG, "configureBarPaddings: Returning immediately since the horizontal and "
+                    + "vertical sides were not provided correctly.");
+            return;
+        }
+
+        SystemBarConfig horizontalBarConfig = mSystemBarConfigMap.get(horizontalSide);
+        SystemBarConfig verticalBarConfig = mSystemBarConfigMap.get(verticalSide);
+
+        if (verticalBarConfig != null && horizontalBarConfig != null) {
+            int horizontalBarZOrder = horizontalBarConfig.getZOrder();
+            int verticalBarZOrder = verticalBarConfig.getZOrder();
+
+            if (horizontalBarZOrder == verticalBarZOrder) {
+                throw new RuntimeException(
+                        BAR_TITLE_MAP.get(horizontalSide) + " " + BAR_TITLE_MAP.get(verticalSide)
+                                + " have the same Z-Order, and so their placing order cannot be "
+                                + "determined. Determine which bar should be placed on top of the "
+                                + "other bar and change the Z-order in config.xml accordingly."
+                );
+            }
+        }
+    }
+
+    private static boolean isHorizontalBar(@SystemBarSide int side) {
+        return side == TOP || side == BOTTOM;
+    }
+
+    private static boolean isVerticalBar(@SystemBarSide int side) {
+        return side == LEFT || side == RIGHT;
+    }
+
+    @Override
+    public boolean isLeftDisplayCompatToolbarEnabled() {
+        return displayCompatibilityV2() && mDisplayCompatToolbarState == 1;
+    }
+
+    @Override
+    public boolean isRightDisplayCompatToolbarEnabled() {
+        return displayCompatibilityV2() && mDisplayCompatToolbarState == 2;
+    }
+
+    private static final class SystemBarConfig {
+        private final int mSide;
+        private final int mBarType;
+        private final int mGirth;
+        private final int mZOrder;
+        private final boolean mHideForKeyboard;
+
+        private int[] mPaddings = new int[]{0, 0, 0, 0};
+
+        private SystemBarConfig(@SystemBarSide int side, int barType, int girth, int zOrder,
+                boolean hideForKeyboard) {
+            mSide = side;
+            mBarType = barType;
+            mGirth = girth;
+            mZOrder = zOrder;
+            mHideForKeyboard = hideForKeyboard;
+        }
+
+        private int getSide() {
+            return mSide;
+        }
+
+        private int getBarType() {
+            return mBarType;
+        }
+
+        private int getGirth() {
+            return mGirth;
+        }
+
+        private int getZOrder() {
+            return mZOrder;
+        }
+
+        private boolean getHideForKeyboard() {
+            return mHideForKeyboard;
+        }
+
+        private int[] getPaddings() {
+            return mPaddings;
+        }
+
+        private WindowManager.LayoutParams getLayoutParams() {
+            WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
+                    isHorizontalBar(mSide) ? ViewGroup.LayoutParams.MATCH_PARENT : mGirth,
+                    isHorizontalBar(mSide) ? mGirth : ViewGroup.LayoutParams.MATCH_PARENT,
+                    mapZOrderToBarType(mZOrder),
+                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
+                            | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
+                            | WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH
+                            | WindowManager.LayoutParams.FLAG_SPLIT_TOUCH,
+                    PixelFormat.TRANSLUCENT);
+            lp.setTitle(BAR_TITLE_MAP.get(mSide));
+            lp.providedInsets = new InsetsFrameProvider[] {
+                    BAR_PROVIDER_MAP[mBarType],
+                    BAR_GESTURE_MAP.get(mSide)
+            };
+            lp.setFitInsetsTypes(0);
+            lp.windowAnimations = 0;
+            lp.gravity = BAR_GRAVITY_MAP.get(mSide);
+            lp.layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
+            if (dockFeature()) {
+                lp.privateFlags = lp.privateFlags
+                        | WindowManager.LayoutParams.PRIVATE_FLAG_INTERCEPT_GLOBAL_DRAG_AND_DROP;
+            }
+            return lp;
+        }
+
+        private int mapZOrderToBarType(int zOrder) {
+            return zOrder >= HUN_Z_ORDER ? WindowManager.LayoutParams.TYPE_NAVIGATION_BAR_PANEL
+                    : WindowManager.LayoutParams.TYPE_STATUS_BAR_ADDITIONAL;
+        }
+
+        private void setPaddingBySide(@SystemBarSide int side, int padding) {
+            mPaddings[side] = padding;
+        }
+    }
+
+    private static final class SystemBarConfigBuilder {
+        private int mSide;
+        private int mBarType;
+        private int mGirth;
+        private int mZOrder;
+        private boolean mHideForKeyboard;
+
+        private SystemBarConfigBuilder setSide(@SystemBarSide int side) {
+            mSide = side;
+            return this;
+        }
+
+        private SystemBarConfigBuilder setBarType(int type) {
+            mBarType = type;
+            return this;
+        }
+
+        private SystemBarConfigBuilder setGirth(int girth) {
+            mGirth = girth;
+            return this;
+        }
+
+        private SystemBarConfigBuilder setZOrder(int zOrder) {
+            mZOrder = zOrder;
+            return this;
+        }
+
+        private SystemBarConfigBuilder setHideForKeyboard(boolean hide) {
+            mHideForKeyboard = hide;
+            return this;
+        }
+
+        private SystemBarConfig build() {
+            return new SystemBarConfig(mSide, mBarType, mGirth, mZOrder, mHideForKeyboard);
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/telecom/InCallServiceImpl.java b/src/com/android/systemui/car/telecom/InCallServiceImpl.java
index dd73816a..20d4efd4 100644
--- a/src/com/android/systemui/car/telecom/InCallServiceImpl.java
+++ b/src/com/android/systemui/car/telecom/InCallServiceImpl.java
@@ -19,9 +19,12 @@ import android.telecom.Call;
 import android.telecom.InCallService;
 import android.util.Log;
 
+import androidx.annotation.VisibleForTesting;
+
 import com.android.car.telephony.calling.InCallServiceManager;
 
 import java.util.ArrayList;
+import java.util.List;
 
 import javax.inject.Inject;
 
@@ -37,6 +40,33 @@ public class InCallServiceImpl extends InCallService {
     private final InCallServiceManager mServiceManager;
     private final ArrayList<InCallListener> mInCallListeners = new ArrayList<>();
 
+    @VisibleForTesting
+    final Call.Callback mCallStateChangedCallback = new Call.Callback() {
+        @Override
+        public void onStateChanged(Call call, int state) {
+            Log.d(TAG, "onStateChanged: " + call);
+            for (InCallListener listener : mInCallListeners) {
+                listener.onStateChanged(call, state);
+            }
+        }
+
+        @Override
+        public void onParentChanged(Call call, Call parent) {
+            Log.d(TAG, "onParentChanged: " + call);
+            for (InCallListener listener : mInCallListeners) {
+                listener.onParentChanged(call, parent);
+            }
+        }
+
+        @Override
+        public void onChildrenChanged(Call call, List<Call> children) {
+            Log.d(TAG, "onChildrenChanged: " + call);
+            for (InCallListener listener : mInCallListeners) {
+                listener.onChildrenChanged(call, children);
+            }
+        }
+    };
+
     @Inject
     public InCallServiceImpl(InCallServiceManager serviceManager) {
         mServiceManager = serviceManager;
@@ -58,7 +88,8 @@ public class InCallServiceImpl extends InCallService {
 
     @Override
     public void onCallAdded(Call call) {
-        if (DEBUG) Log.d(TAG, "onCallAdded: " + call);
+        Log.d(TAG, "onCallAdded: " + call);
+        call.registerCallback(mCallStateChangedCallback);
         for (InCallListener listener : mInCallListeners) {
             listener.onCallAdded(call);
         }
@@ -66,7 +97,8 @@ public class InCallServiceImpl extends InCallService {
 
     @Override
     public void onCallRemoved(Call call) {
-        if (DEBUG) Log.d(TAG, "onCallRemoved: " + call);
+        Log.d(TAG, "onCallRemoved: " + call);
+        call.unregisterCallback(mCallStateChangedCallback);
         for (InCallListener listener : mInCallListeners) {
             listener.onCallRemoved(call);
         }
@@ -101,5 +133,20 @@ public class InCallServiceImpl extends InCallService {
          * indicating that the call has ended.
          */
         void onCallRemoved(Call call);
+
+        /**
+         * Called when the state of a {@link Call} has changed.
+         */
+        void onStateChanged(Call call, int state);
+
+        /**
+         * Called when a {@link Call} has been added to a conference.
+         */
+        void onParentChanged(Call call, Call parent);
+
+        /**
+         * Called when a conference {@link Call} has children calls added or removed.
+         */
+        void onChildrenChanged(Call call, List<Call> children);
     }
 }
diff --git a/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java b/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
index 492edf7e..8b91306c 100644
--- a/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
+++ b/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
@@ -17,7 +17,7 @@
 package com.android.systemui.car.users;
 
 import static android.car.CarOccupantZoneManager.DISPLAY_TYPE_MAIN;
-import static android.hardware.display.DisplayManager.EVENT_FLAG_DISPLAY_BRIGHTNESS;
+import static android.hardware.display.DisplayManager.PRIVATE_EVENT_FLAG_DISPLAY_BRIGHTNESS;
 
 import static com.android.systemui.car.users.CarSystemUIUserUtil.isCurrentSystemUIDisplay;
 import static com.android.systemui.car.users.CarSystemUIUserUtil.isMUMDSystemUI;
@@ -174,7 +174,7 @@ public class CarMUMDDisplayTrackerImpl implements DisplayTracker {
         synchronized (mBrightnessCallbacks) {
             if (mBrightnessCallbacks.isEmpty()) {
                 mDisplayManager.registerDisplayListener(mBrightnessChangedListener, mHandler,
-                        EVENT_FLAG_DISPLAY_BRIGHTNESS);
+                        0, PRIVATE_EVENT_FLAG_DISPLAY_BRIGHTNESS);
             }
             mBrightnessCallbacks.add(new DisplayTrackerCallbackData(callback, executor));
         }
diff --git a/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java b/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
index 61a5c1c0..a6fb5305 100644
--- a/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
+++ b/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
@@ -21,6 +21,7 @@ import static android.content.DialogInterface.BUTTON_POSITIVE;
 import static android.os.UserManager.DISALLOW_ADD_USER;
 import static android.os.UserManager.SWITCHABILITY_STATUS_OK;
 import static android.view.WindowInsets.Type.statusBars;
+import static android.view.WindowManager.LayoutParams.TYPE_KEYGUARD_DIALOG;
 
 import static com.android.systemui.car.users.CarSystemUIUserUtil.getCurrentUserHandle;
 
@@ -253,6 +254,7 @@ public class UserGridRecyclerView extends RecyclerView {
             implements Dialog.OnClickListener, Dialog.OnCancelListener {
 
         private final Context mContext;
+        private Context mKeyguardDialogWindowContext;
         private List<UserRecord> mUsers;
         private final Resources mRes;
         private final String mGuestName;
@@ -397,7 +399,7 @@ public class UserGridRecyclerView extends RecyclerView {
                     .concat(System.getProperty("line.separator"))
                     .concat(mRes.getString(R.string.user_add_user_message_update));
 
-            AlertDialog addUserDialog = new Builder(mContext,
+            AlertDialog addUserDialog = new Builder(getKeyguardDialogWindowContext(),
                     com.android.internal.R.style.Theme_DeviceDefault_Dialog_Alert)
                     .setTitle(R.string.user_add_profile_title)
                     .setMessage(message)
@@ -412,13 +414,21 @@ public class UserGridRecyclerView extends RecyclerView {
 
         private void applyCarSysUIDialogFlags(AlertDialog dialog) {
             final Window window = dialog.getWindow();
-            window.setType(WindowManager.LayoutParams.TYPE_KEYGUARD_DIALOG);
+            window.setType(TYPE_KEYGUARD_DIALOG);
             window.addFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM
                     | WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED);
             window.getAttributes().setFitInsetsTypes(
                     window.getAttributes().getFitInsetsTypes() & ~statusBars());
         }
 
+        private Context getKeyguardDialogWindowContext() {
+            if (mKeyguardDialogWindowContext == null) {
+                mKeyguardDialogWindowContext = mContext.createWindowContext(TYPE_KEYGUARD_DIALOG,
+                        /* options= */ null);
+            }
+            return mKeyguardDialogWindowContext;
+        }
+
         private void notifyUserSelected(UserRecord userRecord) {
             // Notify the listener which user was selected
             if (mUserSelectionListener != null) {
diff --git a/src/com/android/systemui/car/window/OverlayPanelViewController.java b/src/com/android/systemui/car/window/OverlayPanelViewController.java
index d4630879..2a3cfa35 100644
--- a/src/com/android/systemui/car/window/OverlayPanelViewController.java
+++ b/src/com/android/systemui/car/window/OverlayPanelViewController.java
@@ -208,6 +208,23 @@ public abstract class OverlayPanelViewController extends OverlayViewController {
         }
     }
 
+    /**
+     * Returning true from this method will make other panels to become hidden.
+     */
+    public boolean isExclusive() {
+        return true;
+    }
+
+    /**
+     * Returning true from this method means the system bars will return true from
+     * {@link ViewGroup#onInterceptTouchEvent} method if the system bars support
+     * drag by setting both R.bool.config_systemBarButtonsDraggable and
+     * R.bool.config_consumeSystemBarTouchWhenNotificationPanelOpen to true.
+     */
+    public boolean shouldPanelConsumeSystemBarTouch() {
+        return false;
+    }
+
     /** Checks if a {@link MotionEvent} is an action to open the panel.
      * @param e {@link MotionEvent} to check.
      * @return true only if opening action.
diff --git a/src/com/android/systemui/car/window/OverlayViewController.java b/src/com/android/systemui/car/window/OverlayViewController.java
index a1f6f6ca..7ac4c074 100644
--- a/src/com/android/systemui/car/window/OverlayViewController.java
+++ b/src/com/android/systemui/car/window/OverlayViewController.java
@@ -184,6 +184,14 @@ public class OverlayViewController {
         return !mLayout.isInTouchMode() && mLayout.hasFocus();
     }
 
+    /**
+     * Callback for the individual view controllers when the window focusable state has changed.
+     * This will only go to the highest z-order window and will be re-called when the window
+     * visibilities change.
+     */
+    public void onWindowFocusableChanged(boolean focusable) {
+    }
+
     /**
      * Sets whether this view allows rotary focus. This should be set to {@code true} for the
      * topmost layer in the overlay window and {@code false} for the others.
diff --git a/src/com/android/systemui/car/window/OverlayViewGlobalStateController.java b/src/com/android/systemui/car/window/OverlayViewGlobalStateController.java
index 3da60cf1..0b2953a8 100644
--- a/src/com/android/systemui/car/window/OverlayViewGlobalStateController.java
+++ b/src/com/android/systemui/car/window/OverlayViewGlobalStateController.java
@@ -30,13 +30,9 @@ import androidx.annotation.VisibleForTesting;
 
 import com.android.systemui.dagger.SysUISingleton;
 
-import java.util.HashMap;
 import java.util.HashSet;
-import java.util.Map;
 import java.util.Objects;
 import java.util.Set;
-import java.util.SortedMap;
-import java.util.TreeMap;
 
 import javax.inject.Inject;
 
@@ -53,33 +49,30 @@ import javax.inject.Inject;
 public class OverlayViewGlobalStateController {
     private static final boolean DEBUG = false;
     private static final String TAG = OverlayViewGlobalStateController.class.getSimpleName();
-    private static final int UNKNOWN_Z_ORDER = -1;
     private final SystemUIOverlayWindowController mSystemUIOverlayWindowController;
     private final WindowInsetsController mWindowInsetsController;
-    @VisibleForTesting
-    Map<OverlayViewController, Integer> mZOrderMap;
-    @VisibleForTesting
-    SortedMap<Integer, OverlayViewController> mZOrderVisibleSortedMap;
+    private final OverlayVisibilityMediator mOverlayVisibilityMediator;
+
     @VisibleForTesting
     Set<OverlayViewController> mViewsHiddenForOcclusion;
-    @VisibleForTesting
-    OverlayViewController mHighestZOrder;
     private boolean mIsOccluded;
 
     @Inject
     public OverlayViewGlobalStateController(
-            SystemUIOverlayWindowController systemUIOverlayWindowController) {
+            SystemUIOverlayWindowController systemUIOverlayWindowController,
+            OverlayVisibilityMediator overlayVisibilityMediator) {
         mSystemUIOverlayWindowController = systemUIOverlayWindowController;
+        mOverlayVisibilityMediator = overlayVisibilityMediator;
         mSystemUIOverlayWindowController.attach();
         mSystemUIOverlayWindowController.registerOutsideTouchListener((v, event) -> {
-            if (mHighestZOrder != null) {
-                mHighestZOrder.onTouchEvent(v, event);
+            if (mOverlayVisibilityMediator.getHighestZOrderOverlayViewController() != null) {
+                mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()
+                        .onTouchEvent(v, event);
             }
         });
         mWindowInsetsController =
                 mSystemUIOverlayWindowController.getBaseLayout().getWindowInsetsController();
-        mZOrderMap = new HashMap<>();
-        mZOrderVisibleSortedMap = new TreeMap<>();
+
         mViewsHiddenForOcclusion = new HashSet<>();
     }
 
@@ -101,7 +94,7 @@ public class OverlayViewGlobalStateController {
      * controller itself.
      */
     public void showView(OverlayPanelViewController panelViewController) {
-        showView(panelViewController, /* show= */ null);
+        showView(panelViewController, /* show */ null);
     }
 
     /**
@@ -113,7 +106,7 @@ public class OverlayViewGlobalStateController {
             mViewsHiddenForOcclusion.add(viewController);
             return;
         }
-        if (mZOrderVisibleSortedMap.isEmpty()) {
+        if (!mOverlayVisibilityMediator.isAnyOverlayViewVisible()) {
             setWindowVisible(true);
         }
 
@@ -125,41 +118,19 @@ public class OverlayViewGlobalStateController {
             show.run();
         }
 
-        updateInternalsWhenShowingView(viewController);
+        mOverlayVisibilityMediator.showView(viewController);
         refreshUseStableInsets();
         refreshInsetsToFit();
         refreshWindowFocus();
         refreshWindowDefaultDimBehind();
-        refreshSystemBarVisibility();
-        refreshStatusBarVisibility();
+        refreshInsetTypeVisibility(navigationBars());
+        refreshInsetTypeVisibility(statusBars());
         refreshRotaryFocusIfNeeded();
 
         Log.d(TAG, "Content shown: " + viewController.getClass().getName());
         debugLog();
     }
 
-    private void updateInternalsWhenShowingView(OverlayViewController viewController) {
-        int zOrder;
-        if (mZOrderMap.containsKey(viewController)) {
-            zOrder = mZOrderMap.get(viewController);
-        } else {
-            zOrder = mSystemUIOverlayWindowController.getBaseLayout().indexOfChild(
-                    viewController.getLayout());
-            mZOrderMap.put(viewController, zOrder);
-        }
-
-        mZOrderVisibleSortedMap.put(zOrder, viewController);
-
-        refreshHighestZOrderWhenShowingView(viewController);
-    }
-
-    private void refreshHighestZOrderWhenShowingView(OverlayViewController viewController) {
-        if (mZOrderMap.getOrDefault(mHighestZOrder, UNKNOWN_Z_ORDER) < mZOrderMap.get(
-                viewController)) {
-            mHighestZOrder = viewController;
-        }
-    }
-
     /**
      * Hide content in Overlay Window using {@link OverlayPanelViewController}.
      *
@@ -168,7 +139,7 @@ public class OverlayViewGlobalStateController {
      * controller itself.
      */
     public void hideView(OverlayPanelViewController panelViewController) {
-        hideView(panelViewController, /* hide= */ null);
+        hideView(panelViewController, /* hide */ null);
     }
 
     /**
@@ -185,12 +156,12 @@ public class OverlayViewGlobalStateController {
                     + viewController.getClass().getName());
             return;
         }
-        if (!mZOrderMap.containsKey(viewController)) {
+        if (!mOverlayVisibilityMediator.hasOverlayViewBeenShown(viewController)) {
             Log.d(TAG, "Content cannot be hidden since it has never been shown: "
                     + viewController.getClass().getName());
             return;
         }
-        if (!mZOrderVisibleSortedMap.containsKey(mZOrderMap.get(viewController))) {
+        if (!mOverlayVisibilityMediator.isOverlayViewVisible(viewController)) {
             Log.d(TAG, "Content cannot be hidden since it isn't currently shown: "
                     + viewController.getClass().getName());
             return;
@@ -200,17 +171,16 @@ public class OverlayViewGlobalStateController {
             hide.run();
         }
 
-        mZOrderVisibleSortedMap.remove(mZOrderMap.get(viewController));
-        refreshHighestZOrderWhenHidingView(viewController);
+        mOverlayVisibilityMediator.hideView(viewController);
         refreshUseStableInsets();
         refreshInsetsToFit();
         refreshWindowFocus();
         refreshWindowDefaultDimBehind();
-        refreshSystemBarVisibility();
-        refreshStatusBarVisibility();
+        refreshInsetTypeVisibility(navigationBars());
+        refreshInsetTypeVisibility(statusBars());
         refreshRotaryFocusIfNeeded();
 
-        if (mZOrderVisibleSortedMap.isEmpty()) {
+        if (!mOverlayVisibilityMediator.isAnyOverlayViewVisible()) {
             setWindowVisible(false);
         }
 
@@ -225,65 +195,52 @@ public class OverlayViewGlobalStateController {
      * updated
      */
     public boolean updateWindowDimBehind(OverlayViewController viewController, float dimAmount) {
-        if (mHighestZOrder == null || viewController != mHighestZOrder) {
+        OverlayViewController highestZOrder = mOverlayVisibilityMediator
+                .getHighestZOrderOverlayViewController();
+        if (highestZOrder == null || viewController != highestZOrder) {
             return false;
         }
         mSystemUIOverlayWindowController.setDimBehind(dimAmount);
         return true;
     }
 
-    private void refreshHighestZOrderWhenHidingView(OverlayViewController viewController) {
-        if (mZOrderVisibleSortedMap.isEmpty()) {
-            mHighestZOrder = null;
-            return;
-        }
-        if (!mHighestZOrder.equals(viewController)) {
-            return;
-        }
-
-        mHighestZOrder = mZOrderVisibleSortedMap.get(mZOrderVisibleSortedMap.lastKey());
-    }
-
-    private void refreshSystemBarVisibility() {
-        if (mZOrderVisibleSortedMap.isEmpty()) {
-            mWindowInsetsController.show(navigationBars());
+    private void refreshInsetTypeVisibility(@InsetsType int insetType) {
+        if (!mOverlayVisibilityMediator.isAnyOverlayViewVisible()) {
+            mWindowInsetsController.show(insetType);
             return;
         }
 
         // Do not hide navigation bar insets if the window is not focusable.
-        if (mHighestZOrder.shouldFocusWindow() && !mHighestZOrder.shouldShowNavigationBarInsets()) {
-            mWindowInsetsController.hide(navigationBars());
-        } else {
-            mWindowInsetsController.show(navigationBars());
-        }
-    }
-
-    private void refreshStatusBarVisibility() {
-        if (mZOrderVisibleSortedMap.isEmpty()) {
-            mWindowInsetsController.show(statusBars());
-            return;
-        }
-
-        // Do not hide status bar insets if the window is not focusable.
-        if (mHighestZOrder.shouldFocusWindow() && !mHighestZOrder.shouldShowStatusBarInsets()) {
-            mWindowInsetsController.hide(statusBars());
+        OverlayViewController highestZOrder = mOverlayVisibilityMediator
+                .getHighestZOrderOverlayViewController();
+        boolean shouldShowInsets =
+                (insetType == navigationBars() && highestZOrder.shouldShowNavigationBarInsets())
+                || (insetType == statusBars() && highestZOrder.shouldShowStatusBarInsets());
+        if (highestZOrder.shouldFocusWindow() && !shouldShowInsets) {
+            mWindowInsetsController.hide(insetType);
         } else {
-            mWindowInsetsController.show(statusBars());
+            mWindowInsetsController.show(insetType);
         }
     }
 
     private void refreshWindowFocus() {
-        setWindowFocusable(mHighestZOrder == null ? false : mHighestZOrder.shouldFocusWindow());
+        OverlayViewController highestZOrder = mOverlayVisibilityMediator
+                .getHighestZOrderOverlayViewController();
+        setWindowFocusable(highestZOrder == null ? false : highestZOrder.shouldFocusWindow());
     }
 
     private void refreshWindowDefaultDimBehind() {
-        float dimAmount = mHighestZOrder == null ? 0f : mHighestZOrder.getDefaultDimAmount();
+        OverlayViewController highestZOrder = mOverlayVisibilityMediator
+                .getHighestZOrderOverlayViewController();
+        float dimAmount = highestZOrder == null ? 0f : highestZOrder.getDefaultDimAmount();
         mSystemUIOverlayWindowController.setDimBehind(dimAmount);
     }
 
     private void refreshUseStableInsets() {
+        OverlayViewController highestZOrder = mOverlayVisibilityMediator
+                .getHighestZOrderOverlayViewController();
         mSystemUIOverlayWindowController.setUsingStableInsets(
-                mHighestZOrder == null ? false : mHighestZOrder.shouldUseStableInsets());
+                highestZOrder == null ? false : highestZOrder.shouldUseStableInsets());
     }
 
     /**
@@ -294,28 +251,33 @@ public class OverlayViewGlobalStateController {
      * return an {@link InsetsSide}, then that takes precedence over {@link InsetsType}.
      */
     private void refreshInsetsToFit() {
-        if (mZOrderVisibleSortedMap.isEmpty()) {
+        if (!mOverlayVisibilityMediator.isAnyOverlayViewVisible()) {
             setFitInsetsTypes(statusBars());
         } else {
-            if (mHighestZOrder.getInsetSidesToFit() != OverlayViewController.INVALID_INSET_SIDE) {
+            OverlayViewController highestZOrder = mOverlayVisibilityMediator
+                    .getHighestZOrderOverlayViewController();
+            if (highestZOrder.getInsetSidesToFit() != OverlayViewController.INVALID_INSET_SIDE) {
                 // First fit all system bar insets as setFitInsetsSide defines which sides of system
                 // bar insets to actually honor.
                 setFitInsetsTypes(WindowInsets.Type.systemBars());
-                setFitInsetsSides(mHighestZOrder.getInsetSidesToFit());
+                setFitInsetsSides(highestZOrder.getInsetSidesToFit());
             } else {
-                setFitInsetsTypes(mHighestZOrder.getInsetTypesToFit());
+                setFitInsetsTypes(highestZOrder.getInsetTypesToFit());
             }
         }
     }
 
     private void refreshRotaryFocusIfNeeded() {
-        for (OverlayViewController controller : mZOrderVisibleSortedMap.values()) {
-            boolean isTop = Objects.equals(controller, mHighestZOrder);
+        OverlayViewController highestZOrder = mOverlayVisibilityMediator
+                .getHighestZOrderOverlayViewController();
+        for (OverlayViewController controller : mOverlayVisibilityMediator
+                .getVisibleOverlayViewsByZOrder()) {
+            boolean isTop = Objects.equals(controller, highestZOrder);
             controller.setAllowRotaryFocus(isTop);
         }
 
-        if (!mZOrderVisibleSortedMap.isEmpty()) {
-            mHighestZOrder.refreshRotaryFocusIfNeeded();
+        if (mOverlayVisibilityMediator.isAnyOverlayViewVisible()) {
+            highestZOrder.refreshRotaryFocusIfNeeded();
         }
     }
 
@@ -354,6 +316,10 @@ public class OverlayViewGlobalStateController {
     /** Sets the focusable flag of the sysui overlawy window. */
     public void setWindowFocusable(boolean focusable) {
         mSystemUIOverlayWindowController.setWindowFocusable(focusable);
+        if (mOverlayVisibilityMediator.getHighestZOrderOverlayViewController() != null) {
+            mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()
+                    .onWindowFocusableChanged(focusable);
+        }
     }
 
     /** Inflates the view controlled by the given view controller. */
@@ -367,7 +333,10 @@ public class OverlayViewGlobalStateController {
      * Return {@code true} if OverlayWindow is in a state where HUNs should be displayed above it.
      */
     public boolean shouldShowHUN() {
-        return mZOrderVisibleSortedMap.isEmpty() || mHighestZOrder.shouldShowHUN();
+        OverlayViewController highestZOrder = mOverlayVisibilityMediator
+                .getHighestZOrderOverlayViewController();
+        return !mOverlayVisibilityMediator.isAnyOverlayViewVisible()
+                || highestZOrder.shouldShowHUN();
     }
 
     /**
@@ -391,7 +360,7 @@ public class OverlayViewGlobalStateController {
 
     private void hideViewsForOcclusion() {
         HashSet<OverlayViewController> viewsCurrentlyShowing = new HashSet<>(
-                mZOrderVisibleSortedMap.values());
+                mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder());
         viewsCurrentlyShowing.forEach(overlayController -> {
             if (!overlayController.shouldShowWhenOccluded()) {
                 hideView(overlayController, overlayController::hideInternal);
@@ -412,11 +381,12 @@ public class OverlayViewGlobalStateController {
             return;
         }
 
-        Log.d(TAG, "mHighestZOrder: " + mHighestZOrder);
-        Log.d(TAG, "mZOrderVisibleSortedMap.size(): " + mZOrderVisibleSortedMap.size());
-        Log.d(TAG, "mZOrderVisibleSortedMap: " + mZOrderVisibleSortedMap);
-        Log.d(TAG, "mZOrderMap.size(): " + mZOrderMap.size());
-        Log.d(TAG, "mZOrderMap: " + mZOrderMap);
+        Log.d(TAG, "HighestZOrder: " + mOverlayVisibilityMediator
+                .getHighestZOrderOverlayViewController());
+        Log.d(TAG, "Number of visible overlays: " + mOverlayVisibilityMediator
+                .getVisibleOverlayViewsByZOrder().size());
+        Log.d(TAG, "Is any overlay visible: " + mOverlayVisibilityMediator
+                .isAnyOverlayViewVisible());
         Log.d(TAG, "mIsOccluded: " + mIsOccluded);
         Log.d(TAG, "mViewsHiddenForOcclusion: " + mViewsHiddenForOcclusion);
         Log.d(TAG, "mViewsHiddenForOcclusion.size(): " + mViewsHiddenForOcclusion.size());
diff --git a/src/com/android/systemui/car/window/OverlayVisibilityMediator.java b/src/com/android/systemui/car/window/OverlayVisibilityMediator.java
new file mode 100644
index 00000000..fdb62d8e
--- /dev/null
+++ b/src/com/android/systemui/car/window/OverlayVisibilityMediator.java
@@ -0,0 +1,62 @@
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
+package com.android.systemui.car.window;
+
+import androidx.annotation.Nullable;
+
+import java.util.Collection;
+
+/**
+ * Manages the visibility state of the {@link OverlayViewController} on the screen.
+ */
+public interface OverlayVisibilityMediator {
+
+    /**
+     * Called when a panel requests to become visible.
+     */
+    void showView(OverlayViewController controller);
+
+    /**
+     * Called when a panel requests to become hidden.
+     */
+    void hideView(OverlayViewController viewController);
+
+    /**
+     * Returns true if there is any visible overlays.
+     */
+    boolean isAnyOverlayViewVisible();
+
+    /**
+     * Returns true if the given ovelray has been shown before.
+     */
+    boolean hasOverlayViewBeenShown(OverlayViewController viewController);
+
+    /**
+     * Returns true if the given ovelray is currently visible.
+     */
+    boolean isOverlayViewVisible(OverlayViewController viewController);
+
+    /**
+     * Returns the overlay that has the highest Z order.
+     */
+    @Nullable
+    OverlayViewController getHighestZOrderOverlayViewController();
+
+    /**
+     * Returns the {@link Collection} of currently visible overlays sorted by Z order.
+     */
+    Collection<OverlayViewController> getVisibleOverlayViewsByZOrder();
+}
diff --git a/src/com/android/systemui/car/window/OverlayVisibilityMediatorImpl.java b/src/com/android/systemui/car/window/OverlayVisibilityMediatorImpl.java
new file mode 100644
index 00000000..e2fbd665
--- /dev/null
+++ b/src/com/android/systemui/car/window/OverlayVisibilityMediatorImpl.java
@@ -0,0 +1,131 @@
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
+package com.android.systemui.car.window;
+
+import java.util.Collection;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.SortedMap;
+import java.util.TreeMap;
+
+import javax.inject.Inject;
+
+/**
+ * Manages the visibility state of the {@link OverlayViewController} on the screen.
+ */
+public class OverlayVisibilityMediatorImpl implements OverlayVisibilityMediator {
+
+    private static final String TAG = OverlayVisibilityMediatorImpl.class.getSimpleName();
+    private static final int UNKNOWN_Z_ORDER = -1;
+
+    private final SystemUIOverlayWindowController mSystemUIOverlayWindowController;
+
+    private Map<OverlayViewController, Integer> mZOrderMap;
+    private SortedMap<Integer, OverlayViewController> mZOrderVisibleSortedMap;
+    private OverlayViewController mHighestZOrder;
+
+    @Inject
+    public OverlayVisibilityMediatorImpl(
+            SystemUIOverlayWindowController systemUIOverlayWindowController) {
+        mSystemUIOverlayWindowController = systemUIOverlayWindowController;
+        mZOrderMap = new HashMap<>();
+        mZOrderVisibleSortedMap = new TreeMap<>();
+    }
+
+    @Override
+    public void showView(OverlayViewController controller) {
+        /*
+         * Here we make sure that the other panels become hidden if the current panel expects to be
+         * exclusivly visible on the screen.
+         */
+        if (controller instanceof OverlayPanelViewController
+                && ((OverlayPanelViewController) controller).isExclusive()) {
+            for (OverlayViewController value : mZOrderVisibleSortedMap.values()) {
+                if (value instanceof OverlayPanelViewController && controller != value) {
+                    ((OverlayPanelViewController) value).toggle();
+                }
+            }
+        }
+
+        updateInternalsWhenShowingView(controller);
+    }
+
+    @Override
+    public void hideView(OverlayViewController viewController) {
+        mZOrderVisibleSortedMap.remove(mZOrderMap.get(viewController));
+        refreshHighestZOrderWhenHidingView(viewController);
+
+    }
+
+    @Override
+    public boolean isAnyOverlayViewVisible() {
+        return !mZOrderVisibleSortedMap.isEmpty();
+    }
+
+    @Override
+    public boolean hasOverlayViewBeenShown(OverlayViewController viewController) {
+        return mZOrderMap.containsKey(viewController);
+    }
+
+    @Override
+    public boolean isOverlayViewVisible(OverlayViewController viewController) {
+        return mZOrderVisibleSortedMap.containsKey(mZOrderMap.get(viewController));
+    }
+
+    @Override
+    public OverlayViewController getHighestZOrderOverlayViewController() {
+        return mHighestZOrder;
+    }
+
+    @Override
+    public Collection<OverlayViewController> getVisibleOverlayViewsByZOrder() {
+        return mZOrderVisibleSortedMap.values();
+    }
+
+    private void updateInternalsWhenShowingView(OverlayViewController viewController) {
+        int zOrder;
+        if (mZOrderMap.containsKey(viewController)) {
+            zOrder = mZOrderMap.get(viewController);
+        } else {
+            zOrder = mSystemUIOverlayWindowController.getBaseLayout().indexOfChild(
+                    viewController.getLayout());
+            mZOrderMap.put(viewController, zOrder);
+        }
+
+        mZOrderVisibleSortedMap.put(zOrder, viewController);
+
+        refreshHighestZOrderWhenShowingView(viewController);
+    }
+
+    private void refreshHighestZOrderWhenShowingView(OverlayViewController viewController) {
+        if (mZOrderMap.getOrDefault(mHighestZOrder, UNKNOWN_Z_ORDER) < mZOrderMap.get(
+                viewController)) {
+            mHighestZOrder = viewController;
+        }
+    }
+
+    private void refreshHighestZOrderWhenHidingView(OverlayViewController viewController) {
+        if (mZOrderVisibleSortedMap.isEmpty()) {
+            mHighestZOrder = null;
+            return;
+        }
+        if (!mHighestZOrder.equals(viewController)) {
+            return;
+        }
+
+        mHighestZOrder = mZOrderVisibleSortedMap.get(mZOrderVisibleSortedMap.lastKey());
+    }
+}
diff --git a/src/com/android/systemui/car/window/OverlayWindowModule.java b/src/com/android/systemui/car/window/OverlayWindowModule.java
index 756b39b8..824fb8d2 100644
--- a/src/com/android/systemui/car/window/OverlayWindowModule.java
+++ b/src/com/android/systemui/car/window/OverlayWindowModule.java
@@ -18,6 +18,7 @@ package com.android.systemui.car.window;
 
 import com.android.systemui.car.hvac.HvacPanelOverlayViewMediator;
 import com.android.systemui.car.keyguard.CarKeyguardOverlayViewMediator;
+import com.android.systemui.car.keyguard.passenger.PassengerKeyguardOverlayViewMediator;
 import com.android.systemui.car.notification.BottomNotificationPanelViewMediator;
 import com.android.systemui.car.notification.NotificationPanelViewMediator;
 import com.android.systemui.car.notification.TopNotificationPanelViewMediator;
@@ -66,6 +67,13 @@ public abstract class OverlayWindowModule {
     public abstract OverlayViewMediator bindCarKeyguardOverlayViewMediator(
             CarKeyguardOverlayViewMediator carKeyguardOverlayViewMediator);
 
+    /** Injects PassengerKeyguardOverlayViewMediator. */
+    @Binds
+    @IntoMap
+    @ClassKey(PassengerKeyguardOverlayViewMediator.class)
+    public abstract OverlayViewMediator bindPassengerKeyguardViewMediator(
+            PassengerKeyguardOverlayViewMediator overlayViewsMediator);
+
     /** Injects FullscreenUserSwitcherViewsMediator. */
     @Binds
     @IntoMap
@@ -99,4 +107,9 @@ public abstract class OverlayWindowModule {
     @IntoSet
     public abstract ConfigurationListener bindSystemUIOverlayWindowManagerConfigChanges(
             SystemUIOverlayWindowManager systemUIOverlayWindowManager);
+
+    /** Injects OverlayVisibilityMediator. */
+    @Binds
+    public abstract OverlayVisibilityMediator bindOverlayVisibilityMediator(
+            OverlayVisibilityMediatorImpl overlayVisibilityMediatorImpl);
 }
diff --git a/src/com/android/systemui/car/window/SystemUIOverlayWindowController.java b/src/com/android/systemui/car/window/SystemUIOverlayWindowController.java
index f1917cb3..1c953af3 100644
--- a/src/com/android/systemui/car/window/SystemUIOverlayWindowController.java
+++ b/src/com/android/systemui/car/window/SystemUIOverlayWindowController.java
@@ -72,13 +72,13 @@ public class SystemUIOverlayWindowController implements
     @Inject
     public SystemUIOverlayWindowController(
             Context context,
-            WindowManager windowManager,
             ConfigurationController configurationController) {
-        mContext = context;
-        mWindowManager = windowManager;
+        mContext = context.createWindowContext(WindowManager.LayoutParams.TYPE_NOTIFICATION_SHADE,
+                /* options= */ null);
+        mWindowManager = mContext.getSystemService(WindowManager.class);
 
         mLpChanged = new WindowManager.LayoutParams();
-        mBaseLayout = (ViewGroup) LayoutInflater.from(context)
+        mBaseLayout = (ViewGroup) LayoutInflater.from(mContext)
                 .inflate(R.layout.sysui_overlay_window, /* root= */ null, false);
         configurationController.addCallback(this);
     }
diff --git a/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java b/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
index 50b52f6e..5f330ae5 100644
--- a/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
+++ b/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
@@ -18,9 +18,13 @@ package com.android.systemui.car.wm;
 
 import android.app.ActivityManager;
 import android.content.Context;
+import android.util.ArraySet;
 import android.util.Log;
 import android.view.SurfaceControl;
 
+import androidx.annotation.GuardedBy;
+import androidx.annotation.NonNull;
+
 import com.android.systemui.car.CarServiceProvider;
 import com.android.wm.shell.ShellTaskOrganizer;
 import com.android.wm.shell.common.SyncTransactionQueue;
@@ -39,6 +43,8 @@ import java.util.Optional;
  * Please note that this reports FULLSCREEN + MULTI_WINDOW tasks to the CarActivityService but
  * excludes the tasks that are associated with a taskview.
  *
+ * Listeners can also be added to receive task changes for FULLSCREEN + MULTI_WINDOW tasks.
+ *
  * <p>When {@link CarSystemUIProxyImpl#shouldRegisterCarSystemUIProxy(Context)} returns true, the
  * task organizer is registered by the system ui alone and hence SystemUI is responsible to act as
  * a task monitor for the car service.
@@ -48,10 +54,13 @@ import java.util.Optional;
  * multiple task events to the car service.
  */
 public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
-    static final String TAG = "CarFullscrTaskMonitor";
+    static final String TAG = CarFullscreenTaskMonitorListener.class.getSimpleName();
     static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
     private final ShellTaskOrganizer mShellTaskOrganizer;
     private final CarServiceTaskReporter mCarServiceTaskReporter;
+    @GuardedBy("mLock")
+    private final ArraySet<OnTaskChangeListener> mTaskListeners = new ArraySet<>();
+    private final Object mLock = new Object();
 
     private final ShellTaskOrganizer.TaskListener mMultiWindowTaskListener =
             new ShellTaskOrganizer.TaskListener() {
@@ -59,16 +68,31 @@ public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
                 public void onTaskAppeared(ActivityManager.RunningTaskInfo taskInfo,
                         SurfaceControl leash) {
                     mCarServiceTaskReporter.reportTaskAppeared(taskInfo, leash);
+                    synchronized (mLock) {
+                        for (OnTaskChangeListener listener : mTaskListeners) {
+                            listener.onTaskAppeared(taskInfo);
+                        }
+                    }
                 }
 
                 @Override
                 public void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
                     mCarServiceTaskReporter.reportTaskInfoChanged(taskInfo);
+                    synchronized (mLock) {
+                        for (OnTaskChangeListener listener : mTaskListeners) {
+                            listener.onTaskInfoChanged(taskInfo);
+                        }
+                    }
                 }
 
                 @Override
                 public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
                     mCarServiceTaskReporter.reportTaskVanished(taskInfo);
+                    synchronized (mLock) {
+                        for (OnTaskChangeListener listener : mTaskListeners) {
+                            listener.onTaskVanished(taskInfo);
+                        }
+                    }
                 }
             };
 
@@ -99,17 +123,69 @@ public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
             SurfaceControl leash) {
         super.onTaskAppeared(taskInfo, leash);
         mCarServiceTaskReporter.reportTaskAppeared(taskInfo, leash);
+        synchronized (mLock) {
+            for (OnTaskChangeListener listener : mTaskListeners) {
+                listener.onTaskAppeared(taskInfo);
+            }
+        }
     }
 
     @Override
     public void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
         super.onTaskInfoChanged(taskInfo);
         mCarServiceTaskReporter.reportTaskInfoChanged(taskInfo);
+        synchronized (mLock) {
+            for (OnTaskChangeListener listener : mTaskListeners) {
+                listener.onTaskInfoChanged(taskInfo);
+            }
+        }
     }
 
     @Override
     public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
         super.onTaskVanished(taskInfo);
         mCarServiceTaskReporter.reportTaskVanished(taskInfo);
+        synchronized (mLock) {
+            for (OnTaskChangeListener listener : mTaskListeners) {
+                listener.onTaskVanished(taskInfo);
+            }
+        }
+    }
+
+    /**
+     * Adds a listener for tasks.
+     */
+    public void addTaskListener(@NonNull OnTaskChangeListener listener) {
+        synchronized (mLock) {
+            mTaskListeners.add(listener);
+        }
+    }
+
+    /**
+     * Remove a listener for tasks.
+     */
+    public boolean removeTaskListener(@NonNull OnTaskChangeListener listener) {
+        synchronized (mLock) {
+            return mTaskListeners.remove(listener);
+        }
+    }
+
+    /**
+     * Limited scope interface to give information about task changes.
+     */
+    public interface OnTaskChangeListener {
+        /**
+         * Gives the information of the task that just appeared
+         */
+        void onTaskAppeared(ActivityManager.RunningTaskInfo taskInfo);
+
+        /**
+         * Gives the information of the task that just changed
+         */
+        void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo);
+        /**
+         * Gives the information of the task that just vanished
+         */
+        void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo);
     }
 }
diff --git a/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java b/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
index 925995fc..efa5cd57 100644
--- a/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
+++ b/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
@@ -32,6 +32,7 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.graphics.Insets;
+import android.graphics.PixelFormat;
 import android.graphics.Rect;
 import android.hardware.display.DisplayManager;
 import android.opengl.GLSurfaceView;
@@ -258,13 +259,17 @@ public class ActivityBlockingActivity extends FragmentActivity {
         }
         display.getDisplayInfo(displayInfo);
 
-        Rect windowRect = getAppWindowRect();
+        Rect windowRectRelativeToTaskDisplayArea = getAppWindowRect();
+        Rect screenshotRectRelativeToDisplay = getScreenshotRect();
 
-        mSurfaceRenderer = new BlurredSurfaceRenderer(this, windowRect, getDisplayId());
+        mSurfaceRenderer = new BlurredSurfaceRenderer(this, windowRectRelativeToTaskDisplayArea,
+                getDisplayId(), screenshotRectRelativeToDisplay);
 
         mGLSurfaceView = findViewById(R.id.blurred_surface_view);
         mGLSurfaceView.setEGLContextClientVersion(EGL_CONTEXT_VERSION);
 
+        // Sets up the surface so that we can make it translucent if needed
+        mGLSurfaceView.getHolder().setFormat(PixelFormat.TRANSLUCENT);
         mGLSurfaceView.setEGLConfigChooser(EGL_CONFIG_SIZE, EGL_CONFIG_SIZE, EGL_CONFIG_SIZE,
                 EGL_CONFIG_SIZE, EGL_CONFIG_SIZE, EGL_CONFIG_SIZE);
 
@@ -273,27 +278,56 @@ public class ActivityBlockingActivity extends FragmentActivity {
         // We only want to render the screen once
         mGLSurfaceView.setRenderMode(GLSurfaceView.RENDERMODE_WHEN_DIRTY);
 
+        // Activity is set to translucent via its Theme. After taking a screenshot of the
+        // blocked app, disable translucency so the Activity lifecycle state is STOPPED
+        // instead of PAUSED
+        this.setTranslucent(false);
+
         mIsGLSurfaceSetup = true;
     }
 
+    private Insets getSystemBarInsets() {
+        return getWindowManager()
+                .getCurrentWindowMetrics()
+                .getWindowInsets()
+                .getInsets(WindowInsets.Type.systemBars());
+    }
+
     /**
      * Computes a Rect that represents the portion of the screen that contains the activity that is
-     * being blocked.
+     * being blocked and is relative to the default task display area.
      *
      * @return Rect that represents the application window
      */
     private Rect getAppWindowRect() {
-        Insets systemBarInsets = getWindowManager()
-                .getCurrentWindowMetrics()
-                .getWindowInsets()
-                .getInsets(WindowInsets.Type.systemBars());
+        Insets systemBarInsets = getSystemBarInsets();
 
-        Rect displayBounds = getWindowManager().getCurrentWindowMetrics().getBounds();
+        Rect windowBounds = getWindowManager().getCurrentWindowMetrics().getBounds();
 
         int leftX = systemBarInsets.left;
-        int rightX = displayBounds.width() - systemBarInsets.right;
+        int rightX = windowBounds.width() - systemBarInsets.right;
         int topY = systemBarInsets.top;
-        int bottomY = displayBounds.height() - systemBarInsets.bottom;
+        int bottomY = windowBounds.height() - systemBarInsets.bottom;
+
+        return new Rect(leftX, topY, rightX, bottomY);
+    }
+
+    /**
+     * Computes a Rect that represents the portion of the screen for which screenshot needs to be
+     * taken and is relative to the display.
+     *
+     * @return Rect that represents the application window for which the screenshot needs to be
+     * taken
+     */
+    private Rect getScreenshotRect() {
+        Insets systemBarInsets = getSystemBarInsets();
+
+        Rect windowBounds = getWindowManager().getCurrentWindowMetrics().getBounds();
+
+        int leftX = systemBarInsets.left + windowBounds.left;
+        int rightX = windowBounds.width() - systemBarInsets.right;
+        int topY = systemBarInsets.top + windowBounds.top;
+        int bottomY = windowBounds.height() - systemBarInsets.bottom;
 
         return new Rect(leftX, topY, rightX, bottomY);
     }
diff --git a/src/com/android/systemui/car/wm/activity/blurredbackground/BlurredSurfaceRenderer.java b/src/com/android/systemui/car/wm/activity/blurredbackground/BlurredSurfaceRenderer.java
index 98eddd92..3c5fbafe 100644
--- a/src/com/android/systemui/car/wm/activity/blurredbackground/BlurredSurfaceRenderer.java
+++ b/src/com/android/systemui/car/wm/activity/blurredbackground/BlurredSurfaceRenderer.java
@@ -51,7 +51,8 @@ public class BlurredSurfaceRenderer implements GLSurfaceView.Renderer {
     private final String mVertexShader;
     private final String mHorizontalBlurShader;
     private final String mVerticalBlurShader;
-    private final Rect mWindowRect;
+    private final Rect mWindowRectRelativeToTaskDisplayArea;
+    private final Rect mScreenshotRectRelativeToDisplay;
 
     private BlurTextureProgram mProgram;
     private SurfaceTexture mSurfaceTexture;
@@ -69,9 +70,12 @@ public class BlurredSurfaceRenderer implements GLSurfaceView.Renderer {
      * Constructs a new {@link BlurredSurfaceRenderer} and loads the shaders needed for rendering a
      * blurred texture
      *
-     * @param windowRect Rect that represents the application window
+     * @param windowRectRelativeToTaskDisplayArea Rect that represents the application window
+     * @param displayId Display id on which the blurred surface needs to be drawn
+     * @param screenshotRectRelativeToDisplay Rect that represents the screenshot window
      */
-    public BlurredSurfaceRenderer(Context context, Rect windowRect, int displayId) {
+    public BlurredSurfaceRenderer(Context context, Rect windowRectRelativeToTaskDisplayArea,
+            int displayId, Rect screenshotRectRelativeToDisplay) {
         mDisplayId = displayId;
 
         mVertexShader = GLHelper.getShaderFromRaw(context, R.raw.vertex_shader);
@@ -84,7 +88,12 @@ public class BlurredSurfaceRenderer implements GLSurfaceView.Renderer {
                 && mHorizontalBlurShader != null
                 && mVerticalBlurShader != null;
 
-        mWindowRect = windowRect;
+        // windowRectRelativeToTaskDisplayArea corresponds to the area on which the blurred
+        // surface will be drawn relative to the default task display area
+        mWindowRectRelativeToTaskDisplayArea = windowRectRelativeToTaskDisplayArea;
+        // screenshotRectRelativeToDisplay corresponds to the area of which the screenshot needs
+        // to be taken which is relative to the display
+        mScreenshotRectRelativeToDisplay = screenshotRectRelativeToDisplay;
     }
 
     @Override
@@ -110,7 +119,7 @@ public class BlurredSurfaceRenderer implements GLSurfaceView.Renderer {
                     mVertexShader,
                     mHorizontalBlurShader,
                     mVerticalBlurShader,
-                    mWindowRect
+                    mWindowRectRelativeToTaskDisplayArea
             );
             mProgram.render();
         } else {
@@ -144,7 +153,7 @@ public class BlurredSurfaceRenderer implements GLSurfaceView.Renderer {
 
         try {
             final CaptureArgs captureArgs = new CaptureArgs.Builder<>()
-                    .setSourceCrop(mWindowRect)
+                    .setSourceCrop(mScreenshotRectRelativeToDisplay)
                     .build();
             SynchronousScreenCaptureListener syncScreenCapture =
                     ScreenCapture.createSyncCaptureListener();
@@ -193,4 +202,3 @@ public class BlurredSurfaceRenderer implements GLSurfaceView.Renderer {
                 && mShadersLoadedSuccessfully;
     }
 }
-
diff --git a/src/com/android/systemui/car/wm/displayarea/DaHideActivity.kt b/src/com/android/systemui/car/wm/displayarea/DaHideActivity.kt
new file mode 100644
index 00000000..5c0cb5e3
--- /dev/null
+++ b/src/com/android/systemui/car/wm/displayarea/DaHideActivity.kt
@@ -0,0 +1,43 @@
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
+package com.android.systemui.car.wm.displayarea
+
+import android.app.Activity
+import android.os.Bundle
+import android.view.WindowManager
+import android.window.OnBackInvokedCallback
+
+/**
+ * This activity is meant to be used as a signal that a display area is hidden. Whenever this
+ * activity is at the top, the underlying display area should be considered hidden.
+ */
+class DaHideActivity : Activity() {
+
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+        val callbackPriority = 1000
+        window.addFlags(WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE)
+        // Avoid finishing the activity on back pressed to in-turn avoid unwanted transitions.
+        onBackInvokedDispatcher.registerOnBackInvokedCallback(
+            callbackPriority,
+            object : OnBackInvokedCallback {
+                override fun onBackInvoked() {
+                }
+            }
+        )
+    }
+}
diff --git a/src/com/android/systemui/car/wm/displayarea/DaView.kt b/src/com/android/systemui/car/wm/displayarea/DaView.kt
new file mode 100644
index 00000000..b1a8bb5c
--- /dev/null
+++ b/src/com/android/systemui/car/wm/displayarea/DaView.kt
@@ -0,0 +1,287 @@
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
+package com.android.systemui.car.wm.displayarea
+
+import android.content.Context
+import android.graphics.Rect
+import android.graphics.Region
+import android.gui.TrustedOverlay
+import android.os.Binder
+import android.util.AttributeSet
+import android.util.Slog
+import android.util.SparseArray
+import android.view.InsetsSource
+import android.view.SurfaceControl
+import android.view.SurfaceHolder
+import android.view.SurfaceView
+import android.window.DisplayAreaInfo
+import android.window.DisplayAreaOrganizer
+import android.window.WindowContainerTransaction
+import com.android.systemui.R
+import com.android.systemui.car.Flags.daviewBasedWindowing
+
+const val INVALID_DISPLAY_AREA_FEATURE_ID = -1
+const val INVALID_DAVIEW_ID = -1L
+
+/**
+ * A DaView is a SurfaceView which has surface of a display area as a child. It can either be used
+ * with a DAG (DisplayAreaGroup) or a TDA (TaskDisplayArea). When used with a DAG, the DAG must
+ * have only one TDA so that the atomic unit becomes (DAG -> TDA).
+ *
+ * <ul>
+ *     <li> When used for a DAG, the displayAreaFeatureId should be the DAG and launchTaskDisplayAreaFeatureId should be
+ *     the TDA inside the DAG</li>
+ *     <li> When used for a TDA directly, displayAreaFeatureId and launchTaskDisplayAreaFeatureId can both point to TDA
+ *     </li>
+ * </ul>
+ */
+class DaView : SurfaceView, SurfaceHolder.Callback {
+    companion object {
+        private val TAG = DaView::class.java.simpleName
+    }
+
+    /**
+     * A unique identifier composed of the [DaView.displayAreaFeatureId] and the display which
+     * this display area is in.
+     */
+    val id: Long
+    val cornerRadius: Int
+
+    /**
+     * Directly maps to the [com.android.server.wm.DisplayArea.mFeatureId]. This is not a unique
+     * identifier though. Two display areas on different displays can have the same featureId.
+     */
+    val displayAreaFeatureId: Int
+    val launchTaskDisplayAreaFeatureId: Int
+
+    internal lateinit var daInfo: DisplayAreaInfo
+    internal lateinit var daLeash: SurfaceControl
+
+    /**
+     * Governs if the surface change should instantly trigger a wm change without shell transitions
+     * for the corresponding DisplayAreaGroup.
+     * This can be helpful when using composable layouts for prototyping where the changes are need
+     * to take effect right away. But should ideally be disabled in the interest
+     * of using {@link DaViewTransitions} for all the WM updates.
+     * This doesn't apply to surfaceCreated callback. Surface creation leads to direct wm update
+     * as of today as a transition is usually not required when surface is created.
+     */
+    var surfaceToWmSyncEnabled = true
+
+    private val tmpTransaction: SurfaceControl.Transaction = SurfaceControl.Transaction()
+    private val insetsOwner = Binder()
+    private val insets = SparseArray<Rect>()
+    private val touchableInsetsProvider = TouchableInsetsProvider(this)
+    private var obscuredTouchRegion: Region? = null
+    private var surfaceCreated = false
+    private lateinit var organizer: DisplayAreaOrganizer
+
+    constructor(context: Context) : super(context) {
+        if (!daviewBasedWindowing()) {
+            throw IllegalAccessException("DaView feature not available")
+        }
+
+        cornerRadius = 0
+        displayAreaFeatureId = INVALID_DISPLAY_AREA_FEATURE_ID
+        launchTaskDisplayAreaFeatureId = INVALID_DISPLAY_AREA_FEATURE_ID
+        id = INVALID_DAVIEW_ID
+
+        init()
+    }
+
+    constructor(context: Context, attrs: AttributeSet?) : super(context, attrs) {
+        val typedArray = context.obtainStyledAttributes(attrs, R.styleable.DisplayAreaView)
+        cornerRadius = typedArray.getInteger(R.styleable.DisplayAreaView_cornerRadius, 0)
+        displayAreaFeatureId =
+            typedArray.getInteger(R.styleable.DisplayAreaView_displayAreaFeatureId, -1)
+        launchTaskDisplayAreaFeatureId =
+            typedArray.getInteger(R.styleable.DisplayAreaView_launchTaskDisplayAreaFeatureId, -1)
+        id = (context.displayId.toLong() shl 32) or (displayAreaFeatureId.toLong() and 0xffffffffL)
+
+        typedArray.recycle()
+
+        init()
+    }
+
+    private fun init() {
+        if (displayAreaFeatureId == INVALID_DISPLAY_AREA_FEATURE_ID) {
+            Slog.e(TAG, "Unknown feature ID for a DisplayAreaView")
+            return
+        }
+
+        organizer = object : DisplayAreaOrganizer(context.mainExecutor) {
+            override fun onDisplayAreaAppeared(
+                displayAreaInfo: DisplayAreaInfo,
+                leash: SurfaceControl
+            ) {
+                super.onDisplayAreaAppeared(displayAreaInfo, leash)
+                daInfo = displayAreaInfo
+                this@DaView.daLeash = leash
+
+                if (surfaceCreated) {
+                    tmpTransaction.reparent(leash, surfaceControl)
+                        // Sometimes when the systemui crashes and the leash is reattached to
+                        // the new surface control, it could already have some dirty position
+                        // set by WM or the container of DAView. So the child leash must be
+                        // repositioned to 0,0 here.
+                        .setPosition(leash, 0f, 0f)
+                        .show(leash)
+                        .apply()
+                }
+            }
+
+            override fun onDisplayAreaInfoChanged(displayAreaInfo: DisplayAreaInfo) {
+                super.onDisplayAreaInfoChanged(displayAreaInfo)
+                // This callback doesn't need to be handled as of now as the config changes will
+                // directly propagate to the children of DisplayArea. If in the future, the
+                // decors in the window owning the layout of screen are needed to be adjusted
+                // based on display area's config, DaView can expose APIs to listen to these
+                // changes.
+            }
+        }.apply {
+            val displayAreaInfos = registerOrganizer(displayAreaFeatureId)
+            displayAreaInfos.forEach {
+                if (it.displayAreaInfo.displayId == context.displayId) {
+                    // There would be just one DisplayArea with a unique (displayId,
+                    // displayAreaFeatureId)
+                    daInfo = it.displayAreaInfo
+                    daLeash = it.leash
+                }
+            }
+        }
+        holder.addCallback(this)
+    }
+
+    override fun surfaceCreated(holder: SurfaceHolder) {
+        surfaceCreated = true
+        tmpTransaction.reparent(daLeash, surfaceControl)
+            // DaView is meant to contain app activities which shouldn't have trusted overlays
+            // flag set even when itself reparented in a window which is trusted.
+            .setTrustedOverlay(surfaceControl, TrustedOverlay.DISABLED)
+            .setCornerRadius(surfaceControl, cornerRadius.toFloat())
+            .setPosition(daLeash, 0f, 0f)
+            .show(daLeash)
+            .apply()
+        syncBoundsToWm()
+    }
+
+    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
+        if (!surfaceToWmSyncEnabled) {
+            return
+        }
+        syncBoundsToWm()
+    }
+
+    fun syncBoundsToWm() {
+        val wct = WindowContainerTransaction()
+        var rect = Rect()
+        getBoundsOnScreen(rect)
+        wct.setBounds(daInfo.token, rect)
+        DaViewTransitions.sInstance?.instantApplyViaShellTransit(wct)
+    }
+
+    fun resyncLeashToView(tr: SurfaceControl.Transaction) {
+        if (!surfaceCreated) {
+            return
+        }
+        tr.reparent(daLeash, surfaceControl)
+            .setPosition(daLeash, 0f, 0f)
+            .show(daLeash)
+    }
+
+    override fun surfaceDestroyed(holder: SurfaceHolder) {
+        surfaceCreated = false
+        tmpTransaction.reparent(daLeash, null).apply()
+    }
+
+    public override fun onAttachedToWindow() {
+        super.onAttachedToWindow()
+        touchableInsetsProvider.addToViewTreeObserver()
+        DaViewTransitions.sInstance?.add(this) ?: run {
+            Slog.e(TAG, "Failed adding $this to DaViewTransitions")
+        }
+    }
+
+    public override fun onDetachedFromWindow() {
+        super.onDetachedFromWindow()
+        touchableInsetsProvider.removeFromViewTreeObserver()
+        DaViewTransitions.sInstance?.remove(this) ?: run {
+            Slog.e(TAG, "Failed to remove $this from DaViewTransitions")
+        }
+    }
+
+    /**
+     * Indicates a region of the view that is not touchable.
+     *
+     * @param obscuredRect the obscured region of the view.
+     */
+    fun setObscuredTouchRect(obscuredRect: Rect) {
+        obscuredTouchRegion = Region(obscuredRect)
+        touchableInsetsProvider.setObscuredTouchRegion(obscuredTouchRegion)
+    }
+
+    /**
+     * Indicates a region of the view that is not touchable.
+     *
+     * @param obscuredRegion the obscured region of the view.
+     */
+    fun setObscuredTouchRegion(obscuredRegion: Region) {
+        obscuredTouchRegion = obscuredRegion
+        touchableInsetsProvider.setObscuredTouchRegion(obscuredTouchRegion)
+    }
+
+    fun addInsets(index: Int, type: Int, frame: Rect) {
+        insets.append(InsetsSource.createId(insetsOwner, index, type), frame)
+        val wct = WindowContainerTransaction()
+        val insetsFlags = 0
+        wct.addInsetsSource(
+                daInfo.token,
+                insetsOwner,
+                index,
+                type,
+                frame,
+                emptyArray<Rect>(),
+                insetsFlags
+        )
+        DaViewTransitions.sInstance?.instantApplyViaTaskOrganizer(wct)
+    }
+
+    fun removeInsets(index: Int, type: Int) {
+        if (insets.size() == 0) {
+            Slog.w(TAG, "No insets set.")
+            return
+        }
+        val id = InsetsSource.createId(insetsOwner, index, type)
+        if (!insets.contains(id)) {
+            Slog.w(
+                TAG,
+                "Insets type: " + type + " can't be removed as it was not " +
+                        "applied as part of the last addInsets()"
+            )
+            return
+        }
+        insets.remove(id)
+        val wct = WindowContainerTransaction()
+        wct.removeInsetsSource(
+            daInfo.token,
+            insetsOwner,
+            index,
+            type
+        )
+        DaViewTransitions.sInstance?.instantApplyViaTaskOrganizer(wct)
+    }
+}
diff --git a/src/com/android/systemui/car/wm/displayarea/DaViewTransitions.kt b/src/com/android/systemui/car/wm/displayarea/DaViewTransitions.kt
new file mode 100644
index 00000000..24b23251
--- /dev/null
+++ b/src/com/android/systemui/car/wm/displayarea/DaViewTransitions.kt
@@ -0,0 +1,830 @@
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
+package com.android.systemui.car.wm.displayarea
+
+import android.annotation.AnyThread
+import android.app.ActivityManager.RunningTaskInfo
+import android.app.ActivityOptions
+import android.app.PendingIntent
+import android.content.ComponentName
+import android.content.Context
+import android.content.Intent
+import android.content.Intent.FLAG_ACTIVITY_NEW_TASK
+import android.graphics.Rect
+import android.os.IBinder
+import android.util.Slog
+import android.view.SurfaceControl
+import android.view.SurfaceControl.Transaction
+import android.view.WindowManager
+import android.view.WindowManager.TRANSIT_CHANGE
+import android.view.WindowManager.TRANSIT_OPEN
+import android.window.TransitionInfo
+import android.window.TransitionRequestInfo
+import android.window.WindowContainerToken
+import android.window.WindowContainerTransaction
+import com.android.systemui.car.Flags.daviewBasedWindowing
+import com.android.wm.shell.ShellTaskOrganizer
+import com.android.wm.shell.common.ShellExecutor
+import com.android.wm.shell.dagger.WMSingleton
+import com.android.wm.shell.shared.TransitionUtil
+import com.android.wm.shell.shared.annotations.ShellMainThread
+import com.android.wm.shell.taskview.TaskViewTransitions
+import com.android.wm.shell.transition.Transitions
+import com.android.wm.shell.transition.Transitions.TransitionFinishCallback
+import com.google.common.annotations.VisibleForTesting
+import javax.inject.Inject
+
+/**
+ * This class handles the extra transitions work pertaining to shell transitions when using
+ * [DaView]. This class only works when shell transitions are enabled.
+ */
+@WMSingleton
+class DaViewTransitions @Inject constructor(
+    private val shellTaskOrganizer: ShellTaskOrganizer,
+    private val transitions: Transitions,
+    @ShellMainThread private val shellMainThread: ShellExecutor,
+    private val taskViewTransitions: TaskViewTransitions,
+    private val context: Context,
+) : Transitions.TransitionHandler {
+
+    // TODO(b/370075926): think about synchronization here as this state might be getting changed
+    //  in the shell main thread
+    val daCurrState = mutableMapOf<DaView, DaState>()
+
+    private val pendingTransitions = ArrayList<PendingTransition>()
+    private var animationHandler: AnimationHandler? = null
+
+    data class DaState(
+        /**
+         * Signifies if the tasks in the Da should be invisible. Please note that hiding/showing
+         * the surface of corresponding [DaView] is still taken care by the animation handler.
+         */
+        var visible: Boolean = false,
+        var bounds: Rect = Rect(),
+    )
+
+    // Represents a DaView related operation
+    data class DaTransaction(
+        /**
+         * Represents the state of the [DaView]s that are part of this transaction. It maps the
+         * [DaView.id] to its state.
+         */
+        var daStates: Map<Long, DaState> = mutableMapOf(),
+
+        /**
+         * The [DaView.id] of the daview that needs to be focused as part of this transaction. This
+         * is useful to ensure that focus ends up at a reasonable place after a transition
+         * involving multiple DaViews is completed.
+         */
+        var focusedDaId: Long? = null,
+    )
+
+    /**
+     * This interface should be used by the window which hosts the DaViews to hook into transitions
+     * happening on the core side.
+     * It can be used to animate multiple DaViews when an activity is coming up inside a
+     * {@link DaView}
+     */
+    interface AnimationHandler {
+        /**
+         * This method is called whenever a task gets started (adb shell, user, an app launch etc)
+         * on a DA. This is an opportunity to add more work to this transition and then animate
+         * later as part of playAnimation().
+         *
+         * The returned [DaTransaction] is merged with the change happening in WM.
+         * If the  [DaTransaction] doesn't have any participant, this transition will be handled by
+         * the default handler and [AnimationHandler.playAnimation] won't be called for that.
+         *
+         * Note: The returned participants must contain the passed DaView with visibility:true,
+         * otherwise it can lead to unexpected state and compliance issues.
+         */
+        @ShellMainThread
+        fun handleOpenTransitionOnDa(
+            daView: DaView,
+            triggerTaskInfo: RunningTaskInfo,
+            wct: WindowContainerTransaction
+        ): DaTransaction
+
+        /**
+         * Similar to [AnimationHandler.handleOpenTransitionOnDa] but gets called when a
+         * display changes its dimensions.
+         */
+        @ShellMainThread
+        fun handleDisplayChangeTransition(
+            displayId: Int,
+            newSize: Rect
+        ): DaTransaction
+
+        /**
+         * The penultimate method to play the animation. By this time, the required visibility and
+         * bounds change has already been applied to WM. Before this method is called,
+         * DaViewTransitions will ensure that the transition surfaces are reparented correctly to
+         * the participating DAViews.
+         * The handler can animate the DAView participants (using view animations) as per the state
+         * passed and trigger the finish callback which notifies the WM that the transition is
+         * done.
+         */
+        @ShellMainThread
+        fun playAnimation(
+            resolvedDaTransaction: DaTransaction,
+            finishCallback: TransitionFinishCallback
+        )
+    }
+
+    sealed class ChangeType {
+        data object None : ChangeType()
+        data object Hide : ChangeType()
+        data object Show : ChangeType()
+        data object Bounds : ChangeType()
+
+        fun logChange(daView: DaView) {
+            when (this) {
+                Hide -> Slog.d(TAG, "Hiding DA: $daView")
+                Show -> Slog.d(TAG, "Showing DA: $daView")
+                Bounds -> Slog.d(TAG, "Changing DA: $daView")
+                None -> {} // No logging for NONE
+            }
+        }
+    }
+
+    private class DaViewChange(
+        var type: ChangeType = ChangeType.None,
+        var snapshot: SurfaceControl? = null
+    )
+
+    init {
+        if (!daviewBasedWindowing()) {
+            throw IllegalAccessException("DaView feature not available")
+        }
+        transitions.addHandler(this)
+        sInstance = this
+    }
+
+    /**
+     * Instantly apply this transaction using the {@link ShellTaskOrganizer}. Should only be
+     * used for updating insets.
+     */
+    fun instantApplyViaTaskOrganizer(wct: WindowContainerTransaction) {
+        shellTaskOrganizer.applyTransaction(wct)
+    }
+
+    /**
+     * Instantly apply this transaction without any custom animation.
+     */
+    fun instantApplyViaShellTransit(wct: WindowContainerTransaction) {
+        transitions.startTransition(TRANSIT_CHANGE, wct, null)
+    }
+
+    private fun findPending(claimed: IBinder): PendingTransition? {
+        for (pending in pendingTransitions) {
+            if (pending.isClaimed !== claimed) continue
+            return pending
+        }
+        return null
+    }
+
+    fun setAnimationHandler(handler: AnimationHandler?) {
+        animationHandler = handler
+    }
+
+    @AnyThread
+    fun add(daView: DaView) {
+        shellMainThread.execute {
+            daViews[daView.id] = daView
+            daCurrState[daView] = DaState()
+        }
+    }
+
+    @AnyThread
+    fun remove(daView: DaView) {
+        shellMainThread.execute {
+            daViews.remove(daView.id)
+            daCurrState.remove(daView)
+        }
+    }
+
+    /**
+     * Requests to animate the given DaViews to the specified visibility and bounds. It should be
+     * noted that this will send the request to WM but the real playing of the animation should
+     * be done as part of {@link AnimationHandler#playAnimation()}.
+     *
+     * Clients can also set the focus to the desired DaView as part of this transition.
+     */
+    @AnyThread
+    fun startTransaction(daTransaction: DaTransaction) {
+        shellMainThread.execute {
+            val requestedDaStates = daTransaction.daStates
+                    .filter { (key, _) ->
+                        when {
+                            daViews[key] != null -> true
+                            else -> {
+                                Slog.w(TAG, "$key is not known to DaViewTransitions")
+                                false
+                            }
+                        }
+                    }
+                    .mapKeys { (key, _) -> daViews[key]!! }
+
+            val wct = WindowContainerTransaction()
+            val diffedRequestedDaViewStates = calculateWctForAnimationDiff(
+                requestedDaStates,
+                wct
+            )
+            if (DBG) {
+                Slog.d(TAG, "requested da view states = $diffedRequestedDaViewStates")
+            }
+            if (daTransaction.focusedDaId != null) {
+                if (daViews[daTransaction.focusedDaId] != null) {
+                    val toBeFocusedDa = daViews[daTransaction.focusedDaId]!!
+                    wct.reorder(toBeFocusedDa.daInfo.token, true, true)
+                } else {
+                    Slog.w(TAG, "DaView not found for ${daTransaction.focusedDaId}")
+                }
+            }
+
+            pendingTransitions.add(
+                PendingTransition(
+                    TRANSIT_OPEN, // to signify opening of the DaHideActivity
+                    wct,
+                    diffedRequestedDaViewStates,
+                )
+            )
+            startNextTransition()
+        }
+    }
+
+    // The visibility and all will be calculated as part of this
+    // Use the same for hide/show/change bounds
+    fun calculateWctForAnimationDiff(
+        requestedDaStates: Map<DaView, DaState>,
+        wct: WindowContainerTransaction
+    ): Map<DaView, DaState> {
+        val newStates = mutableMapOf<DaView, DaState>()
+        requestedDaStates
+            .filter { (daView, newReqState) ->
+                when {
+                    daCurrState[daView] != null -> true
+                    else -> {
+                        Slog.w(TAG, "$daView is not known to DaViewTransitions")
+                        false
+                    }
+                }
+            }
+            .forEach { (daView, newReqState) ->
+                when {
+                    daCurrState[daView]!!.visible && !newReqState.visible -> {
+                        // Being hidden
+                        prepareHideDaWct(wct, daView, newReqState)
+                        newStates[daView] = newReqState
+                    }
+
+                    !daCurrState[daView]!!.visible && newReqState.visible -> {
+                        // Being shown
+                    wct.setBounds(daView.daInfo.token, newReqState.bounds)
+                    findAndRemoveDaHideActivity(daView, wct)
+                    newStates[daView] = newReqState
+                }
+
+                daCurrState[daView]!!.bounds != newReqState.bounds -> {
+                    // Changing bounds
+                    prepareChangeBoundsWct(wct, daView, daCurrState[daView]!!, newReqState)
+                    newStates[daView] = newReqState
+                }
+                // no changes; doesn't need to be animated
+            }
+        }
+        return newStates
+    }
+
+    private fun prepareHideDaWct(
+        wct: WindowContainerTransaction,
+        daView: DaView,
+        newState: DaState
+    ) {
+        var options = ActivityOptions.makeBasic()
+            .setPendingIntentBackgroundActivityStartMode(
+                ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOW_ALWAYS
+            )
+            .apply {
+                this.launchTaskDisplayAreaFeatureId = daView.launchTaskDisplayAreaFeatureId
+            }
+
+        var intent = Intent(context, DaHideActivity::class.java)
+        intent.setFlags(FLAG_ACTIVITY_NEW_TASK)
+        var pendingIntent = PendingIntent.getActivity(
+            context,
+            /* requestCode= */
+            0,
+            intent,
+            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
+        )
+        wct.setBounds(daView.daInfo.token, newState.bounds)
+        wct.sendPendingIntent(pendingIntent, intent, options.toBundle())
+    }
+
+    private fun prepareChangeBoundsWct(
+        wct: WindowContainerTransaction,
+        daView: DaView,
+        prevState: DaState,
+        newReqState: DaState
+    ) {
+        wct.setBounds(daView.daInfo.token, newReqState.bounds)
+
+        if (DBG) {
+            val sizingUp =
+                (prevState.bounds.width() == newReqState.bounds.width() &&
+                        prevState.bounds.height() < newReqState.bounds.height()) ||
+                        (
+                                prevState.bounds.width() < newReqState.bounds.width() &&
+                                        prevState.bounds.height() == newReqState.bounds.height()
+                                ) ||
+                        (
+                                prevState.bounds.width() < newReqState.bounds.width() &&
+                                        prevState.bounds.height() < newReqState.bounds.height()
+                                )
+            Slog.d(TAG, if (sizingUp) "Sizing up $daView" else "Sizing down $daView")
+        }
+    }
+
+    fun startNextTransition() {
+        if (pendingTransitions.isEmpty()) return
+        val pending: PendingTransition = pendingTransitions[0]
+        if (pending.isClaimed != null) {
+            // Wait for this to start animating.
+            return
+        }
+        pending.isClaimed = transitions.startTransition(pending.mType, pending.wct, this)
+    }
+
+    private fun getDaViewFromDisplayAreaToken(token: WindowContainerToken?): DaView? {
+        val displayArea = daViews.values.stream().filter {
+            it.daInfo.token == token
+        }.findAny()
+        if (displayArea.isEmpty) {
+            return null
+        }
+        return displayArea.get()
+    }
+
+    private fun getDaView(taskInfo: RunningTaskInfo): DaView? = daViews.values.find {
+        it.launchTaskDisplayAreaFeatureId == taskInfo.displayAreaFeatureId &&
+                it.display.displayId == taskInfo.displayId
+    }
+
+    private fun isHideActivity(taskInfo: RunningTaskInfo): Boolean {
+        return taskInfo.topActivity == HIDE_ACTIVITY_NAME
+    }
+
+    override fun handleRequest(
+        transition: IBinder,
+        request: TransitionRequestInfo
+    ): WindowContainerTransaction? {
+        if (DBG) {
+            Slog.d(TAG, "handle request, type=${request.type}")
+        }
+        if (request.displayChange != null && request.displayChange!!.endAbsBounds != null) {
+            return handleRequestForDisplayChange(transition, request)
+        }
+
+        var triggerTask = request.triggerTask ?: run { return@handleRequest null }
+
+        if (DBG) {
+            Slog.d(
+                TAG,
+                "trigger task feature id = ${triggerTask.displayAreaFeatureId}, " +
+                        "type=${request.type}"
+            )
+        }
+
+        // Note: A DaHideActivity is always started as part of a transition from the handler,
+        // so it will never be caught here
+        if (TransitionUtil.isOpeningType(request.type)) {
+            val daView = getDaView(triggerTask)
+            if (daView == null) {
+                if (DBG) {
+                    Slog.d(TAG, "DA not found")
+                }
+                return null
+            }
+            if (!daCurrState.containsKey(daView)) {
+                if (DBG) {
+                    Slog.d(TAG, "DA state not found")
+                }
+                return null
+            }
+            return handleRequestForOpenTransitionOnDa(daView, transition, request)
+        } else {
+            if (DBG) {
+                Slog.d(
+                    TAG,
+                    "current event either not opening event or an event from blank activity"
+                )
+            }
+        }
+        return null
+    }
+
+    private fun handleRequestForDisplayChange(
+        transition: IBinder,
+        request: TransitionRequestInfo
+    ): WindowContainerTransaction? {
+        var wct: WindowContainerTransaction? = null
+        val participants =
+                animationHandler?.handleDisplayChangeTransition(
+                        request.displayChange!!.displayId,
+                        request.displayChange!!.endAbsBounds!!
+                )?.daStates?.mapKeys { (key, _) -> daViews[key]!! } ?: mapOf()
+
+        if (participants.isEmpty()) {
+            Slog.e(
+                    TAG,
+                    "No participants in the DA transition, can lead to " +
+                            "inconsistent state"
+            )
+            return null
+        }
+
+        wct = wct ?: WindowContainerTransaction()
+        var participantsAsPerStateDiff = calculateWctForAnimationDiff(participants, wct)
+        val pending = PendingTransition(
+            request.type,
+            wct,
+            participantsAsPerStateDiff,
+        )
+        pending.isClaimed = transition
+        pendingTransitions.add(pending)
+        return wct
+    }
+
+    private fun handleRequestForOpenTransitionOnDa(
+        daView: DaView,
+        transition: IBinder,
+        request: TransitionRequestInfo
+    ): WindowContainerTransaction? {
+        var wct: WindowContainerTransaction? = null
+        var participantsAsPerStateDiff = mapOf<DaView, DaState>()
+
+        // Even though daHideActivity is nohistory, it still needs to be manually removed here
+        // because the newly opened activity might be translucent which would make the
+        // DaHideActivity be visible in paused state otherwise; which is not desired.
+        wct = findAndRemoveDaHideActivity(daView, wct)
+        if (!pendingTransitions.isEmpty() &&
+            pendingTransitions.get(0).requestedStates.containsKey(daView) &&
+            pendingTransitions.get(0).requestedStates.get(daView)!!.visible == true
+        ) {
+            // This means it will become visible eventually and hence skip visibility
+            if (DBG) {
+                Slog.d(TAG, "DA is already requested to be visible and pending animation")
+            }
+        } else {
+            if (DBG) Slog.d(TAG, "try to show the da ${daView.id}")
+            wct = wct ?: WindowContainerTransaction()
+            val participants =
+                animationHandler!!.handleOpenTransitionOnDa(
+                    daView,
+                    request.triggerTask!!,
+                    wct
+                ).daStates.mapKeys { (key, _) -> daViews[key]!! }
+            if (participants.isEmpty()) {
+                Slog.e(
+                    TAG,
+                    "No participants in the DA transition, can lead to " +
+                            "inconsistent state"
+                )
+                // set wct back to null as this should be handled by the default handler in
+                // shell
+                wct = null
+            } else {
+                participantsAsPerStateDiff = calculateWctForAnimationDiff(participants, wct)
+                if (participantsAsPerStateDiff.isEmpty()) {
+                    wct = null
+                }
+            }
+        }
+        if (wct == null) {
+            // Should be handled by default handler in shell
+            return null
+        }
+        val pending = PendingTransition(
+            request.type,
+            wct
+                .reorder(request.triggerTask!!.token, true, true),
+            participantsAsPerStateDiff,
+        )
+        pending.isClaimed = transition
+        pendingTransitions.add(pending)
+        return wct
+    }
+
+    private fun findAndRemoveDaHideActivity(
+        daView: DaView,
+        inputWct: WindowContainerTransaction?
+    ): WindowContainerTransaction? {
+        var tasks = shellTaskOrganizer.getRunningTasks()
+        if (daView.display == null) {
+            if (DBG) {
+                Slog.d(
+                    TAG,
+                    "daView.display is null, cannot find and remove the hide " +
+                            "activity"
+                )
+            }
+        }
+        val daHideTasks =
+            tasks.filter {
+                it.displayAreaFeatureId == daView.launchTaskDisplayAreaFeatureId &&
+                        it.displayId == daView.display.displayId &&
+                        it.topActivity == HIDE_ACTIVITY_NAME
+                // TODO: Think about handling the home task
+            }
+        if (daHideTasks.isEmpty()) {
+            return inputWct
+        }
+        val wct = inputWct ?: WindowContainerTransaction()
+        for (daHideTask in daHideTasks) {
+            wct.removeTask(daHideTask.token)
+        }
+        return wct
+    }
+
+    private fun reSyncDaLeashesToView() {
+        // consider this an opportunity to restore the DA surfaces because even if this is a
+        // not known transition, it could still involve known DAs which reparent their surfaces.
+        val tr = Transaction()
+        for (daView in daViews.values) {
+            if (daView.surfaceControl == null) {
+                continue
+            }
+            daView.resyncLeashToView(tr)
+        }
+        tr.apply()
+    }
+
+    private fun logChanges(daViewChanges: Map<DaView, DaViewChange>) {
+        for ((daView, daViewChange) in daViewChanges) {
+            daViewChange.type.logChange(daView)
+        }
+    }
+
+    override fun startAnimation(
+        transition: IBinder,
+        info: TransitionInfo,
+        startTransaction: Transaction,
+        finishTransaction: Transaction,
+        finishCallback: TransitionFinishCallback
+    ): Boolean {
+        if (DBG) Slog.d(TAG, "  changes = " + info.changes)
+        val pending: PendingTransition? = findPending(transition)
+        if (pending != null) {
+            pendingTransitions.remove(pending)
+        }
+        if (pending == null) {
+            // TODO: ideally, based on the info.changes, a new transaction should be created and also
+            // routed via client which should eventually result into a new transition.
+            // This should be done so that client gets a chance to act on these missed changes.
+            Slog.e(TAG, "Found a non-DA related transition")
+            reSyncDaLeashesToView()
+            return false
+        }
+
+        if (pending.isInstant) {
+            if (DBG) Slog.d(TAG, "Playing a special instant transition")
+            startTransaction.apply()
+            finishCallback.onTransitionFinished(null)
+            startNextTransition()
+            return true
+        }
+
+        val daViewChanges = calculateDaViewChangesFromTransition(
+            info,
+            pending,
+            startTransaction,
+            finishTransaction
+        )
+        if (DBG) logChanges(daViewChanges)
+
+        configureTaskLeashesAsPerDaChange(
+            info,
+            pending,
+            startTransaction,
+            daViewChanges
+        )
+        if (pending.requestedStates.isEmpty() || animationHandler == null) {
+            startNextTransition()
+            return false
+        }
+        startTransaction.apply()
+        animationHandler?.playAnimation(
+            DaTransaction(daStates = pending.requestedStates.mapKeys { (key, _) -> key.id }),
+            {
+                shellMainThread.execute {
+                    daCurrState.putAll(pending.requestedStates)
+                    finishCallback.onTransitionFinished(null)
+                    startNextTransition()
+                }
+            }
+        )
+        return true
+    }
+
+    private fun calculateDaViewChangesFromTransition(
+        info: TransitionInfo,
+        pending: PendingTransition,
+        startTransaction: Transaction,
+        finishTransaction: Transaction
+    ): Map<DaView, DaViewChange> {
+        val viewChanges = mutableMapOf<DaView, DaViewChange>()
+        for (chg in info.changes) {
+            var daView = getDaViewFromDisplayAreaToken(chg.container)
+            if (daView != null) {
+                // It means that the change being processed is a display area level change
+                // which will have the snapshot.
+                if (chg.snapshot != null) {
+                    viewChanges.getOrPut(daView) { DaViewChange() }.snapshot = chg.snapshot!!
+                }
+                continue
+            }
+
+            if (chg.taskInfo == null) {
+                continue
+            }
+            Slog.d(TAG, "------- ${chg.mode} change ${chg.taskInfo!!.topActivity} ")
+            // The change being processed is a task level change
+
+            daView = getDaView(chg.taskInfo!!)
+            if (daView == null) {
+                Slog.e(TAG, "The da being changed isn't known to DaViewTransitions")
+                continue
+            }
+
+            // Regardless of being in the requested state or not, resync the leashes to view to be
+            // on the safe side
+            daView.resyncLeashToView(startTransaction)
+            daView.resyncLeashToView(finishTransaction)
+
+            if (!pending.requestedStates.contains(daView)) {
+                Slog.e(TAG, "The da being changed isn't part of pending.mDas")
+                startTransaction.reparent(chg.leash, daView.surfaceControl)
+                    .setPosition(chg.leash, 0f, 0f)
+                    .setAlpha(chg.leash, 1f)
+                continue
+            }
+
+            var changeType = viewChanges.getOrDefault(daView, DaViewChange()).type
+            if (TransitionUtil.isOpeningType(chg.mode) &&
+                HIDE_ACTIVITY_NAME == chg.taskInfo?.topActivity) {
+                if (daCurrState.containsKey(daView) && daCurrState[daView]!!.visible == false) {
+                    Slog.e(TAG, "The da being hidden, is already hidden")
+                    continue
+                }
+                changeType = ChangeType.Hide
+            } else if (
+                (TransitionUtil.isClosingType(chg.mode) &&
+                        HIDE_ACTIVITY_NAME == chg.taskInfo?.topActivity) ||
+                (TransitionUtil.isOpeningType(chg.mode) &&
+                        HIDE_ACTIVITY_NAME != chg.taskInfo?.topActivity)
+            ) {
+                if (daCurrState.containsKey(daView) && daCurrState[daView]!!.visible == true) {
+                    Slog.e(TAG, "The da being shown, is already shown")
+                    continue
+                }
+                changeType = ChangeType.Show
+            } else {
+                if (daCurrState.containsKey(daView) &&
+                    daCurrState[daView]!!.bounds == pending.requestedStates[daView]!!.bounds) {
+                    Slog.e(TAG, "The da being changed, already has the same bounds")
+                    continue
+                }
+                if (changeType != ChangeType.Show && changeType != ChangeType.Hide) {
+                    // A task inside a display area which is being shown or hidden can have a bounds
+                    // change as well. Prefer treating the DisplayArea change as SHOW or HIDE
+                    // respectively instead of a more generic CHANGE.
+                    changeType = ChangeType.Bounds
+                }
+            }
+
+            viewChanges.getOrPut(daView) { DaViewChange() }.type = changeType
+        }
+
+        return viewChanges
+    }
+
+    private fun configureTaskLeashesAsPerDaChange(
+        info: TransitionInfo,
+        pending: PendingTransition,
+        startTransaction: Transaction,
+        viewChanges: Map<DaView, DaViewChange>
+    ) {
+        // Attach the snapshots for hiding or changing DaViews
+        for ((daView, chg) in viewChanges) {
+            if (chg.type == ChangeType.Hide || chg.type == ChangeType.Bounds) {
+                if (chg.snapshot != null) {
+                    startTransaction.reparent(chg.snapshot!!, daView.surfaceControl)
+                }
+            }
+        }
+
+        // Determine leash visibility and placement for each task level change
+        for (chg in info.changes) {
+            if (chg.taskInfo == null) continue
+
+            val daView = getDaView(chg.taskInfo!!)
+            if (daView == null) {
+                Slog.e(TAG, "The da being changed isn't known to DaViewTransitions")
+                continue
+            }
+            val daViewChg = viewChanges[daView]
+            if (daViewChg == null) {
+                Slog.e(TAG, "The da being change isn't known. $daView")
+                continue
+            }
+
+            if (!pending.requestedStates.containsKey(daView)) {
+                Slog.e(TAG, "The da being changed isn't part of pending.mDas")
+                continue
+            }
+
+            if (isHideActivity(chg.taskInfo!!)) {
+                Slog.e(TAG, "Disregard the change from blank activity as its leash not needed")
+                continue
+            }
+
+            // TODO(b/357635714), revisit this once the window's surface is stable during da
+            //  transition.
+            val shouldTaskLeashBeVisible = when (daViewChg.type) {
+                ChangeType.Show -> TransitionUtil.isOpeningType(chg.mode)
+                ChangeType.Hide -> TransitionUtil.isClosingType(chg.mode) &&
+                        daViewChg.snapshot == null
+                ChangeType.Bounds -> daViewChg.snapshot == null
+                else -> false
+            }
+
+            startTransaction.reparent(chg.leash, daView.surfaceControl)
+                .apply {
+                    if (taskViewTransitions.isTaskViewTask(chg.taskInfo) &&
+                        shouldTaskLeashBeVisible) {
+                        val daBounds = daCurrState[daView]!!.bounds
+                        val taskBounds = chg.taskInfo!!.configuration.windowConfiguration!!.bounds
+                        taskBounds.offset(daBounds.left, daBounds.right)
+                        setPosition(
+                            chg.leash,
+                            taskBounds.left.toFloat(),
+                            taskBounds.bottom.toFloat()
+                        )
+                    } else {
+                        setPosition(chg.leash, 0f, 0f)
+                    }
+                }
+                .setAlpha(chg.leash, if (shouldTaskLeashBeVisible) 1f else 0f)
+        }
+    }
+
+    override fun onTransitionConsumed(
+        transition: IBinder,
+        aborted: Boolean,
+        finishTransaction: Transaction?
+    ) {
+        Slog.d(TAG, "onTransitionConsumed, aborted=$aborted")
+        if (!aborted) return
+        val pending = findPending(transition) ?: return
+        pendingTransitions.remove(pending)
+        // Probably means that the UI should adjust as per the last (daCurrState) state.
+        // Something should be done but needs more thought.
+        // For now just update the local state with what was requested.
+        daCurrState.putAll(pending.requestedStates)
+        startNextTransition()
+    }
+
+    companion object {
+        private val TAG: String = DaViewTransitions::class.java.simpleName
+        private val DBG = true
+        private val HIDE_ACTIVITY_NAME =
+            ComponentName("com.android.systemui", DaHideActivity::class.java.name)
+        private val daViews = mutableMapOf<Long, DaView>()
+
+        var sInstance: DaViewTransitions? = null
+    }
+
+    @VisibleForTesting
+    internal class PendingTransition(
+        @field:WindowManager.TransitionType @param:WindowManager.TransitionType val mType: Int,
+        val wct: WindowContainerTransaction,
+        val requestedStates: Map<DaView, DaState> = mutableMapOf<DaView, DaState>(),
+        val isInstant: Boolean = false,
+    ) {
+        var isClaimed: IBinder? = null
+    }
+}
diff --git a/src/com/android/systemui/car/wm/displayarea/TouchableInsetsProvider.java b/src/com/android/systemui/car/wm/displayarea/TouchableInsetsProvider.java
new file mode 100644
index 00000000..b708d69a
--- /dev/null
+++ b/src/com/android/systemui/car/wm/displayarea/TouchableInsetsProvider.java
@@ -0,0 +1,98 @@
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
+package com.android.systemui.car.wm.displayarea;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.UiThread;
+import android.graphics.Rect;
+import android.graphics.Region;
+import android.view.View;
+import android.view.ViewTreeObserver.InternalInsetsInfo;
+import android.view.ViewTreeObserver.OnComputeInternalInsetsListener;
+
+/**
+ * Calculates {@link InternalInsetsInfo#TOUCHABLE_INSETS_REGION} for the given {@link View}.
+ * <p>The touch events on the View will pass through the host and be delivered to the window
+ * below it.
+ *
+ * <p>It also provides the api {@link #setObscuredTouchRegion(Region)} to specify the region which
+ * the view host can accept the touch events on it.
+ */
+@UiThread
+public final class TouchableInsetsProvider {
+    private static final String TAG = TouchableInsetsProvider.class.getSimpleName();
+    private final View mView;
+    private final OnComputeInternalInsetsListener mListener = this::onComputeInternalInsets;
+    private final int[] mLocation = new int[2];
+    private final Rect mRect = new Rect();
+
+    @Nullable private Region mObscuredTouchRegion;
+
+    public TouchableInsetsProvider(@NonNull View view) {
+        mView = view;
+    }
+
+    /**
+     * Specifies the region of the view which the view host can accept the touch events.
+     *
+     * @param obscuredRegion the obscured region of the view.
+     */
+    public void setObscuredTouchRegion(@Nullable Region obscuredRegion) {
+        mObscuredTouchRegion = obscuredRegion;
+    }
+
+    private void onComputeInternalInsets(InternalInsetsInfo inoutInfo) {
+        if (!mView.isVisibleToUser()) {
+            return;
+        }
+        if (inoutInfo.touchableRegion.isEmpty()) {
+            // This is the first View to set touchableRegion, then set the entire Window as
+            // touchableRegion first, then subtract each View's region from it.
+            inoutInfo.setTouchableInsets(InternalInsetsInfo.TOUCHABLE_INSETS_REGION);
+            View root = mView.getRootView();
+            root.getLocationInWindow(mLocation);
+            mRect.set(mLocation[0], mLocation[1],
+                    mLocation[0] + root.getWidth(), mLocation[1] + root.getHeight());
+            inoutInfo.touchableRegion.set(mRect);
+        }
+        mView.getLocationInWindow(mLocation);
+        mRect.set(mLocation[0], mLocation[1],
+                mLocation[0] + mView.getWidth(), mLocation[1] + mView.getHeight());
+        inoutInfo.touchableRegion.op(mRect, Region.Op.DIFFERENCE);
+
+        if (mObscuredTouchRegion != null) {
+            inoutInfo.touchableRegion.op(mObscuredTouchRegion, Region.Op.UNION);
+        }
+    };
+
+    /** Registers this to the internal insets computation callback. */
+    public void addToViewTreeObserver() {
+        mView.getViewTreeObserver().addOnComputeInternalInsetsListener(mListener);
+    }
+
+    /** Removes this from the internal insets computation callback. */
+    public void removeFromViewTreeObserver() {
+        mView.getViewTreeObserver().removeOnComputeInternalInsetsListener(mListener);
+    }
+
+    @Override
+    public String toString() {
+        return TAG + "(rect=" + mRect + ", obscuredTouch=" + mObscuredTouchRegion + ")";
+    }
+}
+
diff --git a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewTransitions.java b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewTransitions.java
index 7a3750ac..9b489380 100644
--- a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewTransitions.java
+++ b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewTransitions.java
@@ -16,7 +16,11 @@
 
 package com.android.systemui.car.wm.taskview;
 
+import static android.car.feature.Flags.taskViewTaskReordering;
+import static android.view.WindowManager.TRANSIT_TO_FRONT;
+
 import android.app.ActivityManager;
+import android.app.ActivityTaskManager;
 import android.app.WindowConfiguration;
 import android.content.Context;
 import android.content.pm.PackageManager;
@@ -34,10 +38,13 @@ import androidx.annotation.Nullable;
 import com.android.systemui.car.wm.CarSystemUIProxyImpl;
 import com.android.wm.shell.dagger.WMSingleton;
 import com.android.wm.shell.shared.TransitionUtil;
+import com.android.wm.shell.taskview.TaskViewTransitions;
 import com.android.wm.shell.transition.Transitions;
 
 import dagger.Lazy;
 
+import java.util.List;
+
 import javax.inject.Inject;
 
 /**
@@ -48,18 +55,24 @@ import javax.inject.Inject;
 public final class RemoteCarTaskViewTransitions implements Transitions.TransitionHandler {
     // TODO(b/359584498): Add unit tests for this class.
     private static final String TAG = "CarTaskViewTransit";
+    private static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
 
     private final Transitions mTransitions;
     private final Context mContext;
     private final Lazy<CarSystemUIProxyImpl> mCarSystemUIProxy;
+    private final TaskViewTransitions mTaskViewTransitions;
+
+    private IBinder mLastReorderedTransitionInHandleRequest;
 
     @Inject
     public RemoteCarTaskViewTransitions(Transitions transitions,
             Lazy<CarSystemUIProxyImpl> carSystemUIProxy,
-            Context context) {
+            Context context,
+            TaskViewTransitions taskViewTransitions) {
         mTransitions = transitions;
         mContext = context;
         mCarSystemUIProxy = carSystemUIProxy;
+        mTaskViewTransitions = taskViewTransitions;
 
         if (Transitions.ENABLE_SHELL_TRANSITIONS) {
             mTransitions.addHandler(this);
@@ -83,7 +96,9 @@ public final class RemoteCarTaskViewTransitions implements Transitions.Transitio
         //  on a per taskview basis and remove the ACTIVITY_TYPE_HOME check.
         if (isHome(request.getTriggerTask())
                 && TransitionUtil.isOpeningType(request.getType())) {
-            wct = reorderEmbeddedTasksToTop(request.getTriggerTask().displayId);
+            wct = reorderEmbeddedTasksToTop(
+                    request.getTriggerTask().displayId, /* includeOtherTasksAboveHome= */false);
+            mLastReorderedTransitionInHandleRequest = transition;
         }
 
         // TODO(b/333923667): Think of moving this to CarUiPortraitSystemUI instead.
@@ -109,19 +124,58 @@ public final class RemoteCarTaskViewTransitions implements Transitions.Transitio
         return taskInfo.getWindowingMode() == WindowConfiguration.WINDOWING_MODE_FULLSCREEN;
     }
 
-    private WindowContainerTransaction reorderEmbeddedTasksToTop(int endDisplayId) {
+    private static boolean isInMultiWindowMode(ActivityManager.RunningTaskInfo taskInfo) {
+        return taskInfo.getWindowingMode() == WindowConfiguration.WINDOWING_MODE_MULTI_WINDOW;
+    }
+
+    private WindowContainerTransaction reorderEmbeddedTasksToTop(int endDisplayId,
+            boolean includeOtherTasksAboveHome) {
         WindowContainerTransaction wct = new WindowContainerTransaction();
+        boolean reorderedEmbeddedTasks = false;
         for (int i = mCarSystemUIProxy.get().getAllTaskViews().size() - 1; i >= 0; i--) {
             // TODO(b/359586295): Handle restarting of tasks if required.
             ActivityManager.RunningTaskInfo task =
                     mCarSystemUIProxy.get().getAllTaskViews().valueAt(i).getTaskInfo();
             if (task == null) continue;
             if (task.displayId != endDisplayId) continue;
-            if (Log.isLoggable(TAG, Log.DEBUG)) {
+            if (DBG) {
                 Slog.d(TAG, "Adding transition work to bring the embedded " + task.topActivity
                         + " to top");
             }
-            wct.reorder(task.token, true);
+            wct.reorder(task.token, /* onTop= */true);
+            reorderedEmbeddedTasks = true;
+        }
+        if (reorderedEmbeddedTasks) {
+            return includeOtherTasksAboveHome ? reorderOtherTasks(wct, endDisplayId) : wct;
+        }
+        return null;
+    }
+
+    private WindowContainerTransaction reorderOtherTasks(WindowContainerTransaction wct,
+            int displayId) {
+        // TODO(b/376380746): Remove using ActivityTaskManager to get the tasks once the task
+        //  repository has been implemented in shell
+        List<ActivityManager.RunningTaskInfo> tasks = ActivityTaskManager.getInstance().getTasks(
+                Integer.MAX_VALUE);
+        boolean aboveHomeTask = false;
+        // Iterate in bottom to top manner
+        for (int i = tasks.size() - 1; i >= 0; i--) {
+            ActivityManager.RunningTaskInfo task = tasks.get(i);
+            if (task.getDisplayId() != displayId) continue;
+            // Skip embedded tasks which are running in multi window mode
+            if (mTaskViewTransitions.isTaskViewTask(task) && isInMultiWindowMode(task)) continue;
+            if (isHome(task)) {
+                aboveHomeTask = true;
+                continue;
+            }
+            if (!aboveHomeTask) continue;
+            // Only the tasks which are after the home task and not running in windowing mode
+            // multi window are left
+            if (DBG) {
+                Slog.d(TAG, "Adding transition work to bring the other task " + task.topActivity
+                        + " after home to top");
+            }
+            wct.reorder(task.token, /* onTop= */true);
         }
         return wct;
     }
@@ -131,7 +185,31 @@ public final class RemoteCarTaskViewTransitions implements Transitions.Transitio
             @NonNull SurfaceControl.Transaction startTransaction,
             @NonNull SurfaceControl.Transaction finishTransaction,
             @NonNull Transitions.TransitionFinishCallback finishCallback) {
-        // TODO(b/369186876): Implement reordering of task view task with the host task
+        if (!taskViewTaskReordering()) {
+            if (DBG) {
+                Slog.d(TAG, "Not implementing task view task reordering, as flag is disabled");
+            }
+            return false;
+        }
+        if (mLastReorderedTransitionInHandleRequest != transition) {
+            // This is to handle the case where when some activity on top of home goes away by
+            // pressing back, a handleRequest is not sent for the home due to which the home
+            // comes to the top and embedded tasks become invisible. Only do this when home is
+            // coming to the top due to opening type transition. Note that a new transition will
+            // be sent out for each home activity if the TransitionInfo.Change contains multiple
+            // home activities.
+            for (TransitionInfo.Change chg : info.getChanges()) {
+                if (chg.getTaskInfo() != null && isHome(chg.getTaskInfo())
+                        && TransitionUtil.isOpeningType(chg.getMode())) {
+                    WindowContainerTransaction wct = reorderEmbeddedTasksToTop(
+                            chg.getEndDisplayId(), /* includeOtherTasksAboveHome= */true);
+                    if (wct != null) {
+                        mTransitions.startTransition(TRANSIT_TO_FRONT, wct, /* handler= */null);
+                    }
+                }
+            }
+        }
+        mLastReorderedTransitionInHandleRequest = null;
         return false;
     }
 }
diff --git a/src/com/android/systemui/wm/DisplaySystemBarsController.java b/src/com/android/systemui/wm/DisplaySystemBarsController.java
index 7fe37881..07df7d1e 100644
--- a/src/com/android/systemui/wm/DisplaySystemBarsController.java
+++ b/src/com/android/systemui/wm/DisplaySystemBarsController.java
@@ -29,6 +29,7 @@ import static com.android.systemui.car.systembar.SystemBarUtil.VISIBLE_BAR_VISIB
 import static com.android.systemui.car.systembar.SystemBarUtil.INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX;
 import static com.android.systemui.car.users.CarSystemUIUserUtil.isSecondaryMUMDSystemUI;
 
+import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.content.BroadcastReceiver;
 import android.content.ComponentName;
@@ -275,8 +276,9 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
         }
 
         @Override
-        public void setImeInputTargetRequestedVisibility(boolean visible) {
-            // TODO
+        public void setImeInputTargetRequestedVisibility(boolean visible,
+                @NonNull ImeTracker.Token statsToken) {
+            // no-op - IME visibility is handled by the DisplayImeController
         }
 
         private void registerOverlayChangeBroadcastReceiver() {
@@ -327,9 +329,13 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
                     /* fromIme= */ false, /* statsToken= */ null);
             hideInsets(barVisibilities[INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX],
                     /* fromIme= */ false, /* statsToken = */ null);
+
+            int insetMask = barVisibilities[VISIBLE_BAR_VISIBILITIES_TYPES_INDEX]
+                    | barVisibilities[INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX];
             try {
                 mWmService.updateDisplayWindowRequestedVisibleTypes(mDisplayId,
-                        mRequestedVisibleTypes);
+                        barVisibilities[VISIBLE_BAR_VISIBILITIES_TYPES_INDEX], insetMask,
+                        /* imeStatsToken= */ null);
             } catch (RemoteException e) {
                 Slog.w(TAG, "Unable to update window manager service.");
             }
diff --git a/src/com/android/systemui/wmshell/CarWMComponent.java b/src/com/android/systemui/wmshell/CarWMComponent.java
index 75cb4613..296b9ab9 100644
--- a/src/com/android/systemui/wmshell/CarWMComponent.java
+++ b/src/com/android/systemui/wmshell/CarWMComponent.java
@@ -17,10 +17,11 @@
 package com.android.systemui.wmshell;
 
 import com.android.systemui.car.wm.CarSystemUIProxyImpl;
+import com.android.systemui.car.wm.displayarea.DaViewTransitions;
 import com.android.systemui.car.wm.taskview.RemoteCarTaskViewTransitions;
-import com.android.systemui.dagger.WMComponent;
 import com.android.systemui.wm.DisplaySystemBarsController;
 import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
+import com.android.wm.shell.dagger.WMComponent;
 import com.android.wm.shell.dagger.WMSingleton;
 
 import dagger.Subcomponent;
@@ -58,4 +59,11 @@ public interface CarWMComponent extends WMComponent {
      */
     @WMSingleton
     RemoteCarTaskViewTransitions getRemoteCarTaskViewTransitions();
+
+    /**
+     * Provides the {@link DaViewTransitions}
+     * used to animate DaViews.
+     */
+    @WMSingleton
+    DaViewTransitions getDaViewTransitions();
 }
diff --git a/tests/res/layout/car_system_bar_view_test.xml b/tests/res/layout/car_system_bar_view_test.xml
index cf44a519..74d77b33 100644
--- a/tests/res/layout/car_system_bar_view_test.xml
+++ b/tests/res/layout/car_system_bar_view_test.xml
@@ -40,7 +40,8 @@
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
             systemui:selectedIcon="@drawable/car_ic_overview_selected"
             systemui:highlightWhenSelected="true"
-        />
+            systemui:systemBarDisableFlags="home"
+            systemui:controller="com.android.systemui.car.systembar.HomeButtonController"/>
 
     </LinearLayout>
 
diff --git a/tests/src/com/android/systemui/CarSystemUITestInitializer.java b/tests/src/com/android/systemui/CarSystemUITestInitializer.java
index fb5a89db..f68abe02 100644
--- a/tests/src/com/android/systemui/CarSystemUITestInitializer.java
+++ b/tests/src/com/android/systemui/CarSystemUITestInitializer.java
@@ -21,8 +21,8 @@ import static org.mockito.Mockito.mock;
 import android.content.Context;
 
 import com.android.systemui.dagger.SysUIComponent;
-import com.android.systemui.dagger.WMComponent;
 import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
+import com.android.wm.shell.dagger.WMComponent;
 
 import java.util.Optional;
 
diff --git a/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt b/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
index 6c0c522c..84cea9a7 100644
--- a/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
+++ b/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
@@ -28,6 +28,8 @@ import com.android.systemui.process.ProcessWrapper
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.cancelChildren
 import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.emptyFlow
 import kotlinx.coroutines.flow.flowOf
 import kotlinx.coroutines.launch
@@ -96,7 +98,9 @@ class FakeDisplayRepository(
     private val fakePendingDisplayFlow: Flow<PendingDisplay?>,
     override val displayChangeEvent: Flow<Int> = emptyFlow(),
     override val displayAdditionEvent: Flow<Display?> = emptyFlow(),
-    override val displays: Flow<Set<Display>> = emptyFlow(),
+    override val displayRemovalEvent: Flow<Int> = emptyFlow(),
+    override val displays: StateFlow<Set<Display>> = MutableStateFlow(emptySet()),
     override val defaultDisplayOff: Flow<Boolean> = emptyFlow(),
-    override val pendingDisplay: Flow<PendingDisplay?> = fakePendingDisplayFlow
+    override val pendingDisplay: Flow<PendingDisplay?> = fakePendingDisplayFlow,
+    override val displayIds: StateFlow<Set<Int>> = MutableStateFlow(emptySet()),
 ) : DisplayRepository
diff --git a/tests/src/com/android/systemui/car/hvac/HvacControllerTest.java b/tests/src/com/android/systemui/car/hvac/HvacControllerTest.java
index ca965695..5777e820 100644
--- a/tests/src/com/android/systemui/car/hvac/HvacControllerTest.java
+++ b/tests/src/com/android/systemui/car/hvac/HvacControllerTest.java
@@ -118,6 +118,8 @@ public class HvacControllerTest extends SysuiTestCase {
         when(mTestHvacView1.getHvacPropertyToView()).thenReturn(HVAC_TEMPERATURE_SET);
 
         mHvacController.registerHvacViews(mTestHvacView1);
+        mExecutor.advanceClockToLast();
+        mExecutor.runAllReady();
 
         assertThat(mHvacController.getHvacPropertyViewMap().get(HVAC_TEMPERATURE_SET).get(
                 AREA_1)).contains(mTestHvacView1);
@@ -131,6 +133,8 @@ public class HvacControllerTest extends SysuiTestCase {
                 .thenReturn(VEHICLE_AREA_TYPE_GLOBAL);
 
         mHvacController.registerHvacViews(mTestHvacView1);
+        mExecutor.advanceClockToLast();
+        mExecutor.runAllReady();
 
         assertThat(mHvacController.getHvacPropertyViewMap().get(HVAC_TEMPERATURE_SET).get(
                 AREA_1)).contains(mTestHvacView1);
@@ -156,6 +160,8 @@ public class HvacControllerTest extends SysuiTestCase {
                 .thenReturn(mCarPropertyValue);
 
         mHvacController.registerHvacViews(mTestHvacView1);
+        mExecutor.advanceClockToLast();
+        mExecutor.runAllReady();
 
         assertThat(mHvacController.getHvacPropertyViewMap().get(HVAC_TEMPERATURE_SET).get(
                 AREA_1)).contains(mTestHvacView1);
@@ -172,6 +178,9 @@ public class HvacControllerTest extends SysuiTestCase {
         when(mCarPropertyManager.getCarPropertyConfig(anyInt())).thenReturn(null);
 
         mHvacController.registerHvacViews(mTestHvacView1);
+        mExecutor.advanceClockToLast();
+        mExecutor.runAllReady();
+
         assertThat(mHvacController.getHvacPropertyViewMap()).isEmpty();
     }
 
@@ -179,9 +188,11 @@ public class HvacControllerTest extends SysuiTestCase {
     public void unregisterHvacView_viewNotRegisteredInMap() {
         when(mTestHvacView1.getAreaId()).thenReturn(AREA_1);
         when(mTestHvacView1.getHvacPropertyToView()).thenReturn(HVAC_TEMPERATURE_SET);
-        mHvacController.registerHvacViews(mTestHvacView1);
 
+        mHvacController.registerHvacViews(mTestHvacView1);
         mHvacController.unregisterViews(mTestHvacView1);
+        mExecutor.advanceClockToLast();
+        mExecutor.runAllReady();
 
         assertThat(mHvacController.getHvacPropertyViewMap().get(HVAC_TEMPERATURE_SET)).isNull();
     }
diff --git a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediatorTest.java b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediatorTest.java
index de099d76..9b41fee4 100644
--- a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediatorTest.java
+++ b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediatorTest.java
@@ -62,8 +62,11 @@ public class HvacPanelOverlayViewMediatorTest extends SysuiTestCase {
     public void setUp() {
         MockitoAnnotations.initMocks(this);
 
-        mHvacPanelOverlayViewMediator = new HvacPanelOverlayViewMediator(mContext,
-                mCarSystemBarController, mHvacPanelOverlayViewController, mBroadcastDispatcher,
+        mHvacPanelOverlayViewMediator = new HvacPanelOverlayViewMediator(
+                mContext,
+                mCarSystemBarController,
+                mHvacPanelOverlayViewController,
+                mBroadcastDispatcher,
                 mUserTracker);
     }
 
diff --git a/tests/src/com/android/systemui/car/input/DisplayInputSinkControllerTest.java b/tests/src/com/android/systemui/car/input/DisplayInputSinkControllerTest.java
index 7b24a635..348715ee 100644
--- a/tests/src/com/android/systemui/car/input/DisplayInputSinkControllerTest.java
+++ b/tests/src/com/android/systemui/car/input/DisplayInputSinkControllerTest.java
@@ -137,6 +137,7 @@ public class DisplayInputSinkControllerTest extends SysuiTestCase {
         }).when(mCarServiceProvider).addListener(any(CarServiceOnConnectedListener.class));
         doReturn(mCarPowerManager).when(mCar).getCarManager(CarPowerManager.class);
         doReturn(mCarOccupantZoneManager).when(mCar).getCarManager(CarOccupantZoneManager.class);
+        doReturn(true).when(() -> UserManager.isVisibleBackgroundUsersEnabled());
         // Initialize two displays as passenger displays.
         setUpDisplay(mPassengerDisplay1, mPassengerDisplayId1, mPassengerDisplayUniqueId1);
         setUpDisplay(mPassengerDisplay2, mPassengerDisplayId2, mPassengerDisplayUniqueId2);
@@ -147,6 +148,21 @@ public class DisplayInputSinkControllerTest extends SysuiTestCase {
         mMockingSession.finishMocking();
     }
 
+    @Test
+    public void start_nonMUMDSystem_controllerNotStarted() {
+        doReturn(UserHandle.USER_SYSTEM).when(() -> UserHandle.myUserId());
+        doReturn(true).when(() -> UserManager.isHeadlessSystemUserMode());
+        doReturn(false).when(() -> UserManager.isVisibleBackgroundUsersEnabled());
+
+        mDisplayInputSinkController.start();
+
+        verify(mContentResolver, never())
+                .registerContentObserver(any(Uri.class), anyBoolean(), any(ContentObserver.class));
+        verify(mDisplayManager, never()).registerDisplayListener(
+                any(DisplayManager.DisplayListener.class),
+                any());
+    }
+
     @Test
     public void start_nonSystemUser_controllerNotStarted() {
         doReturn(UserHandle.USER_NULL).when(() -> UserHandle.myUserId());
@@ -220,6 +236,7 @@ public class DisplayInputSinkControllerTest extends SysuiTestCase {
     public void onDisplayAdded_withValidDisplay_callsStartDisplayInputLock() {
         doReturn(UserHandle.USER_SYSTEM).when(() -> UserHandle.myUserId());
         mDisplayInputSinkController.start();
+        writeDisplayInputLockSetting(mContentResolver, mPassengerDisplayUniqueId2);
         mDisplayInputLockSetting.add(mPassengerDisplayUniqueId2);
 
         mDisplayInputSinkController.mDisplayListener.onDisplayAdded(mPassengerDisplayId2);
@@ -242,6 +259,19 @@ public class DisplayInputSinkControllerTest extends SysuiTestCase {
         assertThat(isInputMonitorStarted(mPassengerDisplayId2)).isFalse();
     }
 
+    @Test
+    public void onDisplayAdded_updatesDisplayInputLockFromCurrentSetting() {
+        // Initially display 2 is not locked.
+        assertThat(isInputLockStarted(mPassengerDisplayId2)).isFalse();
+        // In the settings, display 2 is set to be locked.
+        writeDisplayInputLockSetting(mContentResolver, mPassengerDisplayUniqueId2);
+
+        // onDisplayAdded() updates display input locking from the current settings value.
+        mDisplayInputSinkController.mDisplayListener.onDisplayAdded(mPassengerDisplayId2);
+
+        assertThat(isInputLockStarted(mPassengerDisplayId2)).isTrue();
+    }
+
     @Test
     public void onDisplayRemoved_inputLockStarted_callsStopDisplayInputLock() {
         doReturn(UserHandle.USER_SYSTEM).when(() -> UserHandle.myUserId());
diff --git a/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java b/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
index aaff6b62..b8d76e63 100644
--- a/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
@@ -54,11 +54,13 @@ import com.android.systemui.car.window.SystemUIOverlayWindowController;
 import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToGoneTransitionViewModel;
 import com.android.systemui.log.BouncerLogger;
 import com.android.systemui.settings.UserTracker;
+import com.android.systemui.statusbar.domain.interactor.StatusBarKeyguardViewManagerInteractor;
 import com.android.systemui.statusbar.phone.BiometricUnlockController;
 import com.android.systemui.statusbar.policy.KeyguardStateController;
 import com.android.systemui.toast.ToastFactory;
 import com.android.systemui.user.domain.interactor.SelectedUserInteractor;
 import com.android.systemui.util.concurrency.FakeExecutor;
+import com.android.systemui.util.kotlin.JavaAdapter;
 import com.android.systemui.util.time.FakeSystemClock;
 
 import org.junit.Before;
@@ -147,7 +149,9 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
                 mock(BouncerLogger.class),
                 mock(BouncerMessageInteractor.class),
                 mock(SelectedUserInteractor.class),
-                Optional.of(mKeyguardSystemBarPresenter)
+                Optional.of(mKeyguardSystemBarPresenter),
+                mock(StatusBarKeyguardViewManagerInteractor.class),
+                mock(JavaAdapter.class)
         );
         mCarKeyguardViewController.inflate((ViewGroup) LayoutInflater.from(mContext).inflate(
                 R.layout.sysui_overlay_window, /* root= */ null));
diff --git a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java
new file mode 100644
index 00000000..928d8d68
--- /dev/null
+++ b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java
@@ -0,0 +1,166 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+
+import android.app.trust.TrustManager;
+import android.os.Handler;
+import android.testing.AndroidTestingRunner;
+import android.view.View;
+
+import androidx.test.filters.SmallTest;
+
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.internal.widget.LockPatternChecker;
+import com.android.internal.widget.LockPatternUtils;
+import com.android.internal.widget.LockscreenCredential;
+import com.android.internal.widget.VerifyCredentialResponse;
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.settings.UserTracker;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
+
+@CarSystemUiTest
+@RunWith(AndroidTestingRunner.class)
+@SmallTest
+public class PassengerKeyguardCredentialViewControllerTest extends SysuiTestCase {
+
+    private TestPassengerKeyguardCredentialViewController mController;
+    private MockitoSession mSession;
+
+    @Mock
+    private LockPatternUtils mLockPatternUtils;
+    @Mock
+    private UserTracker mUserTracker;
+    @Mock
+    private TrustManager mTrustManager;
+    @Mock
+    private Handler mMainHandler;
+    @Mock
+    private CarServiceProvider mCarServiceProvider;
+    @Mock
+    private PassengerKeyguardLockoutHelper mLockoutHelper;
+    @Mock
+    private PassengerKeyguardCredentialViewController.OnAuthSucceededCallback mCallback;
+
+    @Before
+    public void setUp() {
+        mSession = ExtendedMockito.mockitoSession()
+                .initMocks(this)
+                .mockStatic(LockPatternChecker.class)
+                .strictness(Strictness.LENIENT)
+                .startMocking();
+        View view = new View(mContext);
+        mController = new TestPassengerKeyguardCredentialViewController(view, mLockPatternUtils,
+                mUserTracker, mTrustManager, mMainHandler, mCarServiceProvider, mLockoutHelper);
+        mController.setAuthSucceededCallback(mCallback);
+    }
+
+    @After
+    public void tearDown() {
+        if (mSession != null) {
+            mSession.finishMocking();
+            mSession = null;
+        }
+    }
+
+    @Test
+    public void verifyCredential_invalidCredential_postFailureRunnable() {
+        Runnable failureRunnable = mock(Runnable.class);
+        ArgumentCaptor<LockPatternChecker.OnVerifyCallback> captor = ArgumentCaptor.forClass(
+                LockPatternChecker.OnVerifyCallback.class);
+
+        mController.verifyCredential(failureRunnable);
+
+        ExtendedMockito.verify(() -> LockPatternChecker.verifyCredential(any(), any(), anyInt(),
+                anyInt(), captor.capture()));
+        captor.getValue().onVerified(VerifyCredentialResponse.ERROR, 0);
+        verify(mMainHandler).post(failureRunnable);
+    }
+
+    @Test
+    public void verifyCredential_invalidCredential_timeout() {
+        int throttleTimeoutMs = 1000;
+        Runnable failureRunnable = mock(Runnable.class);
+        ArgumentCaptor<LockPatternChecker.OnVerifyCallback> captor = ArgumentCaptor.forClass(
+                LockPatternChecker.OnVerifyCallback.class);
+
+        mController.verifyCredential(failureRunnable);
+
+        ExtendedMockito.verify(() -> LockPatternChecker.verifyCredential(any(), any(), anyInt(),
+                anyInt(), captor.capture()));
+        captor.getValue().onVerified(VerifyCredentialResponse.ERROR, throttleTimeoutMs);
+        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
+        verify(mMainHandler).post(runnableCaptor.capture());
+        runnableCaptor.getValue().run();
+        verify(mLockoutHelper).onCheckCompletedWithTimeout(throttleTimeoutMs);
+    }
+
+    @Test
+    public void verifyCredential_validCredential_authSucceeded() {
+        Runnable failureRunnable = mock(Runnable.class);
+        ArgumentCaptor<LockPatternChecker.OnVerifyCallback> captor = ArgumentCaptor.forClass(
+                LockPatternChecker.OnVerifyCallback.class);
+
+        mController.verifyCredential(failureRunnable);
+
+        ExtendedMockito.verify(() -> LockPatternChecker.verifyCredential(any(), any(), anyInt(),
+                anyInt(), captor.capture()));
+        captor.getValue().onVerified(VerifyCredentialResponse.OK, /* throttleTimeoutMs= */ 0);
+        verify(mMainHandler, never()).post(failureRunnable);
+        verify(mTrustManager).reportEnabledTrustAgentsChanged(anyInt());
+        verify(mCallback).onAuthSucceeded();
+    }
+
+    private static class TestPassengerKeyguardCredentialViewController
+            extends PassengerKeyguardCredentialViewController {
+
+        TestPassengerKeyguardCredentialViewController(View view,
+                LockPatternUtils lockPatternUtils,
+                UserTracker userTracker,
+                TrustManager trustManager, Handler mainHandler,
+                CarServiceProvider carServiceProvider,
+                PassengerKeyguardLockoutHelper lockoutHelper) {
+            super(view, lockPatternUtils, userTracker, trustManager, mainHandler,
+                    carServiceProvider, lockoutHelper);
+        }
+
+        @Override
+        protected LockscreenCredential getCurrentCredential() {
+            return LockscreenCredential.createPin("1234");
+        }
+
+        @Override
+        protected void onLockedOutChanged(boolean isLockedOut) {
+            // no-op
+        }
+    }
+}
diff --git a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialogTest.java b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialogTest.java
new file mode 100644
index 00000000..d4e52d0c
--- /dev/null
+++ b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardLoadingDialogTest.java
@@ -0,0 +1,306 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_STARTING;
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_STOPPED;
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_UNLOCKED;
+
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.annotation.Nullable;
+import android.car.Car;
+import android.car.CarOccupantZoneManager;
+import android.car.feature.Flags;
+import android.car.user.CarUserManager;
+import android.content.Context;
+import android.hardware.display.DisplayManager;
+import android.os.Handler;
+import android.os.UserHandle;
+import android.os.UserManager;
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.flag.junit.SetFlagsRule;
+import android.testing.AndroidTestingRunner;
+import android.testing.TestableLooper;
+import android.view.Display;
+
+import androidx.test.filters.SmallTest;
+
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.internal.widget.LockPatternUtils;
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.utils.os.FakeHandler;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
+
+import java.util.Set;
+import java.util.concurrent.Executor;
+
+@CarSystemUiTest
+@RunWith(AndroidTestingRunner.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+@EnableFlags(Flags.FLAG_SUPPORTS_SECURE_PASSENGER_USERS)
+public class PassengerKeyguardLoadingDialogTest extends SysuiTestCase {
+    private static final int TEST_USER_ID = 1000;
+    private static final int TEST_DRIVER_DISPLAY_ID = 100;
+    private static final int TEST_PASSENGER_DISPLAY_ID = 101;
+
+    private PassengerKeyguardLoadingDialog mLoadingDialog;
+    private MockitoSession mSession;
+    private FakeHandler mMainHandler;
+
+    @Nullable
+    private CarUserManager.UserLifecycleListener mUserLifecycleListener;
+    @Nullable
+    private DisplayManager.DisplayListener mDisplayListener;
+
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
+    @Mock
+    private CarServiceProvider mCarServiceProvider;
+    @Mock
+    private Executor mBackgroundExecutor;
+
+    @Mock
+    private Handler mBackgroundHandler;
+    @Mock
+    private LockPatternUtils mLockPatternUtils;
+    @Mock
+    private UserManager mUserManager;
+    @Mock
+    private DisplayManager mDisplayManager;
+    @Mock
+    private CarUserManager mCarUserManager;
+    @Mock
+    private CarOccupantZoneManager mCarOccupantZoneManager;
+
+
+    @Before
+    public void setUp() {
+        mSession = ExtendedMockito.mockitoSession()
+                .initMocks(this)
+                .spyStatic(CarSystemUIUserUtil.class)
+                .strictness(Strictness.LENIENT)
+                .startMocking();
+        mMainHandler = new FakeHandler(TestableLooper.get(this).getLooper());
+        mContext.addMockSystemService(UserManager.class, mUserManager);
+        mContext.addMockSystemService(DisplayManager.class, mDisplayManager);
+        mLoadingDialog = new TestPassengerKeyguardLoadingDialog(mContext, mCarServiceProvider,
+                mBackgroundExecutor, mMainHandler, mBackgroundHandler, mLockPatternUtils);
+    }
+
+    @After
+    public void tearDown() {
+        if (mSession != null) {
+            mSession.finishMocking();
+            mSession = null;
+        }
+    }
+
+    @Test
+    public void onStart_notDriverMUMDSysUI_notInitialized() {
+        doReturn(false).when(() -> CarSystemUIUserUtil.isDriverMUMDSystemUI());
+
+        mLoadingDialog.start();
+
+        verify(mCarServiceProvider, never()).addListener(any());
+        verify(mDisplayManager, never()).registerDisplayListener(any(), any());
+    }
+
+    @Test
+    public void onStart_driverMUMDSysUI_initialized() {
+        doReturn(true).when(() -> CarSystemUIUserUtil.isDriverMUMDSystemUI());
+
+        mLoadingDialog.start();
+
+        verify(mCarServiceProvider).addListener(any());
+        verify(mDisplayManager).registerDisplayListener(any(), any());
+    }
+
+    @Test
+    public void onUserStart_nonSecureUser_presentationNotCreated() {
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(false);
+        when(mUserManager.isUserUnlocked(TEST_USER_ID)).thenReturn(true);
+        startAndRegisterMocks();
+        assertThat(mUserLifecycleListener).isNotNull();
+
+        mUserLifecycleListener.onEvent(
+                new CarUserManager.UserLifecycleEvent(USER_LIFECYCLE_EVENT_TYPE_STARTING,
+                        TEST_USER_ID));
+
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isFalse();
+    }
+
+    @Test
+    public void onUserStart_secureUser_presentationCreated() {
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(true);
+        when(mUserManager.isUserUnlocked(TEST_USER_ID)).thenReturn(false);
+        startAndRegisterMocks();
+        assertThat(mUserLifecycleListener).isNotNull();
+
+        mUserLifecycleListener.onEvent(
+                new CarUserManager.UserLifecycleEvent(USER_LIFECYCLE_EVENT_TYPE_STARTING,
+                        TEST_USER_ID));
+
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isTrue();
+    }
+
+    @Test
+    public void onInit_nonSecureUserVisible_presentationNotCreated() {
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(false);
+        when(mUserManager.isUserUnlocked(TEST_USER_ID)).thenReturn(true);
+        when(mUserManager.getVisibleUsers()).thenReturn(Set.of(UserHandle.of(TEST_USER_ID)));
+
+        startAndRegisterMocks();
+
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isFalse();
+    }
+
+    @Test
+    public void onInit_secureUserVisible_presentationCreated() {
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(true);
+        when(mUserManager.isUserUnlocked(TEST_USER_ID)).thenReturn(false);
+        when(mUserManager.getVisibleUsers()).thenReturn(Set.of(UserHandle.of(TEST_USER_ID)));
+
+        startAndRegisterMocks();
+
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isTrue();
+    }
+
+    @Test
+    public void onDisplayRemoved_presentationRemoved() {
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(true);
+        when(mUserManager.isUserUnlocked(TEST_USER_ID)).thenReturn(false);
+        when(mUserManager.getVisibleUsers()).thenReturn(Set.of(UserHandle.of(TEST_USER_ID)));
+        startAndRegisterMocks();
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isTrue();
+        assertThat(mDisplayListener).isNotNull();
+
+        mDisplayListener.onDisplayRemoved(TEST_PASSENGER_DISPLAY_ID);
+
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isFalse();
+    }
+
+    @Test
+    public void onUserUnlocked_presentationRemoved() {
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(true);
+        when(mUserManager.isUserUnlocked(TEST_USER_ID)).thenReturn(false);
+        when(mUserManager.getVisibleUsers()).thenReturn(Set.of(UserHandle.of(TEST_USER_ID)));
+        startAndRegisterMocks();
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isTrue();
+        assertThat(mUserLifecycleListener).isNotNull();
+
+        mUserLifecycleListener.onEvent(
+                new CarUserManager.UserLifecycleEvent(USER_LIFECYCLE_EVENT_TYPE_UNLOCKED,
+                        TEST_USER_ID));
+
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isFalse();
+    }
+
+    @Test
+    public void onUserStopped_presentationRemoved() {
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(true);
+        when(mUserManager.isUserUnlocked(TEST_USER_ID)).thenReturn(false);
+        when(mUserManager.getVisibleUsers()).thenReturn(Set.of(UserHandle.of(TEST_USER_ID)));
+        startAndRegisterMocks();
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isTrue();
+        assertThat(mUserLifecycleListener).isNotNull();
+
+        mUserLifecycleListener.onEvent(
+                new CarUserManager.UserLifecycleEvent(USER_LIFECYCLE_EVENT_TYPE_STOPPED,
+                        TEST_USER_ID));
+
+        assertThat(mLoadingDialog.mPresentations.containsKey(TEST_USER_ID)).isFalse();
+    }
+
+    /**
+     * Start the CoreStartable and setup mocks related to the CarService and DisplayManager
+     */
+    private void startAndRegisterMocks() {
+        doReturn(true).when(() -> CarSystemUIUserUtil.isDriverMUMDSystemUI());
+        Car mockCar = mock(Car.class);
+        when(mockCar.getCarManager(CarUserManager.class)).thenReturn(mCarUserManager);
+        when(mockCar.getCarManager(CarOccupantZoneManager.class)).thenReturn(
+                mCarOccupantZoneManager);
+        when(mCarOccupantZoneManager.getDisplayIdForDriver(
+                CarOccupantZoneManager.DISPLAY_TYPE_MAIN)).thenReturn(TEST_DRIVER_DISPLAY_ID);
+        CarOccupantZoneManager.OccupantZoneInfo passengerZoneInfo = mock(
+                CarOccupantZoneManager.OccupantZoneInfo.class);
+        Display passengerDisplay = mock(Display.class);
+        when(passengerDisplay.getDisplayId()).thenReturn(TEST_PASSENGER_DISPLAY_ID);
+        when(mCarOccupantZoneManager.getOccupantZoneForUser(
+                UserHandle.of(TEST_USER_ID))).thenReturn(passengerZoneInfo);
+        when(mCarOccupantZoneManager.getDisplayForOccupant(passengerZoneInfo,
+                CarOccupantZoneManager.DISPLAY_TYPE_MAIN)).thenReturn(passengerDisplay);
+        when(mCarOccupantZoneManager.getUserForDisplayId(TEST_PASSENGER_DISPLAY_ID)).thenReturn(
+                TEST_USER_ID);
+
+        ArgumentCaptor<CarServiceProvider.CarServiceOnConnectedListener> carConnectedListener =
+                ArgumentCaptor.forClass(CarServiceProvider.CarServiceOnConnectedListener.class);
+        ArgumentCaptor<CarUserManager.UserLifecycleListener> userLifecycleListener =
+                ArgumentCaptor.forClass(CarUserManager.UserLifecycleListener.class);
+        ArgumentCaptor<DisplayManager.DisplayListener> displayListener =
+                ArgumentCaptor.forClass(DisplayManager.DisplayListener.class);
+
+        mLoadingDialog.start();
+
+        verify(mCarServiceProvider).addListener(carConnectedListener.capture());
+        carConnectedListener.getValue().onConnected(mockCar);
+
+        verify(mCarUserManager).addListener(any(), userLifecycleListener.capture());
+        mUserLifecycleListener = userLifecycleListener.getValue();
+        verify(mDisplayManager).registerDisplayListener(displayListener.capture(), any());
+        mDisplayListener = displayListener.getValue();
+    }
+
+    private static class TestPassengerKeyguardLoadingDialog extends PassengerKeyguardLoadingDialog {
+        TestPassengerKeyguardLoadingDialog(Context context,
+                CarServiceProvider carServiceProvider,
+                Executor bgExecutor, Handler mainHandler, Handler bgHandler,
+                LockPatternUtils lockPatternUtils) {
+            super(context, carServiceProvider, bgExecutor, mainHandler, bgHandler,
+                    lockPatternUtils);
+        }
+
+        // Use mock for loading presentation to not depend on real display
+        @Override
+        LoadingPresentation createLoadingPresentation(Display display) {
+            return mock(LoadingPresentation.class);
+        }
+    }
+}
diff --git a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediatorTest.java b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediatorTest.java
new file mode 100644
index 00000000..a75144ef
--- /dev/null
+++ b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardOverlayViewMediatorTest.java
@@ -0,0 +1,123 @@
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
+package com.android.systemui.car.keyguard.passenger;
+
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.app.trust.TrustManager;
+import android.car.feature.Flags;
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.flag.junit.SetFlagsRule;
+import android.testing.AndroidTestingRunner;
+
+import androidx.test.filters.SmallTest;
+
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.internal.widget.LockPatternUtils;
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.settings.UserTracker;
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
+@CarSystemUiTest
+@RunWith(AndroidTestingRunner.class)
+@SmallTest
+@EnableFlags(Flags.FLAG_SUPPORTS_SECURE_PASSENGER_USERS)
+public class PassengerKeyguardOverlayViewMediatorTest extends SysuiTestCase {
+    private static final int TEST_USER_ID = 1000;
+
+    private PassengerKeyguardOverlayViewMediator mMediator;
+    private MockitoSession mSession;
+
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
+    @Mock
+    private PassengerKeyguardOverlayViewController mViewController;
+    @Mock
+    private UserTracker mUserTracker;
+    @Mock
+    private LockPatternUtils mLockPatternUtils;
+    @Mock
+    private TrustManager mTrustManager;
+
+    @Before
+    public void setUp() {
+        mSession = ExtendedMockito.mockitoSession()
+                .initMocks(this)
+                .spyStatic(CarSystemUIUserUtil.class)
+                .strictness(Strictness.LENIENT)
+                .startMocking();
+        when(mUserTracker.getUserId()).thenReturn(TEST_USER_ID);
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(false);
+        mMediator = new PassengerKeyguardOverlayViewMediator(mViewController, mUserTracker,
+                mLockPatternUtils, mTrustManager);
+    }
+
+    @After
+    public void tearDown() {
+        if (mSession != null) {
+            mSession.finishMocking();
+            mSession = null;
+        }
+    }
+
+    @Test
+    public void setupController_nonSecondaryMUMDSysUI_controllerNotInitialized() {
+        doReturn(false).when(() -> CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
+
+        mMediator.setUpOverlayContentViewControllers();
+
+        verify(mViewController, never()).start();
+        verify(mTrustManager, never()).reportEnabledTrustAgentsChanged(anyInt());
+    }
+
+    @Test
+    public void setupController_nonSecureUser_controllerNotInitialized() {
+        doReturn(true).when(() -> CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
+
+        mMediator.setUpOverlayContentViewControllers();
+
+        verify(mViewController, never()).start();
+        verify(mTrustManager).reportEnabledTrustAgentsChanged(TEST_USER_ID);
+    }
+
+    @Test
+    public void setupController_secureUser_controllerInitialized() {
+        doReturn(true).when(() -> CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
+        when(mLockPatternUtils.isSecure(TEST_USER_ID)).thenReturn(true);
+
+        mMediator.setUpOverlayContentViewControllers();
+
+        verify(mTrustManager, never()).reportEnabledTrustAgentsChanged(TEST_USER_ID);
+        verify(mViewController).start();
+    }
+}
diff --git a/tests/src/com/android/systemui/car/ndo/InCallLiveDataTest.java b/tests/src/com/android/systemui/car/ndo/InCallLiveDataTest.java
index cb9e9f6b..8f3d8e85 100644
--- a/tests/src/com/android/systemui/car/ndo/InCallLiveDataTest.java
+++ b/tests/src/com/android/systemui/car/ndo/InCallLiveDataTest.java
@@ -15,13 +15,9 @@
  */
 package com.android.systemui.car.ndo;
 
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.doNothing;
-
 import static com.google.common.truth.Truth.assertThat;
 
-import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.content.ComponentName;
@@ -45,8 +41,6 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
-import org.mockito.ArgumentCaptor;
-import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
@@ -71,8 +65,6 @@ public class InCallLiveDataTest extends SysuiTestCase {
     @Mock
     private Call mMockCall;
     private Call.Details mMockDetails;
-    @Captor
-    private ArgumentCaptor<Call.Callback> mCallbackCaptor;
 
     @Before
     public void setup() {
@@ -81,7 +73,6 @@ public class InCallLiveDataTest extends SysuiTestCase {
         when(mMockInCallService.getCalls()).thenReturn(List.of(mMockCall));
         mMockDetails = createMockCallDetails(NUMBER, Call.STATE_HOLDING);
         when(mMockCall.getDetails()).thenReturn(mMockDetails);
-        doNothing().when(mMockCall).registerCallback(mCallbackCaptor.capture());
 
         mInCallServiceManager = new InCallServiceManager();
         mInCallServiceManager.setInCallService(mMockInCallService);
@@ -91,17 +82,13 @@ public class InCallLiveDataTest extends SysuiTestCase {
     @Test
     public void testOnCallAdded() {
         mInCallLiveData.onCallAdded(mMockCall);
-
-        verify(mMockCall).registerCallback(any());
         assertThat(mInCallLiveData.getValue()).isEqualTo(mMockCall);
     }
 
     @Test
     public void testOnCallRemoved() {
         when(mMockInCallService.getCalls()).thenReturn(List.of());
-
         mInCallLiveData.onCallRemoved(mMockCall);
-        verify(mMockCall).unregisterCallback(any());
         assertThat(mInCallLiveData.getValue()).isNull();
     }
 
@@ -109,12 +96,10 @@ public class InCallLiveDataTest extends SysuiTestCase {
     public void testOnStateChanged() {
         when(mMockDetails.getState()).thenReturn(Call.STATE_RINGING);
         mInCallLiveData.onCallAdded(mMockCall);
-
-        verify(mMockCall).registerCallback(any());
         assertThat(mInCallLiveData.getValue()).isNull();
 
         when(mMockDetails.getState()).thenReturn(Call.STATE_ACTIVE);
-        mCallbackCaptor.getValue().onStateChanged(mMockCall, Call.STATE_ACTIVE);
+        mInCallLiveData.onStateChanged(mMockCall, Call.STATE_ACTIVE);
         assertThat(mInCallLiveData.getValue()).isEqualTo(mMockCall);
     }
 
diff --git a/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java b/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java
index 15f2819f..59f0056f 100644
--- a/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java
+++ b/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java
@@ -101,6 +101,8 @@ public class DataSubscriptionControllerTest extends SysuiTestCase {
     private Executor mExecutor;
     @Mock
     private CarUxRestrictionsUtil mCarUxRestrictionsUtil;
+    @Mock
+    private DataSubscriptionStatsLogHelper mDataSubscriptionStatsLogHelper;
     private MockitoSession mMockingSession;
     private ActivityManager.RunningTaskInfo mRunningTaskInfoMock;
     private DataSubscriptionController mController;
@@ -117,7 +119,8 @@ public class DataSubscriptionControllerTest extends SysuiTestCase {
 
         mContext = spy(mContext);
         when(mUserTracker.getUserHandle()).thenReturn(UserHandle.of(1000));
-        mController = new DataSubscriptionController(mContext, mUserTracker, mHandler, mExecutor);
+        mController = new DataSubscriptionController(mContext, mUserTracker, mHandler, mExecutor,
+                mDataSubscriptionStatsLogHelper);
         mController.setSubscription(mDataSubscription);
         mController.setPopupWindow(mPopupWindow);
         mController.setConnectivityManager(mConnectivityManager);
diff --git a/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java b/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
index 219e9903..31412c11 100644
--- a/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
+++ b/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
@@ -17,6 +17,7 @@
 package com.android.systemui.car.qc;
 
 import static android.car.test.mocks.AndroidMockitoHelper.mockUmGetVisibleUsers;
+import static android.car.user.UserSwitchResult.STATUS_SUCCESSFUL;
 import static android.os.UserManager.SWITCHABILITY_STATUS_OK;
 import static android.os.UserManager.SWITCHABILITY_STATUS_USER_SWITCH_DISALLOWED;
 
@@ -342,6 +343,12 @@ public class ProfileSwitcherTest extends SysuiTestCase {
         // Expect four rows - one for each user, one for the guest user, and one for add user
         assertThat(rows).hasSize(4);
         QCRow otherUserRow = rows.get(1);
+        // When switch user is invoked, mock the UserSwitchResult so it won't wait for timeout
+        doAnswer((inv) -> {
+            SyncResultCallback<UserSwitchResult> callback = inv.getArgument(2);
+            callback.onResult(new UserSwitchResult(STATUS_SUCCESSFUL, null));
+            return null;
+        }).when(mCarUserManager).switchUser(any(), any(), any());
         otherUserRow.getActionHandler().onAction(otherUserRow, mContext, new Intent());
 
         mProfileSwitcher.mHandler.post(() -> {
@@ -372,6 +379,12 @@ public class ProfileSwitcherTest extends SysuiTestCase {
         // Expect 3 rows - one for the user, one for the guest user, and one for add user
         assertThat(rows).hasSize(3);
         QCRow guestRow = rows.get(1);
+        // When switch user is invoked, mock the UserSwitchResult so it won't wait for timeout
+        doAnswer((inv) -> {
+            SyncResultCallback<UserSwitchResult> callback = inv.getArgument(2);
+            callback.onResult(new UserSwitchResult(STATUS_SUCCESSFUL, null));
+            return null;
+        }).when(mCarUserManager).switchUser(any(), any(), any());
         guestRow.getActionHandler().onAction(guestRow, mContext, new Intent());
         verify(mCarUserManager).createGuest(any());
 
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
index 703b1b07..76344fa9 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
@@ -18,31 +18,29 @@ package com.android.systemui.car.systembar;
 
 import static android.app.StatusBarManager.DISABLE2_QUICK_SETTINGS;
 import static android.app.StatusBarManager.DISABLE_HOME;
-import static android.app.StatusBarManager.DISABLE_NOTIFICATION_ICONS;
 
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
 import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
 import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
 import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 
 import static com.google.common.truth.Truth.assertThat;
 
-import static org.junit.Assume.assumeFalse;
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.app.ActivityManager;
-import android.content.Context;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.testing.TestableResources;
 import android.util.ArrayMap;
+import android.util.ArraySet;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.WindowManager;
@@ -58,15 +56,17 @@ import com.android.internal.statusbar.RegisterStatusBarResult;
 import com.android.internal.view.AppearanceRegion;
 import com.android.systemui.R;
 import com.android.systemui.SysuiTestCase;
+import com.android.systemui.SysuiTestableContext;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.hvac.HvacController;
-import com.android.systemui.car.hvac.HvacPanelController;
-import com.android.systemui.car.notification.NotificationsShadeController;
 import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
-import com.android.systemui.flags.FeatureFlags;
+import com.android.systemui.car.window.OverlayVisibilityMediator;
 import com.android.systemui.plugins.DarkIconDispatcher;
 import com.android.systemui.settings.FakeDisplayTracker;
 import com.android.systemui.settings.UserTracker;
@@ -86,12 +86,18 @@ import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
 import java.util.Set;
 
+import javax.inject.Provider;
+
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
@@ -104,7 +110,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     private CarSystemBarControllerImpl mCarSystemBarController;
     private CarSystemBarViewFactory mCarSystemBarViewFactory;
     private TestableResources mTestableResources;
-    private Context mSpiedContext;
+    private SysuiTestableContext mSpiedContext;
     private MockitoSession mSession;
 
     @Mock
@@ -120,14 +126,8 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Mock
     private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
     @Mock
-    private FeatureFlags mFeatureFlags;
-    @Mock
-    private StatusIconPanelViewController.Builder mPanelControllerBuilder;
-    @Mock
     private StatusIconPanelViewController mPanelController;
     @Mock
-    private CarSystemBarElementInitializer mCarSystemBarElementInitializer;
-    @Mock
     private LightBarController mLightBarController;
     @Mock
     private SysuiDarkIconDispatcher mStatusBarIconController;
@@ -150,12 +150,13 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Mock
     private StatusBarSignalPolicy mSignalPolicy;
     @Mock
-    private HvacController mHvacController;
-    @Mock
     private ConfigurationController mConfigurationController;
     @Mock
     private CarSystemBarRestartTracker mCarSystemBarRestartTracker;
-    RegisterStatusBarResult mRegisterStatusBarResult;
+    @Mock
+    private OverlayVisibilityMediator mOverlayVisibilityMediator;
+    private RegisterStatusBarResult mRegisterStatusBarResult;
+    private SystemBarConfigs mSystemBarConfigs;
 
     @Before
     public void setUp() throws Exception {
@@ -166,10 +167,60 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
             .startMocking();
         mTestableResources = mContext.getOrCreateTestableResources();
         mSpiedContext = spy(mContext);
-        when(mSpiedContext.getSystemService(ActivityManager.class)).thenReturn(mActivityManager);
-        mCarSystemBarViewFactory = new CarSystemBarViewFactory(mSpiedContext, mFeatureFlags,
-                mock(UserTracker.class), mCarSystemBarElementInitializer);
-        setupPanelControllerBuilderMocks();
+        mSpiedContext.addMockSystemService(ActivityManager.class, mActivityManager);
+        mSpiedContext.addMockSystemService(WindowManager.class, mWindowManager);
+        when(mSpiedContext.createWindowContext(anyInt(), any())).thenReturn(mSpiedContext);
+        when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
+        when(mDeviceProvisionedController.isCurrentUserSetupInProgress()).thenReturn(false);
+        Map<Class<?>, Provider<CarSystemBarElementController.Factory>> controllerFactoryMap =
+                new ArrayMap<>();
+        Provider<CarSystemBarElementController.Factory> homeButtonControllerProvider =
+                () -> new HomeButtonController.Factory() {
+                    @Override
+                    public HomeButtonController create(CarSystemBarButton view) {
+                        return new HomeButtonController(view,
+                                mock(CarSystemBarElementStatusBarDisableController.class),
+                                mock(CarSystemBarElementStateController.class),
+                                mUserTracker);
+                    }
+                };
+        controllerFactoryMap.put(HomeButtonController.class, homeButtonControllerProvider);
+        Provider<CarSystemBarElementController.Factory> passengerHomeButtonControllerProvider =
+                () -> new PassengerHomeButtonController.Factory() {
+                    @Override
+                    public PassengerHomeButtonController create(CarSystemBarButton view) {
+                        return new PassengerHomeButtonController(view,
+                                mock(CarSystemBarElementStatusBarDisableController.class),
+                                mock(CarSystemBarElementStateController.class),
+                                mUserTracker);
+                    }
+                };
+        controllerFactoryMap.put(PassengerHomeButtonController.class,
+                passengerHomeButtonControllerProvider);
+        CarSystemBarElementInitializer carSystemBarElementInitializer =
+                new CarSystemBarElementInitializer(controllerFactoryMap);
+        mSystemBarConfigs =
+                new SystemBarConfigsImpl(mSpiedContext, mTestableResources.getResources());
+        CarSystemBarViewControllerFactory carSystemBarViewControllerFactory =
+                new CarSystemBarViewControllerImpl.Factory() {
+                    public CarSystemBarViewControllerImpl create(@SystemBarSide int side,
+                            ViewGroup view) {
+                        return spy(new CarSystemBarViewControllerImpl(mSpiedContext, mUserTracker,
+                                carSystemBarElementInitializer, mSystemBarConfigs,
+                                mButtonRoleHolderController, mButtonSelectionStateController,
+                                () -> mCameraPrivacyChipViewController,
+                                () -> mMicPrivacyChipViewController, mOverlayVisibilityMediator,
+                                side, view));
+                    }
+                };
+        Map<@SystemBarSide Integer, CarSystemBarViewControllerFactory> factoriesMap =
+                new HashMap<>();
+        factoriesMap.put(LEFT, carSystemBarViewControllerFactory);
+        factoriesMap.put(TOP, carSystemBarViewControllerFactory);
+        factoriesMap.put(RIGHT, carSystemBarViewControllerFactory);
+        factoriesMap.put(BOTTOM, carSystemBarViewControllerFactory);
+        mCarSystemBarViewFactory =
+                new CarSystemBarViewFactoryImpl(mSpiedContext, factoriesMap, mSystemBarConfigs);
 
         mRegisterStatusBarResult = new RegisterStatusBarResult(new ArrayMap<>(), 0, 0,
                 new AppearanceRegion[0], 0, 0, false, 0, false, 0, 0, "", 0,
@@ -191,65 +242,30 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     }
 
     private void initCarSystemBar() {
-        SystemBarConfigs systemBarConfigs = new SystemBarConfigs(mTestableResources.getResources());
-        FakeDisplayTracker displayTracker = new FakeDisplayTracker(mContext);
+        FakeDisplayTracker displayTracker = new FakeDisplayTracker(mSpiedContext);
         FakeExecutor executor = new FakeExecutor(new FakeSystemClock());
 
         mCarSystemBarController = new CarSystemBarControllerImpl(mSpiedContext,
                 mUserTracker,
                 mCarSystemBarViewFactory,
-                mButtonSelectionStateController,
-                () -> mMicPrivacyChipViewController,
-                () -> mCameraPrivacyChipViewController,
-                mButtonRoleHolderController,
-                systemBarConfigs,
-                () -> mPanelControllerBuilder,
+                mSystemBarConfigs,
                 mLightBarController,
                 mStatusBarIconController,
                 mWindowManager,
                 mDeviceProvisionedController,
-                new CommandQueue(mContext, displayTracker),
+                new CommandQueue(mSpiedContext, displayTracker),
                 mAutoHideController,
                 mButtonSelectionStateListener,
                 executor,
                 mBarService,
                 () -> mKeyguardStateController,
                 () -> mIconPolicy,
-                mHvacController,
                 mConfigurationController,
                 mCarSystemBarRestartTracker,
                 displayTracker,
                 null);
     }
 
-    @Test
-    public void testRemoveAll_callsButtonRoleHolderControllerRemoveAll() {
-        mCarSystemBarController.init();
-
-        mCarSystemBarController.removeAll();
-
-        verify(mButtonRoleHolderController).removeAll();
-    }
-
-    @Test
-    public void testRemoveAll_callsButtonSelectionStateControllerRemoveAll() {
-        mCarSystemBarController.init();
-
-        mCarSystemBarController.removeAll();
-
-        verify(mButtonSelectionStateController).removeAll();
-    }
-
-    @Test
-    public void testRemoveAll_callsPrivacyChipViewControllerRemoveAll() {
-        mCarSystemBarController.init();
-
-        mCarSystemBarController.removeAll();
-
-        verify(mMicPrivacyChipViewController).removeAll();
-        verify(mCameraPrivacyChipViewController).removeAll();
-    }
-
     @Test
     public void testGetTopWindow_topDisabled_returnsNull() {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, false);
@@ -391,7 +407,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.init();
 
         ViewGroup window = mCarSystemBarController.getBarWindow(TOP);
-        mCarSystemBarController.setTopWindowVisibility(View.VISIBLE);
+        mCarSystemBarController.setWindowVisibility(window, View.VISIBLE);
 
         assertThat(window.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -402,7 +418,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.init();
 
         ViewGroup window = mCarSystemBarController.getBarWindow(TOP);
-        mCarSystemBarController.setTopWindowVisibility(View.GONE);
+        mCarSystemBarController.setWindowVisibility(window, View.GONE);
 
         assertThat(window.getVisibility()).isEqualTo(View.GONE);
     }
@@ -413,7 +429,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.init();
 
         ViewGroup window = mCarSystemBarController.getBarWindow(BOTTOM);
-        mCarSystemBarController.setBottomWindowVisibility(View.VISIBLE);
+        mCarSystemBarController.setWindowVisibility(window, View.VISIBLE);
 
         assertThat(window.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -424,7 +440,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.init();
 
         ViewGroup window = mCarSystemBarController.getBarWindow(BOTTOM);
-        mCarSystemBarController.setBottomWindowVisibility(View.GONE);
+        mCarSystemBarController.setWindowVisibility(window, View.GONE);
 
         assertThat(window.getVisibility()).isEqualTo(View.GONE);
     }
@@ -436,7 +452,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.init();
 
         ViewGroup window = mCarSystemBarController.getBarWindow(LEFT);
-        mCarSystemBarController.setLeftWindowVisibility(View.VISIBLE);
+        mCarSystemBarController.setWindowVisibility(window, View.VISIBLE);
 
         assertThat(window.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -448,7 +464,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.init();
 
         ViewGroup window = mCarSystemBarController.getBarWindow(LEFT);
-        mCarSystemBarController.setLeftWindowVisibility(View.GONE);
+        mCarSystemBarController.setWindowVisibility(window, View.GONE);
 
         assertThat(window.getVisibility()).isEqualTo(View.GONE);
     }
@@ -459,7 +475,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.init();
 
         ViewGroup window = mCarSystemBarController.getBarWindow(RIGHT);
-        mCarSystemBarController.setRightWindowVisibility(View.VISIBLE);
+        mCarSystemBarController.setWindowVisibility(window, View.VISIBLE);
 
         assertThat(window.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -470,7 +486,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.init();
 
         ViewGroup window = mCarSystemBarController.getBarWindow(RIGHT);
-        mCarSystemBarController.setRightWindowVisibility(View.GONE);
+        mCarSystemBarController.setWindowVisibility(window, View.GONE);
 
         assertThat(window.getVisibility()).isEqualTo(View.GONE);
     }
@@ -480,101 +496,50 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        Set<View.OnTouchListener> controllers = bottomBar.getStatusBarWindowTouchListeners();
-        assertThat(controllers).isNotNull();
-        assertThat(controllers.size()).isEqualTo(0);
-        mCarSystemBarController.registerBottomBarTouchListener(mock(View.OnTouchListener.class));
-        controllers = bottomBar.getStatusBarWindowTouchListeners();
+        View.OnTouchListener mockOnTouchListener = mock(View.OnTouchListener.class);
+        Set<View.OnTouchListener> listeners = new ArraySet<>();
+        listeners.add(mockOnTouchListener);
+        mCarSystemBarController.registerBarTouchListener(BOTTOM, mockOnTouchListener);
 
-        assertThat(controllers).isNotNull();
-        assertThat(controllers.size()).isEqualTo(1);
-    }
+        ArgumentCaptor<Set<View.OnTouchListener>> captor = ArgumentCaptor.forClass(Set.class);
+        // called 3 times - once for init, once for test getBarViewController call, and once for
+        // test registerBarTouchListener call
+        verify(bottomBar, times(3)).setSystemBarTouchListeners(captor.capture());
 
-    @Test
-    public void testRegisterBottomBarTouchListener_registerFirst_registrationSuccessful() {
-        mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBarController.init();
-
-        mCarSystemBarController.registerBottomBarTouchListener(mock(View.OnTouchListener.class));
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
-                /* isSetUp= */ true);
-        Set<View.OnTouchListener> controllers = bottomBar.getStatusBarWindowTouchListeners();
-
-        assertThat(controllers).isNotNull();
-        assertThat(controllers.size()).isEqualTo(1);
-    }
-
-    @Test
-    public void testRegisterNotificationController_createViewFirst_registrationSuccessful() {
-        mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBarController.init();
-
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
-                /* isSetUp= */ true);
-        NotificationsShadeController controller =
-                bottomBar.getNotificationsPanelController();
-        assertThat(controller).isNull();
-        mCarSystemBarController.registerNotificationController(
-                mock(NotificationsShadeController.class));
-        controller = bottomBar.getNotificationsPanelController();
-
-        assertThat(controller).isNotNull();
-    }
-
-    @Test
-    public void testRegisterNotificationController_registerFirst_registrationSuccessful() {
-        mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBarController.init();
-
-        mCarSystemBarController.registerNotificationController(
-                mock(NotificationsShadeController.class));
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
-                /* isSetUp= */ true);
-        NotificationsShadeController controller =
-                bottomBar.getNotificationsPanelController();
-
-        assertThat(controller).isNotNull();
+        List<Set<View.OnTouchListener>> allValues = captor.getAllValues();
+        assertThat(allValues.contains(listeners));
     }
 
     @Test
-    public void testRegisterHvacController_createViewFirst_registrationSuccessful() {
+    public void testRegisterBottomBarTouchListener_registerFirst_registrationSuccessful() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        View.OnTouchListener mockOnTouchListener = mock(View.OnTouchListener.class);
+        Set<View.OnTouchListener> listeners = new ArraySet<>();
+        listeners.add(mockOnTouchListener);
+        mCarSystemBarController.registerBarTouchListener(BOTTOM, mockOnTouchListener);
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        HvacPanelController controller = bottomBar.getHvacPanelController();
-        assertThat(controller).isNull();
-        mCarSystemBarController.registerHvacPanelController(
-                mock(HvacPanelController.class));
-        controller = bottomBar.getHvacPanelController();
-
-        assertThat(controller).isNotNull();
-    }
-
-    @Test
-    public void testRegisterHvacController_registerFirst_registrationSuccessful() {
-        mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBarController.init();
 
-        mCarSystemBarController.registerHvacPanelController(
-                mock(HvacPanelController.class));
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
-                /* isSetUp= */ true);
-        HvacPanelController controller = bottomBar.getHvacPanelController();
+        ArgumentCaptor<Set<View.OnTouchListener>> captor = ArgumentCaptor.forClass(Set.class);
+        // called 3 times - once for init, once for test registerBarTouchListener
+        // call, and once for test getBarViewController call
+        verify(bottomBar, times(3)).setSystemBarTouchListeners(captor.capture());
 
-        assertThat(controller).isNotNull();
+        List<Set<View.OnTouchListener>> allValues = captor.getAllValues();
+        assertThat(allValues.contains(listeners));
     }
 
     @Test
     public void testShowAllNavigationButtons_bottomEnabled_bottomNavigationButtonsVisible() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View bottomNavButtons = bottomBar.findViewById(R.id.nav_buttons);
+        View bottomNavButtons = bottomBar.getView().findViewById(R.id.nav_buttons);
 
         mCarSystemBarController.showAllNavigationButtons();
 
@@ -585,9 +550,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testShowAllNavigationButtons_bottomEnabled_bottomKeyguardButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View bottomKeyguardButtons = bottomBar.findViewById(R.id.lock_screen_nav_buttons);
+        View bottomKeyguardButtons = bottomBar.getView().findViewById(R.id.lock_screen_nav_buttons);
 
         mCarSystemBarController.showAllNavigationButtons();
 
@@ -598,9 +563,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testShowAllNavigationButtons_bottomEnabled_bottomOcclusionButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View occlusionButtons = bottomBar.findViewById(R.id.occlusion_buttons);
+        View occlusionButtons = bottomBar.getView().findViewById(R.id.occlusion_buttons);
 
         mCarSystemBarController.showAllNavigationButtons();
 
@@ -611,9 +576,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testShowAllKeyguardButtons_bottomEnabled_bottomKeyguardButtonsVisible() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View bottomKeyguardButtons = bottomBar.findViewById(R.id.lock_screen_nav_buttons);
+        View bottomKeyguardButtons = bottomBar.getView().findViewById(R.id.lock_screen_nav_buttons);
 
         mCarSystemBarController.showAllKeyguardButtons();
 
@@ -624,9 +589,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testShowAllKeyguardButtons_bottomEnabled_bottomNavigationButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View bottomNavButtons = bottomBar.findViewById(R.id.nav_buttons);
+        View bottomNavButtons = bottomBar.getView().findViewById(R.id.nav_buttons);
 
         mCarSystemBarController.showAllKeyguardButtons();
 
@@ -637,9 +602,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testShowAllKeyguardButtons_bottomEnabled_bottomOcclusionButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View occlusionButtons = bottomBar.findViewById(R.id.occlusion_buttons);
+        View occlusionButtons = bottomBar.getView().findViewById(R.id.occlusion_buttons);
 
         mCarSystemBarController.showAllKeyguardButtons();
 
@@ -650,9 +615,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testShowOcclusionButtons_bottomEnabled_bottomOcclusionButtonsVisible() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View occlusionButtons = bottomBar.findViewById(R.id.occlusion_buttons);
+        View occlusionButtons = bottomBar.getView().findViewById(R.id.occlusion_buttons);
 
         mCarSystemBarController.showAllOcclusionButtons();
 
@@ -663,9 +628,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testShowOcclusionButtons_bottomEnabled_bottomNavigationButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View bottomNavButtons = bottomBar.findViewById(R.id.nav_buttons);
+        View bottomNavButtons = bottomBar.getView().findViewById(R.id.nav_buttons);
 
         mCarSystemBarController.showAllOcclusionButtons();
 
@@ -676,41 +641,15 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testShowOcclusionButtons_bottomEnabled_bottomKeyguardButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View keyguardButtons = bottomBar.findViewById(R.id.lock_screen_nav_buttons);
+        View keyguardButtons = bottomBar.getView().findViewById(R.id.lock_screen_nav_buttons);
 
         mCarSystemBarController.showAllOcclusionButtons();
 
         assertThat(keyguardButtons.getVisibility()).isEqualTo(View.GONE);
     }
 
-    @Test
-    public void testToggleAllNotificationsUnseenIndicator_bottomEnabled_hasUnseen_setCorrectly() {
-        enableSystemBarWithNotificationButton();
-        mCarSystemBarController.init();
-        CarSystemBarButton notifications = getNotificationCarSystemBarButton();
-
-        boolean hasUnseen = true;
-        mCarSystemBarController.toggleAllNotificationsUnseenIndicator(/* isSetUp= */ true,
-                hasUnseen);
-
-        assertThat(notifications.getUnseen()).isTrue();
-    }
-
-    @Test
-    public void testToggleAllNotificationsUnseenIndicator_bottomEnabled_noUnseen_setCorrectly() {
-        enableSystemBarWithNotificationButton();
-        mCarSystemBarController.init();
-        CarSystemBarButton notifications = getNotificationCarSystemBarButton();
-
-        boolean hasUnseen = false;
-        mCarSystemBarController.toggleAllNotificationsUnseenIndicator(/* isSetUp= */ true,
-                hasUnseen);
-
-        assertThat(notifications.getUnseen()).isFalse();
-    }
-
     @Test
     public void testSetSystemBarStates_stateUpdated() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
@@ -733,66 +672,6 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         assertThat(mCarSystemBarController.getStatusBarState2()).isEqualTo(DISABLE2_QUICK_SETTINGS);
     }
 
-    @Test
-    public void testRefreshSystemBar_homeDisabled() {
-        mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
-                /* isSetUp= */ true);
-        clearSystemBarStates();
-        CarSystemBarButton button = bottomBar.findViewById(R.id.home);
-        assertThat(button.getDisabled()).isFalse();
-
-        mCarSystemBarController.setSystemBarStates(DISABLE_HOME, /* state2= */ 0);
-
-        assertThat(button.getDisabled()).isTrue();
-    }
-
-    @Test
-    public void testRefreshSystemBar_phoneNavDisabled() {
-        assumeFalse("Phone nav button is removed when Dock is enabled", Flags.dockFeature());
-
-        mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
-                /* isSetUp= */ true);
-        clearSystemBarStates();
-        CarSystemBarButton button = bottomBar.findViewById(R.id.phone_nav);
-        assertThat(button.getDisabled()).isFalse();
-
-        setLockTaskModeLocked(/* locked= */true);
-
-        assertThat(button.getDisabled()).isTrue();
-    }
-
-    @Test
-    public void testRefreshSystemBar_appGridisabled() {
-        mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBarController.init();
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
-                /* isSetUp= */ true);
-        clearSystemBarStates();
-        CarSystemBarButton button = bottomBar.findViewById(R.id.grid_nav);
-        assertThat(button.getDisabled()).isFalse();
-
-        mCarSystemBarController.setSystemBarStates(DISABLE_HOME, /* state2= */ 0);
-
-        assertThat(button.getDisabled()).isTrue();
-    }
-
-    @Test
-    public void testRefreshSystemBar_notificationDisabled() {
-        enableSystemBarWithNotificationButton();
-        mCarSystemBarController.init();
-        clearSystemBarStates();
-        CarSystemBarButton button = getNotificationCarSystemBarButton();
-        assertThat(button.getDisabled()).isFalse();
-
-        mCarSystemBarController.setSystemBarStates(DISABLE_NOTIFICATION_ICONS, /* state2= */ 0);
-
-        assertThat(button.getDisabled()).isTrue();
-    }
-
     @Test
     public void cacheAndHideFocus_doesntCallHideFocus_if_focusParkingViewIsFocused() {
         mCarSystemBarController.init();
@@ -800,7 +679,8 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         View mockContainerView = mock(View.class);
         when(mockContainerView.findFocus()).thenReturn(mockFocusParkingView);
 
-        int returnFocusedViewId = mCarSystemBarController.cacheAndHideFocus(mockContainerView);
+        int returnFocusedViewId =
+                CarSystemBarViewControllerImpl.cacheAndHideFocus(mockContainerView);
 
         assertThat(returnFocusedViewId).isEqualTo(View.NO_ID);
     }
@@ -812,10 +692,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, /* value= */ true);
         mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View driverHomeButton = bottomBar.findViewById(R.id.home);
-        View passengerHomeButton = bottomBar.findViewById(R.id.passenger_home);
+        View driverHomeButton = bottomBar.getView().findViewById(R.id.home);
+        View passengerHomeButton = bottomBar.getView().findViewById(R.id.passenger_home);
 
         assertThat(driverHomeButton.getVisibility()).isEqualTo(View.VISIBLE);
         assertThat(passengerHomeButton.getVisibility()).isEqualTo(View.GONE);
@@ -828,10 +708,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+        CarSystemBarViewController bottomBar = mCarSystemBarController.getBarViewController(BOTTOM,
                 /* isSetUp= */ true);
-        View driverHomeButton = bottomBar.findViewById(R.id.home);
-        View passengerHomeButton = bottomBar.findViewById(R.id.passenger_home);
+        View driverHomeButton = bottomBar.getView().findViewById(R.id.home);
+        View passengerHomeButton = bottomBar.getView().findViewById(R.id.passenger_home);
 
         assertThat(driverHomeButton.getVisibility()).isEqualTo(View.GONE);
         assertThat(passengerHomeButton.getVisibility()).isEqualTo(View.VISIBLE);
@@ -851,17 +731,6 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         mCarSystemBarController.setSystemBarStates(/* state= */ 0, /* state2= */ 0);
     }
 
-    private void setupPanelControllerBuilderMocks() {
-        when(mPanelControllerBuilder.setXOffset(anyInt())).thenReturn(mPanelControllerBuilder);
-        when(mPanelControllerBuilder.setYOffset(anyInt())).thenReturn(mPanelControllerBuilder);
-        when(mPanelControllerBuilder.setGravity(anyInt())).thenReturn(mPanelControllerBuilder);
-        when(mPanelControllerBuilder.setDisabledWhileDriving(anyBoolean())).thenReturn(
-                mPanelControllerBuilder);
-        when(mPanelControllerBuilder.setShowAsDropDown(anyBoolean())).thenReturn(
-                mPanelControllerBuilder);
-        when(mPanelControllerBuilder.build(any(), anyInt(), anyInt())).thenReturn(mPanelController);
-    }
-
     private void enableSystemBarWithNotificationButton() {
         if (Flags.dockFeature()) {
             mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
@@ -869,15 +738,4 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
             mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         }
     }
-
-    private CarSystemBarButton getNotificationCarSystemBarButton() {
-        if (Flags.dockFeature()) {
-            CarSystemBarView topBar = mCarSystemBarController.getBarView(TOP, /* isSetUp= */ true);
-            return topBar.findViewById(R.id.notifications);
-        } else {
-            CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
-                    /* isSetUp= */ true);
-            return bottomBar.findViewById(R.id.notifications);
-        }
-    }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
index 29eaecfb..bc3920b9 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
@@ -30,6 +30,7 @@ import static com.google.common.truth.Truth.assertThat;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
@@ -38,7 +39,6 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.app.ActivityManager;
-import android.content.Context;
 import android.content.res.Configuration;
 import android.graphics.Rect;
 import android.os.RemoteException;
@@ -58,9 +58,9 @@ import com.android.internal.statusbar.RegisterStatusBarResult;
 import com.android.internal.view.AppearanceRegion;
 import com.android.systemui.R;
 import com.android.systemui.SysuiTestCase;
+import com.android.systemui.SysuiTestableContext;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.hvac.HvacController;
 import com.android.systemui.car.statusicon.StatusIconPanelViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
 import com.android.systemui.plugins.DarkIconDispatcher;
@@ -96,7 +96,7 @@ import org.mockito.MockitoAnnotations;
 public class CarSystemBarTest extends SysuiTestCase {
 
     private TestableResources mTestableResources;
-    private Context mSpiedContext;
+    private SysuiTestableContext mSpiedContext;
     private FakeExecutor mExecutor;
     private CarSystemBarControllerImpl mCarSystemBarController;
 
@@ -105,16 +105,6 @@ public class CarSystemBarTest extends SysuiTestCase {
     @Mock
     private ActivityManager mActivityManager;
     @Mock
-    private ButtonSelectionStateController mButtonSelectionStateController;
-    @Mock
-    private ButtonRoleHolderController mButtonRoleHolderController;
-    @Mock
-    private MicPrivacyChipViewController mMicPrivacyChipViewController;
-    @Mock
-    private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
-    @Mock
-    private StatusIconPanelViewController.Builder mPanelControllerBuilder;
-    @Mock
     private StatusIconPanelViewController mPanelController;
     @Mock
     private CarSystemBarElementInitializer mCarSystemBarElementInitializer;
@@ -143,27 +133,25 @@ public class CarSystemBarTest extends SysuiTestCase {
     @Mock
     private StatusBarSignalPolicy mSignalPolicy;
     @Mock
-    private HvacController mHvacController;
-    @Mock
     private ConfigurationController mConfigurationController;
     @Mock
     private CarSystemBarRestartTracker mCarSystemBarRestartTracker;
     @Mock
     private CarSystemBarViewFactory mCarSystemBarViewFactory;
     @Mock
-    private CarSystemBarView mTopBar;
+    private CarSystemBarViewController mTopBar;
     @Mock
     private ViewGroup mTopWindow;
     @Mock
-    private CarSystemBarView mRigthBar;
+    private CarSystemBarViewController mRigthBar;
     @Mock
     private ViewGroup mRightWindow;
     @Mock
-    private CarSystemBarView mLeftBar;
+    private CarSystemBarViewController mLeftBar;
     @Mock
     private ViewGroup mLeftWindow;
     @Mock
-    private CarSystemBarView mBottomBar;
+    private CarSystemBarViewController mBottomBar;
     @Mock
     private ViewGroup mBottomWindow;
 
@@ -179,17 +167,27 @@ public class CarSystemBarTest extends SysuiTestCase {
         mExecutor = new FakeExecutor(new FakeSystemClock());
         mUiBgExecutor = new FakeExecutor(new FakeSystemClock());
         mSpiedContext = spy(mContext);
-        when(mSpiedContext.getSystemService(ActivityManager.class)).thenReturn(mActivityManager);
+        mSpiedContext.addMockSystemService(ActivityManager.class, mActivityManager);
+        mSpiedContext.addMockSystemService(WindowManager.class, mWindowManager);
+        when(mSpiedContext.createWindowContext(anyInt(), any())).thenReturn(mSpiedContext);
         when(mStatusBarIconController.getTransitionsController()).thenReturn(
                 mLightBarTransitionsController);
-        when(mCarSystemBarViewFactory.getTopBar(anyBoolean())).thenReturn(mTopBar);
-        when(mCarSystemBarViewFactory.getTopWindow()).thenReturn(mTopWindow);
-        when(mCarSystemBarViewFactory.getRightBar(anyBoolean())).thenReturn(mRigthBar);
-        when(mCarSystemBarViewFactory.getRightWindow()).thenReturn(mRightWindow);
-        when(mCarSystemBarViewFactory.getBottomBar(anyBoolean())).thenReturn(mBottomBar);
-        when(mCarSystemBarViewFactory.getBottomWindow()).thenReturn(mBottomWindow);
-        when(mCarSystemBarViewFactory.getLeftBar(anyBoolean())).thenReturn(mLeftBar);
-        when(mCarSystemBarViewFactory.getLeftWindow()).thenReturn(mLeftWindow);
+        when(mTopBar.getView()).thenReturn(mock(CarSystemBarView.class));
+        when(mCarSystemBarViewFactory.getSystemBarViewController(eq(TOP), anyBoolean()))
+                .thenReturn(mTopBar);
+        when(mCarSystemBarViewFactory.getSystemBarWindow(eq(TOP))).thenReturn(mTopWindow);
+        when(mRigthBar.getView()).thenReturn(mock(CarSystemBarView.class));
+        when(mCarSystemBarViewFactory.getSystemBarViewController(eq(RIGHT), anyBoolean()))
+                .thenReturn(mRigthBar);
+        when(mCarSystemBarViewFactory.getSystemBarWindow(eq(RIGHT))).thenReturn(mRightWindow);
+        when(mBottomBar.getView()).thenReturn(mock(CarSystemBarView.class));
+        when(mCarSystemBarViewFactory.getSystemBarViewController(eq(BOTTOM), anyBoolean()))
+                .thenReturn(mBottomBar);
+        when(mCarSystemBarViewFactory.getSystemBarWindow(eq(BOTTOM))).thenReturn(mBottomWindow);
+        when(mLeftBar.getView()).thenReturn(mock(CarSystemBarView.class));
+        when(mCarSystemBarViewFactory.getSystemBarViewController(eq(LEFT), anyBoolean()))
+                .thenReturn(mLeftBar);
+        when(mCarSystemBarViewFactory.getSystemBarWindow(eq(LEFT))).thenReturn(mLeftWindow);
         mAppearanceRegions = new AppearanceRegion[]{
                 new AppearanceRegion(APPEARANCE_LIGHT_STATUS_BARS, new Rect())
         };
@@ -218,23 +216,17 @@ public class CarSystemBarTest extends SysuiTestCase {
         mDependency.injectMockDependency(DarkIconDispatcher.class);
         mDependency.injectMockDependency(StatusBarIconController.class);
 
-        setupPanelControllerBuilderMocks();
-
         initCarSystemBar();
     }
 
     private void initCarSystemBar() {
-        SystemBarConfigs systemBarConfigs = new SystemBarConfigs(mTestableResources.getResources());
+        SystemBarConfigs systemBarConfigs =
+                new SystemBarConfigsImpl(mSpiedContext, mTestableResources.getResources());
         FakeDisplayTracker displayTracker = new FakeDisplayTracker(mContext);
         mCarSystemBarController = spy(new CarSystemBarControllerImpl(mSpiedContext,
                 mUserTracker,
                 mCarSystemBarViewFactory,
-                mButtonSelectionStateController,
-                () -> mMicPrivacyChipViewController,
-                () -> mCameraPrivacyChipViewController,
-                mButtonRoleHolderController,
                 systemBarConfigs,
-                () -> mPanelControllerBuilder,
                 mLightBarController,
                 mStatusBarIconController,
                 mWindowManager,
@@ -246,7 +238,6 @@ public class CarSystemBarTest extends SysuiTestCase {
                 mBarService,
                 () -> mKeyguardStateController,
                 () -> mIconPolicy,
-                mHvacController,
                 mConfigurationController,
                 mCarSystemBarRestartTracker,
                 displayTracker,
@@ -540,14 +531,14 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, false);
         mTestableResources.addOverride(R.bool.config_enableLeftSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableRightSystemBar, true);
-        mSystemBarConfigs = new SystemBarConfigs(mTestableResources.getResources());
+        mSystemBarConfigs =
+                new SystemBarConfigsImpl(mSpiedContext, mTestableResources.getResources());
         when(mCarSystemBarController.getBarWindow(TOP)).thenReturn(mock(ViewGroup.class));
         when(mCarSystemBarController.getBarWindow(BOTTOM)).thenReturn(null);
         when(mCarSystemBarController.getBarWindow(LEFT)).thenReturn(mock(ViewGroup.class));
         when(mCarSystemBarController.getBarWindow(RIGHT)).thenReturn(mock(ViewGroup.class));
         mCarSystemBarController.restartSystemBars();
 
-        verify(mCarSystemBarController, times(1)).removeAll();
         verify(mCarSystemBarController, times(2)).resetSystemBarConfigs();
         assertThat(mCarSystemBarController.getBarWindow(TOP)).isNotNull();
         assertThat(mCarSystemBarController.getBarWindow(BOTTOM)).isNull();
@@ -559,15 +550,4 @@ public class CarSystemBarTest extends SysuiTestCase {
         mExecutor.advanceClockToLast();
         mExecutor.runAllReady();
     }
-
-    private void setupPanelControllerBuilderMocks() {
-        when(mPanelControllerBuilder.setXOffset(anyInt())).thenReturn(mPanelControllerBuilder);
-        when(mPanelControllerBuilder.setYOffset(anyInt())).thenReturn(mPanelControllerBuilder);
-        when(mPanelControllerBuilder.setGravity(anyInt())).thenReturn(mPanelControllerBuilder);
-        when(mPanelControllerBuilder.setDisabledWhileDriving(anyBoolean())).thenReturn(
-                mPanelControllerBuilder);
-        when(mPanelControllerBuilder.setShowAsDropDown(anyBoolean())).thenReturn(
-                mPanelControllerBuilder);
-        when(mPanelControllerBuilder.build(any(), anyInt(), anyInt())).thenReturn(mPanelController);
-    }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
index e4258422..0046472c 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
@@ -31,7 +31,10 @@ import androidx.test.filters.SmallTest;
 import com.android.systemui.R;
 import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.notification.NotificationsShadeController;
+import com.android.systemui.car.notification.NotificationPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
+import com.android.systemui.car.window.OverlayVisibilityMediator;
+import com.android.systemui.settings.UserTracker;
 
 import org.junit.After;
 import org.junit.Before;
@@ -51,11 +54,26 @@ public class CarSystemBarViewTest extends SysuiTestCase {
     private CarSystemBarView mNavBarView;
 
     @Mock
-    private NotificationsShadeController mNotificationsShadeController;
+    private NotificationPanelViewController mNotificationPanelViewController;
 
     @Mock
     private View.OnTouchListener mNavBarTouchListener;
 
+    @Mock
+    private UserTracker mUserTracker;
+    @Mock
+    private CarSystemBarElementInitializer mCarSystemBarElementInitializer;
+    @Mock
+    private ButtonRoleHolderController mButtonRoleHolderController;
+    @Mock
+    private ButtonSelectionStateController mButtonSelectionStateController;
+    @Mock
+    private MicPrivacyChipViewController mMicPrivacyChipViewController;
+    @Mock
+    private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
+    @Mock
+    private OverlayVisibilityMediator mOverlayVisibilityMediator;
+
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
@@ -73,14 +91,17 @@ public class CarSystemBarViewTest extends SysuiTestCase {
     public void dispatchTouch_shadeOpen_flagOff_doesNotConsumeTouch() {
         getContext().getOrCreateTestableResources().addOverride(
                 R.bool.config_consumeSystemBarTouchWhenNotificationPanelOpen, false);
-        when(mNotificationsShadeController.isNotificationPanelOpen()).thenReturn(true);
+        when(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController())
+                .thenReturn(mNotificationPanelViewController);
+        when(mNotificationPanelViewController.shouldPanelConsumeSystemBarTouch())
+                .thenReturn(true);
         mNavBarView = (CarSystemBarView) LayoutInflater.from(getContext()).inflate(
                 R.layout.car_system_bar_view_test, /* root= */ null);
-        mNavBarView.setNotificationsPanelController(mNotificationsShadeController);
-        mNavBarView.setStatusBarWindowTouchListeners(
+        CarSystemBarViewControllerImpl controller = getSystemBarViewController(mNavBarView);
+        controller.setSystemBarTouchListeners(
                 Collections.singleton(mNavBarTouchListener));
 
-        boolean consume = mNavBarView.onInterceptTouchEvent(
+        boolean consume = controller.onInterceptTouchEvent(
                 MotionEvent.obtain(/* downTime= */ 200, /* eventTime= */ 300,
                         MotionEvent.ACTION_MOVE, mNavBarView.getX(),
                         mNavBarView.getY(), /* metaState= */ 0));
@@ -95,18 +116,37 @@ public class CarSystemBarViewTest extends SysuiTestCase {
         // Prevent the test from failing due to buttons on the system bar not being draggable.
         getContext().getOrCreateTestableResources().addOverride(
                 R.bool.config_systemBarButtonsDraggable, true);
-        when(mNotificationsShadeController.isNotificationPanelOpen()).thenReturn(true);
+        when(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController())
+                .thenReturn(mNotificationPanelViewController);
+        when(mNotificationPanelViewController.shouldPanelConsumeSystemBarTouch())
+                .thenReturn(true);
         mNavBarView = (CarSystemBarView) LayoutInflater.from(getContext()).inflate(
                 R.layout.car_system_bar_view_test, /* root= */ null);
-        mNavBarView.setNotificationsPanelController(mNotificationsShadeController);
-        mNavBarView.setStatusBarWindowTouchListeners(
+        CarSystemBarViewControllerImpl controller = getSystemBarViewController(mNavBarView);
+        controller.setSystemBarTouchListeners(
                 Collections.singleton(mNavBarTouchListener));
 
-        boolean consume = mNavBarView.onInterceptTouchEvent(
+        boolean consume = controller.onInterceptTouchEvent(
                 MotionEvent.obtain(/* downTime= */ 200, /* eventTime= */ 300,
                         MotionEvent.ACTION_MOVE, mNavBarView.getX(),
                         mNavBarView.getY(), /* metaState= */ 0));
 
         assertThat(consume).isTrue();
     }
+
+    private CarSystemBarViewControllerImpl getSystemBarViewController(CarSystemBarView view) {
+        SystemBarConfigs systemBarConfigs = new SystemBarConfigsImpl(getContext(),
+                getContext().getOrCreateTestableResources().getResources());
+        return new CarSystemBarViewControllerImpl(getContext(),
+                mUserTracker,
+                mCarSystemBarElementInitializer,
+                systemBarConfigs,
+                mButtonRoleHolderController,
+                mButtonSelectionStateController,
+                () -> mCameraPrivacyChipViewController,
+                () -> mMicPrivacyChipViewController,
+                mOverlayVisibilityMediator,
+                0,
+                view);
+    }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java b/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
index 9f5220a0..58647657 100644
--- a/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
+++ b/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
@@ -42,7 +42,6 @@ import androidx.test.filters.SmallTest;
 import com.android.systemui.R;
 import com.android.systemui.SysuiTestCase;
 import com.android.systemui.broadcast.BroadcastDispatcher;
-import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.notification.NotificationPanelViewController;
 import com.android.systemui.car.notification.NotificationPanelViewMediator;
@@ -68,7 +67,7 @@ import java.util.Map;
 public class SystemBarConfigsTest extends SysuiTestCase {
     private static final int SYSTEM_BAR_GIRTH = 100;
 
-    private SystemBarConfigs mSystemBarConfigs;
+    private SystemBarConfigsImpl mSystemBarConfigs;
     @Mock
     private Resources mResources;
 
@@ -80,7 +79,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
 
     @Test
     public void onInit_allSystemBarsEnabled_eachHasUniqueBarTypes_doesNotThrowException() {
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
     }
 
     @Test(expected = RuntimeException.class)
@@ -88,12 +87,12 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getInteger(R.integer.config_topSystemBarType)).thenReturn(0);
         when(mResources.getInteger(R.integer.config_bottomSystemBarType)).thenReturn(0);
 
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
     }
 
     @Test
     public void onInit_allSystemBarsEnabled_systemBarTypesSortedByZOrder() {
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
         List<Integer> actualOrder = mSystemBarConfigs.getSystemBarSidesByZOrder();
         List<Integer> expectedOrder = new ArrayList<>();
         expectedOrder.add(LEFT);
@@ -109,7 +108,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getInteger(R.integer.config_topSystemBarZOrder)).thenReturn(33);
         when(mResources.getInteger(R.integer.config_leftSystemBarZOrder)).thenReturn(33);
 
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
     }
 
     @Test(expected = RuntimeException.class)
@@ -119,7 +118,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
                 com.android.internal.R.bool.config_hideNavBarForKeyboard)).thenReturn(
                 true);
 
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
     }
 
     @Test
@@ -128,7 +127,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getString(R.string.config_notificationPanelViewMediator)).thenReturn(
                 TestTopNotificationPanelViewMediator.class.getName());
 
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
     }
 
     @Test(expected = RuntimeException.class)
@@ -137,7 +136,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getString(R.string.config_notificationPanelViewMediator)).thenReturn(
                 TestTopNotificationPanelViewMediator.class.getName());
 
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
     }
 
     @Test
@@ -146,12 +145,12 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getString(R.string.config_notificationPanelViewMediator)).thenReturn(
                 NotificationPanelViewMediator.class.getName());
 
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
     }
 
     @Test
     public void getTopSystemBarLayoutParams_topBarEnabled_returnsTopSystemBarLayoutParams() {
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
                 TOP);
 
@@ -160,7 +159,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
 
     @Test
     public void getTopSystemBarLayoutParams_containsLayoutInDisplayCutoutMode() {
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
                 TOP);
 
@@ -171,7 +170,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
     @Test
     public void getTopSystemBarLayoutParams_topBarNotEnabled_returnsNull() {
         when(mResources.getBoolean(R.bool.config_enableTopSystemBar)).thenReturn(false);
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
                 TOP);
 
@@ -181,7 +180,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
     @Test
     public void getTopSystemBarHideForKeyboard_hideBarForKeyboard_returnsTrue() {
         when(mResources.getBoolean(R.bool.config_hideTopSystemBarForKeyboard)).thenReturn(true);
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
 
         boolean hideKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(TOP);
 
@@ -191,7 +190,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
     @Test
     public void getTopSystemBarHideForKeyboard_topBarNotEnabled_returnsFalse() {
         when(mResources.getBoolean(R.bool.config_enableTopSystemBar)).thenReturn(false);
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
 
         boolean hideKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(TOP);
 
@@ -201,8 +200,8 @@ public class SystemBarConfigsTest extends SysuiTestCase {
     @Test
     public void topSystemBarHasHigherZOrderThanHuns_topSystemBarIsSystemBarPanelType() {
         when(mResources.getInteger(R.integer.config_topSystemBarZOrder)).thenReturn(
-                SystemBarConfigs.getHunZOrder() + 1);
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+                SystemBarConfigsImpl.HUN_Z_ORDER + 1);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
                 TOP);
 
@@ -212,8 +211,8 @@ public class SystemBarConfigsTest extends SysuiTestCase {
     @Test
     public void topSystemBarHasLowerZOrderThanHuns_topSystemBarIsStatusBarAdditionalType() {
         when(mResources.getInteger(R.integer.config_topSystemBarZOrder)).thenReturn(
-                SystemBarConfigs.getHunZOrder() - 1);
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+                SystemBarConfigsImpl.HUN_Z_ORDER - 1);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
                 TOP);
 
@@ -222,7 +221,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
 
     @Test
     public void updateInsetPaddings_overlappingBarWithHigherZOrderDisappeared_removesInset() {
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
         CarSystemBarView leftBar = new CarSystemBarView(mContext, /* attrs= */ null);
         Map<Integer, Boolean> visibilities = new ArrayMap<>();
         visibilities.put(TOP, false);
@@ -238,7 +237,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
 
     @Test
     public void updateInsetPaddings_overlappingBarWithHigherZOrderReappeared_addsInset() {
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
         CarSystemBarView leftBar = new CarSystemBarView(mContext, /* attrs= */ null);
         Map<Integer, Boolean> visibilities = new ArrayMap<>();
         visibilities.put(TOP, false);
@@ -301,7 +300,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getInteger(R.integer.config_leftSystemBarZOrder)).thenReturn(8);
         when(mResources.getInteger(R.integer.config_rightSystemBarZOrder)).thenReturn(6);
 
-        mSystemBarConfigs = new SystemBarConfigs(mResources);
+        mSystemBarConfigs = new SystemBarConfigsImpl(mContext, mResources);
 
         CarSystemBarView topBar = new CarSystemBarView(mContext, /* attrs= */ null);
         CarSystemBarView bottomBar = new CarSystemBarView(mContext, /* attrs= */ null);
@@ -380,11 +379,10 @@ public class SystemBarConfigsTest extends SysuiTestCase {
                 PowerManagerHelper powerManagerHelper,
                 BroadcastDispatcher broadcastDispatcher,
                 UserTracker userTracker,
-                CarDeviceProvisionedController carDeviceProvisionedController,
                 ConfigurationController configurationController) {
             super(context, carSystemBarController, notificationPanelViewController,
                     powerManagerHelper, broadcastDispatcher, userTracker,
-                    carDeviceProvisionedController, configurationController);
+                    configurationController);
         }
     }
 }
diff --git a/tests/src/com/android/systemui/car/telecom/InCallServiceImplTest.java b/tests/src/com/android/systemui/car/telecom/InCallServiceImplTest.java
index a2625ebb..9cbc7dbf 100644
--- a/tests/src/com/android/systemui/car/telecom/InCallServiceImplTest.java
+++ b/tests/src/com/android/systemui/car/telecom/InCallServiceImplTest.java
@@ -17,6 +17,9 @@ package com.android.systemui.car.telecom;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.verify;
+
 import android.telecom.Call;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
@@ -33,6 +36,8 @@ import org.junit.runner.RunWith;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
+import java.util.List;
+
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
@@ -51,6 +56,7 @@ public class InCallServiceImplTest extends SysuiTestCase {
         mInCallServiceManager = new InCallServiceManager();
         mInCallService = new InCallServiceImpl(mInCallServiceManager);
         mCallListener = new CallListener();
+        mInCallService.addListener(mCallListener);
     }
 
     @Test
@@ -67,22 +73,37 @@ public class InCallServiceImplTest extends SysuiTestCase {
 
     @Test
     public void testOnCallAdded() {
-        mInCallService.addListener(mCallListener);
         mInCallService.onCallAdded(mMockCall);
 
+        verify(mMockCall).registerCallback(any());
         assertThat(mCallListener.mCall).isEqualTo(mMockCall);
     }
 
     @Test
     public void testOnCallRemoved() {
-        mInCallService.addListener(mCallListener);
+        mInCallService.onCallRemoved(mMockCall);
+
+        verify(mMockCall).unregisterCallback(any());
+        assertThat(mCallListener.mCall).isEqualTo(mMockCall);
+    }
+
+    @Test
+    public void testOnStateChanged() {
         mInCallService.onCallAdded(mMockCall);
 
+        verify(mMockCall).registerCallback(any());
+        assertThat(mCallListener.mCall).isEqualTo(mMockCall);
+
+        mInCallService.mCallStateChangedCallback.onStateChanged(mMockCall, Call.STATE_ACTIVE);
         assertThat(mCallListener.mCall).isEqualTo(mMockCall);
+        assertThat(mCallListener.mState).isEqualTo(Call.STATE_ACTIVE);
     }
 
     private static class CallListener implements InCallServiceImpl.InCallListener {
         public Call mCall;
+        public int mState;
+        public Call mParent;
+        public List<Call> mChildren;
 
         @Override
         public void onCallAdded(Call call) {
@@ -93,5 +114,23 @@ public class InCallServiceImplTest extends SysuiTestCase {
         public void onCallRemoved(Call call) {
             mCall = call;
         }
+
+        @Override
+        public void onStateChanged(Call call, int state) {
+            mCall = call;
+            mState = state;
+        }
+
+        @Override
+        public void onParentChanged(Call call, Call parent) {
+            mCall = call;
+            mParent = parent;
+        }
+
+        @Override
+        public void onChildrenChanged(Call call, List<Call> children) {
+            mCall = call;
+            mChildren = children;
+        }
     }
 }
diff --git a/tests/src/com/android/systemui/car/toast/CarToastUITest.java b/tests/src/com/android/systemui/car/toast/CarToastUITest.java
index cb03cac9..c779664b 100644
--- a/tests/src/com/android/systemui/car/toast/CarToastUITest.java
+++ b/tests/src/com/android/systemui/car/toast/CarToastUITest.java
@@ -96,7 +96,8 @@ public class CarToastUITest extends SysuiTestCase {
         when(mSystemUIToast.getYOffset()).thenReturn(0);
         when(mSystemUIToast.getHorizontalMargin()).thenReturn(0);
         when(mSystemUIToast.getVerticalMargin()).thenReturn(0);
-        when(mToastFactory.createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt()))
+        when(mToastFactory.createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt()))
                 .thenReturn(mSystemUIToast);
     }
 
@@ -116,8 +117,8 @@ public class CarToastUITest extends SysuiTestCase {
         mCarToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory, never()).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(),
-                anyInt());
+        verify(mToastFactory, never()).createToast(any(), any(), eq(TEXT), eq(PACKAGE_NAME),
+                anyInt(), anyInt());
     }
 
     @Test
@@ -129,7 +130,8 @@ public class CarToastUITest extends SysuiTestCase {
         mCarToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
+        verify(mToastFactory).createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
     }
 
     @Test
@@ -141,8 +143,8 @@ public class CarToastUITest extends SysuiTestCase {
         mCarToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory, never()).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(),
-                anyInt());
+        verify(mToastFactory, never()).createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(),anyInt());
     }
 
     @Test
@@ -154,7 +156,8 @@ public class CarToastUITest extends SysuiTestCase {
         mCarToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
+        verify(mToastFactory).createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
     }
 
     @Test
@@ -166,8 +169,8 @@ public class CarToastUITest extends SysuiTestCase {
         mCarToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory, never()).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(),
-                anyInt());
+        verify(mToastFactory, never()).createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
     }
 
     @Test
@@ -185,7 +188,8 @@ public class CarToastUITest extends SysuiTestCase {
         carToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
+        verify(mToastFactory).createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
     }
 
     @Test
@@ -197,7 +201,8 @@ public class CarToastUITest extends SysuiTestCase {
         mCarToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
+        verify(mToastFactory).createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
     }
 
     @Test
@@ -209,7 +214,8 @@ public class CarToastUITest extends SysuiTestCase {
         mCarToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
+        verify(mToastFactory).createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
     }
 
     @Test
@@ -221,7 +227,8 @@ public class CarToastUITest extends SysuiTestCase {
         mCarToastUI.showToast(UID, PACKAGE_NAME, mIBinder, TEXT, mIBinder, DURATION,
                 mITransientNotificationCallback, Display.DEFAULT_DISPLAY);
 
-        verify(mToastFactory).createToast(any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
+        verify(mToastFactory).createToast(
+                any(), any(), eq(TEXT), eq(PACKAGE_NAME), anyInt(), anyInt());
     }
 
     private void setupPackageInfo(boolean isSystem, boolean isPrivileged,
diff --git a/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java b/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
index ba7952d8..c6fe1d16 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
@@ -15,6 +15,8 @@
  */
 package com.android.systemui.car.userpicker;
 
+import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_INVISIBLE;
+
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mock;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
@@ -28,11 +30,15 @@ import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.after;
+import static org.mockito.Mockito.doAnswer;
 
 import android.app.ActivityManager;
+import android.car.SyncResultCallback;
 import android.car.user.CarUserManager;
 import android.car.user.CarUserManager.UserLifecycleEvent;
 import android.car.user.UserCreationResult;
+import android.car.user.UserStartResponse;
+import android.car.user.UserStopResponse;
 import android.car.util.concurrent.AsyncFuture;
 import android.content.Intent;
 import android.os.UserManager;
@@ -130,14 +136,31 @@ public class UserEventManagerTest extends UserPickerTestCase {
 
     @Test
     public void checkStartUser_requestStartUser_startUser() {
+        // When start user is invoked, mock the UserStartResponse so it won't wait for timeout
+        doAnswer((inv) -> {
+            SyncResultCallback<UserStartResponse> callback = inv.getArgument(2);
+            callback.onResult(new UserStartResponse(UserStartResponse.STATUS_SUCCESSFUL));
+            return null;
+        }).when(mMockCarUserManager).startUser(any(), any(), any());
+
         mUserEventManager.startUserForDisplay(/* prevCurrentUser= */ -1,
                 /* userId= */ USER_ID_FRONT, /* displayId= */ FRONT_PASSENGER_DISPLAY_ID,
                 /* isFgUserStart= */ false);
+
         verify(mMockCarUserManager).startUser(any(), any(), any());
     }
 
     @Test
-    public void checkStopUser_requestStopUser_StopUser() {
+    public void checkStopUser_requestStopUser_stopUser() {
+        // When stop user is invoked, mock the UserStopResponse so it won't wait for timeout
+        doAnswer((inv) -> {
+            SyncResultCallback<UserStopResponse> callback = inv.getArgument(2);
+            callback.onResult(new UserStopResponse(UserStopResponse.STATUS_SUCCESSFUL));
+            mUserEventManager.mUserLifecycleListener.onEvent(
+                    new UserLifecycleEvent(USER_LIFECYCLE_EVENT_TYPE_INVISIBLE, USER_ID_FRONT));
+            return null;
+        }).when(mMockCarUserManager).stopUser(any(), any(), any());
+
         mUserEventManager.stopUserUnchecked(/* userId= */ USER_ID_FRONT,
                 /* displayId= */ FRONT_PASSENGER_DISPLAY_ID);
 
diff --git a/tests/src/com/android/systemui/car/window/OverlayViewGlobalStateControllerTest.java b/tests/src/com/android/systemui/car/window/OverlayViewGlobalStateControllerTest.java
index 660bfdae..8526e72a 100644
--- a/tests/src/com/android/systemui/car/window/OverlayViewGlobalStateControllerTest.java
+++ b/tests/src/com/android/systemui/car/window/OverlayViewGlobalStateControllerTest.java
@@ -46,14 +46,12 @@ import org.junit.Test;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
+import java.util.ArrayList;
 import java.util.Arrays;
 
 @CarSystemUiTest
 @SmallTest
 public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
-    private static final int OVERLAY_VIEW_CONTROLLER_1_Z_ORDER = 0;
-    private static final int OVERLAY_VIEW_CONTROLLER_2_Z_ORDER = 1;
-    private static final int OVERLAY_PANEL_VIEW_CONTROLLER_Z_ORDER = 2;
 
     private OverlayViewGlobalStateController mOverlayViewGlobalStateController;
     private ViewGroup mBaseLayout;
@@ -72,6 +70,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
     private Runnable mRunnable;
     @Mock
     private WindowInsetsController mWindowInsetsController;
+    private OverlayVisibilityMediator mOverlayVisibilityMediator;
 
     @Before
     public void setUp() {
@@ -84,8 +83,10 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         when(mSystemUIOverlayWindowController.getBaseLayout()).thenReturn(mBaseLayout);
 
+        mOverlayVisibilityMediator =
+                new OverlayVisibilityMediatorImpl(mSystemUIOverlayWindowController);
         mOverlayViewGlobalStateController = new OverlayViewGlobalStateController(
-                mSystemUIOverlayWindowController);
+                mSystemUIOverlayWindowController, mOverlayVisibilityMediator);
 
         verify(mSystemUIOverlayWindowController).attach();
     }
@@ -217,7 +218,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.showView(mOverlayViewController1, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mHighestZOrder).isEqualTo(
+        assertThat(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()).isEqualTo(
                 mOverlayViewController1);
     }
 
@@ -227,8 +228,8 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.showView(mOverlayViewController1, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.containsKey(
-                OVERLAY_VIEW_CONTROLLER_1_Z_ORDER)).isTrue();
+        assertThat(mOverlayVisibilityMediator
+                .isOverlayViewVisible(mOverlayViewController1)).isTrue();
     }
 
     @Test
@@ -248,7 +249,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.showView(mOverlayViewController2, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mHighestZOrder).isEqualTo(
+        assertThat(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()).isEqualTo(
                 mOverlayViewController2);
     }
 
@@ -332,9 +333,8 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.showView(mOverlayViewController2, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.keySet().toArray())
-                .isEqualTo(Arrays.asList(OVERLAY_VIEW_CONTROLLER_1_Z_ORDER,
-                        OVERLAY_VIEW_CONTROLLER_2_Z_ORDER).toArray());
+        assertThat(new ArrayList(mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder()))
+                .isEqualTo(Arrays.asList(mOverlayViewController1, mOverlayViewController2));
     }
 
     @Test
@@ -383,7 +383,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.showView(mOverlayViewController1, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mHighestZOrder).isEqualTo(
+        assertThat(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()).isEqualTo(
                 mOverlayViewController2);
     }
 
@@ -471,9 +471,8 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.showView(mOverlayViewController1, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.keySet().toArray())
-                .isEqualTo(Arrays.asList(OVERLAY_VIEW_CONTROLLER_1_Z_ORDER,
-                        OVERLAY_VIEW_CONTROLLER_2_Z_ORDER).toArray());
+        assertThat(new ArrayList(mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder()))
+                .isEqualTo(Arrays.asList(mOverlayViewController1, mOverlayViewController2));
     }
 
     @Test
@@ -578,7 +577,6 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
     @Test
     public void hideView_nothingShown_hideRunnableNotCalled() {
         when(mOverlayViewController2.isInflated()).thenReturn(true);
-        mOverlayViewGlobalStateController.mZOrderMap.clear();
 
         mOverlayViewGlobalStateController.hideView(mOverlayViewController2, mRunnable);
 
@@ -613,7 +611,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.hideView(mOverlayViewController1, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mHighestZOrder).isNull();
+        assertThat(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()).isNull();
     }
 
     @Test
@@ -623,18 +621,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.hideView(mOverlayViewController1, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.isEmpty()).isTrue();
-    }
-
-    @Test
-    public void hideView_viewControllerOnlyShown_viewControllerNotShown() {
-        setupOverlayViewController1();
-        setOverlayViewControllerAsShowing(mOverlayViewController1);
-
-        mOverlayViewGlobalStateController.hideView(mOverlayViewController1, mRunnable);
-
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.containsKey(
-                OVERLAY_VIEW_CONTROLLER_1_Z_ORDER)).isFalse();
+        assertThat(mOverlayVisibilityMediator.isAnyOverlayViewVisible()).isFalse();
     }
 
     @Test
@@ -646,7 +633,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.hideView(mOverlayViewController2, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mHighestZOrder).isEqualTo(
+        assertThat(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()).isEqualTo(
                 mOverlayViewController1);
     }
 
@@ -661,7 +648,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.hideView(mOverlayPanelViewController, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mHighestZOrder).isEqualTo(
+        assertThat(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()).isEqualTo(
                 mOverlayViewController2);
     }
 
@@ -756,7 +743,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.hideView(mOverlayViewController1, mRunnable);
 
-        assertThat(mOverlayViewGlobalStateController.mHighestZOrder).isEqualTo(
+        assertThat(mOverlayVisibilityMediator.getHighestZOrderOverlayViewController()).isEqualTo(
                 mOverlayViewController2);
     }
 
@@ -904,7 +891,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.setOccluded(true);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.containsValue(
+        assertThat(mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder().contains(
                 mOverlayViewController1)).isFalse();
     }
 
@@ -916,7 +903,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.setOccluded(true);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.containsValue(
+        assertThat(mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder().contains(
                 mOverlayViewController1)).isTrue();
     }
 
@@ -930,7 +917,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
         mOverlayViewGlobalStateController.hideView(mOverlayViewController1, /* runnable= */ null);
         mOverlayViewGlobalStateController.setOccluded(false);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.containsValue(
+        assertThat(mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder().contains(
                 mOverlayViewController1)).isFalse();
     }
 
@@ -942,7 +929,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
         mOverlayViewGlobalStateController.setOccluded(true);
         setOverlayViewControllerAsShowing(mOverlayViewController1);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.containsValue(
+        assertThat(mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder().contains(
                 mOverlayViewController1)).isTrue();
     }
 
@@ -954,7 +941,7 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
         mOverlayViewGlobalStateController.setOccluded(true);
         setOverlayViewControllerAsShowing(mOverlayViewController1);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.containsValue(
+        assertThat(mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder().contains(
                 mOverlayViewController1)).isFalse();
     }
 
@@ -967,8 +954,8 @@ public class OverlayViewGlobalStateControllerTest extends SysuiTestCase {
 
         mOverlayViewGlobalStateController.setOccluded(false);
 
-        assertThat(mOverlayViewGlobalStateController.mZOrderVisibleSortedMap.containsValue(
-                mOverlayViewController1)).isTrue();
+        assertThat(mOverlayVisibilityMediator.getVisibleOverlayViewsByZOrder()
+                .contains(mOverlayViewController1)).isTrue();
     }
 
     @Test
```

