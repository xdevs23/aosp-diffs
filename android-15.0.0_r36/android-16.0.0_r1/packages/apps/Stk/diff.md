```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 18f3848..d1bd883 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -40,6 +40,7 @@
         android:process="com.android.phone"
         android:taskAffinity="android.task.stk"
         android:defaultToDeviceProtectedStorage="true"
+        android:enableOnBackInvokedCallback="false"
         android:directBootAware="true">
 
         <activity android:name="StkMain"
@@ -56,7 +57,7 @@
         </activity>
 
         <activity android:name="StkLauncherActivity"
-            android:theme="@style/StkTheme"
+            android:theme="@android:style/Theme.DeviceDefault.DayNight"
             android:label="@string/app_name"
             android:exported="false"
             android:autoRemoveFromRecents="true"
@@ -69,7 +70,7 @@
         </activity>
 
         <activity android:name="StkMenuActivity"
-            android:theme="@style/StkTheme"
+            android:theme="@android:style/Theme.DeviceDefault.DayNight"
             android:icon="@drawable/ic_launcher_sim_toolkit"
             android:label="@string/app_name"
             android:configChanges="orientation|locale|screenSize|keyboardHidden|mnc|mcc"
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 1b07a74..7d43798 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -24,7 +24,4 @@
         <item name="android:backgroundDimEnabled">true</item>
         <item name="android:windowAnimationStyle">@android:style/Animation.Dialog</item>
     </style>
-    <style name="StkTheme" parent="@android:style/Theme.DeviceDefault.DayNight">
-        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
-    </style>
 </resources>
diff --git a/src/com/android/stk/StkApp.java b/src/com/android/stk/StkApp.java
index 9d653c1..26f1c77 100644
--- a/src/com/android/stk/StkApp.java
+++ b/src/com/android/stk/StkApp.java
@@ -16,8 +16,13 @@
 
 package com.android.stk;
 
+import android.app.Activity;
 import android.app.Application;
 
+import androidx.core.graphics.Insets;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.WindowInsetsCompat;
+
 import com.android.internal.telephony.cat.Duration;
 
 /**
@@ -67,4 +72,23 @@ abstract class StkApp extends Application {
         }
         return timeout;
     }
+
+    /**
+     * Given an activity, configure the activity to adjust for edge to edge restrictions.
+     * @param activity the activity.
+     */
+    public static void setupEdgeToEdge(Activity activity) {
+        ViewCompat.setOnApplyWindowInsetsListener(activity.findViewById(android.R.id.content),
+                (v, windowInsets) -> {
+                    Insets insets = windowInsets.getInsets(
+                            WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.ime());
+
+                    // Apply the insets paddings to the view.
+                    v.setPadding(insets.left, insets.top, insets.right, insets.bottom);
+
+                    // Return CONSUMED if you don't want the window insets to keep being
+                    // passed down to descendant views.
+                    return WindowInsetsCompat.CONSUMED;
+                });
+    }
 }
diff --git a/src/com/android/stk/StkDialogActivity.java b/src/com/android/stk/StkDialogActivity.java
index aa5b0df..4c937d9 100644
--- a/src/com/android/stk/StkDialogActivity.java
+++ b/src/com/android/stk/StkDialogActivity.java
@@ -74,7 +74,7 @@ public class StkDialogActivity extends Activity {
             finish();
             return;
         }
-
+        StkApp.setupEdgeToEdge(this);
         // New Dialog is created - set to no response sent
         mIsResponseSent = false;
 
diff --git a/src/com/android/stk/StkInputActivity.java b/src/com/android/stk/StkInputActivity.java
index 365a6d2..1cb6cae 100644
--- a/src/com/android/stk/StkInputActivity.java
+++ b/src/com/android/stk/StkInputActivity.java
@@ -160,7 +160,7 @@ public class StkInputActivity extends AppCompatActivity implements View.OnClickL
             finish();
             return;
         }
-
+        StkApp.setupEdgeToEdge(this);
         // Set the layout for this activity.
         setContentView(R.layout.stk_input);
         setSupportActionBar((Toolbar) findViewById(R.id.toolbar));
diff --git a/src/com/android/stk/StkMenuActivity.java b/src/com/android/stk/StkMenuActivity.java
index 2033900..ad18bb7 100644
--- a/src/com/android/stk/StkMenuActivity.java
+++ b/src/com/android/stk/StkMenuActivity.java
@@ -93,6 +93,7 @@ public class StkMenuActivity extends ListActivity implements View.OnCreateContex
         actionBar.setCustomView(R.layout.stk_title);
         actionBar.setDisplayShowCustomEnabled(true);
 
+        StkApp.setupEdgeToEdge(this);
         // Set the layout for this activity.
         setContentView(R.layout.stk_menu_list);
         mTitleTextView = (TextView) findViewById(R.id.title_text);
```

