```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index d093825..85b4b84 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -35,7 +35,6 @@
     <application
         android:icon="@drawable/ic_launcher_nfc"
         android:label="@string/app_name"
-        android:theme="@style/AppTheme"
     >
         <activity android:name="TagViewer"
             android:label="@string/title_scanned_tag"
diff --git a/OWNERS b/OWNERS
index c43d4d6..30b4824 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,4 +3,3 @@
 alisher@google.com
 jackcwyu@google.com
 georgekgchang@google.com
-zachoverflow@google.com
diff --git a/res/layout/tag_viewer.xml b/res/layout/tag_viewer.xml
index 0370b53..962a1a5 100644
--- a/res/layout/tag_viewer.xml
+++ b/res/layout/tag_viewer.xml
@@ -17,8 +17,8 @@
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
-
     android:orientation="vertical"
+    android:fitsSystemWindows="true"
 >
     <!-- Content -->
 
@@ -57,4 +57,4 @@
 
     </LinearLayout>
 -->
-</LinearLayout>
\ No newline at end of file
+</LinearLayout>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index c222045..c41d85c 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -17,10 +17,6 @@
 
 <resources>
 
-    <style name="AppTheme">
-        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
-    </style>
-
     <style name="record_title">
         <item name="android:layout_width">match_parent</item>
         <item name="android:layout_height">wrap_content</item>
diff --git a/src/com/android/apps/tag/TagViewer.java b/src/com/android/apps/tag/TagViewer.java
index 70c758e..a4e16b6 100644
--- a/src/com/android/apps/tag/TagViewer.java
+++ b/src/com/android/apps/tag/TagViewer.java
@@ -20,7 +20,6 @@ import com.android.apps.tag.message.NdefMessageParser;
 import com.android.apps.tag.message.ParsedNdefMessage;
 import com.android.apps.tag.record.ParsedNdefRecord;
 
-import android.app.Activity;
 import android.content.Intent;
 import android.nfc.NdefMessage;
 import android.nfc.NfcAdapter;
@@ -33,18 +32,24 @@ import android.view.View.OnClickListener;
 import android.widget.LinearLayout;
 import android.widget.TextView;
 
+import androidx.activity.ComponentActivity;
+import androidx.activity.EdgeToEdge;
+import androidx.annotation.NonNull;
+
 import java.util.List;
 
 /**
- * An {@link Activity} which handles a broadcast of a new tag that the device just discovered.
+ * An {@link ComponentActivity} which handles a broadcast of a new tag that
+ * the device just discovered.
  */
-public class TagViewer extends Activity implements OnClickListener {
+public class TagViewer extends ComponentActivity implements OnClickListener {
     static final String TAG = "TagViewer";
 
     LinearLayout mTagContent;
 
     @Override
     protected void onCreate(Bundle savedInstanceState) {
+        EdgeToEdge.enable(this);
         super.onCreate(savedInstanceState);
 
         setContentView(R.layout.tag_viewer);
@@ -83,7 +88,7 @@ public class TagViewer extends Activity implements OnClickListener {
     }
 
     void buildTagViews(NdefMessage msg) {
-        LayoutInflater inflater = LayoutInflater.from(this);
+        LayoutInflater inflater = getLayoutInflater();
         LinearLayout content = mTagContent;
 
         // Clear out any old views in the content area, for example if you scan two tags in a row.
@@ -112,7 +117,8 @@ public class TagViewer extends Activity implements OnClickListener {
     }
 
     @Override
-    public void onNewIntent(Intent intent) {
+    public void onNewIntent(@NonNull Intent intent) {
+        super.onNewIntent(intent);
         setIntent(intent);
         resolveIntent(intent);
     }
```

