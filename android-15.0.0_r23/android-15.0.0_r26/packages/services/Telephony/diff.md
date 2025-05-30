```diff
diff --git a/src/com/android/phone/ADNList.java b/src/com/android/phone/ADNList.java
index 18b48fad5..bcf1a8914 100644
--- a/src/com/android/phone/ADNList.java
+++ b/src/com/android/phone/ADNList.java
@@ -81,6 +81,9 @@ public class ADNList extends ListActivity {
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
         getWindow().requestFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
         setContentView(R.layout.adn_list);
         mEmptyText = (TextView) findViewById(android.R.id.empty);
         mQueryHandler = new QueryHandler(getContentResolver());
diff --git a/src/com/android/phone/CallFeaturesSetting.java b/src/com/android/phone/CallFeaturesSetting.java
index 1c5525689..bec2a81a1 100644
--- a/src/com/android/phone/CallFeaturesSetting.java
+++ b/src/com/android/phone/CallFeaturesSetting.java
@@ -257,6 +257,10 @@ public class CallFeaturesSetting extends PreferenceActivity
         super.onCreate(icicle);
         if (DBG) log("onCreate: Intent is " + getIntent());
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         // Make sure we are running as an admin user.
         UserManager userManager = (UserManager) getSystemService(Context.USER_SERVICE);
         if (!userManager.isAdminUser()) {
diff --git a/src/com/android/phone/CdmaCallForwardOptions.java b/src/com/android/phone/CdmaCallForwardOptions.java
index d70e7099b..62c945f0c 100644
--- a/src/com/android/phone/CdmaCallForwardOptions.java
+++ b/src/com/android/phone/CdmaCallForwardOptions.java
@@ -73,6 +73,10 @@ public class CdmaCallForwardOptions extends TimeConsumingPreferenceActivity {
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         addPreferencesFromResource(R.xml.callforward_options);
 
         mSubscriptionInfoHelper = new SubscriptionInfoHelper(this, getIntent());
diff --git a/src/com/android/phone/CdmaCallOptions.java b/src/com/android/phone/CdmaCallOptions.java
index 4f94b5810..fe6d77728 100644
--- a/src/com/android/phone/CdmaCallOptions.java
+++ b/src/com/android/phone/CdmaCallOptions.java
@@ -59,6 +59,10 @@ public class CdmaCallOptions extends TimeConsumingPreferenceActivity {
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         addPreferencesFromResource(R.xml.cdma_call_privacy);
 
         SubscriptionInfoHelper subInfoHelper = new SubscriptionInfoHelper(this, getIntent());
diff --git a/src/com/android/phone/ChangeIccPinScreen.java b/src/com/android/phone/ChangeIccPinScreen.java
index 078449573..898b21b3f 100644
--- a/src/com/android/phone/ChangeIccPinScreen.java
+++ b/src/com/android/phone/ChangeIccPinScreen.java
@@ -95,6 +95,10 @@ public class ChangeIccPinScreen extends Activity {
     public void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         mUserManager = this.getSystemService(UserManager.class);
         if (mUserManager.hasUserRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS)) {
             mDisallowedConfig = true;
diff --git a/src/com/android/phone/EmergencyDialer.java b/src/com/android/phone/EmergencyDialer.java
index d4fdca6b2..6b3dc9ef7 100644
--- a/src/com/android/phone/EmergencyDialer.java
+++ b/src/com/android/phone/EmergencyDialer.java
@@ -257,6 +257,10 @@ public class EmergencyDialer extends Activity implements View.OnClickListener,
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         mEntryType = getIntent().getIntExtra(EXTRA_ENTRY_TYPE, ENTRY_TYPE_UNKNOWN);
         Log.d(LOG_TAG, "Launched from " + entryTypeToString(mEntryType));
 
diff --git a/src/com/android/phone/EnableIccPinScreen.java b/src/com/android/phone/EnableIccPinScreen.java
index 092fa64af..2e6ce6e3e 100644
--- a/src/com/android/phone/EnableIccPinScreen.java
+++ b/src/com/android/phone/EnableIccPinScreen.java
@@ -68,6 +68,10 @@ public class EnableIccPinScreen extends Activity {
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         mUserManager = this.getSystemService(UserManager.class);
         if (mUserManager.hasUserRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS)) {
             mDisallowedConfig = true;
diff --git a/src/com/android/phone/GsmUmtsAdditionalCallOptions.java b/src/com/android/phone/GsmUmtsAdditionalCallOptions.java
index 6e289221c..6048c927a 100644
--- a/src/com/android/phone/GsmUmtsAdditionalCallOptions.java
+++ b/src/com/android/phone/GsmUmtsAdditionalCallOptions.java
@@ -42,6 +42,10 @@ public class GsmUmtsAdditionalCallOptions extends TimeConsumingPreferenceActivit
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         addPreferencesFromResource(R.xml.gsm_umts_additional_options);
 
         mSubscriptionInfoHelper = new SubscriptionInfoHelper(this, getIntent());
diff --git a/src/com/android/phone/GsmUmtsCallBarringOptions.java b/src/com/android/phone/GsmUmtsCallBarringOptions.java
index 99dc92fea..5cafa8a3a 100644
--- a/src/com/android/phone/GsmUmtsCallBarringOptions.java
+++ b/src/com/android/phone/GsmUmtsCallBarringOptions.java
@@ -351,6 +351,11 @@ public class GsmUmtsCallBarringOptions extends TimeConsumingPreferenceActivity
     @Override
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
+
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         if (DBG) {
             Log.d(LOG_TAG, "onCreate, reading callbarring_options.xml file");
         }
diff --git a/src/com/android/phone/GsmUmtsCallForwardOptions.java b/src/com/android/phone/GsmUmtsCallForwardOptions.java
index db830deb6..6a5cb83d5 100644
--- a/src/com/android/phone/GsmUmtsCallForwardOptions.java
+++ b/src/com/android/phone/GsmUmtsCallForwardOptions.java
@@ -58,6 +58,10 @@ public class GsmUmtsCallForwardOptions extends TimeConsumingPreferenceActivity {
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         addPreferencesFromResource(R.xml.callforward_options);
 
         mSubscriptionInfoHelper = new SubscriptionInfoHelper(this, getIntent());
diff --git a/src/com/android/phone/GsmUmtsCallOptions.java b/src/com/android/phone/GsmUmtsCallOptions.java
index be5295d53..0e666a5ba 100644
--- a/src/com/android/phone/GsmUmtsCallOptions.java
+++ b/src/com/android/phone/GsmUmtsCallOptions.java
@@ -43,6 +43,10 @@ public class GsmUmtsCallOptions extends PreferenceActivity {
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         addPreferencesFromResource(R.xml.gsm_umts_call_options);
 
         SubscriptionInfoHelper subInfoHelper = new SubscriptionInfoHelper(this, getIntent());
diff --git a/src/com/android/phone/SimContacts.java b/src/com/android/phone/SimContacts.java
index d5f78403f..fcbe4a09a 100644
--- a/src/com/android/phone/SimContacts.java
+++ b/src/com/android/phone/SimContacts.java
@@ -232,6 +232,10 @@ public class SimContacts extends ADNList {
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         Intent intent = getIntent();
         if (intent != null) {
             final String accountName = intent.getStringExtra("account_name");
diff --git a/src/com/android/phone/settings/fdn/BaseFdnContactScreen.java b/src/com/android/phone/settings/fdn/BaseFdnContactScreen.java
index 5beff34db..b33421a89 100644
--- a/src/com/android/phone/settings/fdn/BaseFdnContactScreen.java
+++ b/src/com/android/phone/settings/fdn/BaseFdnContactScreen.java
@@ -71,6 +71,9 @@ public abstract class BaseFdnContactScreen extends Activity
         super.onCreate(savedInstanceState);
         resolveIntent();
         getWindow().requestFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
     }
 
     protected void authenticatePin2() {
diff --git a/src/com/android/phone/settings/fdn/DeleteFdnContactScreen.java b/src/com/android/phone/settings/fdn/DeleteFdnContactScreen.java
index 7cd4c935c..ab14c836f 100644
--- a/src/com/android/phone/settings/fdn/DeleteFdnContactScreen.java
+++ b/src/com/android/phone/settings/fdn/DeleteFdnContactScreen.java
@@ -32,6 +32,10 @@ public class DeleteFdnContactScreen extends BaseFdnContactScreen {
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         // Starts PIN2 authentication only for the first time.
         if (icicle == null) authenticatePin2();
         setContentView(R.layout.delete_fdn_contact_screen);
diff --git a/src/com/android/phone/settings/fdn/EditFdnContactScreen.java b/src/com/android/phone/settings/fdn/EditFdnContactScreen.java
index 6bf41f363..6bed39a5b 100644
--- a/src/com/android/phone/settings/fdn/EditFdnContactScreen.java
+++ b/src/com/android/phone/settings/fdn/EditFdnContactScreen.java
@@ -88,6 +88,9 @@ public class EditFdnContactScreen extends BaseFdnContactScreen {
     @Override
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
 
         setContentView(R.layout.edit_fdn_contact_screen);
         setupView();
diff --git a/src/com/android/phone/settings/fdn/FdnList.java b/src/com/android/phone/settings/fdn/FdnList.java
index 1b5a7afa6..e50fc60e9 100644
--- a/src/com/android/phone/settings/fdn/FdnList.java
+++ b/src/com/android/phone/settings/fdn/FdnList.java
@@ -99,6 +99,10 @@ public class FdnList extends ADNList {
     public void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         ActionBar actionBar = getActionBar();
         if (actionBar != null) {
             // android.R.id.home will be triggered in onOptionsItemSelected()
diff --git a/src/com/android/phone/settings/fdn/FdnSetting.java b/src/com/android/phone/settings/fdn/FdnSetting.java
index ddbcc99b3..e9a1aed06 100644
--- a/src/com/android/phone/settings/fdn/FdnSetting.java
+++ b/src/com/android/phone/settings/fdn/FdnSetting.java
@@ -509,6 +509,10 @@ public class FdnSetting extends PreferenceActivity
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         mSubscriptionInfoHelper = new SubscriptionInfoHelper(this, getIntent());
         mPhone = mSubscriptionInfoHelper.getPhone();
 
diff --git a/src/com/android/phone/settings/fdn/GetPin2Screen.java b/src/com/android/phone/settings/fdn/GetPin2Screen.java
index 09cab46d7..7f3b60c4e 100644
--- a/src/com/android/phone/settings/fdn/GetPin2Screen.java
+++ b/src/com/android/phone/settings/fdn/GetPin2Screen.java
@@ -48,6 +48,10 @@ public class GetPin2Screen extends Activity implements TextView.OnEditorActionLi
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
 
+        getWindow().addSystemFlags(
+                android.view.WindowManager.LayoutParams
+                        .SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
+
         setContentView(R.layout.get_pin2_screen);
 
         mPin2Field = (EditText) findViewById(R.id.pin);
```

