```diff
diff --git a/src/com/android/settings/accounts/AccountTypePreferenceLoader.java b/src/com/android/settings/accounts/AccountTypePreferenceLoader.java
index 3b254e9b844..71c71346adb 100644
--- a/src/com/android/settings/accounts/AccountTypePreferenceLoader.java
+++ b/src/com/android/settings/accounts/AccountTypePreferenceLoader.java
@@ -20,6 +20,7 @@ package com.android.settings.accounts;
 import android.accounts.Account;
 import android.accounts.AuthenticatorDescription;
 import android.content.ClipData;
+import android.content.ContentResolver;
 import android.content.Context;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
@@ -186,9 +187,9 @@ public class AccountTypePreferenceLoader {
                                     prefIntent, mUserHandle);
                             } else {
                                 Log.e(TAG,
-                                    "Refusing to launch authenticator intent because"
-                                        + "it exploits Settings permissions: "
-                                        + prefIntent);
+                                        "Refusing to launch authenticator intent because "
+                                                + "it exploits Settings permissions: "
+                                                + prefIntent);
                             }
                             return true;
                         }
@@ -242,13 +243,19 @@ public class AccountTypePreferenceLoader {
     }
 
     /**
-     * Determines if the supplied Intent is safe. A safe intent is one that is
-     * will launch a exported=true activity or owned by the same uid as the
+     * Determines if the supplied Intent is safe. A safe intent is one that
+     * will launch an exported=true activity or owned by the same uid as the
      * authenticator supplying the intent.
      */
-    private boolean isSafeIntent(PackageManager pm, Intent intent, String acccountType) {
+    @VisibleForTesting
+    boolean isSafeIntent(PackageManager pm, Intent intent, String accountType) {
+        if (TextUtils.equals(intent.getScheme(), ContentResolver.SCHEME_CONTENT)) {
+            Log.e(TAG, "Intent with a content scheme is unsafe.");
+            return false;
+        }
+
         AuthenticatorDescription authDesc =
-            mAuthenticatorHelper.getAccountTypeDescription(acccountType);
+                mAuthenticatorHelper.getAccountTypeDescription(accountType);
         ResolveInfo resolveInfo = pm.resolveActivityAsUser(intent, 0, mUserHandle.getIdentifier());
         if (resolveInfo == null) {
             return false;
diff --git a/src/com/android/settings/users/UserSettings.java b/src/com/android/settings/users/UserSettings.java
index a0137df728f..70de64a91b1 100644
--- a/src/com/android/settings/users/UserSettings.java
+++ b/src/com/android/settings/users/UserSettings.java
@@ -465,7 +465,7 @@ public class UserSettings extends SettingsPreferenceFragment
     public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
         int pos = 0;
         if (!isCurrentUserAdmin() && (canSwitchUserNow() || Flags.newMultiuserSettingsUx())
-                && !isCurrentUserGuest()) {
+                && !isCurrentUserGuest() && !mUserManager.isProfile()) {
             String nickname = mUserManager.getUserName();
             MenuItem removeThisUser = menu.add(0, MENU_REMOVE_USER, pos++,
                     getResources().getString(R.string.user_remove_user_menu, nickname));
diff --git a/tests/robotests/src/com/android/settings/accounts/AccountTypePreferenceLoaderTest.java b/tests/robotests/src/com/android/settings/accounts/AccountTypePreferenceLoaderTest.java
index efa5fea7416..0b9c6c357a4 100644
--- a/tests/robotests/src/com/android/settings/accounts/AccountTypePreferenceLoaderTest.java
+++ b/tests/robotests/src/com/android/settings/accounts/AccountTypePreferenceLoaderTest.java
@@ -30,8 +30,11 @@ import static org.mockito.Mockito.when;
 import android.accounts.Account;
 import android.accounts.AccountManager;
 import android.accounts.AuthenticatorDescription;
+import android.content.ClipData;
 import android.content.Context;
+import android.content.Intent;
 import android.content.pm.PackageManager;
+import android.net.Uri;
 import android.os.UserHandle;
 
 import androidx.collection.ArraySet;
@@ -250,4 +253,13 @@ public class AccountTypePreferenceLoaderTest {
         mPrefLoader.filterBlockedFragments(parent, Set.of("nomatch", "other"));
         verify(pref).setOnPreferenceClickListener(any());
     }
+
+    @Test
+    public void isSafeIntent_hasContextScheme_returnFalse() {
+        Intent intent = new Intent();
+        intent.setClipData(ClipData.newRawUri(null,
+                Uri.parse("content://com.android.settings.files/my_cache/NOTICE.html")));
+
+        assertThat(mPrefLoader.isSafeIntent(mPackageManager, intent, mAccount.type)).isFalse();
+    }
 }
```

