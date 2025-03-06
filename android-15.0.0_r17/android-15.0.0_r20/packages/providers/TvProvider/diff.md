```diff
diff --git a/src/com/android/providers/tv/TvProvider.java b/src/com/android/providers/tv/TvProvider.java
index d7a33fe..b8a301a 100644
--- a/src/com/android/providers/tv/TvProvider.java
+++ b/src/com/android/providers/tv/TvProvider.java
@@ -60,6 +60,7 @@ import android.os.Message;
 import android.os.ParcelFileDescriptor;
 import android.os.ParcelFileDescriptor.AutoCloseInputStream;
 import android.os.UserHandle;
+import android.os.UserManager;
 import android.preference.PreferenceManager;
 import android.provider.BaseColumns;
 import android.text.TextUtils;
@@ -1205,6 +1206,8 @@ public class TvProvider extends ContentProvider {
     @VisibleForTesting
     protected TransientRowHelper mTransientRowHelper;
     private final Handler mLogHandler = new WatchLogHandler();
+    private UserManager mUserManager;
+    private Map<UserHandle, Context> mSharingUsersContext;
 
     @Override
     public boolean onCreate() {
@@ -1213,14 +1216,19 @@ public class TvProvider extends ContentProvider {
         }
 
         if (kidsModeTvdbSharing()) {
+            // Creating owner context when current user if not system user
             try {
-                // Creating owner context when current user if not system user
                 if (UserHandle.myUserId() != UserHandle.USER_SYSTEM && mOwnerContext == null) {
                     mOwnerContext = getContext().createContextAsUser(UserHandle.SYSTEM, 0);
                 }
             } catch (Exception e) {
                 Log.e(TAG, "Creating owner context failed due to " + e);
             }
+            // Creating children context map when current user is the system user
+            if (UserHandle.myUserId() == UserHandle.USER_SYSTEM) {
+                mUserManager = getContext().getSystemService(UserManager.class);
+                mSharingUsersContext = new HashMap<>();
+            }
         }
 
         if (mOpenHelper == null) {
@@ -2285,11 +2293,50 @@ public class TvProvider extends ContentProvider {
     }
 
     private void notifyChange(Uri uri) {
+        if (kidsModeTvdbSharing() && DEBUG) {
+            Log.d(TAG, "notify change user is " + UserHandle.myUserId()
+                    + " about " + uri.toString());
+        }
         final Set<Uri> batchNotifications = getBatchNotificationsSet();
         if (batchNotifications != null) {
             batchNotifications.add(uri);
         } else {
-            getContext().getContentResolver().notifyChange(uri, null);
+            // When there is a change made to shared tables by system user
+            if (kidsModeTvdbSharing() && UserHandle.myUserId() == UserHandle.USER_SYSTEM
+                    && checkShareFromOwnerEnabled(uri)) {
+                // Update current childContext map when there is a change in profile counts
+                // Note that the map contains the current user as well
+                Set<UserHandle> profiles = new HashSet<>(mUserManager.getAllProfiles());
+                Set<UserHandle> mSharingUsersContextKeys = new HashSet<>(
+                        mSharingUsersContext.keySet());
+                if (!mSharingUsersContextKeys.equals(profiles)) {
+                    // Removing user profiles from map that are removed in the system
+                    for (UserHandle userProfile: mSharingUsersContextKeys) {
+                        if (!profiles.contains(userProfile)) {
+                            mSharingUsersContext.remove(userProfile);
+                        }
+                    }
+                    // Adding user profiles to map if they do not exist
+                    for (UserHandle userProfile : profiles) {
+                        if (!mSharingUsersContextKeys.contains(userProfile)) {
+                            try {
+                                Context profileContext = getContext()
+                                        .createContextAsUser(userProfile, 0);
+                                mSharingUsersContext.put(userProfile, profileContext);
+                            } catch (Exception e) {
+                                Log.e(TAG, "fail to create shared context due to " + e);
+                            }
+                        }
+                    }
+                }
+                // Notify changes using each content resolver
+                for (UserHandle currentUser : mSharingUsersContext.keySet()) {
+                    mSharingUsersContext.get(currentUser).getContentResolver()
+                            .notifyChange(uri, null);
+                }
+            } else {
+                getContext().getContentResolver().notifyChange(uri, null);
+            }
         }
     }
 
```

