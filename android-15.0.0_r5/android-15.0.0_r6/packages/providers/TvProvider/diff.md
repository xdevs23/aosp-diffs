```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index ce474c2..2dd0804 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -59,6 +59,7 @@
     <uses-permission android:name="com.android.providers.tv.permission.ACCESS_WATCHED_PROGRAMS" />
     <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
     <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
+    <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS"/>
 
     <application android:label="@string/app_label"
         android:forceQueryable="true">
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index d25e400..f76b316 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -17,6 +17,6 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="7454398782183407432">"TV Storage"</string>
-    <string name="permlab_readTvListings" msgid="5272001606068276291">"Read all TV listings"</string>
+    <string name="permlab_readTvListings" msgid="5272001606068276291">"read all TV listings"</string>
     <string name="permdesc_readTvListings" msgid="1165157606059567535">"read all TV listings available on your device"</string>
 </resources>
diff --git a/src/com/android/providers/tv/PackageChangedReceiver.java b/src/com/android/providers/tv/PackageChangedReceiver.java
index c5348ad..da26a1e 100644
--- a/src/com/android/providers/tv/PackageChangedReceiver.java
+++ b/src/com/android/providers/tv/PackageChangedReceiver.java
@@ -36,7 +36,7 @@ import java.util.Arrays;
  * This will be launched when PACKAGE_CHANGED intent is broadcast.
  */
 public class PackageChangedReceiver extends BroadcastReceiver {
-    private static final boolean DEBUG = true;
+    private static final boolean DEBUG = false;
     private static final String TAG = "PackageChangedReceiver";
 
     @Override
@@ -65,7 +65,6 @@ public class PackageChangedReceiver extends BroadcastReceiver {
                     .newDelete(TvContract.PreviewPrograms.CONTENT_URI)
                     .withSelection(ProgramsSelection, ProgramsSelectionArgs).build());
 
-
             String ChannelsSelection = TvContract.BaseTvColumns.COLUMN_PACKAGE_NAME + "=? AND "
                     + TvContract.Channels.COLUMN_TYPE + "=?";
             String[] ChannelsSelectionArgs = {packageName, TvContract.Channels.TYPE_PREVIEW};
diff --git a/src/com/android/providers/tv/TvProvider.java b/src/com/android/providers/tv/TvProvider.java
index 99b19c5..d7a33fe 100644
--- a/src/com/android/providers/tv/TvProvider.java
+++ b/src/com/android/providers/tv/TvProvider.java
@@ -16,14 +16,20 @@
 
 package com.android.providers.tv;
 
+import static android.Manifest.permission.INTERACT_ACROSS_USERS;
+import static android.media.tv.flags.Flags.kidsModeTvdbSharing;
+
+import android.annotation.NonNull;
 import android.annotation.SuppressLint;
 import android.app.AlarmManager;
 import android.app.PendingIntent;
+import android.content.AttributionSource;
 import android.content.ContentProvider;
 import android.content.ContentProviderOperation;
 import android.content.ContentProviderResult;
 import android.content.ContentValues;
 import android.content.Context;
+import android.content.ContextParams;
 import android.content.Intent;
 import android.content.OperationApplicationException;
 import android.content.SharedPreferences;
@@ -44,8 +50,8 @@ import android.media.tv.TvContract.PreviewPrograms;
 import android.media.tv.TvContract.Programs;
 import android.media.tv.TvContract.Programs.Genres;
 import android.media.tv.TvContract.RecordedPrograms;
-import android.media.tv.TvContract.WatchedPrograms;
 import android.media.tv.TvContract.WatchNextPrograms;
+import android.media.tv.TvContract.WatchedPrograms;
 import android.net.Uri;
 import android.os.AsyncTask;
 import android.os.Bundle;
@@ -53,20 +59,16 @@ import android.os.Handler;
 import android.os.Message;
 import android.os.ParcelFileDescriptor;
 import android.os.ParcelFileDescriptor.AutoCloseInputStream;
+import android.os.UserHandle;
 import android.preference.PreferenceManager;
 import android.provider.BaseColumns;
 import android.text.TextUtils;
 import android.text.format.DateUtils;
 import android.util.Log;
-
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.os.SomeArgs;
 import com.android.providers.tv.util.SqlParams;
-
 import com.android.providers.tv.util.SqliteTokenFinder;
-import java.util.Locale;
-import libcore.io.IoUtils;
-
 import java.io.ByteArrayOutputStream;
 import java.io.FileNotFoundException;
 import java.io.IOException;
@@ -77,9 +79,11 @@ import java.util.HashMap;
 import java.util.HashSet;
 import java.util.Iterator;
 import java.util.List;
+import java.util.Locale;
 import java.util.Map;
 import java.util.Set;
 import java.util.concurrent.ConcurrentHashMap;
+import libcore.io.IoUtils;
 
 /**
  * TV content provider. The contract between this provider and applications is defined in
@@ -156,6 +160,7 @@ public class TvProvider extends ContentProvider {
     private static final Map<String, String> sPreviewProgramProjectionMap = new HashMap<>();
     private static final Map<String, String> sWatchNextProgramProjectionMap = new HashMap<>();
     private static boolean sInitialized;
+    private Context mOwnerContext;
 
     static {
         sUriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
@@ -1199,7 +1204,6 @@ public class TvProvider extends ContentProvider {
     private static Map<String, Boolean> sBlockedPackages;
     @VisibleForTesting
     protected TransientRowHelper mTransientRowHelper;
-
     private final Handler mLogHandler = new WatchLogHandler();
 
     @Override
@@ -1207,10 +1211,23 @@ public class TvProvider extends ContentProvider {
         if (DEBUG) {
             Log.d(TAG, "Creating TvProvider");
         }
+
+        if (kidsModeTvdbSharing()) {
+            try {
+                // Creating owner context when current user if not system user
+                if (UserHandle.myUserId() != UserHandle.USER_SYSTEM && mOwnerContext == null) {
+                    mOwnerContext = getContext().createContextAsUser(UserHandle.SYSTEM, 0);
+                }
+            } catch (Exception e) {
+                Log.e(TAG, "Creating owner context failed due to " + e);
+            }
+        }
+
         if (mOpenHelper == null) {
             mOpenHelper = DatabaseHelper.getInstance(getContext());
         }
         mTransientRowHelper = TransientRowHelper.getInstance(getContext());
+
         scheduleEpgDataCleanup();
         buildGenreMap();
 
@@ -1331,7 +1348,24 @@ public class TvProvider extends ContentProvider {
         if (!callerHasAccessAllEpgDataPermission()) {
             return null;
         }
+        if (kidsModeTvdbSharing() && (UserHandle.getCallingUserId() != UserHandle.myUserId()) &&
+                !checkSharePermissionAllowed()) {
+            return null;
+        }
         ensureInitialized();
+
+        if (kidsModeTvdbSharing() && (UserHandle.myUserId() != UserHandle.USER_SYSTEM)
+                && (method.equals(TvContract.METHOD_GET_COLUMNS)
+                || method.equals(TvContract.METHOD_ADD_COLUMN))
+                && checkShareFromOwnerEnabled(Uri.parse(arg))) {
+            if (mOwnerContext != null) {
+                Context context = getOwnerContextWithAttributionSource(getCallingPackage());
+                return context.getContentResolver().call(Uri.parse(arg), method, arg, extras);
+            } else {
+                throw new IllegalArgumentException("Owner context is null.");
+            }
+        }
+
         Map<String, String> projectionMap;
         switch (method) {
             case TvContract.METHOD_GET_COLUMNS:
@@ -1474,6 +1508,24 @@ public class TvProvider extends ContentProvider {
             String sortOrder) {
         ensureInitialized();
         mTransientRowHelper.ensureOldTransientRowsDeleted();
+
+        if (kidsModeTvdbSharing()) {
+            if ((UserHandle.getCallingUserId() != UserHandle.myUserId()) &&
+                    !checkSharePermissionAllowed()) {
+                return null;
+            }
+            if ((UserHandle.myUserId() != UserHandle.USER_SYSTEM) && checkShareFromOwnerEnabled(
+                    uri)) {
+                if (mOwnerContext != null) {
+                    Context context = getOwnerContextWithAttributionSource(getCallingPackage());
+                    return context.getContentResolver().query(
+                            uri, projection, selection, selectionArgs, sortOrder);
+                } else {
+                    throw new IllegalArgumentException("Owner context is null.");
+                }
+            }
+        }
+
         boolean needsToValidateSortOrder = !callerHasAccessAllEpgDataPermission();
         SqlParams params = createSqlParams(OP_QUERY, uri, selection, selectionArgs);
 
@@ -1528,6 +1580,23 @@ public class TvProvider extends ContentProvider {
     public Uri insert(Uri uri, ContentValues values) {
         ensureInitialized();
         mTransientRowHelper.ensureOldTransientRowsDeleted();
+
+        if (kidsModeTvdbSharing()) {
+            if ((UserHandle.getCallingUserId() != UserHandle.myUserId()) &&
+                    !checkSharePermissionAllowed()) {
+                return null;
+            }
+            if ((UserHandle.myUserId() != UserHandle.USER_SYSTEM) && checkShareFromOwnerEnabled(
+                    uri)) {
+                if (mOwnerContext != null) {
+                    Context context = getOwnerContextWithAttributionSource(getCallingPackage());
+                    return context.getContentResolver().insert(uri, values);
+                } else {
+                    throw new IllegalArgumentException("Owner context is null.");
+                }
+            }
+        }
+
         switch (sUriMatcher.match(uri)) {
             case MATCH_CHANNEL:
                 // Preview channels are not necessarily associated with TV input service.
@@ -1705,6 +1774,23 @@ public class TvProvider extends ContentProvider {
     @Override
     public int delete(Uri uri, String selection, String[] selectionArgs) {
         mTransientRowHelper.ensureOldTransientRowsDeleted();
+
+        if (kidsModeTvdbSharing()) {
+            if ((UserHandle.getCallingUserId() != UserHandle.myUserId()) &&
+                    !checkSharePermissionAllowed()) {
+                return 0;
+            }
+            if ((UserHandle.myUserId() != UserHandle.USER_SYSTEM) && checkShareFromOwnerEnabled(
+                    uri)) {
+                if (mOwnerContext != null) {
+                    Context context = getOwnerContextWithAttributionSource(getCallingPackage());
+                    return context.getContentResolver().delete(uri, selection, selectionArgs);
+                } else {
+                    throw new IllegalArgumentException("Owner context is null.");
+                }
+            }
+        }
+
         SqlParams params = createSqlParams(OP_DELETE, uri, selection, selectionArgs);
         SQLiteDatabase db = mOpenHelper.getWritableDatabase();
         int count;
@@ -1744,6 +1830,25 @@ public class TvProvider extends ContentProvider {
     public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
         ensureInitialized();
         mTransientRowHelper.ensureOldTransientRowsDeleted();
+
+        if (kidsModeTvdbSharing()) {
+            if ((UserHandle.getCallingUserId() != UserHandle.myUserId()) &&
+                    !checkSharePermissionAllowed()) {
+                return 0;
+            }
+
+            if ((UserHandle.myUserId() != UserHandle.USER_SYSTEM) && checkShareFromOwnerEnabled(
+                    uri)) {
+                if (mOwnerContext != null) {
+                    Context context = getOwnerContextWithAttributionSource(getCallingPackage());
+                    return context.getContentResolver().update(uri, values, selection,
+                            selectionArgs);
+                } else {
+                    throw new IllegalArgumentException("Owner context is null.");
+                }
+            }
+        }
+
         SqlParams params = createSqlParams(OP_UPDATE, uri, selection, selectionArgs);
         blockIllegalAccessToIdAndPackageName(uri, values);
         boolean containImmutableColumn = false;
@@ -1791,6 +1896,17 @@ public class TvProvider extends ContentProvider {
         return count;
     }
 
+    private @NonNull Context getOwnerContextWithAttributionSource(String packageName) {
+        AttributionSource attributionSource = new AttributionSource
+                .Builder(UserHandle.USER_SYSTEM)
+                .setPackageName(packageName)
+                .build();
+        ContextParams contextParams = new ContextParams.Builder()
+                .setNextAttributionSource(attributionSource)
+                .build();
+        return mOwnerContext.createContext(contextParams);
+    }
+
     private synchronized void ensureInitialized() {
         if (!sInitialized) {
             // Database is not accessed before and the projection maps and the blocked package list
@@ -2178,23 +2294,51 @@ public class TvProvider extends ContentProvider {
     }
 
     private boolean callerHasReadTvListingsPermission() {
-        return getContext().checkCallingOrSelfPermission(PERMISSION_READ_TV_LISTINGS)
-                == PackageManager.PERMISSION_GRANTED;
+        return callerHasPermission(PERMISSION_READ_TV_LISTINGS);
     }
 
     private boolean callerHasAccessAllEpgDataPermission() {
-        return getContext().checkCallingOrSelfPermission(PERMISSION_ACCESS_ALL_EPG_DATA)
-                == PackageManager.PERMISSION_GRANTED;
+        return callerHasPermission(PERMISSION_ACCESS_ALL_EPG_DATA);
     }
 
     private boolean callerHasAccessWatchedProgramsPermission() {
-        return getContext().checkCallingOrSelfPermission(PERMISSION_ACCESS_WATCHED_PROGRAMS)
-                == PackageManager.PERMISSION_GRANTED;
+        return callerHasPermission(PERMISSION_ACCESS_WATCHED_PROGRAMS);
     }
 
     private boolean callerHasModifyParentalControlsPermission() {
-        return getContext().checkCallingOrSelfPermission(
-                android.Manifest.permission.MODIFY_PARENTAL_CONTROLS)
+        return callerHasPermission(android.Manifest.permission.MODIFY_PARENTAL_CONTROLS);
+    }
+
+    private boolean callerHasPermission(String permission) {
+        String callingPackageName = getCallingAttributionSource().getNextPackageName();
+        // Check self permission if caller package is null
+        if (!kidsModeTvdbSharing() || (callingPackageName == null)) {
+            return getContext().checkCallingOrSelfPermission(permission)
+                    == PackageManager.PERMISSION_GRANTED;
+        }
+        return getContext().getPackageManager().checkPermission(permission, callingPackageName)
+                == PackageManager.PERMISSION_GRANTED;
+    }
+
+    private boolean checkShareFromOwnerEnabled(Uri uri) {
+        // Share the channels table, the programs table and the recorded programs table
+        // among all profiles; OEMs could choose to share tables from above options
+        // with runtime resource overlay or etc. if needed.
+        int match = sUriMatcher.match(uri);
+        switch (match) {
+            case MATCH_CHANNEL:
+            case MATCH_CHANNEL_ID:
+            case MATCH_CHANNEL_ID_LOGO:
+            case MATCH_PROGRAM:
+            case MATCH_PROGRAM_ID:
+                return true;
+            default:
+                return false;
+        }
+    }
+
+    private boolean checkSharePermissionAllowed() {
+        return getContext().checkCallingOrSelfPermission(INTERACT_ACROSS_USERS)
                 == PackageManager.PERMISSION_GRANTED;
     }
 
diff --git a/tests/Android.bp b/tests/Android.bp
index facf5ea..996176a 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -24,9 +24,9 @@ android_test {
     srcs: ["src/**/*.java"],
     platform_apis: true,
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
     static_libs: [
         "junit",
```

