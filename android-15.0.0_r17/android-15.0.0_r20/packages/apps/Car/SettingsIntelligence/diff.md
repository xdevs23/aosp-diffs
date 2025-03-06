```diff
diff --git a/src/com/android/settings/intelligence/search/car/CarSearchFragment.java b/src/com/android/settings/intelligence/search/car/CarSearchFragment.java
index ba46e13..82200d7 100644
--- a/src/com/android/settings/intelligence/search/car/CarSearchFragment.java
+++ b/src/com/android/settings/intelligence/search/car/CarSearchFragment.java
@@ -16,6 +16,8 @@
 
 package com.android.settings.intelligence.search.car;
 
+import static android.provider.Settings.EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI;
+
 import static com.android.car.ui.core.CarUi.requireInsets;
 import static com.android.car.ui.core.CarUi.requireToolbar;
 import static com.android.car.ui.utils.CarUiUtils.drawableToBitmap;
@@ -28,6 +30,7 @@ import android.content.pm.ResolveInfo;
 import android.graphics.Bitmap;
 import android.graphics.drawable.BitmapDrawable;
 import android.graphics.drawable.Drawable;
+import android.net.Uri;
 import android.os.Bundle;
 import android.text.TextUtils;
 import android.util.Log;
@@ -78,6 +81,12 @@ public class CarSearchFragment extends PreferenceFragment implements
     private CarSearchResultsAdapter mSearchAdapter;
     private CarSavedQueryController mSavedQueryController;
 
+    public static final String CAR_SETTINGS_SEARCH_RESULT_TRAMPOLINE_ACTION =
+            "com.android.car.settings.SEARCH_RESULT_TRAMPOLINE";
+
+    public static final String CAR_SETTINGS_EMBEDDED_DEEPLINK_INTENT_DATA =
+            "com.android.car.settings.EMBEDDED_DEEPLINK_INTENT_DATA";
+
     private final CarUiRecyclerView.OnScrollListener mScrollListener =
             new CarUiRecyclerView.OnScrollListener() {
                 @Override
@@ -280,12 +289,12 @@ public class CarSearchFragment extends PreferenceFragment implements
 
         Intent intent = result.payload.getIntent();
         if (result instanceof AppSearchResult) {
-            getActivity().startActivity(intent);
+            getActivity().startActivity(buildSearchTrampolineIntent(intent));
         } else {
             PackageManager pm = getActivity().getPackageManager();
             List<ResolveInfo> info = pm.queryIntentActivities(intent, /* flags= */ 0);
             if (info != null && !info.isEmpty()) {
-                startActivityForResult(intent, REQUEST_CODE_NO_OP);
+                startActivityForResult(buildSearchTrampolineIntent(intent), REQUEST_CODE_NO_OP);
             } else {
                 Log.e(TAG, "Cannot launch search result, title: "
                         + result.title + ", " + intent);
@@ -293,6 +302,27 @@ public class CarSearchFragment extends PreferenceFragment implements
         }
     }
 
+    /**
+     * Converts the original search intent into a URI based trampoline intent. This allows
+     * CarSettings to preprocess the original intent before consuming it.
+     *
+     * @param intent Intent for launching the new Activity.
+     * @return an Intent targeting CarSettings with the original intent converted to URI.
+     */
+    private static Intent buildSearchTrampolineIntent(Intent intent) {
+        intent = new Intent(intent);
+        Intent trampolineIntent = new Intent(CAR_SETTINGS_SEARCH_RESULT_TRAMPOLINE_ACTION);
+        Uri data = intent.getData();
+        // If Intent#getData() is not null, Intent#toUri will return an Uri which has the scheme
+        // of Intent#getData(), and it may not be the scheme of the original Intent (i.e http:
+        // instead of ACTION_VIEW.
+        intent.setData(null);
+        trampolineIntent.putExtra(EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI,
+                intent.toUri(Intent.URI_INTENT_SCHEME));
+        trampolineIntent.putExtra(CAR_SETTINGS_EMBEDDED_DEEPLINK_INTENT_DATA, data);
+        return trampolineIntent;
+    }
+
     @Override
     public void onLoaderReset(Loader<List<? extends SearchResult>> loader) {
     }
```

