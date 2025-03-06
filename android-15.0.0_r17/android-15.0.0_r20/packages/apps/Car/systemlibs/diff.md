```diff
diff --git a/car-qc-lib/Android.bp b/car-qc-lib/Android.bp
index 4d3a297..76c8991 100644
--- a/car-qc-lib/Android.bp
+++ b/car-qc-lib/Android.bp
@@ -17,9 +17,22 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+genrule {
+    name: "statslog-carqclib-java-gen",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --java $(out) --module carqclib" +
+        " --javaPackage com.android.car.qc --javaClass CarQcLibStatsLog",
+    out: ["com/android/car/qc/CarQcLibStatsLog.java"],
+}
+
+carqclib_srcs = [
+    "src/**/*.java",
+    ":statslog-carqclib-java-gen",
+]
+
 android_library {
     name: "car-qc-lib",
-    srcs: ["src/**/*.java"],
+    srcs: carqclib_srcs,
     optimize: {
         enabled: false,
     },
diff --git a/car-qc-lib/src/com/android/car/qc/QCItem.java b/car-qc-lib/src/com/android/car/qc/QCItem.java
index c6826ae..b2bab66 100644
--- a/car-qc-lib/src/com/android/car/qc/QCItem.java
+++ b/car-qc-lib/src/com/android/car/qc/QCItem.java
@@ -29,6 +29,8 @@ import androidx.annotation.StringDef;
 
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
+import java.security.MessageDigest;
+import java.security.NoSuchAlgorithmException;
 
 /**
  * Base class for all quick controls elements.
@@ -61,6 +63,8 @@ public abstract class QCItem implements Parcelable {
     private final boolean mIsClickableWhileDisabled;
     private ActionHandler mActionHandler;
     private ActionHandler mDisabledClickActionHandler;
+    private int mPackageUid;
+    private String mTag = "";
 
     public QCItem(@NonNull @QCItemType String type) {
         this(type, /* isEnabled= */true, /* isClickableWhileDisabled= */ false);
@@ -77,6 +81,8 @@ public abstract class QCItem implements Parcelable {
         mType = in.readString();
         mIsEnabled = in.readBoolean();
         mIsClickableWhileDisabled = in.readBoolean();
+        mPackageUid = in.readInt();
+        mTag = in.readString();
     }
 
     @NonNull
@@ -93,6 +99,14 @@ public abstract class QCItem implements Parcelable {
         return mIsClickableWhileDisabled;
     }
 
+    public int getPackageUid() {
+        return mPackageUid;
+    }
+
+    public String getTag() {
+        return mTag;
+    }
+
     @Override
     public int describeContents() {
         return 0;
@@ -103,6 +117,8 @@ public abstract class QCItem implements Parcelable {
         dest.writeString(mType);
         dest.writeBoolean(mIsEnabled);
         dest.writeBoolean(mIsClickableWhileDisabled);
+        dest.writeInt(mPackageUid);
+        dest.writeString(mTag);
     }
 
     public void setActionHandler(@Nullable ActionHandler handler) {
@@ -113,6 +129,22 @@ public abstract class QCItem implements Parcelable {
         mDisabledClickActionHandler = handler;
     }
 
+    public void setPackageUid(int packageUid) {
+        mPackageUid = packageUid;
+    }
+
+    public void setTag(String tag) {
+        //for privacy concerns, these tags should be hashed before they are
+        //recorded for metrics
+        try {
+            MessageDigest digest = MessageDigest.getInstance("SHA-256");
+            byte[] hash = digest.digest(tag.getBytes());
+            mTag = new String(hash);
+        } catch (NoSuchAlgorithmException e) {
+            mTag = "";
+        }
+    }
+
     @Nullable
     public ActionHandler getActionHandler() {
         return mActionHandler;
diff --git a/car-qc-lib/src/com/android/car/qc/QCSlider.java b/car-qc-lib/src/com/android/car/qc/QCSlider.java
index 612274b..30a192d 100644
--- a/car-qc-lib/src/com/android/car/qc/QCSlider.java
+++ b/car-qc-lib/src/com/android/car/qc/QCSlider.java
@@ -21,7 +21,6 @@ import android.os.Parcel;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
-
 /**
  * Quick Control Slider included in {@link QCRow}
  */
@@ -186,4 +185,8 @@ public class QCSlider extends QCItem {
                     mInputAction, mDisabledClickAction);
         }
     }
+
+    int getSliderValueInPercentage(int value) {
+        return (int) (value * 1.0 / (getMax() - getMin()) * 100);
+    }
 }
diff --git a/car-qc-lib/src/com/android/car/qc/StatsLogHelper.java b/car-qc-lib/src/com/android/car/qc/StatsLogHelper.java
new file mode 100644
index 0000000..e7cb5c5
--- /dev/null
+++ b/car-qc-lib/src/com/android/car/qc/StatsLogHelper.java
@@ -0,0 +1,183 @@
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
+package com.android.car.qc;
+
+import static com.android.car.qc.QCItem.QC_ACTION_SLIDER_VALUE;
+import static com.android.car.qc.QCItem.QC_ACTION_TOGGLE_STATE;
+import static com.android.car.qc.QCItem.QC_TYPE_ACTION_SWITCH;
+import static com.android.car.qc.QCItem.QC_TYPE_ACTION_TOGGLE;
+import static com.android.car.qc.QCItem.QC_TYPE_ROW;
+import static com.android.car.qc.QCItem.QC_TYPE_SLIDER;
+import static com.android.car.qc.QCItem.QC_TYPE_TILE;
+
+import android.annotation.IntDef;
+import android.content.Intent;
+import android.os.Build;
+import android.os.Bundle;
+import android.util.Log;
+
+public class StatsLogHelper {
+    private static final String TAG = StatsLogHelper.class.getSimpleName();
+    private static StatsLogHelper sInstance;
+    private static final int DEFAULT_VALUE = -1;
+    private static final boolean DEFAULT_STATE = false;
+
+
+    /**
+     * IntDef representing enum values of CarQcLibEventReported.element_type.
+     */
+    @IntDef({
+        QcElementType.UNSPECIFIED_ELEMENT_TYPE,
+        QcElementType.QC_TYPE_LIST,
+        QcElementType.QC_TYPE_ROW,
+        QcElementType.QC_TYPE_TILE,
+        QcElementType.QC_TYPE_SLIDER,
+        QcElementType.QC_TYPE_ACTION_SWITCH,
+        QcElementType.QC_TYPE_ACTION_TOGGLE,
+    })
+
+    public @interface QcElementType {
+        int UNSPECIFIED_ELEMENT_TYPE =
+                CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__UNSPECIFIED_ELEMENT_TYPE;
+        int QC_TYPE_LIST =
+                CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_LIST;
+        int QC_TYPE_ROW =
+                CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_ROW;
+        int QC_TYPE_TILE =
+                CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_TILE;
+        int QC_TYPE_SLIDER =
+                CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_SLIDER;
+        int QC_TYPE_ACTION_SWITCH =
+                CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_ACTION_SWITCH;
+        int QC_TYPE_ACTION_TOGGLE =
+                CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_ACTION_TOGGLE;
+    }
+
+    /**
+     * Returns the current logging instance of StatsLogHelper to write this devices'
+     * CarQcLibStatsModule.
+     *
+     * @return the logging instance of StatsLogHelper.
+     */
+    public static StatsLogHelper getInstance() {
+        if (sInstance == null) {
+            sInstance = new StatsLogHelper();
+        }
+        return sInstance;
+    }
+
+    /**
+     * Writes to CarQcLibEvent atom with all the optional fields filled.
+     *
+     * @param qcHashedTag         the tag of the QC
+     * @param qcElementType one of {@link QcElementType}
+     * @param qcValue         the current value of the QC element
+     * @param qcState         the current state of the QC element
+     */
+    private void writeCarQcLibEventReported(int packageUid, String qcHashedTag, int qcElementType,
+            int qcValue, boolean qcState) {
+        if (Build.isDebuggable()) {
+            Log.v(TAG, "writing CAR_QC_LIB_EVENT_REPORTED. packageUid=" + packageUid
+                    + ", qcHashedTag=" + qcHashedTag + ", qcElementType= " + qcElementType
+                    + ", qcValue=" + qcValue + ", qcState=" + qcState);
+        }
+        CarQcLibStatsLog.write(
+            /* atomId */ CarQcLibStatsLog.CAR_QC_LIB_EVENT_REPORTED,
+            /* packageUid */ packageUid,
+            /* qcHashedTag */ qcHashedTag,
+            /* qcElementType */ qcElementType,
+            /* qcValue */ qcValue,
+            /* qcState */ qcState);
+    }
+
+    /**
+     * Logs that there is an interaction on QC elements
+     */
+    public void logMetrics(QCItem item, Intent intent) {
+        // if we can't find package uid or tag, we don't need any metrics
+        if (item.getPackageUid() == 0 || item.getTag().isEmpty()) {
+            return;
+        }
+        int value = DEFAULT_VALUE;
+        boolean state = DEFAULT_STATE;
+        if (intent != null) {
+            Bundle bundle = intent.getExtras();
+            if (bundle != null) {
+                String type = item.getType();
+                if (type.equals(QC_TYPE_ACTION_SWITCH)
+                        || type.equals(QC_TYPE_TILE)
+                        || type.equals(QC_TYPE_ACTION_TOGGLE)) {
+                    state = bundle.getBoolean(QC_ACTION_TOGGLE_STATE);
+                } else if (item.getType().equals(QC_TYPE_SLIDER)) {
+                    int i = bundle.getInt(QC_ACTION_SLIDER_VALUE);
+                    value = ((QCSlider) item).getSliderValueInPercentage(i);
+                }
+            }
+            writeCarQcLibEventReported(item.getPackageUid(), item.getTag(),
+                    convertStringToIntQcType(item.getType()),
+                    /* value= */ value, /* state= */ state);
+            return;
+        }
+        if (item.getType().equals(QC_TYPE_ROW) || item.getType().equals(QC_TYPE_TILE)) {
+            if (item.getDisabledClickAction() != null || item.getPrimaryAction() != null) {
+                writeCarQcLibEventReported(item.getPackageUid(), item.getTag(),
+                        convertStringToIntQcType(item.getType()),
+                        /* value= */ DEFAULT_VALUE, /* state= */ DEFAULT_STATE);
+            }
+        }
+    }
+
+    private int convertStringToIntQcType(String qcType) {
+        switch (qcType) {
+            case QCItem.QC_TYPE_LIST -> {
+                return CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_LIST;
+            }
+            case QC_TYPE_ROW -> {
+                return CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_ROW;
+            }
+            case QCItem.QC_TYPE_TILE -> {
+                return CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_TILE;
+            }
+            case QCItem.QC_TYPE_SLIDER -> {
+                return CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_SLIDER;
+            }
+            case QCItem.QC_TYPE_ACTION_SWITCH -> {
+                return CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_ACTION_SWITCH;
+            }
+            case QCItem.QC_TYPE_ACTION_TOGGLE -> {
+                return CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__QC_TYPE_ACTION_TOGGLE;
+            }
+            default -> {
+                return CarQcLibStatsLog
+                    .CAR_QC_LIB_EVENT_REPORTED__ELEMENT_TYPE__UNSPECIFIED_ELEMENT_TYPE;
+            }
+        }
+    }
+}
diff --git a/car-qc-lib/src/com/android/car/qc/view/QCRowView.java b/car-qc-lib/src/com/android/car/qc/view/QCRowView.java
index acbdc70..efbb7f5 100644
--- a/car-qc-lib/src/com/android/car/qc/view/QCRowView.java
+++ b/car-qc-lib/src/com/android/car/qc/view/QCRowView.java
@@ -21,6 +21,7 @@ import static com.android.car.qc.QCItem.QC_ACTION_TOGGLE_STATE;
 import static com.android.car.qc.QCItem.QC_TYPE_ACTION_SWITCH;
 import static com.android.car.qc.view.QCView.QCActionListener;
 
+import android.app.ActivityOptions;
 import android.app.PendingIntent;
 import android.content.Context;
 import android.content.Intent;
@@ -54,6 +55,7 @@ import com.android.car.qc.QCItem;
 import com.android.car.qc.QCRow;
 import com.android.car.qc.QCSlider;
 import com.android.car.qc.R;
+import com.android.car.qc.StatsLogHelper;
 import com.android.car.ui.utils.CarUiUtils;
 import com.android.car.ui.utils.DirectManipulationHelper;
 import com.android.car.ui.uxr.DrawableStateToggleButton;
@@ -464,10 +466,18 @@ public class QCRowView extends FrameLayout {
         if (!item.isEnabled()) {
             if (item.getDisabledClickAction() != null) {
                 try {
-                    item.getDisabledClickAction().send(getContext(), 0, intent);
+                    item.getDisabledClickAction().send(getContext(), 0, intent,
+                            /* requestCode= */ null,
+                            /* fillInIntent= */ null,
+                            /* options= */ null,
+                            ActivityOptions.makeBasic()
+                                .setPendingIntentBackgroundActivityStartMode(
+                                    ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED)
+                                .toBundle());
                     if (mActionListener != null) {
                         mActionListener.onQCAction(item, item.getDisabledClickAction());
                     }
+                    StatsLogHelper.getInstance().logMetrics(item, intent);
                 } catch (PendingIntent.CanceledException e) {
                     Log.d(TAG, "Error sending intent", e);
                 }
@@ -476,16 +486,25 @@ public class QCRowView extends FrameLayout {
                 if (mActionListener != null) {
                     mActionListener.onQCAction(item, item.getDisabledClickActionHandler());
                 }
+                StatsLogHelper.getInstance().logMetrics(item, intent);
             }
             return;
         }
 
         if (item.getPrimaryAction() != null) {
             try {
-                item.getPrimaryAction().send(getContext(), 0, intent);
+                item.getPrimaryAction().send(getContext(), 0, intent,
+                        /* requestCode= */ null,
+                        /* fillInIntent= */ null,
+                        /* options= */ null,
+                        ActivityOptions.makeBasic()
+                            .setPendingIntentBackgroundActivityStartMode(
+                                ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED)
+                            .toBundle());
                 if (mActionListener != null) {
                     mActionListener.onQCAction(item, item.getPrimaryAction());
                 }
+                StatsLogHelper.getInstance().logMetrics(item, intent);
             } catch (PendingIntent.CanceledException e) {
                 Log.d(TAG, "Error sending intent", e);
             }
@@ -494,6 +513,7 @@ public class QCRowView extends FrameLayout {
             if (mActionListener != null) {
                 mActionListener.onQCAction(item, item.getActionHandler());
             }
+            StatsLogHelper.getInstance().logMetrics(item, intent);
         }
     }
 
diff --git a/car-qc-lib/src/com/android/car/qc/view/QCTileView.java b/car-qc-lib/src/com/android/car/qc/view/QCTileView.java
index 4173e25..4cf50bd 100644
--- a/car-qc-lib/src/com/android/car/qc/view/QCTileView.java
+++ b/car-qc-lib/src/com/android/car/qc/view/QCTileView.java
@@ -19,6 +19,7 @@ package com.android.car.qc.view;
 import static com.android.car.qc.QCItem.QC_ACTION_TOGGLE_STATE;
 import static com.android.car.qc.view.QCView.QCActionListener;
 
+import android.app.ActivityOptions;
 import android.app.PendingIntent;
 import android.content.Context;
 import android.content.Intent;
@@ -34,6 +35,7 @@ import androidx.lifecycle.Observer;
 import com.android.car.qc.QCItem;
 import com.android.car.qc.QCTile;
 import com.android.car.qc.R;
+import com.android.car.qc.StatsLogHelper;
 import com.android.car.ui.utils.CarUiUtils;
 import com.android.car.ui.uxr.DrawableStateToggleButton;
 
@@ -107,19 +109,30 @@ public class QCTileView extends FrameLayout implements Observer<QCItem> {
             if (!qcTile.isEnabled()) {
                 if (qcTile.getDisabledClickAction() != null) {
                     try {
-                        qcTile.getDisabledClickAction().send(getContext(), 0, new Intent());
+                        Intent intent = new Intent();
+                        qcTile.getDisabledClickAction().send(getContext(), 0, intent,
+                            /* requestCode= */ null,
+                            /* fillInIntent= */ null,
+                            /* options= */ null,
+                                ActivityOptions.makeBasic()
+                                    .setPendingIntentBackgroundActivityStartMode(
+                                        ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED)
+                                    .toBundle());
                         if (mActionListener != null) {
                             mActionListener.onQCAction(qcTile, qcTile.getDisabledClickAction());
                         }
+                        StatsLogHelper.getInstance().logMetrics(qcTile, intent);
                     } catch (PendingIntent.CanceledException e) {
                         Log.d(TAG, "Error sending intent", e);
                     }
                 } else if (qcTile.getDisabledClickActionHandler() != null) {
+                    Intent intent = new Intent();
                     qcTile.getDisabledClickActionHandler().onAction(qcTile, getContext(),
-                            new Intent());
+                            intent);
                     if (mActionListener != null) {
                         mActionListener.onQCAction(qcTile, qcTile.getDisabledClickActionHandler());
                     }
+                    StatsLogHelper.getInstance().logMetrics(qcTile, intent);
                 }
                 return;
             }
@@ -133,10 +146,18 @@ public class QCTileView extends FrameLayout implements Observer<QCItem> {
                     intent.putExtra(QC_ACTION_TOGGLE_STATE, isChecked);
                     if (qcTile.getPrimaryAction() != null) {
                         try {
-                            qcTile.getPrimaryAction().send(getContext(), 0, intent);
+                            qcTile.getPrimaryAction().send(getContext(), 0, intent,
+                                /* requestCode= */ null,
+                                /* fillInIntent= */ null,
+                                /* options= */ null,
+                                    ActivityOptions.makeBasic()
+                                        .setPendingIntentBackgroundActivityStartMode(
+                                            ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED)
+                                        .toBundle());
                             if (mActionListener != null) {
                                 mActionListener.onQCAction(qcTile, qcTile.getPrimaryAction());
                             }
+                            StatsLogHelper.getInstance().logMetrics(qcTile, intent);
                         } catch (PendingIntent.CanceledException e) {
                             Log.d(TAG, "Error sending intent", e);
                         }
@@ -145,6 +166,7 @@ public class QCTileView extends FrameLayout implements Observer<QCItem> {
                         if (mActionListener != null) {
                             mActionListener.onQCAction(qcTile, qcTile.getActionHandler());
                         }
+                        StatsLogHelper.getInstance().logMetrics(qcTile, intent);
                     }
                 });
     }
diff --git a/car-scalable-ui-lib/Android.bp b/car-scalable-ui-lib/Android.bp
new file mode 100644
index 0000000..23f8ec7
--- /dev/null
+++ b/car-scalable-ui-lib/Android.bp
@@ -0,0 +1,29 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_library {
+    name: "car-scalable-ui-lib",
+    srcs: ["src/**/*.java"],
+    optimize: {
+        enabled: true,
+    },
+    static_libs: [
+        "androidx.annotation_annotation",
+    ],
+}
diff --git a/car-scalable-ui-lib/AndroidManifest.xml b/car-scalable-ui-lib/AndroidManifest.xml
new file mode 100644
index 0000000..d7d9bdc
--- /dev/null
+++ b/car-scalable-ui-lib/AndroidManifest.xml
@@ -0,0 +1,19 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+          package="com.android.car.scalableui">
+</manifest>
diff --git a/car-scalable-ui-lib/OWNERS b/car-scalable-ui-lib/OWNERS
new file mode 100644
index 0000000..1ae9fdc
--- /dev/null
+++ b/car-scalable-ui-lib/OWNERS
@@ -0,0 +1,9 @@
+# People who can approve changes for submission.
+
+# Primary
+babakbo@google.com
+
+# Secondary (only if people in Primary are unreachable)
+alexstetson@google.com
+priyanksingh@google.com
+calhuang@google.com
diff --git a/car-scalable-ui-lib/PREUPLOAD.cfg b/car-scalable-ui-lib/PREUPLOAD.cfg
new file mode 100644
index 0000000..38f9800
--- /dev/null
+++ b/car-scalable-ui-lib/PREUPLOAD.cfg
@@ -0,0 +1,7 @@
+[Hook Scripts]
+checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
+ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py -f ${PREUPLOAD_FILES}
+
+[Builtin Hooks]
+commit_msg_changeid_field = true
+commit_msg_test_field = true
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/Event.java b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/Event.java
new file mode 100644
index 0000000..6c40986
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/Event.java
@@ -0,0 +1,63 @@
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
+package com.android.car.scalableui.manager;
+
+/**
+ * Describes an event in the system. An event can optionally carry a payload object.
+ */
+public class Event {
+    private final String mId;
+    private final Object mPayload;
+
+    /**
+     * Constructs an Event without a payload.
+     *
+     * @param id A unique identifier associated with this event.
+     */
+    public Event(String id) {
+        this(id, null);
+    }
+
+    /**
+     * Constructs an Event with an optional payload.
+     *
+     * @param id A unique identifier associated with this event.
+     * @param payload An optional payload associated with this event.
+     */
+    public Event(String id, Object payload) {
+        mId = id;
+        mPayload = payload;
+    }
+
+    /**
+     * Returns the event identifier.
+     *
+     * @return The event identifier.
+     */
+    public String getId() {
+        return mId;
+    }
+
+    /**
+     * Returns the payload associated with this event.
+     *
+     * @return The payload of the event, or null if no payload is associated.
+     */
+    public Object getPayload() {
+        return mPayload;
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/EventDispatcher.java b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/EventDispatcher.java
new file mode 100644
index 0000000..9543939
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/EventDispatcher.java
@@ -0,0 +1,52 @@
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
+package com.android.car.scalableui.manager;
+
+/**
+ * A utility class for dispatching events. This class provides methods for dispatching events with
+ * or without payloads. All events are handled by the {@link StateManager}.
+ */
+public class EventDispatcher {
+
+    /**
+     * Dispatches an event without a payload.
+     *
+     * @param eventId The id of the event that needs to be dispatched.
+     */
+    public static void dispatch(String eventId) {
+        dispatch(eventId, null);
+    }
+
+    /**
+     * Dispatches an event with a given payload.
+     *
+     * @param eventId The id of the event that needs to be dispatched.
+     * @param payload The payload associated with the event. Can be any Java object.
+     */
+    public static void dispatch(String eventId, Object payload) {
+        dispatch(new Event(eventId, payload));
+    }
+
+    /**
+     * Dispatches a given event.
+     *
+     * @param event The event object to be dispatched.
+     */
+    public static void dispatch(Event event) {
+        StateManager.handleEvent(event);
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/StateManager.java b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/StateManager.java
new file mode 100644
index 0000000..e3f6626
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/StateManager.java
@@ -0,0 +1,116 @@
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
+package com.android.car.scalableui.manager;
+
+import android.animation.Animator;
+import android.animation.AnimatorListenerAdapter;
+
+import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.model.Transition;
+import com.android.car.scalableui.model.Variant;
+import com.android.car.scalableui.panel.Panel;
+import com.android.car.scalableui.panel.PanelPool;
+
+import java.util.ArrayList;
+import java.util.List;
+
+/**
+ * Manages the state of UI panels. This class is responsible for loading panel definitions,
+ * handling events that trigger state transitions, and applying visual updates to panels
+ * based on their current state.
+ */
+public class StateManager {
+
+    private static final StateManager sInstance = new StateManager();
+
+    private StateManager() {}
+
+    private final List<PanelState> mPanels = new ArrayList<>();
+
+    /**
+     * Adds a new panel state definition.
+     *
+     * @param panel The panel state to be added.
+     */
+    public static void addState(PanelState panel) {
+        sInstance.mPanels.add(panel);
+        applyState(panel);
+    }
+
+    /**
+     * Resets the state manager by clearing all panel definitions.
+     */
+    public static void reset() {
+        sInstance.mPanels.clear();
+    }
+
+    /**
+     * Handles an event by triggering state transitions for panels with matching transitions.
+     * This method iterates through all registered panel definitions, checks if any transitions
+     * are defined for the given event, and applies the transition (including animations) if found.
+     *
+     * @param event The event to be handled.
+     */
+    static void handleEvent(Event event) {
+        for (PanelState panelState : sInstance.mPanels) {
+            Transition transition = panelState.getTransition(event);
+            if (transition == null) {
+                continue;
+            }
+
+            Panel panel = PanelPool.getInstance().getPanel(panelState.getId());
+            Animator animator = transition.getAnimator(panel, panelState.getCurrentVariant());
+            if (animator != null) {
+                // Update the internal state to the new variant and show the transition animation
+                panelState.onAnimationStart(animator);
+                panelState.setVariant(transition.getToVariant().getId(), event.getPayload());
+                animator.removeAllListeners();
+                animator.addListener(new AnimatorListenerAdapter() {
+                    @Override
+                    public void onAnimationEnd(Animator animation) {
+                        super.onAnimationEnd(animation);
+                        panelState.onAnimationEnd();
+                        applyState(panelState);
+                    }
+                });
+                animator.start();
+            } else if (!panelState.isAnimating()) {
+                // Force apply the new state if there is no on going animation.
+                Variant toVariant = transition.getToVariant();
+                panelState.setVariant(toVariant.getId(), event.getPayload());
+                applyState(panelState);
+            }
+        }
+    }
+
+    /**
+     * Applies the current state of a panel to the UI. This method updates the panel's
+     * visual properties (bounds, visibility, alpha, layer) based on its current variant.
+     *
+     * @param panelState The panel data containing the current state information.
+     */
+    private static void applyState(PanelState panelState) {
+        Variant variant = panelState.getCurrentVariant();
+        String panelId = panelState.getId();
+        Panel panel = PanelPool.getInstance().getPanel(panelId);
+        panel.setRole(panelState.getRole().getValue());
+        panel.setBounds(variant.getBounds());
+        panel.setVisibility(variant.isVisible());
+        panel.setAlpha(variant.getAlpha());
+        panel.setLayer(variant.getLayer());
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Alpha.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Alpha.java
new file mode 100644
index 0000000..ab70d3d
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Alpha.java
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
+
+package com.android.car.scalableui.model;
+
+import android.util.AttributeSet;
+import android.util.Xml;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+/**
+ * Represents the alpha (transparency) value of a UI element. This class provides methods for
+ * creating an Alpha object from an XML definition and retrieving the alpha value.
+ */
+class Alpha {
+    static final String ALPHA_TAG = "Alpha";
+    private static final String ALPHA_ATTRIBUTE = "alpha";
+    static final float DEFAULT_ALPHA = 1;
+
+    private final float mAlpha;
+
+    /**
+     * Constructs an Alpha object with the specified alpha value.
+     *
+     * @param alpha The alpha value, between 0 (fully transparent) and 1 (fully opaque).
+     */
+    Alpha(float alpha) {
+        mAlpha = alpha;
+    }
+
+    /**
+     * Returns the alpha value.
+     *
+     * @return The alpha value.
+     */
+    public float getAlpha() {
+        return mAlpha;
+    }
+
+    /**
+     * Creates an Alpha object from an XML parser.
+     *
+     * This method parses an XML element with the tag "Alpha" and extracts the "alpha" attribute
+     * to create an Alpha object. If the "alpha" attribute is not specified, it defaults to 1.0.
+     *
+     * @param parser The XML parser.
+     * @return An Alpha object with the parsed alpha value.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    static Alpha create(XmlPullParser parser) throws XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, ALPHA_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        float alpha = attrs.getAttributeFloatValue(null, ALPHA_ATTRIBUTE, DEFAULT_ALPHA);
+        parser.nextTag();
+        parser.require(XmlPullParser.END_TAG, null, ALPHA_TAG);
+        return new Alpha(alpha);
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Bounds.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Bounds.java
new file mode 100644
index 0000000..13041b0
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Bounds.java
@@ -0,0 +1,168 @@
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
+package com.android.car.scalableui.model;
+
+import android.content.Context;
+import android.content.res.Resources;
+import android.graphics.Rect;
+import android.util.AttributeSet;
+import android.util.DisplayMetrics;
+import android.util.Xml;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+
+/**
+ * Represents the bounds of a UI element. This class provides methods for creating a Bounds object
+ * from an XML definition and retrieving the bounds as a {@link Rect}.
+ *
+ * <p>The Bounds class supports defining dimensions in the following formats:
+ * <ul>
+ *     <li><b>Absolute pixels:</b> e.g., <code>left="100"</code></li>
+ *     <li><b>Density-independent pixels (dp):</b> e.g., <code>top="50dip"</code></li>
+ *     <li><b>Percentage of screen width/height:</b> e.g., <code>right="80%"</code></li>
+ *     <li><b>Resource references:</b> e.g., <code>bottom="@dimen/my_bottom_margin"</code></li>
+ * </ul>
+ *
+ * <p>It also allows defining either the left and right positions, or the left position and width.
+ * Similarly, it allows defining either the top and bottom positions, or the top position and
+ * height.
+ */
+class Bounds {
+    static final String BOUNDS_TAG = "Bounds";
+    private static final String LEFT_ATTRIBUTE = "left";
+    private static final String RIGHT_ATTRIBUTE = "right";
+    private static final String TOP_ATTRIBUTE = "top";
+    private static final String BOTTOM_ATTRIBUTE = "bottom";
+    private static final String WIDTH_ATTRIBUTE = "width";
+    private static final String HEIGHT_ATTRIBUTE = "height";
+    private static final String DIP = "dip";
+    private static final String DP = "dp";
+    private static final String PERCENT = "%";
+    private final int mLeft;
+    private final int mTop;
+    private final int mRight;
+    private final int mBottom;
+
+    /**
+     * Constructs a Bounds object with the specified left, top, right, and bottom positions.
+     *
+     * @param left The left position in pixels.
+     * @param top The top position in pixels.
+     * @param right The right position in pixels.
+     * @param bottom The bottom position in pixels.
+     */
+    Bounds(int left, int top, int right, int bottom) {
+        mLeft = left;
+        mTop = top;
+        mRight = right;
+        mBottom = bottom;
+    }
+
+    /**
+     * Returns the bounds as a {@link Rect} object.
+     *
+     * @return A Rect object representing the bounds.
+     */
+    public Rect getRect() {
+        return new Rect(mLeft, mTop, mRight, mBottom);
+    }
+
+    /**
+     * Creates a Bounds object from an XML parser.
+     *
+     * <p>This method parses an XML element with the tag "Bounds" and extracts the "left", "top",
+     * "right", and "bottom" attributes (or equivalent width/height combinations) to create a
+     * Bounds object.
+     *
+     * @param context The application context.
+     * @param parser The XML parser.
+     * @return A Bounds object with the parsed bounds.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    static Bounds create(Context context, XmlPullParser parser) throws XmlPullParserException,
+            IOException {
+        parser.require(XmlPullParser.START_TAG, null, BOUNDS_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        int left = getDimensionPixelSize(context, attrs, LEFT_ATTRIBUTE, true);
+        int top = getDimensionPixelSize(context, attrs,  TOP_ATTRIBUTE, false);
+        int right = getDimensionPixelSize(context, attrs, RIGHT_ATTRIBUTE, true);
+        int bottom = getDimensionPixelSize(context, attrs, BOTTOM_ATTRIBUTE, false);
+
+        int width = getDimensionPixelSize(context, attrs, WIDTH_ATTRIBUTE, true);
+        int height = getDimensionPixelSize(context, attrs, HEIGHT_ATTRIBUTE, false);
+        if (attrs.getAttributeValue(null, RIGHT_ATTRIBUTE) == null) {
+            right = left + width;
+        } else if (attrs.getAttributeValue(null, LEFT_ATTRIBUTE) == null) {
+            left = right - width;
+        }
+        if (attrs.getAttributeValue(null, BOTTOM_ATTRIBUTE) == null) {
+            bottom = top + height;
+        } else if (attrs.getAttributeValue(null, TOP_ATTRIBUTE) == null) {
+            top = bottom - height;
+        }
+
+        parser.nextTag();
+        parser.require(XmlPullParser.END_TAG, null, BOUNDS_TAG);
+        return new Bounds(left, top, right, bottom);
+    }
+
+    /**
+     * Helper method to get a dimension pixel size from an attribute set.
+     *
+     * @param context The application context.
+     * @param attrs The attribute set.
+     * @param name The name of the attribute.
+     * @param isHorizontal Whether the dimension is horizontal (width) or vertical (height).
+     * @return The dimension pixel size.
+     */
+    private static int getDimensionPixelSize(Context context, AttributeSet attrs, String name,
+            boolean isHorizontal) {
+        int resId = attrs.getAttributeResourceValue(null, name, 0);
+        if (resId != 0) {
+            return context.getResources().getDimensionPixelSize(resId);
+        }
+        String dimenStr = attrs.getAttributeValue(null, name);
+        if (dimenStr == null) {
+            return 0;
+        }
+        if (dimenStr.toLowerCase().endsWith(DP)) {
+            String valueStr = dimenStr.substring(0, dimenStr.length() - DP.length());
+            float value = Float.parseFloat(valueStr);
+            return (int) (value * Resources.getSystem().getDisplayMetrics().density);
+        } else if (dimenStr.toLowerCase().endsWith(DIP)) {
+            String valueStr = dimenStr.substring(0, dimenStr.length() - DIP.length());
+            float value = Float.parseFloat(valueStr);
+            return (int) (value * Resources.getSystem().getDisplayMetrics().density);
+        } else if (dimenStr.toLowerCase().endsWith(PERCENT)) {
+            String valueStr = dimenStr.substring(0, dimenStr.length() - PERCENT.length());
+            float value = Float.parseFloat(valueStr);
+            DisplayMetrics displayMetrics = Resources.getSystem().getDisplayMetrics();
+            if (isHorizontal) {
+                return (int) (value * displayMetrics.widthPixels / 100);
+            } else {
+                return (int) (value * displayMetrics.heightPixels / 100);
+            }
+        } else {
+            return attrs.getAttributeIntValue(null, name, 0);
+        }
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameVariant.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameVariant.java
new file mode 100644
index 0000000..de961fc
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameVariant.java
@@ -0,0 +1,302 @@
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
+package com.android.car.scalableui.model;
+
+import android.animation.FloatEvaluator;
+import android.animation.RectEvaluator;
+import android.graphics.Rect;
+import android.util.AttributeSet;
+import android.util.Xml;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+import java.util.ArrayList;
+import java.util.Comparator;
+import java.util.List;
+import java.util.Objects;
+
+/**
+ * A {@link Variant} that interpolates between different variants based on a fraction value.
+ *
+ * <p>This class defines a series of keyframes, each associated with a {@link Variant} and a frame
+ * position. The {@link #setFraction(float)} method sets the current fraction, which determines
+ * the interpolation between keyframes.</p>
+ *
+ * <p>KeyFrameVariant allows for smooth transitions between different panel states by interpolating
+ * properties such as bounds, visibility, and alpha.
+ */
+public class KeyFrameVariant extends Variant {
+    static final String KEY_FRAME_VARIANT_TAG = "KeyFrameVariant";
+    private static final String ID_ATTRIBUTE = "id";
+    private static final String PARENT_ATTRIBUTE = "parent";
+    private static final String KEY_FRAME_TAG = "KeyFrame";
+    private static final String FRAME_ATTRIBUTE = "frame";
+    private static final String VARIANT_ATTRIBUTE = "variant";
+
+    private float mFraction;
+    private final RectEvaluator mRectEvaluator = new RectEvaluator();
+    private final FloatEvaluator mFloatEvaluator = new FloatEvaluator();
+
+    /**
+     * Represents a single keyframe in a {@link KeyFrameVariant}.
+     */
+    public static class KeyFrame {
+        int mFramePosition;
+        Variant mVariant;
+
+        /**
+         * Constructor for KeyFrame.
+         *
+         * @param framePosition The position of the keyframe (0-100).
+         * @param variant       The variant associated with this keyframe.
+         */
+        public KeyFrame(int framePosition, Variant variant) {
+            mFramePosition = framePosition;
+            mVariant = variant;
+        }
+
+        /**
+         * Reads a {@link KeyFrame} from an XMLPullParser.
+         *
+         * @param panelState The current panel state.
+         * @param parser     The XML parser.
+         * @return The created KeyFrame.
+         * @throws XmlPullParserException If an error occurs during XML parsing.
+         * @throws IOException            If an I/O error occurs while reading the XML.
+         */
+        private static KeyFrame create(PanelState panelState, XmlPullParser parser)
+                throws XmlPullParserException, IOException {
+            parser.require(XmlPullParser.START_TAG, null, KEY_FRAME_TAG);
+            AttributeSet attrs = Xml.asAttributeSet(parser);
+            int frame = attrs.getAttributeIntValue(null, FRAME_ATTRIBUTE, 0);
+            String variant = attrs.getAttributeValue(null, VARIANT_ATTRIBUTE);
+            parser.nextTag();
+            parser.require(XmlPullParser.END_TAG, null, KEY_FRAME_TAG);
+            Variant panelVariant = panelState.getVariant(variant);
+            return new KeyFrameVariant.KeyFrame(frame, panelVariant);
+        }
+    }
+
+    private final List<KeyFrame> mKeyFrames = new ArrayList<>();
+
+    /**
+     * Constructor for KeyFrameVariant.
+     *
+     * @param id     The ID of this variant.
+     * @param base The base variant to inherit properties from.
+     */
+    public KeyFrameVariant(String id, Variant base) {
+        super(id, base);
+    }
+
+    /**
+     * Adds a keyframe to this variant.
+     *
+     * @param keyFrame The keyframe to add.
+     */
+    public void addKeyFrame(KeyFrame keyFrame) {
+        mKeyFrames.add(keyFrame);
+        mKeyFrames.sort(Comparator.comparingInt(o -> o.mFramePosition));
+    }
+
+    /**
+     * Sets the current fraction for interpolation.
+     *
+     * @param fraction The fraction value (between 0 and 1).
+     */
+    public void setFraction(float fraction) {
+        mFraction = fraction;
+    }
+
+    /**
+     * Returns the interpolated bounds for the current fraction.
+     *
+     * @return The interpolated bounds.
+     */
+    public Rect getBounds() {
+        return getBounds(mFraction);
+    }
+
+    /**
+     * Returns the interpolated visibility for the current fraction.
+     *
+     * @return The interpolated visibility.
+     */
+    public boolean isVisible() {
+        return getVisibility(mFraction);
+    }
+
+    /**
+     * Returns the interpolated alpha for the current fraction.
+     *
+     * @return The interpolated alpha.
+     */
+    public float getAlpha() {
+        return getAlpha(mFraction);
+    }
+
+    /**
+     * Sets the payload for this variant.
+     *
+     * <p>The payload is expected to be a float value representing the fraction.
+     *
+     * @param payload The payload object.
+     */
+    public void setPayload(Object payload) {
+        setFraction((float) payload);
+    }
+
+    /**
+     * Finds the keyframe immediately before the given fraction.
+     *
+     * <p>This method iterates through the list of keyframes and returns the keyframe that is
+     * immediately before the given fraction. If the fraction is smaller than the first keyframe's
+     * position, the first keyframe is returned. If the fraction is larger than the last keyframe's
+     * position, the last keyframe is returned.
+     *
+     * @param fraction The fraction value (between 0 and 1).
+     * @return The keyframe before the given fraction, or null if there are no keyframes.
+     */
+    private KeyFrame before(float fraction) {
+        if (mKeyFrames.isEmpty()) return null;
+        KeyFrame current = mKeyFrames.get(0);
+        for (KeyFrame keyFrame : mKeyFrames) {
+            if (keyFrame.mFramePosition >= fraction * 100) {
+                return current;
+            }
+            current = keyFrame;
+        }
+        return current;
+    }
+
+    /**
+     * Returns the key frame after the fraction
+     * @param fraction The fraction value (between 0 and 1).
+     * @return The key frame
+     */
+    private KeyFrame after(float fraction) {
+        if (mKeyFrames.isEmpty()) return null;
+        for (KeyFrame keyFrame : mKeyFrames) {
+            if (keyFrame.mFramePosition >= fraction * 100) {
+                return keyFrame;
+            }
+        }
+        return mKeyFrames.get(mKeyFrames.size() - 1);
+    }
+
+    /**
+     * Calculates the fraction between two keyframes based on the given overall fraction.
+     *
+     * <p>This method takes two frame positions (representing keyframes) and an overall fraction
+     * value (between 0 and 1). It calculates the fraction between the two keyframes, effectively
+     * normalizing the overall fraction to the range between the keyframes.
+     *
+     * <p>For example, if framePosition1 is 20, framePosition2 is 80, and fraction is 0.5, the
+     * result will be 0.75, because 0.5 lies at 75% of the range between 20 and 80.
+     *
+     * @param framePosition1 The position of the first keyframe (0-100).
+     * @param framePosition2 The position of the second keyframe (0-100).
+     * @param fraction       The overall fraction value (between 0 and 1).
+     * @return The fraction between the two keyframes.
+     */
+    private float getKeyFrameFraction(int framePosition1, int framePosition2, float fraction) {
+        fraction = fraction * 100;
+        if (fraction <= framePosition1) return 0;
+        if (fraction >= framePosition2) return 1;
+        return (fraction - framePosition1) / (framePosition2 - framePosition1);
+    }
+
+
+    /**
+     * Returns the interpolated bounds for the given fraction.
+     *
+     * @param fraction The fraction value (between 0 and 1).
+     * @return The interpolated bounds.
+     */
+    private Rect getBounds(float fraction) {
+        if (mKeyFrames.isEmpty()) return new Rect();
+        KeyFrame keyFrame1 = before(fraction);
+        Rect bounds1 = Objects.requireNonNull(keyFrame1).mVariant.getBounds();
+        KeyFrame keyFrame2 = after(fraction);
+        Rect bounds2 = Objects.requireNonNull(keyFrame2).mVariant.getBounds();
+        float fractionInBetween = getKeyFrameFraction(keyFrame1.mFramePosition,
+                keyFrame2.mFramePosition, fraction);
+        Rect rect = mRectEvaluator.evaluate(fractionInBetween, bounds1, bounds2);
+        return new Rect(rect.left, rect.top, rect.right, rect.bottom);
+    }
+
+    /**
+     * Returns the interpolated visibility for the given fraction.
+     *
+     * @param fraction The fraction value (between 0 and 1).
+     * @return The interpolated visibility.
+     */
+    private boolean getVisibility(float fraction) {
+        if (mKeyFrames.isEmpty()) return false;
+        KeyFrame keyFrame1 = before(fraction);
+        boolean isVisible1 = Objects.requireNonNull(keyFrame1).mVariant.isVisible();
+        KeyFrame keyFrame2 = after(fraction);
+        boolean isVisible2 = Objects.requireNonNull(keyFrame2).mVariant.isVisible();
+        return isVisible1 || isVisible2;
+    }
+
+    /**
+     * Returns the interpolated alpha for the given fraction.
+     *
+     * @param fraction The fraction value (between 0 and 1).
+     * @return The interpolated alpha.
+     */
+    private float getAlpha(float fraction) {
+        if (mKeyFrames.isEmpty()) return 1;
+        KeyFrame keyFrame1 = before(fraction);
+        float alpha1 = (Objects.requireNonNull(keyFrame1).mVariant.getAlpha());
+        KeyFrame keyFrame2 = after(fraction);
+        float alpha2 = (Objects.requireNonNull(keyFrame2).mVariant.getAlpha());
+        return mFloatEvaluator.evaluate(fraction, alpha1, alpha2);
+    }
+
+    /**
+     * Creates a {@link KeyFrameVariant} from an XMLPullParser.
+     *
+     * @param panelState The current panel state.
+     * @param parser     The XML parser.
+     * @return The created KeyFrameVariant.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException            If an I/O error occurs while reading the XML.
+     */
+    static KeyFrameVariant create(PanelState panelState, XmlPullParser parser)
+            throws XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, KEY_FRAME_VARIANT_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        String id = attrs.getAttributeValue(null, ID_ATTRIBUTE);
+        String parentStr = attrs.getAttributeValue(null, PARENT_ATTRIBUTE);
+        Variant parent = panelState.getVariant(parentStr);
+        KeyFrameVariant result = new KeyFrameVariant(id, parent);
+        while (parser.next() != XmlPullParser.END_TAG) {
+            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
+            String name = parser.getName();
+            if (name.equals(KEY_FRAME_TAG)) {
+                result.addKeyFrame(KeyFrame.create(panelState, parser));
+            } else {
+                XmlPullParserHelper.skip(parser);
+            }
+        }
+        return result;
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Layer.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Layer.java
new file mode 100644
index 0000000..e587728
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Layer.java
@@ -0,0 +1,77 @@
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
+package com.android.car.scalableui.model;
+
+import android.util.AttributeSet;
+import android.util.Xml;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+/**
+ * Represents the layer of a {@code Panel}. This class provides methods for creating a Layer object
+ * from an XML definition and retrieving the layer value.
+ */
+class Layer {
+    static final String LAYER_TAG = "Layer";
+    private static final String LAYER_ATTRIBUTE = "layer";
+
+    static final int DEFAULT_LAYER = 0;
+
+    private final int mLayer;
+
+    /**
+     * Constructs a Layer object with the specified layer value.
+     *
+     * @param layer The layer value. Higher values indicate that the element should be drawn on top
+     *              of elements with lower layer values.
+     */
+    Layer(int layer) {
+        mLayer = layer;
+    }
+
+    /**
+     * Returns the layer value.
+     *
+     * @return The layer value.
+     */
+    public int getLayer() {
+        return mLayer;
+    }
+
+    /**
+     * Creates a Layer object from an XML parser.
+     *
+     * <p>This method parses an XML element with the tag "Layer" and extracts the "layer" attribute
+     * to create a Layer object. If the "layer" attribute is not specified, it defaults to 0.
+     *
+     * @param parser The XML parser.
+     * @return A Layer object with the parsed layer value.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    static Layer create(XmlPullParser parser) throws XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, LAYER_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        int layer = attrs.getAttributeIntValue(null, LAYER_ATTRIBUTE, DEFAULT_LAYER);
+        parser.nextTag();
+        parser.require(XmlPullParser.END_TAG, null, LAYER_TAG);
+        return new Layer(layer);
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelState.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelState.java
new file mode 100644
index 0000000..d8ac257
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelState.java
@@ -0,0 +1,346 @@
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
+package com.android.car.scalableui.model;
+
+import static com.android.car.scalableui.model.KeyFrameVariant.KEY_FRAME_VARIANT_TAG;
+import static com.android.car.scalableui.model.Transition.TRANSITION_TAG;
+import static com.android.car.scalableui.model.Variant.VARIANT_TAG;
+
+import android.animation.Animator;
+import android.content.Context;
+import android.content.res.XmlResourceParser;
+import android.util.AttributeSet;
+import android.util.Xml;
+import android.view.animation.AnimationUtils;
+import android.view.animation.Interpolator;
+
+import com.android.car.scalableui.manager.Event;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+import java.util.ArrayList;
+import java.util.List;
+
+/**
+ * Represents the state of a panel in the Scalable UI system.
+ *
+ * <p>A PanelState defines the different variants (layouts) that a panel can have, as well as the
+ * transitions between those variants. It also manages the current variant and any running
+ * animations.
+ */
+public class PanelState {
+    private static final String PANEL_TAG = "Panel";
+    private static final String ID_TAG = "id";
+    private static final String DEFAULT_VARIANT_ATTRIBUTE = "defaultVariant";
+    private static final String ROLE_ATTRIBUTE = "role";
+    private static final String TRANSITIONS_TAG = "Transitions";
+    private static final String DEFAULT_DURATION_ATTRIBUTE = "defaultDuration";
+    private static final String DEFAULT_INTERPOLATOR_ATTRIBUTE = "defaultInterpolator";
+    private static final int DEFAULT_TRANSITION_DURATION = 300;
+
+    /**
+     * Loads a PanelState from an XML resource.
+     *
+     * @param context    The context to use.
+     * @param resourceId The ID of the XML resource.
+     * @return The loaded PanelState.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    public static PanelState load(Context context, int resourceId) throws XmlPullParserException,
+            IOException {
+        XmlResourceParser parser = context.getResources().getXml(resourceId);
+        while (true) {
+            if (parser.next() == XmlPullParser.START_TAG) break;
+        }
+        return PanelState.create(context, parser);
+    }
+
+    private final String mId;
+    private final Role mRole;
+    private final List<Variant> mVariants = new ArrayList<>();
+    private final List<Transition> mTransitions = new ArrayList<>();
+
+    private Animator mRunningAnimator;
+    private Variant mCurrentVariant;
+
+    /**
+     * Constructor for PanelState.
+     *
+     * @param id The ID of the panel.
+     * @param role The role of the panel.
+     */
+    public PanelState(String id, Role role) {
+        mId = id;
+        mRole = role;
+    }
+
+    /**
+     * Returns the ID of the panel.
+     *
+     * @return The ID of the panel.
+     */
+    public String getId() {
+        return mId;
+    }
+
+    /**
+     * Adds a variant to the panel.
+     *
+     * @param variant The variant to add.
+     */
+    public void addVariant(Variant variant) {
+        mVariants.add(variant);
+    }
+
+    /**
+     * Adds a transition to the panel.
+     *
+     * @param transition The transition to add.
+     */
+    public void addTransition(Transition transition) {
+        mTransitions.add(transition);
+    }
+
+    /**
+     * Returns the current variant of the panel.
+     *
+     * @return The current variant of the panel.
+     */
+    public Variant getCurrentVariant() {
+        if (mCurrentVariant == null) {
+            mCurrentVariant = mVariants.get(0);
+        }
+        return mCurrentVariant;
+    }
+
+    /**
+     * Returns the variant with the given ID.
+     *
+     * @param id The ID of the variant.
+     * @return The variant with the given ID, or null if not found.
+     */
+    public Variant getVariant(String id) {
+        for (Variant variant : mVariants) {
+            if (variant.getId().equals(id)) {
+                return variant;
+            }
+        }
+        return null;
+    }
+
+    /**
+     * Sets the current variant to the variant with the given ID.
+     *
+     * @param id The ID of the variant.
+     */
+    public void setVariant(String id) {
+        setVariant(id, null);
+    }
+
+    /**
+     * Sets the current variant to the variant with the given ID and payload.
+     *
+     * @param id      The ID of the variant.
+     * @param payload The payload to pass to the variant.
+     */
+    public void setVariant(String id, Object payload) {
+        for (Variant variant : mVariants) {
+            if (variant.getId().equals(id)) {
+                mCurrentVariant = variant;
+                if (mCurrentVariant instanceof KeyFrameVariant) {
+                    ((KeyFrameVariant) mCurrentVariant).setPayload(payload);
+                }
+                return;
+            }
+        }
+    }
+
+    /**
+     * Returns the role of the panel.
+     *
+     * @return The role of the panel.
+     */
+    public Role getRole() {
+        return mRole;
+    }
+
+    /**
+     * Returns true if the panel is currently animating.
+     *
+     * @return True if the panel is currently animating.
+     */
+    public boolean isAnimating() {
+        return mRunningAnimator != null && mRunningAnimator.isRunning();
+    }
+
+    /**
+     * Should be called when an animation starts.
+     *
+     * @param animator The animator that started.
+     */
+    public void onAnimationStart(Animator animator) {
+        if (mRunningAnimator != null) {
+            mRunningAnimator.pause();
+            mRunningAnimator.removeAllListeners();
+        }
+        mRunningAnimator = animator;
+    }
+
+    /**
+     * Should be Called when an animation ends.
+     */
+    public void onAnimationEnd() {
+        mRunningAnimator = null;
+    }
+
+    /**
+     * Returns the transition for the given event.
+     *
+     * @param event The event.
+     * @return The transition for the given event, or null if not found.
+     */
+    public Transition getTransition(Event event) {
+        // If both onEvent and fromVariant matches
+        Transition result = getTransition(event.getId(), getCurrentVariant().getId());
+        if (result != null) {
+            return result;
+        }
+        // If only onEvent matches
+        return getTransition(event.getId());
+    }
+
+    /**
+     * Returns a transition that matches the given event ID and "from" variant.
+     *
+     * @param eventId The ID of the event to find a transition for.
+     * @param fromVariant The ID of the variant the transition should start from.
+     * @return The matching transition, or null if no such transition is found.
+     */
+    private Transition getTransition(String eventId, String fromVariant) {
+        for (Transition transition : mTransitions) {
+            if (eventId.equals(transition.getOnEvent())
+                    && transition.getFromVariant() != null
+                    && transition.getFromVariant().getId().equals(fromVariant)) {
+                return transition;
+            }
+        }
+        return null;
+    }
+
+    /**
+     * Returns a transition that matches the given event ID and has no "from" variant specified.
+     *
+     * @param eventId The ID of the event to find a transition for.
+     * @return The matching transition, or null if no such transition is found.
+     */
+    private Transition getTransition(String eventId) {
+        for (Transition transition : mTransitions) {
+            if (eventId.equals(transition.getOnEvent())
+                    && transition.getFromVariant() == null) {
+                return transition;
+            }
+        }
+        return null;
+    }
+
+    /**
+     * Creates a PanelState object from an XML parser.
+     *
+     * <p>This method parses an XML element with the tag "Panel" and extracts its attributes
+     * and child elements to create a Panel object.
+     *
+     * @param context The application context.
+     * @param parser The XML parser.
+     * @return A PanelState object with the parsed properties.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    private static PanelState create(Context context, XmlPullParser parser) throws
+            XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, PANEL_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        String id = attrs.getAttributeValue(null, ID_TAG);
+        String defaultVariant = attrs.getAttributeValue(null, DEFAULT_VARIANT_ATTRIBUTE);
+        int roleValue = attrs.getAttributeResourceValue(null, ROLE_ATTRIBUTE, 0);
+        PanelState result = new PanelState(id, new Role(roleValue));
+        while (parser.next() != XmlPullParser.END_TAG) {
+            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
+            String name = parser.getName();
+            switch (name) {
+                case VARIANT_TAG:
+                    Variant variant = Variant.create(context, result, parser);
+                    result.addVariant(variant);
+                    break;
+                case KEY_FRAME_VARIANT_TAG:
+                    KeyFrameVariant keyFrameVariant = KeyFrameVariant.create(result, parser);
+                    result.addVariant(keyFrameVariant);
+                    break;
+                case TRANSITIONS_TAG:
+                    List<Transition> transitions = readTransitions(context, result, parser);
+                    for (Transition transition : transitions) {
+                        result.addTransition(transition);
+                    }
+                    break;
+                default:
+                    XmlPullParserHelper.skip(parser);
+                    break;
+            }
+        }
+        result.setVariant(defaultVariant);
+        return result;
+    }
+
+    /**
+     * Reads a list of Transition objects from an XML parser.
+     *
+     * <p>This method parses an XML element with the tag "Transitions" and extracts its attributes
+     * and child transition elements.
+     *
+     * @param context The application context.
+     * @param parser The XML parser.
+     * @return A list of Transition objects with the parsed properties.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    private static List<Transition> readTransitions(Context context, PanelState panelState,
+                                                    XmlPullParser parser)
+            throws XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, TRANSITIONS_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        int duration = attrs.getAttributeIntValue(null,
+                DEFAULT_DURATION_ATTRIBUTE, DEFAULT_TRANSITION_DURATION);
+        int interpolatorRef = attrs.getAttributeResourceValue(null,
+                DEFAULT_INTERPOLATOR_ATTRIBUTE, 0);
+        Interpolator interpolator = interpolatorRef == 0 ? null :
+                AnimationUtils.loadInterpolator(context, interpolatorRef);
+
+        List<Transition> result = new ArrayList<>();
+        while (parser.next() != XmlPullParser.END_TAG) {
+            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
+
+            if (parser.getName().equals(TRANSITION_TAG)) {
+                result.add(Transition.create(context, panelState, duration, interpolator, parser));
+            } else {
+                XmlPullParserHelper.skip(parser);
+            }
+        }
+        return result;
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Role.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Role.java
new file mode 100644
index 0000000..c2d4ef7
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Role.java
@@ -0,0 +1,45 @@
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
+package com.android.car.scalableui.model;
+
+/**
+ * Represents the role of a {@code Panel} within the system.
+ *
+ * <p>This class encapsulates an integer value that signifies the role of a UI element.
+ * The specific meaning of the role value is determined by the system using it.
+ */
+public class Role {
+    private final int mValue;
+
+    /**
+     * Constructor for Role.
+     *
+     * @param value The integer value representing the role.
+     */
+    public Role(int value) {
+        mValue = value;
+    }
+
+    /**
+     * Returns the integer value representing the role.
+     *
+     * @return The integer value of the role.
+     */
+    public int getValue() {
+        return mValue;
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Transition.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Transition.java
new file mode 100644
index 0000000..d8dd997
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Transition.java
@@ -0,0 +1,165 @@
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
+package com.android.car.scalableui.model;
+
+import android.animation.Animator;
+import android.animation.AnimatorInflater;
+import android.content.Context;
+import android.util.AttributeSet;
+import android.util.Xml;
+import android.view.animation.AccelerateDecelerateInterpolator;
+import android.view.animation.Interpolator;
+
+import androidx.annotation.NonNull;
+
+import com.android.car.scalableui.panel.Panel;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+/**
+ * Represents a transition between two {@link Variant}s in the Scalable UI system.
+ *
+ * <p>A Transition defines the animation that should be used to transition from one variant to
+ * another in response to an event. It can optionally specify a specific "from" variant, a "to"
+ * variant, an event trigger, and a custom animator.
+ */
+public class Transition {
+    public static final String TRANSITION_TAG = "Transition";
+    private static final String FROM_VARIANT_ATTRIBUTE = "fromVariant";
+    private static final String TO_VARIANT_ATTRIBUTE = "toVariant";
+    private static final String ON_EVENT_ATTRIBUTE = "onEvent";
+    private static final String ANIMATOR_ATTRIBUTE = "animator";
+    private static final long DEFAULT_DURATION = 300;
+
+    private final Variant mFromVariant;
+    @NonNull
+    private final Variant mToVariant;
+    private final String mOnEvent;
+    private final Animator mAnimator;
+    private final Interpolator mDefaultInterpolator;
+    private final long mDefaultDuration;
+
+    /**
+     * Constructor for Transition.
+     *
+     * @param fromVariant The variant to transition from (can be null).
+     * @param toVariant The variant to transition to.
+     * @param onEvent The event that triggers the transition.
+     * @param animator A custom animator to use for the transition (can be null).
+     * @param defaultDuration The default duration of the transition.
+     * @param defaultInterpolator The default interpolator to use for the transition.
+     */
+    public Transition(Variant fromVariant, @NonNull Variant toVariant, String onEvent,
+            Animator animator, long defaultDuration, Interpolator defaultInterpolator) {
+        mFromVariant = fromVariant;
+        mToVariant = toVariant;
+        mAnimator = animator;
+        mOnEvent = onEvent;
+        mDefaultDuration = defaultDuration >= 0 ? defaultDuration : DEFAULT_DURATION;
+        mDefaultInterpolator = defaultInterpolator != null
+                ? defaultInterpolator
+                : new AccelerateDecelerateInterpolator();
+    }
+
+    /**
+     * Returns the "from" variant of the transition.
+     *
+     * @return The "from" variant, or null if not specified.
+     */
+    public Variant getFromVariant() {
+        return mFromVariant;
+    }
+
+    /**
+     * Returns the "to" variant of the transition.
+     *
+     * @return The "to" variant.
+     */
+    public @NonNull Variant getToVariant() {
+        return mToVariant;
+    }
+
+    /**
+     * Returns the animator for the transition.
+     *
+     * <p>If a custom animator was provided, it is cloned and returned. Otherwise, a default
+     * animator will be created to transition from "from" variant to "to" variant with the default
+     * duration and interpolator.
+     *
+     * @param panel The panel to apply the animation to.
+     * @param fromVariant The actual "from" variant of the transition.
+     * @return The animator for the transition.
+     */
+    public Animator getAnimator(Panel panel, @NonNull Variant fromVariant) {
+        if (fromVariant.getId().equals(mToVariant.getId())) {
+            return null;
+        }
+
+        if (mAnimator != null) {
+            Animator animator = this.mAnimator.clone();
+            animator.setTarget(panel);
+            return animator;
+        }
+        return fromVariant.getAnimator(panel, mToVariant, mDefaultDuration, mDefaultInterpolator);
+    }
+
+    /**
+     * Returns the event that triggers the transition.
+     *
+     * @return The event that triggers the transition.
+     */
+    public String getOnEvent() {
+        return mOnEvent;
+    }
+
+    /**
+     * Creates a Transition object from an XML parser.
+     *
+     * @param context The context to use.
+     * @param panelState The panel state that this transition belongs to.
+     * @param defaultDuration The default duration to use if not specified in the XML.
+     * @param defaultInterpolator The default interpolator to use if not specified in the XML.
+     * @param parser The XML parser.
+     * @return The created Transition object.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    public static Transition create(Context context, PanelState panelState, long defaultDuration,
+                                    Interpolator defaultInterpolator, XmlPullParser parser)
+            throws XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, TRANSITION_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+
+        String from = attrs.getAttributeValue(null, FROM_VARIANT_ATTRIBUTE);
+        String to = attrs.getAttributeValue(null, TO_VARIANT_ATTRIBUTE);
+        String onEvent = attrs.getAttributeValue(null, ON_EVENT_ATTRIBUTE);
+        int animatorId = attrs.getAttributeResourceValue(null, ANIMATOR_ATTRIBUTE, 0);
+        Animator animator = animatorId == 0
+                ? null
+                : AnimatorInflater.loadAnimator(context, animatorId);
+        Variant fromVariant = panelState.getVariant(from);
+        Variant toVariant = panelState.getVariant(to);
+        Transition result = new Transition(fromVariant, toVariant, onEvent, animator,
+                defaultDuration, defaultInterpolator);
+        parser.nextTag();
+        parser.require(XmlPullParser.END_TAG, null, TRANSITION_TAG);
+        return result;
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Variant.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Variant.java
new file mode 100644
index 0000000..ba2e1b5
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Variant.java
@@ -0,0 +1,241 @@
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
+package com.android.car.scalableui.model;
+
+import android.animation.Animator;
+import android.animation.FloatEvaluator;
+import android.animation.RectEvaluator;
+import android.animation.ValueAnimator;
+import android.content.Context;
+import android.graphics.Rect;
+import android.util.AttributeSet;
+import android.util.Xml;
+import android.view.animation.Interpolator;
+
+import com.android.car.scalableui.panel.Panel;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+/**
+ * Represents a specific visual state or variant of a {@code Panel}.
+ *
+ * <p>This class defines the visual properties of a {@code Panel}, such as its bounds,
+ * visibility, layer, and alpha. It also provides methods for creating animations
+ * to transition between different variants.
+ */
+public class Variant {
+    static final String VARIANT_TAG = "Variant";
+    private static final String ID_ATTRIBUTE = "id";
+    private static final String PARENT_ATTRIBUTE = "parent";
+
+    private final FloatEvaluator mFloatEvaluator = new FloatEvaluator();
+    private final RectEvaluator mRectEvaluator = new RectEvaluator();
+
+    private final String mId;
+    private float mAlpha;
+    private boolean mIsVisible;
+    private int mLayer;
+    private Rect mBounds;
+
+    /**
+     * Constructs a Variant object with the specified ID and optional base variant.
+     *
+     * <p>If a base variant is provided, the new variant inherits its visual properties.
+     *
+     * @param id The ID of the variant.
+     * @param base The optional base variant to inherit properties from.
+     */
+    public Variant(String id, Variant base) {
+        this.mId = id;
+        if (base != null) {
+            mBounds = base.getBounds();
+            mIsVisible = base.isVisible();
+            mLayer = base.getLayer();
+            mAlpha = base.getAlpha();
+        } else {
+            mBounds = new Rect();
+            mIsVisible = Visibility.DEFAULT_VISIBILITY;
+            mLayer = Layer.DEFAULT_LAYER;
+            mAlpha = Alpha.DEFAULT_ALPHA;
+        }
+    }
+
+    /**
+     * Returns the ID of the variant.
+     *
+     * @return The ID of the variant.
+     */
+    public String getId() {
+        return mId;
+    }
+
+    /**
+     * Creates an animator to transition from the current state of a panel to this variant.
+     *
+     * @param panel The panel to animate.
+     * @param toVariant The target variant to animate to.
+     * @param duration The duration of the animation.
+     * @param interpolator The interpolator to use for the animation.
+     * @return An animator that animates the panel's properties to the target variant.
+     */
+    public Animator getAnimator(Panel panel, Variant toVariant, long duration,
+            Interpolator interpolator) {
+        if (toVariant instanceof KeyFrameVariant) {
+            return null;
+        } else {
+            float fromAlpha = panel.getAlpha();
+            float toAlpha = toVariant.getAlpha();
+            Rect fromBounds = panel.getBounds();
+            Rect toBounds = toVariant.getBounds();
+            boolean isVisible = panel.isVisible() || toVariant.isVisible();
+            int layer = toVariant.getLayer();
+            ValueAnimator valueAnimator = ValueAnimator.ofFloat(0, 1);
+            valueAnimator.setDuration(duration);
+            valueAnimator.setInterpolator(interpolator);
+            valueAnimator.addUpdateListener(animator -> {
+                panel.setVisibility(isVisible);
+                panel.setLayer(layer);
+                float fraction = animator.getAnimatedFraction();
+                Rect bounds = mRectEvaluator.evaluate(fraction, fromBounds, toBounds);
+                panel.setBounds(bounds);
+                float alpha = mFloatEvaluator.evaluate(fraction, fromAlpha, toAlpha);
+                panel.setAlpha(alpha);
+            });
+            return valueAnimator;
+        }
+    }
+
+    /**
+     * Returns whether the variant is visible.
+     *
+     * @return True if the variant is visible, false otherwise.
+     */
+    public boolean isVisible() {
+        return mIsVisible;
+    }
+
+    /**
+     * Sets the visibility of the variant.
+     *
+     * @param isVisible True if the variant should be visible, false otherwise.
+     */
+    public void setVisibility(boolean isVisible) {
+        this.mIsVisible = isVisible;
+    }
+
+    /**
+     * Returns the layer of the variant.
+     *
+     * @return The layer of the variant.
+     */
+    public int getLayer() {
+        return mLayer;
+    }
+
+    /**
+     * Returns the alpha of the variant.
+     *
+     * @return The alpha of the variant.
+     */
+    public float getAlpha() {
+        return mAlpha;
+    }
+
+    /**
+     * Sets the alpha of the variant.
+     *
+     * @param alpha The alpha value to set.
+     */
+    public void setAlpha(float alpha) {
+        mAlpha = alpha;
+    }
+
+    /**
+     * Sets the layer of the variant.
+     *
+     * @param layer The layer value to set.
+     */
+    public void setLayer(int layer) {
+        mLayer = layer;
+    }
+
+    /**
+     * Returns the bounds of the variant.
+     *
+     * @return The bounds of the variant.
+     */
+    public Rect getBounds() {
+        return mBounds;
+    }
+
+    /**
+     * Sets the bounds of the variant.
+     *
+     * @param bounds The bounds to set.
+     */
+    public void setBounds(Rect bounds) {
+        mBounds = bounds;
+    }
+
+    /**
+     * Creates a Variant object from an XML parser.
+     *
+     * <p>This method parses an XML element with the tag "Variant" and extracts its attributes
+     * and child elements to create a Variant object.
+     *
+     * @param context The application context.
+     * @param panelState The panel data associated with this variant.
+     * @param parser The XML parser.
+     * @return A Variant object with the parsed properties.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    static Variant create(Context context, PanelState panelState, XmlPullParser parser) throws
+            XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, VARIANT_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        String id = attrs.getAttributeValue(null, ID_ATTRIBUTE);
+        String parentStr = attrs.getAttributeValue(null, PARENT_ATTRIBUTE);
+        Variant parent = panelState.getVariant(parentStr);
+        Variant result = new Variant(id, parent);
+        while (parser.next() != XmlPullParser.END_TAG) {
+            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
+            String name = parser.getName();
+            switch (name) {
+                case Visibility.VISIBILITY_TAG:
+                    result.setVisibility(Visibility.create(parser).isVisible());
+                    break;
+                case Alpha.ALPHA_TAG:
+                    result.setAlpha(Alpha.create(parser).getAlpha());
+                    break;
+                case Layer.LAYER_TAG:
+                    result.setLayer(Layer.create(parser).getLayer());
+                    break;
+                case Bounds.BOUNDS_TAG:
+                    result.setBounds(Bounds.create(context, parser).getRect());
+                    break;
+                default:
+                    XmlPullParserHelper.skip(parser);
+                    break;
+            }
+        }
+        return result;
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Visibility.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Visibility.java
new file mode 100644
index 0000000..06ac811
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Visibility.java
@@ -0,0 +1,85 @@
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
+package com.android.car.scalableui.model;
+
+import android.util.AttributeSet;
+import android.util.Xml;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+/**
+ * Represents the visibility of a Panel in the Scalable UI system.
+ *
+ * <p>This class encapsulates a boolean value indicating whether a panel is visible or not.
+ * It can be created from an XML definition or directly using a boolean value.
+ */
+public class Visibility {
+    static final String VISIBILITY_TAG = "Visibility";
+    private static final String IS_VISIBLE_ATTRIBUTE = "isVisible";
+    static final boolean DEFAULT_VISIBILITY = true;
+
+    private final boolean mIsVisible;
+
+    /**
+     * Constructor for Visibility.
+     *
+     * @param isVisible Whether the element is visible.
+     */
+    public Visibility(boolean isVisible) {
+        this.mIsVisible = isVisible;
+    }
+
+    /**
+     * Copy constructor for Visibility.
+     *
+     * @param visibility The Visibility object to copy from.
+     */
+    public Visibility(Visibility visibility) {
+        this(visibility.mIsVisible);
+    }
+
+    /**
+     * Returns whether the element is visible.
+     *
+     * @return True if the element is visible, false otherwise.
+     */
+    public boolean isVisible() {
+        return mIsVisible;
+    }
+
+    /**
+     * Creates a Visibility object from an XML parser.
+     *
+     * @param parser The XML parser.
+     * @return The created Visibility object.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    public static Visibility create(XmlPullParser parser) throws XmlPullParserException,
+            IOException {
+        parser.require(XmlPullParser.START_TAG, null, VISIBILITY_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        boolean isVisible = attrs.getAttributeBooleanValue(null, IS_VISIBLE_ATTRIBUTE,
+                DEFAULT_VISIBILITY);
+        parser.nextTag();
+        parser.require(XmlPullParser.END_TAG, null, VISIBILITY_TAG);
+        return new Visibility(isVisible);
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/XmlPullParserHelper.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/XmlPullParserHelper.java
new file mode 100644
index 0000000..a1141e5
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/XmlPullParserHelper.java
@@ -0,0 +1,49 @@
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
+package com.android.car.scalableui.model;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+/**
+ * This class provides helper methods for working with XmlPullParser.
+ */
+public class XmlPullParserHelper {
+    /**
+     * Skips an XML tag and all its contents.
+     *
+     * @param parser The XML parser.
+     * @throws XmlPullParserException If an error occurs during XML parsing.
+     * @throws IOException If an I/O error occurs while reading the XML.
+     */
+    static void skip(XmlPullParser parser) throws XmlPullParserException, IOException {
+        if (parser.getEventType() != XmlPullParser.START_TAG) throw new IllegalStateException();
+        int depth = 1;
+        while (depth != 0) {
+            switch (parser.next()) {
+                case XmlPullParser.END_TAG:
+                    depth--;
+                    break;
+                case XmlPullParser.START_TAG:
+                    depth++;
+                    break;
+            }
+        }
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/Panel.java b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/Panel.java
new file mode 100644
index 0000000..38aace1
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/Panel.java
@@ -0,0 +1,147 @@
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
+package com.android.car.scalableui.panel;
+
+import android.graphics.Rect;
+
+/**
+ * Represents a rectangular panel that can be displayed on the screen.
+ * Panels have properties such as bounds, layer, visibility, and alpha.
+ */
+public interface Panel {
+    /**
+     * Gets the bounding rectangle of this panel.
+     *
+     * @return The bounding rectangle.
+     */
+    Rect getBounds();
+
+    /**
+     * Sets the bounding rectangle of this panel.
+     *
+     * @param bounds The new bounding rectangle.
+     */
+    void setBounds(Rect bounds);
+
+    /**
+     * Gets the layer of this panel.
+     * Panels with higher layer values are drawn on top of panels with lower layer values.
+     *
+     * @return The layer of this panel.
+     */
+    int getLayer();
+
+    /**
+     * Sets the layer of this panel.
+     *
+     * @param layer The new layer of this panel.
+     */
+    void setLayer(int layer);
+
+    /**
+     * Gets the x-coordinate of the left edge of this panel.
+     *
+     * @return The x-coordinate of the left edge.
+     */
+    int getX1();
+
+    /**
+     * Sets the x-coordinate of the left edge of this panel.
+     *
+     * @param x The new x-coordinate of the left edge.
+     */
+    void setX1(int x);
+
+    /**
+     * Gets the x-coordinate of the right edge of this panel.
+     *
+     * @return The x-coordinate of the right edge.
+     */
+    int getX2();
+
+    /**
+     * Sets the x-coordinate of the right edge of this panel.
+     *
+     * @param x The new x-coordinate of the right edge.
+     */
+    void setX2(int x);
+
+    /**
+     * Gets the y-coordinate of the top edge of this panel.
+     *
+     * @return The y-coordinate of the top edge.
+     */
+    int getY1();
+
+    /**
+     * Sets the y-coordinate of the top edge of this panel.
+     *
+     * @param y The new y-coordinate of the top edge.
+     */
+    void setY1(int y);
+
+    /**
+     * Gets the y-coordinate of the bottom edge of this panel.
+     *
+     * @return The y-coordinate of the bottom edge.
+     */
+    int getY2();
+
+    /**
+     * Sets the y-coordinate of the bottom edge of this panel.
+     *
+     * @param y The new y-coordinate of the bottom edge.
+     */
+    void setY2(int y);
+
+    /**
+     * Gets the alpha value of this panel.
+     * The alpha value is a float between 0.0 (fully transparent) and 1.0 (fully opaque).
+     *
+     * @return The alpha value of this panel.
+     */
+    float getAlpha();
+
+    /**
+     * Sets the alpha value of this panel.
+     *
+     * @param alpha The new alpha value.
+     */
+    void setAlpha(float alpha);
+
+    /**
+     * Sets the visibility of this panel.
+     *
+     * @param isVisible True if the panel should be visible, false otherwise.
+     */
+    void setVisibility(boolean isVisible);
+
+    /**
+     * Checks if this panel is visible.
+     *
+     * @return True if the panel is visible, false otherwise.
+     */
+    boolean isVisible();
+
+    /**
+     * Sets the role of this panel.
+     * The role of a panel can be used to identify its purpose or function.
+     *
+     * @param role The new role of this panel.
+     */
+    void setRole(int role);
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelPool.java b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelPool.java
new file mode 100644
index 0000000..aa643fe
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelPool.java
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
+package com.android.car.scalableui.panel;
+
+import java.util.HashMap;
+
+/**
+ * A pool for managing {@link Panel} instances.
+ *
+ * <p>This class provides a centralized mechanism for creating and retrieving panels, ensuring that
+ * only one instance of a panel with a given ID exists at a time. It uses a
+ * {@link PanelCreatorDelegate} to handle the actual creation of panel instances.
+ */
+public class PanelPool {
+    private static final PanelPool sInstance = new PanelPool();
+
+    /**
+     * An instance of the {@link PanelPool}.
+     */
+    public static PanelPool getInstance() {
+        return sInstance;
+    }
+
+    /**
+     * A delegate interface for creating {@link Panel} instances.
+     */
+    public interface PanelCreatorDelegate {
+        /**
+         * Creates a panel object.
+         * @param id given identifier for the panel.
+         * @return the panel object.
+         */
+        Panel createPanel(String id);
+    }
+
+    private final HashMap<String, Panel> mPanels = new HashMap<>();
+    private PanelCreatorDelegate mDelegate;
+
+    private PanelPool() {}
+
+    /**
+     * Sets the {@link PanelCreatorDelegate} to be used for creating panel instances.
+     *
+     * @param delegate The delegate to set.
+     */
+    public void setDelegate(PanelCreatorDelegate delegate) {
+        mDelegate = delegate;
+    }
+
+    /**
+     * Clears all panels from the pool.
+     */
+    public void clearPanels() {
+        mPanels.clear();
+    }
+
+    /**
+     * Retrieves a panel with the given ID.
+     *
+     * <p>If a panel with the given ID already exists in the pool, it is returned. Otherwise, a new
+     * panel is created using the {@link PanelCreatorDelegate}, added to the pool, and returned.
+     *
+     * @param id The ID of the panel to retrieve.
+     * @return The panel with the given ID.
+     */
+    public Panel getPanel(String id) {
+        Panel panel = mPanels.get(id);
+        if (panel == null) {
+            panel = mDelegate.createPanel(id);
+            mPanels.put(id, panel);
+        }
+        return mPanels.get(id);
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelView.java b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelView.java
new file mode 100644
index 0000000..6ef93ae
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelView.java
@@ -0,0 +1,220 @@
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
+package com.android.car.scalableui.panel;
+
+import android.content.Context;
+import android.graphics.Rect;
+import android.util.AttributeSet;
+import android.view.LayoutInflater;
+import android.view.View;
+import android.view.ViewGroup;
+import android.widget.FrameLayout;
+import android.widget.ImageView;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+/**
+ * A view based implementation of a {@link Panel}.
+ */
+public class PanelView extends FrameLayout implements Panel {
+    private static final String DRAWABLE_RESOURCE_TYPE = "drawable";
+    private static final String LAYOUT_RESOURCE_TYPE = "layout";
+
+    private int mLayer = -1;
+    private int mRole = 0;
+
+    private int mImageHolderLayoutId;
+    private int mImageId;
+
+    public PanelView(@NonNull Context context) {
+        super(context);
+    }
+
+    public PanelView(@NonNull Context context, @Nullable AttributeSet attrs) {
+        super(context, attrs);
+    }
+
+    public PanelView(@NonNull Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
+        super(context, attrs, defStyleAttr);
+    }
+
+    @Override
+    public Rect getBounds() {
+        return new Rect(getLeft(), getTop(), getRight(), getBottom());
+    }
+
+    @Override
+    public void setBounds(Rect bounds) {
+        LayoutParams params = new LayoutParams(bounds.width(), bounds.height());
+        params.topMargin = bounds.top;
+        params.leftMargin = bounds.left;
+        setLayoutParams(params);
+
+        // Update left, right, top and bottom to make sure these values are correctly set before a
+        // full round of re-layout.
+        setLeft(bounds.left);
+        setRight(bounds.right);
+        setTop(bounds.top);
+        setBottom(bounds.bottom);
+    }
+
+    public int getLayer() {
+        return mLayer;
+    }
+
+    /**
+     * Sets the z-order of the panel.
+     * @param layer the required z-order.
+     */
+    public void setLayer(int layer) {
+        if (this.mLayer == layer) return;
+        this.mLayer = layer;
+        ViewGroup parent = (ViewGroup) getParent();
+        boolean isSorted = false;
+        // Make sure all the sibling PanelViews have the correct relative z-order.
+        while (!isSorted) {
+            isSorted = true;
+            int lastLayer = Integer.MAX_VALUE;
+            for (int i = parent.getChildCount() - 1; i >= 0; i--) {
+                View child = parent.getChildAt(i);
+                if (!(child instanceof PanelView panelView)) continue;
+                if (panelView.getLayer() > lastLayer) {
+                    panelView.bringToFront();
+                    isSorted = false;
+                    break;
+                }
+                lastLayer = panelView.getLayer();
+            }
+        }
+    }
+
+    public int getX1() {
+        return getLeft();
+    }
+
+    public int getX2() {
+        return getRight();
+    }
+
+    public int getY1() {
+        return getTop();
+    }
+
+    public int getY2() {
+        return getBottom();
+    }
+
+    @Override
+    public void setX1(int x) {
+        setBounds(new Rect(x, getTop(), getRight(), getBottom()));
+    }
+
+    @Override
+    public void setX2(int x) {
+        setBounds(new Rect(getLeft(), getTop(), x, getBottom()));
+    }
+
+    @Override
+    public void setY1(int y) {
+        setBounds(new Rect(getLeft(), y, getRight(), getBottom()));
+    }
+
+    @Override
+    public void setY2(int y) {
+        setBounds(new Rect(getLeft(), getTop(), getRight(), y));
+    }
+
+    /**
+     * Checks if this panel is visible.
+     *
+     * @return True if the panel is visible, false otherwise.
+     */
+    public boolean isVisible() {
+        return super.getVisibility() == VISIBLE;
+    }
+
+    /**
+     * Sets the visibility of this panel.
+     *
+     * @param isVisible True if the panel should be visible, false otherwise.
+     */
+    public void setVisibility(boolean isVisible) {
+        super.setVisibility(isVisible ? VISIBLE : INVISIBLE);
+    }
+
+    /**
+     * Gets the alpha value of this panel.
+     * The alpha value is a float between 0.0 (fully transparent) and 1.0 (fully opaque).
+     *
+     * @return The alpha value of this panel.
+     */
+    public float getAlpha() {
+        return super.getAlpha();
+    }
+
+    /**
+     * Sets the alpha value of this panel.
+     *
+     * @param alpha The new alpha value.
+     */
+    public void setAlpha(float alpha) {
+        super.setAlpha(alpha);
+    }
+
+    public void setImageHolderLayoutId(int imageHolderLayoutId) {
+        this.mImageHolderLayoutId = imageHolderLayoutId;
+    }
+
+    public void setImageId(int imageId) {
+        this.mImageId = imageId;
+    }
+
+    /**
+     * Sets the role of this panel.
+     * The role of a panel can be used to identify its purpose or function.
+     *
+     * @param role The new role of this panel.
+     */
+    public void setRole(int role) {
+        if (this.mRole == role) return;
+        this.mRole = role;
+        if (isDrawableRole(role)) {
+            LayoutInflater inflater = LayoutInflater.from(getContext());
+            View view = inflater.inflate(mImageHolderLayoutId, this, true);
+            ImageView imageView = view.findViewById(mImageId);
+            if (imageView != null) {
+                imageView.setImageResource(role);
+            }
+        } else if (isLayoutRole(role)) {
+            LayoutInflater inflater = LayoutInflater.from(getContext());
+            inflater.inflate(role, this, true);
+        } else {
+            throw new UnsupportedOperationException("Specified role is not supported");
+        }
+    }
+
+    private boolean isDrawableRole(int role) {
+        String resourceTypeName = getContext().getResources().getResourceTypeName(role);
+        return DRAWABLE_RESOURCE_TYPE.equals(resourceTypeName);
+    }
+
+    private boolean isLayoutRole(int role) {
+        String resourceTypeName = getContext().getResources().getResourceTypeName(role);
+        return LAYOUT_RESOURCE_TYPE.equals(resourceTypeName);
+    }
+}
```

