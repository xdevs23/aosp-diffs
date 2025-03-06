```diff
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/EarfcnRangeWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/EarfcnRangeWrapper.java
new file mode 100644
index 0000000..b2f9821
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/EarfcnRangeWrapper.java
@@ -0,0 +1,139 @@
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
+package android.telephony.satellite.wrapper;
+
+import android.annotation.FlaggedApi;
+import android.annotation.IntRange;
+import android.annotation.NonNull;
+import android.os.Parcel;
+import android.os.Parcelable;
+
+import com.android.internal.telephony.flags.Flags;
+
+import java.util.Objects;
+
+/**
+ * EARFCN (E-UTRA Absolute Radio Frequency Channel Number):  A number that identifies a
+ * specific frequency channel in LTE/5G NR, used to define the carrier frequency.
+ * The range can be [0 ~ 65535] according to the 3GPP TS 36.101
+ *
+ * In satellite communication:
+ * - Efficient frequency allocation across a wide coverage area.
+ * - Handles Doppler shift due to satellite movement.
+ * - Manages interference with terrestrial networks.
+ *
+ * See 3GPP TS 36.101 and 38.101-1 for details.
+ *
+ * @hide
+ */
+public class EarfcnRangeWrapper implements Parcelable {
+
+    /**
+     * The start frequency of the earfcn range and is inclusive in the range
+     */
+    private int mStartEarfcn;
+
+    /**
+     * The end frequency of the earfcn range and is inclusive in the range.
+     */
+    private int mEndEarfcn;
+
+    private EarfcnRangeWrapper(@NonNull Parcel in) {
+        readFromParcel(in);
+    }
+
+    @Override
+    public void writeToParcel(@NonNull Parcel dest, int flags) {
+        dest.writeInt(mStartEarfcn);
+        dest.writeInt(mEndEarfcn);
+    }
+
+    private void readFromParcel(Parcel in) {
+        mStartEarfcn = in.readInt();
+        mEndEarfcn = in.readInt();
+    }
+
+    /**
+     * Constructor for the EarfcnRangeWrapper class.
+     * The range can be [0 ~ 65535] according to the 3GPP TS 36.101
+     *
+     * @param startEarfcn The starting earfcn value.
+     * @param endEarfcn   The ending earfcn value.
+     */
+    public EarfcnRangeWrapper(@IntRange(from = 0, to = 65535) int startEarfcn,
+            @IntRange(from = 0, to = 65535) int endEarfcn) {
+        mStartEarfcn = startEarfcn;
+        mEndEarfcn = endEarfcn;
+    }
+
+    @Override
+    public int describeContents() {
+        return 0;
+    }
+
+    @Override
+    @NonNull
+    public String toString() {
+        return "startEarfcn: " + mStartEarfcn + ", " + "endEarfcn: " + mEndEarfcn;
+    }
+
+    @NonNull
+    public static final Creator<EarfcnRangeWrapper> CREATOR = new Creator<EarfcnRangeWrapper>() {
+        @Override
+        public EarfcnRangeWrapper createFromParcel(Parcel in) {
+            return new EarfcnRangeWrapper(in);
+        }
+
+        @Override
+        public EarfcnRangeWrapper[] newArray(int size) {
+            return new EarfcnRangeWrapper[size];
+        }
+    };
+
+    /**
+     * Returns the starting earfcn value for this range.
+     * It can be [0 ~ 65535] according to the 3GPP TS 36.101
+     *
+     * @return The starting earfcn.
+     */
+    public @IntRange(from = 0, to = 65535) int getStartEarfcn() {
+        return mStartEarfcn;
+    }
+
+    /**
+     * Returns the ending earfcn value for this range.
+     * It can be [0 ~ 65535] according to the 3GPP TS 36.101
+     *
+     * @return The ending earfcn.
+     */
+    public @IntRange(from = 0, to = 65535) int getEndEarfcn() {
+        return mEndEarfcn;
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof EarfcnRangeWrapper that)) return false;
+
+        return (that.mStartEarfcn == mStartEarfcn) && (that.mEndEarfcn == mEndEarfcn);
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(mStartEarfcn, mEndEarfcn);
+    }
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteAccessConfigurationWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteAccessConfigurationWrapper.java
new file mode 100644
index 0000000..694a2be
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteAccessConfigurationWrapper.java
@@ -0,0 +1,142 @@
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
+package android.telephony.satellite.wrapper;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+
+import androidx.annotation.NonNull;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.Objects;
+
+/**
+ * SatelliteAccessConfigurationWrapper is used to store satellite access configuration
+ * that will be applied to the satellite communication at the corresponding region.
+ *
+ * @hide
+ */
+public class SatelliteAccessConfigurationWrapper implements Parcelable {
+    /**
+     * The list of satellites available at the current location.
+     */
+    @NonNull
+    private List<SatelliteInfoWrapper> mSatelliteInfoList;
+
+    /**
+     * The list of tag IDs associated with the current location
+     */
+    @NonNull
+    private List<Integer> mTagIdList;
+
+    /**
+     * Constructor for {@link SatelliteAccessConfigurationWrapper}.
+     *
+     * @param satelliteInfos The list of {@link SatelliteInfoWrapper} objects representing
+     *                       the satellites accessible with this configuration.
+     * @param tagidList      The list of tag IDs associated with this configuration.
+     */
+    public SatelliteAccessConfigurationWrapper(@NonNull List<SatelliteInfoWrapper> satelliteInfos,
+            @NonNull List<Integer> tagidList) {
+        mSatelliteInfoList = satelliteInfos;
+        mTagIdList = tagidList;
+    }
+
+    public SatelliteAccessConfigurationWrapper(Parcel in) {
+        mSatelliteInfoList = in.createTypedArrayList(SatelliteInfoWrapper.CREATOR);
+        mTagIdList = new ArrayList<>();
+        in.readList(mTagIdList, Integer.class.getClassLoader(), Integer.class);
+    }
+
+    public static final Parcelable.Creator<SatelliteAccessConfigurationWrapper> CREATOR =
+            new Parcelable.Creator<SatelliteAccessConfigurationWrapper>() {
+                @Override
+                public SatelliteAccessConfigurationWrapper createFromParcel(Parcel in) {
+                    return new SatelliteAccessConfigurationWrapper(in);
+                }
+
+                @Override
+                public SatelliteAccessConfigurationWrapper[] newArray(int size) {
+                    return new SatelliteAccessConfigurationWrapper[size];
+                }
+            };
+
+    @Override
+    public int describeContents() {
+        return 0;
+    }
+
+    /**
+     * @param dest  The Parcel in which the object should be written.
+     * @param flags Additional flags about how the object should be written.
+     *              May be 0 or {@link #PARCELABLE_WRITE_RETURN_VALUE}.
+     */
+    @Override
+    public void writeToParcel(@NonNull Parcel dest, int flags) {
+        dest.writeTypedList(mSatelliteInfoList);
+        dest.writeList(mTagIdList);
+    }
+
+    /**
+     * Returns a list of {@link SatelliteInfoWrapper} objects representing the satellites
+     * associated with this object.
+     *
+     * @return The list of {@link SatelliteInfoWrapper} objects.
+     */
+    @NonNull
+    public List<SatelliteInfoWrapper> getSatelliteInfos() {
+        return mSatelliteInfoList;
+    }
+
+    /**
+     * Returns a list of tag IDs associated with this object.
+     *
+     * @return The list of tag IDs.
+     */
+    @NonNull
+    public List<Integer> getTagIds() {
+        return mTagIdList;
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof SatelliteAccessConfigurationWrapper that)) return false;
+
+        return mSatelliteInfoList.equals(that.mSatelliteInfoList)
+                && Objects.equals(mTagIdList, that.mTagIdList);
+    }
+
+    @Override
+    public int hashCode() {
+        int result = Objects.hash(mSatelliteInfoList);
+        result = 31 * result + Objects.hashCode(mTagIdList);
+        return result;
+    }
+
+    @Override
+    @NonNull
+    public String toString() {
+        StringBuilder sb = new StringBuilder();
+        sb.append("SatelliteAccessConfigurationWrapper{");
+        sb.append("mSatelliteInfoList=").append(mSatelliteInfoList);
+        sb.append(", mTagIds=").append(mTagIdList);
+        sb.append('}');
+        return sb.toString();
+    }
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteCommunicationAllowedStateCallbackWrapper2.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteCommunicationAllowedStateCallbackWrapper2.java
new file mode 100644
index 0000000..744b09c
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteCommunicationAllowedStateCallbackWrapper2.java
@@ -0,0 +1,46 @@
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
+package android.telephony.satellite.wrapper;
+
+import android.annotation.Nullable;
+
+/** A callback class for monitoring satellite communication allowed state change events. */
+public interface SatelliteCommunicationAllowedStateCallbackWrapper2 {
+    /**
+     * Telephony does not guarantee that whenever there is a change in communication allowed state,
+     * this API will be called. Telephony does its best to detect the changes and notify its
+     * listeners accordingly.
+     *
+     * @param isAllowed {@code true} means satellite allow state is changed,
+     *                  {@code false} satellite allow state is not changed
+     */
+    void onSatelliteCommunicationAllowedStateChanged(boolean isAllowed);
+
+    /**
+     * Callback method invoked when the satellite access configuration changes
+     *
+     * @param satelliteAccessConfigurationWrapper The satellite access configuration associated with
+     *                                            the current location. When satellite is not
+     *                                            allowed at the current location,
+     *                                            {@code satelliteAccessConfigurationWrapper}
+     *                                            will be null.
+     * @hide
+     */
+    default void onSatelliteAccessConfigurationChanged(
+            @Nullable SatelliteAccessConfigurationWrapper satelliteAccessConfigurationWrapper) {
+    };
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteInfoWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteInfoWrapper.java
new file mode 100644
index 0000000..bdbb379
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteInfoWrapper.java
@@ -0,0 +1,195 @@
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
+package android.telephony.satellite.wrapper;
+
+import android.annotation.Nullable;
+import android.os.Parcel;
+import android.os.ParcelUuid;
+import android.os.Parcelable;
+
+import androidx.annotation.NonNull;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.Objects;
+import java.util.UUID;
+
+/**
+ * SatelliteInfoWrapper stores a satellite's identification, position, and frequency information
+ * facilitating efficient satellite communications.
+ *
+ * @hide
+ */
+public class SatelliteInfoWrapper implements Parcelable {
+    /**
+     * Unique identification number for the satellite.
+     * This ID is used to distinguish between different satellites in the network.
+     */
+    @NonNull
+    private UUID mId;
+
+    /**
+     * Position information of a geostationary satellite.
+     * This includes the longitude and altitude of the satellite.
+     * If the SatellitePosition is invalid,
+     * longitudeDegree and altitudeKm will be represented as DOUBLE.NaN.
+     */
+    @NonNull
+    private SatellitePositionWrapper mPosition;
+
+    /**
+     * The frequency band list to scan. Bands and earfcns won't overlap.
+     * Bands will be filled only if the whole band is needed.
+     * Maximum length of the vector is 8.
+     */
+    private List<Integer> mBandList;
+
+    /**
+     * EARFCN (E-UTRA Absolute Radio Frequency Channel Number) range list
+     * The supported frequency range list.
+     * Maximum length of the vector is 8.
+     */
+    private final List<EarfcnRangeWrapper> mEarfcnRangeList;
+
+    protected SatelliteInfoWrapper(Parcel in) {
+        ParcelUuid parcelUuid = in.readParcelable(
+                ParcelUuid.class.getClassLoader(), ParcelUuid.class);
+        if (parcelUuid != null) {
+            mId = parcelUuid.getUuid();
+        }
+        mPosition = in.readParcelable(SatellitePositionWrapper.class.getClassLoader(),
+                SatellitePositionWrapper.class);
+        mBandList = new ArrayList<>();
+        in.readList(mBandList, Integer.class.getClassLoader(), Integer.class);
+        mEarfcnRangeList = in.createTypedArrayList(EarfcnRangeWrapper.CREATOR);
+    }
+
+    /**
+     * Constructor for {@link SatelliteInfoWrapper}.
+     *
+     * @param satelliteId       The ID of the satellite.
+     * @param satellitePosition The {@link SatellitePositionWrapper} of the satellite.
+     * @param bandList          The list of frequency bandList supported by the satellite.
+     * @param earfcnRanges      The list of {@link EarfcnRangeWrapper} objects representing the
+     *                          EARFCN ranges supported by the satellite.
+     */
+    public SatelliteInfoWrapper(@NonNull UUID satelliteId,
+            @NonNull SatellitePositionWrapper satellitePosition,
+            @NonNull List<Integer> bandList, @NonNull List<EarfcnRangeWrapper> earfcnRanges) {
+        mId = satelliteId;
+        mPosition = satellitePosition;
+        mBandList = bandList;
+        mEarfcnRangeList = earfcnRanges;
+    }
+
+    public static final Parcelable.Creator<SatelliteInfoWrapper>
+            CREATOR = new Parcelable.Creator<SatelliteInfoWrapper>() {
+        @Override
+        public SatelliteInfoWrapper createFromParcel(Parcel in) {
+            return new SatelliteInfoWrapper(in);
+        }
+
+        @Override
+        public SatelliteInfoWrapper[] newArray(int size) {
+            return new SatelliteInfoWrapper[size];
+        }
+    };
+
+    @Override
+    public int describeContents() {
+        return 0;
+    }
+
+    @Override
+    public void writeToParcel(@NonNull Parcel dest, int flags) {
+        dest.writeParcelable(new ParcelUuid(mId), flags);
+        dest.writeParcelable(mPosition, flags);
+        dest.writeList(mBandList);
+        dest.writeTypedList(mEarfcnRangeList);
+    }
+
+    /**
+     * Returns the ID of the satellite.
+     *
+     * @return The satellite ID.
+     */
+    @NonNull
+    public UUID getSatelliteId() {
+        return mId;
+    }
+
+    /**
+     * Returns the position of the satellite.
+     *
+     * @return The {@link SatellitePositionWrapper} of the satellite.
+     */
+    @NonNull
+    public SatellitePositionWrapper getSatellitePosition() {
+        return mPosition;
+    }
+
+    /**
+     * Returns the list of frequency bands supported by the satellite.
+     *
+     * @return The list of frequency bands.
+     */
+    @NonNull
+    public List<Integer> getBands() {
+        return mBandList;
+    }
+
+    /**
+     * Returns the list of EARFCN ranges supported by the satellite.
+     *
+     * @return The list of {@link EarfcnRangeWrapper} objects.
+     */
+    @NonNull
+    public List<EarfcnRangeWrapper> getEarfcnRanges() {
+        return mEarfcnRangeList;
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof SatelliteInfoWrapper that)) return false;
+
+        return mId.equals(that.mId)
+                && Objects.equals(mPosition, that.mPosition)
+                && Objects.equals(mBandList, that.mBandList)
+                && mEarfcnRangeList.equals(that.mEarfcnRangeList);
+    }
+
+    @Override
+    public int hashCode() {
+        int result = Objects.hash(mId, mPosition, mEarfcnRangeList);
+        result = 31 * result + Objects.hashCode(mBandList);
+        return result;
+    }
+
+    @Override
+    @NonNull
+    public String toString() {
+        StringBuilder sb = new StringBuilder();
+        sb.append("SatelliteInfoWrapper{");
+        sb.append("mId=").append(mId);
+        sb.append(", mPosition=").append(mPosition);
+        sb.append(", mBandList=").append(mBandList);
+        sb.append(", mEarfcnRangeList=").append(mEarfcnRangeList);
+        sb.append('}');
+        return sb.toString();
+    }
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
index e4f38f9..b4c55d1 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteManagerWrapper.java
@@ -26,6 +26,7 @@ import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.content.Context;
+import android.os.Binder;
 import android.os.CancellationSignal;
 import android.os.OutcomeReceiver;
 import android.telephony.NetworkRegistrationInfo;
@@ -35,15 +36,18 @@ import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyCallback;
 import android.telephony.TelephonyManager;
 import android.telephony.satellite.AntennaPosition;
+import android.telephony.satellite.EarfcnRange;
 import android.telephony.satellite.EnableRequestAttributes;
 import android.telephony.satellite.NtnSignalStrength;
 import android.telephony.satellite.NtnSignalStrengthCallback;
 import android.telephony.satellite.PointingInfo;
+import android.telephony.satellite.SatelliteAccessConfiguration;
 import android.telephony.satellite.SatelliteCapabilities;
 import android.telephony.satellite.SatelliteCapabilitiesCallback;
 import android.telephony.satellite.SatelliteCommunicationAllowedStateCallback;
 import android.telephony.satellite.SatelliteDatagram;
 import android.telephony.satellite.SatelliteDatagramCallback;
+import android.telephony.satellite.SatelliteInfo;
 import android.telephony.satellite.SatelliteManager;
 import android.telephony.satellite.SatelliteModemStateCallback;
 import android.telephony.satellite.SatelliteProvisionStateCallback;
@@ -52,6 +56,7 @@ import android.telephony.satellite.SatelliteSubscriberInfo;
 import android.telephony.satellite.SatelliteSubscriberProvisionStatus;
 import android.telephony.satellite.SatelliteSupportedStateCallback;
 import android.telephony.satellite.SatelliteTransmissionUpdateCallback;
+import android.telephony.satellite.SelectedNbIotSatelliteSubscriptionCallback;
 
 import com.android.internal.telephony.flags.Flags;
 import com.android.telephony.Rlog;
@@ -61,6 +66,7 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.reflect.Method;
 import java.time.Duration;
 import java.util.ArrayList;
+import java.util.Collections;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
@@ -78,6 +84,8 @@ import java.util.stream.Collectors;
 public class SatelliteManagerWrapper {
   private static final String TAG = "SatelliteManagerWrapper";
 
+  private static final int VERSION = 1;
+
   private static final ConcurrentHashMap<
       SatelliteDatagramCallbackWrapper, SatelliteDatagramCallback>
       sSatelliteDatagramCallbackWrapperMap = new ConcurrentHashMap<>();
@@ -126,6 +134,14 @@ public class SatelliteManagerWrapper {
           SatelliteCommunicationAllowedStateCallback>
           sSatelliteCommunicationAllowedStateCallbackWrapperMap = new ConcurrentHashMap<>();
 
+  private static final ConcurrentHashMap<SatelliteCommunicationAllowedStateCallbackWrapper2,
+          SatelliteCommunicationAllowedStateCallback>
+          sSatelliteCommunicationAllowedStateCallbackWrapperMap2 = new ConcurrentHashMap<>();
+
+  private static final ConcurrentHashMap<SelectedNbIotSatelliteSubscriptionCallbackWrapper,
+          SelectedNbIotSatelliteSubscriptionCallback>
+      sSelectedNbIotSatelliteSubscriptionCallbackWrapperMap = new ConcurrentHashMap<>();
+
   private final SatelliteManager mSatelliteManager;
   private final SubscriptionManager mSubscriptionManager;
   private final TelephonyManager mTelephonyManager;
@@ -174,6 +190,12 @@ public class SatelliteManagerWrapper {
    * Datagram type indicating that the message to be sent or received is of type SMS.
    */
   public static final int DATAGRAM_TYPE_SMS = 6;
+  /**
+   * Datagram type indicating that the message to be sent is an SMS checking
+   * for pending incoming SMS.
+   * @hide
+   */
+    public static final int DATAGRAM_TYPE_CHECK_PENDING_INCOMING_SMS = 7;
 
   /** @hide */
   @IntDef(
@@ -185,7 +207,8 @@ public class SatelliteManagerWrapper {
               DATAGRAM_TYPE_KEEP_ALIVE,
               DATAGRAM_TYPE_LAST_SOS_MESSAGE_STILL_NEED_HELP,
               DATAGRAM_TYPE_LAST_SOS_MESSAGE_NO_HELP_NEEDED,
-              DATAGRAM_TYPE_SMS
+              DATAGRAM_TYPE_SMS,
+              DATAGRAM_TYPE_CHECK_PENDING_INCOMING_SMS
       })
   @Retention(RetentionPolicy.SOURCE)
   public @interface DatagramType {}
@@ -538,6 +561,14 @@ public class SatelliteManagerWrapper {
     }
   }
 
+  /**
+   * Returns the current version of the satellite wrapper. Versions start at 1.
+   * There is no to explicit versioning support before the first version.
+   */
+  public int getVersion() {
+    return VERSION;
+  }
+
   /**
    * Request to enable or disable the satellite modem and demo mode. If the satellite modem is
    * enabled, this may also disable the cellular modem, and if the satellite modem is disabled, this
@@ -549,6 +580,13 @@ public class SatelliteManagerWrapper {
       boolean isEmergency,
       @NonNull @CallbackExecutor Executor executor,
       @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("requestEnabled: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     mSatelliteManager.requestEnabled(new EnableRequestAttributes.Builder(enableSatellite)
             .setDemoMode(enableDemoMode)
             .setEmergencyMode(isEmergency)
@@ -559,6 +597,14 @@ public class SatelliteManagerWrapper {
   public void requestIsEnabled(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestIsEnabled: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
         new OutcomeReceiver<Boolean, SatelliteException>() {
           @Override
@@ -578,6 +624,14 @@ public class SatelliteManagerWrapper {
   public void requestIsDemoModeEnabled(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestIsDemoModeEnabled: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
         new OutcomeReceiver<Boolean, SatelliteException>() {
           @Override
@@ -597,6 +651,14 @@ public class SatelliteManagerWrapper {
   public void requestIsEmergencyModeEnabled(
           @NonNull @CallbackExecutor Executor executor,
           @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestIsEmergencyModeEnabled: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
         new OutcomeReceiver<Boolean, SatelliteException>() {
           @Override
@@ -616,6 +678,12 @@ public class SatelliteManagerWrapper {
   public void requestIsSupported(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestIsSupported: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onResult(false)));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
         new OutcomeReceiver<Boolean, SatelliteException>() {
           @Override
@@ -635,6 +703,14 @@ public class SatelliteManagerWrapper {
   public void requestCapabilities(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull OutcomeReceiver<SatelliteCapabilitiesWrapper, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestCapabilities: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
         new OutcomeReceiver<SatelliteCapabilities, SatelliteException>() {
           @Override
@@ -667,6 +743,12 @@ public class SatelliteManagerWrapper {
       @NonNull @CallbackExecutor Executor executor,
       @SatelliteResult @NonNull Consumer<Integer> resultListener,
       @NonNull SatelliteTransmissionUpdateCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("startTransmissionUpdates: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
 
     SatelliteTransmissionUpdateCallback internalCallback =
         new SatelliteTransmissionUpdateCallback() {
@@ -721,6 +803,12 @@ public class SatelliteManagerWrapper {
           @NonNull @CallbackExecutor Executor executor,
           @SatelliteResult @NonNull Consumer<Integer> resultListener,
           @NonNull SatelliteTransmissionUpdateCallbackWrapper2 callback) {
+    if (mSatelliteManager == null) {
+      logd("startTransmissionUpdates2: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
 
     SatelliteTransmissionUpdateCallback internalCallback =
             new SatelliteTransmissionUpdateCallback() {
@@ -779,6 +867,13 @@ public class SatelliteManagerWrapper {
       @NonNull SatelliteTransmissionUpdateCallbackWrapper callback,
       @NonNull @CallbackExecutor Executor executor,
       @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("stopTransmissionUpdates: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     SatelliteTransmissionUpdateCallback internalCallback =
         sSatelliteTransmissionUpdateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
@@ -797,6 +892,13 @@ public class SatelliteManagerWrapper {
           @NonNull SatelliteTransmissionUpdateCallbackWrapper2 callback,
           @NonNull @CallbackExecutor Executor executor,
           @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("stopTransmissionUpdates2: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     SatelliteTransmissionUpdateCallback internalCallback =
             sSatelliteTransmissionUpdateCallbackWrapperMap2.remove(callback);
     if (internalCallback != null) {
@@ -815,6 +917,13 @@ public class SatelliteManagerWrapper {
       @Nullable CancellationSignal cancellationSignal,
       @NonNull @CallbackExecutor Executor executor,
       @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("provisionService: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     mSatelliteManager.provisionService(
         token, provisionData, cancellationSignal, executor, resultListener);
   }
@@ -829,6 +938,13 @@ public class SatelliteManagerWrapper {
       @NonNull String token,
       @NonNull @CallbackExecutor Executor executor,
       @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("deprovisionService: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     mSatelliteManager.deprovisionService(token, executor, resultListener);
   }
 
@@ -837,6 +953,11 @@ public class SatelliteManagerWrapper {
   public int registerForProvisionStateChanged(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull SatelliteProvisionStateCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("registerForProvisionStateChanged: mSatelliteManager is null");
+      return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
+    }
+
     SatelliteProvisionStateCallback internalCallback =
         new SatelliteProvisionStateCallback() {
           @Override
@@ -863,6 +984,11 @@ public class SatelliteManagerWrapper {
    */
   public void unregisterForProvisionStateChanged(
       @NonNull SatelliteProvisionStateCallbackWrapper callback) {
+    if (mSatelliteManager == null){
+      logd("unregisterForProvisionStateChanged: mSatelliteManager is null");
+      return;
+    }
+
     SatelliteProvisionStateCallback internalCallback =
         sSatelliteProvisionStateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
@@ -874,6 +1000,14 @@ public class SatelliteManagerWrapper {
   public void requestIsProvisioned(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestIsProvisioned: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
         new OutcomeReceiver<Boolean, SatelliteException>() {
           @Override
@@ -894,6 +1028,11 @@ public class SatelliteManagerWrapper {
   public int registerForModemStateChanged(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull SatelliteModemStateCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("registerForModemStateChanged: mSatelliteManager is null");
+      return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
+    }
+
     SatelliteModemStateCallback internalCallback =
         new SatelliteModemStateCallback() {
           public void onSatelliteModemStateChanged(@SatelliteModemState int state) {
@@ -912,6 +1051,11 @@ public class SatelliteManagerWrapper {
   public int registerForModemStateChanged(
           @NonNull @CallbackExecutor Executor executor,
           @NonNull SatelliteModemStateCallbackWrapper2 callback) {
+    if (mSatelliteManager == null) {
+      logd("registerForModemStateChanged: mSatelliteManager is null");
+      return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
+    }
+
     SatelliteModemStateCallback internalCallback =
             new SatelliteModemStateCallback() {
               public void onSatelliteModemStateChanged(@SatelliteModemState int state) {
@@ -925,6 +1069,10 @@ public class SatelliteManagerWrapper {
               public void onRegistrationFailure(int causeCode) {
                 callback.onRegistrationFailure(causeCode);
               }
+
+              public void onTerrestrialNetworkAvailableChanged(boolean isAvailable) {
+                callback.onTerrestrialNetworkAvailableChanged(isAvailable);
+              }
             };
     sSatelliteModemStateCallbackWrapperMap2.put(callback, internalCallback);
 
@@ -939,6 +1087,11 @@ public class SatelliteManagerWrapper {
    */
   public void unregisterForModemStateChanged(
       @NonNull SatelliteModemStateCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("unregisterForModemStateChanged: mSatelliteManager is null");
+      return;
+    }
+
     SatelliteModemStateCallback internalCallback = sSatelliteModemStateCallbackWrapperMap.remove(
             callback);
     if (internalCallback != null) {
@@ -952,6 +1105,11 @@ public class SatelliteManagerWrapper {
    */
   public void unregisterForModemStateChanged(
           @NonNull SatelliteModemStateCallbackWrapper2 callback) {
+    if (mSatelliteManager == null) {
+      logd("unregisterForModemStateChanged: mSatelliteManager is null");
+      return;
+    }
+
     SatelliteModemStateCallback internalCallback = sSatelliteModemStateCallbackWrapperMap2.remove(
             callback);
     if (internalCallback != null) {
@@ -964,6 +1122,11 @@ public class SatelliteManagerWrapper {
   public int registerForIncomingDatagram(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull SatelliteDatagramCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("registerForIncomingDatagram: mSatelliteManager is null");
+      return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
+    }
+
     SatelliteDatagramCallback internalCallback =
         new SatelliteDatagramCallback() {
           @Override
@@ -989,6 +1152,11 @@ public class SatelliteManagerWrapper {
    * before, the request will be ignored.
    */
   public void unregisterForIncomingDatagram(@NonNull SatelliteDatagramCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("unregisterForIncomingDatagram: mSatelliteManager is null");
+      return;
+    }
+
     SatelliteDatagramCallback internalCallback =
             sSatelliteDatagramCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
@@ -1029,6 +1197,12 @@ public class SatelliteManagerWrapper {
         mListenerWrapper2.onCarrierRoamingNtnEligibleStateChanged(eligible);
       }
     }
+
+    @Override
+    public void onCarrierRoamingNtnAvailableServicesChanged(
+            @NetworkRegistrationInfo.ServiceType int[] availableServices) {
+      logd("onCarrierRoamingNtnAvailableServicesChanged");
+    }
   }
 
   /** Register for carrier roaming non-terrestrial network mode changes. */
@@ -1082,6 +1256,13 @@ public class SatelliteManagerWrapper {
   public void pollPendingDatagrams(
       @NonNull @CallbackExecutor Executor executor,
       @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("pollPendingDatagrams: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     mSatelliteManager.pollPendingDatagrams(executor, resultListener);
   }
 
@@ -1098,6 +1279,13 @@ public class SatelliteManagerWrapper {
       boolean needFullScreenPointingUI,
       @NonNull @CallbackExecutor Executor executor,
       @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("sendDatagram: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     SatelliteDatagram datagramInternal = new SatelliteDatagram(datagram.getSatelliteDatagram());
     mSatelliteManager.sendDatagram(
         datagramType, datagramInternal, needFullScreenPointingUI, executor, resultListener);
@@ -1107,6 +1295,14 @@ public class SatelliteManagerWrapper {
   public void requestIsCommunicationAllowedForCurrentLocation(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestIsCommunicationAllowedForCurrentLocation: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
         new OutcomeReceiver<Boolean, SatelliteException>() {
           @Override
@@ -1123,6 +1319,37 @@ public class SatelliteManagerWrapper {
         executor, internalCallback);
   }
 
+  /** Request to get satellite access configuration for the current location. */
+  public void requestSatelliteAccessConfigurationForCurrentLocation(
+          @NonNull @CallbackExecutor Executor executor,
+          @NonNull OutcomeReceiver<SatelliteAccessConfigurationWrapper, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestSatelliteAccessConfigurationForCurrentLocation: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
+    OutcomeReceiver internalCallback =
+            new OutcomeReceiver<SatelliteAccessConfiguration, SatelliteException>() {
+              @Override
+              public void onResult(SatelliteAccessConfiguration result) {
+                callback.onResult(new SatelliteAccessConfigurationWrapper(
+                        getSatelliteInfoListWrapper(result.getSatelliteInfos()),
+                        result.getTagIds()));
+              }
+
+              @Override
+              public void onError(SatelliteException exception) {
+                callback.onError(new SatelliteExceptionWrapper(exception.getErrorCode()));
+              }
+            };
+
+    mSatelliteManager.requestSatelliteAccessConfigurationForCurrentLocation(executor,
+            internalCallback);
+  }
+
   /**
    * Request to get the duration in seconds after which the satellite will be visible. This will be
    * {@link Duration#ZERO} if the satellite is currently visible.
@@ -1130,6 +1357,14 @@ public class SatelliteManagerWrapper {
   public void requestTimeForNextSatelliteVisibility(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull OutcomeReceiver<Duration, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestTimeForNextSatelliteVisibility: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
         new OutcomeReceiver<Duration, SatelliteException>() {
           @Override
@@ -1145,10 +1380,112 @@ public class SatelliteManagerWrapper {
     mSatelliteManager.requestTimeForNextSatelliteVisibility(executor, internalCallback);
   }
 
+  /**
+   * Request to get the name to display for Satellite as a {@link String}.
+   */
+  public void requestSatelliteDisplayName(
+          @NonNull @CallbackExecutor Executor executor,
+          @NonNull OutcomeReceiver<CharSequence, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestSatelliteDisplayName: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
+    OutcomeReceiver internalCallback =
+            new OutcomeReceiver<CharSequence, SatelliteException>() {
+              @Override
+              public void onResult(CharSequence result) {
+                callback.onResult(result);
+              }
+
+              @Override
+              public void onError(SatelliteException exception) {
+                callback.onError(new SatelliteExceptionWrapper(exception.getErrorCode()));
+              }
+            };
+    mSatelliteManager.requestSatelliteDisplayName(executor, internalCallback);
+  }
+
+  /**
+   * Request to get the currently selected satellite subscription id as an {@link Integer}.
+   */
+  public void requestSelectedNbIotSatelliteSubscriptionId(
+      @NonNull @CallbackExecutor Executor executor,
+      @NonNull OutcomeReceiver<Integer, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestSelectedNbIotSatelliteSubscriptionId: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
+    OutcomeReceiver internalCallback =
+        new OutcomeReceiver<Integer, SatelliteException>() {
+          @Override
+          public void onResult(Integer result) {
+            callback.onResult(result);
+          }
+
+          @Override
+          public void onError(SatelliteException exception) {
+            callback.onError(new SatelliteExceptionWrapper(exception.getErrorCode()));
+          }
+        };
+    mSatelliteManager.requestSelectedNbIotSatelliteSubscriptionId(executor, internalCallback);
+  }
+
+    /**
+     * Wrapper API to register for selected satellite subscription changed event from the satellite
+     * service.
+     *
+     * @param executor The executor on which the callback will be called.
+     * @param callback The callback to handle the selected satellite subscription changed event.
+     */
+    @SatelliteResult public int registerForSelectedNbIotSatelliteSubscriptionChanged(
+            @NonNull @CallbackExecutor Executor executor,
+            @NonNull SelectedNbIotSatelliteSubscriptionCallbackWrapper callback) {
+        SelectedNbIotSatelliteSubscriptionCallback internalCallback =
+                selectedSubId -> callback.onSelectedNbIotSatelliteSubscriptionChanged(
+                        selectedSubId);
+    sSelectedNbIotSatelliteSubscriptionCallbackWrapperMap.put(callback, internalCallback);
+    return mSatelliteManager.registerForSelectedNbIotSatelliteSubscriptionChanged(executor,
+            internalCallback);
+    }
+
+    /**
+     * Wrapper API to unregisters for selected satellite subscription changed event from the
+     * satellite service. If callback was not registered before, the request will be ignored.
+     *
+     * @param callback The callback that was passed to {@link
+     *     #registerForSelectedNbIotSatelliteSubscriptionChanged(Executor,
+     *     SelectedNbIotSatelliteSubscriptionCallbackWrapper)}.
+     */
+    public void unregisterForSelectedNbIotSatelliteSubscriptionChanged(
+            @NonNull SelectedNbIotSatelliteSubscriptionCallbackWrapper callback) {
+        SelectedNbIotSatelliteSubscriptionCallback internalCallback =
+                sSelectedNbIotSatelliteSubscriptionCallbackWrapperMap.remove(callback);
+        if (internalCallback != null) {
+            mSatelliteManager.unregisterForSelectedNbIotSatelliteSubscriptionChanged(
+                    internalCallback);
+        } else {
+            logd("unregisterForSelectedNbIotSatelliteSubscriptionChanged: internalCallback is"
+                    + " null");
+        }
+    }
+
   /**
    * Inform whether the device is aligned with the satellite for demo mode.
    */
   public void setDeviceAlignedWithSatellite(boolean isAligned) {
+    if (mSatelliteManager == null) {
+      logd("setDeviceAlignedWithSatellite: mSatelliteManager is null");
+      return;
+    }
+
     mSatelliteManager.setDeviceAlignedWithSatellite(isAligned);
   }
 
@@ -1177,6 +1514,14 @@ public class SatelliteManagerWrapper {
   public void requestNtnSignalStrength(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull OutcomeReceiver<NtnSignalStrengthWrapper, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestNtnSignalStrength: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
             new OutcomeReceiver<NtnSignalStrength, SatelliteException>() {
               @Override
@@ -1197,6 +1542,11 @@ public class SatelliteManagerWrapper {
   public void registerForNtnSignalStrengthChanged(
       @NonNull @CallbackExecutor Executor executor,
       @NonNull NtnSignalStrengthCallbackWrapper callback) {
+    if (mSatelliteManager == null){
+      logd("registerForNtnSignalStrengthChanged: mSatelliteManager is null");
+      return;
+    }
+
     NtnSignalStrengthCallback internalCallback =
         new NtnSignalStrengthCallback() {
           @Override
@@ -1216,6 +1566,11 @@ public class SatelliteManagerWrapper {
   @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public void unregisterForNtnSignalStrengthChanged(
       @NonNull NtnSignalStrengthCallbackWrapper callback) {
+    if (mSatelliteManager == null){
+      logd("unregisterForNtnSignalStrengthChanged: mSatelliteManager is null");
+      return;
+    }
+
     NtnSignalStrengthCallback internalCallback =
             sNtnSignalStrengthCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
@@ -1260,6 +1615,11 @@ public class SatelliteManagerWrapper {
   public int registerForCapabilitiesChanged(
           @NonNull @CallbackExecutor Executor executor,
           @NonNull SatelliteCapabilitiesCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("requestForCapabilitiesChanged: mSatelliteManager is null");
+      return SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
+    }
+
     SatelliteCapabilitiesCallback internalCallback =
             capabilities -> callback.onSatelliteCapabilitiesChanged(
                     new SatelliteCapabilitiesWrapper(
@@ -1281,6 +1641,11 @@ public class SatelliteManagerWrapper {
   @FlaggedApi(Flags.FLAG_OEM_ENABLED_SATELLITE_FLAG)
   public void unregisterForCapabilitiesChanged(
           @NonNull SatelliteCapabilitiesCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("unregisterForCapabilitiesChanged: mSatelliteManager is null");
+      return;
+    }
+
     SatelliteCapabilitiesCallback internalCallback =
             sSatelliteCapabilitiesCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
@@ -1394,6 +1759,13 @@ public class SatelliteManagerWrapper {
   public void requestAttachEnabledForCarrier(int subId, boolean enableSatellite,
           @NonNull @CallbackExecutor Executor executor,
           @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("requestAttachEnabledForCarrier: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     mSatelliteManager.requestAttachEnabledForCarrier(subId, enableSatellite, executor,
             resultListener);
   }
@@ -1419,6 +1791,14 @@ public class SatelliteManagerWrapper {
   public void requestIsAttachEnabledForCarrier(int subId,
           @NonNull @CallbackExecutor Executor executor,
           @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestIsAttachEnabledForCarrier: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
             new OutcomeReceiver<Boolean, SatelliteException>() {
               @Override
@@ -1451,6 +1831,13 @@ public class SatelliteManagerWrapper {
           @SatelliteCommunicationRestrictionReason int reason,
           @NonNull @CallbackExecutor Executor executor,
           @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("addAttachRestrictionForCarrier: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     mSatelliteManager.addAttachRestrictionForCarrier(subId, reason, executor, resultListener);
   }
 
@@ -1471,6 +1858,13 @@ public class SatelliteManagerWrapper {
           @SatelliteCommunicationRestrictionReason int reason,
           @NonNull @CallbackExecutor Executor executor,
           @SatelliteResult @NonNull Consumer<Integer> resultListener) {
+    if (mSatelliteManager == null) {
+      logd("removeAttachRestrictionForCarrier: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> resultListener.accept(
+              SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED)));
+      return;
+    }
+
     mSatelliteManager.removeAttachRestrictionForCarrier(subId, reason, executor, resultListener);
   }
 
@@ -1487,6 +1881,11 @@ public class SatelliteManagerWrapper {
    */
   @SatelliteCommunicationRestrictionReason
   @NonNull public Set<Integer> getAttachRestrictionReasonsForCarrier(int subId) {
+    if (mSatelliteManager == null) {
+      logd("getAttachRestrictionReasonsForCarrier: mSatelliteManager is null");
+      return Collections.emptySet();
+    }
+
     return mSatelliteManager.getAttachRestrictionReasonsForCarrier(subId);
   }
 
@@ -1499,6 +1898,11 @@ public class SatelliteManagerWrapper {
    * be returned.
    */
   @NonNull public List<String> getSatellitePlmnsForCarrier(int subId) {
+    if (mSatelliteManager == null) {
+      logd("getSatellitePlmnsForCarrier: mSatelliteManager is null");
+      return new ArrayList<>();
+    }
+
     return mSatelliteManager.getSatellitePlmnsForCarrier(subId);
   }
 
@@ -1507,6 +1911,11 @@ public class SatelliteManagerWrapper {
   public int registerForSupportedStateChanged(
           @NonNull @CallbackExecutor Executor executor,
           @NonNull SatelliteSupportedStateCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("registerForSupportedStateChanged: mSatelliteManager is null");
+      return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
+    }
+
     SatelliteSupportedStateCallback internalCallback =
             new SatelliteSupportedStateCallback() {
               @Override
@@ -1525,6 +1934,14 @@ public class SatelliteManagerWrapper {
           @NonNull @CallbackExecutor Executor executor,
           @NonNull OutcomeReceiver<SatelliteSessionStatsWrapper,
                   SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestSessionStats: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
             new OutcomeReceiver<SatelliteSessionStats, SatelliteException>() {
               @Override
@@ -1552,12 +1969,72 @@ public class SatelliteManagerWrapper {
     mSatelliteManager.requestSessionStats(executor, internalCallback);
   }
 
+  /** Request to get the {@link SatelliteSessionStatsWrapper2} of the satellite service. */
+  public void requestSessionStats2(@NonNull @CallbackExecutor Executor executor,
+          @NonNull OutcomeReceiver<SatelliteSessionStatsWrapper2,
+                  SatelliteExceptionWrapper> callback) {
+    logd("requestSessionStats2 called");
+    if (mSatelliteManager == null) {
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+    OutcomeReceiver internalCallback =
+            new OutcomeReceiver<SatelliteSessionStats, SatelliteException>() {
+              @Override
+              public void onResult(SatelliteSessionStats result) {
+                logd("requestSessionStats2 onResult received");
+                Map<Integer, SatelliteSessionStats> satelliteSessionStats =
+                        result.getSatelliteSessionStats();
+                Map<Integer, SatelliteSessionStatsWrapper2> sessionStatsMap = new HashMap<>();
+                for (Map.Entry<Integer, SatelliteSessionStats> entry :
+                        satelliteSessionStats.entrySet()) {
+                  sessionStatsMap.put(entry.getKey(),
+                          buildSatelliteSessionStatsWrapper2(entry.getValue()));
+                }
+                SatelliteSessionStatsWrapper2 sessionStatsWrapper2 =
+                        new SatelliteSessionStatsWrapper2();
+                sessionStatsWrapper2.setSatelliteSessionStats(sessionStatsMap);
+                logd("requestSessionStats2 completed sessionStatsWrapper2 = " +sessionStatsWrapper2);
+                callback.onResult(sessionStatsWrapper2);
+              }
+
+              @Override
+              public void onError(SatelliteException exception) {
+                callback.onError(new SatelliteExceptionWrapper(exception.getErrorCode()));
+              }
+            };
+    mSatelliteManager.requestSessionStats(executor, internalCallback);
+  }
+
+  private SatelliteSessionStatsWrapper2 buildSatelliteSessionStatsWrapper2(
+          SatelliteSessionStats value) {
+    SatelliteSessionStatsWrapper2 data = new SatelliteSessionStatsWrapper2();
+    data.updateLatencyOfAllSuccessfulUserMessages(value.getLatencyOfAllSuccessfulUserMessages());
+    data.setMaxLatency(value.getMaxLatency());
+    data.setLastMessageLatency(value.getLastMessageLatency());
+    data.setCountOfSuccessfulUserMessages(value.getCountOfSuccessfulUserMessages());
+    data.setCountOfUnsuccessfulUserMessages(value.getCountOfUnsuccessfulUserMessages());
+    data.setCountOfTimedOutUserMessagesWaitingForAck(
+            value.getCountOfTimedOutUserMessagesWaitingForAck());
+    data.setCountOfTimedOutUserMessagesWaitingForConnection(
+            value.getCountOfTimedOutUserMessagesWaitingForConnection());
+    data.setCountOfUserMessagesInQueueToBeSent(value.getCountOfUserMessagesInQueueToBeSent());
+    return data;
+  }
+
   /**
    * Unregisters for the satellite supported state changed. If callback was not registered before,
    * the request will be ignored.
    */
   public void unregisterForSupportedStateChanged(
           @NonNull SatelliteSupportedStateCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("unregisterForSupportedStateChanged: mSatelliteManager is null");
+      return;
+    }
+
     SatelliteSupportedStateCallback internalCallback =
             sSatelliteSupportedStateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
@@ -1570,6 +2047,11 @@ public class SatelliteManagerWrapper {
   public int registerForCommunicationAllowedStateChanged(
           @NonNull @CallbackExecutor Executor executor,
           @NonNull SatelliteCommunicationAllowedStateCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("requestForCommunicationAllowedStateChanged: mSatelliteManager is null");
+      return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
+    }
+
     SatelliteCommunicationAllowedStateCallback internalCallback =
             new SatelliteCommunicationAllowedStateCallback() {
               @Override
@@ -1583,12 +2065,76 @@ public class SatelliteManagerWrapper {
     return result;
   }
 
+  @NonNull
+  private List<SatelliteInfoWrapper> getSatelliteInfoListWrapper(@NonNull
+          List<SatelliteInfo> satelliteInfoList) {
+      List<SatelliteInfoWrapper> satelliteInfoWrapperList = new ArrayList<>();
+
+      for (SatelliteInfo info : satelliteInfoList) {
+          SatellitePositionWrapper satellitePositionWrapper = new SatellitePositionWrapper(
+                      info.getSatellitePosition().getLongitudeDegrees(),
+                      info.getSatellitePosition().getAltitudeKm());
+
+          List<EarfcnRangeWrapper> earfcnRangeWrapperList = new ArrayList<>();
+          for (EarfcnRange range : info.getEarfcnRanges()) {
+              earfcnRangeWrapperList.add(new EarfcnRangeWrapper(
+                      range.getStartEarfcn(), range.getEndEarfcn()));
+          }
+
+          SatelliteInfoWrapper satelliteInfoWrapper = new SatelliteInfoWrapper(
+                  info.getSatelliteId(), satellitePositionWrapper,
+                  info.getBands(), earfcnRangeWrapperList);
+
+          satelliteInfoWrapperList.add(satelliteInfoWrapper);
+      }
+      return satelliteInfoWrapperList;
+  }
+
+  /** Registers for the satellite communication allowed state changed. */
+  @SatelliteResult
+  public int registerForCommunicationAllowedStateChanged2(
+          @NonNull @CallbackExecutor Executor executor,
+          @NonNull SatelliteCommunicationAllowedStateCallbackWrapper2 callback) {
+    if (mSatelliteManager == null) {
+      logd("registerForCommunicationAllowedStateChanged2: mSatelliteManager is null");
+      return SatelliteManagerWrapper.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
+    }
+
+    SatelliteCommunicationAllowedStateCallback internalCallback =
+            new SatelliteCommunicationAllowedStateCallback() {
+              @Override
+              public void onSatelliteCommunicationAllowedStateChanged(boolean supported) {
+                callback.onSatelliteCommunicationAllowedStateChanged(supported);
+              }
+
+              @Override
+              public void onSatelliteAccessConfigurationChanged(SatelliteAccessConfiguration
+                      config) {
+                if (config != null) {
+                  callback.onSatelliteAccessConfigurationChanged(
+                          new SatelliteAccessConfigurationWrapper(
+                                  getSatelliteInfoListWrapper(config.getSatelliteInfos()),
+                                  config.getTagIds()));
+                }
+              }
+            };
+    sSatelliteCommunicationAllowedStateCallbackWrapperMap2.put(callback, internalCallback);
+    int result = mSatelliteManager.registerForCommunicationAllowedStateChanged(executor,
+            internalCallback);
+    return result;
+  }
+
   /**
    * Unregisters for the satellite communication allowed state changed. If callback was not
    * registered before, the request will be ignored.
    */
   public void unregisterForCommunicationAllowedStateChanged(
           @NonNull SatelliteCommunicationAllowedStateCallbackWrapper callback) {
+    if (mSatelliteManager == null) {
+      logd("unregisterForCommunicationAllowedStateChanged: mSatelliteManager is null");
+      return;
+    }
+
     SatelliteCommunicationAllowedStateCallback internalCallback =
             sSatelliteCommunicationAllowedStateCallbackWrapperMap.remove(callback);
     if (internalCallback != null) {
@@ -1596,6 +2142,19 @@ public class SatelliteManagerWrapper {
     }
   }
 
+  /**
+   * Unregisters for the satellite communication allowed state changed. If callback was not
+   * registered before, the request will be ignored.
+   */
+  public void unregisterForCommunicationAllowedStateChanged2(
+          @NonNull SatelliteCommunicationAllowedStateCallbackWrapper2 callback) {
+    SatelliteCommunicationAllowedStateCallback internalCallback =
+            sSatelliteCommunicationAllowedStateCallbackWrapperMap2.remove(callback);
+    if (internalCallback != null) {
+      mSatelliteManager.unregisterForCommunicationAllowedStateChanged(internalCallback);
+    }
+  }
+
   /**
    * Wrapper API to provide a way to check if the subscription is capable for non-terrestrial
    * networks for the carrier.
@@ -1636,6 +2195,14 @@ public class SatelliteManagerWrapper {
           @NonNull @CallbackExecutor Executor executor,
           @NonNull OutcomeReceiver<List<SatelliteSubscriberProvisionStatusWrapper>,
                   SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("requestSatelliteSubscriberProvisionStatus: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     Objects.requireNonNull(executor);
     Objects.requireNonNull(callback);
 
@@ -1665,6 +2232,14 @@ public class SatelliteManagerWrapper {
   public void provisionSatellite(@NonNull List<SatelliteSubscriberInfoWrapper> list,
           @NonNull @CallbackExecutor Executor executor,
           @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("provisionSatellite: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
     OutcomeReceiver internalCallback =
             new OutcomeReceiver<Boolean, SatelliteException>() {
               @Override
@@ -1693,7 +2268,7 @@ public class SatelliteManagerWrapper {
       for (SatelliteSubscriberProvisionStatus status : input) {
         SatelliteSubscriberInfo info = status.getSatelliteSubscriberInfo();
         output.add(new SatelliteSubscriberProvisionStatusWrapper.Builder()
-                .setProvisionStatus(status.getProvisionStatus())
+                .setProvisionStatus(status.isProvisioned())
                 .setSatelliteSubscriberInfo(
                         new SatelliteSubscriberInfoWrapper.Builder()
                                 .setSubscriberId(info.getSubscriberId())
@@ -1707,6 +2282,11 @@ public class SatelliteManagerWrapper {
   }
 
   public boolean isSatelliteSubscriberIdSupported() {
+    if (mSatelliteManager == null) {
+      logd("isSatelliteSubscriberIdSupported: mSatelliteManager is null");
+      return false;
+    }
+
     try {
       final String methodName = "requestSatelliteSubscriberProvisionStatus";
       Method method = mSatelliteManager.getClass().getMethod(methodName, Executor.class,
@@ -1717,6 +2297,63 @@ public class SatelliteManagerWrapper {
     }
   }
 
+  /**
+   * Deliver the list of deprovisioned satellite subscriber ids.
+   *
+   * @param list List of deprovisioned SatelliteSubscriberInfo.
+   * @param executor The executor on which the callback will be called.
+   * @param callback The callback object to which the result will be delivered.
+   */
+  @FlaggedApi(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN)
+  public void deprovisionSatellite(@NonNull List<SatelliteSubscriberInfoWrapper> list,
+          @NonNull @CallbackExecutor Executor executor,
+          @NonNull OutcomeReceiver<Boolean, SatelliteExceptionWrapper> callback) {
+    if (mSatelliteManager == null) {
+      logd("deprovisionSatellite: mSatelliteManager is null");
+      executor.execute(() -> Binder.withCleanCallingIdentity(() -> callback.onError(
+              new SatelliteExceptionWrapper(
+                      SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED))));
+      return;
+    }
+
+    OutcomeReceiver internalCallback =
+            new OutcomeReceiver<Boolean, SatelliteException>() {
+              @Override
+              public void onResult(Boolean result) {
+                callback.onResult(result);
+              }
+
+              @Override
+              public void onError(SatelliteException exception) {
+                callback.onError(new SatelliteExceptionWrapper(exception.getErrorCode()));
+              }
+            };
+    mSatelliteManager.deprovisionSatellite(list.stream()
+            .map(info -> new SatelliteSubscriberInfo.Builder()
+                    .setSubscriberId(info.getSubscriberId())
+                    .setCarrierId(info.getCarrierId()).setNiddApn(info.getNiddApn())
+                    .setSubId(info.getSubId()).setSubscriberIdType(info.getSubscriberIdType())
+                    .build())
+            .collect(Collectors.toList()), executor, internalCallback);
+  }
+
+  /**
+   * Inform whether application supports NTN SMS in satellite mode.
+   *
+   * This method is used by default messaging application to inform framework whether it supports
+   * NTN SMS or not.
+   *
+   * @param ntnSmsSupported {@code true} If application supports NTN SMS, else {@code false}.
+   */
+  public void setNtnSmsSupported(boolean ntnSmsSupported) {
+    if (mSatelliteManager == null) {
+      logd("setNtnSmsSupported: mSatelliteManager is null");
+      return;
+    }
+
+    mSatelliteManager.setNtnSmsSupported(ntnSmsSupported);
+  }
+
   @Nullable
   private ServiceState getServiceStateForSubscriptionId(int subId) {
     if (!mSubscriptionManager.isValidSubscriptionId(subId)) {
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteModemStateCallbackWrapper2.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteModemStateCallbackWrapper2.java
index 054167b..ea01f8b 100644
--- a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteModemStateCallbackWrapper2.java
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteModemStateCallbackWrapper2.java
@@ -40,4 +40,11 @@ public interface SatelliteModemStateCallbackWrapper2 {
    *        For LTE (EMM), cause codes are TS 24.301 Sec 9.9.3.9
    */
   default void onRegistrationFailure(int causeCode) {};
+
+  /**
+   * Indicates that the background search for terrestrial network is finished with result
+   *
+   * @param isAvailable True means there's terrestrial network and false means there's not.
+   */
+  default void onTerrestrialNetworkAvailableChanged(boolean isAvailable) {};
 }
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatellitePositionWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SatellitePositionWrapper.java
new file mode 100644
index 0000000..60b197e
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatellitePositionWrapper.java
@@ -0,0 +1,138 @@
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
+package android.telephony.satellite.wrapper;
+
+import android.annotation.FlaggedApi;
+import android.os.Parcel;
+import android.os.Parcelable;
+
+import androidx.annotation.NonNull;
+
+import com.android.internal.telephony.flags.Flags;
+
+import java.util.Objects;
+
+/**
+ * The position of a satellite in Earth orbit.
+ *
+ * Longitude is the angular distance, measured in degrees, east or west of the prime longitude line
+ * ranging from -180 to 180 degrees
+ * Altitude is the distance from the center of the Earth to the satellite, measured in kilometers
+ *
+ * @hide
+ */
+public class SatellitePositionWrapper implements Parcelable {
+
+    /**
+     * The longitude of the satellite in degrees, ranging from -180 to 180 degrees
+     */
+    private double mLongitudeDegree;
+
+    /**
+     * The distance from the center of the earth to the satellite, measured in kilometers
+     */
+    private double mAltitudeKm;
+
+    /**
+     * Constructor for {@link SatellitePositionWrapper} used to create an instance from a
+     * {@link Parcel}.
+     *
+     * @param in The {@link Parcel} to read the satellite position data from.
+     */
+    public SatellitePositionWrapper(Parcel in) {
+        mLongitudeDegree = in.readDouble();
+        mAltitudeKm = in.readDouble();
+    }
+
+    /**
+     * Constructor for {@link SatellitePositionWrapper}.
+     *
+     * @param longitudeDegree The longitude of the satellite in degrees.
+     * @param altitudeKm      The altitude of the satellite in kilometers.
+     */
+    public SatellitePositionWrapper(double longitudeDegree, double altitudeKm) {
+        mLongitudeDegree = longitudeDegree;
+        mAltitudeKm = altitudeKm;
+    }
+
+    public static final Creator<SatellitePositionWrapper> CREATOR =
+            new Creator<SatellitePositionWrapper>() {
+                @Override
+                public SatellitePositionWrapper createFromParcel(Parcel in) {
+                    return new SatellitePositionWrapper(in);
+                }
+
+                @Override
+                public SatellitePositionWrapper[] newArray(int size) {
+                    return new SatellitePositionWrapper[size];
+                }
+            };
+
+    @Override
+    public int describeContents() {
+        return 0;
+    }
+
+    /**
+     * @param dest  The Parcel in which the object should be written.
+     * @param flags Additional flags about how the object should be written.
+     *              May be 0 or {@link #PARCELABLE_WRITE_RETURN_VALUE}.
+     */
+    @Override
+    public void writeToParcel(@NonNull Parcel dest, int flags) {
+        dest.writeDouble(mLongitudeDegree);
+        dest.writeDouble(mAltitudeKm);
+    }
+
+    /**
+     * Returns the longitude of the satellite in degrees, ranging from -180 to 180 degrees.
+     *
+     * @return The longitude of the satellite.
+     */
+    public double getLongitudeDegrees() {
+        return mLongitudeDegree;
+    }
+
+    /**
+     * Returns the altitude of the satellite in kilometers
+     *
+     * @return The altitude of the satellite.
+     */
+    public double getAltitudeKm() {
+        return mAltitudeKm;
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof SatellitePositionWrapper that)) return false;
+
+        return Double.compare(that.mLongitudeDegree, mLongitudeDegree) == 0
+                && Double.compare(that.mAltitudeKm, mAltitudeKm) == 0;
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(mLongitudeDegree, mAltitudeKm);
+    }
+
+    @Override
+    @NonNull
+    public String toString() {
+        return "mLongitudeDegree: " + mLongitudeDegree + ", " + "mAltitudeKm: " + mAltitudeKm;
+    }
+}
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSessionStatsWrapper2.java b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSessionStatsWrapper2.java
new file mode 100644
index 0000000..6a4a862
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SatelliteSessionStatsWrapper2.java
@@ -0,0 +1,462 @@
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
+package android.telephony.satellite.wrapper;
+
+import android.annotation.NonNull;
+import android.os.Parcel;
+import android.os.Parcelable;
+import android.telephony.satellite.SatelliteManager;
+import android.util.Log;
+
+import java.util.HashMap;
+import java.util.Map;
+import java.util.Objects;
+
+/**
+ * SatelliteSessionStatsWrapper2 is used to represent the usage stats of the satellite service.
+ */
+public class SatelliteSessionStatsWrapper2 implements Parcelable {
+
+    private static final int VERSION = 2;
+    private int mCountOfSuccessfulUserMessages;
+    private int mCountOfUnsuccessfulUserMessages;
+    private int mCountOfTimedOutUserMessagesWaitingForConnection;
+    private int mCountOfTimedOutUserMessagesWaitingForAck;
+    private int mCountOfUserMessagesInQueueToBeSent;
+    private long mLatencyOfSuccessfulUserMessages;
+
+    private Map<Integer, SatelliteSessionStatsWrapper2> datagramStats;
+    private long mMaxLatency;
+    private long mLastMessageLatency;
+
+
+    public SatelliteSessionStatsWrapper2() {
+        this.datagramStats = new HashMap<>();
+    }
+
+
+    /**
+     * SatelliteSessionStatsWrapper2 constructor
+     *
+     * @param builder Builder to create SatelliteSessionStatsWrapper2 object/
+     */
+    public SatelliteSessionStatsWrapper2(@NonNull Builder builder) {
+        mCountOfSuccessfulUserMessages = builder.mCountOfSuccessfulUserMessages;
+        mCountOfUnsuccessfulUserMessages = builder.mCountOfUnsuccessfulUserMessages;
+        mCountOfTimedOutUserMessagesWaitingForConnection =
+                builder.mCountOfTimedOutUserMessagesWaitingForConnection;
+        mCountOfTimedOutUserMessagesWaitingForAck =
+                builder.mCountOfTimedOutUserMessagesWaitingForAck;
+        mCountOfUserMessagesInQueueToBeSent = builder.mCountOfUserMessagesInQueueToBeSent;
+        mLatencyOfSuccessfulUserMessages = builder.mLatencyOfSuccessfulUserMessages;
+    }
+
+    private SatelliteSessionStatsWrapper2(Parcel in) {
+        readFromParcel(in);
+    }
+
+    @Override
+    public int describeContents() {
+        return 0;
+    }
+
+    @Override
+    public void writeToParcel(@NonNull Parcel out, int flags) {
+        out.writeInt(mCountOfSuccessfulUserMessages);
+        out.writeInt(mCountOfUnsuccessfulUserMessages);
+        out.writeInt(mCountOfTimedOutUserMessagesWaitingForConnection);
+        out.writeInt(mCountOfTimedOutUserMessagesWaitingForAck);
+        out.writeInt(mCountOfUserMessagesInQueueToBeSent);
+        out.writeLong(mLatencyOfSuccessfulUserMessages);
+        out.writeLong(mMaxLatency);
+        out.writeLong(mLastMessageLatency);
+
+        if (datagramStats != null && !datagramStats.isEmpty()) {
+            out.writeInt(datagramStats.size());
+            for (Map.Entry<Integer, SatelliteSessionStatsWrapper2> entry :
+                    datagramStats.entrySet()) {
+                out.writeInt(entry.getKey());
+                out.writeParcelable(entry.getValue(), flags);
+            }
+        } else {
+            out.writeInt(0);
+        }
+    }
+
+    @NonNull
+    public static final Creator<SatelliteSessionStatsWrapper2> CREATOR = new Creator<>() {
+
+        @Override
+        public SatelliteSessionStatsWrapper2 createFromParcel(Parcel in) {
+            return new SatelliteSessionStatsWrapper2(in);
+        }
+
+        @Override
+        public SatelliteSessionStatsWrapper2[] newArray(int size) {
+            return new SatelliteSessionStatsWrapper2[size];
+        }
+    };
+
+    @Override
+    @NonNull
+    public String toString() {
+        StringBuilder sb = new StringBuilder();
+        if (datagramStats != null) {
+            sb.append(" ====== SatelliteSessionStatsWrapper2 Info =============");
+            for (Map.Entry<Integer, SatelliteSessionStatsWrapper2> entry :
+                    datagramStats.entrySet()) {
+                Integer key = entry.getKey();
+                SatelliteSessionStatsWrapper2 value = entry.getValue();
+                sb.append("\n");
+                sb.append("Key:");
+                sb.append(key);
+                sb.append(", SatelliteSessionStatsWrapper2:[");
+                value.getPrintableCounters(sb);
+                sb.append(",");
+                sb.append(" LatencyOfSuccessfulUserMessages:");
+                sb.append(value.mLatencyOfSuccessfulUserMessages);
+                sb.append(",");
+                sb.append(" mMaxLatency:");
+                sb.append(value.mMaxLatency);
+                sb.append(",");
+                sb.append(" mLastMessageLatency:");
+                sb.append(value.mLastMessageLatency);
+                sb.append(",");
+                sb.append(" VERSION:");
+                sb.append(value.VERSION);
+                sb.append("]");
+                sb.append("\n");
+            }
+            sb.append(" ============== ================== ===============");
+            sb.append("\n");
+            sb.append("\n");
+        } else {
+            sb.append("\n");
+            getPrintableCounters(sb);
+        }
+        sb.append("\n");
+        return sb.toString();
+    }
+
+    private void getPrintableCounters(StringBuilder sb) {
+        sb.append("countOfSuccessfulUserMessages:");
+        sb.append(mCountOfSuccessfulUserMessages);
+        sb.append(",");
+
+        sb.append("countOfUnsuccessfulUserMessages:");
+        sb.append(mCountOfUnsuccessfulUserMessages);
+        sb.append(",");
+
+        sb.append("countOfTimedOutUserMessagesWaitingForConnection:");
+        sb.append(mCountOfTimedOutUserMessagesWaitingForConnection);
+        sb.append(",");
+
+        sb.append("countOfTimedOutUserMessagesWaitingForAck:");
+        sb.append(mCountOfTimedOutUserMessagesWaitingForAck);
+        sb.append(",");
+
+        sb.append("countOfUserMessagesInQueueToBeSent:");
+        sb.append(mCountOfUserMessagesInQueueToBeSent);
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (o == null || getClass() != o.getClass()) return false;
+        SatelliteSessionStatsWrapper2 that = (SatelliteSessionStatsWrapper2) o;
+        return mCountOfSuccessfulUserMessages == that.mCountOfSuccessfulUserMessages
+                && mLatencyOfSuccessfulUserMessages == that.mLatencyOfSuccessfulUserMessages
+                && mCountOfUnsuccessfulUserMessages == that.mCountOfUnsuccessfulUserMessages
+                && mCountOfTimedOutUserMessagesWaitingForConnection
+                == that.mCountOfTimedOutUserMessagesWaitingForConnection
+                && mCountOfTimedOutUserMessagesWaitingForAck
+                == that.mCountOfTimedOutUserMessagesWaitingForAck
+                && mCountOfUserMessagesInQueueToBeSent == that.mCountOfUserMessagesInQueueToBeSent;
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(mCountOfSuccessfulUserMessages, mLatencyOfSuccessfulUserMessages,
+                mCountOfUnsuccessfulUserMessages, mCountOfTimedOutUserMessagesWaitingForConnection,
+                mCountOfTimedOutUserMessagesWaitingForAck, mCountOfUserMessagesInQueueToBeSent);
+    }
+
+    public int getCountOfSuccessfulUserMessages() {
+        return mCountOfSuccessfulUserMessages;
+    }
+
+    public void incrementSuccessfulUserMessageCount() {
+        mCountOfSuccessfulUserMessages++;
+    }
+
+    public int getCountOfUnsuccessfulUserMessages() {
+        return mCountOfUnsuccessfulUserMessages;
+    }
+
+    public void incrementUnsuccessfulUserMessageCount() {
+        mCountOfUnsuccessfulUserMessages++;
+    }
+
+    public int getCountOfTimedOutUserMessagesWaitingForConnection() {
+        return mCountOfTimedOutUserMessagesWaitingForConnection;
+    }
+
+    public void incrementTimedOutUserMessagesWaitingForConnection() {
+        mCountOfTimedOutUserMessagesWaitingForConnection++;
+    }
+
+    public int getCountOfTimedOutUserMessagesWaitingForAck() {
+        return mCountOfTimedOutUserMessagesWaitingForAck;
+    }
+
+    public void incrementTimedOutUserMessagesWaitingForAck() {
+        mCountOfTimedOutUserMessagesWaitingForAck++;
+    }
+
+    public int getCountOfUserMessagesInQueueToBeSent() {
+        return mCountOfUserMessagesInQueueToBeSent;
+    }
+
+    public long getLatencyOfAllSuccessfulUserMessages() {
+        return mLatencyOfSuccessfulUserMessages;
+    }
+
+    public void updateLatencyOfAllSuccessfulUserMessages(long messageLatency) {
+        mLatencyOfSuccessfulUserMessages += messageLatency;
+    }
+
+    public void recordSuccessfulOutgoingDatagramStats(
+            @SatelliteManager.DatagramType int datagramType, long latency) {
+        try {
+            datagramStats.putIfAbsent(datagramType, new Builder().build());
+            SatelliteSessionStatsWrapper2 data = datagramStats.get(datagramType);
+            data.incrementSuccessfulUserMessageCount();
+            if (data.mMaxLatency < latency) {
+                data.mMaxLatency = latency;
+            }
+            data.mLastMessageLatency = latency;
+            data.updateLatencyOfAllSuccessfulUserMessages(latency);
+        } catch (Exception e) {
+            Log.e("SatelliteSessionStatsWrapper2",
+                    "Error while recordSuccessfulOutgoingDatagramStats: " + e.getMessage());
+        }
+    }
+
+    public int getCountOfSuccessfulOutgoingDatagram(
+            @SatelliteManager.DatagramType int datagramType) {
+        SatelliteSessionStatsWrapper2 data = datagramStats.getOrDefault(datagramType,
+                new SatelliteSessionStatsWrapper2());
+        return data.getCountOfSuccessfulUserMessages();
+    }
+
+    public long getMaxLatency() {
+        return this.mMaxLatency;
+    }
+
+    public void setMaxLatency(long latency) {
+        this.mMaxLatency = latency;
+    }
+
+    public Long getLatencyOfAllSuccessfulUserMessages(
+            @SatelliteManager.DatagramType int datagramType) {
+        SatelliteSessionStatsWrapper2 data = datagramStats.getOrDefault(datagramType,
+                new SatelliteSessionStatsWrapper2());
+        return data.getLatencyOfAllSuccessfulUserMessages();
+    }
+
+    public long getLastMessageLatency() {
+        return this.mLastMessageLatency;
+    }
+
+    public void setLastMessageLatency(long latency) {
+        this.mLastMessageLatency = latency;
+    }
+
+    public void addCountOfUnsuccessfulUserMessages(@SatelliteManager.DatagramType int datagramType,
+            @SatelliteManager.SatelliteResult int resultCode) {
+        try {
+            datagramStats.putIfAbsent(datagramType, new Builder().build());
+            SatelliteSessionStatsWrapper2 data = datagramStats.get(datagramType);
+            data.incrementUnsuccessfulUserMessageCount();
+            if (resultCode == SatelliteManager.SATELLITE_RESULT_NOT_REACHABLE) {
+                data.incrementTimedOutUserMessagesWaitingForConnection();
+            } else if (resultCode == SatelliteManager.SATELLITE_RESULT_MODEM_TIMEOUT) {
+                data.incrementTimedOutUserMessagesWaitingForAck();
+            }
+        } catch (Exception e) {
+            Log.e("SatelliteSessionStatsWrapper2",
+                    "Error while addCountOfUnsuccessfulUserMessages: " + e.getMessage());
+        }
+    }
+
+    public int getCountOfUnsuccessfulUserMessages(@SatelliteManager.DatagramType int datagramType) {
+        SatelliteSessionStatsWrapper2 data = datagramStats.get(datagramType);
+        return data.getCountOfUnsuccessfulUserMessages();
+    }
+
+    public int getCountOfTimedOutUserMessagesWaitingForConnection(
+            @SatelliteManager.DatagramType int datagramType) {
+        SatelliteSessionStatsWrapper2 data = datagramStats.get(datagramType);
+        return data.getCountOfTimedOutUserMessagesWaitingForConnection();
+    }
+
+    public int getCountOfTimedOutUserMessagesWaitingForAck(
+            @SatelliteManager.DatagramType int datagramType) {
+        SatelliteSessionStatsWrapper2 data = datagramStats.get(datagramType);
+        return data.getCountOfTimedOutUserMessagesWaitingForAck();
+    }
+
+    public int getCountOfUserMessagesInQueueToBeSent(
+            @SatelliteManager.DatagramType int datagramType) {
+        SatelliteSessionStatsWrapper2 data = datagramStats.get(datagramType);
+        return data.getCountOfUserMessagesInQueueToBeSent();
+    }
+
+    public int getVersion() {
+        return VERSION;
+    }
+
+    public void clear() {
+        datagramStats.clear();
+    }
+
+    @NonNull
+    public Map<Integer, SatelliteSessionStatsWrapper2> getSatelliteSessionStats() {
+        return datagramStats;
+    }
+
+    public void setSatelliteSessionStats(Map<Integer, SatelliteSessionStatsWrapper2> sessionStats) {
+        this.datagramStats = sessionStats;
+    }
+
+    public void setCountOfSuccessfulUserMessages(int count) {
+        mCountOfSuccessfulUserMessages = count;
+    }
+
+    public void setCountOfUnsuccessfulUserMessages(int count) {
+        mCountOfUnsuccessfulUserMessages = count;
+    }
+
+    public void setCountOfTimedOutUserMessagesWaitingForConnection(int count) {
+        mCountOfTimedOutUserMessagesWaitingForConnection = count;
+    }
+
+
+    public void setCountOfTimedOutUserMessagesWaitingForAck(int count) {
+        mCountOfTimedOutUserMessagesWaitingForAck = count;
+    }
+
+
+    public void setCountOfUserMessagesInQueueToBeSent(int count) {
+        mCountOfUserMessagesInQueueToBeSent = count;
+    }
+
+    private void readFromParcel(Parcel in) {
+        mCountOfSuccessfulUserMessages = in.readInt();
+        mCountOfUnsuccessfulUserMessages = in.readInt();
+        mCountOfTimedOutUserMessagesWaitingForConnection = in.readInt();
+        mCountOfTimedOutUserMessagesWaitingForAck = in.readInt();
+        mCountOfUserMessagesInQueueToBeSent = in.readInt();
+        mLatencyOfSuccessfulUserMessages = in.readLong();
+        mMaxLatency = in.readLong();
+        mLastMessageLatency = in.readLong();
+
+        int size = in.readInt();
+        datagramStats = new HashMap<>();
+        for (int i = 0; i < size; i++) {
+            Integer key = in.readInt();
+            SatelliteSessionStatsWrapper2 value = in.readParcelable(
+                    SatelliteSessionStatsWrapper2.class.getClassLoader());
+            datagramStats.put(key, value);
+        }
+    }
+
+    /**
+     * A builder class to create {@link SatelliteSessionStatsWrapper2} data object.
+     */
+    public static final class Builder {
+        private int mCountOfSuccessfulUserMessages;
+        private int mCountOfUnsuccessfulUserMessages;
+        private int mCountOfTimedOutUserMessagesWaitingForConnection;
+        private int mCountOfTimedOutUserMessagesWaitingForAck;
+        private int mCountOfUserMessagesInQueueToBeSent;
+        private long mLatencyOfSuccessfulUserMessages;
+
+        /**
+         * Sets countOfSuccessfulUserMessages value of {@link SatelliteSessionStatsWrapper2}
+         * and then returns the Builder class.
+         */
+        @NonNull
+        public Builder setCountOfSuccessfulUserMessages(int count) {
+            mCountOfSuccessfulUserMessages = count;
+            return this;
+        }
+
+        /**
+         * Sets countOfUnsuccessfulUserMessages value of {@link SatelliteSessionStatsWrapper2}
+         * and then returns the Builder class.
+         */
+        @NonNull
+        public Builder setCountOfUnsuccessfulUserMessages(int count) {
+            mCountOfUnsuccessfulUserMessages = count;
+            return this;
+        }
+
+        /**
+         * Sets countOfTimedOutUserMessagesWaitingForConnection value of
+         * {@link SatelliteSessionStatsWrapper2} and then returns the Builder class.
+         */
+        @NonNull
+        public Builder setCountOfTimedOutUserMessagesWaitingForConnection(int count) {
+            mCountOfTimedOutUserMessagesWaitingForConnection = count;
+            return this;
+        }
+
+        /**
+         * Sets countOfTimedOutUserMessagesWaitingForAck value of
+         * {@link SatelliteSessionStatsWrapper2}
+         * and then returns the Builder class.
+         */
+        @NonNull
+        public Builder setCountOfTimedOutUserMessagesWaitingForAck(int count) {
+            mCountOfTimedOutUserMessagesWaitingForAck = count;
+            return this;
+        }
+
+        /**
+         * Sets countOfUserMessagesInQueueToBeSent value of {@link SatelliteSessionStatsWrapper2}
+         * and then returns the Builder class.
+         */
+        @NonNull
+        public Builder setCountOfUserMessagesInQueueToBeSent(int count) {
+            mCountOfUserMessagesInQueueToBeSent = count;
+            return this;
+        }
+
+        @NonNull
+        public Builder setLatencyOfSuccessfulUserMessages(long latency) {
+            mLatencyOfSuccessfulUserMessages = latency;
+            return this;
+        }
+
+        /** Returns SatelliteSessionStatsWrapper2 object. */
+        @NonNull
+        public SatelliteSessionStatsWrapper2 build() {
+            return new SatelliteSessionStatsWrapper2(this);
+        }
+    }
+}
\ No newline at end of file
diff --git a/satellite_client/src/android/telephony/satellite/wrapper/SelectedNbIotSatelliteSubscriptionCallbackWrapper.java b/satellite_client/src/android/telephony/satellite/wrapper/SelectedNbIotSatelliteSubscriptionCallbackWrapper.java
new file mode 100644
index 0000000..b716de5
--- /dev/null
+++ b/satellite_client/src/android/telephony/satellite/wrapper/SelectedNbIotSatelliteSubscriptionCallbackWrapper.java
@@ -0,0 +1,29 @@
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
+package android.telephony.satellite.wrapper;
+
+/**
+ * A callback class for selected satellite subscription changed events.
+ */
+public interface SelectedNbIotSatelliteSubscriptionCallbackWrapper {
+  /**
+   * Called when selected satellite subscription has changed.
+   *
+   * @param selectedSubId The new satellite subscription id.
+   */
+  void onSelectedNbIotSatelliteSubscriptionChanged(int selectedSubId);
+}
\ No newline at end of file
```

