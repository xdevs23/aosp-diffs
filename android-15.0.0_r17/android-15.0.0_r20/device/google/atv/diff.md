```diff
diff --git a/FrameworkPackageStubs/res/values-fa/strings.xml b/FrameworkPackageStubs/res/values-fa/strings.xml
index a11a290..6466153 100644
--- a/FrameworkPackageStubs/res/values-fa/strings.xml
+++ b/FrameworkPackageStubs/res/values-fa/strings.xml
@@ -1,7 +1,7 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="1051886861071228918">"شبه‌کد فعالیت"</string>
+    <string name="app_name" msgid="1051886861071228918">"فعالیت پایه"</string>
     <string name="message_not_supported" msgid="5269947674108844893">"برنامه‌ای ندارید که بتواند این کار را انجام دهد"</string>
     <string name="stub_name" msgid="2907730040872891281">"هیچ‌کدام"</string>
 </resources>
diff --git a/FrameworkPackageStubs/res/values-tr/strings.xml b/FrameworkPackageStubs/res/values-tr/strings.xml
index f69892b..72726ec 100644
--- a/FrameworkPackageStubs/res/values-tr/strings.xml
+++ b/FrameworkPackageStubs/res/values-tr/strings.xml
@@ -1,7 +1,7 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="1051886861071228918">"İşlem Kaba Koduı"</string>
+    <string name="app_name" msgid="1051886861071228918">"Activity Stub"</string>
     <string name="message_not_supported" msgid="5269947674108844893">"Bunu yapabilen bir uygulamanız yok"</string>
     <string name="stub_name" msgid="2907730040872891281">"Yok"</string>
 </resources>
diff --git a/MdnsOffloadManagerService/AndroidManifest.xml b/MdnsOffloadManagerService/AndroidManifest.xml
index bcfd1de..14218c4 100644
--- a/MdnsOffloadManagerService/AndroidManifest.xml
+++ b/MdnsOffloadManagerService/AndroidManifest.xml
@@ -31,7 +31,7 @@
     <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
     <uses-permission android:name="android.permission.INTERNET" />
     <uses-permission android:name="android.permission.WAKE_LOCK"/>
-    <uses-permission android:name="android.permission.NETWORK_SETTINGS"/>
+    <uses-permission android:name="android.permission.REGISTER_NSD_OFFLOAD_ENGINE"/>
 
     <application
         android:label="MdnsOffloadManager"
diff --git a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/MdnsOffloadManagerService.java b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/MdnsOffloadManagerService.java
index df4b4d3..153e55b 100644
--- a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/MdnsOffloadManagerService.java
+++ b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/MdnsOffloadManagerService.java
@@ -71,6 +71,8 @@ public class MdnsOffloadManagerService extends Service {
     private static final int VENDOR_SERVICE_COMPONENT_ID =
             R.string.config_mdnsOffloadVendorServiceComponent;
     private static final int AWAIT_DUMP_SECONDS = 5;
+    /** If the service is currently bound. */
+    private static boolean mIsBound;
 
     private final ConnectivityManager.NetworkCallback mNetworkCallback =
             new ConnectivityManagerNetworkCallback();
@@ -84,6 +86,8 @@ public class MdnsOffloadManagerService extends Service {
     private ConnectivityManager mConnectivityManager;
     private PackageManager mPackageManager;
     private WakeLockWrapper mWakeLock;
+    private BroadcastReceiver lowPowerStandbyPolicyReceiver;
+    private BroadcastReceiver screenBroadcastReceiver;
 
     private NsdManagerWrapper mNsdManager;
 
@@ -147,6 +151,13 @@ public class MdnsOffloadManagerService extends Service {
             return mContext.bindService(intent, connection, flags);
         }
 
+        void unbindService(ServiceConnection connection) {
+            if (mIsBound) {
+                mContext.unbindService(connection);
+            }
+            mIsBound = false;
+        }
+
         void registerReceiver(BroadcastReceiver receiver, IntentFilter filter, int flags) {
             mContext.registerReceiver(receiver, filter, flags);
         }
@@ -172,12 +183,24 @@ public class MdnsOffloadManagerService extends Service {
         mPackageManager = mInjector.getPackageManager();
         mWakeLock = mInjector.newWakeLock();
         mNsdManager = mInjector.getNsdManager();
+        lowPowerStandbyPolicyReceiver = new LowPowerStandbyPolicyReceiver();
+        screenBroadcastReceiver = new ScreenBroadcastReceiver();
         bindVendorService();
         setupScreenBroadcastReceiver();
         setupConnectivityListener();
         setupStandbyPolicyListener();
     }
 
+    @Override
+    public void onDestroy() {
+        // Unregister the receiver to avoid memory leaks
+        unregisterReceiver(lowPowerStandbyPolicyReceiver);
+        unregisterReceiver(screenBroadcastReceiver);
+        mConnectivityManager.unregisterNetworkCallback(mNetworkCallback);
+        mInjector.unbindService(mVendorServiceConnection);
+        super.onDestroy();
+    }
+
     private void bindVendorService() {
         String vendorServicePath = mInjector.getResources().getString(VENDOR_SERVICE_COMPONENT_ID);
 
@@ -198,9 +221,9 @@ public class MdnsOffloadManagerService extends Service {
 
         Intent explicitIntent = new Intent();
         explicitIntent.setComponent(componentName);
-        boolean bindingSuccessful = mInjector.bindService(
+        boolean mIsBound = mInjector.bindService(
                 explicitIntent, mVendorServiceConnection, Context.BIND_AUTO_CREATE);
-        if (!bindingSuccessful) {
+        if (!mIsBound) {
             String msg = "Failed to bind to vendor service at {" + vendorServicePath + "}.";
             Log.e(TAG, msg);
             throw new IllegalStateException(msg);
@@ -208,11 +231,10 @@ public class MdnsOffloadManagerService extends Service {
     }
 
     private void setupScreenBroadcastReceiver() {
-        BroadcastReceiver receiver = new ScreenBroadcastReceiver();
         IntentFilter filter = new IntentFilter();
         filter.addAction(Intent.ACTION_SCREEN_ON);
         filter.addAction(Intent.ACTION_SCREEN_OFF);
-        mInjector.registerReceiver(receiver, filter, 0);
+        mInjector.registerReceiver(screenBroadcastReceiver, filter, 0);
         mHandler.post(() -> mOffloadWriter.setOffloadState(!mInjector.isInteractive()));
     }
 
@@ -226,10 +248,9 @@ public class MdnsOffloadManagerService extends Service {
     }
 
     private void setupStandbyPolicyListener() {
-        BroadcastReceiver receiver = new LowPowerStandbyPolicyReceiver();
         IntentFilter filter = new IntentFilter();
         filter.addAction(PowerManager.ACTION_LOW_POWER_STANDBY_POLICY_CHANGED);
-        mInjector.registerReceiver(receiver, filter, 0);
+        mInjector.registerReceiver(lowPowerStandbyPolicyReceiver, filter, 0);
         refreshAppIdAllowlist();
     }
 
@@ -442,7 +463,7 @@ public class MdnsOffloadManagerService extends Service {
         }
 
         public void onServiceDisconnected(ComponentName className) {
-            Log.e(TAG, "IMdnsOffload service has unexpectedly disconnected.");
+            Log.e(TAG, "IMdnsOffload service has disconnected.");
             mHandler.post(() -> {
                 mOffloadWriter.setVendorService(null);
                 mInterfaceOffloadManagers.values()
@@ -557,4 +578,4 @@ public class MdnsOffloadManagerService extends Service {
     }
 
 
-}
+}
\ No newline at end of file
diff --git a/audio_proxy/Android.bp b/audio_proxy/Android.bp
deleted file mode 100644
index eca5f07..0000000
--- a/audio_proxy/Android.bp
+++ /dev/null
@@ -1,38 +0,0 @@
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_google_atv_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["device_google_atv_license"],
-}
-
-cc_library {
-  name: "libaudio_proxy.google",
-
-  system_ext_specific: true,
-
-  srcs: [
-    "AudioProxy.cpp",
-    "AudioProxyDevice.cpp",
-    "AudioProxyManager.cpp",
-    "AudioProxyStreamOut.cpp",
-    "OutputStreamImpl.cpp",
-    "StreamProviderImpl.cpp",
-  ],
-
-  shared_libs: [
-    "device.google.atv.audio_proxy-aidl-V3-ndk",
-    "libbase",
-    "libbinder_ndk",
-    "libcutils",
-    "libfmq",
-    "libutils",
-  ],
-
-  cflags: [
-    "-Werror",
-    "-Wthread-safety",
-    "-Wno-unused-parameter",
-  ],
-}
diff --git a/audio_proxy/AudioProxy.cpp b/audio_proxy/AudioProxy.cpp
deleted file mode 100644
index 0a2fce3..0000000
--- a/audio_proxy/AudioProxy.cpp
+++ /dev/null
@@ -1,53 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include <android-base/logging.h>
-
-#include "AudioProxyManager.h"
-#include "public/audio_proxy.h"
-
-namespace {
-class AudioProxyImpl {
- public:
-  static AudioProxyImpl* getInstance();
-
-  bool registerDevice(audio_proxy_device_t* device);
-
- private:
-  AudioProxyImpl();
-  ~AudioProxyImpl() = default;
-
-  std::unique_ptr<audio_proxy::AudioProxyManager> mManager;
-};
-
-AudioProxyImpl::AudioProxyImpl()
-    : mManager(audio_proxy::createAudioProxyManager()) {
-  DCHECK(mManager);
-}
-
-bool AudioProxyImpl::registerDevice(audio_proxy_device_t* device) {
-  return mManager->registerDevice(device);
-}
-
-// static
-AudioProxyImpl* AudioProxyImpl::getInstance() {
-  static AudioProxyImpl instance;
-  return &instance;
-}
-
-}  // namespace
-
-extern "C" int audio_proxy_register_device(audio_proxy_device_t* device) {
-  return AudioProxyImpl::getInstance()->registerDevice(device) ? 0 : -1;
-}
\ No newline at end of file
diff --git a/audio_proxy/AudioProxyClientError.h b/audio_proxy/AudioProxyClientError.h
deleted file mode 100644
index cf46ab2..0000000
--- a/audio_proxy/AudioProxyClientError.h
+++ /dev/null
@@ -1,29 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-namespace audio_proxy {
-
-enum {
-  ERROR_UNEXPECTED = 1,
-
-  // The arguments don't meet requirements.
-  ERROR_INVALID_ARGS = 2,
-
-  // Failure happens when creating FMQ.
-  ERROR_FMQ_CREATION_FAILURE = 3,
-};
-
-}  // namespace audio_proxy
\ No newline at end of file
diff --git a/audio_proxy/AudioProxyDevice.cpp b/audio_proxy/AudioProxyDevice.cpp
deleted file mode 100644
index 1721cdd..0000000
--- a/audio_proxy/AudioProxyDevice.cpp
+++ /dev/null
@@ -1,99 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "AudioProxyDevice.h"
-
-#include <android-base/logging.h>
-
-#include "AudioProxyStreamOut.h"
-
-using aidl::device::google::atv::audio_proxy::AudioConfig;
-
-#define CHECK_API(st, func)                    \
-  do {                                         \
-    if (!st->func) {                           \
-      LOG(ERROR) << "Undefined API " << #func; \
-      return false;                            \
-    }                                          \
-  } while (0)
-
-namespace audio_proxy {
-namespace {
-bool isValidStreamOut(const audio_proxy_stream_out_t* stream) {
-  CHECK_API(stream, standby);
-  CHECK_API(stream, pause);
-  CHECK_API(stream, resume);
-  CHECK_API(stream, flush);
-  CHECK_API(stream, drain);
-  CHECK_API(stream, write);
-  CHECK_API(stream, get_presentation_position);
-  CHECK_API(stream, set_volume);
-  CHECK_API(stream, get_buffer_size);
-  CHECK_API(stream, get_latency);
-
-  if (stream->v2) {
-    CHECK_API(stream->v2, start);
-    CHECK_API(stream->v2, stop);
-    CHECK_API(stream->v2, create_mmap_buffer);
-    CHECK_API(stream->v2, get_mmap_position);
-  }
-
-  return true;
-}
-}  // namespace
-
-AudioProxyDevice::AudioProxyDevice(audio_proxy_device_t* device)
-    : mDevice(device) {}
-
-AudioProxyDevice::~AudioProxyDevice() = default;
-
-const char* AudioProxyDevice::getServiceName() {
-  return mDevice->v2->get_service_name(mDevice->v2);
-}
-
-std::unique_ptr<AudioProxyStreamOut> AudioProxyDevice::openOutputStream(
-    const std::string& address, const AudioConfig& aidlConfig, int32_t flags) {
-  audio_proxy_config_v2_t config_v2 = {
-      .buffer_size_bytes = aidlConfig.bufferSizeBytes,
-      .latency_ms = aidlConfig.latencyMs,
-      .extension = nullptr};
-
-  audio_proxy_config_t config = {
-      .format = static_cast<audio_proxy_format_t>(aidlConfig.format),
-      .sample_rate = static_cast<uint32_t>(aidlConfig.sampleRateHz),
-      .channel_mask =
-          static_cast<audio_proxy_channel_mask_t>(aidlConfig.channelMask),
-      .frame_count = 0,
-      .v2 = &config_v2};
-
-  // TODO(yucliu): Pass address to the app. For now, the only client app
-  // (MediaShell) can use flags to distinguish different streams.
-  audio_proxy_stream_out_t* stream = nullptr;
-  int ret = mDevice->v2->open_output_stream(
-      mDevice->v2, address.c_str(),
-      static_cast<audio_proxy_output_flags_t>(flags), &config, &stream);
-
-  if (ret || !stream) {
-    return nullptr;
-  }
-
-  if (!isValidStreamOut(stream)) {
-    mDevice->close_output_stream(mDevice, stream);
-    return nullptr;
-  }
-
-  return std::make_unique<AudioProxyStreamOut>(stream, mDevice);
-}
-
-}  // namespace audio_proxy
diff --git a/audio_proxy/AudioProxyDevice.h b/audio_proxy/AudioProxyDevice.h
deleted file mode 100644
index 66636f5..0000000
--- a/audio_proxy/AudioProxyDevice.h
+++ /dev/null
@@ -1,45 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <aidl/device/google/atv/audio_proxy/AudioConfig.h>
-
-#include <memory>
-
-#include "public/audio_proxy.h"
-
-namespace audio_proxy {
-
-class AudioProxyStreamOut;
-
-// C++ friendly wrapper of audio_proxy_device. It handles type conversion
-// between C type and aidl type.
-class AudioProxyDevice final {
- public:
-  explicit AudioProxyDevice(audio_proxy_device_t* device);
-  ~AudioProxyDevice();
-
-  const char* getServiceName();
-
-  std::unique_ptr<AudioProxyStreamOut> openOutputStream(
-      const std::string& address,
-      const aidl::device::google::atv::audio_proxy::AudioConfig& config,
-      int32_t flags);
-
- private:
-  audio_proxy_device_t* const mDevice;
-};
-
-}  // namespace audio_proxy
diff --git a/audio_proxy/AudioProxyManager.cpp b/audio_proxy/AudioProxyManager.cpp
deleted file mode 100644
index 54abfd9..0000000
--- a/audio_proxy/AudioProxyManager.cpp
+++ /dev/null
@@ -1,137 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "AudioProxyManager.h"
-
-#include <aidl/device/google/atv/audio_proxy/IAudioProxy.h>
-#include <android-base/logging.h>
-#include <android-base/thread_annotations.h>
-#include <android/binder_manager.h>
-
-#include <mutex>
-
-#include "AudioProxyDevice.h"
-#include "StreamProviderImpl.h"
-
-using aidl::device::google::atv::audio_proxy::IAudioProxy;
-using android::sp;
-using android::status_t;
-
-namespace audio_proxy {
-namespace {
-
-bool checkDevice(audio_proxy_device_t* device) {
-  return device && device->get_address && device->open_output_stream &&
-         device->close_output_stream &&
-         // Check v2 extension. Currently only MediaShell uses this library and
-         // we'll make sure the MediaShell will update to use the new API.
-         device->v2 && device->v2->get_service_name &&
-         device->v2->open_output_stream;
-}
-
-std::shared_ptr<IAudioProxy> getAudioProxyService(
-    const std::string& serviceName) {
-  std::string instanceName =
-      std::string(IAudioProxy::descriptor) + "/" + serviceName;
-  return IAudioProxy::fromBinder(
-      ndk::SpAIBinder(AServiceManager_getService(instanceName.c_str())));
-}
-
-class AudioProxyManagerImpl : public AudioProxyManager {
- public:
-  AudioProxyManagerImpl();
-  ~AudioProxyManagerImpl() override = default;
-
-  bool registerDevice(audio_proxy_device_t* device) override;
-
-
- private:
-  static void onServiceDied(void* cookie);
-  bool reconnectService();
-  bool reconnectService_Locked() REQUIRES(mLock);
-
-  ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
-
-  std::mutex mLock;
-  std::shared_ptr<IAudioProxy> mService GUARDED_BY(mLock);
-  std::unique_ptr<AudioProxyDevice> mDevice GUARDED_BY(mLock);
-};
-
-AudioProxyManagerImpl::AudioProxyManagerImpl()
-    : mDeathRecipient(
-          AIBinder_DeathRecipient_new(AudioProxyManagerImpl::onServiceDied)) {}
-
-bool AudioProxyManagerImpl::registerDevice(audio_proxy_device_t* device) {
-  if (!checkDevice(device)) {
-    LOG(ERROR) << "Invalid device.";
-    return false;
-  }
-
-  std::scoped_lock<std::mutex> lock(mLock);
-  if (mDevice) {
-    DCHECK(mService);
-    LOG(ERROR) << "Device already registered!";
-    return false;
-  }
-  mDevice = std::make_unique<AudioProxyDevice>(device);
-
-  DCHECK(!mService);
-  return reconnectService_Locked();
-}
-
-bool AudioProxyManagerImpl::reconnectService() {
-  std::scoped_lock<std::mutex> lock(mLock);
-  return reconnectService_Locked();
-}
-
-bool AudioProxyManagerImpl::reconnectService_Locked() {
-  DCHECK(mDevice);
-
-  auto service = getAudioProxyService(mDevice->getServiceName());
-  if (!service) {
-    LOG(ERROR) << "Failed to reconnect service";
-    return false;
-  }
-
-  binder_status_t binder_status = AIBinder_linkToDeath(
-      service->asBinder().get(), mDeathRecipient.get(), this);
-  if (binder_status != STATUS_OK) {
-    LOG(ERROR) << "Failed to linkToDeath " << static_cast<int>(binder_status);
-    return false;
-  }
-
-  ndk::ScopedAStatus status = service->start(
-      ndk::SharedRefBase::make<StreamProviderImpl>(mDevice.get()));
-  if (!status.isOk()) {
-    LOG(ERROR) << "Failed to start service.";
-    return false;
-  }
-
-  mService = std::move(service);
-  return true;
-}
-
-// static
-void AudioProxyManagerImpl::onServiceDied(void* cookie) {
-  auto* manager = static_cast<AudioProxyManagerImpl*>(cookie);
-  manager->reconnectService();
-}
-
-}  // namespace
-
-std::unique_ptr<AudioProxyManager> createAudioProxyManager() {
-  return std::make_unique<AudioProxyManagerImpl>();
-}
-
-}  // namespace audio_proxy
diff --git a/audio_proxy/AudioProxyManager.h b/audio_proxy/AudioProxyManager.h
deleted file mode 100644
index 24b922f..0000000
--- a/audio_proxy/AudioProxyManager.h
+++ /dev/null
@@ -1,31 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <memory>
-
-#include "public/audio_proxy.h"
-
-namespace audio_proxy {
-
-class AudioProxyManager {
- public:
-  virtual ~AudioProxyManager() = default;
-
-  virtual bool registerDevice(audio_proxy_device_t* device) = 0;
-};
-
-std::unique_ptr<AudioProxyManager> createAudioProxyManager();
-}  // namespace audio_proxy
diff --git a/audio_proxy/AudioProxyStreamOut.cpp b/audio_proxy/AudioProxyStreamOut.cpp
deleted file mode 100644
index cb60fe4..0000000
--- a/audio_proxy/AudioProxyStreamOut.cpp
+++ /dev/null
@@ -1,106 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "AudioProxyStreamOut.h"
-
-namespace audio_proxy {
-
-AudioProxyStreamOut::AudioProxyStreamOut(audio_proxy_stream_out_t* stream,
-                                         audio_proxy_device_t* device)
-    : mStream(stream), mDevice(device) {}
-
-AudioProxyStreamOut::~AudioProxyStreamOut() {
-  mDevice->close_output_stream(mDevice, mStream);
-}
-
-ssize_t AudioProxyStreamOut::write(const void* buffer, size_t bytes) {
-  return mStream->write(mStream, buffer, bytes);
-}
-
-void AudioProxyStreamOut::getPresentationPosition(int64_t* frames,
-                                                  TimeSpec* timestamp) const {
-  struct timespec ts;
-  mStream->get_presentation_position(mStream,
-                                     reinterpret_cast<uint64_t*>(frames), &ts);
-
-  timestamp->tvSec = ts.tv_sec;
-  timestamp->tvNSec = ts.tv_nsec;
-}
-
-void AudioProxyStreamOut::standby() { mStream->standby(mStream); }
-
-void AudioProxyStreamOut::pause() { mStream->pause(mStream); }
-
-void AudioProxyStreamOut::resume() { mStream->resume(mStream); }
-
-void AudioProxyStreamOut::drain(AudioDrain type) {
-  mStream->drain(mStream, static_cast<audio_proxy_drain_type_t>(type));
-}
-
-void AudioProxyStreamOut::flush() { mStream->flush(mStream); }
-
-void AudioProxyStreamOut::setVolume(float left, float right) {
-  mStream->set_volume(mStream, left, right);
-}
-
-int64_t AudioProxyStreamOut::getBufferSizeBytes() {
-  return mStream->get_buffer_size(mStream);
-}
-
-int32_t AudioProxyStreamOut::getLatencyMs() {
-  return mStream->get_latency(mStream);
-}
-
-void AudioProxyStreamOut::start() {
-  if (mStream->v2) {
-    mStream->v2->start(mStream->v2);
-  }
-}
-
-void AudioProxyStreamOut::stop() {
-  if (mStream->v2) {
-    mStream->v2->stop(mStream->v2);
-  }
-}
-
-MmapBufferInfo AudioProxyStreamOut::createMmapBuffer(
-    int32_t minBufferSizeFrames) {
-  MmapBufferInfo aidlInfo;
-  if (!mStream->v2) {
-    return aidlInfo;
-  }
-
-  audio_proxy_mmap_buffer_info_t info =
-      mStream->v2->create_mmap_buffer(mStream->v2, minBufferSizeFrames);
-  aidlInfo.sharedMemoryFd.set(info.shared_memory_fd);
-  aidlInfo.bufferSizeFrames = info.buffer_size_frames;
-  aidlInfo.burstSizeFrames = info.burst_size_frames;
-  aidlInfo.flags = info.flags;
-  return aidlInfo;
-}
-
-PresentationPosition AudioProxyStreamOut::getMmapPosition() {
-  PresentationPosition position;
-  if (!mStream->v2) {
-    return position;
-  }
-
-  int64_t frames = 0;
-  struct timespec ts = {0, 0};
-  mStream->v2->get_mmap_position(mStream->v2, &frames, &ts);
-  position.frames = frames;
-  position.timestamp = {ts.tv_sec, ts.tv_nsec};
-  return position;
-}
-}  // namespace audio_proxy
diff --git a/audio_proxy/AudioProxyStreamOut.h b/audio_proxy/AudioProxyStreamOut.h
deleted file mode 100644
index 3ecd4fd..0000000
--- a/audio_proxy/AudioProxyStreamOut.h
+++ /dev/null
@@ -1,65 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <aidl/device/google/atv/audio_proxy/AudioDrain.h>
-#include <aidl/device/google/atv/audio_proxy/MmapBufferInfo.h>
-#include <aidl/device/google/atv/audio_proxy/PresentationPosition.h>
-#include <aidl/device/google/atv/audio_proxy/TimeSpec.h>
-
-#include <memory>
-
-#include "public/audio_proxy.h"
-
-namespace audio_proxy {
-
-using aidl::device::google::atv::audio_proxy::AudioDrain;
-using aidl::device::google::atv::audio_proxy::MmapBufferInfo;
-using aidl::device::google::atv::audio_proxy::PresentationPosition;
-using aidl::device::google::atv::audio_proxy::TimeSpec;
-
-// C++ friendly wrapper of audio_proxy_stream_out. It handles type conversion
-// between C type and aidl type.
-class AudioProxyStreamOut final {
- public:
-  AudioProxyStreamOut(audio_proxy_stream_out_t* stream,
-                      audio_proxy_device_t* device);
-  ~AudioProxyStreamOut();
-
-  ssize_t write(const void* buffer, size_t bytes);
-  void getPresentationPosition(int64_t* frames, TimeSpec* timestamp) const;
-
-  void standby();
-  void pause();
-  void resume();
-  void drain(AudioDrain type);
-  void flush();
-
-  void setVolume(float left, float right);
-
-  int64_t getBufferSizeBytes();
-  int32_t getLatencyMs();
-
-  void start();
-  void stop();
-  MmapBufferInfo createMmapBuffer(int32_t minBufferSizeFrames);
-  PresentationPosition getMmapPosition();
-
- private:
-  audio_proxy_stream_out_t* const mStream;
-  audio_proxy_device_t* const mDevice;
-};
-
-}  // namespace audio_proxy
diff --git a/audio_proxy/OWNERS b/audio_proxy/OWNERS
deleted file mode 100644
index 435706b..0000000
--- a/audio_proxy/OWNERS
+++ /dev/null
@@ -1,2 +0,0 @@
-dorindrimus@google.com
-yucliu@google.com
diff --git a/audio_proxy/OutputStreamImpl.cpp b/audio_proxy/OutputStreamImpl.cpp
deleted file mode 100644
index 935a879..0000000
--- a/audio_proxy/OutputStreamImpl.cpp
+++ /dev/null
@@ -1,289 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "OutputStreamImpl.h"
-
-#include <aidl/device/google/atv/audio_proxy/MessageQueueFlag.h>
-#include <aidl/device/google/atv/audio_proxy/PresentationPosition.h>
-#include <android-base/logging.h>
-#include <time.h>
-
-#include "AudioProxyClientError.h"
-#include "AudioProxyStreamOut.h"
-
-using aidl::device::google::atv::audio_proxy::MessageQueueFlag;
-using android::status_t;
-
-namespace audio_proxy {
-namespace {
-// 1GB
-constexpr uint32_t kMaxBufferSize = 1 << 30;
-
-void deleteEventFlag(EventFlag* obj) {
-  if (!obj) {
-    return;
-  }
-
-  status_t status = EventFlag::deleteEventFlag(&obj);
-  if (status) {
-    LOG(ERROR) << "write MQ event flag deletion error: " << strerror(-status);
-  }
-}
-
-class WriteThread : public Thread {
- public:
-  // WriteThread's lifespan never exceeds StreamOut's lifespan.
-  WriteThread(std::atomic<bool>* stop, AudioProxyStreamOut* stream,
-              OutputStreamImpl::DataMQ* dataMQ,
-              OutputStreamImpl::StatusMQ* statusMQ, EventFlag* eventFlag);
-
-  ~WriteThread() override;
-
- private:
-  bool threadLoop() override;
-
-  PresentationPosition doGetPresentationPosition();
-  int64_t doWrite();
-
-  std::atomic<bool>* const mStop;
-  AudioProxyStreamOut* mStream;
-  OutputStreamImpl::DataMQ* const mDataMQ;
-  OutputStreamImpl::StatusMQ* const mStatusMQ;
-  EventFlag* const mEventFlag;
-  const std::unique_ptr<int8_t[]> mBuffer;
-};
-
-WriteThread::WriteThread(std::atomic<bool>* stop, AudioProxyStreamOut* stream,
-                         OutputStreamImpl::DataMQ* dataMQ,
-                         OutputStreamImpl::StatusMQ* statusMQ,
-                         EventFlag* eventFlag)
-    : Thread(false /*canCallJava*/),
-      mStop(stop),
-      mStream(stream),
-      mDataMQ(dataMQ),
-      mStatusMQ(statusMQ),
-      mEventFlag(eventFlag),
-      mBuffer(new int8_t[mDataMQ->getQuantumCount()]) {}
-
-WriteThread::~WriteThread() = default;
-
-int64_t WriteThread::doWrite() {
-  const size_t availToRead = mDataMQ->availableToRead();
-  if (availToRead == 0) {
-    return 0;
-  }
-
-  if (!mDataMQ->read(&mBuffer[0], availToRead)) {
-    return 0;
-  }
-
-  return mStream->write(&mBuffer[0], availToRead);
-}
-
-PresentationPosition WriteThread::doGetPresentationPosition() {
-  PresentationPosition position;
-  mStream->getPresentationPosition(&position.frames, &position.timestamp);
-  return position;
-}
-
-bool WriteThread::threadLoop() {
-  // This implementation doesn't return control back to the Thread until the
-  // parent thread decides to stop, as the Thread uses mutexes, and this can
-  // lead to priority inversion.
-  while (!std::atomic_load_explicit(mStop, std::memory_order_acquire)) {
-    uint32_t efState = 0;
-    mEventFlag->wait(static_cast<uint32_t>(MessageQueueFlag::NOT_EMPTY),
-                     &efState);
-    if (!(efState & static_cast<uint32_t>(MessageQueueFlag::NOT_EMPTY))) {
-      continue;  // Nothing to do.
-    }
-
-    WriteStatus status;
-    status.written = doWrite();
-    status.position = doGetPresentationPosition();
-
-    if (!mStatusMQ->write(&status)) {
-      LOG(ERROR) << "status message queue write failed.";
-    }
-    mEventFlag->wake(static_cast<uint32_t>(MessageQueueFlag::NOT_FULL));
-  }
-
-  return false;
-}
-
-}  // namespace
-
-OutputStreamImpl::OutputStreamImpl(std::unique_ptr<AudioProxyStreamOut> stream)
-    : mStream(std::move(stream)), mEventFlag(nullptr, deleteEventFlag) {}
-
-OutputStreamImpl::~OutputStreamImpl() {
-  closeImpl();
-
-  if (mWriteThread) {
-    status_t status = mWriteThread->join();
-    if (status) {
-      LOG(ERROR) << "write thread exit error: " << strerror(-status);
-    }
-  }
-
-  mEventFlag.reset();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::standby() {
-  mStream->standby();
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::close() { return closeImpl(); }
-
-ndk::ScopedAStatus OutputStreamImpl::closeImpl() {
-  if (mStopWriteThread.load(
-          std::memory_order_relaxed)) {  // only this thread writes
-    return ndk::ScopedAStatus::ok();
-  }
-  mStopWriteThread.store(true, std::memory_order_release);
-  if (mEventFlag) {
-    mEventFlag->wake(static_cast<uint32_t>(MessageQueueFlag::NOT_EMPTY));
-  }
-
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::prepareForWriting(
-    int32_t frameSize, int32_t framesCount, DataMQDesc* dataMQDesc,
-    StatusMQDesc* statusMQDesc) {
-  if (mDataMQ) {
-    LOG(ERROR) << "the client attempted to call prepareForWriting twice.";
-    return ndk::ScopedAStatus::fromServiceSpecificError(ERROR_INVALID_ARGS);
-  }
-
-  if (frameSize == 0 || framesCount == 0) {
-    LOG(ERROR) << "Invalid frameSize (" << frameSize << ") or framesCount ("
-               << framesCount << ")";
-    return ndk::ScopedAStatus::fromServiceSpecificError(ERROR_INVALID_ARGS);
-  }
-
-  if (frameSize > kMaxBufferSize / framesCount) {
-    LOG(ERROR) << "Buffer too big: " << frameSize << "*" << framesCount
-               << " bytes > MAX_BUFFER_SIZE (" << kMaxBufferSize << ")";
-    return ndk::ScopedAStatus::fromServiceSpecificError(ERROR_INVALID_ARGS);
-  }
-
-  auto dataMQ =
-      std::make_unique<DataMQ>(frameSize * framesCount, true /* EventFlag */);
-  if (!dataMQ->isValid()) {
-    LOG(ERROR) << "data MQ is invalid";
-    return ndk::ScopedAStatus::fromServiceSpecificError(
-        ERROR_FMQ_CREATION_FAILURE);
-  }
-
-  auto statusMQ = std::make_unique<StatusMQ>(1);
-  if (!statusMQ->isValid()) {
-    LOG(ERROR) << "status MQ is invalid";
-    return ndk::ScopedAStatus::fromServiceSpecificError(
-        ERROR_FMQ_CREATION_FAILURE);
-  }
-
-  EventFlag* rawEventFlag = nullptr;
-  status_t status =
-      EventFlag::createEventFlag(dataMQ->getEventFlagWord(), &rawEventFlag);
-  std::unique_ptr<EventFlag, EventFlagDeleter> eventFlag(rawEventFlag,
-                                                         deleteEventFlag);
-  if (status != ::android::OK || !eventFlag) {
-    LOG(ERROR) << "failed creating event flag for data MQ: "
-               << strerror(-status);
-    return ndk::ScopedAStatus::fromServiceSpecificError(
-        ERROR_FMQ_CREATION_FAILURE);
-  }
-
-  sp<WriteThread> writeThread =
-      new WriteThread(&mStopWriteThread, mStream.get(), dataMQ.get(),
-                      statusMQ.get(), eventFlag.get());
-  status = writeThread->run("writer", ::android::PRIORITY_URGENT_AUDIO);
-  if (status != ::android::OK) {
-    LOG(ERROR) << "failed to start writer thread: " << strerror(-status);
-    return ndk::ScopedAStatus::fromServiceSpecificError(
-        ERROR_FMQ_CREATION_FAILURE);
-  }
-
-  mDataMQ = std::move(dataMQ);
-  mStatusMQ = std::move(statusMQ);
-  mEventFlag = std::move(eventFlag);
-  mWriteThread = std::move(writeThread);
-
-  *dataMQDesc = mDataMQ->dupeDesc();
-  *statusMQDesc = mStatusMQ->dupeDesc();
-
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::pause() {
-  mStream->pause();
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::resume() {
-  mStream->resume();
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::drain(AudioDrain type) {
-  mStream->drain(type);
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::flush() {
-  mStream->flush();
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::setVolume(float left, float right) {
-  mStream->setVolume(left, right);
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::getBufferSizeBytes(
-    int64_t* bufferSizeBytes) {
-  *bufferSizeBytes = mStream->getBufferSizeBytes();
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::getLatencyMs(int32_t* latencyMs) {
-  *latencyMs = mStream->getLatencyMs();
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::start() {
-  mStream->start();
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::stop() {
-  mStream->stop();
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::createMmapBuffer(
-    int32_t minBufferSizeFrames, MmapBufferInfo* info) {
-  *info = mStream->createMmapBuffer(minBufferSizeFrames);
-  return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus OutputStreamImpl::getMmapPosition(
-    PresentationPosition* position) {
-  *position = mStream->getMmapPosition();
-  return ndk::ScopedAStatus::ok();
-}
-
-}  // namespace audio_proxy
\ No newline at end of file
diff --git a/audio_proxy/OutputStreamImpl.h b/audio_proxy/OutputStreamImpl.h
deleted file mode 100644
index 7a3f7dc..0000000
--- a/audio_proxy/OutputStreamImpl.h
+++ /dev/null
@@ -1,84 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <aidl/device/google/atv/audio_proxy/BnOutputStream.h>
-#include <fmq/AidlMessageQueue.h>
-#include <fmq/EventFlag.h>
-#include <utils/Thread.h>
-
-using aidl::android::hardware::common::fmq::MQDescriptor;
-using aidl::android::hardware::common::fmq::SynchronizedReadWrite;
-using android::AidlMessageQueue;
-using android::sp;
-using android::Thread;
-using android::hardware::EventFlag;
-
-using aidl::device::google::atv::audio_proxy::AudioDrain;
-using aidl::device::google::atv::audio_proxy::BnOutputStream;
-using aidl::device::google::atv::audio_proxy::MmapBufferInfo;
-using aidl::device::google::atv::audio_proxy::PresentationPosition;
-using aidl::device::google::atv::audio_proxy::WriteStatus;
-
-namespace audio_proxy {
-class AudioProxyStreamOut;
-
-class OutputStreamImpl : public BnOutputStream {
- public:
-  using DataMQ = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
-  using DataMQDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;
-  using StatusMQ = AidlMessageQueue<WriteStatus, SynchronizedReadWrite>;
-  using StatusMQDesc = MQDescriptor<WriteStatus, SynchronizedReadWrite>;
-
-  explicit OutputStreamImpl(std::unique_ptr<AudioProxyStreamOut> stream);
-  ~OutputStreamImpl() override;
-
-  ndk::ScopedAStatus prepareForWriting(int32_t frameSize, int32_t framesCount,
-                                       DataMQDesc* dataMQDesc,
-                                       StatusMQDesc* statusMQDesc) override;
-
-  ndk::ScopedAStatus standby() override;
-  ndk::ScopedAStatus close() override;
-  ndk::ScopedAStatus pause() override;
-  ndk::ScopedAStatus resume() override;
-  ndk::ScopedAStatus drain(AudioDrain type) override;
-  ndk::ScopedAStatus flush() override;
-
-  ndk::ScopedAStatus setVolume(float left, float right) override;
-
-  ndk::ScopedAStatus getBufferSizeBytes(int64_t* bufferSizeBytes) override;
-  ndk::ScopedAStatus getLatencyMs(int32_t* latencyMs) override;
-
-  ndk::ScopedAStatus start() override;
-  ndk::ScopedAStatus stop() override;
-  ndk::ScopedAStatus createMmapBuffer(int32_t minBufferSizeFrames,
-                                      MmapBufferInfo* info) override;
-  ndk::ScopedAStatus getMmapPosition(PresentationPosition* position) override;
-
- private:
-  typedef void (*EventFlagDeleter)(EventFlag*);
-
-  ndk::ScopedAStatus closeImpl();
-
-  std::unique_ptr<AudioProxyStreamOut> mStream;
-
-  std::unique_ptr<DataMQ> mDataMQ;
-  std::unique_ptr<StatusMQ> mStatusMQ;
-  std::unique_ptr<EventFlag, EventFlagDeleter> mEventFlag;
-  std::atomic<bool> mStopWriteThread = false;
-  sp<Thread> mWriteThread;
-};
-
-}  // namespace audio_proxy
\ No newline at end of file
diff --git a/audio_proxy/StreamProviderImpl.cpp b/audio_proxy/StreamProviderImpl.cpp
deleted file mode 100644
index aab0aa2..0000000
--- a/audio_proxy/StreamProviderImpl.cpp
+++ /dev/null
@@ -1,51 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "StreamProviderImpl.h"
-
-#include <android-base/logging.h>
-
-#include "AudioProxyDevice.h"
-#include "AudioProxyStreamOut.h"
-#include "OutputStreamImpl.h"
-
-using aidl::device::google::atv::audio_proxy::AudioConfig;
-using aidl::device::google::atv::audio_proxy::IOutputStream;
-
-namespace audio_proxy {
-
-StreamProviderImpl::StreamProviderImpl(AudioProxyDevice* device)
-    : mDevice(device) {}
-StreamProviderImpl::~StreamProviderImpl() = default;
-
-ndk::ScopedAStatus StreamProviderImpl::openOutputStream(
-    const std::string& address, const AudioConfig& config, int32_t flags,
-    std::shared_ptr<IOutputStream>* outputStream) {
-  *outputStream = nullptr;
-
-  std::unique_ptr<AudioProxyStreamOut> stream =
-      mDevice->openOutputStream(address, config, flags);
-  if (stream) {
-    *outputStream =
-        ndk::SharedRefBase::make<OutputStreamImpl>(std::move(stream));
-  } else {
-    LOG(WARNING) << "Failed to open output stream.";
-  }
-
-  // Returns OK as this is a recoverable failure. The caller can open a new
-  // output stream with different config and flags.
-  return ndk::ScopedAStatus::ok();
-}
-
-}  // namespace audio_proxy
\ No newline at end of file
diff --git a/audio_proxy/StreamProviderImpl.h b/audio_proxy/StreamProviderImpl.h
deleted file mode 100644
index 2fa6f6e..0000000
--- a/audio_proxy/StreamProviderImpl.h
+++ /dev/null
@@ -1,43 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <aidl/device/google/atv/audio_proxy/BnStreamProvider.h>
-
-#include "public/audio_proxy.h"
-
-namespace audio_proxy {
-
-class AudioProxyDevice;
-
-class StreamProviderImpl
-    : public aidl::device::google::atv::audio_proxy::BnStreamProvider {
- public:
-  explicit StreamProviderImpl(AudioProxyDevice* device);
-  ~StreamProviderImpl() override;
-
-  // Methods from IStreamProvider:
-  ndk::ScopedAStatus openOutputStream(
-      const std::string& addres,
-      const aidl::device::google::atv::audio_proxy::AudioConfig& config,
-      int32_t flags,
-      std::shared_ptr<aidl::device::google::atv::audio_proxy::IOutputStream>*
-          outputStream) override;
-
- private:
-  AudioProxyDevice* const mDevice;
-};
-
-}  // namespace audio_proxy
\ No newline at end of file
diff --git a/audio_proxy/common/AudioProxyVersionMacro.h b/audio_proxy/common/AudioProxyVersionMacro.h
deleted file mode 100644
index d8fcd1b..0000000
--- a/audio_proxy/common/AudioProxyVersionMacro.h
+++ /dev/null
@@ -1,43 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-
-#pragma once
-
-#if !defined(MAJOR_VERSION) || !defined(MINOR_VERSION)
-#error "MAJOR_VERSION and MINOR_VERSION must be defined"
-#endif
-
-/** Allows macro expansion for x and add surrounding `<>`.
- * Is intended to be used for version dependant includes as
- * `#include` do not macro expand if starting with < or "
- * Example usage:
- *      #include PATH(path/to/FILE_VERSION/file)
- * @note: uses the implementation-define "Computed Includes" feature.
- */
-#define PATH(x) <x>
-
-#define CONCAT_3(a, b, c) a##b##c
-#define EXPAND_CONCAT_3(a, b, c) CONCAT_3(a, b, c)
-/** The directory name of the version: <major>.<minor> */
-#define FILE_VERSION EXPAND_CONCAT_3(MAJOR_VERSION, ., MINOR_VERSION)
-
-#define CONCAT_4(a, b, c, d) a##b##c##d
-#define EXPAND_CONCAT_4(a, b, c, d) CONCAT_4(a, b, c, d)
-/** The c++ namespace of the version: V<major>_0.
- * Always use minor version 0's namespace. If minor version is not zero, use
- * the full namespace path explicitly.
- */
-#define CPP_VERSION EXPAND_CONCAT_4(V, MAJOR_VERSION, _, 0)
diff --git a/audio_proxy/interfaces/5.0/Android.bp b/audio_proxy/interfaces/5.0/Android.bp
deleted file mode 100644
index ab3ca26..0000000
--- a/audio_proxy/interfaces/5.0/Android.bp
+++ /dev/null
@@ -1,27 +0,0 @@
-// This file is autogenerated by hidl-gen -Landroidbp.
-
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_google_atv_license"
-    // to get the below license kinds:
-    //   legacy_notice
-    default_applicable_licenses: ["device_google_atv_license"],
-}
-
-hidl_interface {
-    name: "device.google.atv.audio_proxy@5.0",
-    root: "device.google.atv.audio_proxy",
-    system_ext_specific: true,
-    srcs: [
-        "IAudioProxyDevicesManager.hal",
-        "IBusDevice.hal",
-    ],
-    interfaces: [
-        "android.hardware.audio.common@5.0",
-        "android.hardware.audio@5.0",
-        "android.hidl.base@1.0",
-        "android.hidl.safe_union@1.0",
-    ],
-    gen_java: false,
-}
diff --git a/audio_proxy/interfaces/5.0/IAudioProxyDevicesManager.hal b/audio_proxy/interfaces/5.0/IAudioProxyDevicesManager.hal
deleted file mode 100644
index b2a6771..0000000
--- a/audio_proxy/interfaces/5.0/IAudioProxyDevicesManager.hal
+++ /dev/null
@@ -1,28 +0,0 @@
-/* Copyright 2020 Google Inc. All Rights Reserved. */
-
-package device.google.atv.audio_proxy@5.0;
-
-import IBusDevice;
-
-/**
- * Main entrance for audio proxy service. Client should use this interface to
- * register IBusDevice. Service also implements audio HAL IDevicesFactory. When
- * needed, service will use registered IBusDevice to open output stream. This
- * allows the client to behave like an audio HAL and read audio from audio
- * server, if permitted.
- *
- * Note, the implementation only supports one version of audio HAL. To avoid
- * confusion, this interface shares the same version as the supported audio HAL
- * version.
- */
-interface IAudioProxyDevicesManager {
-    /**
-     * Registers IBusDevice at `address`. IBusService impl should live as long
-     * as its process, after registered.
-     *
-     * @param address The address associated with the device.
-     * @param device The audio bus device.
-     * @return success True if the device is registered successfully.
-     */
-    registerDevice(string address, IBusDevice device) generates (bool success);
-};
diff --git a/audio_proxy/interfaces/5.0/IBusDevice.hal b/audio_proxy/interfaces/5.0/IBusDevice.hal
deleted file mode 100644
index 0044a48..0000000
--- a/audio_proxy/interfaces/5.0/IBusDevice.hal
+++ /dev/null
@@ -1,27 +0,0 @@
-/* Copyright 2020 Google Inc. All Rights Reserved. */
-
-package device.google.atv.audio_proxy@5.0;
-
-import android.hardware.audio.common@5.0;
-import android.hardware.audio@5.0::IStreamOut;
-import android.hardware.audio@5.0::Result;
-
-/**
- * Represents a bus device in audio HAL. Check Java AudioDeviceInfo.TYPE_BUS for
- * more details.
- */
-interface IBusDevice {
-    /**
-     * Opens an audio stream for output. This function has the same requirement
-     * as audio HAL IDevice.openOutputStream.
-     */
-    openOutputStream(
-            AudioIoHandle ioHandle,
-            DeviceAddress device,
-            AudioConfig config,
-            bitfield<AudioOutputFlag> flags,
-            SourceMetadata sourceMetadata) generates (
-                    Result retval,
-                    IStreamOut outStream,
-                    AudioConfig suggestedConfig);
-};
diff --git a/audio_proxy/interfaces/5.1/Android.bp b/audio_proxy/interfaces/5.1/Android.bp
deleted file mode 100644
index efd9b94..0000000
--- a/audio_proxy/interfaces/5.1/Android.bp
+++ /dev/null
@@ -1,30 +0,0 @@
-// This file is autogenerated by hidl-gen -Landroidbp.
-
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_google_atv_license"
-    // to get the below license kinds:
-    //   legacy_notice
-    default_applicable_licenses: ["device_google_atv_license"],
-}
-
-hidl_interface {
-    name: "device.google.atv.audio_proxy@5.1",
-    root: "device.google.atv.audio_proxy",
-    system_ext_specific: true,
-    srcs: [
-        "IAudioProxyDevicesManager.hal",
-        "IAudioProxyStreamOut.hal",
-        "IBusDevice.hal",
-        "IStreamEventListener.hal",
-    ],
-    interfaces: [
-        "android.hardware.audio.common@5.0",
-        "android.hardware.audio@5.0",
-        "android.hidl.base@1.0",
-        "android.hidl.safe_union@1.0",
-        "device.google.atv.audio_proxy@5.0",
-    ],
-    gen_java: false,
-}
diff --git a/audio_proxy/interfaces/5.1/IAudioProxyDevicesManager.hal b/audio_proxy/interfaces/5.1/IAudioProxyDevicesManager.hal
deleted file mode 100644
index f295f5f..0000000
--- a/audio_proxy/interfaces/5.1/IAudioProxyDevicesManager.hal
+++ /dev/null
@@ -1,12 +0,0 @@
-/* Copyright 2020 Google Inc. All Rights Reserved. */
-
-package device.google.atv.audio_proxy@5.1;
-
-import @5.0::IAudioProxyDevicesManager;
-
-/**
- * See @5.0::IAudioProxyDevicesManager for more details.
- * New in 5.1:
- * -- Client may call registerDevice with @5.1::IBusDevice.
- */
-interface IAudioProxyDevicesManager extends @5.0::IAudioProxyDevicesManager {};
diff --git a/audio_proxy/interfaces/5.1/IAudioProxyStreamOut.hal b/audio_proxy/interfaces/5.1/IAudioProxyStreamOut.hal
deleted file mode 100644
index 636c9dd..0000000
--- a/audio_proxy/interfaces/5.1/IAudioProxyStreamOut.hal
+++ /dev/null
@@ -1,20 +0,0 @@
-/* Copyright 2020 Google Inc. All Rights Reserved. */
-
-package device.google.atv.audio_proxy@5.1;
-
-import android.hardware.audio@5.0::IStreamOut;
-import android.hardware.audio@5.0::Result;
-
-import IStreamEventListener;
-
-/**
- * IStreamOut with extra APIs for audio proxy HAL.
- */
-interface IAudioProxyStreamOut extends IStreamOut {
-    /**
-     * Set a listener on this object. It allows the audio proxy client to
-     * communicate stream events with audio proxy service.
-     * @param listener the listener to receive the event callbacks.
-     */
-    setEventListener(IStreamEventListener listener);
-};
\ No newline at end of file
diff --git a/audio_proxy/interfaces/5.1/IBusDevice.hal b/audio_proxy/interfaces/5.1/IBusDevice.hal
deleted file mode 100644
index 4f9d429..0000000
--- a/audio_proxy/interfaces/5.1/IBusDevice.hal
+++ /dev/null
@@ -1,13 +0,0 @@
-/* Copyright 2020 Google Inc. All Rights Reserved. */
-
-package device.google.atv.audio_proxy@5.1;
-
-import @5.0::IBusDevice;
-
-/**
- * See @5.0::IBusDevice for more details.
- * New in 5.1:
- * -- openOutputStream may return IAudioProxyStream, which is a subclass of
- *    IStreamOut.
- */
-interface IBusDevice extends @5.0::IBusDevice {};
diff --git a/audio_proxy/interfaces/5.1/IStreamEventListener.hal b/audio_proxy/interfaces/5.1/IStreamEventListener.hal
deleted file mode 100644
index 196c698..0000000
--- a/audio_proxy/interfaces/5.1/IStreamEventListener.hal
+++ /dev/null
@@ -1,13 +0,0 @@
-/* Copyright 2020 Google Inc. All Rights Reserved. */
-
-package device.google.atv.audio_proxy@5.1;
-
-/**
- * Async event listener for the IAudioProxyStreamOut.
- */
-interface IStreamEventListener {
-    /**
-     * Called when audioserver closes the IStreamOut.
-     */
-    oneway onClose();
-};
diff --git a/audio_proxy/interfaces/Android.bp b/audio_proxy/interfaces/Android.bp
deleted file mode 100644
index 1a15b5e..0000000
--- a/audio_proxy/interfaces/Android.bp
+++ /dev/null
@@ -1,13 +0,0 @@
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_google_atv_license"
-    // to get the below license kinds:
-    //   legacy_notice
-    default_applicable_licenses: ["device_google_atv_license"],
-}
-
-hidl_package_root {
-    name: "device.google.atv.audio_proxy",
-    path: "device/google/atv/audio_proxy/interfaces",
-}
diff --git a/audio_proxy/interfaces/aidl/Android.bp b/audio_proxy/interfaces/aidl/Android.bp
deleted file mode 100644
index 56ad152..0000000
--- a/audio_proxy/interfaces/aidl/Android.bp
+++ /dev/null
@@ -1,52 +0,0 @@
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-aidl_interface {
-    name: "device.google.atv.audio_proxy-aidl",
-    vendor_available: true,
-    system_ext_specific: true,
-    srcs: [
-        "device/google/atv/audio_proxy/*.aidl",
-    ],
-    imports: [
-        "android.hardware.common-V2",
-        "android.hardware.common.fmq-V1",
-    ],
-    stability: "vintf",
-    frozen: true,
-    backend: {
-        ndk: {
-            enabled: true,
-        },
-        java: {
-            enabled: false,
-        },
-        cpp: {
-            enabled: false,
-        },
-    },
-    versions_with_info: [
-        {
-            version: "1",
-            imports: [
-                "android.hardware.common-V2",
-                "android.hardware.common.fmq-V1",
-            ],
-        },
-        {
-            version: "2",
-            imports: [
-                "android.hardware.common-V2",
-                "android.hardware.common.fmq-V1",
-            ],
-        },
-        {
-            version: "3",
-            imports: [
-                "android.hardware.common-V2",
-                "android.hardware.common.fmq-V1",
-            ],
-        },
-    ],
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/.hash b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/.hash
deleted file mode 100644
index d097e82..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/.hash
+++ /dev/null
@@ -1 +0,0 @@
-71ad4076df6f80c8373d408a8d95f7eca4ec8aa0
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioChannelMask.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioChannelMask.aidl
deleted file mode 100644
index 821a29a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioChannelMask.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioChannelMask {
-  MONO = 1,
-  STEREO = 3,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioConfig.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioConfig.aidl
deleted file mode 100644
index 2c32b79..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioConfig.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-parcelable AudioConfig {
-  device.google.atv.audio_proxy.AudioFormat format;
-  int sampleRateHz;
-  device.google.atv.audio_proxy.AudioChannelMask channelMask;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioDrain.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioDrain.aidl
deleted file mode 100644
index 3b78e78..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioDrain.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioDrain {
-  ALL = 0,
-  EARLY_NOTIFY = 1,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioFormat.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioFormat.aidl
deleted file mode 100644
index 778ce15..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioFormat.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioFormat {
-  PCM_16_BIT = 1,
-  PCM_8_BIT = 2,
-  PCM_FLOAT = 5,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioOutputFlag.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioOutputFlag.aidl
deleted file mode 100644
index 100762a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/AudioOutputFlag.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioOutputFlag {
-  NONE = 0,
-  DIRECT = 1,
-  HW_AV_SYNC = 64,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IAudioProxy.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IAudioProxy.aidl
deleted file mode 100644
index eadd1a5..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IAudioProxy.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IAudioProxy {
-  void start(in device.google.atv.audio_proxy.IStreamProvider provider);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IOutputStream.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IOutputStream.aidl
deleted file mode 100644
index 226ebd4..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IOutputStream.aidl
+++ /dev/null
@@ -1,30 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IOutputStream {
-  void standby();
-  void close();
-  void pause();
-  void resume();
-  void drain(device.google.atv.audio_proxy.AudioDrain drain);
-  void flush();
-  void prepareForWriting(in int frameSize, in int framesCount, out android.hardware.common.fmq.MQDescriptor<byte,android.hardware.common.fmq.SynchronizedReadWrite> dataMQ, out android.hardware.common.fmq.MQDescriptor<device.google.atv.audio_proxy.WriteStatus,android.hardware.common.fmq.SynchronizedReadWrite> statusMQ);
-  void setVolume(float left, float right);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IStreamProvider.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IStreamProvider.aidl
deleted file mode 100644
index 4d05698..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/IStreamProvider.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IStreamProvider {
-  device.google.atv.audio_proxy.IOutputStream openOutputStream(in String address, in device.google.atv.audio_proxy.AudioConfig config, in int flags);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/MessageQueueFlag.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/MessageQueueFlag.aidl
deleted file mode 100644
index 736bfc3..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/MessageQueueFlag.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum MessageQueueFlag {
-  NOT_EMPTY = 1,
-  NOT_FULL = 2,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/PresentationPosition.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/PresentationPosition.aidl
deleted file mode 100644
index 4fa7cb9..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/PresentationPosition.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable PresentationPosition {
-  long frames;
-  device.google.atv.audio_proxy.TimeSpec timestamp;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/TimeSpec.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/TimeSpec.aidl
deleted file mode 100644
index daed6ac..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/TimeSpec.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable TimeSpec {
-  long tvSec;
-  long tvNSec;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/WriteStatus.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/WriteStatus.aidl
deleted file mode 100644
index 169163a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/1/device/google/atv/audio_proxy/WriteStatus.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable WriteStatus {
-  long written;
-  device.google.atv.audio_proxy.PresentationPosition position;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/.hash b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/.hash
deleted file mode 100644
index 87f9d36..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/.hash
+++ /dev/null
@@ -1 +0,0 @@
-36478e9608536b679d90121e62177577f2aae0b7
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioChannelMask.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioChannelMask.aidl
deleted file mode 100644
index 821a29a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioChannelMask.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioChannelMask {
-  MONO = 1,
-  STEREO = 3,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioConfig.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioConfig.aidl
deleted file mode 100644
index b75f906..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioConfig.aidl
+++ /dev/null
@@ -1,27 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-parcelable AudioConfig {
-  device.google.atv.audio_proxy.AudioFormat format;
-  int sampleRateHz;
-  device.google.atv.audio_proxy.AudioChannelMask channelMask;
-  long bufferSizeBytes;
-  int latencyMs;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioDrain.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioDrain.aidl
deleted file mode 100644
index 3b78e78..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioDrain.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioDrain {
-  ALL = 0,
-  EARLY_NOTIFY = 1,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioFormat.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioFormat.aidl
deleted file mode 100644
index 778ce15..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioFormat.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioFormat {
-  PCM_16_BIT = 1,
-  PCM_8_BIT = 2,
-  PCM_FLOAT = 5,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioOutputFlag.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioOutputFlag.aidl
deleted file mode 100644
index 100762a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/AudioOutputFlag.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioOutputFlag {
-  NONE = 0,
-  DIRECT = 1,
-  HW_AV_SYNC = 64,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IAudioProxy.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IAudioProxy.aidl
deleted file mode 100644
index eadd1a5..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IAudioProxy.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IAudioProxy {
-  void start(in device.google.atv.audio_proxy.IStreamProvider provider);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IOutputStream.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IOutputStream.aidl
deleted file mode 100644
index 44abe39..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IOutputStream.aidl
+++ /dev/null
@@ -1,32 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IOutputStream {
-  void standby();
-  void close();
-  void pause();
-  void resume();
-  void drain(device.google.atv.audio_proxy.AudioDrain drain);
-  void flush();
-  void prepareForWriting(in int frameSize, in int framesCount, out android.hardware.common.fmq.MQDescriptor<byte,android.hardware.common.fmq.SynchronizedReadWrite> dataMQ, out android.hardware.common.fmq.MQDescriptor<device.google.atv.audio_proxy.WriteStatus,android.hardware.common.fmq.SynchronizedReadWrite> statusMQ);
-  void setVolume(float left, float right);
-  long getBufferSizeBytes();
-  int getLatencyMs();
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IStreamProvider.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IStreamProvider.aidl
deleted file mode 100644
index 4d05698..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/IStreamProvider.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IStreamProvider {
-  device.google.atv.audio_proxy.IOutputStream openOutputStream(in String address, in device.google.atv.audio_proxy.AudioConfig config, in int flags);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/MessageQueueFlag.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/MessageQueueFlag.aidl
deleted file mode 100644
index 736bfc3..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/MessageQueueFlag.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum MessageQueueFlag {
-  NOT_EMPTY = 1,
-  NOT_FULL = 2,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/PresentationPosition.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/PresentationPosition.aidl
deleted file mode 100644
index 4fa7cb9..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/PresentationPosition.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable PresentationPosition {
-  long frames;
-  device.google.atv.audio_proxy.TimeSpec timestamp;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/TimeSpec.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/TimeSpec.aidl
deleted file mode 100644
index daed6ac..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/TimeSpec.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable TimeSpec {
-  long tvSec;
-  long tvNSec;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/WriteStatus.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/WriteStatus.aidl
deleted file mode 100644
index 169163a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/2/device/google/atv/audio_proxy/WriteStatus.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable WriteStatus {
-  long written;
-  device.google.atv.audio_proxy.PresentationPosition position;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/.hash b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/.hash
deleted file mode 100644
index a5ef705..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/.hash
+++ /dev/null
@@ -1 +0,0 @@
-70fdeee12fa5bd9b169842e36699920dd0283c56
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioChannelMask.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioChannelMask.aidl
deleted file mode 100644
index 821a29a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioChannelMask.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioChannelMask {
-  MONO = 1,
-  STEREO = 3,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioConfig.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioConfig.aidl
deleted file mode 100644
index b75f906..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioConfig.aidl
+++ /dev/null
@@ -1,27 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-parcelable AudioConfig {
-  device.google.atv.audio_proxy.AudioFormat format;
-  int sampleRateHz;
-  device.google.atv.audio_proxy.AudioChannelMask channelMask;
-  long bufferSizeBytes;
-  int latencyMs;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioDrain.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioDrain.aidl
deleted file mode 100644
index 3b78e78..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioDrain.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioDrain {
-  ALL = 0,
-  EARLY_NOTIFY = 1,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioFormat.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioFormat.aidl
deleted file mode 100644
index 778ce15..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioFormat.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioFormat {
-  PCM_16_BIT = 1,
-  PCM_8_BIT = 2,
-  PCM_FLOAT = 5,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioOutputFlag.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioOutputFlag.aidl
deleted file mode 100644
index 100762a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/AudioOutputFlag.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioOutputFlag {
-  NONE = 0,
-  DIRECT = 1,
-  HW_AV_SYNC = 64,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IAudioProxy.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IAudioProxy.aidl
deleted file mode 100644
index eadd1a5..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IAudioProxy.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IAudioProxy {
-  void start(in device.google.atv.audio_proxy.IStreamProvider provider);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IOutputStream.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IOutputStream.aidl
deleted file mode 100644
index 7b5f9ce..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IOutputStream.aidl
+++ /dev/null
@@ -1,36 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IOutputStream {
-  void standby();
-  void close();
-  void pause();
-  void resume();
-  void drain(device.google.atv.audio_proxy.AudioDrain drain);
-  void flush();
-  void prepareForWriting(in int frameSize, in int framesCount, out android.hardware.common.fmq.MQDescriptor<byte,android.hardware.common.fmq.SynchronizedReadWrite> dataMQ, out android.hardware.common.fmq.MQDescriptor<device.google.atv.audio_proxy.WriteStatus,android.hardware.common.fmq.SynchronizedReadWrite> statusMQ);
-  void setVolume(float left, float right);
-  long getBufferSizeBytes();
-  int getLatencyMs();
-  void start();
-  void stop();
-  device.google.atv.audio_proxy.MmapBufferInfo createMmapBuffer(int minSizeFrames);
-  device.google.atv.audio_proxy.PresentationPosition getMmapPosition();
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IStreamProvider.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IStreamProvider.aidl
deleted file mode 100644
index 4d05698..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/IStreamProvider.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IStreamProvider {
-  device.google.atv.audio_proxy.IOutputStream openOutputStream(in String address, in device.google.atv.audio_proxy.AudioConfig config, in int flags);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/MessageQueueFlag.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/MessageQueueFlag.aidl
deleted file mode 100644
index 736bfc3..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/MessageQueueFlag.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum MessageQueueFlag {
-  NOT_EMPTY = 1,
-  NOT_FULL = 2,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/MmapBufferInfo.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/MmapBufferInfo.aidl
deleted file mode 100644
index c205c97..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/MmapBufferInfo.aidl
+++ /dev/null
@@ -1,26 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-parcelable MmapBufferInfo {
-  ParcelFileDescriptor sharedMemoryFd;
-  int bufferSizeFrames;
-  int burstSizeFrames;
-  int flags;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/PresentationPosition.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/PresentationPosition.aidl
deleted file mode 100644
index 4fa7cb9..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/PresentationPosition.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable PresentationPosition {
-  long frames;
-  device.google.atv.audio_proxy.TimeSpec timestamp;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/TimeSpec.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/TimeSpec.aidl
deleted file mode 100644
index daed6ac..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/TimeSpec.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable TimeSpec {
-  long tvSec;
-  long tvNSec;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/WriteStatus.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/WriteStatus.aidl
deleted file mode 100644
index 169163a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/3/device/google/atv/audio_proxy/WriteStatus.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable WriteStatus {
-  long written;
-  device.google.atv.audio_proxy.PresentationPosition position;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioChannelMask.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioChannelMask.aidl
deleted file mode 100644
index 821a29a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioChannelMask.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioChannelMask {
-  MONO = 1,
-  STEREO = 3,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioConfig.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioConfig.aidl
deleted file mode 100644
index b75f906..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioConfig.aidl
+++ /dev/null
@@ -1,27 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-parcelable AudioConfig {
-  device.google.atv.audio_proxy.AudioFormat format;
-  int sampleRateHz;
-  device.google.atv.audio_proxy.AudioChannelMask channelMask;
-  long bufferSizeBytes;
-  int latencyMs;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioDrain.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioDrain.aidl
deleted file mode 100644
index 3b78e78..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioDrain.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioDrain {
-  ALL = 0,
-  EARLY_NOTIFY = 1,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioFormat.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioFormat.aidl
deleted file mode 100644
index 778ce15..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioFormat.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioFormat {
-  PCM_16_BIT = 1,
-  PCM_8_BIT = 2,
-  PCM_FLOAT = 5,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioOutputFlag.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioOutputFlag.aidl
deleted file mode 100644
index 100762a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/AudioOutputFlag.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum AudioOutputFlag {
-  NONE = 0,
-  DIRECT = 1,
-  HW_AV_SYNC = 64,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IAudioProxy.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IAudioProxy.aidl
deleted file mode 100644
index eadd1a5..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IAudioProxy.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IAudioProxy {
-  void start(in device.google.atv.audio_proxy.IStreamProvider provider);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IOutputStream.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IOutputStream.aidl
deleted file mode 100644
index 7b5f9ce..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IOutputStream.aidl
+++ /dev/null
@@ -1,36 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IOutputStream {
-  void standby();
-  void close();
-  void pause();
-  void resume();
-  void drain(device.google.atv.audio_proxy.AudioDrain drain);
-  void flush();
-  void prepareForWriting(in int frameSize, in int framesCount, out android.hardware.common.fmq.MQDescriptor<byte,android.hardware.common.fmq.SynchronizedReadWrite> dataMQ, out android.hardware.common.fmq.MQDescriptor<device.google.atv.audio_proxy.WriteStatus,android.hardware.common.fmq.SynchronizedReadWrite> statusMQ);
-  void setVolume(float left, float right);
-  long getBufferSizeBytes();
-  int getLatencyMs();
-  void start();
-  void stop();
-  device.google.atv.audio_proxy.MmapBufferInfo createMmapBuffer(int minSizeFrames);
-  device.google.atv.audio_proxy.PresentationPosition getMmapPosition();
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IStreamProvider.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IStreamProvider.aidl
deleted file mode 100644
index 4d05698..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/IStreamProvider.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-interface IStreamProvider {
-  device.google.atv.audio_proxy.IOutputStream openOutputStream(in String address, in device.google.atv.audio_proxy.AudioConfig config, in int flags);
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/MessageQueueFlag.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/MessageQueueFlag.aidl
deleted file mode 100644
index 736bfc3..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/MessageQueueFlag.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@Backing(type="int") @VintfStability
-enum MessageQueueFlag {
-  NOT_EMPTY = 1,
-  NOT_FULL = 2,
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/MmapBufferInfo.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/MmapBufferInfo.aidl
deleted file mode 100644
index c205c97..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/MmapBufferInfo.aidl
+++ /dev/null
@@ -1,26 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@VintfStability
-parcelable MmapBufferInfo {
-  ParcelFileDescriptor sharedMemoryFd;
-  int bufferSizeFrames;
-  int burstSizeFrames;
-  int flags;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/PresentationPosition.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/PresentationPosition.aidl
deleted file mode 100644
index 4fa7cb9..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/PresentationPosition.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable PresentationPosition {
-  long frames;
-  device.google.atv.audio_proxy.TimeSpec timestamp;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/TimeSpec.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/TimeSpec.aidl
deleted file mode 100644
index daed6ac..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/TimeSpec.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable TimeSpec {
-  long tvSec;
-  long tvNSec;
-}
diff --git a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/WriteStatus.aidl b/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/WriteStatus.aidl
deleted file mode 100644
index 169163a..0000000
--- a/audio_proxy/interfaces/aidl/aidl_api/device.google.atv.audio_proxy-aidl/current/device/google/atv/audio_proxy/WriteStatus.aidl
+++ /dev/null
@@ -1,24 +0,0 @@
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package device.google.atv.audio_proxy;
-@FixedSize @VintfStability
-parcelable WriteStatus {
-  long written;
-  device.google.atv.audio_proxy.PresentationPosition position;
-}
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioChannelMask.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioChannelMask.aidl
deleted file mode 100644
index b6a8946..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioChannelMask.aidl
+++ /dev/null
@@ -1,13 +0,0 @@
-package device.google.atv.audio_proxy;
-
-/**
- * Audio channel mask. The enum values are from AUDIO_CHANNEL_OUT_MASK defined
- * in audio-hal-enums.h. The listed values are required to be supported by the
- * client.
- */
-@VintfStability
-@Backing(type="int")
-enum AudioChannelMask {
-    MONO = 1,
-    STEREO = 3,
-}
\ No newline at end of file
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioConfig.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioConfig.aidl
deleted file mode 100644
index 97b5e17..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioConfig.aidl
+++ /dev/null
@@ -1,20 +0,0 @@
-package device.google.atv.audio_proxy;
-
-import device.google.atv.audio_proxy.AudioChannelMask;
-import device.google.atv.audio_proxy.AudioFormat;
-
-/**
- * Config for the output stream.
- */
-@VintfStability
-parcelable AudioConfig {
-    AudioFormat format;
-    int sampleRateHz;
-    AudioChannelMask channelMask;
-
-    // Expected buffer size and latency for the stream. If 0, the impl should
-    // provide their own value.
-    long bufferSizeBytes;
-    int latencyMs;
-}
-
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioDrain.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioDrain.aidl
deleted file mode 100644
index a1038a9..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioDrain.aidl
+++ /dev/null
@@ -1,13 +0,0 @@
-package device.google.atv.audio_proxy;
-
-/**
- * Enum defines the behavior for IOutputStream.drain.
- */
-@VintfStability
-@Backing(type="int")
-enum AudioDrain {
-    // drain() returns after all the frames being played out.
-    ALL = 0,
-    // drain() returns shortly before all the frame being played out.
-    EARLY_NOTIFY = 1,
-}
\ No newline at end of file
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioFormat.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioFormat.aidl
deleted file mode 100644
index 58aaf3b..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioFormat.aidl
+++ /dev/null
@@ -1,14 +0,0 @@
-package device.google.atv.audio_proxy;
-
-/**
- * Audio format for the output stream. The enum values are from AUDIO_FORMAT_
- * defined in audio-hal-enums.h. The listed values are required to be supported
- * by the client.
- */
-@VintfStability
-@Backing(type="int")
-enum AudioFormat {
-    PCM_16_BIT = 1,
-    PCM_8_BIT = 2,
-    PCM_FLOAT = 5,
-}
\ No newline at end of file
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioOutputFlag.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioOutputFlag.aidl
deleted file mode 100644
index 1196b21..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/AudioOutputFlag.aidl
+++ /dev/null
@@ -1,14 +0,0 @@
-package device.google.atv.audio_proxy;
-
-/**
- * Audio output flag for the output stream. The enum values are from
- * AUDIO_OUTPUT_FLAG_ defined in audio-hal-enums.h. The values listed
- * except HW_AV_SYNC are required to be supported by the client.
- */
-@VintfStability
-@Backing(type="int")
-enum AudioOutputFlag {
-    NONE = 0,
-    DIRECT = 0x1,
-    HW_AV_SYNC = 0x40,
-}
\ No newline at end of file
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IAudioProxy.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IAudioProxy.aidl
deleted file mode 100644
index 72b76f1..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IAudioProxy.aidl
+++ /dev/null
@@ -1,16 +0,0 @@
-package device.google.atv.audio_proxy;
-
-import device.google.atv.audio_proxy.IStreamProvider;
-
-@VintfStability
-interface IAudioProxy {
-    /*
-     * Init AudioProxy service with provider. This should be called only once
-     * before any other APIs, otherwise an exception will be thrown. In NDK
-     * backend, the ScopedAStatus::isOk() returns false.
-     *
-     * @param provider the provider to provide different IOutputStream for
-     *                 playback.
-     */
-    void start(in IStreamProvider provider);
-}
\ No newline at end of file
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IOutputStream.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IOutputStream.aidl
deleted file mode 100644
index 955d369..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IOutputStream.aidl
+++ /dev/null
@@ -1,69 +0,0 @@
-package device.google.atv.audio_proxy;
-
-import android.hardware.common.fmq.MQDescriptor;
-import android.hardware.common.fmq.SynchronizedReadWrite;
-
-import device.google.atv.audio_proxy.AudioDrain;
-import device.google.atv.audio_proxy.MmapBufferInfo;
-import device.google.atv.audio_proxy.PresentationPosition;
-import device.google.atv.audio_proxy.WriteStatus;
-
-/**
- * A simplified audio HAL IStreamOut interface. The methods listed should cover
- * usages for PCM playback.
- * Unless specified, the method should have a corresponding API in IStreamOut.hal.
- * Some optional APIs are removed since they are not needed for our use case.
- * Refer IStreamOut.hal/IStream.hal for more details.
- */
-@VintfStability
-interface IOutputStream {
-    /**
-     * Playback control signals.
-     */
-    void standby();
-    void close();
-    void pause();
-    void resume();
-    void drain(AudioDrain drain);
-    void flush();
-
-    /**
-     * Creates FMQ for audio data. Compared to IStreamOut::prepareForWriting,
-     * 1. WriteStatus contains both written bytes and rendering delay.
-     * 2. We removed WriteCommand FMQ because the impl should return all the
-     *    fields. The rendering delay will be used to calculate the presentation
-     *    position required by IStreamOut.
-     */
-    void prepareForWriting(
-        in int frameSize,
-        in int framesCount,
-        out MQDescriptor<byte, SynchronizedReadWrite> dataMQ,
-        out MQDescriptor<WriteStatus, SynchronizedReadWrite> statusMQ);
-
-    /**
-     * Volume control.
-     */
-    void setVolume(float left, float right);
-
-    /**
-     * Get the buffer size and latency of the stream. They're called before starting the playback.
-     */
-    long getBufferSizeBytes();
-    int getLatencyMs();
-
-    /**
-     * Start/Stop playback for MMAP_NOIRQ stream.
-     */
-    void start();
-    void stop();
-
-    /**
-     * Create a share memory for MMAP_NOIRQ stream.
-     */
-    MmapBufferInfo createMmapBuffer(int minSizeFrames);
-
-    /**
-     * Query the presentation position for MMAP_NOIRQ stream.
-     */
-    PresentationPosition getMmapPosition();
-}
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IStreamProvider.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IStreamProvider.aidl
deleted file mode 100644
index 613bb9b..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/IStreamProvider.aidl
+++ /dev/null
@@ -1,21 +0,0 @@
-package device.google.atv.audio_proxy;
-
-import device.google.atv.audio_proxy.AudioConfig;
-import device.google.atv.audio_proxy.IOutputStream;
-
-@VintfStability
-interface IStreamProvider {
-    /**
-     * Opens an output stream for PCM playback. From audio server's perspective,
-     * the stream is opened by an audio device with type AUDIO_DEVICE_OUT_BUS.
-     *
-     * @param address used to distinguish different streams. In practice, the
-     *                client app will use address to configure the audio
-     *                routing, e.g. media stream to address1, any other streams
-     *                to address2.
-     * @param config the config for the output stream.
-     * @param flags bitset of AudioOutputFlag.
-     */
-    IOutputStream openOutputStream(
-        in String address, in AudioConfig config, in int flags);
-}
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/MessageQueueFlag.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/MessageQueueFlag.aidl
deleted file mode 100644
index 2e9820b..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/MessageQueueFlag.aidl
+++ /dev/null
@@ -1,11 +0,0 @@
-package device.google.atv.audio_proxy;
-
-/**
- * FMQ event flag to indicate the status of the queue.
- */
-@VintfStability
-@Backing(type="int")
-enum MessageQueueFlag {
-    NOT_EMPTY = 1 << 0,
-    NOT_FULL = 1 << 1,
-}
\ No newline at end of file
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/MmapBufferInfo.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/MmapBufferInfo.aidl
deleted file mode 100644
index dbc7f70..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/MmapBufferInfo.aidl
+++ /dev/null
@@ -1,15 +0,0 @@
-package device.google.atv.audio_proxy;
-
-import android.os.ParcelFileDescriptor;
-
-/**
- * Shared memory and the associated info for the playback.
- * This is the corresponding structure of audio HAL MmapBufferInfo.
- */
-@VintfStability
-parcelable MmapBufferInfo {
-    ParcelFileDescriptor sharedMemoryFd;
-    int bufferSizeFrames;
-    int burstSizeFrames;
-    int flags;
-}
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/PresentationPosition.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/PresentationPosition.aidl
deleted file mode 100644
index 6a2e663..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/PresentationPosition.aidl
+++ /dev/null
@@ -1,17 +0,0 @@
-package device.google.atv.audio_proxy;
-
-import device.google.atv.audio_proxy.TimeSpec;
-
-/**
- * Info on playback timestamp:
- * frames is the amount of data which the pipeline played out up to this
- * timestamp.
- * timestamp is the CLOCK_MONOTONIC time at which the presented frames
- * measurement was taken.
- */
-@VintfStability
-@FixedSize
-parcelable PresentationPosition {
-    long frames;
-    TimeSpec timestamp;
-}
\ No newline at end of file
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/TimeSpec.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/TimeSpec.aidl
deleted file mode 100644
index 2cbac24..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/TimeSpec.aidl
+++ /dev/null
@@ -1,11 +0,0 @@
-package device.google.atv.audio_proxy;
-
-/**
- * AIDL version of timespec.
- */
-@VintfStability
-@FixedSize
-parcelable TimeSpec {
-    long tvSec;
-    long tvNSec;
-}
diff --git a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/WriteStatus.aidl b/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/WriteStatus.aidl
deleted file mode 100644
index f0212b5..0000000
--- a/audio_proxy/interfaces/aidl/device/google/atv/audio_proxy/WriteStatus.aidl
+++ /dev/null
@@ -1,16 +0,0 @@
-package device.google.atv.audio_proxy;
-
-import device.google.atv.audio_proxy.PresentationPosition;
-
-/**
- * Status for one audio data write. It will be returned by the status FMQ as a
- * response to the data FMQ write.
- * written is the number of bytes been written into the output stream.
- * position is the playback position info measured by the output stream.
- */
-@VintfStability
-@FixedSize
-parcelable WriteStatus {
-    long written;
-    PresentationPosition position;
-}
\ No newline at end of file
diff --git a/audio_proxy/interfaces/current.txt b/audio_proxy/interfaces/current.txt
deleted file mode 100644
index 4717fdd..0000000
--- a/audio_proxy/interfaces/current.txt
+++ /dev/null
@@ -1,7 +0,0 @@
-d47b2be3f897db91b1ae495ae3000e8caf1bf06ee8a221365648fafca06da8f6 device.google.atv.audio_proxy@5.0::IAudioProxyDevicesManager
-a344f820405e52558fc305b66c7c5d1284f500a8dd40ac954332ec9b934db489 device.google.atv.audio_proxy@5.0::IBusDevice
-
-6c3b161270503f4dcc7eb10b3df1e5e4af82548080d68cc22dec3615f6087762 device.google.atv.audio_proxy@5.1::IAudioProxyDevicesManager
-00014f3fcf306620fca18bc6696ad8403049e5cf9b69a7f539417e6110c1985a device.google.atv.audio_proxy@5.1::IAudioProxyStreamOut
-1c662d4c4da3ec0786ba86a9decb8768e3ddab5667d31b0e5af900e459e42f88 device.google.atv.audio_proxy@5.1::IBusDevice
-e661632f8eed485ff0bae85d5be9226f69853b353a2cd357e77fabb84299aac6 device.google.atv.audio_proxy@5.1::IStreamEventListener
diff --git a/audio_proxy/interfaces/update-makefiles.sh b/audio_proxy/interfaces/update-makefiles.sh
deleted file mode 100755
index d3f832e..0000000
--- a/audio_proxy/interfaces/update-makefiles.sh
+++ /dev/null
@@ -1,10 +0,0 @@
-#!/bin/bash
-
-# Run from Android root, e.g.:
-#
-#   device/google/atv/audio_proxy/interfaces/update-makefiles.sh
-
-source $ANDROID_BUILD_TOP/system/tools/hidl/update-makefiles-helper.sh
-
-do_makefiles_update \
-  "device.google.atv.audio_proxy:device/google/atv/audio_proxy/interfaces"
diff --git a/audio_proxy/public/audio_proxy.h b/audio_proxy/public/audio_proxy.h
deleted file mode 100644
index f6ea632..0000000
--- a/audio_proxy/public/audio_proxy.h
+++ /dev/null
@@ -1,315 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#ifndef DEVICE_GOOGLE_ATV_AUDIO_PROXY_PUBLIC_AUDIO_PROXY_H_
-#define DEVICE_GOOGLE_ATV_AUDIO_PROXY_PUBLIC_AUDIO_PROXY_H_
-
-#include <stdint.h>
-#include <sys/types.h>
-#include <time.h>
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-// audio proxy allows the application to implement an audio HAL. It contains two
-// components, a client library and a service.
-// The client library is defined by this header file. Applications should
-// integrate this library to provide audio HAL components. Currently it's only
-// IStreamOut.
-// The service implements IDevicesFactory and IDevice. It will register itself
-// to audio server and forward function calls to client.
-
-// Most of the struct/functions just converts the HIDL definitions into C
-// definitions.
-
-// The following enum and typedef are subset of those defined in
-// hardware/interfaces/audio/common/$VERSION/types.hal, or
-// hardware/interfaces/audio/$VERSION/types.hal.
-// The selected subsets are those commonly supported by a normal audio HAL. The
-// library won't check the validation of these enums. In other words, Audio
-// server can still pass value not defined here to the application.
-
-// AudioFormat
-enum {
-  AUDIO_PROXY_FORMAT_INVALID = 0xFFFFFFFFu,
-  AUDIO_PROXY_FORMAT_PCM_16_BIT = 0x1u,
-  AUDIO_PROXY_FORMAT_PCM_8_BIT = 0x2u,
-  AUDIO_PROXY_FORMAT_PCM_32_BIT = 0x3u,
-  AUDIO_PROXY_FORMAT_PCM_8_24_BIT = 0x4u,
-  AUDIO_PROXY_FORMAT_PCM_FLOAT = 0x5u,
-  AUDIO_PROXY_FORMAT_PCM_24_BIT_PACKED = 0x6u,
-};
-typedef uint32_t audio_proxy_format_t;
-
-// AudioChannelMask
-enum {
-  AUDIO_PROXY_CHANNEL_INVALID = 0xC0000000u,
-  AUDIO_PROXY_CHANNEL_OUT_MONO = 0x1u,
-  AUDIO_PROXY_CHANNEL_OUT_STEREO = 0x3u,
-  AUDIO_PROXY_CHANNEL_OUT_2POINT1 = 0xBu,
-  AUDIO_PROXY_CHANNEL_OUT_TRI = 0x7u,
-  AUDIO_PROXY_CHANNEL_OUT_TRI_BACK = 0x103u,
-  AUDIO_PROXY_CHANNEL_OUT_3POINT1 = 0xFu,
-  AUDIO_PROXY_CHANNEL_OUT_2POINT0POINT2 = 0xC0003u,
-  AUDIO_PROXY_CHANNEL_OUT_2POINT1POINT2 = 0xC000Bu,
-  AUDIO_PROXY_CHANNEL_OUT_3POINT0POINT2 = 0xC0007u,
-  AUDIO_PROXY_CHANNEL_OUT_3POINT1POINT2 = 0xC000Fu,
-  AUDIO_PROXY_CHANNEL_OUT_QUAD = 0x33u,
-  // AUDIO_PROXY_CHANNEL_OUT_QUAD_BACK = 0x33u,
-  AUDIO_PROXY_CHANNEL_OUT_QUAD_SIDE = 0x603u,
-  AUDIO_PROXY_CHANNEL_OUT_SURROUND = 0x107u,
-  AUDIO_PROXY_CHANNEL_OUT_PENTA = 0x37u,
-  AUDIO_PROXY_CHANNEL_OUT_5POINT1 = 0x3Fu,
-  // AUDIO_PROXY_CHANNEL_OUT_5POINT1_BACK = 0x3Fu,
-  AUDIO_PROXY_CHANNEL_OUT_5POINT1_SIDE = 0x60Fu,
-  AUDIO_PROXY_CHANNEL_OUT_5POINT1POINT2 = 0xC003Fu,
-  AUDIO_PROXY_CHANNEL_OUT_5POINT1POINT4 = 0x2D03Fu,
-  AUDIO_PROXY_CHANNEL_OUT_6POINT1 = 0x13Fu,
-  AUDIO_PROXY_CHANNEL_OUT_7POINT1 = 0x63Fu,
-  AUDIO_PROXY_CHANNEL_OUT_7POINT1POINT2 = 0xC063Fu,
-  AUDIO_PROXY_CHANNEL_OUT_7POINT1POINT4 = 0x2D63Fu,
-  AUDIO_PROXY_CHANNEL_OUT_13POINT_360RA = 0x72F607u,
-  AUDIO_PROXY_CHANNEL_OUT_22POINT2 = 0xFFFFFFu,
-  AUDIO_PROXY_CHANNEL_OUT_MONO_HAPTIC_A = 0x20000001u,
-  AUDIO_PROXY_CHANNEL_OUT_STEREO_HAPTIC_A = 0x20000003u,
-  AUDIO_PROXY_CHANNEL_OUT_HAPTIC_AB = 0x30000000u,
-  AUDIO_PROXY_CHANNEL_OUT_MONO_HAPTIC_AB = 0x30000001u,
-  AUDIO_PROXY_CHANNEL_OUT_STEREO_HAPTIC_AB = 0x30000003u,
-};
-typedef uint32_t audio_proxy_channel_mask_t;
-
-// AudioDrain
-enum {
-  AUDIO_PROXY_DRAIN_ALL,
-  AUDIO_PROXY_DRAIN_EARLY_NOTIFY,
-};
-typedef int32_t audio_proxy_drain_type_t;
-
-// AudioOutputFlag
-enum {
-  AUDIO_PROXY_OUTPUT_FLAG_NONE = 0x0,
-  AUDIO_PROXY_OUTPUT_FLAG_DIRECT = 0x1,
-  AUDIO_PROXY_OUTPUT_FLAG_HW_AV_SYNC = 0x40,
-};
-typedef int32_t audio_proxy_output_flags_t;
-
-// AudioConfig
-typedef struct {
-  int64_t buffer_size_bytes;
-  int32_t latency_ms;
-
-  // Points to extra fields defined in the future versions.
-  void* extension;
-} audio_proxy_config_v2_t;
-
-typedef struct {
-  uint32_t sample_rate;
-  audio_proxy_channel_mask_t channel_mask;
-  audio_proxy_format_t format;
-  uint32_t frame_count;
-
-  // Points to extra fields.
-  audio_proxy_config_v2_t* v2;
-} audio_proxy_config_t;
-
-// Util structure for key value pair.
-typedef struct {
-  const char* key;
-  const char* val;
-} audio_proxy_key_val_t;
-
-typedef void (*audio_proxy_get_parameters_callback_t)(
-    void*, const audio_proxy_key_val_t*);
-
-enum {
-  AUDIO_PROXY_MMAP_BUFFER_FLAG_NONE = 0x0,
-  AUDIO_PROXY_MMAP_BUFFER_FLAG_APPLICATION_SHAREABLE = 0x1,
-};
-typedef int32_t audio_proxy_mmap_buffer_flag_t;
-
-typedef struct {
-  int shared_memory_fd;
-  int32_t buffer_size_frames;
-  int32_t burst_size_frames;
-  audio_proxy_mmap_buffer_flag_t flags;
-} audio_proxy_mmap_buffer_info_t;
-
-// IStreamOut.
-struct audio_proxy_stream_out_v2 {
-  void (*start)(struct audio_proxy_stream_out_v2* stream);
-  void (*stop)(struct audio_proxy_stream_out_v2* stream);
-  audio_proxy_mmap_buffer_info_t (*create_mmap_buffer)(
-      struct audio_proxy_stream_out_v2* stream, int32_t min_buffer_size_frames);
-  void (*get_mmap_position)(struct audio_proxy_stream_out_v2* stream,
-                            int64_t* frames, struct timespec* timestamp);
-  // Pointer to the next version structure, for compatibility.
-  void* extension;
-};
-typedef struct audio_proxy_stream_out_v2 audio_proxy_stream_out_v2_t;
-
-struct audio_proxy_stream_out {
-  size_t (*get_buffer_size)(const struct audio_proxy_stream_out* stream);
-  uint64_t (*get_frame_count)(const struct audio_proxy_stream_out* stream);
-
-  // Gets all the sample rate supported by the stream. The list is terminated
-  // by 0. The returned list should have the same life cycle of |stream|.
-  const uint32_t* (*get_supported_sample_rates)(
-      const struct audio_proxy_stream_out* stream, audio_proxy_format_t format);
-  uint32_t (*get_sample_rate)(const struct audio_proxy_stream_out* stream);
-
-  // optional.
-  int (*set_sample_rate)(struct audio_proxy_stream_out* stream, uint32_t rate);
-
-  // Gets all the channel mask supported by the stream. The list is terminated
-  // by AUDIO_PROXY_CHANNEL_INVALID. The returned list should have the same life
-  // cycle of |stream|.
-  const audio_proxy_channel_mask_t* (*get_supported_channel_masks)(
-      const struct audio_proxy_stream_out* stream, audio_proxy_format_t format);
-  audio_proxy_channel_mask_t (*get_channel_mask)(
-      const struct audio_proxy_stream_out* stream);
-
-  // optional.
-  int (*set_channel_mask)(struct audio_proxy_stream_out* stream,
-                          audio_proxy_channel_mask_t mask);
-
-  // Gets all the audio formats supported by the stream. The list is terminated
-  // by AUDIO_PROXY_FORMAT_INVALID. The returned list should have the same life
-  // cycle of |stream|.
-  const audio_proxy_format_t* (*get_supported_formats)(
-      const struct audio_proxy_stream_out* stream);
-  audio_proxy_format_t (*get_format)(
-      const struct audio_proxy_stream_out* stream);
-
-  // optional.
-  int (*set_format)(struct audio_proxy_stream_out* stream,
-                    audio_proxy_format_t format);
-
-  uint32_t (*get_latency)(const struct audio_proxy_stream_out* stream);
-
-  int (*standby)(struct audio_proxy_stream_out* stream);
-
-  int (*pause)(struct audio_proxy_stream_out* stream);
-  int (*resume)(struct audio_proxy_stream_out* stream);
-
-  // optional.
-  int (*drain)(struct audio_proxy_stream_out* stream,
-               audio_proxy_drain_type_t type);
-
-  int (*flush)(struct audio_proxy_stream_out* stream);
-
-  // Writes |buffer| into |stream|. This is called on an internal thread of this
-  // library.
-  ssize_t (*write)(struct audio_proxy_stream_out* self, const void* buffer,
-                   size_t bytes);
-
-  // optional.
-  int (*get_render_position)(const struct audio_proxy_stream_out* stream,
-                             uint32_t* dsp_frames);
-
-  // optional.
-  int (*get_next_write_timestamp)(const struct audio_proxy_stream_out* stream,
-                                  int64_t* timestamp);
-
-  int (*get_presentation_position)(const struct audio_proxy_stream_out* stream,
-                                   uint64_t* frames,
-                                   struct timespec* timestamp);
-
-  // opional.
-  int (*set_volume)(struct audio_proxy_stream_out* stream, float left,
-                    float right);
-
-  // Sets parameters on |stream|. Both |context| and |param| are terminated
-  // by key_val_t whose key is null. They are only valid during the function
-  // call.
-  int (*set_parameters)(struct audio_proxy_stream_out* stream,
-                        const audio_proxy_key_val_t* context,
-                        const audio_proxy_key_val_t* param);
-
-  // Gets parameters from |stream|.
-  // |context| is key val pairs array terminated by null key
-  // audio_proxy_key_val_t. |keys| is C string array, terminated by nullptr.
-  // |on_result| is the callback to deliver the result. It must be called before
-  // this function returns, with |obj| as the first argument, and the list of
-  // caller owned list of key value pairs as the second argument.
-  // |obj| opaque object. Implementation should not touch it.
-  void (*get_parameters)(const struct audio_proxy_stream_out* stream,
-                         const audio_proxy_key_val_t* context,
-                         const char** keys,
-                         audio_proxy_get_parameters_callback_t on_result,
-                         void* obj);
-
-  // optional.
-  int (*dump)(const struct audio_proxy_stream_out* stream, int fd);
-
-  // Pointer to the next version structure.
-  audio_proxy_stream_out_v2_t* v2;
-};
-
-typedef struct audio_proxy_stream_out audio_proxy_stream_out_t;
-
-// Extension of audio_proxy_device.
-struct audio_proxy_device_v2 {
-  // Returns the AudioProxy service name that the client wants to connect to.
-  const char* (*get_service_name)(struct audio_proxy_device_v2* device);
-
-  // Opens output stream for playback. Compared to the old version, this one
-  // will pass the address of the stream to the implementation.
-  int (*open_output_stream)(struct audio_proxy_device_v2* device,
-                            const char* address,
-                            audio_proxy_output_flags_t flags,
-                            audio_proxy_config_t* config,
-                            audio_proxy_stream_out_t** stream_out);
-
-  // Points to next version's struct. Implementation should set this field to
-  // null if next version struct is not available.
-  // This allows library to work with applications integrated with older version
-  // header.
-  void* extension;
-};
-
-typedef struct audio_proxy_device_v2 audio_proxy_device_v2_t;
-
-// Represents an audio HAL bus device.
-struct audio_proxy_device {
-  // Returns the unique address of this device.
-  const char* (*get_address)(struct audio_proxy_device* device);
-
-  // Similar to IDevice::openOutputStream.
-  int (*open_output_stream)(struct audio_proxy_device* device,
-                            audio_proxy_output_flags_t flags,
-                            audio_proxy_config_t* config,
-                            audio_proxy_stream_out_t** stream_out);
-
-  // Close |stream|. No more methods will be called on |stream| after this.
-  void (*close_output_stream)(struct audio_proxy_device* device,
-                              struct audio_proxy_stream_out* stream);
-
-  // Pointer to the extension structure.
-  audio_proxy_device_v2_t* v2;
-};
-
-typedef struct audio_proxy_device audio_proxy_device_t;
-
-// Provides |device| to the library. It returns 0 on success. This function is
-// supposed to be called once per process.
-// The service behind this library will register a new audio HAL to the audio
-// server, on the first call to the service.
-int audio_proxy_register_device(audio_proxy_device_t* device);
-
-#ifdef __cplusplus
-}
-#endif
-
-#endif  // DEVICE_GOOGLE_ATV_AUDIO_PROXY_PUBLIC_AUDIO_PROXY_H_
diff --git a/audio_proxy/sepolicy/OWNERS b/audio_proxy/sepolicy/OWNERS
deleted file mode 100644
index 508598e..0000000
--- a/audio_proxy/sepolicy/OWNERS
+++ /dev/null
@@ -1,2 +0,0 @@
-include platform/system/sepolicy:/OWNERS
-
diff --git a/audio_proxy/sepolicy/public/hal_audio_proxy.te b/audio_proxy/sepolicy/public/hal_audio_proxy.te
deleted file mode 100644
index 8b643b9..0000000
--- a/audio_proxy/sepolicy/public/hal_audio_proxy.te
+++ /dev/null
@@ -1,6 +0,0 @@
-# This could be moved to attributes
-hal_attribute(audio_proxy);
-
-binder_call(hal_audio_proxy_client, hal_audio_proxy_server);
-binder_call(hal_audio_proxy_server, hal_audio_proxy_client);
-binder_call(hal_audio_proxy_server, servicemanager);
diff --git a/audio_proxy/sepolicy/vendor/dumpstate.te b/audio_proxy/sepolicy/vendor/dumpstate.te
deleted file mode 100644
index 4fc2358..0000000
--- a/audio_proxy/sepolicy/vendor/dumpstate.te
+++ /dev/null
@@ -1 +0,0 @@
-binder_call(dumpstate, hal_audio_proxy_default);
diff --git a/audio_proxy/sepolicy/vendor/file_contexts b/audio_proxy/sepolicy/vendor/file_contexts
deleted file mode 100644
index e60f828..0000000
--- a/audio_proxy/sepolicy/vendor/file_contexts
+++ /dev/null
@@ -1,2 +0,0 @@
-# audio proxy service
-/(vendor|system/vendor)/bin/hw/device\.google\.atv\.audio_proxy@\d+\.\d+-service u:object_r:hal_audio_proxy_default_exec:s0
diff --git a/audio_proxy/sepolicy/vendor/hal_audio_proxy_default.te b/audio_proxy/sepolicy/vendor/hal_audio_proxy_default.te
deleted file mode 100644
index e53bfc5..0000000
--- a/audio_proxy/sepolicy/vendor/hal_audio_proxy_default.te
+++ /dev/null
@@ -1,12 +0,0 @@
-type hal_audio_proxy_default, domain;
-type hal_audio_proxy_default_exec, exec_type, vendor_file_type, file_type;
-
-# allows transition from init to the daemon _exec domain
-init_daemon_domain(hal_audio_proxy_default);
-
-# AudioProxy HAL incluces Audio as well as AudioProxy HAL interfaces.
-hal_server_domain(hal_audio_proxy_default, hal_audio);
-hal_server_domain(hal_audio_proxy_default, hal_audio_proxy);
-
-# allow audioserver to call hal_audio dump with its own fd to retrieve status
-allow hal_audio_proxy_default audioserver:fifo_file write;
diff --git a/audio_proxy/sepolicy/vendor/service.te b/audio_proxy/sepolicy/vendor/service.te
deleted file mode 100644
index f96c68d..0000000
--- a/audio_proxy/sepolicy/vendor/service.te
+++ /dev/null
@@ -1,2 +0,0 @@
-type hal_audio_proxy_service, hal_service_type, protected_service, service_manager_type;
-hal_attribute_service(hal_audio_proxy, hal_audio_proxy_service);
diff --git a/audio_proxy/sepolicy/vendor/service_contexts b/audio_proxy/sepolicy/vendor/service_contexts
deleted file mode 100644
index db21df0..0000000
--- a/audio_proxy/sepolicy/vendor/service_contexts
+++ /dev/null
@@ -1 +0,0 @@
-device.google.atv.audio_proxy.IAudioProxy/mediashell  u:object_r:hal_audio_proxy_service:s0
diff --git a/audio_proxy/service/AidlTypes.h b/audio_proxy/service/AidlTypes.h
deleted file mode 100644
index 022098b..0000000
--- a/audio_proxy/service/AidlTypes.h
+++ /dev/null
@@ -1,39 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <aidl/device/google/atv/audio_proxy/AudioChannelMask.h>
-#include <aidl/device/google/atv/audio_proxy/AudioConfig.h>
-#include <aidl/device/google/atv/audio_proxy/AudioDrain.h>
-#include <aidl/device/google/atv/audio_proxy/AudioFormat.h>
-#include <aidl/device/google/atv/audio_proxy/MmapBufferInfo.h>
-#include <aidl/device/google/atv/audio_proxy/PresentationPosition.h>
-#include <aidl/device/google/atv/audio_proxy/WriteStatus.h>
-
-namespace audio_proxy::service {
-
-// Short name for aidl types.
-using AidlAudioChannelMask =
-    aidl::device::google::atv::audio_proxy::AudioChannelMask;
-using AidlAudioConfig = aidl::device::google::atv::audio_proxy::AudioConfig;
-using AidlAudioDrain = aidl::device::google::atv::audio_proxy::AudioDrain;
-using AidlAudioFormat = aidl::device::google::atv::audio_proxy::AudioFormat;
-using AidlMmapBufferInfo =
-    aidl::device::google::atv::audio_proxy::MmapBufferInfo;
-using AidlPresentationPosition =
-    aidl::device::google::atv::audio_proxy::PresentationPosition;
-using AidlWriteStatus = aidl::device::google::atv::audio_proxy::WriteStatus;
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/Android.bp b/audio_proxy/service/Android.bp
deleted file mode 100644
index 6dd2cc1..0000000
--- a/audio_proxy/service/Android.bp
+++ /dev/null
@@ -1,197 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_google_atv_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["device_google_atv_license"],
-}
-
-cc_library_static {
-  name: "audio_proxy_service_util",
-  vendor_available: true,
-  host_supported: true,
-  srcs: [
-    "RingBufferUtil.cpp",
-    "ServiceConfig.cpp",
-  ],
-  shared_libs: [
-    "libbase",
-  ],
-}
-
-cc_defaults {
-  name: "audio_proxy_service_defaults",
-  vendor: true,
-  relative_install_path: "hw",
-
-  srcs: [
-    "AudioProxyImpl.cpp",
-    "AudioUtil.cpp",
-    "BusOutputStream.cpp",
-    "BusStreamProvider.cpp",
-    "DeviceImpl.cpp",
-    "DevicesFactoryImpl.cpp",
-    "DummyBusOutputStream.cpp",
-    "RemoteBusOutputStream.cpp",
-    "StreamOutImpl.cpp",
-    "WriteThread.cpp",
-    "main.cpp",
-  ],
-
-  shared_libs: [
-    "device.google.atv.audio_proxy-aidl-V3-ndk",
-    "libbase",
-    "libbinder_ndk",
-    "libhidlbase",
-    "libcutils",
-    "libfmq",
-    "libutils",
-  ],
-
-  static_libs: [
-    "audio_proxy_service_util",
-  ],
-
-  header_libs: [
-    "libaudio_system_headers",
-  ],
-
-  cflags: [
-    "-include ../common/AudioProxyVersionMacro.h",
-    "-Werror",
-    "-Wthread-safety",
-    "-Wno-unused-parameter",
-  ],
-}
-
-cc_binary {
-  name: "device.google.atv.audio_proxy@5.1-service",
-
-  defaults: [
-    "audio_proxy_service_defaults"
-  ],
-
-  init_rc: [
-    "device.google.atv.audio_proxy@5.1-service.rc",
-  ],
-
-  vintf_fragments: [ "manifest_audio_proxy_5_0.xml" ],
-
-  shared_libs: [
-    "android.hardware.audio@5.0",
-    "android.hardware.audio.common@5.0",
-  ],
-
-  cflags: [
-    "-DMAJOR_VERSION=5",
-    "-DMINOR_VERSION=0",
-  ],
-}
-
-cc_binary {
-  name: "device.google.atv.audio_proxy@6.0-service",
-
-  defaults: [
-    "audio_proxy_service_defaults"
-  ],
-
-  init_rc: [
-    "device.google.atv.audio_proxy@6.0-service.rc",
-  ],
-
-  vintf_fragments: [ "manifest_audio_proxy_6_0.xml" ],
-
-  shared_libs: [
-    "android.hardware.audio@6.0",
-    "android.hardware.audio.common@6.0",
-  ],
-
-  cflags: [
-    "-DMAJOR_VERSION=6",
-    "-DMINOR_VERSION=0",
-  ],
-}
-
-cc_binary {
-  name: "device.google.atv.audio_proxy@7.0-service",
-
-  defaults: [
-    "audio_proxy_service_defaults"
-  ],
-
-  init_rc: [
-    "device.google.atv.audio_proxy@7.0-service.rc",
-  ],
-
-  vintf_fragments: [ "manifest_audio_proxy_7_0.xml" ],
-
-  shared_libs: [
-    "android.hardware.audio@7.0",
-    "android.hardware.audio.common@7.0",
-  ],
-
-  cflags: [
-    "-DMAJOR_VERSION=7",
-    "-DMINOR_VERSION=0",
-  ],
-}
-
-cc_binary {
-  name: "device.google.atv.audio_proxy@7.1-service",
-
-  defaults: [
-    "audio_proxy_service_defaults"
-  ],
-
-  init_rc: [
-    "device.google.atv.audio_proxy@7.1-service.rc",
-  ],
-
-  vintf_fragments: [ "manifest_audio_proxy_7_1.xml" ],
-
-  shared_libs: [
-    "android.hardware.audio@7.1",
-    "android.hardware.audio@7.0",
-    "android.hardware.audio.common@7.0",
-  ],
-
-  cflags: [
-    "-DMAJOR_VERSION=7",
-    "-DMINOR_VERSION=1",
-  ],
-}
-
-cc_test {
-  name: "audio_proxy_service_util_test",
-  host_supported: true,
-
-  srcs: [
-    "RingBufferUtilTest.cpp",
-    "ServiceConfigTest.cpp",
-  ],
-  static_libs: [
-    "audio_proxy_service_util",
-    "libbase",
-    "libgtest",
-  ],
-
-  cflags: [
-    // Suppress the warning to make ServiceConfigTest easier.
-    "-Wno-writable-strings",
-  ],
-}
diff --git a/audio_proxy/service/AudioProxyError.h b/audio_proxy/service/AudioProxyError.h
deleted file mode 100644
index d653b5a..0000000
--- a/audio_proxy/service/AudioProxyError.h
+++ /dev/null
@@ -1,39 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-namespace audio_proxy {
-namespace service {
-
-enum {
-  ERROR_UNEXPECTED = 1,
-
-  // Error caused by AIDL transactions. It doesn't include client/server logical
-  // failures.
-  ERROR_AIDL_FAILURE = 2,
-
-  // Error caused by HIDL transactions. It doesn't include client/server logical
-  // failures.
-  ERROR_HIDL_FAILURE = 3,
-
-  // The server already has a registered IStreamProvider.
-  ERROR_STREAM_PROVIDER_EXIST = 4,
-
-  // Invalid command line args.
-  ERROR_INVALID_ARGS = 5,
-};
-
-}  // namespace service
-}  // namespace audio_proxy
\ No newline at end of file
diff --git a/audio_proxy/service/AudioProxyImpl.cpp b/audio_proxy/service/AudioProxyImpl.cpp
deleted file mode 100644
index 52ad4d1..0000000
--- a/audio_proxy/service/AudioProxyImpl.cpp
+++ /dev/null
@@ -1,61 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "AudioProxyImpl.h"
-
-#include <android-base/logging.h>
-
-#include "AudioProxyError.h"
-
-namespace audio_proxy::service {
-
-AudioProxyImpl::AudioProxyImpl()
-    : mDeathRecipient(
-          AIBinder_DeathRecipient_new(AudioProxyImpl::onStreamProviderDied)) {}
-
-ndk::ScopedAStatus AudioProxyImpl::start(
-    const std::shared_ptr<IStreamProvider>& provider) {
-  if (mBusStreamProvider.getStreamProvider()) {
-    LOG(ERROR) << "Service is already started.";
-    return ndk::ScopedAStatus::fromServiceSpecificError(
-        ERROR_STREAM_PROVIDER_EXIST);
-  }
-
-  binder_status_t binder_status = AIBinder_linkToDeath(
-      provider->asBinder().get(), mDeathRecipient.get(), this);
-  if (binder_status != STATUS_OK) {
-    LOG(ERROR) << "Failed to linkToDeath " << static_cast<int>(binder_status);
-    return ndk::ScopedAStatus::fromServiceSpecificError(ERROR_AIDL_FAILURE);
-  }
-
-  mBusStreamProvider.setStreamProvider(provider);
-  return ndk::ScopedAStatus::ok();
-}
-
-BusStreamProvider& AudioProxyImpl::getBusStreamProvider() {
-  return mBusStreamProvider;
-}
-
-void AudioProxyImpl::resetStreamProvider() {
-  mBusStreamProvider.setStreamProvider(nullptr);
-}
-
-void AudioProxyImpl::onStreamProviderDied(void* cookie) {
-  // AudioProxyImpl lives longer than the death handler. The reinterpret_cast
-  // here is safe.
-  auto* audioProxy = reinterpret_cast<AudioProxyImpl*>(cookie);
-  audioProxy->resetStreamProvider();
-}
-
-}  // namespace audio_proxy::service
diff --git a/audio_proxy/service/AudioProxyImpl.h b/audio_proxy/service/AudioProxyImpl.h
deleted file mode 100644
index 36f23d9..0000000
--- a/audio_proxy/service/AudioProxyImpl.h
+++ /dev/null
@@ -1,45 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <aidl/device/google/atv/audio_proxy/BnAudioProxy.h>
-
-#include "BusStreamProvider.h"
-
-namespace audio_proxy::service {
-
-using aidl::device::google::atv::audio_proxy::IStreamProvider;
-
-class AudioProxyImpl
-    : public aidl::device::google::atv::audio_proxy::BnAudioProxy {
- public:
-  AudioProxyImpl();
-  ~AudioProxyImpl() override = default;
-
-  ndk::ScopedAStatus start(
-      const std::shared_ptr<IStreamProvider>& provider) override;
-
-  BusStreamProvider& getBusStreamProvider();
-
- private:
-  static void onStreamProviderDied(void* cookie);
-  void resetStreamProvider();
-
-  BusStreamProvider mBusStreamProvider;
-  ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
-  std::shared_ptr<IStreamProvider> mStreamProvider;
-};
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/AudioUtil.cpp b/audio_proxy/service/AudioUtil.cpp
deleted file mode 100644
index b51c63d..0000000
--- a/audio_proxy/service/AudioUtil.cpp
+++ /dev/null
@@ -1,38 +0,0 @@
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "AudioUtil.h"
-
-#include <system/audio.h>
-
-namespace audio_proxy::service {
-int computeFrameSize(const AidlAudioConfig& config) {
-  audio_format_t format = static_cast<audio_format_t>(config.format);
-
-  if (!audio_has_proportional_frames(format)) {
-    return sizeof(int8_t);
-  }
-
-  size_t channelSampleSize = audio_bytes_per_sample(format);
-  return audio_channel_count_from_out_mask(
-             static_cast<audio_channel_mask_t>(config.channelMask)) *
-         channelSampleSize;
-}
-
-int64_t computeBufferSizeBytes(const AidlAudioConfig& config,
-                               int32_t bufferSizeMs) {
-  return static_cast<int64_t>(bufferSizeMs) * config.sampleRateHz *
-         computeFrameSize(config) / 1000;
-}
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/AudioUtil.h b/audio_proxy/service/AudioUtil.h
deleted file mode 100644
index 5430472..0000000
--- a/audio_proxy/service/AudioUtil.h
+++ /dev/null
@@ -1,25 +0,0 @@
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <cstdint>
-
-#include "AidlTypes.h"
-
-namespace audio_proxy::service {
-int computeFrameSize(const AidlAudioConfig& config);
-int64_t computeBufferSizeBytes(const AidlAudioConfig& config,
-                               int32_t bufferSizeMs);
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/BusOutputStream.cpp b/audio_proxy/service/BusOutputStream.cpp
deleted file mode 100644
index e456faf..0000000
--- a/audio_proxy/service/BusOutputStream.cpp
+++ /dev/null
@@ -1,56 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "BusOutputStream.h"
-
-#include <android-base/logging.h>
-
-#include "AudioUtil.h"
-
-namespace audio_proxy::service {
-
-BusOutputStream::BusOutputStream(const std::string& address,
-                                 const AidlAudioConfig& config, int32_t flags)
-    : mAddress(address), mConfig(config), mFlags(flags) {}
-BusOutputStream::~BusOutputStream() = default;
-
-const std::string& BusOutputStream::getAddress() const { return mAddress; }
-const AidlAudioConfig& BusOutputStream::getConfig() const { return mConfig; }
-int32_t BusOutputStream::getFlags() const { return mFlags; }
-
-int BusOutputStream::getFrameSize() const { return computeFrameSize(mConfig); }
-
-bool BusOutputStream::prepareForWriting(uint32_t frameSize,
-                                        uint32_t frameCount) {
-  DCHECK_EQ(mWritingFrameSize, 0);
-  DCHECK_EQ(mWritingFrameCount, 0);
-
-  if (!prepareForWritingImpl(frameSize, frameCount)) {
-    return false;
-  }
-
-  mWritingFrameSize = frameSize;
-  mWritingFrameCount = frameCount;
-  return true;
-}
-
-uint32_t BusOutputStream::getWritingFrameSize() const {
-  return mWritingFrameSize;
-}
-
-uint32_t BusOutputStream::getWritingFrameCount() const {
-  return mWritingFrameCount;
-}
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/BusOutputStream.h b/audio_proxy/service/BusOutputStream.h
deleted file mode 100644
index 2116bca..0000000
--- a/audio_proxy/service/BusOutputStream.h
+++ /dev/null
@@ -1,70 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <inttypes.h>
-
-#include "AidlTypes.h"
-
-namespace audio_proxy::service {
-
-// Interface for audio playback. It has similar APIs to the AIDL IOutputStream.
-class BusOutputStream {
- public:
-  BusOutputStream(const std::string& address, const AidlAudioConfig& config,
-                  int32_t flags);
-  virtual ~BusOutputStream();
-
-  const std::string& getAddress() const;
-  const AidlAudioConfig& getConfig() const;
-  int32_t getFlags() const;
-  int getFrameSize() const;
-
-  bool prepareForWriting(uint32_t frameSize, uint32_t frameCount);
-  uint32_t getWritingFrameSize() const;
-  uint32_t getWritingFrameCount() const;
-
-  virtual bool standby() = 0;
-  virtual bool pause() = 0;
-  virtual bool resume() = 0;
-  virtual bool drain(AidlAudioDrain drain) = 0;
-  virtual bool flush() = 0;
-  virtual bool close() = 0;
-  virtual bool setVolume(float left, float right) = 0;
-
-  virtual size_t availableToWrite() = 0;
-  virtual AidlWriteStatus writeRingBuffer(const uint8_t* firstMem,
-                                          size_t firstLength,
-                                          const uint8_t* secondMem,
-                                          size_t secondLength) = 0;
-
-  virtual bool start() = 0;
-  virtual bool stop() = 0;
-  virtual AidlMmapBufferInfo createMmapBuffer(int32_t minBufferSizeFrames) = 0;
-  virtual AidlPresentationPosition getMmapPosition() = 0;
-
- protected:
-  virtual bool prepareForWritingImpl(uint32_t frameSize,
-                                     uint32_t frameCount) = 0;
-
-  const std::string mAddress;
-  const AidlAudioConfig mConfig;
-  const int32_t mFlags;
-
-  uint32_t mWritingFrameSize = 0;
-  uint32_t mWritingFrameCount = 0;
-};
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/BusStreamProvider.cpp b/audio_proxy/service/BusStreamProvider.cpp
deleted file mode 100644
index af2c5b8..0000000
--- a/audio_proxy/service/BusStreamProvider.cpp
+++ /dev/null
@@ -1,117 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "BusStreamProvider.h"
-
-#include <android-base/logging.h>
-
-#include <algorithm>
-
-#include "DummyBusOutputStream.h"
-#include "RemoteBusOutputStream.h"
-
-using aidl::device::google::atv::audio_proxy::IOutputStream;
-
-namespace audio_proxy::service {
-
-void BusStreamProvider::setStreamProvider(
-    std::shared_ptr<IStreamProvider> provider) {
-  std::lock_guard<std::mutex> lock(mLock);
-  cleanStreamOutList_Locked();
-  mStreamProvider = std::move(provider);
-
-  for (auto& weakStream : mStreamOutList) {
-    if (sp<StreamOutImpl> stream = weakStream.promote()) {
-      auto oldOutputStream = stream->getOutputStream();
-      auto outputStream = openOutputStream_Locked(
-          oldOutputStream->getAddress(), oldOutputStream->getConfig(),
-          oldOutputStream->getFlags(),
-          oldOutputStream->getConfig().bufferSizeBytes,
-          oldOutputStream->getConfig().latencyMs);
-      stream->updateOutputStream(std::move(outputStream));
-    }
-  }
-}
-
-std::shared_ptr<IStreamProvider> BusStreamProvider::getStreamProvider() {
-  std::lock_guard<std::mutex> lock(mLock);
-  return mStreamProvider;
-}
-
-std::shared_ptr<BusOutputStream> BusStreamProvider::openOutputStream(
-    const std::string& address, const AidlAudioConfig& config, int32_t flags,
-    int64_t bufferSizeBytes, int32_t latencyMs) {
-  std::lock_guard<std::mutex> lock(mLock);
-  return openOutputStream_Locked(address, config, flags, bufferSizeBytes,
-                                 latencyMs);
-}
-
-void BusStreamProvider::onStreamOutCreated(wp<StreamOutImpl> stream) {
-  std::lock_guard<std::mutex> lock(mLock);
-  cleanStreamOutList_Locked();
-  mStreamOutList.emplace_back(std::move(stream));
-}
-
-std::shared_ptr<BusOutputStream> BusStreamProvider::openOutputStream_Locked(
-    const std::string& address, const AidlAudioConfig& config, int32_t flags,
-    int64_t bufferSizeBytes, int32_t latencyMs) {
-  AidlAudioConfig newConfig = config;
-  newConfig.bufferSizeBytes = bufferSizeBytes;
-  newConfig.latencyMs = latencyMs;
-
-  if (!mStreamProvider) {
-    return std::make_shared<DummyBusOutputStream>(address, newConfig, flags);
-  }
-
-  std::shared_ptr<IOutputStream> stream;
-  ndk::ScopedAStatus status =
-      mStreamProvider->openOutputStream(address, config, flags, &stream);
-  if (!status.isOk() || !stream) {
-    LOG(ERROR) << "Failed to open output stream, status " << status.getStatus();
-    return std::make_shared<DummyBusOutputStream>(address, newConfig, flags);
-  }
-
-  int64_t aidlBufferSizeInBytes = -1;
-  if (stream->getBufferSizeBytes(&aidlBufferSizeInBytes).isOk() &&
-      aidlBufferSizeInBytes > 0) {
-    newConfig.bufferSizeBytes = aidlBufferSizeInBytes;
-  }
-
-  int32_t aidlLatencyMs = -1;
-  if (stream->getLatencyMs(&aidlLatencyMs).isOk() && aidlLatencyMs > 0) {
-    newConfig.latencyMs = aidlLatencyMs;
-  }
-
-  return std::make_shared<RemoteBusOutputStream>(std::move(stream), address,
-                                                 newConfig, flags);
-}
-
-size_t BusStreamProvider::cleanAndCountStreamOuts() {
-  std::lock_guard<std::mutex> lock(mLock);
-  cleanStreamOutList_Locked();
-  return mStreamOutList.size();
-}
-
-void BusStreamProvider::cleanStreamOutList_Locked() {
-  auto it = mStreamOutList.begin();
-  while (it != mStreamOutList.end()) {
-    if (!it->promote()) {
-      it = mStreamOutList.erase(it);
-    } else {
-      ++it;
-    }
-  }
-}
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/BusStreamProvider.h b/audio_proxy/service/BusStreamProvider.h
deleted file mode 100644
index 8d3ebbb..0000000
--- a/audio_proxy/service/BusStreamProvider.h
+++ /dev/null
@@ -1,74 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <aidl/device/google/atv/audio_proxy/IStreamProvider.h>
-#include <android-base/thread_annotations.h>
-#include <utils/RefBase.h>
-
-#include <mutex>
-#include <vector>
-
-#include "AidlTypes.h"
-#include "StreamOutImpl.h"
-
-namespace audio_proxy::service {
-
-using aidl::device::google::atv::audio_proxy::IStreamProvider;
-using android::wp;
-
-class BusOutputStream;
-
-// Class to provider BusOutputStream to clients (StreamOutImpl). The public
-// functions will be called from either the AIDL thread pool or HIDL thread
-// pool. So the public functions are thread safe.
-class BusStreamProvider {
- public:
-  // Set/unset remote IStreamProvider. It will notify the opened StreamOut in
-  // mStreamOutList as well.
-  void setStreamProvider(std::shared_ptr<IStreamProvider> streamProvider);
-
-  std::shared_ptr<IStreamProvider> getStreamProvider();
-
-  // Add stream to the list so that they can be notified when the client becomes
-  // available.
-  void onStreamOutCreated(wp<StreamOutImpl> stream);
-
-  // Returns different BusOutputStream depends on the current status:
-  // 1. If mStreamProvider is available and mStreamProvider::openOutputStream
-  //    returns valid IOutputStream, returns RemoteBusOutputStream.
-  // 2. Returns DummyBusOutputStream otherwise.
-  // This function always return a non null BusOutputStream.
-  std::shared_ptr<BusOutputStream> openOutputStream(
-      const std::string& address, const AidlAudioConfig& config, int32_t flags,
-      int64_t bufferSizeBytes, int32_t latencyMs);
-
-  // Clear closed StreamOut and return number of opened StreamOut.
-  size_t cleanAndCountStreamOuts();
-
- private:
-  std::shared_ptr<BusOutputStream> openOutputStream_Locked(
-      const std::string& address, const AidlAudioConfig& config, int32_t flags,
-      int64_t bufferSizeBytes, int32_t latencyMs) REQUIRES(mLock);
-
-  // Remove the dead dead from mStreamOutList.
-  void cleanStreamOutList_Locked() REQUIRES(mLock);
-
-  std::mutex mLock;
-  std::shared_ptr<IStreamProvider> mStreamProvider GUARDED_BY(mLock);
-  std::vector<wp<StreamOutImpl>> mStreamOutList GUARDED_BY(mLock);
-};
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/DeviceImpl.cpp b/audio_proxy/service/DeviceImpl.cpp
deleted file mode 100644
index 1cbae5a..0000000
--- a/audio_proxy/service/DeviceImpl.cpp
+++ /dev/null
@@ -1,503 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "DeviceImpl.h"
-
-#include <android-base/logging.h>
-#include <android-base/strings.h>
-#include <system/audio-hal-enums.h>
-#include <utils/RefBase.h>
-
-#include <optional>
-
-#include "AidlTypes.h"
-#include "AudioUtil.h"
-#include "BusOutputStream.h"
-#include "BusStreamProvider.h"
-#include "ServiceConfig.h"
-#include "StreamOutImpl.h"
-
-using namespace ::android::hardware::audio::common::CPP_VERSION;
-using namespace ::android::hardware::audio::CPP_VERSION;
-
-using ::android::wp;
-
-namespace audio_proxy {
-namespace service {
-namespace {
-AudioPatchHandle gNextAudioPatchHandle = 1;
-
-#if MAJOR_VERSION >= 7
-std::optional<AidlAudioConfig> toAidlAudioConfig(
-    const AudioConfigBase& hidl_config) {
-  audio_format_t format = AUDIO_FORMAT_INVALID;
-  if (!audio_format_from_string(hidl_config.format.c_str(), &format)) {
-    return std::nullopt;
-  }
-
-  audio_channel_mask_t channelMask = AUDIO_CHANNEL_INVALID;
-  if (!audio_channel_mask_from_string(hidl_config.channelMask.c_str(),
-                                      &channelMask)) {
-    return std::nullopt;
-  }
-
-  AidlAudioConfig aidlConfig = {
-      .format = static_cast<AidlAudioFormat>(format),
-      .sampleRateHz = static_cast<int32_t>(hidl_config.sampleRateHz),
-      .channelMask = static_cast<AidlAudioChannelMask>(channelMask),
-      .bufferSizeBytes = 0,
-      .latencyMs = 0};
-
-  return aidlConfig;
-}
-
-std::optional<int32_t> toAidlAudioOutputFlags(
-    const hidl_vec<AudioInOutFlag>& flags) {
-  int32_t outputFlags = static_cast<int32_t>(AUDIO_OUTPUT_FLAG_NONE);
-  for (const auto& flag : flags) {
-    audio_output_flags_t outputFlag = AUDIO_OUTPUT_FLAG_NONE;
-    if (audio_output_flag_from_string(flag.c_str(), &outputFlag)) {
-      outputFlags |= static_cast<int32_t>(outputFlag);
-    } else {
-      return std::nullopt;
-    }
-  }
-
-  return outputFlags;
-}
-
-bool checkSourceMetadata(const SourceMetadata& metadata) {
-  for (const auto& track : metadata.tracks) {
-    audio_usage_t usage;
-    if (!audio_usage_from_string(track.usage.c_str(), &usage)) {
-      return false;
-    }
-
-    audio_content_type_t contentType;
-    if (!audio_content_type_from_string(track.contentType.c_str(),
-                                        &contentType)) {
-      return false;
-    }
-
-    audio_channel_mask_t channelMask;
-    if (!audio_channel_mask_from_string(track.channelMask.c_str(),
-                                        &channelMask)) {
-      return false;
-    }
-
-    // From types.hal:
-    // Tags are set by vendor specific applications and must be prefixed by
-    // "VX_". Vendor must namespace their tag names to avoid conflicts. See
-    // 'vendorExtension' in audio_policy_configuration.xsd for a formal
-    // definition.
-    //
-    // From audio_policy_configuration.xsd:
-    // Vendor extension names must be prefixed by "VX_" to distinguish them from
-    // AOSP values. Vendors must namespace their names to avoid conflicts. The
-    // namespace part must only use capital latin characters and decimal digits
-    // and consist of at least 3 characters.
-    for (const auto& tag : track.tags) {
-      if (!android::base::StartsWith(tag.c_str(), "VX_")) {
-        return false;
-      }
-    }
-  }
-
-  return true;
-}
-
-bool checkAudioPortConfig(const AudioPortConfig& config) {
-  if (config.base.format.getDiscriminator() ==
-      AudioConfigBaseOptional::Format::hidl_discriminator::value) {
-    audio_format_t format;
-    if (!audio_format_from_string(config.base.format.value().c_str(),
-                                  &format)) {
-      return false;
-    }
-  }
-
-  if (config.base.channelMask.getDiscriminator() ==
-      AudioConfigBaseOptional::ChannelMask::hidl_discriminator::value) {
-    audio_channel_mask_t channelMask;
-    if (!audio_channel_mask_from_string(config.base.channelMask.value().c_str(),
-                                        &channelMask)) {
-      return false;
-    }
-  }
-
-  if (config.gain.getDiscriminator() ==
-      AudioPortConfig::OptionalGain::hidl_discriminator::config) {
-    for (const auto& mode : config.gain.config().mode) {
-      audio_gain_mode_t gainMode;
-      if (!audio_gain_mode_from_string(mode.c_str(), &gainMode)) {
-        return false;
-      }
-    }
-
-    audio_channel_mask_t channelMask;
-    if (!audio_channel_mask_from_string(
-            config.gain.config().channelMask.c_str(), &channelMask)) {
-      return false;
-    }
-  }
-
-  if (config.ext.getDiscriminator() ==
-      AudioPortExtendedInfo::hidl_discriminator::device) {
-    audio_devices_t deviceType;
-    if (!audio_device_from_string(config.ext.device().deviceType.c_str(),
-                                  &deviceType)) {
-      return false;
-    }
-  }
-
-  if (config.ext.getDiscriminator() ==
-      AudioPortExtendedInfo::hidl_discriminator::mix) {
-    const auto& useCase = config.ext.mix().useCase;
-    if (useCase.getDiscriminator() == AudioPortExtendedInfo::AudioPortMixExt::
-                                          UseCase::hidl_discriminator::stream) {
-      audio_stream_type_t audioStreamType;
-      if (!audio_stream_type_from_string(useCase.stream().c_str(),
-                                         &audioStreamType)) {
-        return false;
-      }
-    } else {
-      audio_source_t audioSource;
-      if (!audio_source_from_string(useCase.source().c_str(), &audioSource)) {
-        return false;
-      }
-    }
-  }
-
-  return true;
-}
-#else
-AidlAudioConfig toAidlAudioConfig(const AudioConfig& hidl_config) {
-  AidlAudioConfig aidlConfig = {
-      .format = static_cast<AidlAudioFormat>(hidl_config.format),
-      .sampleRateHz = static_cast<int32_t>(hidl_config.sampleRateHz),
-      .channelMask = static_cast<AidlAudioChannelMask>(hidl_config.channelMask),
-      .bufferSizeBytes = 0,
-      .latencyMs = 0};
-
-  return aidlConfig;
-}
-
-// Before 7.0, the fields are using enum instead of string. There's no need to
-// validate them.
-bool checkAudioPortConfig(const AudioPortConfig& config) { return true; }
-#endif
-}  // namespace
-
-DeviceImpl::DeviceImpl(BusStreamProvider& busStreamProvider,
-                       const ServiceConfig& serviceConfig)
-    : mBusStreamProvider(busStreamProvider), mServiceConfig(serviceConfig) {}
-
-// Methods from ::android::hardware::audio::V5_0::IDevice follow.
-Return<Result> DeviceImpl::initCheck() { return Result::OK; }
-
-Return<Result> DeviceImpl::setMasterVolume(float volume) {
-  // software mixer will emulate this ability
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> DeviceImpl::getMasterVolume(getMasterVolume_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, 0.f);
-  return Void();
-}
-
-Return<Result> DeviceImpl::setMicMute(bool mute) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> DeviceImpl::getMicMute(getMicMute_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, false);
-  return Void();
-}
-
-Return<Result> DeviceImpl::setMasterMute(bool mute) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> DeviceImpl::getMasterMute(getMasterMute_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, false);
-  return Void();
-}
-
-Return<void> DeviceImpl::getInputBufferSize(const AudioConfig& config,
-                                            getInputBufferSize_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, 0);
-  return Void();
-}
-
-#if MAJOR_VERSION >= 7
-template <typename CallbackType>
-Return<void> DeviceImpl::openOutputStreamImpl(
-    int32_t ioHandle, const DeviceAddress& device, const AudioConfig& config,
-    const hidl_vec<AudioInOutFlag>& flags, const SourceMetadata& sourceMetadata,
-    CallbackType _hidl_cb) {
-  std::optional<AidlAudioConfig> aidlConfig = toAidlAudioConfig(config.base);
-  if (!aidlConfig) {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr, {});
-    return Void();
-  }
-
-  std::optional<int32_t> outputFlags = toAidlAudioOutputFlags(flags);
-  if (!outputFlags) {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr, {});
-    return Void();
-  }
-
-  if (!checkSourceMetadata(sourceMetadata)) {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr, {});
-    return Void();
-  }
-
-  std::string address;
-
-  // Default device is used for VTS test.
-  if (device.deviceType == "AUDIO_DEVICE_OUT_DEFAULT") {
-    address = "default";
-  } else if (device.deviceType == "AUDIO_DEVICE_OUT_BUS") {
-    address = device.address.id();
-  } else {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr, {});
-    return Void();
-  }
-
-  const auto configIt = mServiceConfig.streams.find(address);
-  if (configIt == mServiceConfig.streams.end()) {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr, {});
-    return Void();
-  }
-
-  std::shared_ptr<BusOutputStream> busOutputStream =
-      mBusStreamProvider.openOutputStream(
-          address, *aidlConfig, *outputFlags,
-          computeBufferSizeBytes(*aidlConfig, configIt->second.bufferSizeMs),
-          configIt->second.latencyMs);
-  DCHECK(busOutputStream);
-  auto streamOut =
-      sp<StreamOutImpl>::make(std::move(busOutputStream), config.base);
-  mBusStreamProvider.onStreamOutCreated(streamOut);
-  _hidl_cb(Result::OK, streamOut, config);
-  return Void();
-}
-
-Return<void> DeviceImpl::openOutputStream(int32_t ioHandle,
-                                          const DeviceAddress& device,
-                                          const AudioConfig& config,
-                                          const hidl_vec<AudioInOutFlag>& flags,
-                                          const SourceMetadata& sourceMetadata,
-                                          openOutputStream_cb _hidl_cb) {
-  return openOutputStreamImpl(ioHandle, device, config, flags, sourceMetadata,
-                              _hidl_cb);
-}
-
-Return<void> DeviceImpl::openInputStream(int32_t ioHandle,
-                                         const DeviceAddress& device,
-                                         const AudioConfig& config,
-                                         const hidl_vec<AudioInOutFlag>& flags,
-                                         const SinkMetadata& sinkMetadata,
-                                         openInputStream_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, sp<IStreamIn>(), config);
-  return Void();
-}
-#else
-Return<void> DeviceImpl::openOutputStream(int32_t ioHandle,
-                                          const DeviceAddress& device,
-                                          const AudioConfig& config,
-                                          hidl_bitfield<AudioOutputFlag> flags,
-                                          const SourceMetadata& sourceMetadata,
-                                          openOutputStream_cb _hidl_cb) {
-  std::string address;
-  if (device.device == AudioDevice::OUT_DEFAULT) {
-    address = "default";
-  } else if (device.device == AudioDevice::OUT_BUS) {
-    address = device.busAddress;
-  } else {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr, {});
-    return Void();
-  }
-
-  const auto configIt = mServiceConfig.streams.find(address);
-  if (configIt == mServiceConfig.streams.end()) {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr, {});
-    return Void();
-  }
-
-  auto aidlConfig = toAidlAudioConfig(config);
-  std::shared_ptr<BusOutputStream> busOutputStream =
-      mBusStreamProvider.openOutputStream(
-          address, aidlConfig, static_cast<int32_t>(flags),
-          computeBufferSizeBytes(aidlConfig, configIt->second.bufferSizeMs),
-          configIt->second.latencyMs);
-  DCHECK(busOutputStream);
-  auto streamOut = sp<StreamOutImpl>::make(std::move(busOutputStream), config);
-  mBusStreamProvider.onStreamOutCreated(streamOut);
-  _hidl_cb(Result::OK, streamOut, config);
-  return Void();
-}
-
-Return<void> DeviceImpl::openInputStream(int32_t ioHandle,
-                                         const DeviceAddress& device,
-                                         const AudioConfig& config,
-                                         hidl_bitfield<AudioInputFlag> flags,
-                                         const SinkMetadata& sinkMetadata,
-                                         openInputStream_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, sp<IStreamIn>(), config);
-  return Void();
-}
-#endif
-
-Return<bool> DeviceImpl::supportsAudioPatches() { return true; }
-
-// Create a do-nothing audio patch.
-Return<void> DeviceImpl::createAudioPatch(
-    const hidl_vec<AudioPortConfig>& sources,
-    const hidl_vec<AudioPortConfig>& sinks, createAudioPatch_cb _hidl_cb) {
-  for (const auto& config : sources) {
-    if (!checkAudioPortConfig(config)) {
-      _hidl_cb(Result::INVALID_ARGUMENTS, 0);
-      return Void();
-    }
-  }
-
-  for (const auto& config : sinks) {
-    if (!checkAudioPortConfig(config)) {
-      _hidl_cb(Result::INVALID_ARGUMENTS, 0);
-      return Void();
-    }
-  }
-
-  AudioPatchHandle handle = gNextAudioPatchHandle++;
-  mAudioPatchHandles.insert(handle);
-  _hidl_cb(Result::OK, handle);
-  return Void();
-}
-
-Return<Result> DeviceImpl::releaseAudioPatch(AudioPatchHandle patch) {
-  size_t removed = mAudioPatchHandles.erase(patch);
-  return removed > 0 ? Result::OK : Result::INVALID_ARGUMENTS;
-}
-
-Return<void> DeviceImpl::getAudioPort(const AudioPort& port,
-                                      getAudioPort_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, port);
-  return Void();
-}
-
-Return<Result> DeviceImpl::setAudioPortConfig(const AudioPortConfig& config) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> DeviceImpl::getHwAvSync(getHwAvSync_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, 0);
-  return Void();
-}
-
-Return<Result> DeviceImpl::setScreenState(bool turnedOn) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> DeviceImpl::getParameters(const hidl_vec<ParameterValue>& context,
-                                       const hidl_vec<hidl_string>& keys,
-                                       getParameters_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, hidl_vec<ParameterValue>());
-  return Void();
-}
-
-Return<Result> DeviceImpl::setParameters(
-    const hidl_vec<ParameterValue>& context,
-    const hidl_vec<ParameterValue>& parameters) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> DeviceImpl::getMicrophones(getMicrophones_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, hidl_vec<MicrophoneInfo>());
-  return Void();
-}
-
-Return<Result> DeviceImpl::setConnectedState(const DeviceAddress& address,
-                                             bool connected) {
-#if MAJOR_VERSION >= 7
-  audio_devices_t deviceType = AUDIO_DEVICE_NONE;
-  if (!audio_device_from_string(address.deviceType.c_str(), &deviceType)) {
-    return Result::INVALID_ARGUMENTS;
-  }
-
-  if (deviceType != AUDIO_DEVICE_OUT_BUS) {
-    return Result::NOT_SUPPORTED;
-  }
-
-  const auto& busAddress = address.address.id();
-#else
-  if (address.device != AudioDevice::OUT_BUS) {
-    return Result::NOT_SUPPORTED;
-  }
-
-  const auto& busAddress = address.busAddress;
-#endif
-
-  return mServiceConfig.streams.count(busAddress) > 0 ? Result::OK
-                                                      : Result::NOT_SUPPORTED;
-}
-
-#if MAJOR_VERSION >= 6
-Return<void> DeviceImpl::updateAudioPatch(
-    AudioPatchHandle previousPatch, const hidl_vec<AudioPortConfig>& sources,
-    const hidl_vec<AudioPortConfig>& sinks, updateAudioPatch_cb _hidl_cb) {
-  if (mAudioPatchHandles.erase(previousPatch) == 0) {
-    _hidl_cb(Result::INVALID_ARGUMENTS, 0);
-    return Void();
-  }
-  AudioPatchHandle newPatch = gNextAudioPatchHandle++;
-  mAudioPatchHandles.insert(newPatch);
-  _hidl_cb(Result::OK, newPatch);
-  return Void();
-}
-
-Return<Result> DeviceImpl::close() {
-  return mBusStreamProvider.cleanAndCountStreamOuts() == 0
-             ? Result::OK
-             : Result::INVALID_STATE;
-}
-
-Return<Result> DeviceImpl::addDeviceEffect(AudioPortHandle device,
-                                           uint64_t effectId) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<Result> DeviceImpl::removeDeviceEffect(AudioPortHandle device,
-                                              uint64_t effectId) {
-  return Result::NOT_SUPPORTED;
-}
-#endif
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-Return<void> DeviceImpl::openOutputStream_7_1(
-    int32_t ioHandle, const DeviceAddress& device, const AudioConfig& config,
-    const hidl_vec<AudioInOutFlag>& flags, const SourceMetadata& sourceMetadata,
-    openOutputStream_7_1_cb _hidl_cb) {
-  return openOutputStreamImpl(ioHandle, device, config, flags, sourceMetadata,
-                              _hidl_cb);
-}
-
-Return<Result> DeviceImpl::setConnectedState_7_1(const AudioPort& devicePort,
-                                                 bool connected) {
-  return Result::OK;
-}
-#endif
-
-}  // namespace service
-}  // namespace audio_proxy
diff --git a/audio_proxy/service/DeviceImpl.h b/audio_proxy/service/DeviceImpl.h
deleted file mode 100644
index ffe3f88..0000000
--- a/audio_proxy/service/DeviceImpl.h
+++ /dev/null
@@ -1,162 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <set>
-
-// clang-format off
-#include PATH(android/hardware/audio/FILE_VERSION/IDevice.h)
-// clang-format on
-#include <hidl/MQDescriptor.h>
-#include <hidl/Status.h>
-
-namespace audio_proxy {
-namespace service {
-
-using ::android::sp;
-using ::android::hardware::hidl_array;
-using ::android::hardware::hidl_bitfield;
-using ::android::hardware::hidl_death_recipient;
-using ::android::hardware::hidl_memory;
-using ::android::hardware::hidl_string;
-using ::android::hardware::hidl_vec;
-using ::android::hardware::Return;
-using ::android::hardware::Void;
-using ::android::hardware::audio::common::CPP_VERSION::AudioConfig;
-using ::android::hardware::audio::common::CPP_VERSION::AudioPatchHandle;
-using ::android::hardware::audio::common::CPP_VERSION::AudioPort;
-using ::android::hardware::audio::common::CPP_VERSION::AudioPortConfig;
-using ::android::hardware::audio::common::CPP_VERSION::AudioPortHandle;
-using ::android::hardware::audio::common::CPP_VERSION::DeviceAddress;
-using ::android::hardware::audio::common::CPP_VERSION::SinkMetadata;
-using ::android::hardware::audio::common::CPP_VERSION::SourceMetadata;
-using ::android::hardware::audio::CPP_VERSION::IDevice;
-using ::android::hardware::audio::CPP_VERSION::ParameterValue;
-using ::android::hardware::audio::CPP_VERSION::Result;
-
-#if MAJOR_VERSION >= 7
-using ::android::hardware::audio::CPP_VERSION::AudioInOutFlag;
-#else
-using ::android::hardware::audio::common::CPP_VERSION::AudioInputFlag;
-using ::android::hardware::audio::common::CPP_VERSION::AudioOutputFlag;
-#endif
-
-class BusStreamProvider;
-struct ServiceConfig;
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-class DeviceImpl : public android::hardware::audio::V7_1::IDevice {
-#else
-class DeviceImpl : public IDevice {
-#endif
- public:
-  DeviceImpl(BusStreamProvider& busStreamProvider, const ServiceConfig& config);
-
-  // Methods from ::android::hardware::audio::V5_0::IDevice follow.
-  Return<Result> initCheck() override;
-  Return<Result> setMasterVolume(float volume) override;
-  Return<void> getMasterVolume(getMasterVolume_cb _hidl_cb) override;
-  Return<Result> setMicMute(bool mute) override;
-  Return<void> getMicMute(getMicMute_cb _hidl_cb) override;
-  Return<Result> setMasterMute(bool mute) override;
-  Return<void> getMasterMute(getMasterMute_cb _hidl_cb) override;
-  Return<void> getInputBufferSize(const AudioConfig& config,
-                                  getInputBufferSize_cb _hidl_cb) override;
-
-#if MAJOR_VERSION >= 7
-  Return<void> openOutputStream(int32_t ioHandle, const DeviceAddress& device,
-                                const AudioConfig& config,
-                                const hidl_vec<AudioInOutFlag>& flags,
-                                const SourceMetadata& sourceMetadata,
-                                openOutputStream_cb _hidl_cb) override;
-  Return<void> openInputStream(int32_t ioHandle, const DeviceAddress& device,
-                               const AudioConfig& config,
-                               const hidl_vec<AudioInOutFlag>& flags,
-                               const SinkMetadata& sinkMetadata,
-                               openInputStream_cb _hidl_cb) override;
-#else
-  Return<void> openOutputStream(int32_t ioHandle, const DeviceAddress& device,
-                                const AudioConfig& config,
-                                hidl_bitfield<AudioOutputFlag> flags,
-                                const SourceMetadata& sourceMetadata,
-                                openOutputStream_cb _hidl_cb) override;
-  Return<void> openInputStream(int32_t ioHandle, const DeviceAddress& device,
-                               const AudioConfig& config,
-                               hidl_bitfield<AudioInputFlag> flags,
-                               const SinkMetadata& sinkMetadata,
-                               openInputStream_cb _hidl_cb) override;
-#endif
-
-  Return<bool> supportsAudioPatches() override;
-  Return<void> createAudioPatch(const hidl_vec<AudioPortConfig>& sources,
-                                const hidl_vec<AudioPortConfig>& sinks,
-                                createAudioPatch_cb _hidl_cb) override;
-  Return<Result> releaseAudioPatch(AudioPatchHandle patch) override;
-  Return<void> getAudioPort(const AudioPort& port,
-                            getAudioPort_cb _hidl_cb) override;
-  Return<Result> setAudioPortConfig(const AudioPortConfig& config) override;
-  Return<void> getHwAvSync(getHwAvSync_cb _hidl_cb) override;
-  Return<Result> setScreenState(bool turnedOn) override;
-  Return<void> getParameters(const hidl_vec<ParameterValue>& context,
-                             const hidl_vec<hidl_string>& keys,
-                             getParameters_cb _hidl_cb) override;
-  Return<Result> setParameters(
-      const hidl_vec<ParameterValue>& context,
-      const hidl_vec<ParameterValue>& parameters) override;
-  Return<void> getMicrophones(getMicrophones_cb _hidl_cb) override;
-  Return<Result> setConnectedState(const DeviceAddress& address,
-                                   bool connected) override;
-
-#if MAJOR_VERSION >= 6
-  Return<void> updateAudioPatch(AudioPatchHandle previousPatch,
-                                const hidl_vec<AudioPortConfig>& sources,
-                                const hidl_vec<AudioPortConfig>& sinks,
-                                updateAudioPatch_cb _hidl_cb) override;
-  Return<Result> close() override;
-  Return<Result> addDeviceEffect(AudioPortHandle device,
-                                 uint64_t effectId) override;
-  Return<Result> removeDeviceEffect(AudioPortHandle device,
-                                    uint64_t effectId) override;
-#endif
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-  Return<void> openOutputStream_7_1(int32_t ioHandle,
-                                    const DeviceAddress& device,
-                                    const AudioConfig& config,
-                                    const hidl_vec<AudioInOutFlag>& flags,
-                                    const SourceMetadata& sourceMetadata,
-                                    openOutputStream_7_1_cb _hidl_cb) override;
-  Return<Result> setConnectedState_7_1(const AudioPort& devicePort,
-                                       bool connected) override;
-#endif
-
- private:
-#if MAJOR_VERSION >= 7
-  template<typename CallbackType>
-  Return<void> openOutputStreamImpl(int32_t ioHandle,
-                                    const DeviceAddress& device,
-                                    const AudioConfig& config,
-                                    const hidl_vec<AudioInOutFlag>& flags,
-                                    const SourceMetadata& sourceMetadata,
-                                    CallbackType _hidl_cb);
-#endif
-
-  BusStreamProvider& mBusStreamProvider;
-  const ServiceConfig& mServiceConfig;
-  std::set<AudioPatchHandle> mAudioPatchHandles;
-};
-
-}  // namespace service
-}  // namespace audio_proxy
diff --git a/audio_proxy/service/DevicesFactoryImpl.cpp b/audio_proxy/service/DevicesFactoryImpl.cpp
deleted file mode 100644
index c5575a5..0000000
--- a/audio_proxy/service/DevicesFactoryImpl.cpp
+++ /dev/null
@@ -1,71 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "DevicesFactoryImpl.h"
-
-#include <android-base/logging.h>
-
-using android::hardware::Void;
-using namespace android::hardware::audio::CPP_VERSION;
-
-namespace audio_proxy {
-namespace service {
-
-DevicesFactoryImpl::DevicesFactoryImpl(BusStreamProvider& busStreamProvider,
-                                       const ServiceConfig& config)
-    : mBusStreamProvider(busStreamProvider), mConfig(config) {}
-
-// Methods from android::hardware::audio::CPP_VERSION::IDevicesFactory follow.
-Return<void> DevicesFactoryImpl::openDevice(const hidl_string& device,
-                                            openDevice_cb _hidl_cb) {
-  if (device == mConfig.name) {
-    LOG(INFO) << "Audio Device was opened: " << device;
-    _hidl_cb(Result::OK, new DeviceImpl(mBusStreamProvider, mConfig));
-  } else {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr);
-  }
-
-  return Void();
-}
-
-Return<void> DevicesFactoryImpl::openPrimaryDevice(
-    openPrimaryDevice_cb _hidl_cb) {
-  // The AudioProxy HAL does not support a primary device.
-  _hidl_cb(Result::NOT_SUPPORTED, nullptr);
-  return Void();
-}
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-Return<void> DevicesFactoryImpl::openDevice_7_1(const hidl_string& device,
-                                                openDevice_7_1_cb _hidl_cb) {
-  if (device == mConfig.name) {
-    LOG(INFO) << "Audio Device was opened: " << device;
-    _hidl_cb(Result::OK, new DeviceImpl(mBusStreamProvider, mConfig));
-  } else {
-    _hidl_cb(Result::INVALID_ARGUMENTS, nullptr);
-  }
-
-  return Void();
-}
-
-Return<void> DevicesFactoryImpl::openPrimaryDevice_7_1(
-    openPrimaryDevice_7_1_cb _hidl_cb) {
-  // The AudioProxy HAL does not support a primary device.
-  _hidl_cb(Result::NOT_SUPPORTED, nullptr);
-  return Void();
-}
-#endif
-
-}  // namespace service
-}  // namespace audio_proxy
diff --git a/audio_proxy/service/DevicesFactoryImpl.h b/audio_proxy/service/DevicesFactoryImpl.h
deleted file mode 100644
index d9326eb..0000000
--- a/audio_proxy/service/DevicesFactoryImpl.h
+++ /dev/null
@@ -1,60 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-// clang-format off
-#include PATH(android/hardware/audio/FILE_VERSION/IDevicesFactory.h)
-// clang-format on
-
-#include "DeviceImpl.h"
-#include "ServiceConfig.h"
-
-namespace audio_proxy {
-namespace service {
-
-using android::hardware::Return;
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-using android::hardware::audio::V7_1::IDevicesFactory;
-#else
-using android::hardware::audio::CPP_VERSION::IDevicesFactory;
-#endif
-
-class BusStreamProvider;
-
-class DevicesFactoryImpl : public IDevicesFactory {
- public:
-  DevicesFactoryImpl(BusStreamProvider& busDeviceProvider,
-                     const ServiceConfig& config);
-
-  // Methods from android::hardware::audio::V5_0::IDevicesFactory follow.
-  Return<void> openDevice(const hidl_string& device,
-                          openDevice_cb _hidl_cb) override;
-  Return<void> openPrimaryDevice(openPrimaryDevice_cb _hidl_cb) override;
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-  Return<void> openDevice_7_1(const hidl_string& device,
-                              openDevice_7_1_cb _hidl_cb) override;
-  Return<void> openPrimaryDevice_7_1(
-      openPrimaryDevice_7_1_cb _hidl_cb) override;
-#endif
-
- private:
-  BusStreamProvider& mBusStreamProvider;
-  const ServiceConfig& mConfig;
-};
-
-}  // namespace service
-}  // namespace audio_proxy
diff --git a/audio_proxy/service/DummyBusOutputStream.cpp b/audio_proxy/service/DummyBusOutputStream.cpp
deleted file mode 100644
index 3b9b56e..0000000
--- a/audio_proxy/service/DummyBusOutputStream.cpp
+++ /dev/null
@@ -1,131 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "DummyBusOutputStream.h"
-
-#include <algorithm>
-
-#include <aidl/device/google/atv/audio_proxy/TimeSpec.h>
-#include <android-base/logging.h>
-#include <unistd.h>
-
-using aidl::device::google::atv::audio_proxy::TimeSpec;
-
-namespace audio_proxy::service {
-namespace {
-constexpr int64_t kOneSecInNs = 1'000'000'000;
-constexpr int64_t kOneSecInUs = 1'000'000;
-constexpr int64_t kOneUSecInNs = 1'000;
-
-int64_t timespecDelta(const timespec& newTime, const timespec& oldTime) {
-  int64_t deltaSec = 0;
-  int64_t deltaNSec = 0;
-  if (newTime.tv_nsec >= oldTime.tv_nsec) {
-    deltaSec = newTime.tv_sec - oldTime.tv_sec;
-    deltaNSec = newTime.tv_nsec - oldTime.tv_nsec;
-  } else {
-    deltaSec = newTime.tv_sec - oldTime.tv_sec - 1;
-    deltaNSec = kOneSecInNs + newTime.tv_nsec - oldTime.tv_nsec;
-  }
-
-  return deltaSec * kOneSecInUs + deltaNSec / kOneUSecInNs;
-}
-}  // namespace
-
-DummyBusOutputStream::DummyBusOutputStream(const std::string& address,
-                                           const AidlAudioConfig& config,
-                                           int32_t flags)
-    : BusOutputStream(address, config, flags) {}
-DummyBusOutputStream::~DummyBusOutputStream() = default;
-
-bool DummyBusOutputStream::standby() { return true; }
-bool DummyBusOutputStream::pause() { return true; }
-bool DummyBusOutputStream::resume() { return true; }
-bool DummyBusOutputStream::drain(AidlAudioDrain drain) { return true; }
-bool DummyBusOutputStream::flush() { return true; }
-bool DummyBusOutputStream::close() { return true; }
-bool DummyBusOutputStream::setVolume(float left, float right) { return true; }
-
-size_t DummyBusOutputStream::availableToWrite() {
-  return mWritingFrameSize * mWritingFrameCount;
-}
-
-AidlWriteStatus DummyBusOutputStream::writeRingBuffer(const uint8_t* firstMem,
-                                                      size_t firstLength,
-                                                      const uint8_t* secondMem,
-                                                      size_t secondLength) {
-  size_t bufferBytes = firstLength + secondLength;
-  int64_t numFrames = bufferBytes / getFrameSize();
-  int64_t durationUs = numFrames * kOneSecInUs / mConfig.sampleRateHz;
-
-  timespec now = {0, 0};
-  clock_gettime(CLOCK_MONOTONIC, &now);
-  if (mStartTime.tv_sec == 0) {
-    mStartTime = now;
-  }
-
-  // Check underrun
-  int64_t elapsedTimeUs = timespecDelta(now, mStartTime);
-  if (elapsedTimeUs > mInputUsSinceStart) {
-    // Underrun
-    mPlayedUsBeforeUnderrun += mInputUsSinceStart;
-    mStartTime = now;
-    mInputUsSinceStart = 0;
-  }
-
-  // Wait if buffer full.
-  mInputUsSinceStart += durationUs;
-  int64_t waitTimeUs = mInputUsSinceStart - elapsedTimeUs - mMaxBufferUs;
-  if (waitTimeUs > 0) {
-    usleep(waitTimeUs);
-    clock_gettime(CLOCK_MONOTONIC, &now);
-  }
-
-  // Calculate played frames.
-  int64_t playedUs =
-      mPlayedUsBeforeUnderrun +
-      std::min(timespecDelta(now, mStartTime), mInputUsSinceStart);
-
-  TimeSpec timeSpec = {now.tv_sec, now.tv_nsec};
-
-  AidlWriteStatus status;
-  status.written = bufferBytes;
-  status.position = {playedUs * mConfig.sampleRateHz / kOneSecInUs, timeSpec};
-
-  return status;
-}
-
-bool DummyBusOutputStream::prepareForWritingImpl(uint32_t frameSize,
-                                                 uint32_t frameCount) {
-  // The `frame` here is not audio frame, it doesn't count the sample format and
-  // channel layout.
-  mMaxBufferUs = frameSize * frameCount * 10 * kOneSecInUs /
-                 (mConfig.sampleRateHz * getFrameSize());
-  return true;
-}
-
-bool DummyBusOutputStream::start() { return false; }
-
-bool DummyBusOutputStream::stop() { return false; };
-
-AidlMmapBufferInfo DummyBusOutputStream::createMmapBuffer(
-    int32_t minBufferSizeFrames) {
-  return AidlMmapBufferInfo();
-}
-
-AidlPresentationPosition DummyBusOutputStream::getMmapPosition() {
-  return AidlPresentationPosition();
-}
-
-}  // namespace audio_proxy::service
diff --git a/audio_proxy/service/DummyBusOutputStream.h b/audio_proxy/service/DummyBusOutputStream.h
deleted file mode 100644
index 0cb8e44..0000000
--- a/audio_proxy/service/DummyBusOutputStream.h
+++ /dev/null
@@ -1,66 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include "BusOutputStream.h"
-
-#include <time.h>
-
-namespace audio_proxy::service {
-
-// Impl of BusOutputStream which has a small buffer and consumes the audio data
-// in real time.
-class DummyBusOutputStream : public BusOutputStream {
- public:
-  DummyBusOutputStream(const std::string& address,
-                       const AidlAudioConfig& config, int32_t flags);
-  ~DummyBusOutputStream() override;
-
-  bool standby() override;
-  bool pause() override;
-  bool resume() override;
-  bool drain(AidlAudioDrain drain) override;
-  bool flush() override;
-  bool close() override;
-  bool setVolume(float left, float right) override;
-
-  size_t availableToWrite() override;
-  AidlWriteStatus writeRingBuffer(const uint8_t* firstMem, size_t firstLength,
-                                  const uint8_t* secondMem,
-                                  size_t secondLength) override;
-
-  bool start() override;
-  bool stop() override;
-  AidlMmapBufferInfo createMmapBuffer(int32_t minBufferSizeFrames) override;
-  AidlPresentationPosition getMmapPosition() override;
-
- protected:
-  bool prepareForWritingImpl(uint32_t frameSize, uint32_t frameCount) override;
-
- private:
-  // Buffer capacity.
-  int64_t mMaxBufferUs = 0;
-
-  // Timestamp for the first played frame. Underrun will reset it.
-  timespec mStartTime = {0, 0};
-
-  // Total written buffer size in us after `mStartTime` reset.
-  int64_t mInputUsSinceStart = 0;
-
-  // Total played buffer size in us before underrun.
-  int64_t mPlayedUsBeforeUnderrun = 0;
-};
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/RemoteBusOutputStream.cpp b/audio_proxy/service/RemoteBusOutputStream.cpp
deleted file mode 100644
index 177cb55..0000000
--- a/audio_proxy/service/RemoteBusOutputStream.cpp
+++ /dev/null
@@ -1,179 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "RemoteBusOutputStream.h"
-
-#include <aidl/device/google/atv/audio_proxy/MessageQueueFlag.h>
-#include <android-base/logging.h>
-
-#include "RingBufferUtil.h"
-
-using aidl::device::google::atv::audio_proxy::MessageQueueFlag;
-using android::status_t;
-
-namespace audio_proxy {
-namespace service {
-namespace {
-
-// Time out for FMQ read in ns -- 1s.
-constexpr int64_t kFmqReadTimeoutNs = 1'000'000'000;
-
-void deleteEventFlag(EventFlag* obj) {
-  if (!obj) {
-    return;
-  }
-
-  status_t status = EventFlag::deleteEventFlag(&obj);
-  if (status != android::OK) {
-    LOG(ERROR) << "write MQ event flag deletion error: " << strerror(-status);
-  }
-}
-
-}  // namespace
-
-RemoteBusOutputStream::RemoteBusOutputStream(
-    std::shared_ptr<IOutputStream> stream, const std::string& address,
-    const AidlAudioConfig& config, int32_t flags)
-    : BusOutputStream(address, config, flags),
-      mStream(std::move(stream)),
-      mEventFlag(nullptr, deleteEventFlag) {}
-RemoteBusOutputStream::~RemoteBusOutputStream() = default;
-
-bool RemoteBusOutputStream::standby() { return mStream->standby().isOk(); }
-
-bool RemoteBusOutputStream::pause() { return mStream->pause().isOk(); }
-
-bool RemoteBusOutputStream::resume() { return mStream->resume().isOk(); }
-
-bool RemoteBusOutputStream::drain(AidlAudioDrain drain) {
-  return mStream->drain(drain).isOk();
-}
-
-bool RemoteBusOutputStream::flush() { return mStream->flush().isOk(); }
-
-bool RemoteBusOutputStream::close() { return mStream->close().isOk(); }
-
-bool RemoteBusOutputStream::setVolume(float left, float right) {
-  return mStream->setVolume(left, right).isOk();
-}
-
-size_t RemoteBusOutputStream::availableToWrite() {
-  return mDataMQ->availableToWrite();
-}
-
-AidlWriteStatus RemoteBusOutputStream::writeRingBuffer(const uint8_t* firstMem,
-                                                       size_t firstLength,
-                                                       const uint8_t* secondMem,
-                                                       size_t secondLength) {
-  DCHECK(mDataMQ);
-  DCHECK(mStatusMQ);
-  DCHECK(mEventFlag);
-  AidlWriteStatus status;
-  DataMQ::MemTransaction tx;
-  if (!mDataMQ->beginWrite(firstLength + secondLength, &tx)) {
-    LOG(ERROR) << "Failed to begin write.";
-    return status;
-  }
-
-  const DataMQ::MemRegion& firstRegion = tx.getFirstRegion();
-  const DataMQ::MemRegion& secondRegion = tx.getSecondRegion();
-
-  copyRingBuffer(firstRegion.getAddress(), firstRegion.getLength(),
-                 secondRegion.getAddress(), secondRegion.getLength(),
-                 reinterpret_cast<const int8_t*>(firstMem), firstLength,
-                 reinterpret_cast<const int8_t*>(secondMem), secondLength);
-  if (!mDataMQ->commitWrite(firstLength + secondLength)) {
-    LOG(ERROR) << "Failed to commit write.";
-    return status;
-  }
-
-  mEventFlag->wake(static_cast<uint32_t>(MessageQueueFlag::NOT_EMPTY));
-
-  // readNotification is used to "wake" after successful read, hence we don't
-  // need it. writeNotification is used to "wait" for the other end to write
-  // enough data.
-  // It's fine to use readBlocking here because:
-  // 1. We don't wake without writing mStatusMQ.
-  // 2. The other end will always write mStatusMQ before wake mEventFlag.
-  if (!mStatusMQ->readBlocking(
-          &status, 1 /* count */, 0 /* readNotification */,
-          static_cast<uint32_t>(
-              MessageQueueFlag::NOT_FULL) /* writeNotification */,
-          kFmqReadTimeoutNs, mEventFlag.get())) {
-    LOG(ERROR) << "Failed to read status!";
-    return status;
-  }
-
-  return status;
-}
-
-bool RemoteBusOutputStream::prepareForWritingImpl(uint32_t frameSize,
-                                                  uint32_t frameCount) {
-  DataMQDesc dataMQDesc;
-  StatusMQDesc statusMQDesc;
-  ndk::ScopedAStatus status = mStream->prepareForWriting(
-      frameSize, frameCount, &dataMQDesc, &statusMQDesc);
-  if (!status.isOk()) {
-    LOG(ERROR) << "prepareForWriting fails.";
-    return false;
-  }
-
-  auto dataMQ = std::make_unique<DataMQ>(dataMQDesc);
-  if (!dataMQ->isValid()) {
-    LOG(ERROR) << "invalid data mq.";
-    return false;
-  }
-
-  EventFlag* rawEventFlag = nullptr;
-  status_t eventFlagStatus =
-      EventFlag::createEventFlag(dataMQ->getEventFlagWord(), &rawEventFlag);
-  std::unique_ptr<EventFlag, EventFlagDeleter> eventFlag(rawEventFlag,
-                                                         deleteEventFlag);
-  if (eventFlagStatus != android::OK || !eventFlag) {
-    LOG(ERROR) << "failed creating event flag for data MQ: "
-               << strerror(-eventFlagStatus);
-    return false;
-  }
-
-  auto statusMQ = std::make_unique<StatusMQ>(statusMQDesc);
-  if (!statusMQ->isValid()) {
-    LOG(ERROR) << "invalid status mq.";
-    return false;
-  }
-
-  mDataMQ = std::move(dataMQ);
-  mStatusMQ = std::move(statusMQ);
-  mEventFlag = std::move(eventFlag);
-  return true;
-}
-
-bool RemoteBusOutputStream::start() { return mStream->start().isOk(); }
-
-bool RemoteBusOutputStream::stop() { return mStream->stop().isOk(); };
-
-AidlMmapBufferInfo RemoteBusOutputStream::createMmapBuffer(
-    int32_t minBufferSizeFrames) {
-  AidlMmapBufferInfo info;
-  mStream->createMmapBuffer(minBufferSizeFrames, &info);
-  return info;
-}
-
-AidlPresentationPosition RemoteBusOutputStream::getMmapPosition() {
-  AidlPresentationPosition position;
-  mStream->getMmapPosition(&position);
-  return position;
-}
-
-}  // namespace service
-}  // namespace audio_proxy
\ No newline at end of file
diff --git a/audio_proxy/service/RemoteBusOutputStream.h b/audio_proxy/service/RemoteBusOutputStream.h
deleted file mode 100644
index cb7de19..0000000
--- a/audio_proxy/service/RemoteBusOutputStream.h
+++ /dev/null
@@ -1,76 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <aidl/device/google/atv/audio_proxy/IOutputStream.h>
-#include <fmq/AidlMessageQueue.h>
-#include <fmq/EventFlag.h>
-
-#include "BusOutputStream.h"
-
-namespace audio_proxy {
-namespace service {
-
-using aidl::android::hardware::common::fmq::MQDescriptor;
-using aidl::android::hardware::common::fmq::SynchronizedReadWrite;
-using aidl::device::google::atv::audio_proxy::IOutputStream;
-using android::AidlMessageQueue;
-using android::hardware::EventFlag;
-
-class RemoteBusOutputStream : public BusOutputStream {
- public:
-  RemoteBusOutputStream(std::shared_ptr<IOutputStream> stream,
-                        const std::string& address,
-                        const AidlAudioConfig& config, int32_t flags);
-  ~RemoteBusOutputStream() override;
-
-  bool standby() override;
-  bool pause() override;
-  bool resume() override;
-  bool drain(AidlAudioDrain drain) override;
-  bool flush() override;
-  bool close() override;
-  bool setVolume(float left, float right) override;
-
-  size_t availableToWrite() override;
-  AidlWriteStatus writeRingBuffer(const uint8_t* firstMem, size_t firstLength,
-                                  const uint8_t* secondMem,
-                                  size_t secondLength) override;
-
-  bool start() override;
-  bool stop() override;
-  AidlMmapBufferInfo createMmapBuffer(int32_t minBufferSizeFrames) override;
-  AidlPresentationPosition getMmapPosition() override;
-
- protected:
-  bool prepareForWritingImpl(uint32_t frameSize, uint32_t frameCount) override;
-
- private:
-  using DataMQ = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
-  using DataMQDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;
-  using StatusMQ = AidlMessageQueue<AidlWriteStatus, SynchronizedReadWrite>;
-  using StatusMQDesc = MQDescriptor<AidlWriteStatus, SynchronizedReadWrite>;
-
-  typedef void (*EventFlagDeleter)(EventFlag*);
-
-  std::shared_ptr<IOutputStream> mStream;
-
-  std::unique_ptr<DataMQ> mDataMQ;
-  std::unique_ptr<StatusMQ> mStatusMQ;
-  std::unique_ptr<EventFlag, EventFlagDeleter> mEventFlag;
-};
-
-}  // namespace service
-}  // namespace audio_proxy
\ No newline at end of file
diff --git a/audio_proxy/service/RingBufferUtil.cpp b/audio_proxy/service/RingBufferUtil.cpp
deleted file mode 100644
index dbe80f4..0000000
--- a/audio_proxy/service/RingBufferUtil.cpp
+++ /dev/null
@@ -1,83 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "RingBufferUtil.h"
-
-#include <android-base/logging.h>
-
-namespace audio_proxy::service {
-namespace {
-struct CopyDesc {
-  int8_t* dst = nullptr;
-  const int8_t* src = nullptr;
-  size_t len = 0;
-};
-}  // namespace
-
-void copyRingBuffer(int8_t* dstBuf1, size_t dstLen1, int8_t* dstBuf2,
-                    size_t dstLen2, const int8_t* srcBuf1, size_t srcLen1,
-                    const int8_t* srcBuf2, size_t srcLen2) {
-  // Caller should make sure the dst buffer has more space.
-  DCHECK_GE(dstLen1 + dstLen2, srcLen1 + srcLen2);
-
-  CopyDesc cp1 = {dstBuf1, srcBuf1, 0};
-  CopyDesc cp2;
-  CopyDesc cp3;
-
-  if (srcLen1 == dstLen1) {
-    cp1 = {dstBuf1, srcBuf1, srcLen1};
-
-    DCHECK_LE(srcLen2, dstLen2);
-    cp2 = {dstBuf2, srcBuf2, srcLen2};
-
-    // No need to copy more data, thus no need to update cp3.
-  } else if (srcLen1 < dstLen1) {
-    cp1 = {dstBuf1, srcBuf1, srcLen1};
-
-    if (dstLen1 <= srcLen1 + srcLen2) {
-      // Copy data into both dstBuf1 and dstBuf2.
-      cp2 = {cp1.dst + cp1.len, srcBuf2, dstLen1 - srcLen1};
-      cp3 = {dstBuf2, cp2.src + cp2.len, srcLen1 + srcLen2 - dstLen1};
-    } else {
-      // dstBuf1 is bigger enough to hold all the data from src.
-      cp2 = {cp1.dst + cp1.len, srcBuf2, srcLen2};
-
-      // No need to copy more data, thus no need to update cp3.
-    }
-  } else {  // srcLen1 > dstLen1
-    cp1 = {dstBuf1, srcBuf1, dstLen1};
-    cp2 = {dstBuf2, cp1.src + cp1.len, srcLen1 - dstLen1};
-    cp3 = {cp2.dst + cp2.len, srcBuf2, srcLen2};
-  }
-
-  if (cp1.len > 0) {
-    DCHECK(cp1.dst);
-    DCHECK(cp1.src);
-    std::memcpy(cp1.dst, cp1.src, cp1.len);
-  }
-
-  if (cp2.len > 0) {
-    DCHECK(cp2.dst);
-    DCHECK(cp2.src);
-    std::memcpy(cp2.dst, cp2.src, cp2.len);
-  }
-
-  if (cp3.len > 0) {
-    DCHECK(cp3.dst);
-    DCHECK(cp3.src);
-    std::memcpy(cp3.dst, cp3.src, cp3.len);
-  }
-}
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/RingBufferUtil.h b/audio_proxy/service/RingBufferUtil.h
deleted file mode 100644
index a37f03e..0000000
--- a/audio_proxy/service/RingBufferUtil.h
+++ /dev/null
@@ -1,28 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <stddef.h>
-#include <stdint.h>
-
-namespace audio_proxy::service {
-
-// Copy data from ring buffer "src" to ring buffer "dst". "dst" is guaranteed to
-// have more space than "src".
-void copyRingBuffer(int8_t* dstBuf1, size_t dstLen1, int8_t* dstBuf2,
-                    size_t dstLen2, const int8_t* srcBuf1, size_t srcLen1,
-                    const int8_t* srcBuf2, size_t srcLen2);
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/RingBufferUtilTest.cpp b/audio_proxy/service/RingBufferUtilTest.cpp
deleted file mode 100644
index 59b431c..0000000
--- a/audio_proxy/service/RingBufferUtilTest.cpp
+++ /dev/null
@@ -1,80 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include <gtest/gtest.h>
-
-#include "RingBufferUtil.h"
-
-using namespace audio_proxy::service;
-
-using Buffer = std::vector<int8_t>;
-
-class RingBufferUtilTest : public testing::TestWithParam<
-                               std::tuple<Buffer, Buffer, Buffer, Buffer>> {};
-
-TEST_P(RingBufferUtilTest, DifferentBufferSize) {
-  auto [src1, src2, expectedDst1, expectedDst2] = GetParam();
-
-  Buffer dst1(expectedDst1.size());
-  Buffer dst2(expectedDst2.size());
-
-  copyRingBuffer(dst1.data(), dst1.size(), dst2.data(), dst2.size(),
-                 src1.data(), src1.size(), src2.data(), src2.size());
-
-  EXPECT_EQ(dst1, expectedDst1);
-  EXPECT_EQ(dst2, expectedDst2);
-}
-
-// clang-format off
-const std::vector<std::tuple<Buffer, Buffer, Buffer, Buffer>> testParams = {
-  // The layout are the same for src and dst.
-  {
-    {0, 1, 2, 3, 4},
-    {5, 6, 7, 8, 9},
-    {0, 1, 2, 3, 4},
-    {5, 6, 7, 8, 9}
-  },
-  // src1 size is samller than dst1 size.
-  {
-    {0, 1, 2, 3},
-    {4, 5, 6, 7, 8, 9},
-    {0, 1, 2, 3, 4},
-    {5, 6, 7, 8, 9}
-  },
-  // src2 size is larger than dst1 size.
-  {
-    {0, 1, 2, 3, 4, 5},
-    {6, 7, 8, 9},
-    {0, 1, 2, 3, 4},
-    {5, 6, 7, 8, 9}
-  },
-  // dst1 size is larger enough to hold all the src data.
-  {
-    {0, 1, 2, 3, 4},
-    {5, 6, 7, 8, 9},
-    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0},
-    {0, 0, 0, 0, 0}
-  },
-  // Empty src
-  {{}, {}, {}, {}}
-};
-// clang-format off
-
-INSTANTIATE_TEST_SUITE_P(RingBufferUtilTestSuite, RingBufferUtilTest,
-                         testing::ValuesIn(testParams));
-
-TEST(RingBufferUtilTest, CopyNullptr) {
-  // Test should not crash.
-  copyRingBuffer(nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0);
-}
diff --git a/audio_proxy/service/ServiceConfig.cpp b/audio_proxy/service/ServiceConfig.cpp
deleted file mode 100644
index 61f40aa..0000000
--- a/audio_proxy/service/ServiceConfig.cpp
+++ /dev/null
@@ -1,94 +0,0 @@
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "ServiceConfig.h"
-
-#include <android-base/parseint.h>
-#include <android-base/strings.h>
-#include <getopt.h>
-
-#include <utility>
-#include <vector>
-
-namespace audio_proxy::service {
-namespace {
-std::pair<std::string, StreamConfig> parseStreamConfig(const char* optarg) {
-  std::vector<std::string> tokens = android::base::Split(optarg, ":");
-  if (tokens.size() != 3) {
-    return {};
-  }
-
-  StreamConfig config;
-  if (!android::base::ParseUint(tokens[1].c_str(), &config.bufferSizeMs)) {
-    return {};
-  }
-
-  if (!android::base::ParseUint(tokens[2].c_str(), &config.latencyMs)) {
-    return {};
-  }
-
-  return {tokens[0], config};
-}
-}  // namespace
-
-std::optional<ServiceConfig> parseServiceConfigFromCommandLine(int argc,
-                                                               char** argv) {
-  // $command --name service_name
-  //   --stream address1:buffer_size:latency
-  //   --stream address2:buffer_size:latency
-  static option options[] = {
-      {"name", required_argument, nullptr, 'n'},
-      {"stream", required_argument, nullptr, 's'},
-      {nullptr, 0, nullptr, 0},
-  };
-
-  // Reset, this is useful in unittest.
-  optind = 0;
-
-  ServiceConfig config;
-  int val = 0;
-  while ((val = getopt_long(argc, argv, "n:s:", options, nullptr)) != -1) {
-    switch (val) {
-      case 'n':
-        config.name = optarg;
-        break;
-
-      case 's': {
-        std::pair<std::string, StreamConfig> streamConfig =
-            parseStreamConfig(optarg);
-        if (streamConfig.first.empty()) {
-          return std::nullopt;
-        }
-
-        auto it = config.streams.emplace(std::move(streamConfig));
-        if (!it.second) {
-          return std::nullopt;
-        }
-
-        break;
-      }
-
-      default:
-        break;
-    }
-  }
-
-  if (config.name.empty() || config.streams.empty()) {
-    return std::nullopt;
-  }
-
-  return config;
-}
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/ServiceConfig.h b/audio_proxy/service/ServiceConfig.h
deleted file mode 100644
index f3de742..0000000
--- a/audio_proxy/service/ServiceConfig.h
+++ /dev/null
@@ -1,47 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <stdint.h>
-
-#include <map>
-#include <optional>
-#include <string>
-
-namespace audio_proxy::service {
-
-struct StreamConfig {
-  // Buffer size in milliseconds, as defined by IStream::getBufferSize.
-  uint32_t bufferSizeMs;
-
-  // Latency in milliseconds, as defined by IStreamOut::getLatency.
-  uint32_t latencyMs;
-};
-
-// Global configurations for the audio HAL service and AudioProxy service.
-struct ServiceConfig {
-  // Name of the service. It will be used to identify the audio HAL service and
-  // AudioProxy service.
-  std::string name;
-
-  // Supported stream configs. Key is the address of the stream. Value is the
-  // config.
-  std::map<std::string, StreamConfig> streams;
-};
-
-std::optional<ServiceConfig> parseServiceConfigFromCommandLine(int argc,
-                                                               char** argv);
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/ServiceConfigTest.cpp b/audio_proxy/service/ServiceConfigTest.cpp
deleted file mode 100644
index e796464..0000000
--- a/audio_proxy/service/ServiceConfigTest.cpp
+++ /dev/null
@@ -1,61 +0,0 @@
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include <gtest/gtest.h>
-
-#include "ServiceConfig.h"
-
-using namespace audio_proxy::service;
-
-TEST(ServiceConfigTest, GoodConfig) {
-  char* argv[] = {"command", "--name", "service", "--stream", "A:1:2"};
-  auto config =
-      parseServiceConfigFromCommandLine(sizeof(argv) / sizeof(argv[0]), argv);
-
-  ASSERT_TRUE(config);
-  EXPECT_EQ(config->name, "service");
-  EXPECT_EQ(config->streams.size(), 1);
-  EXPECT_EQ(config->streams.begin()->first, "A");
-  EXPECT_EQ(config->streams.begin()->second.bufferSizeMs, 1u);
-  EXPECT_EQ(config->streams.begin()->second.latencyMs, 2u);
-}
-
-TEST(ServiceConfigTest, MultipleStreams) {
-  char* argv[] = {"command", "--name",   "service", "--stream",
-                  "A:1:2",   "--stream", "B:3:4"};
-  auto config =
-      parseServiceConfigFromCommandLine(sizeof(argv) / sizeof(argv[0]), argv);
-
-  ASSERT_TRUE(config);
-  EXPECT_EQ(config->name, "service");
-  EXPECT_EQ(config->streams.size(), 2);
-
-  ASSERT_TRUE(config->streams.count("A"));
-  const auto& streamA = config->streams["A"];
-  EXPECT_EQ(streamA.bufferSizeMs, 1u);
-  EXPECT_EQ(streamA.latencyMs, 2u);
-
-  ASSERT_TRUE(config->streams.count("B"));
-  const auto& streamB = config->streams["B"];
-  EXPECT_EQ(streamB.bufferSizeMs, 3u);
-  EXPECT_EQ(streamB.latencyMs, 4u);
-}
-
-TEST(ServiceConfigTest, NoStreamConfig) {
-  char* argv[] = {"command", "--name", "service"};
-  auto config =
-      parseServiceConfigFromCommandLine(sizeof(argv) / sizeof(argv[0]), argv);
-
-  EXPECT_FALSE(config);
-}
diff --git a/audio_proxy/service/StreamOutImpl.cpp b/audio_proxy/service/StreamOutImpl.cpp
deleted file mode 100644
index 5e4a772..0000000
--- a/audio_proxy/service/StreamOutImpl.cpp
+++ /dev/null
@@ -1,602 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "StreamOutImpl.h"
-
-#include <android-base/logging.h>
-#include <inttypes.h>
-#include <math.h>
-#include <system/audio-hal-enums.h>
-#include <time.h>
-#include <utils/Log.h>
-
-#include <cstring>
-
-#include "AidlTypes.h"
-#include "BusOutputStream.h"
-#include "WriteThread.h"
-
-using android::status_t;
-using android::hardware::hidl_memory;
-
-namespace audio_proxy::service {
-
-namespace {
-
-// 1GB
-constexpr uint32_t kMaxBufferSize = 1 << 30;
-
-constexpr int64_t kOneSecInNs = 1'000'000'000;
-
-void deleteEventFlag(EventFlag* obj) {
-  if (!obj) {
-    return;
-  }
-
-  status_t status = EventFlag::deleteEventFlag(&obj);
-  if (status) {
-    LOG(ERROR) << "Write MQ event flag deletion error: " << strerror(-status);
-  }
-}
-
-uint64_t estimatePlayedFramesSince(const TimeSpec& timestamp,
-                                   uint32_t sampleRateHz) {
-  timespec now = {0, 0};
-  clock_gettime(CLOCK_MONOTONIC, &now);
-  int64_t deltaSec = 0;
-  int64_t deltaNSec = 0;
-  if (now.tv_nsec >= timestamp.tvNSec) {
-    deltaSec = now.tv_sec - timestamp.tvSec;
-    deltaNSec = now.tv_nsec - timestamp.tvNSec;
-  } else {
-    deltaSec = now.tv_sec - timestamp.tvSec - 1;
-    deltaNSec = kOneSecInNs + now.tv_nsec - timestamp.tvNSec;
-  }
-
-  if (deltaSec < 0 || deltaNSec < 0) {
-    return 0;
-  }
-
-  return deltaSec * sampleRateHz + deltaNSec * sampleRateHz / kOneSecInNs;
-}
-
-}  // namespace
-
-StreamOutImpl::StreamOutImpl(std::shared_ptr<BusOutputStream> stream,
-                             const StreamOutConfig& config)
-    : mStream(std::move(stream)),
-      mConfig(config),
-      mBufferSizeBytes(mStream->getConfig().bufferSizeBytes),
-      mLatencyMs(mStream->getConfig().latencyMs),
-      mEventFlag(nullptr, deleteEventFlag) {}
-
-StreamOutImpl::~StreamOutImpl() {
-  if (mWriteThread) {
-    mWriteThread->stop();
-    status_t status = mWriteThread->join();
-    if (status) {
-      LOG(ERROR) << "write thread exit error " << strerror(-status);
-    }
-  }
-
-  mEventFlag.reset();
-}
-
-Return<uint64_t> StreamOutImpl::getFrameSize() {
-  return mStream->getFrameSize();
-}
-
-Return<uint64_t> StreamOutImpl::getFrameCount() {
-  return mBufferSizeBytes / mStream->getFrameSize();
-}
-
-Return<uint64_t> StreamOutImpl::getBufferSize() { return mBufferSizeBytes; }
-
-#if MAJOR_VERSION >= 7
-Return<void> StreamOutImpl::getSupportedProfiles(
-    getSupportedProfiles_cb _hidl_cb) {
-  // For devices with fixed configuration, this method can return NOT_SUPPORTED.
-  _hidl_cb(Result::NOT_SUPPORTED, {});
-  return Void();
-}
-
-Return<void> StreamOutImpl::getAudioProperties(getAudioProperties_cb _hidl_cb) {
-  _hidl_cb(Result::OK, mConfig);
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setAudioProperties(
-    const AudioConfigBaseOptional& config) {
-  return Result::NOT_SUPPORTED;
-}
-#else
-Return<uint32_t> StreamOutImpl::getSampleRate() { return mConfig.sampleRateHz; }
-
-Return<void> StreamOutImpl::getSupportedSampleRates(
-    AudioFormat format, getSupportedSampleRates_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, {});
-  return Void();
-}
-
-Return<void> StreamOutImpl::getSupportedChannelMasks(
-    AudioFormat format, getSupportedChannelMasks_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, {});
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setSampleRate(uint32_t sampleRateHz) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<hidl_bitfield<AudioChannelMask>> StreamOutImpl::getChannelMask() {
-  return mConfig.channelMask;
-}
-
-Return<Result> StreamOutImpl::setChannelMask(
-    hidl_bitfield<AudioChannelMask> mask) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<AudioFormat> StreamOutImpl::getFormat() { return mConfig.format; }
-
-Return<void> StreamOutImpl::getSupportedFormats(
-    getSupportedFormats_cb _hidl_cb) {
-#if MAJOR_VERSION >= 6
-  _hidl_cb(Result::NOT_SUPPORTED, {});
-#else
-  _hidl_cb({});
-#endif
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setFormat(AudioFormat format) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> StreamOutImpl::getAudioProperties(getAudioProperties_cb _hidl_cb) {
-  _hidl_cb(mConfig.sampleRateHz, mConfig.channelMask, mConfig.format);
-  return Void();
-}
-#endif
-
-// We don't support effects. So any effectId is invalid.
-Return<Result> StreamOutImpl::addEffect(uint64_t effectId) {
-  return Result::INVALID_ARGUMENTS;
-}
-
-Return<Result> StreamOutImpl::removeEffect(uint64_t effectId) {
-  return Result::INVALID_ARGUMENTS;
-}
-
-Return<Result> StreamOutImpl::standby() {
-  bool success = mStream->standby();
-  if (!success) {
-    return Result::INVALID_STATE;
-  }
-
-  mTotalPlayedFramesSinceStandby = estimateTotalPlayedFrames();
-  return Result::OK;
-}
-
-Return<void> StreamOutImpl::getDevices(getDevices_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, {});
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setDevices(
-    const hidl_vec<DeviceAddress>& devices) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> StreamOutImpl::getParameters(
-    const hidl_vec<ParameterValue>& context, const hidl_vec<hidl_string>& keys,
-    getParameters_cb _hidl_cb) {
-  _hidl_cb(keys.size() > 0 ? Result::NOT_SUPPORTED : Result::OK, {});
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setParameters(
-    const hidl_vec<ParameterValue>& context,
-    const hidl_vec<ParameterValue>& parameters) {
-  return Result::OK;
-}
-
-Return<Result> StreamOutImpl::setHwAvSync(uint32_t hwAvSync) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<Result> StreamOutImpl::close() {
-  if (!mStream) {
-    return Result::INVALID_STATE;
-  }
-
-  if (mWriteThread) {
-    mWriteThread->stop();
-  }
-
-  if (!mStream->close()) {
-    LOG(WARNING) << "Failed to close stream.";
-  }
-
-  mStream = nullptr;
-
-  return Result::OK;
-}
-
-Return<uint32_t> StreamOutImpl::getLatency() { return mLatencyMs; }
-
-Return<Result> StreamOutImpl::setVolume(float left, float right) {
-  if (isnan(left) || left < 0.f || left > 1.f || isnan(right) || right < 0.f ||
-      right > 1.f) {
-    return Result::INVALID_ARGUMENTS;
-  }
-  return mStream->setVolume(left, right) ? Result::OK : Result::INVALID_STATE;
-}
-
-Return<void> StreamOutImpl::prepareForWriting(uint32_t frameSize,
-                                              uint32_t framesCount,
-                                              prepareForWriting_cb _hidl_cb) {
-#if MAJOR_VERSION >= 7
-  int32_t threadInfo = 0;
-#else
-  ThreadInfo threadInfo = {0, 0};
-#endif
-
-  // Wrap the _hidl_cb to return an error
-  auto sendError = [&threadInfo, &_hidl_cb](Result result) -> Return<void> {
-    _hidl_cb(result, CommandMQ::Descriptor(), DataMQ::Descriptor(),
-             StatusMQ::Descriptor(), threadInfo);
-    return Void();
-  };
-
-  if (mDataMQ) {
-    LOG(ERROR) << "The client attempted to call prepareForWriting twice";
-    return sendError(Result::INVALID_STATE);
-  }
-
-  if (frameSize == 0 || framesCount == 0) {
-    LOG(ERROR) << "Invalid frameSize (" << frameSize << ") or framesCount ("
-               << framesCount << ")";
-    return sendError(Result::INVALID_ARGUMENTS);
-  }
-
-  if (frameSize > kMaxBufferSize / framesCount) {
-    LOG(ERROR) << "Buffer too big: " << frameSize << "*" << framesCount
-               << " bytes > MAX_BUFFER_SIZE (" << kMaxBufferSize << ")";
-    return sendError(Result::INVALID_ARGUMENTS);
-  }
-
-  auto commandMQ = std::make_unique<CommandMQ>(1);
-  if (!commandMQ->isValid()) {
-    LOG(ERROR) << "Command MQ is invalid";
-    return sendError(Result::INVALID_ARGUMENTS);
-  }
-
-  auto dataMQ =
-      std::make_unique<DataMQ>(frameSize * framesCount, true /* EventFlag */);
-  if (!dataMQ->isValid()) {
-    LOG(ERROR) << "Data MQ is invalid";
-    return sendError(Result::INVALID_ARGUMENTS);
-  }
-
-  auto statusMQ = std::make_unique<StatusMQ>(1);
-  if (!statusMQ->isValid()) {
-    LOG(ERROR) << "Status MQ is invalid";
-    return sendError(Result::INVALID_ARGUMENTS);
-  }
-
-  EventFlag* rawEventFlag = nullptr;
-  status_t status =
-      EventFlag::createEventFlag(dataMQ->getEventFlagWord(), &rawEventFlag);
-  std::unique_ptr<EventFlag, EventFlagDeleter> eventFlag(rawEventFlag,
-                                                         deleteEventFlag);
-  if (status != ::android::OK || !eventFlag) {
-    LOG(ERROR) << "Failed creating event flag for data MQ: "
-               << strerror(-status);
-    return sendError(Result::INVALID_ARGUMENTS);
-  }
-
-  if (!mStream->prepareForWriting(frameSize, framesCount)) {
-    LOG(ERROR) << "Failed to prepare writing channel.";
-    return sendError(Result::INVALID_ARGUMENTS);
-  }
-
-  sp<WriteThread> writeThread =
-      sp<WriteThread>::make(mStream, commandMQ.get(), dataMQ.get(),
-                            statusMQ.get(), eventFlag.get(), mLatencyMs);
-  status = writeThread->run("writer", ::android::PRIORITY_URGENT_AUDIO);
-  if (status != ::android::OK) {
-    LOG(ERROR) << "Failed to start writer thread: " << strerror(-status);
-    return sendError(Result::INVALID_ARGUMENTS);
-  }
-
-  mCommandMQ = std::move(commandMQ);
-  mDataMQ = std::move(dataMQ);
-  mStatusMQ = std::move(statusMQ);
-  mEventFlag = std::move(eventFlag);
-  mWriteThread = std::move(writeThread);
-
-#if MAJOR_VERSION >= 7
-  threadInfo = mWriteThread->getTid();
-#else
-  threadInfo.pid = getpid();
-  threadInfo.tid = mWriteThread->getTid();
-#endif
-
-  _hidl_cb(Result::OK, *mCommandMQ->getDesc(), *mDataMQ->getDesc(),
-           *mStatusMQ->getDesc(), threadInfo);
-
-  return Void();
-}
-
-Return<void> StreamOutImpl::getRenderPosition(getRenderPosition_cb _hidl_cb) {
-  uint64_t totalPlayedFrames = estimateTotalPlayedFrames();
-  if (totalPlayedFrames == 0) {
-    _hidl_cb(Result::OK, 0);
-    return Void();
-  }
-
-  // getRenderPosition returns the number of frames played since the output has
-  // exited standby.
-  DCHECK_GE(totalPlayedFrames, mTotalPlayedFramesSinceStandby);
-  uint64_t position = totalPlayedFrames - mTotalPlayedFramesSinceStandby;
-
-  if (position > std::numeric_limits<uint32_t>::max()) {
-    _hidl_cb(Result::INVALID_STATE, 0);
-    return Void();
-  }
-
-  _hidl_cb(Result::OK, position);
-  return Void();
-}
-
-Return<void> StreamOutImpl::getNextWriteTimestamp(
-    getNextWriteTimestamp_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, 0);
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setCallback(
-    const sp<IStreamOutCallback>& callback) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<Result> StreamOutImpl::clearCallback() { return Result::NOT_SUPPORTED; }
-
-Return<void> StreamOutImpl::supportsPauseAndResume(
-    supportsPauseAndResume_cb _hidl_cb) {
-  _hidl_cb(true, true);
-  return Void();
-}
-
-// pause should not be called before starting the playback.
-Return<Result> StreamOutImpl::pause() {
-  if (!mWriteThread) {
-    return Result::INVALID_STATE;
-  }
-
-  if (!mStream->pause()) {
-    return Result::INVALID_STATE;
-  }
-
-  mIsPaused = true;
-  return Result::OK;
-}
-
-// Resume should onl be called after pause.
-Return<Result> StreamOutImpl::resume() {
-  if (!mIsPaused) {
-    return Result::INVALID_STATE;
-  }
-
-  if (!mStream->resume()) {
-    return Result::INVALID_STATE;
-  }
-
-  mIsPaused = false;
-  return Result::OK;
-}
-
-// Drain and flush should always succeed if supported.
-Return<bool> StreamOutImpl::supportsDrain() { return true; }
-
-Return<Result> StreamOutImpl::drain(AudioDrain type) {
-  if (!mStream->drain(static_cast<AidlAudioDrain>(type))) {
-    LOG(WARNING) << "Failed to drain the stream.";
-  }
-
-  return Result::OK;
-}
-
-Return<Result> StreamOutImpl::flush() {
-  if (!mStream->flush()) {
-    LOG(WARNING) << "Failed to flush the stream.";
-  }
-
-  return Result::OK;
-}
-
-Return<void> StreamOutImpl::getPresentationPosition(
-    getPresentationPosition_cb _hidl_cb) {
-  if (!mWriteThread) {
-    _hidl_cb(Result::INVALID_STATE, 0, {});
-    return Void();
-  }
-
-  auto [frames, timestamp] = mWriteThread->getPresentationPosition();
-  _hidl_cb(Result::OK, frames, timestamp);
-  return Void();
-}
-
-Return<Result> StreamOutImpl::start() {
-  return mStream->start() ? Result::OK : Result::NOT_SUPPORTED;
-}
-
-Return<Result> StreamOutImpl::stop() {
-  return mStream->stop() ? Result::OK : Result::NOT_SUPPORTED;
-}
-
-Return<void> StreamOutImpl::createMmapBuffer(int32_t minSizeFrames,
-                                             createMmapBuffer_cb _hidl_cb) {
-  MmapBufferInfo hidlInfo;
-  AidlMmapBufferInfo info = mStream->createMmapBuffer(minSizeFrames);
-  int sharedMemoryFd = info.sharedMemoryFd.get();
-  if (sharedMemoryFd == -1) {
-    _hidl_cb(Result::NOT_SUPPORTED, hidlInfo);
-    return Void();
-  }
-
-  native_handle_t* hidlHandle = nullptr;
-  hidlHandle = native_handle_create(1, 0);
-  hidlHandle->data[0] = sharedMemoryFd;
-
-  hidlInfo.sharedMemory =
-      hidl_memory("audio_proxy_mmap_buffer", hidlHandle,
-                  mStream->getFrameSize() * info.bufferSizeFrames);
-  hidlInfo.bufferSizeFrames = info.bufferSizeFrames;
-  hidlInfo.burstSizeFrames = info.burstSizeFrames;
-  hidlInfo.flags = static_cast<hidl_bitfield<MmapBufferFlag>>(info.flags);
-  _hidl_cb(Result::OK, hidlInfo);
-  return Void();
-}
-
-Return<void> StreamOutImpl::getMmapPosition(getMmapPosition_cb _hidl_cb) {
-  MmapPosition hidlPosition;
-
-  AidlPresentationPosition position = mStream->getMmapPosition();
-  if (position.timestamp.tvSec == 0 && position.timestamp.tvNSec == 0) {
-    _hidl_cb(Result::NOT_SUPPORTED, hidlPosition);
-    return Void();
-  }
-
-  hidlPosition.timeNanoseconds =
-      position.timestamp.tvSec * kOneSecInNs + position.timestamp.tvNSec;
-  hidlPosition.positionFrames = position.frames;
-  _hidl_cb(Result::OK, hidlPosition);
-  return Void();
-}
-
-#if MAJOR_VERSION >= 7
-Return<Result> StreamOutImpl::updateSourceMetadata(
-    const SourceMetadata& sourceMetadata) {
-  return Result::NOT_SUPPORTED;
-}
-#else
-Return<void> StreamOutImpl::updateSourceMetadata(
-    const SourceMetadata& sourceMetadata) {
-  return Void();
-}
-#endif
-
-Return<Result> StreamOutImpl::selectPresentation(int32_t presentationId,
-                                                 int32_t programId) {
-  return Result::NOT_SUPPORTED;
-}
-
-std::shared_ptr<BusOutputStream> StreamOutImpl::getOutputStream() {
-  return mStream;
-}
-
-void StreamOutImpl::updateOutputStream(
-    std::shared_ptr<BusOutputStream> stream) {
-  DCHECK(stream);
-  DCHECK(mStream);
-  if (stream->getConfig() != mStream->getConfig()) {
-    LOG(ERROR) << "New stream's config doesn't match the old stream's config.";
-    return;
-  }
-
-  if (mWriteThread) {
-    if (!stream->prepareForWriting(mStream->getWritingFrameSize(),
-                                   mStream->getWritingFrameCount())) {
-      LOG(ERROR) << "Failed to prepare writing channel.";
-      return;
-    }
-
-    mWriteThread->updateOutputStream(stream);
-  }
-
-  mStream = std::move(stream);
-}
-
-uint64_t StreamOutImpl::estimateTotalPlayedFrames() const {
-  if (!mWriteThread) {
-    return 0;
-  }
-
-  auto [frames, timestamp] = mWriteThread->getPresentationPosition();
-  if (frames == 0) {
-    return 0;
-  }
-
-  return frames + estimatePlayedFramesSince(timestamp, mConfig.sampleRateHz);
-}
-
-#if MAJOR_VERSION >= 6
-Return<Result> StreamOutImpl::setEventCallback(
-    const sp<IStreamOutEventCallback>& callback) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> StreamOutImpl::getDualMonoMode(getDualMonoMode_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, DualMonoMode::OFF);
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setDualMonoMode(DualMonoMode mode) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> StreamOutImpl::getAudioDescriptionMixLevel(
-    getAudioDescriptionMixLevel_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, 0.f);
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setAudioDescriptionMixLevel(float leveldB) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> StreamOutImpl::getPlaybackRateParameters(
-    getPlaybackRateParameters_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, {});
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setPlaybackRateParameters(
-    const PlaybackRate& playbackRate) {
-  return Result::NOT_SUPPORTED;
-}
-#endif
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-Return<Result> StreamOutImpl::setLatencyMode(
-    android::hardware::audio::V7_1::LatencyMode mode) {
-  return Result::NOT_SUPPORTED;
-}
-
-Return<void> StreamOutImpl::getRecommendedLatencyModes(
-    getRecommendedLatencyModes_cb _hidl_cb) {
-  _hidl_cb(Result::NOT_SUPPORTED, {});
-  return Void();
-}
-
-Return<Result> StreamOutImpl::setLatencyModeCallback(
-    const sp<android::hardware::audio::V7_1::IStreamOutLatencyModeCallback>&
-        cb) {
-  return Result::NOT_SUPPORTED;
-}
-#endif
-
-}  // namespace audio_proxy::service
diff --git a/audio_proxy/service/StreamOutImpl.h b/audio_proxy/service/StreamOutImpl.h
deleted file mode 100644
index c1b557d..0000000
--- a/audio_proxy/service/StreamOutImpl.h
+++ /dev/null
@@ -1,188 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-// clang-format off
-#include PATH(android/hardware/audio/FILE_VERSION/IStreamOut.h)
-// clang-format on
-
-#include <fmq/EventFlag.h>
-#include <fmq/MessageQueue.h>
-#include <hidl/MQDescriptor.h>
-#include <hidl/Status.h>
-#include <utils/Thread.h>
-
-using android::sp;
-using android::Thread;
-using android::hardware::EventFlag;
-using android::hardware::hidl_bitfield;
-using android::hardware::hidl_string;
-using android::hardware::hidl_vec;
-using android::hardware::kSynchronizedReadWrite;
-using android::hardware::MessageQueue;
-using android::hardware::Return;
-using android::hardware::Void;
-using namespace android::hardware::audio::common::CPP_VERSION;
-using namespace android::hardware::audio::CPP_VERSION;
-
-namespace audio_proxy::service {
-
-class BusOutputStream;
-class WriteThread;
-
-typedef void (*EventFlagDeleter)(EventFlag*);
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-class StreamOutImpl : public android::hardware::audio::V7_1::IStreamOut {
-#else
-class StreamOutImpl : public IStreamOut {
-#endif
- public:
-  using CommandMQ = MessageQueue<WriteCommand, kSynchronizedReadWrite>;
-  using DataMQ = MessageQueue<uint8_t, kSynchronizedReadWrite>;
-  using StatusMQ = MessageQueue<WriteStatus, kSynchronizedReadWrite>;
-
-#if MAJOR_VERSION >= 7
-  using StreamOutConfig = AudioConfigBase;
-#else
-  using StreamOutConfig = AudioConfig;
-#endif
-
-  StreamOutImpl(std::shared_ptr<BusOutputStream> stream,
-                const StreamOutConfig& config);
-  ~StreamOutImpl() override;
-
-  std::shared_ptr<BusOutputStream> getOutputStream();
-  void updateOutputStream(std::shared_ptr<BusOutputStream> stream);
-
-  // Methods from ::android::hardware::audio::CPP_VERSION::IStream follow.
-  Return<uint64_t> getFrameSize() override;
-  Return<uint64_t> getFrameCount() override;
-  Return<uint64_t> getBufferSize() override;
-
-#if MAJOR_VERSION >= 7
-  Return<void> getSupportedProfiles(getSupportedProfiles_cb _hidl_cb) override;
-  Return<Result> setAudioProperties(
-      const AudioConfigBaseOptional& config) override;
-#else
-  Return<uint32_t> getSampleRate() override;
-  Return<void> getSupportedSampleRates(
-      AudioFormat format, getSupportedSampleRates_cb _hidl_cb) override;
-  Return<void> getSupportedChannelMasks(
-      AudioFormat format, getSupportedChannelMasks_cb _hidl_cb) override;
-  Return<Result> setSampleRate(uint32_t sampleRateHz) override;
-  Return<hidl_bitfield<AudioChannelMask>> getChannelMask() override;
-  Return<Result> setChannelMask(hidl_bitfield<AudioChannelMask> mask) override;
-  Return<AudioFormat> getFormat() override;
-  Return<void> getSupportedFormats(getSupportedFormats_cb _hidl_cb) override;
-  Return<Result> setFormat(AudioFormat format) override;
-#endif
-
-  Return<void> getAudioProperties(getAudioProperties_cb _hidl_cb) override;
-  Return<Result> addEffect(uint64_t effectId) override;
-  Return<Result> removeEffect(uint64_t effectId) override;
-  Return<Result> standby() override;
-  Return<void> getDevices(getDevices_cb _hidl_cb) override;
-  Return<Result> setDevices(const hidl_vec<DeviceAddress>& devices) override;
-  Return<void> getParameters(const hidl_vec<ParameterValue>& context,
-                             const hidl_vec<hidl_string>& keys,
-                             getParameters_cb _hidl_cb) override;
-  Return<Result> setParameters(
-      const hidl_vec<ParameterValue>& context,
-      const hidl_vec<ParameterValue>& parameters) override;
-  Return<Result> setHwAvSync(uint32_t hwAvSync) override;
-  Return<Result> close() override;
-
-  // Methods from ::android::hardware::audio::CPP_VERSION::IStreamOut follow.
-  Return<uint32_t> getLatency() override;
-  Return<Result> setVolume(float left, float right) override;
-  Return<void> prepareForWriting(uint32_t frameSize, uint32_t framesCount,
-                                 prepareForWriting_cb _hidl_cb) override;
-  Return<void> getRenderPosition(getRenderPosition_cb _hidl_cb) override;
-  Return<void> getNextWriteTimestamp(
-      getNextWriteTimestamp_cb _hidl_cb) override;
-  Return<Result> setCallback(const sp<IStreamOutCallback>& callback) override;
-  Return<Result> clearCallback() override;
-  Return<void> supportsPauseAndResume(
-      supportsPauseAndResume_cb _hidl_cb) override;
-  Return<Result> pause() override;
-  Return<Result> resume() override;
-  Return<bool> supportsDrain() override;
-  Return<Result> drain(AudioDrain type) override;
-  Return<Result> flush() override;
-  Return<void> getPresentationPosition(
-      getPresentationPosition_cb _hidl_cb) override;
-  Return<Result> start() override;
-  Return<Result> stop() override;
-  Return<void> createMmapBuffer(int32_t minSizeFrames,
-                                createMmapBuffer_cb _hidl_cb) override;
-  Return<void> getMmapPosition(getMmapPosition_cb _hidl_cb) override;
-#if MAJOR_VERSION >= 7
-  Return<Result> updateSourceMetadata(
-      const SourceMetadata& sourceMetadata) override;
-#else
-  Return<void> updateSourceMetadata(
-      const SourceMetadata& sourceMetadata) override;
-#endif
-  Return<Result> selectPresentation(int32_t presentationId,
-                                    int32_t programId) override;
-
-#if MAJOR_VERSION >= 6
-  Return<Result> setEventCallback(
-      const sp<IStreamOutEventCallback>& callback) override;
-  Return<void> getDualMonoMode(getDualMonoMode_cb _hidl_cb) override;
-  Return<Result> setDualMonoMode(DualMonoMode mode) override;
-  Return<void> getAudioDescriptionMixLevel(
-      getAudioDescriptionMixLevel_cb _hidl_cb) override;
-  Return<Result> setAudioDescriptionMixLevel(float leveldB) override;
-  Return<void> getPlaybackRateParameters(
-      getPlaybackRateParameters_cb _hidl_cb) override;
-  Return<Result> setPlaybackRateParameters(
-      const PlaybackRate& playbackRate) override;
-#endif
-
-#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
-  Return<Result> setLatencyMode(
-      android::hardware::audio::V7_1::LatencyMode mode) override;
-  Return<void> getRecommendedLatencyModes(
-      getRecommendedLatencyModes_cb _hidl_cb) override;
-  Return<Result> setLatencyModeCallback(
-      const sp<android::hardware::audio::V7_1::IStreamOutLatencyModeCallback>&
-          cb) override;
-#endif
-
- private:
-  uint64_t estimateTotalPlayedFrames() const;
-
-  // The object is always valid until close is called.
-  std::shared_ptr<BusOutputStream> mStream;
-  const StreamOutConfig mConfig;
-
-  const uint64_t mBufferSizeBytes;
-  const uint32_t mLatencyMs;
-
-  std::unique_ptr<CommandMQ> mCommandMQ;
-  std::unique_ptr<DataMQ> mDataMQ;
-  std::unique_ptr<StatusMQ> mStatusMQ;
-  std::unique_ptr<EventFlag, EventFlagDeleter> mEventFlag;
-  sp<WriteThread> mWriteThread;
-
-  uint64_t mTotalPlayedFramesSinceStandby = 0;
-
-  // Whether pause is called. It's used to avoid resuming when not paused.
-  bool mIsPaused = false;
-};
-
-}  // namespace audio_proxy::service
diff --git a/audio_proxy/service/WriteThread.cpp b/audio_proxy/service/WriteThread.cpp
deleted file mode 100644
index 0e715cb..0000000
--- a/audio_proxy/service/WriteThread.cpp
+++ /dev/null
@@ -1,211 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "WriteThread.h"
-
-#include <android-base/logging.h>
-#include <time.h>
-
-#include <atomic>
-
-#include "AidlTypes.h"
-#include "BusOutputStream.h"
-
-namespace audio_proxy::service {
-
-WriteThread::WriteThread(std::shared_ptr<BusOutputStream> stream,
-                         CommandMQ* commandMQ, DataMQ* dataMQ,
-                         StatusMQ* statusMQ, EventFlag* eventFlag,
-                         uint32_t latencyMs)
-    : Thread(false /*canCallJava*/),
-      mStream(std::move(stream)),
-      mCommandMQ(commandMQ),
-      mDataMQ(dataMQ),
-      mStatusMQ(statusMQ),
-      mEventFlag(eventFlag),
-      mLatencyMs(latencyMs) {}
-
-WriteThread::~WriteThread() = default;
-
-void WriteThread::stop() {
-  if (mStop.load(std::memory_order_relaxed)) {
-    return;
-  }
-
-  mStop.store(true, std::memory_order_release);
-  mEventFlag->wake(static_cast<uint32_t>(MessageQueueFlagBits::NOT_EMPTY));
-}
-
-void WriteThread::updateOutputStream(std::shared_ptr<BusOutputStream> stream) {
-  {
-    std::scoped_lock<std::mutex> lock(mStreamLock);
-    mStream = std::move(stream);
-  }
-
-  // Assume all the written frames are already played out by the old stream.
-  std::scoped_lock<std::mutex> lock(mPositionLock);
-  mPresentationFramesOffset = mTotalWrittenFrames;
-}
-
-std::pair<uint64_t, TimeSpec> WriteThread::getPresentationPosition() {
-  std::scoped_lock<std::mutex> lock(mPositionLock);
-  return std::make_pair(mPresentationFrames, mPresentationTimestamp);
-}
-
-IStreamOut::WriteStatus WriteThread::doWrite(BusOutputStream* stream) {
-  IStreamOut::WriteStatus status;
-  status.replyTo = IStreamOut::WriteCommand::WRITE;
-  status.retval = Result::INVALID_STATE;
-  status.reply.written = 0;
-
-  const size_t availToRead = mDataMQ->availableToRead();
-  if (stream->availableToWrite() < availToRead) {
-    LOG(WARNING) << "No space to write, wait...";
-    return status;
-  }
-
-  DataMQ::MemTransaction tx;
-  if (mDataMQ->beginRead(availToRead, &tx)) {
-    status.retval = Result::OK;
-    AidlWriteStatus writeStatus = stream->writeRingBuffer(
-        tx.getFirstRegion().getAddress(), tx.getFirstRegion().getLength(),
-        tx.getSecondRegion().getAddress(), tx.getSecondRegion().getLength());
-    if (writeStatus.written < availToRead) {
-      LOG(WARNING) << "Failed to write all the bytes to client. Written "
-                   << writeStatus.written << ", available " << availToRead;
-    }
-
-    if (writeStatus.written < 0) {
-      writeStatus.written = 0;
-    }
-
-    status.reply.written = writeStatus.written;
-    mDataMQ->commitRead(writeStatus.written);
-
-    if (writeStatus.position.frames < 0 ||
-        writeStatus.position.timestamp.tvSec < 0 ||
-        writeStatus.position.timestamp.tvNSec < 0) {
-      LOG(WARNING) << "Invalid latency info.";
-      return status;
-    }
-
-    updatePresentationPosition(writeStatus, stream);
-  }
-
-  return status;
-}
-
-IStreamOut::WriteStatus WriteThread::doGetPresentationPosition() const {
-  IStreamOut::WriteStatus status;
-  status.replyTo = IStreamOut::WriteCommand::GET_PRESENTATION_POSITION;
-  status.retval = Result::OK;
-  // Write always happens on the same thread, there's no need to lock.
-  status.reply.presentationPosition = {mPresentationFrames,
-                                       mPresentationTimestamp};
-  return status;
-}
-
-IStreamOut::WriteStatus WriteThread::doGetLatency() const {
-  IStreamOut::WriteStatus status;
-  status.replyTo = IStreamOut::WriteCommand::GET_LATENCY;
-  status.retval = Result::OK;
-  // Write always happens on the same thread, there's no need to lock.
-  status.reply.latencyMs = mLatencyMs;
-  return status;
-}
-
-bool WriteThread::threadLoop() {
-  // This implementation doesn't return control back to the Thread until the
-  // parent thread decides to stop, as the Thread uses mutexes, and this can
-  // lead to priority inversion.
-  while (!mStop.load(std::memory_order_acquire)) {
-    std::shared_ptr<BusOutputStream> stream;
-    {
-      std::scoped_lock<std::mutex> lock(mStreamLock);
-      stream = mStream;
-    }
-
-    // Read command. Don't use readBlocking, because readBlocking will block
-    // when there's no data. When stopping the thread, there's a chance that we
-    // only wake the mEventFlag without writing any data to FMQ. In this case,
-    // readBlocking will block until timeout.
-    IStreamOut::WriteCommand replyTo;
-    uint32_t efState = 0;
-    mEventFlag->wait(static_cast<uint32_t>(MessageQueueFlagBits::NOT_EMPTY),
-                     &efState);
-    if (!(efState & static_cast<uint32_t>(MessageQueueFlagBits::NOT_EMPTY))) {
-      continue;  // Nothing to do.
-    }
-    if (!mCommandMQ->read(&replyTo)) {
-      continue;  // Nothing to do.
-    }
-
-    if (replyTo == IStreamOut::WriteCommand::WRITE) {
-      mNonWriteCommandCount = 0;
-    } else {
-      mNonWriteCommandCount++;
-    }
-
-    IStreamOut::WriteStatus status;
-    switch (replyTo) {
-      case IStreamOut::WriteCommand::WRITE:
-        status = doWrite(stream.get());
-        break;
-      case IStreamOut::WriteCommand::GET_PRESENTATION_POSITION:
-        // If we don't write data for a while, the presentation position info
-        // may not be accurate. Write 0 bytes data to the client to get the
-        // latest presentation position info.
-        if (mNonWriteCommandCount >= 3 || mNonWriteCommandCount < 0) {
-          queryPresentationPosition(stream.get());
-        }
-        status = doGetPresentationPosition();
-        break;
-      case IStreamOut::WriteCommand::GET_LATENCY:
-        status = doGetLatency();
-        break;
-      default:
-        LOG(ERROR) << "Unknown write thread command code "
-                   << static_cast<int>(replyTo);
-        status.retval = Result::NOT_SUPPORTED;
-        break;
-    }
-
-    if (!mStatusMQ->write(&status)) {
-      LOG(ERROR) << "Status message queue write failed";
-    }
-    mEventFlag->wake(static_cast<uint32_t>(MessageQueueFlagBits::NOT_FULL));
-  }
-
-  return false;
-}
-
-void WriteThread::queryPresentationPosition(BusOutputStream* stream) {
-    AidlWriteStatus writeStatus =
-        stream->writeRingBuffer(nullptr, 0, nullptr, 0);
-    updatePresentationPosition(writeStatus, stream);
-}
-
-void WriteThread::updatePresentationPosition(const AidlWriteStatus& writeStatus,
-                                             BusOutputStream* stream) {
-  std::scoped_lock<std::mutex> lock(mPositionLock);
-  mPresentationFrames = mPresentationFramesOffset + writeStatus.position.frames;
-  mPresentationTimestamp = {
-    .tvSec = static_cast<uint64_t>(writeStatus.position.timestamp.tvSec),
-    .tvNSec = static_cast<uint64_t>(writeStatus.position.timestamp.tvNSec),
-  };
-
-  mTotalWrittenFrames += writeStatus.written / stream->getFrameSize();
-}
-
-}  // namespace audio_proxy::service
diff --git a/audio_proxy/service/WriteThread.h b/audio_proxy/service/WriteThread.h
deleted file mode 100644
index d313686..0000000
--- a/audio_proxy/service/WriteThread.h
+++ /dev/null
@@ -1,113 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-#include <atomic>
-#include <mutex>
-
-// clang-format off
-#include PATH(android/hardware/audio/FILE_VERSION/IStreamOut.h)
-// clang-format on
-
-#include <android-base/thread_annotations.h>
-#include <fmq/EventFlag.h>
-#include <fmq/MessageQueue.h>
-#include <hidl/MQDescriptor.h>
-#include <inttypes.h>
-#include <utils/Thread.h>
-
-#include "AidlTypes.h"
-
-using android::sp;
-using android::Thread;
-using android::hardware::EventFlag;
-using android::hardware::kSynchronizedReadWrite;
-using android::hardware::MessageQueue;
-using namespace android::hardware::audio::common::CPP_VERSION;
-using namespace android::hardware::audio::CPP_VERSION;
-
-namespace audio_proxy::service {
-
-class BusOutputStream;
-
-class WriteThread : public Thread {
- public:
-  using CommandMQ =
-      MessageQueue<IStreamOut::WriteCommand, kSynchronizedReadWrite>;
-  using DataMQ = MessageQueue<uint8_t, kSynchronizedReadWrite>;
-  using StatusMQ =
-      MessageQueue<IStreamOut::WriteStatus, kSynchronizedReadWrite>;
-
-  // WriteThread's lifespan never exceeds StreamOut's lifespan.
-  WriteThread(std::shared_ptr<BusOutputStream> stream, CommandMQ* commandMQ,
-              DataMQ* dataMQ, StatusMQ* statusMQ, EventFlag* eventFlag,
-              uint32_t latencyMs);
-
-  ~WriteThread() override;
-
-  void stop();
-
-  void updateOutputStream(std::shared_ptr<BusOutputStream> stream);
-
-  std::pair<uint64_t, TimeSpec> getPresentationPosition();
-
- private:
-  bool threadLoop() override;
-
-  // The following function is called on the thread and it will modify the
-  // variables which may be read from another thread.
-  IStreamOut::WriteStatus doWrite(BusOutputStream* stream);
-
-  // The following function is called on the thread and only read variable
-  // that is written on the same thread, so there's no need to lock the
-  // resources.
-  IStreamOut::WriteStatus doGetPresentationPosition() const
-      NO_THREAD_SAFETY_ANALYSIS;
-
-  IStreamOut::WriteStatus doGetLatency() const;
-
-  // Write 0 buffer to {@param stream} for latest presentation info.
-  void queryPresentationPosition(BusOutputStream* stream);
-
-  // Update presentation position info after writing to {@param stream}. Caller
-  // should validate the {@param status}.
-  void updatePresentationPosition(const AidlWriteStatus& status,
-                                  BusOutputStream* stream);
-
-  std::atomic<bool> mStop = false;
-
-  std::mutex mStreamLock;
-  std::shared_ptr<BusOutputStream> mStream GUARDED_BY(mStreamLock);
-
-  CommandMQ* const mCommandMQ;
-  DataMQ* const mDataMQ;
-  StatusMQ* const mStatusMQ;
-  EventFlag* const mEventFlag;
-
-  // Latency in ms, used in HIDL API getLatency.
-  const uint32_t mLatencyMs;
-
-  // Count for consecutive FMQ command that is not WRITE.
-  int64_t mNonWriteCommandCount = 0;
-
-  // Presentation position information.
-  std::mutex mPositionLock;
-  uint64_t mPresentationFramesOffset GUARDED_BY(mPositionLock) = 0;
-  uint64_t mPresentationFrames GUARDED_BY(mPositionLock) = 0;
-  TimeSpec mPresentationTimestamp GUARDED_BY(mPositionLock) = {0, 0};
-  uint64_t mTotalWrittenFrames GUARDED_BY(mPositionLock) = 0;
-};
-
-}  // namespace audio_proxy::service
\ No newline at end of file
diff --git a/audio_proxy/service/audio_proxy_policy_configuration.xml b/audio_proxy/service/audio_proxy_policy_configuration.xml
deleted file mode 100644
index 6fddee2..0000000
--- a/audio_proxy/service/audio_proxy_policy_configuration.xml
+++ /dev/null
@@ -1,57 +0,0 @@
-<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
-<module name="mediashell" halVersion="3.0">
-  <attachedDevices>
-    <item>MediaShell Direct Audio Device</item>
-    <item>MediaShell Mixer Audio Device</item>
-  </attachedDevices>
-
-  <mixPorts>
-    <mixPort name="direct_mix_port" role="source"
-             flags="AUDIO_OUTPUT_FLAG_DIRECT" maxOpenCount="0">
-      <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-               samplingRates="16000 22050 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_8_BIT"
-               samplingRates="16000 22050 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_32_BIT"
-               samplingRates="16000 22050 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_8_24_BIT"
-               samplingRates="16000 22050 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_FLOAT"
-               samplingRates="16000 22050 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_24_BIT_PACKED"
-               samplingRates="16000 22050 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-    </mixPort>
-
-    <mixPort name="mixer_mix_port" role="source">
-      <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-               samplingRates="48000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO"/>
-    </mixPort>
-  </mixPorts>
-
-  <devicePorts>
-    <devicePort tagName="MediaShell Direct Audio Device"
-                type="AUDIO_DEVICE_OUT_BUS"
-                role="sink" address="MEDIASHELL_AUDIO_DEVICE_ADDR">
-    </devicePort>
-
-    <devicePort tagName="MediaShell Mixer Audio Device"
-                type="AUDIO_DEVICE_OUT_BUS"
-                role="sink" address="MEDIASHELL_MIXER_DEVICE_ADDR">
-    </devicePort>
-  </devicePorts>
-
-  <routes>
-    <route type="mix" sink="MediaShell Direct Audio Device"
-           sources="direct_mix_port"/>
-
-    <route type="mix" sink="MediaShell Mixer Audio Device"
-           sources="mixer_mix_port"/>
-  </routes>
-</module>
diff --git a/audio_proxy/service/audio_proxy_policy_configuration_hw_av_sync.xml b/audio_proxy/service/audio_proxy_policy_configuration_hw_av_sync.xml
deleted file mode 100644
index b86a897..0000000
--- a/audio_proxy/service/audio_proxy_policy_configuration_hw_av_sync.xml
+++ /dev/null
@@ -1,86 +0,0 @@
-<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
-<module name="mediashell" halVersion="3.0">
-  <attachedDevices>
-    <item>MediaShell Direct Audio Device</item>
-    <item>MediaShell Mixer Audio Device</item>
-  </attachedDevices>
-
-  <mixPorts>
-    <mixPort name="direct_mix_port" role="source"
-             flags="AUDIO_OUTPUT_FLAG_DIRECT" maxOpenCount="0">
-      <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_8_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_32_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_8_24_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_FLOAT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_24_BIT_PACKED"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-    </mixPort>
-
-    <mixPort name="tunneling_mix_port" role="source"
-             flags="AUDIO_OUTPUT_FLAG_DIRECT AUDIO_OUTPUT_FLAG_HW_AV_SYNC" maxOpenCount="0">
-      <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_8_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_32_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_8_24_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_FLOAT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-      <profile name="" format="AUDIO_FORMAT_PCM_24_BIT_PACKED"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO AUDIO_CHANNEL_OUT_2POINT1 AUDIO_CHANNEL_OUT_TRI AUDIO_CHANNEL_OUT_TRI_BACK AUDIO_CHANNEL_OUT_3POINT1 AUDIO_CHANNEL_OUT_2POINT0POINT2 AUDIO_CHANNEL_OUT_2POINT1POINT2 AUDIO_CHANNEL_OUT_3POINT0POINT2 AUDIO_CHANNEL_OUT_3POINT1POINT2 AUDIO_CHANNEL_OUT_QUAD AUDIO_CHANNEL_OUT_QUAD_BACK AUDIO_CHANNEL_OUT_QUAD_SIDE AUDIO_CHANNEL_OUT_SURROUND AUDIO_CHANNEL_OUT_PENTA AUDIO_CHANNEL_OUT_5POINT1 AUDIO_CHANNEL_OUT_5POINT1_BACK AUDIO_CHANNEL_OUT_5POINT1_SIDE"/>
-    </mixPort>
-
-    <mixPort name="mmap_noirq_mix_port" role="source"
-             flags="AUDIO_OUTPUT_FLAG_DIRECT AUDIO_OUTPUT_FLAG_MMAP_NOIRQ" maxOpenCount="0">
-      <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-               samplingRates="16000 22050 24000 32000 44100 48000 96000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO"/>
-    </mixPort>
-
-    <mixPort name="mixer_mix_port" role="source">
-      <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-               samplingRates="48000"
-               channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO"/>
-    </mixPort>
-  </mixPorts>
-
-  <devicePorts>
-    <devicePort tagName="MediaShell Direct Audio Device"
-                type="AUDIO_DEVICE_OUT_BUS"
-                role="sink" address="MEDIASHELL_AUDIO_DEVICE_ADDR">
-    </devicePort>
-
-    <devicePort tagName="MediaShell Mixer Audio Device"
-                type="AUDIO_DEVICE_OUT_BUS"
-                role="sink" address="MEDIASHELL_MIXER_DEVICE_ADDR">
-    </devicePort>
-  </devicePorts>
-
-  <routes>
-    <route type="mix" sink="MediaShell Direct Audio Device"
-           sources="direct_mix_port,tunneling_mix_port,mmap_noirq_mix_port"/>
-
-    <route type="mix" sink="MediaShell Mixer Audio Device"
-           sources="mixer_mix_port"/>
-  </routes>
-</module>
diff --git a/audio_proxy/service/device.google.atv.audio_proxy@5.1-service.rc b/audio_proxy/service/device.google.atv.audio_proxy@5.1-service.rc
deleted file mode 100644
index 3b1d713..0000000
--- a/audio_proxy/service/device.google.atv.audio_proxy@5.1-service.rc
+++ /dev/null
@@ -1,7 +0,0 @@
-service audio_proxy_service /vendor/bin/hw/device.google.atv.audio_proxy@5.1-service \
-  --name mediashell \
-  --stream MEDIASHELL_AUDIO_DEVICE_ADDR:40:600 \
-  --stream MEDIASHELL_MIXER_DEVICE_ADDR:40:40
-    class hal
-    user system
-    group system
diff --git a/audio_proxy/service/device.google.atv.audio_proxy@6.0-service.rc b/audio_proxy/service/device.google.atv.audio_proxy@6.0-service.rc
deleted file mode 100644
index fa6ed77..0000000
--- a/audio_proxy/service/device.google.atv.audio_proxy@6.0-service.rc
+++ /dev/null
@@ -1,7 +0,0 @@
-service audio_proxy_service /vendor/bin/hw/device.google.atv.audio_proxy@6.0-service \
-  --name mediashell \
-  --stream MEDIASHELL_AUDIO_DEVICE_ADDR:40:600 \
-  --stream MEDIASHELL_MIXER_DEVICE_ADDR:40:40
-    class hal
-    user system
-    group system
diff --git a/audio_proxy/service/device.google.atv.audio_proxy@7.0-service.rc b/audio_proxy/service/device.google.atv.audio_proxy@7.0-service.rc
deleted file mode 100644
index e8477fb..0000000
--- a/audio_proxy/service/device.google.atv.audio_proxy@7.0-service.rc
+++ /dev/null
@@ -1,7 +0,0 @@
-service audio_proxy_service /vendor/bin/hw/device.google.atv.audio_proxy@7.0-service \
-  --name mediashell \
-  --stream MEDIASHELL_AUDIO_DEVICE_ADDR:40:600 \
-  --stream MEDIASHELL_MIXER_DEVICE_ADDR:40:40
-    class hal
-    user system
-    group system
diff --git a/audio_proxy/service/device.google.atv.audio_proxy@7.1-service.rc b/audio_proxy/service/device.google.atv.audio_proxy@7.1-service.rc
deleted file mode 100644
index 37cab1e..0000000
--- a/audio_proxy/service/device.google.atv.audio_proxy@7.1-service.rc
+++ /dev/null
@@ -1,7 +0,0 @@
-service audio_proxy_service /vendor/bin/hw/device.google.atv.audio_proxy@7.1-service \
-  --name mediashell \
-  --stream MEDIASHELL_AUDIO_DEVICE_ADDR:40:600 \
-  --stream MEDIASHELL_MIXER_DEVICE_ADDR:40:40
-    class hal
-    user system
-    group system
diff --git a/audio_proxy/service/main.cpp b/audio_proxy/service/main.cpp
deleted file mode 100644
index 352ff0d..0000000
--- a/audio_proxy/service/main.cpp
+++ /dev/null
@@ -1,74 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include <android-base/logging.h>
-#include <android/binder_manager.h>
-#include <android/binder_process.h>
-#include <hidl/HidlTransportSupport.h>
-
-#include <optional>
-
-#include "AudioProxyError.h"
-#include "AudioProxyImpl.h"
-#include "DevicesFactoryImpl.h"
-#include "ServiceConfig.h"
-
-using android::sp;
-using android::status_t;
-
-using namespace audio_proxy::service;
-
-int main(int argc, char** argv) {
-  auto config = parseServiceConfigFromCommandLine(argc, argv);
-  if (!config) {
-    return ERROR_INVALID_ARGS;
-  }
-
-  // Default stream config.
-  StreamConfig defaultStreamConfig = {10, 10};
-  config->streams.emplace("default", defaultStreamConfig);
-
-  // Config thread pool.
-  ABinderProcess_setThreadPoolMaxThreadCount(1);
-  android::hardware::configureRpcThreadpool(1, false /* callerWillJoin */);
-
-  // Register AudioProxy service.
-  auto audioProxy = ndk::SharedRefBase::make<AudioProxyImpl>();
-  const std::string audioProxyName =
-      std::string(AudioProxyImpl::descriptor) + "/" + config->name;
-
-  binder_status_t binder_status = AServiceManager_addService(
-      audioProxy->asBinder().get(), audioProxyName.c_str());
-  if (binder_status != STATUS_OK) {
-    LOG(ERROR) << "Failed to start " << config->name
-               << " AudioProxy service, status " << binder_status;
-    return ERROR_AIDL_FAILURE;
-  }
-
-  // Register AudioProxy audio HAL.
-  auto devicesFactory =
-      sp<DevicesFactoryImpl>::make(audioProxy->getBusStreamProvider(), *config);
-  status_t status = devicesFactory->registerAsService(config->name);
-  if (status != android::OK) {
-    LOG(ERROR) << "Failed to start " << config->name << " audio HAL, status "
-               << status;
-    return ERROR_HIDL_FAILURE;
-  }
-
-  ABinderProcess_joinThreadPool();
-
-  // `ABinderProcess_joinThreadpool` should never return. Return -2 here for
-  // unexpected process exit.
-  return ERROR_UNEXPECTED;
-}
diff --git a/audio_proxy/service/manifest_audio_proxy_5_0.xml b/audio_proxy/service/manifest_audio_proxy_5_0.xml
deleted file mode 100644
index 176b388..0000000
--- a/audio_proxy/service/manifest_audio_proxy_5_0.xml
+++ /dev/null
@@ -1,13 +0,0 @@
-<manifest version="1.0" type="device">
-     <hal format="aidl">
-        <name>device.google.atv.audio_proxy</name>
-        <version>3</version>
-        <fqname>IAudioProxy/mediashell</fqname>
-    </hal>
-
-    <hal format="hidl">
-        <name>android.hardware.audio</name>
-        <transport>hwbinder</transport>
-        <fqname>@5.0::IDevicesFactory/mediashell</fqname>
-    </hal>
-</manifest>
diff --git a/audio_proxy/service/manifest_audio_proxy_6_0.xml b/audio_proxy/service/manifest_audio_proxy_6_0.xml
deleted file mode 100644
index fdb5eb1..0000000
--- a/audio_proxy/service/manifest_audio_proxy_6_0.xml
+++ /dev/null
@@ -1,13 +0,0 @@
-<manifest version="1.0" type="device">
-     <hal format="aidl">
-        <name>device.google.atv.audio_proxy</name>
-        <version>3</version>
-        <fqname>IAudioProxy/mediashell</fqname>
-    </hal>
-
-    <hal format="hidl">
-        <name>android.hardware.audio</name>
-        <transport>hwbinder</transport>
-        <fqname>@6.0::IDevicesFactory/mediashell</fqname>
-    </hal>
-</manifest>
diff --git a/audio_proxy/service/manifest_audio_proxy_7_0.xml b/audio_proxy/service/manifest_audio_proxy_7_0.xml
deleted file mode 100644
index 3adb4b5..0000000
--- a/audio_proxy/service/manifest_audio_proxy_7_0.xml
+++ /dev/null
@@ -1,13 +0,0 @@
-<manifest version="1.0" type="device">
-     <hal format="aidl">
-        <name>device.google.atv.audio_proxy</name>
-        <version>3</version>
-        <fqname>IAudioProxy/mediashell</fqname>
-    </hal>
-
-    <hal format="hidl">
-        <name>android.hardware.audio</name>
-        <transport>hwbinder</transport>
-        <fqname>@7.0::IDevicesFactory/mediashell</fqname>
-    </hal>
-</manifest>
diff --git a/audio_proxy/service/manifest_audio_proxy_7_1.xml b/audio_proxy/service/manifest_audio_proxy_7_1.xml
deleted file mode 100644
index 51b93d6..0000000
--- a/audio_proxy/service/manifest_audio_proxy_7_1.xml
+++ /dev/null
@@ -1,13 +0,0 @@
-<manifest version="1.0" type="device">
-     <hal format="aidl">
-        <name>device.google.atv.audio_proxy</name>
-        <version>3</version>
-        <fqname>IAudioProxy/mediashell</fqname>
-    </hal>
-
-    <hal format="hidl">
-        <name>android.hardware.audio</name>
-        <transport>hwbinder</transport>
-        <fqname>@7.1::IDevicesFactory/mediashell</fqname>
-    </hal>
-</manifest>
diff --git a/libraries/BluetoothServices/Android.bp b/libraries/BluetoothServices/Android.bp
index 822435d..092b22d 100644
--- a/libraries/BluetoothServices/Android.bp
+++ b/libraries/BluetoothServices/Android.bp
@@ -12,6 +12,7 @@ android_library {
 
     srcs: ["src/**/*.java"],
     static_libs: [
+        "android.media.tv.flags-aconfig-java",
         "androidx.annotation_annotation",
         "androidx.leanback_leanback",
         "androidx.leanback_leanback-preference",
diff --git a/libraries/BluetoothServices/OWNERS b/libraries/BluetoothServices/OWNERS
new file mode 100644
index 0000000..242a7f2
--- /dev/null
+++ b/libraries/BluetoothServices/OWNERS
@@ -0,0 +1,10 @@
+# Bug component: 1066323
+# Android > Android OS & Apps > TV > Connectivity > BT
+hisbilir@google.com
+arjundhaliwal@google.com
+xincheny@google.com
+agazal@google.com
+gubailey@google.com
+maitrim@google.com
+
+include /OWNERS
diff --git a/libraries/BluetoothServices/res/values-af/strings.xml b/libraries/BluetoothServices/res/values-af/strings.xml
index e87400b..83fafac 100644
--- a/libraries/BluetoothServices/res/values-af/strings.xml
+++ b/libraries/BluetoothServices/res/values-af/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Aktiveer HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC maak dit vir jou moontlik om ander HDMI-CEC-geaktiveerde toestelle met \'n enkele afstandbeheer te beheer en outomaties aan of af te skakel.\n\nLet wel: Maak seker dat HDMI-CEC op jou TV en ander HDMI-toestelle geaktiveer is. Vervaardigers het dikwels ander name vir HDMI-CEC, byvoorbeeld:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Gaan na bystand wanneer invoer na ’n ander bron oorgeskakel word"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Wanneer jy hierdie instelling aktiveer en HDMI-CEC op jou TV geaktiveer het, sal hierdie toestel outomaties in bystand kom kort nadat jy na ’n ander invoer op jou TV oorgeskakel het. Dit kan help om inhoud te onderbreek en kragverbruik te verminder wanneer jy nie aktief kyk nie."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Stel afstandbeheerknoppies op"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Beheer volume, krag, invoer op TV\'s, ontvangers en klankbalke"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Soek my afstandbeheerder"</string>
diff --git a/libraries/BluetoothServices/res/values-am/strings.xml b/libraries/BluetoothServices/res/values-am/strings.xml
index 635e6b9..09cfde6 100644
--- a/libraries/BluetoothServices/res/values-am/strings.xml
+++ b/libraries/BluetoothServices/res/values-am/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CECን አንቃ"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ሌላ በ HDMI-CEC የነቁ መሣሪያዎችን ከአንድ ነጠላ የርቀት መቆጣጠሪያ ጋር ለመቆጣጠር እና በራስሰር እንዲያበሩ/እንዲያጠፉ ያስችልዎታል።\n\nማስታወሻ፦ HDMI-CEC በእርስዎ ቴሌቪዥን ላይ እና ሌሎች HDMI መሣሪያዎች ላይ መንቃቱን ያረጋግጡ። አምራቾች ለ HDMI-CEC, ብዙውን ጊዜ የተለዩ ስሞች አሏቸው፤ ለምሳሌ፦"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung፦ Anynet+\nLG፦ SimpLink\nSony፦ BRAVIA Sync\nPhilips፦ EasyLink\nSharp፦ Aquos አገናኝ"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ግብዓትን ወደ ሌላ ምንጭ በመቀየር ወቅት ተጠባባቂ ውስጥ ይግቡ"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"ይህን ቅንብር ሲያነቁ እና ቲቪዎ ላይ HDMI-CECን ሲያነቁ ይህ መሣሪያ ቲቪዎ ላይ ወደተለየ ግብዓት ከቀየሩ በኋላ በአጭር ጊዜ ውስጥ በራስ-ሰር ተጠባባቂ ውስጥ ይገባል። ይህ ገቢር በሆነ መልኩ በማይመለከቱበት ወቅት ይዘትን ባለበት ለማቆም እና የኃይል አጠቃቀምን ለመቀነስ ሊያግዝ ይችላል።"</string>
     <string name="settings_axel" msgid="8253298947221430993">"የርቀት መቆጣጠሪያ አዝራሮችን ያዋቅሩ"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"በቲቪዎች፣ ተቀባዮች እና የድምፅ አሞሌዎች ላይ የድምፅ መጠንን፣ ኃይልን፣ ግብዓትን ይቆጣጠሩ"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"የእኔን የርቀት መቆጣጠሪያ አግኝ"</string>
diff --git a/libraries/BluetoothServices/res/values-ar/strings.xml b/libraries/BluetoothServices/res/values-ar/strings.xml
index ef363ee..eecfa9f 100644
--- a/libraries/BluetoothServices/res/values-ar/strings.xml
+++ b/libraries/BluetoothServices/res/values-ar/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"تفعيل HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"تسمح لك ميزة HDMI-CEC بالتحكم في الأجهزة الأخرى التي تم تفعيل ميزة HDMI-CEC عليها وتفعيلها/إيقافها تلقائيًا باستخدام وحدة تحكم واحدة عن بُعد.\n\nملاحظة: احرص على تفعيل ميزة HDMI-CEC على التلفزيون وغيره من أجهزة HDMI. وتوفر الشركات المصنِّعة ميزة HDMI-CEC غالبًا بأسماء مختلفة مثل:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"الدخول في وضع الاستعداد عند تبديل مصدر الإدخال إلى مصدر آخر"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"عند تفعيل هذا الإعداد وميزة HDMI-CEC على التلفزيون، سيدخل هذا الجهاز تلقائيًا في وضع الاستعداد بعد فترة قصيرة من التبديل إلى مصدر إدخال مختلف. يساعد هذا في إيقاف عرض المحتوى مؤقتًا وتقليل استهلاك الطاقة عند عدم المشاهدة."</string>
     <string name="settings_axel" msgid="8253298947221430993">"إعداد أزرار جهاز التحكّم عن بُعد"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"التحكّم في مستوى الصوت وإمكانية الإيقاف أو التشغيل والإدخال في أجهزة التلفزيون وأجهزة الاستقبال ومكبّرات الصوت العمودي"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"العثور على جهاز التحكّم عن بُعد"</string>
diff --git a/libraries/BluetoothServices/res/values-as/strings.xml b/libraries/BluetoothServices/res/values-as/strings.xml
index 3a12a6a..ad8fab4 100644
--- a/libraries/BluetoothServices/res/values-as/strings.xml
+++ b/libraries/BluetoothServices/res/values-as/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC সক্ষম কৰক"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"আপোনাক HDMI-CECএ অইন HDMI-CEC সক্ষম ডিভাইচ নিয়ন্ত্ৰণ আৰু স্বয়ংক্ৰিয়ভাৱে এটা একক ৰিম’ট নিয়ন্ত্ৰকৰ জৰিয়তে অন/অফ কৰিবলৈ সুবিধা দিয়ে।\n\nটোকা: আপোনাৰ টিভি আৰু আন HDMI ডিভাইচসমূহত HDMI-CEC সক্ষম কৰি থোৱাটো নিশ্চিত কৰক। বেলেগ বেলেগ নিৰ্মাতাই সাধাৰণতে HDMI-CECৰ কাৰণে বেলেগে বেলেগ নাম ব্যৱহাৰ কৰে, উদাহৰণস্বৰূপে:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ইনপুটটো অন্য উৎসলৈ সলনি কৰিলে ষ্টেণ্ডবাইত সোমাওক"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"আপুনি এই ছেটিংটো সক্ষম কৰিলে আৰু আপোনাৰ টিভিত HDMI-CEC সক্ষম কৰা থাকিলে, আপুনি নিজৰ টিভিত অন্য কোনো ইনপুটলৈ সলনি কৰাৰ পাছতেই এই ডিভাইচটো স্বয়ংক্ৰিয়ভাৱে ষ্টেণ্ডবাই হ’ব। আপুনি সক্ৰিয়ভাৱে চাই নাথাকিলে এইটোৱে সমল পজ কৰাত আৰু শক্তিৰ ব্যৱহাৰ কম কৰাত সহায় কৰিব পাৰে।"</string>
     <string name="settings_axel" msgid="8253298947221430993">"ৰিম’টৰ বুটামসমূহ ছেট আপ কৰক"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"টিভি, ৰিচিভাৰ আৰু ছাউণ্ডবাৰত ভলিউম, পাৱাৰ আৰু ইনপুট নিয়ন্ত্ৰণ কৰক"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"মোৰ ৰিম’ট বিচাৰক"</string>
diff --git a/libraries/BluetoothServices/res/values-az/strings.xml b/libraries/BluetoothServices/res/values-az/strings.xml
index d4f9446..9d8c78d 100644
--- a/libraries/BluetoothServices/res/values-az/strings.xml
+++ b/libraries/BluetoothServices/res/values-az/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC-i aktiv edin"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC yalnız bir pult ilə HDMI-CEC funksiyası aktiv olan digər cihazlara nəzarət etməyə və avtomatik aktiv/deaktiv etməyə icazə verir.\n\nQeyd: HDMI-CEC funksiyasının TV və digər HDMI cihazlarında aktiv olduğuna əmin olun. İstehsalçılar adətən HDMI-CEC funksiyasına fərqli adlar verir, məsələn:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Daxiletməni başqa mənbəyə keçirərkən gözləmə rejiminə daxil olun"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Bu ayarı və TV-də HDMI-CEC-i aktiv etdikdə TV-də başqa daxiletməyə keçdikdən qısa müddət sonra bu cihaz avtomatik olaraq gözləmə rejiminə keçəcək. Bu, aktiv şəkildə izləmədiyiniz zaman kontenti dayandırmağa və enerji istehlakını azaltmağa kömək edə bilər."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Pult düymələrini quraşdırın"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"TV, qəbuledici və səs panellərində səs, yandırıb-söndürmə və daxiletməni idarə edin"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Pultumu tapın"</string>
diff --git a/libraries/BluetoothServices/res/values-b+sr+Latn/strings.xml b/libraries/BluetoothServices/res/values-b+sr+Latn/strings.xml
index 1be2979..7dc04c1 100644
--- a/libraries/BluetoothServices/res/values-b+sr+Latn/strings.xml
+++ b/libraries/BluetoothServices/res/values-b+sr+Latn/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Omogući HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC vam omogućava da kontrolišete i automatski uključujete/isključujete ostale uređaje na kojima je omogućen HDMI-CEC pomoću samo jednog daljinskog upravljača.\n\nNapomena: Uverite se da je HDMI-CEC omogućen na televizoru i drugim HDMI uređajima. Proizvođači obično imaju različite nazive za HDMI-CEC, na primer:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Pokrenite stanje pripravnosti pri prelasku na drugi izvor za ulaz"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Kada omogućite ovo podešavanje i imate HDMI-CEC omogućen na televizoru, ovaj uređaj automatski prelazi u stanje pripravnosti ubrzo pošto pređete na drugi ulaz na televizoru. To može da pomogne da se sadržaj pauzira i smanji potrošnja energije kada aktivno ne gledate."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Podesite dugmad na daljinskom upravljaču"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Kontrolišite jačinu zvuka, napajanje i ulaz TV-a, prijemnika i saundbarova"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Nađi daljinski"</string>
diff --git a/libraries/BluetoothServices/res/values-be/strings.xml b/libraries/BluetoothServices/res/values-be/strings.xml
index 8a4f441..b55c6a5 100644
--- a/libraries/BluetoothServices/res/values-be/strings.xml
+++ b/libraries/BluetoothServices/res/values-be/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Уключыць HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC дазваляе кіраваць іншымі сумяшчальнымі з HDMI-CEC прыладамі і аўтаматычна ўключаць/выключаць іх, карыстаючыся адным пультам аддаленага кіравання.\n\nЗаўвага. Праверце, ці ўключаны HDMI-CEC на вашым тэлевізары і іншых HDMI-прыладах. Вытворцы часта па-рознаму называюць HDMI-CEC, напрыклад:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Пераходзіць у рэжым чакання пры пераключэнні крыніцы ўваходнага сігналу"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Калі гэта налада ўключана, а на тэлевізары ўключаны HDMI-CEC, прылада будзе аўтаматычна пераключацца ў рэжым чакання неўзабаве пасля таго, як вы пераключыцеся на іншы ўваходны сігнал тэлевізара. Гэта можа дапамагчы прыпыніць прайграванне змесціва і паменшыць спажыванне энергіі, калі вы не вельмі актыўна гледзіце відэа."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Наладзіць кнопкі дыстанцыйнага пульта кіравання"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Кіраванне гучнасцю, сілкаваннем, уваходнымі сігналамі на тэлевізарах, рэсіверах і гукавых панэлях"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Пошук пульта"</string>
diff --git a/libraries/BluetoothServices/res/values-bg/strings.xml b/libraries/BluetoothServices/res/values-bg/strings.xml
index 101ee7b..5072d6c 100644
--- a/libraries/BluetoothServices/res/values-bg/strings.xml
+++ b/libraries/BluetoothServices/res/values-bg/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Активиране на CEC за HDMI"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"CEC за HDMI ви позволява да управлявате и автоматично да включвате/изключвате други активирани за CEC за HDMI устройства посредством едно дистанционно управление.\n\nЗабележка: Уверете се, че сте активирали CEC за HDMI на телевизора си и другите HDMI устройства. Производителите често имат различни имена за тази функция, като например:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Влизане в режим на готовност при превключване на входа към друг източник"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Когато активирате тази настройка и сте включили CEC за HDMI на телевизора си, това устройство автоматично ще премине в режим на готовност малко след като превключите към друг вход на телевизора си. Това може да помогне да поставяте съдържанието на пауза и да намалите разхода на енергия, когато не гледате активно."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Настройване на бутоните на дистанционното управление"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Управление на бутоните за силата на звука, включване/изключване и избор на вход на телевизори, приемници и звукови панели"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Намиране на дистанционното ми управление"</string>
diff --git a/libraries/BluetoothServices/res/values-bn/strings.xml b/libraries/BluetoothServices/res/values-bn/strings.xml
index c35e968..2b24d43 100644
--- a/libraries/BluetoothServices/res/values-bn/strings.xml
+++ b/libraries/BluetoothServices/res/values-bn/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC চালু করুন"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC-এর মাধ্যমে আপনি অন্য HDMI-CEC চালু আছে এমন ডিভাইস একটি রিমোট কন্ট্রোল দিয়ে নিজে থেকে চালু/বন্ধ করতে পারবেন।\n\nদ্রষ্টব্য: আপনার টিভি এবং অন্য HDMI ডিভাইসে HDMI-CEC চালু আছে কিনা ভাল করে দেখে নিন। প্রস্তুতকারকরা HDMI-CEC কে বিভিন্ন নাম দিয়ে থাকেন, যেমন:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ইনপুট অন্য সোর্সে পরিবর্তন করা হলে ডিভাইস স্ট্যান্ডবাই মোডে চলে যাবে"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"আপনি টিভিতে এই সেটিং এবং HDMI-CEC চালু করলে, আপনার টিভির জন্য অন্য ইনপুটে পরিবর্তন করার কিছুক্ষণ পরেই এই ডিভাইসটি অটোমেটিক স্ট্যান্ডবাই মোডে চলে যাবে। এর ফলে আপনি যখন সক্রিয়ভাবে টিভি দেখছেন না এটি কন্টেন্ট পজ করা এবং বিদ্যুৎ সাশ্রয় করার ক্ষেত্রে সাহায্য করতে পারে।"</string>
     <string name="settings_axel" msgid="8253298947221430993">"রিমোটের বোতাম সেট-আপ করুন"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ভলিউম, পাওয়ার, টিভির ইনপুট, রিসিভার ও সাউন্ডবার নিয়ন্ত্রণ করুন"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"\'আমার রিমোট খুঁজুন\'"</string>
diff --git a/libraries/BluetoothServices/res/values-bs/strings.xml b/libraries/BluetoothServices/res/values-bs/strings.xml
index 8ba9026..c98a0ea 100644
--- a/libraries/BluetoothServices/res/values-bs/strings.xml
+++ b/libraries/BluetoothServices/res/values-bs/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Omogući HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC vam omogućava kontroliranje i automatsko uključivanje/isključivanje drugih uređaja na kojima je omogućena funkcija HDMI-CEC i to pomoću jednog daljinskog upravljača.\n\nNapomena: Provjerite je li funkcija HDMI-CEC omogućena na vašem TV-u i drugim HDMI uređajima. Proizvođači često imaju različite nazive za funkciju HDMI-CEC, naprimjer:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Prelazak u stanje pripravnosti prilikom prebacivanja ulaza na drugi izvor"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Kada omogućite ovu postavku i imate omogućeni HDMI-CEC na TV-u, uređaj će automatski preći u stanje mirovanja ubrzo nakon što prebacite na drugi ulaz na TV-u. Ovo vam može pomoći da pauzirate sadržaj i smanjite potrošnju energije kada ne gledate aktivno."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Postavite dugmad daljinskog upravljača"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Kontrolirajte jačinu zvuka, uključivanje, ulaz na TV-ima, prijemnicima i soundbar zvučnicima"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Pronađi moj daljinski upravljač"</string>
diff --git a/libraries/BluetoothServices/res/values-ca/strings.xml b/libraries/BluetoothServices/res/values-ca/strings.xml
index e0ededc..8cfa305 100644
--- a/libraries/BluetoothServices/res/values-ca/strings.xml
+++ b/libraries/BluetoothServices/res/values-ca/strings.xml
@@ -30,7 +30,7 @@
     <string name="settings_bt_update_available" msgid="414405852666517260">"Actualització disponible"</string>
     <string name="settings_bt_update_not_necessary" msgid="6906777343269759565">"El comandament està actualitzat"</string>
     <string name="settings_bt_update_failed" msgid="2593228509570726064">"No s\'ha pogut actualitzar el comandament"</string>
-    <string name="settings_bt_update_error" msgid="6267154862961568780">"S\'ha produït un error en actualitzar el comandament. Torna-ho a provar."</string>
+    <string name="settings_bt_update_error" msgid="6267154862961568780">"Hi ha hagut un error en actualitzar el comandament. Torna-ho a provar."</string>
     <string name="settings_bt_update_please_wait" msgid="8029641271132945499">"Espera"</string>
     <string name="settings_bt_update_needs_repair" msgid="1310917691218455907">"Torna a vincular el comandament"</string>
     <string name="settings_enabled" msgid="431464375814187683">"Activat"</string>
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Activa HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC et permet controlar i activar i desactivar automàticament els dispositius en què l\'hagis activat amb un únic comandament.\n\nNota: Comprova que HDMI-CEC està activat al televisor i en altres dispositius HDMI. El nom d\'HDMI-CEC pot variar segons el fabricant, com en els casos següents:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Entra en mode d\'espera quan canviïs la font d\'entrada"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Si actives aquesta opció de configuració i tens HDMI-CEC activat al televisor, aquest dispositiu entrarà automàticament en mode d\'espera poc després que canviïs a una altra entrada del televisor. Això pot ajudar a posar en pausa el contingut i reduir el consum d\'energia quan no estàs mirant contingut de manera activa."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configura els botons del comandament"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controla el volum, l\'engegada i l\'entrada de televisors, receptors i barres de so"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Troba el meu comandament"</string>
diff --git a/libraries/BluetoothServices/res/values-cs/strings.xml b/libraries/BluetoothServices/res/values-cs/strings.xml
index 99ecaab..ccd701f 100644
--- a/libraries/BluetoothServices/res/values-cs/strings.xml
+++ b/libraries/BluetoothServices/res/values-cs/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Aktivovat HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC umožňuje ovládat a automaticky zapínat/vypínat jiná zařízení s podporou HDMI-CEC, a to pomocí jediného dálkového ovládání.\n\nPoznámka: Zkontrolujte, zda je v televizoru a ostatních zařízeních HDMI aktivováno HDMI-CEC. Výrobci pro technologii HDMI-CEC často používají jiný název, např.:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Aktivujte pohotovostní režim při přepnutí vstupu na jiný zdroj"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Když aktivujete toto nastavení a budete mít na televizi aktivováno HDMI-CEC, toto zařízení automaticky přejde do pohotovostního režimu krátce poté, co na televizi přepnete na jiný vstup. Pomůže vám to pozastavit obsah a snížit spotřebu energie, když televizi aktivně nesledujete."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Nastavení vzdálených tlačítek"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Ovládání hlasitosti, vstupu a napájení televizorů, přijímačů a soundbarů"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Vyhledání dálkového ovládání"</string>
diff --git a/libraries/BluetoothServices/res/values-da/strings.xml b/libraries/BluetoothServices/res/values-da/strings.xml
index 6d2b534..effdf83 100644
--- a/libraries/BluetoothServices/res/values-da/strings.xml
+++ b/libraries/BluetoothServices/res/values-da/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Aktivér HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Med HDMI-CEC kan du styre og automatisk aktivere/deaktivere andre enheder med HDMI-CEC ved hjælp af en enkelt fjernbetjening.\n\nBemærk! Du skal sørge for, at HDMI-CEC er aktiveret på dit fjernsyn og dine andre HDMI-enheder. Producenter bruger ofte forskellige navne for HDMI-CEC, f.eks.:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Gå på standby, når du skifter indgang til en anden kilde"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Når du aktiverer denne indstilling og har aktiveret HDMI-CEC på dit fjernsyn, går denne enhed automatisk i standbytilstand, kort efter du skifter til en anden indgang på dit fjernsyn. Dette kan hjælpe med at sætte indholdet på pause og reducere strømforbruget, når du ikke ser indholdet."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Konfigurer fjern­betjenings­knapper"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Styr lydstyrke, afbryderknap og indgangskilde på fjernsyn, modtagere og soundbars"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Find min fjernbetjening"</string>
diff --git a/libraries/BluetoothServices/res/values-de/strings.xml b/libraries/BluetoothServices/res/values-de/strings.xml
index 5458f4e..7668302 100644
--- a/libraries/BluetoothServices/res/values-de/strings.xml
+++ b/libraries/BluetoothServices/res/values-de/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC aktivieren"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Mit HDMI-CEC kannst du andere HDMI-CEC-fähige Geräte verwalten und automatisch mit einer einzigen Fernbedienung aktivieren/deaktivieren.\n\nHinweis: Beachte, dass hierfür HDMI-CEC auf deinem Fernseher und anderen HDMI-Geräten aktiviert sein muss. Hersteller haben häufig unterschiedliche Namen für HDMI-CEC. Zum Beispiel:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Bereitschaftsmodus aktivieren, wenn der Eingang zu einer anderen Quelle wechselt"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Wenn du diese Einstellung aktivierst und HDMI‑CEC auf deinem Fernseher aktiviert ist, wechselt dieses Gerät automatisch in den Stand‑by-Modus, kurz nachdem du auf einen anderen Eingang deines Fernsehers umgeschaltet hast. Dadurch können Inhalte pausiert und der Stromverbrauch reduziert werden, wenn du dir nicht aktiv Inhalte ansiehst."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Tasten der Fernbedienung einrichten"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Lautstärke, Ein/Aus und Eingang auf Fernsehern, Receivern und Soundbars steuern"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Fernbedienung finden"</string>
diff --git a/libraries/BluetoothServices/res/values-el/strings.xml b/libraries/BluetoothServices/res/values-el/strings.xml
index c73708e..698cc04 100644
--- a/libraries/BluetoothServices/res/values-el/strings.xml
+++ b/libraries/BluetoothServices/res/values-el/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Ενεργοποίηση HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Το HDMI-CEC σάς επιτρέπει να ελέγχετε και να ενεργοποιείτε/απενεργοποιείτε αυτόματα άλλες συσκευές με δυνατότητα HDMI-CEC, με ένα μόνο τηλεχειριστήριο.\n\nΣημείωση: Επιβεβαιώστε ότι το HDMI-CEC είναι ενεργοποιημένο στην τηλεόρασή σας και σε άλλες συσκευές HDMI. Οι κατασκευαστές έχουν συχνά διαφορετικές ονομασίες για το HDMI-CEC, για παράδειγμα:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Μετάβαση σε κατάσταση αναμονής κατά την εναλλαγή εισόδου σε άλλη πηγή"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Όταν ενεργοποιείτε αυτή τη ρύθμιση και έχετε ενεργό το HDMI-CEC στην τηλεόρασή σας, αυτή η συσκευή θα μεταβαίνει αυτόματα σε κατάσταση αναμονής λίγο αφότου κάνετε εναλλαγή σε διαφορετική είσοδο της τηλεόρασης. Αυτό μπορεί να βοηθήσει στην παύση του περιεχομένου και στη μείωση της κατανάλωσης ενέργειας, όταν δεν παρακολουθείτε ενεργά."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Ρύθμιση κουμπιών τηλεχειριστηρίου"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Έλεγχος έντασης ήχου, λειτουργίας και πηγών εισόδου σε τηλεοράσεις, δέκτες και soundbar"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Εύρεση τηλεχειριστηρίου"</string>
diff --git a/libraries/BluetoothServices/res/values-en-rAU/strings.xml b/libraries/BluetoothServices/res/values-en-rAU/strings.xml
index 99ae238..616b772 100644
--- a/libraries/BluetoothServices/res/values-en-rAU/strings.xml
+++ b/libraries/BluetoothServices/res/values-en-rAU/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Enable HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC allows you to control and automatically turn on/off other HDMI-CEC enabled devices with a single remote control.\n\nNote: Ensure HDMI-CEC is enabled on your TV and other HDMI devices. Manufacturers often have different names for HDMI-CEC, for example:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Enter standby when switching input to another source"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"When you enable this setting and have HDMI-CEC enabled on your TV, this device will automatically enter standby shortly after you switch to a different input on your TV. This may help to pause content and reduce power consumption when you aren\'t actively watching."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Set up remote buttons"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Control volume, power, input on TVs, receivers and soundbars"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Find my remote"</string>
diff --git a/libraries/BluetoothServices/res/values-en-rCA/strings.xml b/libraries/BluetoothServices/res/values-en-rCA/strings.xml
index 78349ed..7c28d1c 100644
--- a/libraries/BluetoothServices/res/values-en-rCA/strings.xml
+++ b/libraries/BluetoothServices/res/values-en-rCA/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Enable HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC allows you to control and automatically turn on/off other HDMI-CEC enabled devices with a single remote control.\n\nNote: Ensure HDMI-CEC is enabled on your TV and other HDMI devices. Manufacturers often have different names for HDMI-CEC, for example:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Enter standby when switching input to another source"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"When you enable this setting and have HDMI-CEC enabled on your TV, this device will automatically enter standby shortly after you switch to a different input on your TV. This may help pause content and reduce power consumption when you aren\'t actively watching."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Set up remote buttons"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Control volume, power, input on TVs, receivers and soundbars"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Find my remote"</string>
diff --git a/libraries/BluetoothServices/res/values-en-rGB/strings.xml b/libraries/BluetoothServices/res/values-en-rGB/strings.xml
index 99ae238..616b772 100644
--- a/libraries/BluetoothServices/res/values-en-rGB/strings.xml
+++ b/libraries/BluetoothServices/res/values-en-rGB/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Enable HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC allows you to control and automatically turn on/off other HDMI-CEC enabled devices with a single remote control.\n\nNote: Ensure HDMI-CEC is enabled on your TV and other HDMI devices. Manufacturers often have different names for HDMI-CEC, for example:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Enter standby when switching input to another source"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"When you enable this setting and have HDMI-CEC enabled on your TV, this device will automatically enter standby shortly after you switch to a different input on your TV. This may help to pause content and reduce power consumption when you aren\'t actively watching."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Set up remote buttons"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Control volume, power, input on TVs, receivers and soundbars"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Find my remote"</string>
diff --git a/libraries/BluetoothServices/res/values-en-rIN/strings.xml b/libraries/BluetoothServices/res/values-en-rIN/strings.xml
index 99ae238..616b772 100644
--- a/libraries/BluetoothServices/res/values-en-rIN/strings.xml
+++ b/libraries/BluetoothServices/res/values-en-rIN/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Enable HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC allows you to control and automatically turn on/off other HDMI-CEC enabled devices with a single remote control.\n\nNote: Ensure HDMI-CEC is enabled on your TV and other HDMI devices. Manufacturers often have different names for HDMI-CEC, for example:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Enter standby when switching input to another source"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"When you enable this setting and have HDMI-CEC enabled on your TV, this device will automatically enter standby shortly after you switch to a different input on your TV. This may help to pause content and reduce power consumption when you aren\'t actively watching."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Set up remote buttons"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Control volume, power, input on TVs, receivers and soundbars"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Find my remote"</string>
diff --git a/libraries/BluetoothServices/res/values-es-rUS/strings.xml b/libraries/BluetoothServices/res/values-es-rUS/strings.xml
index 6997f2e..372f992 100644
--- a/libraries/BluetoothServices/res/values-es-rUS/strings.xml
+++ b/libraries/BluetoothServices/res/values-es-rUS/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Habilitar HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC te permite controlar y activar/desactivar automáticamente dispositivos compatibles con HDMI-CEC con un único control remoto.\n\nNota: Asegúrate de que HDMI-CEC esté habilitado en tu TV y otros dispositivos HDMI. Con frecuencia, los fabricantes tienen diferentes nombres para HDMI-CEC, como los siguientes:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Entrar en modo en espera cuando se cambia la entrada a otra fuente"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Si habilitas este parámetro de configuración y tienes HDMI-CEC habilitado en la TV, el dispositivo entrará automáticamente en modo de espera poco después de que cambies a una entrada diferente en la TV. Esto puede ayudar a pausar el contenido y reducir el consumo de energía cuando no estás mirando activamente."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configura botones de control remoto"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controla el volumen, el encendido y la entrada en TVs, receptores y barras de sonido"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Buscar mi control remoto"</string>
diff --git a/libraries/BluetoothServices/res/values-es/strings.xml b/libraries/BluetoothServices/res/values-es/strings.xml
index 8699f5a..436a085 100644
--- a/libraries/BluetoothServices/res/values-es/strings.xml
+++ b/libraries/BluetoothServices/res/values-es/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Habilitar HDMI‑CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC te permite controlar y activar o desactivar automáticamente otros dispositivos habilitados con HDMI-CEC con un solo mando.\n\nNota: HDMI-CEC debe estar habilitado en tu TV y otros dispositivos HDMI. Los fabricantes suelen usar diferentes nombres para HDMI-CEC, como:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Entrar en modo Inactivo al cambiar la entrada a otra fuente"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Si habilitas este ajuste y tienes HDMI-CEC habilitado en tu televisión, este dispositivo entrará automáticamente en modo Inactivo poco después de que cambies a otra entrada en tu televisión. Esto puede ayudar a pausar el contenido y reducir el consumo de energía cuando no estás viendo contenido activamente."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configurar botones del mando"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controlar el volumen, el encendido y la fuente de entrada de televisiones, receptores AV y barras de sonido"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Encontrar mi mando a distancia"</string>
diff --git a/libraries/BluetoothServices/res/values-et/strings.xml b/libraries/BluetoothServices/res/values-et/strings.xml
index 66a544c..8ebe2c6 100644
--- a/libraries/BluetoothServices/res/values-et/strings.xml
+++ b/libraries/BluetoothServices/res/values-et/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Luba HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC võimaldab teil ühe juhtimispuldiga juhtida ja automaatselt sisse või välja lülitada teisi HDMI-CEC-toega seadmeid.\n\nMärkus. Veenduge, et HDMI-CEC oleks lubatud teie teleris ja muudes HDMI-seadmetes. Tootjatel on HDMI-CEC jaoks tihti teistsugused nimed, näiteks:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Lülituge ooterežiimile, kui lülitate sisendi teisele allikale"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Kui lubate selle seade ja teie teleris on lubatud HDMI-CEC-funktsioon, lülitub see seade varsti pärast teleri teisele sisendile lülitamist automaatselt ooterežiimile. See võib aidata sisu peatada ja vähendada energiatarbimist, kui te aktiivselt ei vaata."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Kaugjuhtimispuldi nuppude seadistamine"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Helitugevuse, toite ja sisendi juhtimine telerites, vastuvõtjates ning heliribades"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Leia mu pult"</string>
diff --git a/libraries/BluetoothServices/res/values-eu/strings.xml b/libraries/BluetoothServices/res/values-eu/strings.xml
index acbb53d..bcbb650 100644
--- a/libraries/BluetoothServices/res/values-eu/strings.xml
+++ b/libraries/BluetoothServices/res/values-eu/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Gaitu HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC eginbideari esker, hura gaituta daukaten beste gailu batzuk kontrolatzeko eta automatikoki aktibatu eta desaktibatzeko aukera duzu, den-dena urruneko kontrolagailu bakarra erabilita.\n\nOharra: ziurtatu HDMI-CEC gaituta daukazula telebistan eta bestelako HDMI gailuetan. Fabrikatzaile batzuek beste nolabait izendatu ohi dute HDMI-CEC, adibidez:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Jarri egonean moduan sarrera-iturburua aldatzean"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Ezarpen hau gaitzen baduzu eta telebistan HDMI-CEC gaituta badago, gailu hau egonean moduan jarriko da automatikoki telebistan beste sarrera-iturburu batera aldatu ondoren. Horrela, errazagoa izango da edukia pausatzea eta energia-kontsumoa murriztea telebista aktiboki ikusten ari ez zarenean."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Konfiguratu urruneko kontrolagailuaren botoiak"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Kontrolatu telebista, hargailu eta soinu-barren bolumena, etengailua eta sarrera"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Bilatu urruneko kontrolagailua"</string>
diff --git a/libraries/BluetoothServices/res/values-fa/strings.xml b/libraries/BluetoothServices/res/values-fa/strings.xml
index 035f413..01064a6 100644
--- a/libraries/BluetoothServices/res/values-fa/strings.xml
+++ b/libraries/BluetoothServices/res/values-fa/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"فعال کردن HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC به شما اجازه می‌دهد سایر دستگاه‌های دارای قابلیت HDMI-CEC را تنها با یک کنترل ازراه‌دور کنترل و به‌طور خودکار روشن/خاموش کنید.\n\nتوجه: مطمئن شوید HDMI-CEC در تلویزیون و سایر دستگاه‌های HDMI فعال باشد. سازندگان اغلب نام‌های مختلفی برای HDMI-CEC دارند، برای مثال:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ورود به حالت آماده به‌کار وقتی ورودی به منبع دیگری تغییر می‌کند"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"وقتی این تنظیم را فعال می‌کنید و HDMI-CEC در تلویزیونتان فعال است، این دستگاه مدت کوتاهی پس‌از آنکه به ورودی دیگری در تلویزیون جابه‌جا می‌شوید، به‌طور خودکار به حالت آماده به‌کار می‌رود. این کار می‌تواند به موقتاً متوقف شدن محتوا و کاهش مصرف برق وقتی درحال تماشای فعال نیستید کمک کند."</string>
     <string name="settings_axel" msgid="8253298947221430993">"راه‌اندازی دکمه‌های کنترل ازراه‌دور"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"میزان صدا، ورودی، و روشن/خاموش شدن تلویزیون‌ها، گیرنده‌ها، و بلندگوهای ستونی را کنترل کنید"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"پیدا کردن کنترل از راه دور"</string>
diff --git a/libraries/BluetoothServices/res/values-fi/strings.xml b/libraries/BluetoothServices/res/values-fi/strings.xml
index 9914bb1..7713cc6 100644
--- a/libraries/BluetoothServices/res/values-fi/strings.xml
+++ b/libraries/BluetoothServices/res/values-fi/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Ota käyttöön HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC:n avulla voit ohjata muita HDMI-CEC-yhteensopivia laitteita ja käynnistää ja sammuttaa niitä yhdellä kaukosäätimellä.\n\nHuom. Varmista, että HDMI-CEC on käytössä televisiossasi ja muissa HDMI-laitteissa. Valmistajilla on usein eri nimiä HDMI-CEC:lle, esimerkiksi:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Siirry valmiustilaan, kun vaihdat toiseen lähteeseen"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Kun otat tämän asetuksen käyttöön ja HDMI-CEC on käytössä televisiossa, laite siirtyy automaattisesti valmiustilaan pian sen jälkeen, kun olet vaihtanut televisiossa toiseen tuloon. Tämä voi auttaa keskeyttämään sisällön ja vähentämään virrankulutusta, kun et katso aktiivisesti."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Valitse kaukosäätimen painikkeet"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Ohjaa äänenvoimakkuutta, virtaa, TV:n tuloja, vastaanottimia ja soundbar-kaiuttimia"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Etsi kaukosäätimeni"</string>
diff --git a/libraries/BluetoothServices/res/values-fr-rCA/strings.xml b/libraries/BluetoothServices/res/values-fr-rCA/strings.xml
index 8c57291..a38ccd1 100644
--- a/libraries/BluetoothServices/res/values-fr-rCA/strings.xml
+++ b/libraries/BluetoothServices/res/values-fr-rCA/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Activer le HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Le HDMI-CEC vous permet de commander et d\'allumer/d\'éteindre d\'autres appareils compatibles HDMI-CEC à l\'aide d\'une simple télécommande.\n\nRemarque : Assurez-vous que le HDMI-CEC est activé sur votre téléviseur et vos autres appareils HDMI. Les fabricants utilisent souvent un nom différent pour la technologie HDMI-CEC. Par exemple :"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung : Anynet+\nLG : SimpLink\nSony : BRAVIA Sync\nPhilips : EasyLink\nSharp : Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Passer en mode veille lors du passage de l\'entrée à une autre source"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Lorsque vous activez ce paramètre et que la fonctionnalité HDMI-CEC est activée sur votre téléviseur, cet appareil se met automatiquement en veille peu de temps après que vous ayez changé d\'entrée sur votre téléviseur. Cela peut permettre de mettre le contenu en pause et de réduire la consommation d\'énergie lorsque vous ne regardez pas activement."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configurer les boutons de la télécommande"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Contrôlez le volume, l\'alimentation, les entrées sur les téléviseurs, les récepteurs et les barres de son"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Localiser ma télécommande"</string>
diff --git a/libraries/BluetoothServices/res/values-fr/strings.xml b/libraries/BluetoothServices/res/values-fr/strings.xml
index 9dad6cb..a6ba691 100644
--- a/libraries/BluetoothServices/res/values-fr/strings.xml
+++ b/libraries/BluetoothServices/res/values-fr/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Activer le HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Le HDMI-CEC vous permet de contrôler et d\'allumer ou d\'éteindre automatiquement d\'autres appareils sur lequel il est activé à l\'aide d\'une télécommande unique.\n\nRemarque : Assurez-vous que le HDMI-CEC est activé sur votre téléviseur et sur d\'autres appareils HDMI. Les fabricants utilisent souvent d\'autres termes pour faire référence au HDMI-CEC, par exemple :"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung : Anynet+\nLG : SimpLink\nSony : BRAVIA Sync\nPhilips : EasyLink\nSharp : Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Passer en veille lorsque la source est changée"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Lorsque vous activez ce paramètre et que le HDMI-CEC est activé sur votre TV, cet appareil passe automatiquement en veille peu de temps après que vous avez changé d\'entrée sur votre TV. Cela peut vous aider à mettre en pause le contenu et à réduire la consommation d\'énergie lorsque vous ne regardez pas activement."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configurer les boutons de la télécommande"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Contrôlez le volume, l\'alimentation et le mode d\'entrée sur vos téléviseurs, vos récepteurs et vos barres de son"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Trouver ma télécommande"</string>
diff --git a/libraries/BluetoothServices/res/values-gl/strings.xml b/libraries/BluetoothServices/res/values-gl/strings.xml
index 17bfe8c..87a475a 100644
--- a/libraries/BluetoothServices/res/values-gl/strings.xml
+++ b/libraries/BluetoothServices/res/values-gl/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Activar HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC permíteche controlar e activar/desactivar automaticamente outros dispositivos con HDMI-CEC a través dun mando a distancia.\n\nNota: HDMI-CEC debe estar activado no televisor e noutros dispositivos HDMI. Os fabricantes adoitan utilizar diferentes nomes para HDMI-CEC, por exemplo:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Pasar ao modo de espera ao cambiar a entrada a outra fonte"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Se tes habilitado HDMI-CEC na televisión e activas esta opción de configuración, este dispositivo pasará ao modo de espera de xeito automático ao pouco de que cambies a unha entrada diferente no televisor. Deste xeito, ponse o contido en pausa cando non o estás vendo de forma activa e redúcese o consumo enerxético."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configurar botóns do mando a distancia"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controla o volume, o acendido e a entrada nos receptores, barras de son e televisións"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Localizar o mando a distancia"</string>
diff --git a/libraries/BluetoothServices/res/values-gu/strings.xml b/libraries/BluetoothServices/res/values-gu/strings.xml
index 73f54bf..1a316bd 100644
--- a/libraries/BluetoothServices/res/values-gu/strings.xml
+++ b/libraries/BluetoothServices/res/values-gu/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC ચાલુ કરો"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC તમને બીજા HDMI-CEC  ચાલુ કરેલા ડિવાઇસને એક જ રિમોટ કન્ટ્રોલ વડે નિયંત્રિત અને ચાલુ/બંધ કરવા દે છે. \n\n નોંધ: HDMI-CEC તમારા ટીવી અને બીજા HDMI ડિવાઇસ પર ચાલુ  હોવાની ખાતરી કરો. ઘણી વખત ઉત્પાદકો HDMI-CEC માટે અલગ ધરાવતા હોય છે, ઉદાહરણ તરીકે:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA \nPhilips સિંક કરો: EasyLink\nSharp: Aquos લિંક"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ઇનપુટને બીજા સૉર્સ પર સ્વિચ કરતી વખતે સ્ટેન્ડબાયમાં દાખલ થાઓ"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"જ્યારે તમે આ સેટિંગ ચાલુ કરો અને તમારા ટીવી પર HDMI-CEC ચાલુ હોય, ત્યારે તમે તમારા ટીવી પર અલગ ઇનપુટ પર સ્વિચ કરો તે પછી ટૂંક સમયમાં આ ડિવાઇસ ઑટોમૅટિક રીતે સ્ટેન્ડબાયમાં દાખલ થશે. જ્યારે તમે સક્રિય રીતે ન જોઈ રહ્યાં હો, ત્યારે આ કન્ટેન્ટ થોભાવવામાં અને પાવર વપરાશ ઘટાડવામાં સહાય કરી શકે છે."</string>
     <string name="settings_axel" msgid="8253298947221430993">"રિમોટ બટનનું સેટઅપ કરો"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ટીવી, રિસીવર અને સાઉન્ડબાર પર વૉલ્યૂમ, પાવર અને ઇનપુટને નિયંત્રિત કરો"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"મારું રિમોટ શોધો"</string>
diff --git a/libraries/BluetoothServices/res/values-hi/strings.xml b/libraries/BluetoothServices/res/values-hi/strings.xml
index af65a04..4d70d99 100644
--- a/libraries/BluetoothServices/res/values-hi/strings.xml
+++ b/libraries/BluetoothServices/res/values-hi/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC चालू करें"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC की सुविधा से आप उन डिवाइस को एक रिमोट कंट्रोल से नियंत्रित और अपने आप चालू/बंद कर सकते हैं, जिन पर यह सुविधा काम करती है.\n\nनोट: अपने टीवी और दूसरे HDMI डिवाइस पर HDMI-CEC चालू करना याद रखें. अलग-अलग निर्माताओं के लिए अक्सर HDMI-CEC के अलग-अलग नाम होते हैं, जैसे:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"इनपुट को दूसरे सोर्स पर स्विच करने पर डिवाइस, स्टैंडबाय मोड में चला जाता है"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"अगर आपने इस सेटिंग को चालू किया है और टीवी पर एचडीएमआई-सीईसी की सुविधा चालू है, तो टीवी पर किसी दूसरे इनपुट का इस्तेमाल करने पर यह डिवाइस अपने-आप स्टैंडबाय मोड में चला जाएगा. इससे, वीडियो को रोकने और बिजली की खपत कम करने में मदद मिल सकती है."</string>
     <string name="settings_axel" msgid="8253298947221430993">"रिमोट के बटन सेट अप करें"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"आवाज़, पावर बटन, और इनपुट के विकल्पों को टीवी, AV रिसीवर, और साउंडबार पर कंट्रोल करें"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"मेरा रिमोट ढूंढें"</string>
diff --git a/libraries/BluetoothServices/res/values-hr/strings.xml b/libraries/BluetoothServices/res/values-hr/strings.xml
index fa60f83..e4b86d0 100644
--- a/libraries/BluetoothServices/res/values-hr/strings.xml
+++ b/libraries/BluetoothServices/res/values-hr/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Omogući HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC vam omogućuje da samo jednim daljinskim upravljačem upravljate drugim uređajima omogućenima za HDMI-CEC i automatski ih uključujete i isključujete.\n\nNapomena: Provjerite je li HDMI-CEC omogućen na vašem televizoru i drugim HDMI uređajima. Proizvođači često imaju različite nazive za HDMI-CEC, na primjer:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Prijeđi u stanje mirovanja pri prebacivanju ulaznog signala na drugi izvor"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Kad omogućite tu postavku i HDMI-CEC na svom TV-u, taj će uređaj automatski prijeći u stanje mirovanja nakon što se prebacite na drugi ulazni signal na TV-u. To može pomoći u pauziranju sadržaja i smanjenju potrošnje energije kad ne gledate aktivno."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Postavite gumbe na daljinskom upravljaču"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Upravljanje glasnoćom, uključivanjem, isključivanjem, ulazom na televizorima, prijemnicima i soundbarovima"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Pronađi moj daljinski upravljač"</string>
diff --git a/libraries/BluetoothServices/res/values-hu/strings.xml b/libraries/BluetoothServices/res/values-hu/strings.xml
index 0719ab5..4ba37d1 100644
--- a/libraries/BluetoothServices/res/values-hu/strings.xml
+++ b/libraries/BluetoothServices/res/values-hu/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC engedélyezése"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"A HDMI-CEC lehetővé teszi a többi HDMI-CEC-kompatibilis eszköz vezérlését és automatikus ki-/bekapcsolását egyetlen távvezérlő használatával.\n\nMegjegyzés: Győződjön meg arról, hogy a tévén és a többi HDMI-eszközön is engedélyezve van a HDMI-CEC. A különböző gyártók gyakran máshogy hívják a HDMI-CEC funkciót. Például:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Készenléti módba lépés, ha a bemenetet másik forrásra váltja"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Ha aktiválja ezt a beállítást, és a tévén engedélyezve van a HDMI-CEC, akkor az eszköz automatikusan készenléti módba lép, miután Ön átvált egy másik bemenetre a tévén. Ez segíthet a tartalomlejátszás szüneteltetésében, valamint csökkentheti az energiafogyasztást, amikor Ön nem nézi aktívan a tévét."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Távirányító gombjainak beállítása"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Hangerő, bekapcsológomb és bemenet kezelése tévén, vevőeszközön és hangprojektoron"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Find my remote"</string>
diff --git a/libraries/BluetoothServices/res/values-hy/strings.xml b/libraries/BluetoothServices/res/values-hy/strings.xml
index 1b20c3b..29da1b3 100644
--- a/libraries/BluetoothServices/res/values-hy/strings.xml
+++ b/libraries/BluetoothServices/res/values-hy/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Միացնել HDMI-CEC-ը"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Սարքերը, որոնք համատեղելի են HDMI-CEC հաղորդակարգի հետ, հնարավոր է կառավարել և ավտոմատ միացնել/անջատել մեկ հեռակառավարիչի միջոցով։\n\nՆշում. Համոզվեք, որ հաղորդակարգը միացված է հեռուստացույցում և մյուս HDMI սարքերում։ Տարբեր արտադրողներ HDMI-CEC հաղորդակարգի համար տարբեր անվանումներ են օգտագործում, օրինակ՝"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung-ը՝ Anynet+\nLG-ն՝ SimpLink\nSony-ն՝ BRAVIA Sync\nPhilips-ը՝ EasyLink\nSharp-ը՝ Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Անցնել սպասման ռեժիմին՝ մուտքի այլ աղբյուր ընտրելու դեպքում"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Երբ միացնեք այս կարգավորումը, և ձեր հեռուստացույցում միացված լինի HDMI-CEC-ը, այս սարքն ավտոմատ կանցնի սպասման ռեժիմին, հենց որ հեռուստացույցում այլ մուտք ընտրեք։ Դա կարող է օգնել դադարեցնել բովանդակության նվագարկումը և նվազեցնել էներգիայի սպառումը, երբ ոչինչ չդիտեք այդ պահին։"</string>
     <string name="settings_axel" msgid="8253298947221430993">"Հեռակառավարման վահանակի կոճակների կարգավորում"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Միացրեք/անջատեք հեռուստացույցը, ընդունիչները և բարձրախոս-վահանակները, ինչպես նաև կառավարեք դրանց ձայնի ուժգնությունն ու մուտքի աղբյուրները"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Գտնել իմ հեռակառավարիչը"</string>
diff --git a/libraries/BluetoothServices/res/values-in/strings.xml b/libraries/BluetoothServices/res/values-in/strings.xml
index 1d8b7d1..e3119fb 100644
--- a/libraries/BluetoothServices/res/values-in/strings.xml
+++ b/libraries/BluetoothServices/res/values-in/strings.xml
@@ -24,7 +24,7 @@
     <string name="settings_bt_confirm_update" msgid="7490528407190318108">"Konfirmasi update remote"</string>
     <string name="settings_bt_update_summary" msgid="137113561617823800">"Selama proses update, koneksi remote Anda mungkin terputus sebentar."</string>
     <string name="settings_continue" msgid="5640776697820481568">"Lanjutkan"</string>
-    <string name="settings_cancel" msgid="1284029950430684039">"Batalkan"</string>
+    <string name="settings_cancel" msgid="1284029950430684039">"Batal"</string>
     <string name="settings_bt_update" msgid="8210371540974244481">"Update remote"</string>
     <string name="settings_bt_update_software_available" msgid="7002004529854458452">"Software baru tersedia"</string>
     <string name="settings_bt_update_available" msgid="414405852666517260">"Ada update"</string>
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Aktifkan HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC memungkinkan Anda mengontrol dan secara otomatis mengaktifkan/menonaktifkan perangkat lain yang memiliki HDMI-CEC aktif dengan satu remote kontrol.\n\nCatatan: Pastikan HDMI-CEC diaktifkan di TV Anda dan perangkat HDMI lainnya. Produsen biasanya memberikan nama yang berbeda untuk HDMI-CEC, misalnya:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Masuk ke mode standby saat beralih input ke sumber lain"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Jika Anda mengaktifkan setelan ini dan mengaktifkan HDMI-CEC di TV, perangkat ini akan otomatis masuk ke mode standby segera setelah Anda beralih ke input yang berbeda di TV. Hal ini mungkin dapat membantu menjeda konten dan mengurangi penggunaan daya saat Anda tidak aktif menonton."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Siapkan tombol remote"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Mengontrol volume, daya, input di TV, penerima, dan soundbar"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Temukan remote saya"</string>
@@ -76,16 +78,16 @@
     <string name="settings_devices_connected" msgid="3256213134907921013">"Terhubung"</string>
     <string name="settings_devices_paired" msgid="4460141776955368574">"Perangkat yang terhubung sebelumnya"</string>
     <string name="settings_pair_remote" msgid="7566753084479902759">"Sambungkan remote atau aksesori"</string>
-    <string name="bluetooth_disconnect" msgid="1385608885917484057">"Putuskan koneksi"</string>
+    <string name="bluetooth_disconnect" msgid="1385608885917484057">"Berhenti hubungkan"</string>
     <string name="bluetooth_connect" msgid="6283971929092004620">"Hubungkan"</string>
     <string name="bluetooth_rename" msgid="4433577238394058486">"Ganti nama"</string>
     <string name="bluetooth_forget" msgid="4933552074497360964">"Lupakan"</string>
     <string name="bluetooth_toggle_active_audio_output" msgid="494557568422711885">"Gunakan untuk audio TV"</string>
     <string name="bluetooth_connected_status" msgid="8391804274846835227">"Terhubung"</string>
-    <string name="bluetooth_disconnected_status" msgid="972515438988962457">"Terputus"</string>
+    <string name="bluetooth_disconnected_status" msgid="972515438988962457">"Tidak terhubung"</string>
     <string name="settings_devices_control" msgid="1862490057009510077">"Kontrol perangkat"</string>
     <string name="settings_bt_pair_title" msgid="1205942796805671508">"Hubungkan perangkat baru"</string>
-    <string name="pair_device_description" msgid="5145574754576245361">"Sebelum menghubungkan perangkat Bluetooth baru, pastikan perangkat dalam mode penyambungan. Untuk menghubungkan %1$s, tekan dan tahan %2$s + %3$s selama 3 detik."</string>
+    <string name="pair_device_description" msgid="5145574754576245361">"Sebelum menyambungkan perangkat Bluetooth baru, pastikan perangkat dalam mode penyambungan. Untuk menyambungkan %1$s, tekan %2$s + %3$s selama 3 detik."</string>
     <string name="pair_device_device_name" msgid="4004194247588260613">"Remote Android TV"</string>
     <string name="settings_bt_available_devices" msgid="6237789711837183219">"Perangkat yang tersedia"</string>
     <string name="settings_bt_empty_text" msgid="6228875847390369960">"Mencari perangkat…"</string>
diff --git a/libraries/BluetoothServices/res/values-is/strings.xml b/libraries/BluetoothServices/res/values-is/strings.xml
index c75680a..73d1e25 100644
--- a/libraries/BluetoothServices/res/values-is/strings.xml
+++ b/libraries/BluetoothServices/res/values-is/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Virkja HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC gerir þér kleift að stjórna og kveikja og slökkva sjálfkrafa á öðrum HDMI-CEC tækjum með einni fjarstýringu.\n\nAthugaðu: Gakktu úr skugga um að HDMI-CEC sé virkt í sjónvarpinu þínu og í öðrum HDMI-tækjum. Framleiðendur nota oft annað heiti fyrir HDMI-CEC, til dæmis:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Fara í biðstöðu þegar inntaki er skipt yfir á annan uppruna"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Þegar þú kveikir á þessari stillingu og kveikt er á HDMI-CEC í sjónvarpinu mun tækið sjálfkrafa fara í biðstöðu skömmu eftir að þú skiptir yfir í annað inntak í sjónvarpinu. Þetta getur til dæmis auðveldað þér að gera hlé á efnisspilun og dregið úr orkunotkun þegar þú ert ekki að horfa á sjónvarpið."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Setja upp hnappa fyrir fjarstýringu"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Stjórnaðu hljóðstyrk, afli, sjónvarpsinntaki, mögnurum og hljóðstöngum"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Finna fjarstýringuna mína"</string>
diff --git a/libraries/BluetoothServices/res/values-it/strings.xml b/libraries/BluetoothServices/res/values-it/strings.xml
index a6dac10..8e5a2ff 100644
--- a/libraries/BluetoothServices/res/values-it/strings.xml
+++ b/libraries/BluetoothServices/res/values-it/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Attiva HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ti consente di controllare e attivare/disattivare automaticamente con un singolo telecomando i dispositivi su cui è abilitato.\n\nNota: assicurati che HDMI-CEC sia abilitato sulla tua TV e sugli altri dispositivi HDMI. Spesso i produttori utilizzano nomi diversi per HDMI-CEC, ad esempio:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Attiva la modalità standby quando cambi l\'ingresso su un\'altra sorgente"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Se attivi questa impostazione e abiliti HDMI-CEC sulla TV, il dispositivo entrerà automaticamente in modalità standby poco dopo aver selezionato un ingresso diverso sulla TV. In questo modo, i contenuti vengono messi in pausa e il consumo di energia viene ridotto quando non guardi attivamente la TV."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configura tasti telecomando"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controlla volume, accensione/spegnimento e ingresso su TV, ricevitori e soundbar"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Trova il telecomando"</string>
diff --git a/libraries/BluetoothServices/res/values-iw/strings.xml b/libraries/BluetoothServices/res/values-iw/strings.xml
index d536b2e..5fc898e 100644
--- a/libraries/BluetoothServices/res/values-iw/strings.xml
+++ b/libraries/BluetoothServices/res/values-iw/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"הפעלת HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"בעזרת HDMI-CEC אפשר לשלוט, וגם להפעיל ולכבות באופן אוטומטי, מכשירים אחרים שמופעלת בהם התכונה HDMI-CEC, באמצעות שלט רחוק אחד.\n\nהערה: יש לוודא שהתכונה HDMI-CEC מופעלת בטלוויזיה ובמכשירי HDMI אחרים. ל-HDMI-CEC יש שמות שונים אצל יצרנים שונים, לדוגמה:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung:‎ Anynet+\nLG:‎ SimpLink\nSony:‎ BRAVIA Sync\nPhilips:‎ EasyLink\nSharp:‎ Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"כניסה למצב המתנה בזמן שינוי הקלט למקור אחר"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"כשמפעילים את ההגדרה הזו ומפעילים את HDMI-CEC בטלוויזיה, המכשיר הזה עובר למצב המתנה באופן אוטומטי זמן קצר אחרי שמעבירים את הקלט בטלוויזיה למקור אחר. האפשרות הזו עשויה לעזור להשהות תוכן ולהפחית את צריכת החשמל כשלא צופים בתוכן באופן פעיל."</string>
     <string name="settings_axel" msgid="8253298947221430993">"הגדרת הלחצנים בשלט הרחוק"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"שליטה בעוצמת הקול, בהפעלה, בקלט של טלוויזיות, ברסיברים ובמקרני קול"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"איפה השלט שלי"</string>
diff --git a/libraries/BluetoothServices/res/values-ja/strings.xml b/libraries/BluetoothServices/res/values-ja/strings.xml
index 9b436fb..a0caa3f 100644
--- a/libraries/BluetoothServices/res/values-ja/strings.xml
+++ b/libraries/BluetoothServices/res/values-ja/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC を有効にする"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC を利用すると、1 台のリモコンによる他の HDMI-CEC 対応デバイスの操作や電源の自動オン / オフが可能になります。\n\n注: テレビや他の HDMI デバイスで HDMI-CEC が有効になっていることをご確認ください。HDMI-CEC の呼び名は、下記のようにメーカーで異なることがあります。"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nソニー: ブラビアリンク\nフィリップス: EasyLink\nシャープ: Aquos ファミリンク"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"入力を別のソースに切り替えたときにスタンバイ モードにする"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"この設定を有効にしてテレビで HDMI-CEC を有効にすると、テレビで別の入力に切り替えた直後に、このデバイスは自動的にスタンバイ モードになります。視聴していないときはコンテンツを一時停止して、消費電力を抑えることができます。"</string>
     <string name="settings_axel" msgid="8253298947221430993">"リモコンボタンのセットアップ"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"テレビ、レシーバー、サウンドバーの音量、電源の操作や、入力の切り替えを行えます"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"リモコンを探す"</string>
diff --git a/libraries/BluetoothServices/res/values-ka/strings.xml b/libraries/BluetoothServices/res/values-ka/strings.xml
index 5707a75..f2ad970 100644
--- a/libraries/BluetoothServices/res/values-ka/strings.xml
+++ b/libraries/BluetoothServices/res/values-ka/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC-ის ჩართვა"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC საშუალებას გაძლევთ, ერთი პულტის მეშვეობით მართოთ და ავტომატურად ჩართოთ/გამორთოთ HDMI-CEC-ის მხარდაჭერის მქონე სხვა მოწყობილობები.\n\nშენიშვნა: დარწმუნდით, რომ თქვენს ტელევიზორზე და სხვა HDMI მოწყობილობებზე ჩართულია HDMI-CEC. მწარმოებლები HDMI-CEC-ს ხშირად სხვადასხვა სახელით მოიხსენიებენ, მაგალითად:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"მოლოდინის რეჟიმში გადასვლა შემავალი სიგნალის სხვა წყაროზე გადართვისას"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"ამ პარამეტრების ჩართვისას თქვენს ტელევიზორში, თუ ჩართული გაქვთ HDMI-CEC, მოწყობილობა ავტომატურად გადავა მოლოდინის რეჟიმში ტელევიზორის სხვა შემავალ სიგნალზე გადართვიდან მალევე. ეს დააპაუზებს კონტენტს და ხელს შეუწყობს ენერგომოხმარების შემცირებას, როდესაც აქტიურად არ უყურებთ."</string>
     <string name="settings_axel" msgid="8253298947221430993">"დისტანციური მართვის პულტის ღილაკების დაყენება"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ტელევიზორებზე, მიმღებებსა და ხმოვან პანელებზე ხმის, ელკვებისა და შემავალი სიგნალის მართვა"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"იპოვეთ ჩემი დისტანციური მართვის პულტი"</string>
diff --git a/libraries/BluetoothServices/res/values-kk/strings.xml b/libraries/BluetoothServices/res/values-kk/strings.xml
index 4912557..6f34ae5 100644
--- a/libraries/BluetoothServices/res/values-kk/strings.xml
+++ b/libraries/BluetoothServices/res/values-kk/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC функциясын қосу"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC протоколы басқа HDMI-CEC қосылған құрылғыларды бір пультпен басқаруға және автоматты түрде қосуға/өшіруге мүмкіндік береді.\n\nЕскертпе: HDMI-CEC протоколының теледидарда және басқа HDMI құрылғыларында қосулы екенін тексеріңіз. Өндірушілер HDMI-CEC үшін түрлі атауларды пайдаланады, мысалы:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Кірісті басқа көзге ауыстырғанда күту режиміне өту"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Бұл параметрді қоссаңыз және теледидарда HDMI-CEC қосылған болса, басқа кіріске ауысқаннан кейін, бұл құрылғы автоматты түрде күту режиміне өтеді. Бұл — контентті кідіртуге және сіз оны қарамаған кезде қуат тұтынуды азайтуға көмектеседі."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Пульт түймелерін реттеу"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Теледидардағы, қабылдағыштардағы және саундбарлардағы дыбыс деңгейін, қуатты, кіріс сигналының көздерін басқару"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Пультімді табу"</string>
diff --git a/libraries/BluetoothServices/res/values-km/strings.xml b/libraries/BluetoothServices/res/values-km/strings.xml
index 95023ce..5b022bb 100644
--- a/libraries/BluetoothServices/res/values-km/strings.xml
+++ b/libraries/BluetoothServices/res/values-km/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"បើក HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC អនុញ្ញាតឱ្យ​អ្នក​គ្រប់គ្រង​ និងបើក/បិទ​ឧបករណ៍​ដែល​អាច​ប្រើ HDMI-CEC ផ្សេង​ទៀត​ដោយស្វ័យប្រវត្តិ​តាមរយៈឧបករណ៍​​បញ្ជា​ពី​ចម្ងាយតែមួយ។\n\nចំណាំ៖ សូមប្រាកដ​ថា HDMI-CEC បានបើក​នៅលើ​ទូរទស្សន៍​ និងឧបករណ៍ HDMI ផ្សេងទៀត​របស់អ្នក។ ជាទូទៅ ក្រុមហ៊ុន​ផលិតឧបករណ៍ដាក់ឈ្មោះខុសៗ​គ្នាឱ្យ​ HDMI-CEC ឧទាហរណ៍៖"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung៖ Anynet+\nLG៖ SimpLink\nSony៖ BRAVIA Sync\nPhilips៖ EasyLink\nSharp៖ Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ចូលមុខងារសម្ងំ នៅពេលប្ដូរឧបករណ៍​បញ្ចូលទៅប្រភពផ្សេង"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"នៅពេលអ្នកបើកការ​កំណត់នេះ និងបានបើក HDMI-CEC នៅលើទូរទស្សន៍របស់អ្នក ឧបករណ៍នេះនឹងចូលមុខងារសម្ងំភ្លាមៗដោយស្វ័យប្រវត្តិ បន្ទាប់ពីអ្នកប្ដូរទៅឧបករណ៍​បញ្ចូលផ្សេងនៅលើទូរទស្សន៍របស់អ្នក។ ការធ្វើបែបនេះអាចជួយផ្អាកខ្លឹមសារ និងកាត់បន្ថយការប្រើប្រាស់ថាមពល នៅពេលអ្នកមិនមើលយ៉ាងសកម្មទេ។"</string>
     <string name="settings_axel" msgid="8253298947221430993">"រៀបចំ​ប៊ូតុងឧបករណ៍​បញ្ជា​ពី​ចម្ងាយ"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"គ្រប់គ្រងកម្រិតសំឡេង ថាមពល ប្រភពបញ្ចូលនៅលើទូរទស្សន៍ ឧបករណ៍ចាប់សំឡេងនិងរូបភាព និងរបារ​សំឡេង"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"ស្វែងរកឧបករណ៍​បញ្ជាពីចម្ងាយរបស់ខ្ញុំ"</string>
diff --git a/libraries/BluetoothServices/res/values-kn/strings.xml b/libraries/BluetoothServices/res/values-kn/strings.xml
index d226c95..08e8640 100644
--- a/libraries/BluetoothServices/res/values-kn/strings.xml
+++ b/libraries/BluetoothServices/res/values-kn/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC ಅನ್ನು ಸಕ್ರಿಯಗೊಳಿಸಿ"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC, ಒಂದೇ ರಿಮೋಟ್ ನಿಯಂತ್ರಣ ಬಳಸಿಕೊಂಡು ಇತರ HDMI-CEC ಸಕ್ರಿಯಗೊಳಿಸಿದ ಸಾಧನಗಳನ್ನು ನಿಯಂತ್ರಿಸಲು ಮತ್ತು ಸ್ವಯಂಚಾಲಿತವಾಗಿ ಆನ್/ಆಫ್ ಮಾಡಲು ನಿಮಗೆ ಅನುಮತಿಸುತ್ತದೆ.\n\nಸೂಚನೆ: ನಿಮ್ಮ ಟಿವಿ ಮತ್ತು ಇತರ HDMI ಸಾಧನಗಳಲ್ಲಿ HDMI-CEC ಸಕ್ರಿಯವಾಗಿರುವುದನ್ನು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ. ತಯಾರಕರು ಸಾಮಾನ್ಯವಾಗಿ HDMI-CEC ಗಾಗಿ ವಿವಿಧ ಹೆಸರುಗಳನ್ನು ಹೊಂದಿರುತ್ತಾರೆ, ಉದಾಹರಣೆಗೆ:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ಇನ್‌ಪುಟ್ ಅನ್ನು ಇನ್ನೊಂದು ಮೂಲಕ್ಕೆ ಬದಲಿಸುವಾಗ ಸ್ಟ್ಯಾಂಡ್‌ಬೈ ನಮೂದಿಸಿ"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"ನೀವು ಈ ಸೆಟ್ಟಿಂಗ್ ಅನ್ನು ಮತ್ತು ನಿಮ್ಮ ಟಿವಿಯಲ್ಲಿ HDMI-CEC ಅನ್ನು ಸಕ್ರಿಯಗೊಳಿಸಿದಾಗ, ನಿಮ್ಮ ಟಿವಿಯಲ್ಲಿ ನೀವು ಬೇರೆ ಇನ್‌ಪುಟ್‌ಗೆ ಬದಲಿಸಿದ ಸ್ವಲ್ಪ ಸಮಯದ ನಂತರ ಈ ಸಾಧನವು ಸ್ವಯಂಚಾಲಿತವಾಗಿ ಸ್ಟ್ಯಾಂಡ್‌ಬೈ ಅನ್ನು ಪ್ರವೇಶಿಸುತ್ತದೆ. ಇದು ಕಂಟೆಂಟ್ ಅನ್ನು ವಿರಾಮಗೊಳಿಸಲು ಸಹಾಯ ಮಾಡುತ್ತದೆ ಮತ್ತು ನೀವು ಸಕ್ರಿಯವಾಗಿ ವೀಕ್ಷಿಸದಿದ್ದಾಗ ವಿದ್ಯುತ್ ಬಳಕೆಯನ್ನು ಕಡಿಮೆ ಮಾಡಬಹುದು."</string>
     <string name="settings_axel" msgid="8253298947221430993">"ರಿಮೋಟ್ ಬಟನ್‌ಗಳನ್ನು ಸೆಟಪ್ ಮಾಡಿ"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ಟಿವಿಗಳು, ರಿಸೀವರ್‌ಗಳು ಮತ್ತು ಸೌಂಡ್‌ಬಾರ್‌ಗಳಲ್ಲಿ ವಾಲ್ಯೂಮ್, ಪವರ್, ಇನ್‌ಪುಟ್ ಅನ್ನು ನಿಯಂತ್ರಿಸಿ"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"ನನ್ನ ರಿಮೋಟ್ ಅನ್ನು ಹುಡುಕಿ"</string>
diff --git a/libraries/BluetoothServices/res/values-ko/strings.xml b/libraries/BluetoothServices/res/values-ko/strings.xml
index a0cadf7..a24a253 100644
--- a/libraries/BluetoothServices/res/values-ko/strings.xml
+++ b/libraries/BluetoothServices/res/values-ko/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC 사용"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC를 사용하면 다른 단일 리모컨과 사용 설정된 HDMI-CEC 기기를 자동으로 사용/사용 중지할 수 있습니다.\n\n참고: HDMI-CEC가 TV 및 다른 HDMI 기기에서 사용 설정되었는지 확인하세요. 제조업체에서 HDMI-CEC에 다른 이름을 사용하는 경우도 있습니다. 예:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"삼성: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"입력을 다른 소스로 전환할 때 대기 모드로 전환"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"이 설정을 사용하고 TV에서 HDMI-CEC를 사용 설정하면, TV에서 다른 입력으로 전환하는 즉시 이 기기가 자동으로 대기 모드로 전환됩니다. 이 기능을 사용하면 콘텐츠를 일시중지할 뿐만 아니라 시청하지 않을 때 전력 소비를 줄일 수 있습니다."</string>
     <string name="settings_axel" msgid="8253298947221430993">"리모컨 버튼 설정"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"TV, 수신기 및 사운드바의 볼륨, 전원, 입력을 제어합니다."</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"내 리모컨 찾기"</string>
diff --git a/libraries/BluetoothServices/res/values-ky/strings.xml b/libraries/BluetoothServices/res/values-ky/strings.xml
index 672c670..56d541c 100644
--- a/libraries/BluetoothServices/res/values-ky/strings.xml
+++ b/libraries/BluetoothServices/res/values-ky/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC функциясын иштетүү"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC функциясы бир гана алыстан башкаруу куралынын жардамы менен, HDMI-CEC аркылуу иштетилген башка түзмөктөрдү көзөмөлдөөгө жана автоматтык түрдө күйгүзүп/өчүрүүгө мүмкүнчүлүк берет.\n\nЭскертүү: HDMI-CEC функциясы сыналгыңызда жана башка HDMI түзмөктөрүндө иштетилгенин текшериңиз. Өндүрүүчүлөр HDMI-CEC функциясын көп учурларда башкача атап коюшу мүмкүн, мисалы:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Киргизүүнү башка булакка которгондо күтүү режимине өтүү"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Бул функция жана сыналгыда HDMI-CEC иштетилсе, түзмөк сыналгыңыздагы башка киргизүүгө өткөндөн көп өтпөй автоматтык түрдө күтүү режимине өтөт. Бул контентти тындырууга жана аны жигердүү көрбөгөнүңүздө энергияны керектөөнү азайтууга жардам берет."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Пульттун баскычтарын тууралоо"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Сыналгыларда, ресиверлерде жана үн такталарында үндүн катуулугун, күйгүзүү/өчүрүүнү жана киргизүүнү башкаруу"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Пультумду табуу"</string>
diff --git a/libraries/BluetoothServices/res/values-lo/strings.xml b/libraries/BluetoothServices/res/values-lo/strings.xml
index 7abb0a3..aa0839f 100644
--- a/libraries/BluetoothServices/res/values-lo/strings.xml
+++ b/libraries/BluetoothServices/res/values-lo/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"ເປີດໃຊ້ HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ຈະເຮັດໃຫ້ທ່ານສາມາດຄວບຄຸມ ແລະ ເປີດ/ປິດ ອຸປະກອນທີ່ມີ HDMI-CEC ອື່ນໆໄດ້ໂດຍອັດຕະໂນມັດດ້ວຍການໃຊ້ຣີໂໝດອັນດຽວ.\n\nໝາຍເຫດ: ກະລຸນາກວດສອບວ່າມີການເປີດໃຊ້ HDMI-CEC ຢູ່ໂທລະທັດ ແລະ ອຸປະກອນ HDMI ອື່ນໆຂອງທ່ານແລ້ວ. ຜູ້ພັດທະນາມັກຈະຕັ້ງຊື່ທີ່ແຕກຕ່າງກັນໄປສຳລັບ HDMI-CEC, ຕົວຢ່າງ:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ເຂົ້າສູ່ໂໝດສະແຕນບາຍເມື່ອປ່ຽນອິນພຸດໄປຫາແຫຼ່ງທີ່ມາອື່ນ"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"ເມື່ອທ່ານເປີດໃຊ້ການຕັ້ງຄ່ານີ້ ແລະ HDMI-CEC ຢູ່ໂທລະທັດຂອງທ່ານ, ອຸປະກອນນີ້ຈະເຂົ້າສູ່ໂໝດສະແຕນບາຍໂດຍອັດຕະໂນມັດໃນອີກບໍ່ດົນຫຼັງຈາກທີ່ທ່ານປ່ຽນໄປໃຊ້ອິນພຸດອື່ນຢູ່ໂທລະທັດຂອງທ່ານ. ການດຳເນີນການນີ້ອາດຊ່ວຍຢຸດເນື້ອຫາໄວ້ຊົ່ວຄາວ ແລະ ຫຼຸດການໃຊ້ພະລັງງານເມື່ອທ່ານບໍ່ໄດ້ກຳລັງເບິ່ງຢູ່."</string>
     <string name="settings_axel" msgid="8253298947221430993">"ຕັ້ງຄ່າປຸ່ມຣີໂໝດ"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ຄວບຄຸມລະດັບສຽງ, ການເປີດປິດ, ອິນພຸດຢູ່ໂທລະທັດ, ຕົວຮັບສັນຍານ ແລະ ລຳໂພງຊາວບາ"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"ຊອກຫາຣີໂໝດຂອງຂ້ອຍ"</string>
diff --git a/libraries/BluetoothServices/res/values-lt/strings.xml b/libraries/BluetoothServices/res/values-lt/strings.xml
index f668ed2..a5bdbd1 100644
--- a/libraries/BluetoothServices/res/values-lt/strings.xml
+++ b/libraries/BluetoothServices/res/values-lt/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Įgalinti HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Naudodami HDMI-CEC galite valdyti ir automatiškai įjungti / išjungti kitus įrenginius, kuriuose įgalinta HDMI-CEC, vienu nuotolinio valdymo pulteliu.\n\nPastaba: įsitikinkite, kad HDMI-CEC yra įgalinta jūsų TV ir kituose HDMI įrenginiuose. Gamintojai dažnai HDMI-CEC pavadina skirtingais pavadinimais, pavyzdžiui:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"„Samsung“: „Anynet+“\nLG: „SimpLink“\n„Sony“: „BRAVIA Sync“\n„Philips“: „EasyLink“\n„Sharp“: „Aquos Link“"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Budėjimo režimo įjungimas, kai įvestis perjungiama į kitą šaltinį"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Kai įgalinsite šį nustatymą ir televizoriuje įgalinsite HDMI-CEC, šis įrenginys automatiškai pereis į budėjimo režimą netrukus po to, kai perjungsite į kitą televizoriaus įvestį. Tai gali padėti pristabdyti turinį ir sumažinti energijos sąnaudas, kai nežiūrite aktyviai."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Nuotolinio valdymo pultelio mygtukų nustatymas"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Valdykite TV, imtuvų ir garso kolonėlių garsumą, maitinimą bei įvestį"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Rasti nuotolinio valdymo pultelį"</string>
diff --git a/libraries/BluetoothServices/res/values-lv/strings.xml b/libraries/BluetoothServices/res/values-lv/strings.xml
index f1bfcb0..bfbf745 100644
--- a/libraries/BluetoothServices/res/values-lv/strings.xml
+++ b/libraries/BluetoothServices/res/values-lv/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Iespējot HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ļauj jums kontrolēt un automātiski ieslēgt/izslēgt citas ierīces ar iespējotu HDMI-CEC, izmantojot vienu tālvadības ierīci.\n\nPiezīme. Noteikti iespējojiet HDMI-CEC savā televizorā un citās HDMI ierīcēs. Ražotāji bieži izmanto atšķirīgus HDMI-CEC nosaukumus (skatiet tālāk piemērus)."</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Gaidstāves režīma ieslēgšana, kad tiek pārslēgta ievade uz citu avotu"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Ja iespējosiet šo iestatījumu un televizorā būs iespējota funkcija HDMI-CEC, tad šī ierīce automātiski pāries gaidīšanas režīmā neilgi pēc tam, kad televizorā pārslēgsiet uz citu ievadi. Tas var palīdzēt pārtraukt satura atskaņošanu un samazināt enerģijas patēriņu, kad tieši neskatāties TV."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Tālvadības ierīces pogu iestatīšana"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Kontrolējiet skaļumu, ieslēgšanu un izslēgšanu, kā arī televizoru, uztvērēju un skaņas joslu ieejas avotus."</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Tālvadības ierīces atrašana"</string>
diff --git a/libraries/BluetoothServices/res/values-mk/strings.xml b/libraries/BluetoothServices/res/values-mk/strings.xml
index 1eb2e44..a07a9c8 100644
--- a/libraries/BluetoothServices/res/values-mk/strings.xml
+++ b/libraries/BluetoothServices/res/values-mk/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Овозможи HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ви овозможува да контролирате и автоматски да вклучувате/исклучувате други уреди што поддржуваат HDMI-CEC со еден далечински управувач.\n\nЗабелешка: Проверете дали е овозможен HDMI-CEC на телевизорот и на другите HDMI-уреди. Производителите честопати имаат различни имиња за HDMI-CEC, на пример:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Влезете во „Режим на подготвеност“ кога ќе го префрлите влезот на друг извор"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Кога ќе ја овозможите поставкава и ќе овозможите HDMI-CEC на вашиот телевизор, уредов ќе влезе во „Режим на подготвеност“ автоматски набргу откако ќе се префрлите на друг влез на вашиот телевизор. Ова може да помогне да се паузираат содржините и да се намали потрошувачката на енергија кога не гледате активно."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Поставете копчиња на далечинскиот управувач"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Контролирајте ги јачината на звукот, вклучувањето, влезот на телевизорите, приемниците и звучниците"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Најди го мојот далечински управувач"</string>
diff --git a/libraries/BluetoothServices/res/values-ml/strings.xml b/libraries/BluetoothServices/res/values-ml/strings.xml
index cfc55e6..e29b559 100644
--- a/libraries/BluetoothServices/res/values-ml/strings.xml
+++ b/libraries/BluetoothServices/res/values-ml/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC പ്രവർത്തനക്ഷമമാക്കുക"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC പ്രവര്‍ത്തനക്ഷമമാക്കിയ മറ്റ് ഉപകരണങ്ങള്‍ ഒരു റിമോട്ട് കണ്‍ട്രോള്‍ ഉപയോഗിച്ച് നിയന്ത്രിക്കാനും സ്വയമേവ ഓണാക്കാനും/ഓഫാക്കാനും HDMI-CEC നിങ്ങളെ അനുവദിക്കുന്നു. \n\nകുറിപ്പ്: നിങ്ങളുടെ ടിവിയിലും മറ്റ് HDMI ഉപകരണങ്ങളിലും HDMI-CEC പ്രവര്‍ത്തനക്ഷമമാക്കിയിട്ടുണ്ടെന്ന് ഉറപ്പാക്കുക. HDMI-CEC-ക്ക് നിര്‍മ്മാതാക്കള്‍ പലപ്പോഴും വ്യത്യസ്‌ത പേരുകള്‍ നല്‍കാറുണ്ട്, ഉദാഹരണത്തിന്:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"മറ്റൊരു ഉറവിടത്തിലേക്ക് ഇൻപുട്ട് മാറുമ്പോൾ സ്റ്റാൻഡ്ബൈ നൽകുക"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"നിങ്ങൾ ഈ ക്രമീകരണം പ്രവർത്തനക്ഷമമാക്കുകയും നിങ്ങളുടെ ടിവിയിൽ HDMI-CEC പ്രവർത്തനക്ഷമമാക്കുകയും ചെയ്യുമ്പോൾ, നിങ്ങളുടെ ടിവി മറ്റൊരു ഇൻപുട്ടിലേക്ക് മാറിയതിന് ശേഷം ഈ ഉപകരണം സ്വയമേവ സ്റ്റാൻഡ്‌ബൈയിൽ പ്രവേശിക്കും. നിങ്ങൾ സജീവമായി കാണാത്തപ്പോൾ ഉള്ളടക്കം താൽക്കാലികമായി നിർത്താനും വൈദ്യുതി ഉപഭോഗം കുറയ്ക്കാനും ഇത് സഹായിച്ചേക്കാം."</string>
     <string name="settings_axel" msgid="8253298947221430993">"റിമോട്ട് ബട്ടണുകൾ സജ്ജീകരിക്കുക"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ശബ്‌ദം, പവർ, ടിവികളിലെ ഇൻപുട്ട്, റിസീവറുകൾ, സൗണ്ട് ബാറുകൾ എന്നിവ നിയന്ത്രിക്കുക"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"എന്റെ റിമോട്ട് കണ്ടെത്തൂ"</string>
diff --git a/libraries/BluetoothServices/res/values-mn/strings.xml b/libraries/BluetoothServices/res/values-mn/strings.xml
index e588b8d..92ddb56 100644
--- a/libraries/BluetoothServices/res/values-mn/strings.xml
+++ b/libraries/BluetoothServices/res/values-mn/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC-г идэвхжүүлэх"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Та HDMI-CEC-г ашиглан бусад HDMI-CEC-г идэвхжүүлсэн төхөөрөмжийг нэг алсын удирдлагаар хянаж, автоматаар асаах/унтраах боломжтой.\n\nСанамж: HDMI-CEC-г ТВ болон бусад HDMI төхөөрөмждөө идэвхжүүлсэн эсэхээ шалгана уу. Үйлдвэрлэгчид ихэвчлэн HDMI-CEC-н өөр өөр нэртэй байдаг бөгөөд жишээлбэл:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Оролтыг өөр эх сурвалж руу сэлгэхэд зогсолтын горимд орох"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Таныг энэ тохиргоог идэвхжүүлж, ТВ дээрээ HDMI-CEC-г идэвхжүүлэхэд уг төхөөрөмж таныг ТВ-ийнхээ өөр оролт руу сэлгэснээс хойш удалгүй зогсолтын горимд автоматаар орно. Энэ нь таныг идэвхтэйгээр үзээгүй байхад контентыг түр зогсоож, эрчим хүчний зарцуулалтыг багасгахад тусалж магадгүй."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Алсын удирдлагын товчлуурыг тохируулах"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ТВ, хүлээн авагч болон дууны самбаруудын дууны түвшин, тэжээл, оролтыг хянана уу"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Алсын удирдлагаа олох"</string>
diff --git a/libraries/BluetoothServices/res/values-mr/strings.xml b/libraries/BluetoothServices/res/values-mr/strings.xml
index 54ff4e8..d7d31db 100644
--- a/libraries/BluetoothServices/res/values-mr/strings.xml
+++ b/libraries/BluetoothServices/res/values-mr/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC सुरू करा"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC तुम्हाला एकच रिमोट कंट्रोल वापरून HDMI-CEC सुरू केलेली डिव्हाइस नियंत्रित करण्याची आणि आपोआप सुरू/बंद करण्याची अनुमती देते.\n\nटीप: तुमचा टीव्ही आणि इतर HDMI डिव्हाइसवर HDMI-CEC सुरू केले असल्याची खात्री करा. उत्पादक नेहमी HDMI-CEC साठी विविध नावे देतात, उदाहरणार्थ:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"इनपुट दुसऱ्या स्त्रोतावर स्विच करताना स्टँडबायमध्ये एंटर करा"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"तुम्ही हे सेटिंग सुरू करून तुमच्या टीव्हीवर HDMI-CEC सुरू करता, तेव्हा तुम्ही तुमच्या टीव्हीवर वेगळ्या इनपुटवर स्विच केल्यानंतर हे डिव्हाइस आपोआप स्टँडबायमध्ये एंटर करेल. तुम्ही सक्रियपणे पाहत नसाल, तेव्हा यामुळे आशय थांबवण्यास आणि वीज वापर कमी करण्यास मदत होऊ शकते."</string>
     <string name="settings_axel" msgid="8253298947221430993">"रिमोटची बटणे सेट करा"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"टीव्ही, रीसीव्हर आणि साउंडबारवरील व्हॉल्यूम, पॉवर, इनपुट नियंत्रित करा"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"माझा रिमोट शोधा"</string>
diff --git a/libraries/BluetoothServices/res/values-ms/strings.xml b/libraries/BluetoothServices/res/values-ms/strings.xml
index 5edc9f9..c1b2dff 100644
--- a/libraries/BluetoothServices/res/values-ms/strings.xml
+++ b/libraries/BluetoothServices/res/values-ms/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Dayakan HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC membenarkan anda mengawal dan menghidupkan/mematikan peranti berdaya HDMI-CEC lain secara automatik menggunakan alat kawalan jauh tunggal.\n\nNota: Pastikan HDMI-CEC didayakan pada TV dan peranti HDMI anda yang lain. Pengilang sering mempunyai nama yang berbeza untuk HDMI-CEC, contohnya:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Masuk mod tunggu sedia apabila menukar input kepada sumber lain"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Apabila anda mendayakan tetapan ini dan HDMI-CEC telah didayakan pada TV anda, peranti ini akan memasuki mod tunggu sedia secara automatik sejurus selepas anda beralih kepada input lain pada TV anda. Tindakan ini boleh membantu untuk menjeda kandungan dan mengurangkan penggunaan kuasa apabila anda tidak menonton secara aktif."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Sediakan butang alat kawalan jauh"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Kawal kelantangan, kuasa, input pada TV, penerima dan bar bunyi"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Cari alat kawalan jauh saya"</string>
diff --git a/libraries/BluetoothServices/res/values-my/strings.xml b/libraries/BluetoothServices/res/values-my/strings.xml
index 185e1a8..62bbda1 100644
--- a/libraries/BluetoothServices/res/values-my/strings.xml
+++ b/libraries/BluetoothServices/res/values-my/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC ဖွင့်ရန်"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ဖြင့် အခြား HDMI-CEC ဖွင့်ထားသည့် စက်ပစ္စည်းများအား အဝေးထိန်းခလုတ်တစ်ခုတည်းနှင့် ထိန်းချုပ်ပြီး အလိုအလျောက် ဖွင့်နိုင်/ပိတ်နိုင်သည်။ \n\nမှတ်ချက်- သင်၏ တီဗီနှင့် အခြား HDMI စက်ပစ္စည်းများတွင် HDMI-CEC ဖွင့်ထားပါ။ ကုန်ထုတ်လုပ်သူများတွင် HDMI-CEC အတွက် အမည်များ ကွဲပြားခြားနားသည်၊ ဥပမာ-"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"အဝင်ပေါက်ကို အခြားရင်းမြစ်သို့ ပြောင်းသည့်အခါ အရန်သင့်မုဒ်သို့ ဝင်သည်"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"ဤဆက်တင်ဖွင့်ပြီး သင့် TV တွင် HDMI-CEC ဖွင့်ထားသည့်အခါ ဤစက်သည် TV ၌ အခြားအဝင်ပေါက်သို့ ပြောင်းလိုက်ပြီးနောက် မကြာမီတွင် အရန်သင့်မုဒ်သို့ အလိုအလျောက် ဝင်မည်။ သင်ကြည့်မနေချိန်တွင် ၎င်းက အကြောင်းအရာကို ခဏရပ်ပြီး စွမ်းအင်အသုံးပြုမှု လျှော့ချပေးနိုင်သည်။"</string>
     <string name="settings_axel" msgid="8253298947221430993">"အဝေးထိန်း ခလုတ်များကို စနစ်ထည့်သွင်းရန်"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"TV၊ ရုပ်သံဖမ်းစက်နှင့် အသံဘားများတွင် အသံအတိုးအကျယ်၊ အဖွင့်အပိတ်၊ အဝင်တို့ကို ထိန်းချုပ်နိုင်သည်"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"ကျွန်ုပ်၏ အဝေးထိန်းခလုတ်ရှာခြင်း"</string>
diff --git a/libraries/BluetoothServices/res/values-nb/strings.xml b/libraries/BluetoothServices/res/values-nb/strings.xml
index 9fcdb6b..970c346 100644
--- a/libraries/BluetoothServices/res/values-nb/strings.xml
+++ b/libraries/BluetoothServices/res/values-nb/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Slå på HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Med HDMI-CEC kan du kontrollere og automatisk slå andre HDMI-CEC-aktiverte enheter av/på med én enkelt fjernkontroll.\n\nMerk: Sjekk at HDMI-CEC er slått på for TV-en din og andre HDMI-enheter. Produsenter har ofte forskjellige navn for HDMI-CEC, for eksempel:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Gå i hvilemodus når du bytter til en annen inndatakilde"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Når du slår på denne innstillingen og HDMI-CEC er aktivert på TV-en, går denne enheten automatisk i hvilemodus kort tid etter at du bytter til en annen inngang på TV-en. Dette kan bidra til å sette innholdet på pause og redusere strømforbruket når du ikke ser aktivt på noe."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Konfigurer fjernkontrollknapper"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Kontroller volumet og innenheter på TV-er, mottakere og lydplanker, og slå dem av og på"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Finn fjernkontrollen min"</string>
diff --git a/libraries/BluetoothServices/res/values-ne/strings.xml b/libraries/BluetoothServices/res/values-ne/strings.xml
index f53ff6a..0d25d31 100644
--- a/libraries/BluetoothServices/res/values-ne/strings.xml
+++ b/libraries/BluetoothServices/res/values-ne/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC सक्षम गर्नुहोस्"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ले तपाईंलाई एकल दूरवर्ती नियन्त्रणमार्फत HDMI-CEC सक्षम पारिएका अन्य डिभाइसहरू नियन्त्रण गर्ने र स्वतः सक्रिय गर्ने/निष्क्रिय पार्ने अनुमति दिन्छ।\n\nटिपोट: आफ्ना टिभी र अन्य HDMI यन्त्रहरूमा HDMI-CEC सक्षम पारिएको छ भन्ने कुरा सुनिश्चित गर्नुहोस्। HDMI-CEC मा निर्माताहरूको नाम उदारणमा दिए जस्तै प्रायः फरक फरक हुन्छन्:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"अर्को स्रोतमा इन्पुट बदल्दा स्ट्यान्डबाइ मोडमा प्रवेश गर्नुहोस्"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"तपाईंले यो सेटिङ अन गर्नुभयो र आफ्नो टिभीमा HDMI-CEC अन गर्नुभयो भने तपाईंले आफ्नो टिभीमा अर्को इन्पुट बदलेपछि यो डिभाइस चाँडै नै स्ट्यान्डबाइ मोडमा स्वतः प्रवेश गर्ने छ। तपाईंले सक्रिय रूपमा टिभी नहेरेका बेला यसले सामग्री पज गर्न र बिजुलीको खपत घटाउन सक्छ।"</string>
     <string name="settings_axel" msgid="8253298947221430993">"रिमोटका बटनहरू सेटअप गर्नुहोस्"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"टिभी, रिसिभर र साउन्डबारको भोल्युम, पावर र इनपुट नियन्त्रण गर्नुहोस्"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"मेरो रिमोट भेट्टाइयोस्"</string>
diff --git a/libraries/BluetoothServices/res/values-nl/strings.xml b/libraries/BluetoothServices/res/values-nl/strings.xml
index 4fe216a..8fb2f97 100644
--- a/libraries/BluetoothServices/res/values-nl/strings.xml
+++ b/libraries/BluetoothServices/res/values-nl/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC aanzetten"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Via HDMI-CEC kun je andere apparaten met HDMI-CEC-functionaliteit bedienen en automatisch aan-/uitzetten met één afstandsbediening.\n\nOpmerking: Zorg ervoor dat HDMI-CEC aanstaat op je tv en andere HDMI-apparaten. Fabrikanten hebben vaak verschillende namen voor HDMI-CEC, zoals:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Stand-bymodus activeren als je van invoerbron wisselt"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Als je deze instelling aanzet en HDMI-CEC aanstaat op je tv, gaat dit apparaat automatisch in de stand-bymodus kort nadat je naar een andere ingang op je tv bent overgeschakeld. Zo kun je content pauzeren en het energieverbruik verminderen als je niet actief kijkt."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Afstandsbedieningsknoppen instellen"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Volume bedienen, aan- en uitzetten en invoer selecteren op tv\'s, ontvangers en soundbars"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Mijn afstandsbediening vinden"</string>
diff --git a/libraries/BluetoothServices/res/values-or/strings.xml b/libraries/BluetoothServices/res/values-or/strings.xml
index 562190a..146f248 100644
--- a/libraries/BluetoothServices/res/values-or/strings.xml
+++ b/libraries/BluetoothServices/res/values-or/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC ସକ୍ଷମ କରନ୍ତୁ"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ଆପଣଙ୍କୁ ଏକ ଏକକ ରିମୋଟ୍ କଣ୍ଟ୍ରୋଲ୍ ସହ ଅନ୍ୟ HDMI-CEC ସମର୍ଥିତ ଡିଭାଇସ୍‍ଗୁଡିକୁ ସ୍ବଚାଳିତଭାବରେ ଚାଲୁ/ବନ୍ଦ ଏବଂ ନିୟନ୍ତ୍ରଣ କରିବାକୁ ଅନୁମତି ଦେଇଥାଏ।\n\nଟିପ୍ପଣୀ: ଆପଣଙ୍କର ଟିଭି ଏବଂ ଅନ୍ୟ HDMI ଡିଭାଇସ୍‍ଗୁଡିକରେ HDMI-CEC ସକ୍ଷମ କରାଯାଇଥିବା ସୁନିଶ୍ଚିତ ହୁଅନ୍ତୁ। HDMI-CEC ପାଇଁ ଉତ୍ପାଦକଗଣ ପ୍ରାୟତଃ ଭିନ୍ନ ଭିନ୍ନ ନାମ ରଖିଥାନ୍ତି:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nସାର୍ପ: Aquos ଲିିିିଙ୍କ୍"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ଅନ୍ୟ ଏକ ସୋର୍ସକୁ ଇନପୁଟ ସୁଇଚ କରିବା ସମୟରେ ଷ୍ଟାଣ୍ଡବାଏରେ ରହିବ"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"ଆପଣ ଏହି ସେଟିଂକୁ ସକ୍ଷମ କଲେ ଏବଂ ଆପଣଙ୍କ TVରେ HDMI-CEC ସକ୍ଷମ ହେଲେ, ଆପଣ ଆପଣଙ୍କ TVରେ ଏକ ଭିନ୍ନ ଇନପୁଟକୁ ସୁଇଚ କରିବାର କିଛି ସମୟ ପରେ ଏହି ଡିଭାଇସ ସ୍ୱତଃ ଷ୍ଟାଣ୍ଡବାଏରେ ରହିବ। ଆପଣ ସକ୍ରିୟ ଭାବେ ଦେଖୁନଥିବା ସମୟରେ ଏହା ବିଷୟବସ୍ତୁକୁ ବିରତ କରିବା ଏବଂ ପାୱାର ବ୍ୟବହାରକୁ ହ୍ରାସ କରିବାରେ ସାହାଯ୍ୟ କରିପାରେ।"</string>
     <string name="settings_axel" msgid="8253298947221430993">"ରିମୋଟ୍ ବଟନଗୁଡ଼ିକୁ ସେଟ୍ ଅପ୍ କରନ୍ତୁ"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ଟିଭି, ରିସିଭର୍ ଏବଂ ସାଉଣ୍ଡବାରଗୁଡ଼ିକରେ ଭଲ୍ୟୁମ୍, ପାୱାର, ଇନପୁଟକୁ ନିୟନ୍ତ୍ରଣ କରନ୍ତୁ"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"ମୋ ରିମୋଟ ଖୋଜନ୍ତୁ"</string>
diff --git a/libraries/BluetoothServices/res/values-pa/strings.xml b/libraries/BluetoothServices/res/values-pa/strings.xml
index 514fecb..4d7906d 100644
--- a/libraries/BluetoothServices/res/values-pa/strings.xml
+++ b/libraries/BluetoothServices/res/values-pa/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC ਚਾਲੂ ਕਰੋ"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ਤੁਹਾਨੂੰ ਇਕਹਿਰੇ ਰਿਮੋਟ ਕੰਟਰੋਲ ਨਾਲ ਹੋਰਾਂ HDMI-CEC ਸਮਰਥਿਤ ਡੀਵਾਈਸਾਂ ਨੂੰ ਕੰਟਰੋਲ ਅਤੇ ਚਾਲੂ ਜਾਂ ਬੰਦ ਕਰਨ ਦਿੰਦਾ ਹੈ।\n\nਨੋਟ ਕਰੋ: ਪੱਕਾ ਕਰੋ ਕਿ ਤੁਹਾਡੇ ਟੀਵੀ ਅਤੇ ਹੋਰਾਂ HDMI ਡੀਵਾਈਸਾਂ \'ਤੇ HDMI-CEC ਚਾਲੂ ਕੀਤਾ ਹੋਵੇ। ਨਿਰਮਾਤਾ ਅਕਸਰ HDMI-CEC ਲਈ ਵੱਖੋ-ਵੱਖਰੇ ਨਾਮ ਰੱਖਦੇ ਹਨ, ਉਦਾਹਰਨ ਲਈ:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ਕਿਸੇ ਹੋਰ ਸਰੋਤ \'ਤੇ ਇਨਪੁੱਟ ਸਵਿੱਚ ਕਰਨ ਵੇਲੇ ਸਟੈਂਡਬਾਈ ਮੋਡ ਵਿੱਚ ਦਾਖਲ ਹੋਵੋ"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"ਜਦੋਂ ਤੁਸੀਂ ਇਸ ਸੈਟਿੰਗ ਨੂੰ ਚਾਲੂ ਕਰਦੇ ਹੋ ਅਤੇ ਆਪਣੇ ਟੀਵੀ \'ਤੇ HDMI-CEC ਨੂੰ ਚਾਲੂ ਕੀਤਾ ਹੋਇਆ ਹੈ, ਤਾਂ ਇਹ ਡੀਵਾਈਸ ਤੁਹਾਡੇ ਟੀਵੀ \'ਤੇ ਕਿਸੇ ਵੱਖਰੇ ਇਨਪੁੱਟ \'ਤੇ ਸਵਿੱਚ ਕਰਨ ਤੋਂ ਬਾਅਦ ਜਲਦ ਹੀ ਸਵੈਚਲਿਤ ਤੌਰ \'ਤੇ ਸਟੈਂਡਬਾਏ ਮੋਡ ਵਿੱਚ ਦਾਖਲ ਹੋ ਜਾਵੇਗਾ। ਇਸ ਨਾਲ ਅਜਿਹੀ ਸਮੱਗਰੀ ਨੂੰ ਰੋਕਣ ਅਤੇ ਬਿਜਲੀ ਦੀ ਖਪਤ ਘੱਟ ਕਰਨ ਵਿੱਚ ਮਦਦ ਮਿਲ ਸਕਦੀ ਹੈ ਜਦੋਂ ਤੁਸੀਂ ਸਰਗਰਮੀ ਨਾਲ ਨਾ ਦੇਖ ਰਹੇ ਹੋਵੋ।"</string>
     <string name="settings_axel" msgid="8253298947221430993">"ਰਿਮੋਟ ਦੇ ਬਟਨਾਂ ਦਾ ਸੈੱਟਅੱਪ ਕਰੋ"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ਅਵਾਜ਼, ਪਾਵਰ, ਟੀਵੀਆਂ \'ਤੇ ਇਨਪੁੱਟ, ਰਿਸੀਵਰਾਂ ਅਤੇ ਸਾਊਂਡਬਾਰਾਂ ਨੂੰ ਕੰਟਰੋਲ ਕਰੋ"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"ਮੇਰਾ ਰਿਮੋਟ ਲੱਭੋ"</string>
diff --git a/libraries/BluetoothServices/res/values-pl/strings.xml b/libraries/BluetoothServices/res/values-pl/strings.xml
index 09dd861..bb1ba4b 100644
--- a/libraries/BluetoothServices/res/values-pl/strings.xml
+++ b/libraries/BluetoothServices/res/values-pl/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Włącz HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Złącze HDMI-CEC umożliwia sterowanie innymi urządzeniami obsługującymi ten standard oraz ich automatyczne włączanie i wyłączanie przy użyciu jednego pilota.\n\nUwaga: upewnij się, że komunikacja HDMI-CEC jest włączona na telewizorze i innych urządzeniach ze złączem HDMI. Różni producenci stosują różne nazwy standardu HDMI-CEC, na przykład:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Przejdź w tryb gotowości po przełączeniu sygnału na inne źródło"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Gdy włączysz to ustawienie i będziesz mieć włączony tryb HDMI-CEC na telewizorze, urządzenie automatycznie przejdzie w stan czuwania, gdy tylko przełączysz się na inne źródło sygnału na telewizorze. Może to zmniejszyć zużycie energii dzięki wstrzymywaniu odtwarzania, gdy nie będziesz aktywnie oglądać treści."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Skonfiguruj przyciski pilota"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Steruj głośnością, zasilaniem i źródłem sygnału na telewizorach, amplitunerach i soundbarach"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Znajdź pilota"</string>
diff --git a/libraries/BluetoothServices/res/values-pt-rBR/strings.xml b/libraries/BluetoothServices/res/values-pt-rBR/strings.xml
index 3183ac8..46447b7 100644
--- a/libraries/BluetoothServices/res/values-pt-rBR/strings.xml
+++ b/libraries/BluetoothServices/res/values-pt-rBR/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Ativar HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Com o HDMI-CEC, é possível controlar e ativar/desativar automaticamente outros dispositivos compatíveis com HDMI-CEC usando o mesmo controle remoto.\n\nObservação: o HDMI-CEC precisa estar ativado na TV e nos outros dispositivos HDMI. Muitas vezes, os fabricantes usam outros nomes para o HDMI-CEC, por exemplo:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Entrar no modo de espera ao mudar a entrada para outra origem"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Ao ativar essa configuração e o HDMI-CEC na sua TV, o dispositivo entra automaticamente no modo de espera logo depois que você muda para uma entrada diferente na TV. Isso pode ajudar a pausar o conteúdo e reduzir o consumo de energia quando você não estiver assistindo ativamente."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configurar botões de controle remoto"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controle o volume, a função liga/desliga e a entrada em TVs, receptores e soundbars"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Encontrar meu controle remoto"</string>
diff --git a/libraries/BluetoothServices/res/values-pt-rPT/strings.xml b/libraries/BluetoothServices/res/values-pt-rPT/strings.xml
index 0acd950..de4238a 100644
--- a/libraries/BluetoothServices/res/values-pt-rPT/strings.xml
+++ b/libraries/BluetoothServices/res/values-pt-rPT/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Ativar HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"O HDMI-CEC permite-lhe controlar e ativar/desativar automaticamente outros dispositivos compatíveis com o HDMI-CEC com um único comando.\n\nNota: certifique-se de que o HDMI-CEC está ativado na sua TV e nos outros dispositivos com HDMI. Muitas vezes, os fabricantes atribuem nomes diferentes ao HDMI-CEC, por exemplo:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Entrar no modo de espera ao mudar de entrada para outra origem"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Quando ativa esta definição e tem o HDMI-CEC ativado na sua TV, este dispositivo entra automaticamente em modo de espera pouco depois de mudar para uma entrada diferente na sua TV. Isto pode ajudar a pausar o conteúdo e reduzir o consumo de energia quando não está a ver ativamente."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configure os botões do comando"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controle o volume, o botão ligar/desligar, a entrada em TVs, os recetores e as barras de som"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Localizar o meu comando"</string>
diff --git a/libraries/BluetoothServices/res/values-pt/strings.xml b/libraries/BluetoothServices/res/values-pt/strings.xml
index 3183ac8..46447b7 100644
--- a/libraries/BluetoothServices/res/values-pt/strings.xml
+++ b/libraries/BluetoothServices/res/values-pt/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Ativar HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Com o HDMI-CEC, é possível controlar e ativar/desativar automaticamente outros dispositivos compatíveis com HDMI-CEC usando o mesmo controle remoto.\n\nObservação: o HDMI-CEC precisa estar ativado na TV e nos outros dispositivos HDMI. Muitas vezes, os fabricantes usam outros nomes para o HDMI-CEC, por exemplo:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Entrar no modo de espera ao mudar a entrada para outra origem"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Ao ativar essa configuração e o HDMI-CEC na sua TV, o dispositivo entra automaticamente no modo de espera logo depois que você muda para uma entrada diferente na TV. Isso pode ajudar a pausar o conteúdo e reduzir o consumo de energia quando você não estiver assistindo ativamente."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configurar botões de controle remoto"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controle o volume, a função liga/desliga e a entrada em TVs, receptores e soundbars"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Encontrar meu controle remoto"</string>
diff --git a/libraries/BluetoothServices/res/values-ro/strings.xml b/libraries/BluetoothServices/res/values-ro/strings.xml
index 1798fca..17c1cdc 100644
--- a/libraries/BluetoothServices/res/values-ro/strings.xml
+++ b/libraries/BluetoothServices/res/values-ro/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Activează HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC îți permite să controlezi și să pornești/oprești alte dispozitive compatibile HDMI-CEC cu o singură telecomandă.\n\nNotă: Asigură-te că HDMI-CEC este activat pe televizor și pe alte dispozitive HDMI. Producătorii au adesea nume diferite pentru HDMI-CEC, de exemplu:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Intră în modul standby când comuți intrarea la altă sursă"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Când activezi setarea și ai HDMI-CEC activat pe televizor, dispozitivul va intra automat în standby la scurt timp după ce comuți la altă intrare pe televizor. Astfel, poți să întrerupi conținutul și să reduci consumul de energie când nu vizionezi în mod activ."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Configurează butoanele telecomenzii"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Controlează volumul, alimentarea și intrarea pentru televizoare, receivere și bare de sunet"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Găsește-mi telecomanda"</string>
diff --git a/libraries/BluetoothServices/res/values-ru/strings.xml b/libraries/BluetoothServices/res/values-ru/strings.xml
index 1b165c9..92c0cee 100644
--- a/libraries/BluetoothServices/res/values-ru/strings.xml
+++ b/libraries/BluetoothServices/res/values-ru/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Включить HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Устройствами, совместимыми с протоколом HDMI-CEC, можно управлять (в том числе автоматически включать и выключать их) с помощью одного пульта ДУ.\n\nПримечание. Убедитесь, что протокол включен на телевизоре и на других HDMI-устройствах. Разные производители используют для HDMI-CEC разные названия, например:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SIMPLINK\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Переходить в режим ожидания после переключения на другой источник сигнала"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Когда на текущем устройстве включен этот параметр, а на телевизоре – HDMI-CEC, оно автоматически перейдет в режим ожидания вскоре после того, как вы выберете другой источник сигнала на телевизоре. В результате, возможно, воспроизведение контента будет приостановлено и снизится энергопотребление. Эта функция пригодится, когда вы захотите включить какой-нибудь контент на фоне."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Настройка кнопок на пульте ДУ"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Управляйте громкостью и питанием, а также выбирайте источники сигнала на телевизорах, ресиверах и саундбарах"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Поиск пульта"</string>
diff --git a/libraries/BluetoothServices/res/values-si/strings.xml b/libraries/BluetoothServices/res/values-si/strings.xml
index 14f6944..4c0fa20 100644
--- a/libraries/BluetoothServices/res/values-si/strings.xml
+++ b/libraries/BluetoothServices/res/values-si/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC සබල කරන්න"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC මඟින් ඔබට තනි දුරස්ථ පාලකයකින් වෙනත් HDMI-CEC සබලිත උපාංග පාලනය කිරීමට සහ ස්වයංක්‍රීයව ක්‍රියාත්මක/ක්‍රියා විරහිත කිරීමට ඉඩ දෙයි.\n\nසටහන: HDMI-CEC ඔබේ රූපවාහිනියෙහි සහ වෙනත් HDMI උපාංගවල සබල කර ඇති බව සහතික කර ගන්න. නිෂ්පාදකයින්ට බොහෝ විට HDMI-CEC සඳහා විවිධ නම් තිබේ, උදාහරණයක් ලෙස:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"වෙනත් මූලාශ්‍රයකට ආදානය මාරු කරන විට පොරොත්තුවට ඇතුළු වන්න"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"ඔබ මෙම සැකසීම සබල කර ඔබේ රූපවාහිනියේ HDMI-CEC සබල කර ඇති විට, ඔබ ඔබේ රූපවාහිනියේ වෙනත් ආදානයකට මාරු වූ පසු මෙම උපාංගය ස්වයංක්‍රීයව පොරොත්තුවට ඇතුළු වේ. මෙය ඔබ සක්‍රියව නරඹන්නේ නැති විට අන්තර්ගතය විරාම කිරීමට සහ බල පරිභෝජනය අඩු කිරීමට උදවු විය හැක."</string>
     <string name="settings_axel" msgid="8253298947221430993">"දුරස්ථ පාලක බොත්තම් පිහිටුවන්න"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"රූපවාහිනී, ග්‍රාහක සහ හඬ තීරුවල හඬ පරිමාව, බලය, ආදානය පාලනය කරන්න"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"මගේ දුරස්ථ පාලකය සොයා ගන්න"</string>
diff --git a/libraries/BluetoothServices/res/values-sk/strings.xml b/libraries/BluetoothServices/res/values-sk/strings.xml
index 687e883..253be62 100644
--- a/libraries/BluetoothServices/res/values-sk/strings.xml
+++ b/libraries/BluetoothServices/res/values-sk/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Povoliť HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC umožňuje ovládať a automaticky zapínať alebo vypínať zariadenia s povolenou funkciou HDMI-CEC jediným diaľkovým ovládaním.\n\nPoznámka: Skontrolujte, či je funkcia HDMI-CEC povolená v televízore a ďalších zariadeniach HDMI. Výrobcovia nazývajú HDMI-CEC rôzne, napríklad:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Prechod do pohotovostného režimu po prepnutí na iný zdroj"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Keď v televízore zapnete funkciu HDMI-CEC a povolíte toto nastavenie, zariadenie krátko po prepnutí na iný vstup v televízore automaticky prejde do pohotovostného režimu. Vďaka tomu sa bude môcť obsah pozastaviť, pričom sa zníži aj spotreba energie, keď nebudete aktívne pozerať."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Nastavenie tlačidiel diaľkového ovládania"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Ovládanie hlasitosti, vypínača a vstupu v televízoroch, prijímačoch a soundbaroch"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Find my remote"</string>
diff --git a/libraries/BluetoothServices/res/values-sl/strings.xml b/libraries/BluetoothServices/res/values-sl/strings.xml
index 6365b43..c0670a3 100644
--- a/libraries/BluetoothServices/res/values-sl/strings.xml
+++ b/libraries/BluetoothServices/res/values-sl/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Omogoči HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC vam z enim samim daljinskim upravljalnikom omogoča upravljanje in samodejni vklop/izklop drugih naprav z omogočeno funkcijo HDMI-CEC.\n\nOpomba: Funkcija HDMI-CEC mora biti omogočena v televizorju in drugih napravah HDMI. Proizvajalci imajo za funkcijo HDMI-CEC pogosto drugačna imena, na primer:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Vstop v stanje pripravljenosti pri preklopu vhoda na drug vir"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Če omogočite to nastavitev in je v televizorju omogočen HDMI-CEC, ta naprava samodejno preklopi v stanje pripravljenosti kmalu po tem, ko v televizorju preklopite na drug vhod. To vam lahko pomaga začasno zaustaviti vsebino in zmanjšati porabo energije, ko ne gledate aktivno."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Nastavitev gumbov daljinskega upravljalnika"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Nadziranje glasnosti, vklopa/izklopa in vhodov v televizorjih, sprejemnikih ter zvočniških modulih"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Poišči moj daljinski upravljalnik"</string>
diff --git a/libraries/BluetoothServices/res/values-sq/strings.xml b/libraries/BluetoothServices/res/values-sq/strings.xml
index d631d34..897bc1e 100644
--- a/libraries/BluetoothServices/res/values-sq/strings.xml
+++ b/libraries/BluetoothServices/res/values-sq/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Aktivizo HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC të lejon të kontrollosh dhe të aktivizosh/çaktivizosh automatikisht pajisjet që mbështesin HDMI-CEC me një telekomandë të vetme.\n\nShënim: Sigurohu që televizori yt dhe pajisjet e tjera HDMI të mbështesin HDMI-CEC. Prodhuesit shpesh kanë emra të ndryshëm për HDMI-CEC, për shembull:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Kalo në gatishmëri kur ndryshon hyrjen në një burim tjetër"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Kur aktivizon këtë cilësim dhe ke të aktivizuar HDMI-CEC në televizor, kjo pajisje do të kalojë automatikisht në gatishmëri pak pasi të kalosh në një hyrje tjetër në televizor. Kjo mund të ndihmojnë në vendosjen në pauzë të përmbajtjeve dhe të reduktojë konsumin e energjisë kur nuk je duke shikuar në mënyrë aktive."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Konfiguro butonat e telekomandës"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Kontrollo volumin, energjinë dhe hyrjen në televizorë, marrës dhe soundbar-ë"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Gjej telekomandën time"</string>
diff --git a/libraries/BluetoothServices/res/values-sr/strings.xml b/libraries/BluetoothServices/res/values-sr/strings.xml
index f18ddb3..36661eb 100644
--- a/libraries/BluetoothServices/res/values-sr/strings.xml
+++ b/libraries/BluetoothServices/res/values-sr/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Омогући HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC вам омогућава да контролишете и аутоматски укључујете/искључујете остале уређаје на којима је омогућен HDMI-CEC помоћу само једног даљинског управљача.\n\nНапомена: Уверите се да је HDMI-CEC омогућен на телевизору и другим HDMI уређајима. Произвођачи обично имају различите називе за HDMI-CEC, на пример:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Покрените стање приправности при преласку на други извор за улаз"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Када омогућите ово подешавање и имате HDMI-CEC омогућен на телевизору, овај уређај аутоматски прелази у стање приправности убрзо пошто пређете на други улаз на телевизору. То може да помогне да се садржај паузира и смањи потрошња енергије када активно не гледате."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Подесите дугмад на даљинском управљачу"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Контролишите јачину звука, напајање и улаз TV-а, пријемника и саундбарова"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Нађи даљински"</string>
diff --git a/libraries/BluetoothServices/res/values-sv/strings.xml b/libraries/BluetoothServices/res/values-sv/strings.xml
index 6dcc352..1ac5479 100644
--- a/libraries/BluetoothServices/res/values-sv/strings.xml
+++ b/libraries/BluetoothServices/res/values-sv/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Aktivera HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Med HDMI-CEC kan du styra andra HDMI-CEC-kompatibla enheter och slå på eller av dem automatiskt med en enda fjärrkontroll.\n\nObs! Kontrollera att HDMI-CEC har aktiverats på tv:n och övriga HDMI-enheter. Olika tillverkare kan använda olika namn på HDMI-CEC. Några exempel:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Aktivera viloläge när du byter ingång till en annan källa"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"När du aktiverar den här inställningen och har HDMI-CEC aktiverat på tv:n aktiveras viloläget automatiskt strax efter att du byter till en annan ingång på tv:n. Då kan innehåll pausas och strömförbrukningen minska när du inte tittar aktivt."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Konfigurera fjärrkontrollsknappar"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Styr volymen, av/på-knappen och val av ingångskälla på tv:ar, mottagare och soundbar-högtalare"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Hitta min fjärrkontroll"</string>
diff --git a/libraries/BluetoothServices/res/values-sw/strings.xml b/libraries/BluetoothServices/res/values-sw/strings.xml
index 18882e4..b423a79 100644
--- a/libraries/BluetoothServices/res/values-sw/strings.xml
+++ b/libraries/BluetoothServices/res/values-sw/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Washa HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC hukuwezesha kudhibiti na kuwasha au kuzima kiotomatiki vifaa vingine vinavyotumia HDMI-CEC ukitumia kidhibiti kimoja cha mbali.\n\nKumbuka: Hakikisha umewasha HDMI-CEC kwenye TV yako na vifaa vingine vya HDMI. Watengenezaji hutumia majina tofauti kurejelea HDMI-CEC, Kwa mfano:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Ingia katika hali tuli unapobadilisha utumie chanzo tofauti kuingiza data"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Unapowasha mipangilio hii na HDMI-CEC imewasha kwenye televisheni yako, kifaa hiki kitaingia kiotomatiki katika hali tuli muda mfupi baada ya kubadilisha ili kutumia kifaa tofauti cha kuingiza data kwenye televisheni yako. Huenda hii ikasaidia kusitisha maudhui na kupunguza matumizi ya nishati wakati hutazami maudhui."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Weka mipangilio ya vitufe vya kidhibiti cha mbali"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Dhibiti sauti, nishati, vifaa vya kuingiza data kwenye TV, spika na vipokea sauti na video"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Tafuta kidhibiti changu cha mbali"</string>
diff --git a/libraries/BluetoothServices/res/values-ta/strings.xml b/libraries/BluetoothServices/res/values-ta/strings.xml
index 998e470..d764c96 100644
--- a/libraries/BluetoothServices/res/values-ta/strings.xml
+++ b/libraries/BluetoothServices/res/values-ta/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CECயை இயக்கு"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC இயக்கப்பட்டுள்ள வேறு சாதனங்களை ரிமோட் கன்ட்ரோல் மூலம் கட்டுப்படுத்தவும் தானாகவே ஆன்/ஆஃப் செய்யவும் HDMI-CEC அனுமதிக்கும்.\n\nகவனத்திற்கு: டிவியிலும் பிற HDMI சாதனங்களிலும் HDMI-CEC இயக்கப்பட்டிருப்பதை உறுதிசெய்யவும். HDMI-CECக்கு ஒவ்வொரு தயாரிப்பாளரும் ஒவ்வொரு பெயரை வைத்திருப்பார், உதாரணமாக:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"மற்றொரு உள்ளீட்டிற்கு மாறும்போது சாதனம் காத்திருப்புப் பயன்முறைக்குச் செல்லும்"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"உங்கள் டிவியில் HDMI-CEC இயக்கப்பட்டிருந்து இந்த அமைப்பை இயக்கினால், டிவியில் வேறு உள்ளீட்டிற்கு மாறிய சிறிது நேரத்திலேயே இந்தச் சாதனம் தானாகவே காத்திருப்புப் பயன்முறைக்குச் செல்லும். நீங்கள் டிவியைத் தொடர்ந்து பார்க்காதபோது, உள்ளடக்கத்தை இடைநிறுத்தி வைக்கவும் மின்சார உபயோகத்தைக் குறைக்கவும் இது உதவக்கூடும்."</string>
     <string name="settings_axel" msgid="8253298947221430993">"ரிமோட் பட்டன்களை அமைத்தல்"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"டிவிகள், ரிசீவர்கள், சவுண்ட்பார்கள் ஆகியவற்றில் ஒலியளவையும் பவரையும் உள்ளீட்டையும் கட்டுப்படுத்தலாம்"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"எனது ரிமோட்டைக் கண்டறிதல்"</string>
diff --git a/libraries/BluetoothServices/res/values-te/strings.xml b/libraries/BluetoothServices/res/values-te/strings.xml
index 95f2509..2853d15 100644
--- a/libraries/BluetoothServices/res/values-te/strings.xml
+++ b/libraries/BluetoothServices/res/values-te/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CECని ప్రారంభించండి"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"ఒక రిమోట్ నియంత్రణతో ఇతర HDMI-CEC ప్రారంభించబడిన పరికరాలను నియంత్రించడానికి మరియు ఆటోమేటిక్‌గా ఆన్/ఆఫ్ చేయడానికి HDMI-CEC మిమ్మల్ని అనుమతిస్తుంది.\n\nగమనిక: మీ టీవీ మరియు ఇతర HDMI పరికరాలలో HDMI-CEC ప్రారంభించబడిందని నిర్థారించండి. తయారీదారులు తరచుగా HDMI-CECకి వివిధ పేర్లను కలిగి ఉంటారు, ఉదాహరణకు:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ఇన్‌పుట్‌ను వేరొక సోర్స్‌కు మార్చినప్పుడు స్టాండ్‌బైలోకి ఎంటర్ అవ్వండి"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"మీరు ఈ సెట్టింగ్‌ను ఎనేబుల్ చేసి, మీ టీవిలో HDMI-CECని ఎనేబుల్ చేసినట్లయితే, మీ టీవీలో మీరు వేరొక ఇన్‌పుట్‌కు మారిన కొద్దిసేపటికే, ఈ పరికరం ఆటోమేటిక్‌గా స్టాండ్‌బై‌లోకి ఎంటర్ అవుతుంది. ఇలా చేయడం వలన మీరు టీవీ చూడనప్పుడు, కంటెంట్‌ను పాజ్ చేసినప్పుడు, విద్యుత్తు వినియోగాన్ని తగ్గించడంలో సహాయపడుతుంది."</string>
     <string name="settings_axel" msgid="8253298947221430993">"రిమోట్ బటన్‌లను సెటప్ చేయండి"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"వాల్యూమ్, పవర్, టీవీలలోని ఇన్‌పుట్, రిసీవర్‌లు అలాగే సౌండ్‌బార్‌లను కంట్రోల్ చేయండి"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"నా రిమోట్‌ను కనుగొనండి"</string>
diff --git a/libraries/BluetoothServices/res/values-th/strings.xml b/libraries/BluetoothServices/res/values-th/strings.xml
index 186f929..978e981 100644
--- a/libraries/BluetoothServices/res/values-th/strings.xml
+++ b/libraries/BluetoothServices/res/values-th/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"เปิดใช้ HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC ช่วยให้คุณควบคุมและเปิดหรือปิดอุปกรณ์ที่ใช้ HDMI-CEC อื่นๆ ได้ด้วยรีโมตควบคุม\n\nหมายเหตุ: ตรวจสอบว่าเปิดใช้ HDMI-CEC ในทีวีและอุปกรณ์ HDMI อื่นๆ แล้ว ผู้ผลิตมักจะใช้ชื่อสำหรับ HDMI-CEC แตกต่างกันไป ตัวอย่างเช่น:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"เข้าสู่โหมดสแตนด์บายเมื่อเปลี่ยนอินพุตไปยังแหล่งที่มาอื่น"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"เมื่อเปิดใช้การตั้งค่านี้และ HDMI-CEC ในทีวี อุปกรณ์นี้จะเข้าสู่โหมดสแตนด์บายโดยอัตโนมัติในไม่ช้าหลังจากเปลี่ยนไปใช้อินพุตอื่นในทีวี การดำเนินการนี้อาจช่วยหยุดเนื้อหาชั่วคราวและลดการใช้พลังงานเมื่อคุณไม่ได้ดูอยู่"</string>
     <string name="settings_axel" msgid="8253298947221430993">"ตั้งค่าปุ่มรีโมต"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"ควบคุมระดับเสียง การเปิด/ปิด อินพุตในทีวี ตัวรับสัญญาณ และซาวด์บาร์"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"หารีโมตของฉัน"</string>
diff --git a/libraries/BluetoothServices/res/values-tl/strings.xml b/libraries/BluetoothServices/res/values-tl/strings.xml
index f03b110..f105429 100644
--- a/libraries/BluetoothServices/res/values-tl/strings.xml
+++ b/libraries/BluetoothServices/res/values-tl/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"I-enable ang HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Nagbibigay-daan sa iyo ang HDMI-CEC na kontrolin at awtomatikong i-on/i-off ang iba pang device na may naka-enable na HDMI-CEC sa pamamagitan ng isang remote control.\n\nTandaan: Tiyaking naka-enable ang HDMI-CEC sa iyong TV at iba pang HDMI device. Madalas na magkaiba ang mga pangalan ng mga manufacturer para sa HDMI-CEC, halimbawa:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"I-activate ang standby kapag inililipat ang input sa ibang source"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Kapag na-enable mo ang setting na ito at may naka-enable na HDMI-CEC sa iyong TV, awtomatikong mag-a-activate ang standby ilang sandali pagkatapos mong lumipat sa ibang input sa TV mo. Posibleng makatulong ito na i-pause ang content at bawasan ang pagkonsumo ng kuryente kapag hindi ka aktibong nanonood."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Mag-set up ng mga button ng remote"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Kontrolin ang volume, power, input sa mga TV, receiver, at soundbar"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Hanapin ang remote ko"</string>
diff --git a/libraries/BluetoothServices/res/values-tr/strings.xml b/libraries/BluetoothServices/res/values-tr/strings.xml
index 8737c56..14fa649 100644
--- a/libraries/BluetoothServices/res/values-tr/strings.xml
+++ b/libraries/BluetoothServices/res/values-tr/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC\'yi etkinleştir"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC, tek bir uzaktan kumanda ile HDMI-CEC özellikli diğer cihazları kontrol etmenize olanak sağlar .\n\nNot: TV\'nizde ve diğer HDMI cihazlarınızda HDMI-CEC\'nin etkin olduğundan emin olun. Üreticiler çoğunlukla HDMI-CEC için farklı adlar kullanırlar. Örneğin:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Başka bir kaynağa geçildiğinde bekleme moduna gir"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Bu ayarı ve TV\'nizde HDMI-CEC\'i etkinleştirildiğinde TV\'nizde farklı bir girişe geçtikten kısa bir süre sonra bu cihaz otomatik olarak bekleme moduna girer. Bu özellik, aktif olarak izlemediğinizde içeriği duraklatmaya ve güç tüketimini azaltmaya yardımcı olabilir."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Uzaktan kumanda düğmeleri ayarlayın"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"TV\'lerde, alıcılarda ve ses çubuklarında ses düzeyini, gücü, girişi kontrol edin"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Uzaktan kumandamı bul"</string>
diff --git a/libraries/BluetoothServices/res/values-uk/strings.xml b/libraries/BluetoothServices/res/values-uk/strings.xml
index 3eaf01d..b2a7731 100644
--- a/libraries/BluetoothServices/res/values-uk/strings.xml
+++ b/libraries/BluetoothServices/res/values-uk/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Увімкнути HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"Функція HDMI-CEC дає змогу контролювати, а також автоматично вмикати й вимикати сумісні з нею пристрої за допомогою єдиного пульта дистанційного керування.\n\nПримітка: упевніться, що HDMI-CEC ввімкнено на телевізорі та інших HDMI-пристроях. Назви функції HDMI-CEC можуть відрізнятися залежно від виробника, наприклад:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung – Anynet+\nLG – SimpLink\nSony – BRAVIA Sync\nPhilips – EasyLink\nSharp – Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Переходити в режим очікування в разі перемикання на інше джерело вхідного сигналу"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Якщо ввімкнути це налаштування й HDMI-CEC на телевізорі, цей пристрій автоматично переходитиме в режим очікування невдовзі після перемикання на інший вхід на телевізорі. Це допоможе вам призупиняти відтворення контенту й економити електроенергію, коли ви не дивитеся відео."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Налаштувати кнопки дистанційного керування"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Керуйте гучністю, живленням і джерелами вхідного сигналу телевізора, приймача й звукової панелі"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Знайти пульт"</string>
diff --git a/libraries/BluetoothServices/res/values-ur/strings.xml b/libraries/BluetoothServices/res/values-ur/strings.xml
index e102e6b..89000a9 100644
--- a/libraries/BluetoothServices/res/values-ur/strings.xml
+++ b/libraries/BluetoothServices/res/values-ur/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC فعال کریں"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC آپ کو صرف ایک ریموٹ کنٹرول کے ذریعے HDMI-CEC فعال کردہ دیگر آلات کو خودکار طور پر آن/آف کرنے کی اجازت دیتی ہے۔ \n\nنوٹ: یقینی بنائیں کہ HDMI-CEC آپ کے TV اور دیگر HDMI آلات پر فعال ہو۔ بسا اوقات مینوفیکچررز کے پاس HDMI-CEC کے الگ الگ نام ہوتے ہیں، مثال کے طور پر:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung:‎ Anynet+\nLG:‎ SimpLink\nSony:‎ BRAVIA Sync\nPhilips:‎ EasyLink\nSharp:‎ Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"ان پٹ کو دوسرے ماخذ پر سوئچ کرتے وقت اسٹینڈ بائی میں داخل ہوں"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"جب آپ اس ترتیب کو فعال کرتے ہیں اور HDMI-CEC آپ کے TV پر فعال ہو جاتا ہے تو یہ آلہ آپ کے TV پر مختلف ان پٹ پر سوئچ کرنے کے فوراً بعد خودکار طور پر اسٹینڈ بائی میں داخل ہو جائے گا۔ جب آپ فعال طور پر نہیں دیکھ رہے ہوں تو یہ کارروائی مواد کو موقوف کرنے اور بجلی کی کھپت کو کم کرنے میں مدد کر سکتی ہے۔"</string>
     <string name="settings_axel" msgid="8253298947221430993">"ریموٹ بٹنز سیٹ اپ کریں"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"TVs، ریسیورز اور ساؤنڈ بارز پر والیوم، پاور اور ان پٹ کنٹرول کریں"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"میرا ریموٹ تلاش کریں"</string>
diff --git a/libraries/BluetoothServices/res/values-uz/strings.xml b/libraries/BluetoothServices/res/values-uz/strings.xml
index 43964a5..bdc9771 100644
--- a/libraries/BluetoothServices/res/values-uz/strings.xml
+++ b/libraries/BluetoothServices/res/values-uz/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"HDMI-CEC xususiyatini yoqish"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC bilan boshqa HDMI-CEC xususiyatli qurilmalarni bir pult orqali boshqarish va avtomatik yoqish/oʻchirib qoʻyish mumkin.\n\nEslatma: TV va boshqa HDMI qurilmalaringizda HDMI-CEC yoniqligini tekshiring. Odatda ishlab chiqaruvchilar HDMI-CEC uchun boshqa nomlar ishlatadi, masalan:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Boshqa manbaga almashtirishda kutish rejimiga oʻtish"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Joriy qurilmada bu sozlama va televizorda HDMI-CEC yoqilsa, televizorda boshqa manba tanlanishi bilan bu qruilma avtomatik kutish rejimiga oʻtadi. Natijada, kontent ijrosi toʻxtatilsa, quvvat sarfi pasayadi. Bu funksiya fondagi kontent ijrosi uchun foydali boʻladi."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Pult tugmalarini sozlash"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Televizor, resiver va saundbarlardagi tovush balandligi, quvvat va manbalarni boshqarish"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Pultimni top"</string>
diff --git a/libraries/BluetoothServices/res/values-vi/strings.xml b/libraries/BluetoothServices/res/values-vi/strings.xml
index 1c203d4..c7b1652 100644
--- a/libraries/BluetoothServices/res/values-vi/strings.xml
+++ b/libraries/BluetoothServices/res/values-vi/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Bật HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC cho phép bạn điều khiển và tự động bật/tắt các thiết bị hỗ trợ HDMI-CEC khác chỉ với một bộ điều khiển từ xa.\n\nLưu ý: Hãy đảm bảo là bạn đã bật HDMI-CEC trên TV và các thiết bị HDMI khác. Các nhà sản xuất thường có các tên khác nhau cho HDMI-CEC, ví dụ:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Chuyển sang chế độ chờ khi thay đổi nguồn đầu vào"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Khi bạn bật chế độ cài đặt này và bật HDMI-CEC trên TV, thiết bị này sẽ tự động chuyển sang chế độ chờ ngay sau khi bạn sử dụng nguồn đầu vào khác trên TV. Việc này có thể giúp tạm dừng nội dung và giảm mức tiêu thụ điện năng khi bạn không xem TV."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Thiết lập nút trên điều khiển từ xa"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Điều chỉnh âm lượng, điều khiển nguồn, nguồn đầu vào của TV, bộ thu và loa thanh"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Tìm điều khiển từ xa"</string>
diff --git a/libraries/BluetoothServices/res/values-zh-rCN/strings.xml b/libraries/BluetoothServices/res/values-zh-rCN/strings.xml
index cd3b309..4eb44f2 100644
--- a/libraries/BluetoothServices/res/values-zh-rCN/strings.xml
+++ b/libraries/BluetoothServices/res/values-zh-rCN/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"启用 HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC 可让您通过一个遥控器控制及自动开启/关闭其他启用了 HDMI-CEC 的设备。\n\n注意：请确认您的电视和其他 HDMI 设备均已启用 HDMI-CEC。不同的制造商对 HDMI-CEC 通常有不同的称呼，例如："</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"三星：Anynet+\nLG：SimpLink\n索尼：BRAVIA Sync\n飞利浦：EasyLink\n夏普：Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"将输入源切换到其他来源后进入待机状态"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"当您启用此设置并在电视上启用 HDMI-CEC 后，此设备会在您将电视切换到其他输入源后不久自动进入待机状态。这样，在您不观看时，设备可以自动暂停播放内容并降低耗电量。"</string>
     <string name="settings_axel" msgid="8253298947221430993">"设置遥控器按钮"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"控制电视、接收器及条形音箱的音量、电源和输入源"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"查找我的遥控器"</string>
diff --git a/libraries/BluetoothServices/res/values-zh-rHK/strings.xml b/libraries/BluetoothServices/res/values-zh-rHK/strings.xml
index 9f770cf..677f861 100644
--- a/libraries/BluetoothServices/res/values-zh-rHK/strings.xml
+++ b/libraries/BluetoothServices/res/values-zh-rHK/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"啟用 HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC 讓你使用同一個遙控即可控制和自動開啟/關閉其他已啟用 HDMI-CEC 的裝置。\n\n請注意：請確定電視和其他 HDMI 裝置已啟用 HDMI-CEC。不同製造商有不同的 HDMI-CEC 名稱，例如："</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung：Anynet+\nLG：SimpLink\nSony：BRAVIA Sync\nPhilips：EasyLink\nSharp：Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"切換至其他輸入來源時進入待機模式"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"在電視啟用此設定和 HDMI-CEC 後，你在電視切換至其他輸入來源時，此裝置將會自動在短時間內進入待機模式。此設定讓你在未有觀看內容時，暫停播放內容並減少耗電。"</string>
     <string name="settings_axel" msgid="8253298947221430993">"設定遙控器按鈕"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"控制電視、接收器和 Soundbar 揚聲器的音量、電源開關和訊號源"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"尋找遙控器"</string>
diff --git a/libraries/BluetoothServices/res/values-zh-rTW/strings.xml b/libraries/BluetoothServices/res/values-zh-rTW/strings.xml
index 2210aaf..77b397d 100644
--- a/libraries/BluetoothServices/res/values-zh-rTW/strings.xml
+++ b/libraries/BluetoothServices/res/values-zh-rTW/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"啟用 HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"HDMI-CEC 可讓你透過一個遙控器控制及自動開啟/關閉其他支援 HDMI-CEC 的裝置。\n\n注意：請確認你的電視和其他 HDMI 裝置已啟用 HDMI-CEC 功能。不同的製造商對 HDMI-CEC 功能有其各自的稱呼。例如："</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung：Anynet+\nLG：SimpLink\nSony：BRAVIA Sync\nPhilips：EasyLink\nSharp：Aquos Link"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"切換輸入來源時進入待機模式"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"如果啟用這項設定，且電視已啟用 HDMI-CEC，你切換輸入來源不久後，這部裝置就會自動進入待機模式，在你未觀看影視內容時暫停播放，藉此降低耗電量。"</string>
     <string name="settings_axel" msgid="8253298947221430993">"設定遙控器按鈕"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"控制電視、接收器和單件式環繞劇院的音量、電源和輸入來源"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"尋找我的聲控器"</string>
diff --git a/libraries/BluetoothServices/res/values-zu/strings.xml b/libraries/BluetoothServices/res/values-zu/strings.xml
index 9303760..519bad4 100644
--- a/libraries/BluetoothServices/res/values-zu/strings.xml
+++ b/libraries/BluetoothServices/res/values-zu/strings.xml
@@ -63,6 +63,8 @@
     <string name="settings_enable_hdmi_cec" msgid="3955194037299390473">"Nika amandla i-HDMI-CEC"</string>
     <string name="settings_cec_explain" msgid="282126756909187653">"I-HDMI-CEC ikuvumela ukuthi ulawule futhi uvule/uvale ngokuzenzakalela amadivayisi anikwe amandla i-HDMI-CEC ngesilawulikude esisodwa.\n\nQaphela: Qiniseka ukuthi i-HDMI-CEC inikwe amandla ku-TV yakho namanye amadivayisi. Abakhiqizi bavame ukuba namagama ahlukahlukene e-HDMI-CEC, isibonelo:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"I-Samsung: I-Anynet+\nLG: I-SimpLink\nSony: I-BRAVIA Sync\nPhilips: I-EasyLink\nSharp: Isixhumanisi se-Aquos"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"Faka okubekwe eceleni lapho ushintshela okokufaka komunye umthombo"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"Uma unika amandla leli sethingi futhi uvula i-HDMI-CEC ku-TV yakho, le divayisi izongena ngokuzenzekela okulindile ngemva nje kokushintshela kokokufaka okuhlukile ku-TV yakho. Lokhu kungasiza ukumisa isikhashana okuqukethwe futhi kunciphise ukusetshenziswa kwamandla uma ungabukeli kakhulu."</string>
     <string name="settings_axel" msgid="8253298947221430993">"Setha izinkinobho zerimothi"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"Lawula ivolumu, amandla, okokufaka kuma-TV, izamukeli namabha omsindo"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"Thola irimothi yami"</string>
diff --git a/libraries/BluetoothServices/res/values/strings.xml b/libraries/BluetoothServices/res/values/strings.xml
index b596648..5b8e95c 100644
--- a/libraries/BluetoothServices/res/values/strings.xml
+++ b/libraries/BluetoothServices/res/values/strings.xml
@@ -81,6 +81,8 @@
   <string name="settings_enable_hdmi_cec">Enable HDMI-CEC</string>
   <string name="settings_cec_explain">HDMI-CEC allows you to control and automatically turn on/off other HDMI-CEC enabled devices with a single remote control.\n\nNote: Ensure HDMI-CEC is enabled on your TV and other HDMI devices. Manufacturers often have different names for HDMI-CEC, for example:</string>
   <string name="settings_cec_feature_names">Samsung: Anynet+\nLG: SimpLink\nSony: BRAVIA Sync\nPhilips: EasyLink\nSharp: Aquos Link</string>
+  <string name="settings_cec_go_to_sleep_on_active_source_lost_title">Enter standby when switching input to another source</string>
+  <string name="settings_cec_go_to_sleep_on_active_source_lost_description">When you enable this setting and have HDMI-CEC enabled on your TV, this device will automatically enter standby shortly after you switch to a different input on your TV. This may help pause content and reduce power consumption when you aren\'t actively watching.</string>
 
   <string name="settings_axel">Set up remote buttons</string>
   <string name="settings_axel_description">Control volume, power, input on TVs, receivers and soundbars</string>
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/BluetoothUtils.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/BluetoothUtils.java
index ef30f60..f0202f0 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/BluetoothUtils.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/BluetoothUtils.java
@@ -16,6 +16,8 @@
 
 package com.google.android.tv.btservices;
 
+import static android.media.tv.flags.Flags.enableLeAudioUnicastUi;
+
 import android.annotation.SuppressLint;
 import android.bluetooth.BluetoothAdapter;
 import android.bluetooth.BluetoothClass;
@@ -27,6 +29,9 @@ import android.util.Log;
 import com.android.settingslib.bluetooth.CachedBluetoothDevice;
 import com.android.settingslib.bluetooth.LocalBluetoothManager;
 import com.android.settingslib.bluetooth.LocalBluetoothProfile;
+import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
+import com.android.settingslib.bluetooth.A2dpProfile;
+import com.android.settingslib.bluetooth.LeAudioProfile;
 
 import java.util.Arrays;
 import java.util.Collections;
@@ -340,8 +345,11 @@ public class BluetoothUtils {
         return null;
     }
 
-    /** Returns true if the BluetoothDevice is the active audio output, false otherwise. */
-    public static boolean isActiveAudioOutput(BluetoothDevice device) {
+    /**
+     * Returns true if the BluetoothDevice is the active audio output over A2DP,
+     * false otherwise.
+     */
+    public static boolean isActiveA2dpAudioOutput(BluetoothDevice device) {
         if (device != null) {
             final BluetoothAdapter btAdapter = getDefaultBluetoothAdapter();
             if (btAdapter != null) {
@@ -369,15 +377,80 @@ public class BluetoothUtils {
         return false;
     }
 
+    /** Returns true if the platform supports LE Audio Unicast, false otherwise. */
+    public static boolean leAudioUnicastSupported(Context context) {
+        final LocalBluetoothManager btManager = getLocalBluetoothManager(context);
+        if (btManager == null) {
+            return false;
+        }
+
+        final LocalBluetoothProfileManager btProfileManager = btManager.getProfileManager();
+        if (btProfileManager == null) {
+            return false;
+        }
+
+        // The BT Framework returns a profile only if
+        // LeAudioService is enabled and running.
+        return btProfileManager.getLeAudioProfile() != null;
+    }
+
+    /** Returns true if the BluetoothDevice is an LE Audio device, false otherwise. */
+    public static boolean isLeAudioDevice(BluetoothDevice device) {
+        if (device == null) {
+            return false;
+        }
+
+        final BluetoothAdapter btAdapter = getDefaultBluetoothAdapter();
+        if (btAdapter != null) {
+            return btAdapter.getActiveDevices(BluetoothProfile.LE_AUDIO).contains(device);
+        }
+
+        return false;
+    }
+
     /**
-     * Returns true if the CachedBluetoothDevice supports an audio profile (A2DP for now),
-     * false otherwise.
+     * Flips the specified audio device between LE Audio and A2DP. Returns false
+     * if no device was set.
+     */
+    public static boolean setLeAudioEnabled(BluetoothDevice device, Context context, boolean leAudioEnabled) {
+        if (device == null) {
+            return false;
+        }
+
+        final LocalBluetoothManager btManager = getLocalBluetoothManager(context);
+        if (btManager == null) {
+            return false;
+        }
+
+        final LocalBluetoothProfileManager btProfileManager = btManager.getProfileManager();
+        if (btProfileManager == null) {
+            return false;
+        }
+
+        LeAudioProfile leAudioProfile = btProfileManager.getLeAudioProfile();
+        A2dpProfile a2dpProfile = btProfileManager.getA2dpProfile();
+        if (leAudioEnabled) {
+            a2dpProfile.setEnabled(device, false);
+            leAudioProfile.setEnabled(device, true);
+        } else {
+            leAudioProfile.setEnabled(device, false);
+            a2dpProfile.setEnabled(device, true);
+        }
+        return true;
+    }
+
+    /**
+     * Returns true if the CachedBluetoothDevice supports an audio profile
+     * (A2DP or LE Audio for now), false otherwise.
      */
     public static boolean hasAudioProfile(CachedBluetoothDevice cachedDevice) {
       if (cachedDevice != null) {
           for (LocalBluetoothProfile profile : cachedDevice.getProfiles()) {
               if (profile.getProfileId() == BluetoothProfile.A2DP) {
                   return true;
+              } else if (enableLeAudioUnicastUi()
+              && profile.getProfileId() == BluetoothProfile.LE_AUDIO) {
+                return true;
               }
           }
       }
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/PowerUtils.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/PowerUtils.java
index 4bec449..167d3ae 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/PowerUtils.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/PowerUtils.java
@@ -36,4 +36,22 @@ public class PowerUtils {
                 ? HdmiControlManager.HDMI_CEC_CONTROL_ENABLED
                 : HdmiControlManager.HDMI_CEC_CONTROL_DISABLED);
     }
+
+    public static boolean isEnabledGoToSleepOnActiveSourceLost(Context context) {
+        HdmiControlManager hdmiControlManager = context.getSystemService(HdmiControlManager.class);
+        return hdmiControlManager.getPowerStateChangeOnActiveSourceLost().equals(
+            HdmiControlManager.POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST_STANDBY_NOW);
+    }
+
+    public static void setPowerStateChangeOnActiveSourceLost(Context context, boolean enable) {
+        HdmiControlManager hdmiControlManager = context.getSystemService(HdmiControlManager.class);
+        hdmiControlManager.setPowerStateChangeOnActiveSourceLost(enable
+            ? HdmiControlManager.POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST_STANDBY_NOW
+            : HdmiControlManager.POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST_NONE);
+    }
+
+    public static boolean isPlaybackDevice(Context context) {
+        HdmiControlManager hdmiControlManager = context.getSystemService(HdmiControlManager.class);
+        return hdmiControlManager.getPlaybackClient() != null;
+    }
 }
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/remote/BleConnection.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/remote/BleConnection.java
index 4c3d09e..38cb215 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/remote/BleConnection.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/remote/BleConnection.java
@@ -125,6 +125,7 @@ public class BleConnection {
     private CharacteristicReadResultCallback lastCharacteristicReadCallback;
     private DescriptorWriteResultCallback lastDescriptorWriteCallback;
     private Consumer<Boolean> lastRequestMtuCallback;
+    public Context mContext;
 
     private class CharacteristicWriteRequest implements GattRequest {
         final BluetoothGattCharacteristic characteristic;
@@ -204,6 +205,7 @@ public class BleConnection {
         if (state.compareAndSet(
                     ConnectionState.UNINITIALIZED,
                     ConnectionState.GATT_CONNECTING)) {
+            mContext = context;
             synchronized (state) {
                 gatt = device.connectGatt(context, false, new GattCallback());
             }
@@ -361,7 +363,7 @@ public class BleConnection {
             }
             if (newState == BluetoothProfile.STATE_CONNECTED) {
                 Log.i(TAG, "Remote connected. Calibrating the time clock...");
-                schedulePeriodicSyncs();
+                schedulePeriodicSyncs(mContext);
                 if (state.compareAndSet(
                         ConnectionState.GATT_CONNECTING,
                         ConnectionState.SERVICE_DISCOVERING)) {
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
index b83947d..8d423b4 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
@@ -19,6 +19,8 @@ package com.google.android.tv.btservices.settings;
 import static android.app.PendingIntent.FLAG_IMMUTABLE;
 import static android.app.PendingIntent.FLAG_UPDATE_CURRENT;
 import static android.content.Intent.FLAG_RECEIVER_FOREGROUND;
+import static android.media.tv.flags.Flags.hdmiControlEnhancedBehavior;
+import static android.media.tv.flags.Flags.enableLeAudioUnicastUi;
 
 import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_SLICE_FOLLOWUP;
 
@@ -40,7 +42,9 @@ import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.A
 import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.ACTION_FIND_MY_REMOTE;
 import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.ACTION_TOGGLE_CHANGED;
 import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.ACTIVE_AUDIO_OUTPUT;
+import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.LE_AUDIO_UNICAST;
 import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.CEC;
+import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST;
 import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.TOGGLE_STATE;
 import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.TOGGLE_TYPE;
 import static com.google.android.tv.btservices.settings.SliceBroadcastReceiver.backAndUpdateSliceIntent;
@@ -111,6 +115,8 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
     private static final boolean DISCONNECT_PREFERENCE_ENABLED = false;
     private static final int ACTIVE_AUDIO_OUTPUT_REQUEST_CODE = 4;
     private static final int ACTIVE_AUDIO_OUTPUT_UPDATE_REQUEST_CODE = 5;
+    private static final int LE_AUDIO_UNICAST_REQUEST_CODE = 6;
+    private static final int LE_AUDIO_UNICAST_UPDATE_REQUEST_CODE = 7;
     private boolean mBtDeviceServiceBound;
     private final Map<String, Version> mVersionsMap = new ConcurrentHashMap<>();
     private BluetoothDeviceService.LocalBinder mBtDeviceServiceBinder;
@@ -541,7 +547,7 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
                 && BluetoothUtils.isConnected(device) && cachedDevice.isConnected()
                 && (BluetoothUtils.isBluetoothHeadset(device)
                 || BluetoothUtils.hasAudioProfile(cachedDevice))) {
-            boolean isActive = BluetoothUtils.isActiveAudioOutput(device);
+            boolean isActive = BluetoothUtils.isActiveA2dpAudioOutput(device);
 
             Intent intent = new Intent(ACTION_TOGGLE_CHANGED);
             intent.setClass(context, SliceBroadcastReceiver.class);
@@ -668,6 +674,40 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
         forgetPref.setPendingIntent(disconnectPendingIntent);
         psb.addPreference(forgetPref);
 
+        // Update "LE Audio".
+        if (enableLeAudioUnicastUi()
+        && BluetoothUtils.leAudioUnicastSupported(context)
+        && BluetoothUtils.hasAudioProfile(cachedDevice)) {
+            boolean isActive = BluetoothUtils.isLeAudioDevice(device);
+
+            Intent intent = new Intent(ACTION_TOGGLE_CHANGED);
+            intent.setClass(context, SliceBroadcastReceiver.class);
+            intent.putExtra(TOGGLE_TYPE, LE_AUDIO_UNICAST);
+            intent.putExtra(TOGGLE_STATE, !isActive);
+            intent.putExtra(KEY_EXTRAS_DEVICE, device);
+
+            updatedUris = Arrays.asList(GENERAL_SLICE_URI.toString(), sliceUri.toString());
+            updateSliceIntent = updateSliceIntent(getContext(),
+                    LE_AUDIO_UNICAST_UPDATE_REQUEST_CODE, new ArrayList<>(updatedUris),
+                    sliceUri.toString());
+            intent.putExtra(EXTRA_SLICE_FOLLOWUP, updateSliceIntent);
+
+            PendingIntent pendingIntent = PendingIntent.getBroadcast(context,
+                    LE_AUDIO_UNICAST_REQUEST_CODE, intent,
+                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
+
+            // Update set/unset active LE Audio preference
+            RowBuilder leAudioPref = new RowBuilder()
+                    .setKey("KEY_TOGGLE_LE_UNICAST")
+                    .setTitle("LE Audio")
+                    .setActionId(0) // TODO: Add a TvSettingsEnums entry for LE Audio
+                    .addSwitch(pendingIntent,
+                            "LE Audio",
+                            isActive);
+
+            psb.addPreference(leAudioPref);
+        }
+
         // Update "bluetooth device info preference".
         RowBuilder infoPref = new RowBuilder()
                 .setIcon(IconCompat.createWithResource(context, R.drawable.ic_baseline_info_24dp));
@@ -707,7 +747,7 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
                 new RowBuilder()
                         .setTitle(getString(R.string.settings_hdmi_cec))
                         .setPageId(0x18300000)); // TvSettingsEnums.CONNECTED_SLICE_HDMICEC
-        final boolean isEnabled = PowerUtils.isCecControlEnabled(getContext());
+        final boolean isEnabled = PowerUtils.isCecControlEnabled(context);
         Intent intent = new Intent(context, SliceBroadcastReceiver.class)
                 .setAction(ACTION_TOGGLE_CHANGED)
                 .putExtra(TOGGLE_TYPE, CEC)
@@ -724,6 +764,30 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
         psb.addPreference(new RowBuilder()
                 .setTitle(getString(R.string.settings_cec_feature_names))
                 .setEnabled(false));
+
+        // Allow the user to choose the behavior of their device when losing active source.
+        // This setting should be visible only on playback devices (OTTs/STBs) and it should be
+        // available to be toggled only when CEC is enabled.
+        if (hdmiControlEnhancedBehavior() && PowerUtils.isPlaybackDevice(context)) {
+            final boolean isEnabledGoToSleepOnActiveSourceLost =
+                    PowerUtils.isEnabledGoToSleepOnActiveSourceLost(context);
+            Intent intentGoToSleepOnActiveSourceLost = new Intent(context,
+                    SliceBroadcastReceiver.class)
+                    .setAction(ACTION_TOGGLE_CHANGED)
+                    .putExtra(TOGGLE_TYPE, POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST)
+                    .putExtra(TOGGLE_STATE, !isEnabledGoToSleepOnActiveSourceLost);
+            PendingIntent pendingIntentGoToSleepOnActiveSourceLost = PendingIntent.getBroadcast(
+                    context, 1, intentGoToSleepOnActiveSourceLost,
+                    FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT);
+            psb.addPreference(new RowBuilder()
+                    .setTitle(getString(
+                            R.string.settings_cec_go_to_sleep_on_active_source_lost_title))
+                    .setInfoSummary(getString(
+                            R.string.settings_cec_go_to_sleep_on_active_source_lost_description))
+                    .addSwitch(pendingIntentGoToSleepOnActiveSourceLost, null,
+                            isEnabledGoToSleepOnActiveSourceLost && isEnabled)
+                    .setEnabled(isEnabled));
+        }
         return psb.build();
     }
 
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/SliceBroadcastReceiver.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/SliceBroadcastReceiver.java
index 55c8b41..b5e48f3 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/SliceBroadcastReceiver.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/SliceBroadcastReceiver.java
@@ -19,6 +19,7 @@ package com.google.android.tv.btservices.settings;
 import static android.content.Intent.FLAG_INCLUDE_STOPPED_PACKAGES;
 import static android.content.Intent.FLAG_RECEIVER_FOREGROUND;
 import static android.content.Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND;
+import static android.media.tv.flags.Flags.enableLeAudioUnicastUi;
 
 import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_SLICE_FOLLOWUP;
 import static com.google.android.tv.btservices.settings.ConnectedDevicesSliceProvider.KEY_EXTRAS_DEVICE;
@@ -54,6 +55,8 @@ import java.util.ArrayList;
 public class SliceBroadcastReceiver extends BroadcastReceiver {
     private static final String TAG = "SliceBroadcastReceiver";
     static final String CEC = "CEC";
+    static final String POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST =
+        "POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST";
 
     static final String TOGGLE_TYPE = "TOGGLE_TYPE";
     static final String TOGGLE_STATE = "TOGGLE_STATE";
@@ -64,6 +67,7 @@ public class SliceBroadcastReceiver extends BroadcastReceiver {
     static final String ACTION_BACKLIGHT = "com.google.android.tv.BACKLIGHT";
     static final String KEY_BACKLIGHT_MODE = "key_backlight_mode";
     static final String ACTIVE_AUDIO_OUTPUT = "ACTIVE_AUDIO_OUTPUT";
+    static final String LE_AUDIO_UNICAST = "LE_AUDIO_UNICAST";
     private static final String ACTION_UPDATE_SLICE = "UPDATE_SLICE";
     private static final String ACTION_BACK_AND_UPDATE_SLICE = "BACK_AND_UPDATE_SLICE";
     private static final String PARAM_URIS = "URIS";
@@ -100,6 +104,24 @@ public class SliceBroadcastReceiver extends BroadcastReceiver {
                     } catch (Throwable ex) {
                         Log.e(TAG, "Followup PendingIntent for slice cannot be sent", ex);
                     }
+                } else if (POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST.equals(toggleType)) {
+                    PowerUtils.setPowerStateChangeOnActiveSourceLost(context, isChecked);
+                    context.getContentResolver().notifyChange(CEC_SLICE_URI, null);
+                } else if (enableLeAudioUnicastUi() && LE_AUDIO_UNICAST.equals(toggleType)) {
+                    boolean enabled = intent.getBooleanExtra(TOGGLE_STATE, false);
+                    BluetoothDevice device = intent.getParcelableExtra(KEY_EXTRAS_DEVICE,
+                            BluetoothDevice.class);
+                    BluetoothUtils.setLeAudioEnabled(device, context, enabled);
+                    // If there is followup pendingIntent, send it
+                    try {
+                        PendingIntent followupPendingIntent = intent.getParcelableExtra(
+                                EXTRA_SLICE_FOLLOWUP, PendingIntent.class);
+                        if (followupPendingIntent != null) {
+                            followupPendingIntent.send();
+                        }
+                    } catch (Throwable ex) {
+                        Log.e(TAG, "Followup PendingIntent for slice cannot be sent", ex);
+                    }
                 }
                 break;
             }
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/syncwork/RemoteSyncWorkManager.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/syncwork/RemoteSyncWorkManager.java
index 64aa732..f8093a4 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/syncwork/RemoteSyncWorkManager.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/syncwork/RemoteSyncWorkManager.java
@@ -24,6 +24,7 @@ import androidx.work.ExistingPeriodicWorkPolicy;
 import androidx.work.Operation;
 import androidx.work.PeriodicWorkRequest;
 import androidx.work.WorkManager;
+import androidx.work.Configuration;
 
 import java.util.concurrent.TimeUnit;
 
@@ -35,9 +36,23 @@ public class RemoteSyncWorkManager {
     public static final String WORK_NAME = "SYNC_REMOTE_PERIODIC";
 
     public RemoteSyncWorkManager(){}
-    private static final WorkManager workManager = WorkManager.getInstance();
 
-    public static void schedulePeriodicSyncs() {
+    public static WorkManager getWorkManagerInstance(Context context) {
+        // Typically WorkManager is initialized as part of app start up. It is possible for
+        // apps to disable that for customized configuration, so to be safe we should
+        // attempt to initialize it here as well.
+        try {
+            WorkManager.initialize(context.getApplicationContext(),
+                    new Configuration.Builder().build());
+        } catch (IllegalStateException ex) {
+            // The call to initialize can fail in normal scenarios when WorkManager is already
+            // initialized.
+        }
+        return WorkManager.getInstance(context.getApplicationContext());
+    }
+
+    public static void schedulePeriodicSyncs(Context context) {
+        WorkManager workManager = getWorkManagerInstance(context);
         Log.i(TAG, "Scheduling periodic remote time syncs");
         // Run periodically
         final PeriodicWorkRequest periodicSyncRequest = getDailySyncRequest();
diff --git a/overlay/TvFrameworkOverlay/res/values/config.xml b/overlay/TvFrameworkOverlay/res/values/config.xml
index 7577052..f102cb3 100644
--- a/overlay/TvFrameworkOverlay/res/values/config.xml
+++ b/overlay/TvFrameworkOverlay/res/values/config.xml
@@ -207,4 +207,7 @@
 
     <!-- If supported, whether Low Power Standby is enabled by default. -->
     <bool name="config_lowPowerStandbyEnabledByDefault">true</bool>
+
+    <!-- Bytes that the PinnerService will pin for Home app. -->
+    <integer name="config_pinnerHomePinBytes">0</integer>
 </resources>
diff --git a/products/atv_emulator_vendor.mk b/products/atv_emulator_vendor.mk
index ab3a5fb..ea3c8a5 100644
--- a/products/atv_emulator_vendor.mk
+++ b/products/atv_emulator_vendor.mk
@@ -51,9 +51,11 @@ PRODUCT_CHARACTERISTICS := emulator
 PRODUCT_COPY_FILES += \
     device/generic/goldfish/data/etc/config.ini.tv:config.ini
 
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/data/etc/advancedFeatures.ini:advancedFeatures.ini
+
 PRODUCT_COPY_FILES += \
     device/generic/goldfish/camera/media/media_codecs_google_tv.xml:${TARGET_COPY_OUT_VENDOR}/etc/media_codecs_google_tv.xml \
-    device/generic/goldfish/data/etc/apns-conf.xml:$(TARGET_COPY_OUT_VENDOR)/etc/apns-conf.xml \
     frameworks/native/data/etc/android.hardware.ethernet.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.ethernet.xml \
     hardware/libhardware_legacy/audio/audio_policy.conf:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy.conf
 
diff --git a/products/atv_logpersist.mk b/products/atv_logpersist.mk
index 7c0f814..3e4a291 100644
--- a/products/atv_logpersist.mk
+++ b/products/atv_logpersist.mk
@@ -2,8 +2,6 @@
 # See go/agw/platform/system/logging/+/refs/heads/master/logd/README.property for available options
 
 ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
-PRODUCT_PRODUCT_PROPERTIES +=
-    logd.logpersistd=logcatd \
-    logd.logpersistd.size=30 \
-    logd.logpersistd.rotate_kbytes=2048
+PRODUCT_PRODUCT_PROPERTIES += \
+    logd.logpersistd=logcatd
 endif
diff --git a/products/atv_lowram_defaults.mk b/products/atv_lowram_defaults.mk
index e0cee53..522cbf2 100644
--- a/products/atv_lowram_defaults.mk
+++ b/products/atv_lowram_defaults.mk
@@ -34,7 +34,6 @@ PRODUCT_COPY_FILES += device/google/atv/products/lowram_boot_profiles/preloaded-
 # Use TV specific profile for the boot classpath, determines which methods
 # from the boot classpath get optimized, which class is included in the boot
 # .art image, and how the corresponding DEX files are laid out.
-PRODUCT_USE_PROFILE_FOR_BOOT_IMAGE := true
 PRODUCT_DEX_PREOPT_BOOT_IMAGE_PROFILE_LOCATION := device/google/atv/products/lowram_boot_profiles/boot-image-profile.txt
 
 # Do not generate libartd.
diff --git a/products/atv_product.mk b/products/atv_product.mk
index 4c38e84..a7bacc5 100644
--- a/products/atv_product.mk
+++ b/products/atv_product.mk
@@ -17,8 +17,6 @@
 # a generic TV device.
 $(call inherit-product, $(SRC_TARGET_DIR)/product/media_product.mk)
 
-PRODUCT_PUBLIC_SEPOLICY_DIRS += device/google/atv/audio_proxy/sepolicy/public
-
 PRODUCT_PACKAGES += \
     TvNetworkStackOverlay \
     TvFrameworkOverlay \
@@ -41,3 +39,8 @@ PRODUCT_COPY_FILES += \
 # Too many tombstones can cause bugreports to grow too large to be uploaded.
 PRODUCT_PRODUCT_PROPERTIES += \
     tombstoned.max_tombstone_count?=10
+
+# Limit persistent logs to 60MB
+PRODUCT_PRODUCT_PROPERTIES += \
+    logd.logpersistd.size=30 \
+    logd.logpersistd.rotate_kbytes=2048
diff --git a/products/atv_system.mk b/products/atv_system.mk
index cd4364b..3ffafcb 100644
--- a/products/atv_system.mk
+++ b/products/atv_system.mk
@@ -15,6 +15,10 @@
 #
 # This makefile contains the system partition contents for
 # a generic TV device.
+
+# Release Configuration map
+PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard vendor/google_shared/tv/release/release_config_map.textproto)
+
 $(call inherit-product, $(SRC_TARGET_DIR)/product/media_system.mk)
 
 $(call inherit-product-if-exists, frameworks/base/data/fonts/fonts.mk)
```

