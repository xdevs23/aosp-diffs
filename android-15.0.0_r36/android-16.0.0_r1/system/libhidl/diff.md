```diff
diff --git a/Android.bp b/Android.bp
index 06959a0..961f47f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -98,8 +98,7 @@ cc_library {
         // - no testing story/infra for deprecation schedule
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.media",
         "com.android.media.swcodec",
         "com.android.nfcservices",
diff --git a/base/include/hidl/HidlInternal.h b/base/include/hidl/HidlInternal.h
index 3d1a444..bc11979 100644
--- a/base/include/hidl/HidlInternal.h
+++ b/base/include/hidl/HidlInternal.h
@@ -118,18 +118,22 @@ private:
 };
 
 #define HAL_LIBRARY_PATH_SYSTEM_64BIT "/system/lib64/hw/"
+#define HAL_LIBRARY_PATH_SYSTEM_EXT_64BIT "/system_ext/lib64/hw/"
 #define HAL_LIBRARY_PATH_VENDOR_64BIT "/vendor/lib64/hw/"
 #define HAL_LIBRARY_PATH_ODM_64BIT    "/odm/lib64/hw/"
 #define HAL_LIBRARY_PATH_SYSTEM_32BIT "/system/lib/hw/"
+#define HAL_LIBRARY_PATH_SYSTEM_EXT_32BIT "/system_ext/lib/hw/"
 #define HAL_LIBRARY_PATH_VENDOR_32BIT "/vendor/lib/hw/"
 #define HAL_LIBRARY_PATH_ODM_32BIT    "/odm/lib/hw/"
 
 #if defined(__LP64__)
 #define HAL_LIBRARY_PATH_SYSTEM HAL_LIBRARY_PATH_SYSTEM_64BIT
+#define HAL_LIBRARY_PATH_SYSTEM_EXT HAL_LIBRARY_PATH_SYSTEM_EXT_64BIT
 #define HAL_LIBRARY_PATH_VENDOR HAL_LIBRARY_PATH_VENDOR_64BIT
 #define HAL_LIBRARY_PATH_ODM    HAL_LIBRARY_PATH_ODM_64BIT
 #else
 #define HAL_LIBRARY_PATH_SYSTEM HAL_LIBRARY_PATH_SYSTEM_32BIT
+#define HAL_LIBRARY_PATH_SYSTEM_EXT HAL_LIBRARY_PATH_SYSTEM_EXT_32BIT
 #define HAL_LIBRARY_PATH_VENDOR HAL_LIBRARY_PATH_VENDOR_32BIT
 #define HAL_LIBRARY_PATH_ODM    HAL_LIBRARY_PATH_ODM_32BIT
 #endif
diff --git a/fuzzer/Android.bp b/fuzzer/Android.bp
index c353960..09d41bf 100644
--- a/fuzzer/Android.bp
+++ b/fuzzer/Android.bp
@@ -27,8 +27,6 @@ cc_defaults {
         "liblog",
         "libcutils",
         "libutils",
-        "libprocessgroup",
-        "libjsoncpp",
         "libfmq",
     ],
     target: {
diff --git a/libhidlmemory/Android.bp b/libhidlmemory/Android.bp
index 063cd8e..43654d2 100644
--- a/libhidlmemory/Android.bp
+++ b/libhidlmemory/Android.bp
@@ -38,7 +38,6 @@ cc_library {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
         "com.android.media",
         "com.android.media.swcodec",
     ],
diff --git a/transport/HidlLazyUtils.cpp b/transport/HidlLazyUtils.cpp
index c5f8c74..618f279 100644
--- a/transport/HidlLazyUtils.cpp
+++ b/transport/HidlLazyUtils.cpp
@@ -16,6 +16,8 @@
 
 #define LOG_TAG "HidlLazyUtils"
 
+#include <mutex>
+
 #include <hidl/HidlLazyUtils.h>
 #include <hidl/HidlTransportSupport.h>
 
diff --git a/transport/ServiceManagement.cpp b/transport/ServiceManagement.cpp
index b5e02df..447701f 100644
--- a/transport/ServiceManagement.cpp
+++ b/transport/ServiceManagement.cpp
@@ -513,10 +513,10 @@ struct PassthroughServiceManager : IServiceManager1_1 {
         dlerror(); // clear
 
         static std::string halLibPathVndkSp = details::getVndkSpHwPath();
-        std::vector<std::string> paths = {
-            HAL_LIBRARY_PATH_ODM, HAL_LIBRARY_PATH_VENDOR, halLibPathVndkSp,
+        std::vector<std::string> paths = {HAL_LIBRARY_PATH_ODM, HAL_LIBRARY_PATH_VENDOR,
+                                          halLibPathVndkSp,
 #ifndef __ANDROID_VNDK__
-            HAL_LIBRARY_PATH_SYSTEM,
+                                          HAL_LIBRARY_PATH_SYSTEM, HAL_LIBRARY_PATH_SYSTEM_EXT
 #endif
         };
 
diff --git a/transport/memory/1.0/default/Android.bp b/transport/memory/1.0/default/Android.bp
index c0dd3b7..e631215 100644
--- a/transport/memory/1.0/default/Android.bp
+++ b/transport/memory/1.0/default/Android.bp
@@ -26,6 +26,7 @@ cc_library_shared {
     vendor_available: true,
     compile_multilib: "both",
     relative_install_path: "hw",
+    system_ext_specific: true,
     defaults: ["libhidl-defaults"],
     srcs: [
         "AshmemMapper.cpp",
diff --git a/transport/token/1.0/utils/include/hidl/HybridInterface.h b/transport/token/1.0/utils/include/hidl/HybridInterface.h
index d00a0a1..2fb4c35 100644
--- a/transport/token/1.0/utils/include/hidl/HybridInterface.h
+++ b/transport/token/1.0/utils/include/hidl/HybridInterface.h
@@ -323,7 +323,7 @@ private:
             if (mHasConverter) {
                 typedef std::variant_alternative_t<Index, _ConverterVar>
                         Converter;
-                sp<Converter> converter = new Converter(halInterface);
+                sp<Converter> converter = sp<Converter>::make(halInterface);
                 if (converter) {
                     mBase = converter;
                 } else {
@@ -347,72 +347,62 @@ private:
 
 // ----------------------------------------------------------------------
 
-#define DECLARE_HYBRID_META_INTERFACE(INTERFACE, ...)                     \
-        DECLARE_HYBRID_META_INTERFACE_WITH_CODE(                          \
-            ::android::DEFAULT_GET_HAL_TOKEN_TRANSACTION_CODE,            \
-            INTERFACE, __VA_ARGS__)                                       \
-
-
-#define DECLARE_HYBRID_META_INTERFACE_WITH_CODE(GTKCODE, INTERFACE, ...)  \
-private:                                                                  \
-    typedef ::std::variant<::std::monostate, __VA_ARGS__> _HalVariant;    \
-    template <typename... Types>                                          \
-    using _SpVariant =                                                    \
-            ::std::variant<::std::monostate, ::android::sp<Types>...>;    \
-public:                                                                   \
-    typedef _SpVariant<__VA_ARGS__> HalVariant;                           \
-    virtual HalVariant getHalVariant() const;                             \
-    size_t getHalIndex() const;                                           \
-    template <size_t Index>                                               \
-    using HalInterface = ::std::variant_alternative_t<Index, _HalVariant>;\
-    template <typename HAL>                                               \
-    sp<HAL> getHalInterface() const {                                     \
-        HalVariant halVariant = getHalVariant();                          \
-        const sp<HAL>* hal = std::get_if<sp<HAL>>(&halVariant);           \
-        return hal ? *hal : nullptr;                                      \
-    }                                                                     \
-                                                                          \
-    static const ::android::String16 descriptor;                          \
-    static ::android::sp<I##INTERFACE> asInterface(                       \
-            const ::android::sp<::android::IBinder>& obj);                \
-    virtual const ::android::String16& getInterfaceDescriptor() const;    \
-    I##INTERFACE();                                                       \
-    virtual ~I##INTERFACE();                                              \
-    static constexpr uint32_t sGetHalTokenTransactionCode = GTKCODE;      \
-
-
-#define IMPLEMENT_HYBRID_META_INTERFACE(INTERFACE, NAME)                  \
-    I##INTERFACE::HalVariant I##INTERFACE::getHalVariant() const {        \
-        return HalVariant{std::in_place_index<0>};                        \
-    }                                                                     \
-    size_t I##INTERFACE::getHalIndex() const {                            \
-        return getHalVariant().index();                                   \
-    }                                                                     \
-    constexpr uint32_t I##INTERFACE::sGetHalTokenTransactionCode;         \
-    static const ::android::StaticString16 I##INTERFACE##_desc_str16(     \
-        u##NAME);                                                         \
-    const ::android::String16 I##INTERFACE::descriptor(                   \
-        I##INTERFACE##_desc_str16);                                       \
-    const ::android::String16&                                            \
-            I##INTERFACE::getInterfaceDescriptor() const {                \
-        return I##INTERFACE::descriptor;                                  \
-    }                                                                     \
-    ::android::sp<I##INTERFACE> I##INTERFACE::asInterface(                \
-            const ::android::sp<::android::IBinder>& obj)                 \
-    {                                                                     \
-        ::android::sp<I##INTERFACE> intr;                                 \
-        if (obj != nullptr) {                                             \
-            intr = static_cast<I##INTERFACE*>(                            \
-                obj->queryLocalInterface(                                 \
-                        I##INTERFACE::descriptor).get());                 \
-            if (intr == nullptr) {                                        \
-                intr = new Hp##INTERFACE(obj);                            \
-            }                                                             \
-        }                                                                 \
-        return intr;                                                      \
-    }                                                                     \
-    I##INTERFACE::I##INTERFACE() { }                                      \
-    I##INTERFACE::~I##INTERFACE() { }                                     \
+#define DECLARE_HYBRID_META_INTERFACE(INTERFACE, ...)                                          \
+    DECLARE_HYBRID_META_INTERFACE_WITH_CODE(::android::DEFAULT_GET_HAL_TOKEN_TRANSACTION_CODE, \
+                                            INTERFACE, __VA_ARGS__)
+
+#define DECLARE_HYBRID_META_INTERFACE_WITH_CODE(GTKCODE, INTERFACE, ...)                          \
+  private:                                                                                        \
+    typedef ::std::variant<::std::monostate, __VA_ARGS__> _HalVariant;                            \
+    template <typename... Types>                                                                  \
+    using _SpVariant = ::std::variant<::std::monostate, ::android::sp<Types>...>;                 \
+                                                                                                  \
+  public:                                                                                         \
+    typedef _SpVariant<__VA_ARGS__> HalVariant;                                                   \
+    virtual HalVariant getHalVariant() const;                                                     \
+    size_t getHalIndex() const;                                                                   \
+    template <size_t Index>                                                                       \
+    using HalInterface = ::std::variant_alternative_t<Index, _HalVariant>;                        \
+    template <typename HAL>                                                                       \
+    sp<HAL> getHalInterface() const {                                                             \
+        HalVariant halVariant = getHalVariant();                                                  \
+        const sp<HAL>* hal = std::get_if<sp<HAL>>(&halVariant);                                   \
+        return hal ? *hal : nullptr;                                                              \
+    }                                                                                             \
+                                                                                                  \
+    static const ::android::String16 descriptor;                                                  \
+    static ::android::sp<I##INTERFACE> asInterface(const ::android::sp<::android::IBinder>& obj); \
+    virtual const ::android::String16& getInterfaceDescriptor() const;                            \
+    I##INTERFACE();                                                                               \
+    virtual ~I##INTERFACE();                                                                      \
+    static constexpr uint32_t sGetHalTokenTransactionCode = GTKCODE;
+
+#define IMPLEMENT_HYBRID_META_INTERFACE(INTERFACE, NAME)                                       \
+    I##INTERFACE::HalVariant I##INTERFACE::getHalVariant() const {                             \
+        return HalVariant{std::in_place_index<0>};                                             \
+    }                                                                                          \
+    size_t I##INTERFACE::getHalIndex() const {                                                 \
+        return getHalVariant().index();                                                        \
+    }                                                                                          \
+    constexpr uint32_t I##INTERFACE::sGetHalTokenTransactionCode;                              \
+    static const ::android::StaticString16 I##INTERFACE##_desc_str16(u##NAME);                 \
+    const ::android::String16 I##INTERFACE::descriptor(I##INTERFACE##_desc_str16);             \
+    const ::android::String16& I##INTERFACE::getInterfaceDescriptor() const {                  \
+        return I##INTERFACE::descriptor;                                                       \
+    }                                                                                          \
+    ::android::sp<I##INTERFACE> I##INTERFACE::asInterface(                                     \
+            const ::android::sp<::android::IBinder>& obj) {                                    \
+        ::android::sp<I##INTERFACE> intr;                                                      \
+        if (obj != nullptr) {                                                                  \
+            intr = sp<I##INTERFACE>::cast(obj->queryLocalInterface(I##INTERFACE::descriptor)); \
+            if (intr == nullptr) {                                                             \
+                intr = sp<Hp##INTERFACE>::make(obj);                                           \
+            }                                                                                  \
+        }                                                                                      \
+        return intr;                                                                           \
+    }                                                                                          \
+    I##INTERFACE::I##INTERFACE() {}                                                            \
+    I##INTERFACE::~I##INTERFACE() {}
 
 // ----------------------------------------------------------------------
 
@@ -460,7 +450,8 @@ status_t H2BConverter<HINTERFACE, BNINTERFACE>::linkToDeath(
             "linkToDeath(): recipient must not be null.");
     {
         std::lock_guard<std::mutex> lock(mObituariesLock);
-        mObituaries.push_back(new Obituary(recipient, cookie, flags, this));
+        mObituaries.push_back(
+                sp<Obituary>::make(recipient, cookie, flags, wp<IBinder>::fromExisting(this)));
         if (!mBase->linkToDeath(mObituaries.back(), 0)) {
            return DEAD_OBJECT;
         }
@@ -491,10 +482,8 @@ status_t H2BConverter<HINTERFACE, BNINTERFACE>::unlinkToDeath(
 }
 
 template <typename BPINTERFACE, typename CONVERTER, typename... CONVERTERS>
-HpInterface<BPINTERFACE, CONVERTER, CONVERTERS...>::HpInterface(
-        const sp<IBinder>& impl)
-      : mBpBinder{impl.get()},
-        mBp{new BPINTERFACE(impl)} {
+HpInterface<BPINTERFACE, CONVERTER, CONVERTERS...>::HpInterface(const sp<IBinder>& impl)
+    : mBpBinder{impl.get()}, mBp{sp<BPINTERFACE>::make(impl)} {
     mBase = mBp;
     if (!mBpBinder->remoteBinder()) {
         return;
diff --git a/vintfdata/device_compatibility_matrix.default.xml b/vintfdata/device_compatibility_matrix.default.xml
index 70d23e2..1a050fc 100644
--- a/vintfdata/device_compatibility_matrix.default.xml
+++ b/vintfdata/device_compatibility_matrix.default.xml
@@ -1,5 +1,5 @@
 <compatibility-matrix version="1.0" type="device">
-    <hal format="hidl" optional="true">
+    <hal format="hidl">
         <name>android.hidl.manager</name>
         <version>1.0</version>
         <interface>
diff --git a/vintfdata/frozen/202404.xml b/vintfdata/frozen/202404.xml
index 91d537a..06a6918 100644
--- a/vintfdata/frozen/202404.xml
+++ b/vintfdata/frozen/202404.xml
@@ -3,7 +3,7 @@
          cameraserver is installed for all phones and tablets, but not
          auto, TV, or Wear.
     -->
-    <hal format="aidl" optional="true">
+    <hal format="aidl">
         <name>android.frameworks.cameraservice.service</name>
         <version>2</version>
         <interface>
@@ -11,7 +11,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.frameworks.location.altitude</name>
         <version>2</version>
         <interface>
@@ -19,14 +19,14 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.frameworks.sensorservice</name>
         <interface>
             <name>ISensorManager</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.frameworks.stats</name>
         <version>2</version>
         <interface>
@@ -37,21 +37,21 @@
     <!--
           vibrator is installed for all form factors except TV
     -->
-    <hal format="aidl" optional="true">
+    <hal format="aidl">
         <name>android.frameworks.vibrator</name>
         <interface>
             <name>IVibratorControlService</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.hardware.media.c2</name>
         <interface>
             <name>IComponentStore</name>
             <instance>software</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.keystore2</name>
         <version>4</version>
         <interface>
@@ -59,14 +59,14 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.net.netd</name>
         <interface>
             <name>INetd</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.suspend</name>
         <interface>
             <name>ISystemSuspend</name>
diff --git a/vintfdata/frozen/202504.xml b/vintfdata/frozen/202504.xml
new file mode 100644
index 0000000..206dc6f
--- /dev/null
+++ b/vintfdata/frozen/202504.xml
@@ -0,0 +1,101 @@
+<compatibility-matrix version="9.0" type="device">
+    <!--
+         cameraserver is installed for all phones and tablets, but not
+         auto, TV, or Wear.
+    -->
+    <hal format="aidl" optional="true">
+        <name>android.frameworks.cameraservice.service</name>
+        <version>3</version>
+        <interface>
+            <name>ICameraService</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.frameworks.devicestate</name>
+        <interface>
+            <name>IDeviceStateService</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.frameworks.location.altitude</name>
+        <version>2</version>
+        <interface>
+            <name>IAltitudeService</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.frameworks.sensorservice</name>
+        <interface>
+            <name>ISensorManager</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.frameworks.stats</name>
+        <version>2</version>
+        <interface>
+            <name>IStats</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <!--
+          vibrator is installed for all form factors except TV
+    -->
+    <hal format="aidl" optional="true">
+        <name>android.frameworks.vibrator</name>
+        <interface>
+            <name>IVibratorControlService</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.hardware.media.c2</name>
+        <interface>
+            <name>IComponentStore</name>
+            <instance>software</instance>
+        </interface>
+    </hal>
+    <!--
+          keymint is not typically installed in the framework manifest
+    -->
+    <hal format="aidl" optional="true">
+        <name>android.hardware.security.keymint</name>
+        <version>3</version>
+        <interface>
+            <name>IRemotelyProvisionedComponent</name>
+            <instance>avf</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.system.keystore2</name>
+        <version>5</version>
+        <interface>
+            <name>IKeystoreService</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.system.net.netd</name>
+        <interface>
+            <name>INetd</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.system.suspend</name>
+        <interface>
+            <name>ISystemSuspend</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="aidl" optional="false">
+        <name>android.system.vold</name>
+        <interface>
+            <name>IVold</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+</compatibility-matrix>
diff --git a/vintfdata/frozen/5.xml b/vintfdata/frozen/5.xml
index 525829d..cb99f43 100644
--- a/vintfdata/frozen/5.xml
+++ b/vintfdata/frozen/5.xml
@@ -3,7 +3,7 @@
          cameraserver is installed for all phones and tablets, but not
          auto or TV.
     -->
-    <hal format="hidl" optional="true">
+    <hal format="hidl">
         <name>android.frameworks.cameraservice.service</name>
         <version>2.1</version>
         <interface>
@@ -11,7 +11,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.frameworks.displayservice</name>
         <version>1.0</version>
         <interface>
@@ -19,7 +19,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.frameworks.schedulerservice</name>
         <version>1.0</version>
         <interface>
@@ -27,7 +27,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.frameworks.sensorservice</name>
         <version>1.0</version>
         <interface>
@@ -35,7 +35,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.frameworks.stats</name>
         <version>1.0</version>
         <interface>
@@ -43,7 +43,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hardware.media.c2</name>
         <version>1.1</version>
         <interface>
@@ -51,7 +51,7 @@
             <instance>software</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.allocator</name>
         <version>1.0</version>
         <interface>
@@ -59,7 +59,7 @@
             <instance>ashmem</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.manager</name>
         <version>1.2</version>
         <interface>
@@ -67,7 +67,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.memory</name>
         <version>1.0</version>
         <interface>
@@ -75,7 +75,7 @@
             <instance>ashmem</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.token</name>
         <version>1.0</version>
         <interface>
@@ -83,7 +83,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.system.net.netd</name>
         <version>1.1</version>
         <interface>
@@ -91,7 +91,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.system.suspend</name>
         <version>1.0</version>
         <interface>
@@ -99,7 +99,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.system.wifi.keystore</name>
         <version>1.0</version>
         <interface>
diff --git a/vintfdata/frozen/6.xml b/vintfdata/frozen/6.xml
index eb078c0..d0b93c7 100644
--- a/vintfdata/frozen/6.xml
+++ b/vintfdata/frozen/6.xml
@@ -3,7 +3,7 @@
          cameraserver is installed for all phones and tablets, but not
          auto or TV.
     -->
-    <hal format="hidl" optional="true">
+    <hal format="hidl">
         <name>android.frameworks.cameraservice.service</name>
         <version>2.2</version>
         <interface>
@@ -11,7 +11,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.frameworks.displayservice</name>
         <version>1.0</version>
         <interface>
@@ -19,7 +19,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.frameworks.sensorservice</name>
         <version>1.0</version>
         <interface>
@@ -27,14 +27,14 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.frameworks.stats</name>
         <interface>
             <name>IStats</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hardware.media.c2</name>
         <version>1.2</version>
         <interface>
@@ -42,7 +42,7 @@
             <instance>software</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.allocator</name>
         <version>1.0</version>
         <interface>
@@ -50,7 +50,7 @@
             <instance>ashmem</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.manager</name>
         <version>1.2</version>
         <interface>
@@ -58,7 +58,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.memory</name>
         <version>1.0</version>
         <interface>
@@ -66,7 +66,7 @@
             <instance>ashmem</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.token</name>
         <version>1.0</version>
         <interface>
@@ -74,7 +74,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.keystore2</name>
         <version>2</version>
         <interface>
@@ -82,7 +82,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.system.net.netd</name>
         <version>1.1</version>
         <interface>
@@ -90,7 +90,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.system.suspend</name>
         <version>1.0</version>
         <interface>
@@ -98,14 +98,14 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.suspend</name>
         <interface>
             <name>ISystemSuspend</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.system.wifi.keystore</name>
         <version>1.0</version>
         <interface>
diff --git a/vintfdata/frozen/7.xml b/vintfdata/frozen/7.xml
index fcfeba7..83cc860 100644
--- a/vintfdata/frozen/7.xml
+++ b/vintfdata/frozen/7.xml
@@ -3,7 +3,7 @@
          cameraserver is installed for all phones and tablets, but not
          auto or TV.
     -->
-    <hal format="hidl" optional="true">
+    <hal format="hidl">
         <name>android.frameworks.cameraservice.service</name>
         <version>2.2</version>
         <interface>
@@ -11,7 +11,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.frameworks.sensorservice</name>
         <version>1.0</version>
         <interface>
@@ -19,14 +19,14 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.frameworks.stats</name>
         <interface>
             <name>IStats</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hardware.media.c2</name>
         <version>1.2</version>
         <interface>
@@ -34,7 +34,7 @@
             <instance>software</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.allocator</name>
         <version>1.0</version>
         <interface>
@@ -42,7 +42,7 @@
             <instance>ashmem</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.manager</name>
         <version>1.2</version>
         <interface>
@@ -50,7 +50,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.memory</name>
         <version>1.0</version>
         <interface>
@@ -58,7 +58,7 @@
             <instance>ashmem</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.token</name>
         <version>1.0</version>
         <interface>
@@ -66,7 +66,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.keystore2</name>
         <version>2</version>
         <interface>
@@ -74,7 +74,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.system.net.netd</name>
         <version>1.1</version>
         <interface>
@@ -82,14 +82,14 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.suspend</name>
         <interface>
             <name>ISystemSuspend</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.system.wifi.keystore</name>
         <version>1.0</version>
         <interface>
diff --git a/vintfdata/frozen/8.xml b/vintfdata/frozen/8.xml
index 58db476..e50f0dc 100644
--- a/vintfdata/frozen/8.xml
+++ b/vintfdata/frozen/8.xml
@@ -3,28 +3,28 @@
          cameraserver is installed for all phones and tablets, but not
          auto, TV, or Wear.
     -->
-    <hal format="aidl" optional="true">
+    <hal format="aidl">
         <name>android.frameworks.cameraservice.service</name>
         <interface>
             <name>ICameraService</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.frameworks.location.altitude</name>
         <interface>
             <name>IAltitudeService</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.frameworks.sensorservice</name>
         <interface>
             <name>ISensorManager</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.frameworks.sensorservice</name>
         <version>1.0</version>
         <interface>
@@ -32,7 +32,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.frameworks.stats</name>
         <version>2</version>
         <interface>
@@ -40,7 +40,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hardware.media.c2</name>
         <version>1.2</version>
         <interface>
@@ -48,7 +48,7 @@
             <instance>software</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.allocator</name>
         <version>1.0</version>
         <interface>
@@ -56,7 +56,7 @@
             <instance>ashmem</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.manager</name>
         <version>1.2</version>
         <interface>
@@ -64,7 +64,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.memory</name>
         <version>1.0</version>
         <interface>
@@ -72,7 +72,7 @@
             <instance>ashmem</instance>
         </interface>
     </hal>
-    <hal format="hidl" optional="false">
+    <hal format="hidl">
         <name>android.hidl.token</name>
         <version>1.0</version>
         <interface>
@@ -80,7 +80,7 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.keystore2</name>
         <version>3</version>
         <interface>
@@ -88,14 +88,14 @@
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.net.netd</name>
         <interface>
             <name>INetd</name>
             <instance>default</instance>
         </interface>
     </hal>
-    <hal format="aidl" optional="false">
+    <hal format="aidl">
         <name>android.system.suspend</name>
         <interface>
             <name>ISystemSuspend</name>
```

