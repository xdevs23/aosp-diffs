```diff
diff --git a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp
index f5e63f1..506c05e 100644
--- a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp
+++ b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp
@@ -408,20 +408,21 @@ int32_t ExynosDisplayDrmInterfaceModule::setPlaneColorSetting(
 
 ExynosDisplayDrmInterfaceModule::SaveBlob::~SaveBlob() {
     clearBlobs();
+    blobs.clear();
 }
 
 void ExynosDisplayDrmInterfaceModule::SaveBlob::clearBlobs() {
-    for (auto &it: blobs) {
-        mDrmDevice->DestroyPropertyBlob(it);
+    for (size_t i = 0; i < blobs.size(); ++i) {
+        mDrmDevice->DestroyPropertyBlob(blobs[i]);
+        blobs[i] = 0;
     }
-    blobs.clear();
 }
 
 void ExynosDisplayDrmInterfaceModule::SaveBlob::addBlob(
         uint32_t type, uint32_t blob)
 {
     if (type >= blobs.size()) {
-        ALOGE("Invalid dqe blop type: %d", type);
+        ALOGE("%s: Invalid blob type: %u", mBlobClassName, type);
         return;
     }
     if (blobs[type] > 0)
@@ -433,7 +434,7 @@ void ExynosDisplayDrmInterfaceModule::SaveBlob::addBlob(
 uint32_t ExynosDisplayDrmInterfaceModule::SaveBlob::getBlob(uint32_t type)
 {
     if (type >= blobs.size()) {
-        ALOGE("Invalid dqe blop type: %d", type);
+        ALOGE("%s: Invalid blob type: %u", mBlobClassName, type);
         return 0;
     }
     return blobs[type];
diff --git a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.h b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.h
index ba3613c..90d003e 100644
--- a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.h
+++ b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.h
@@ -65,6 +65,7 @@ class ExynosDisplayDrmInterfaceModule : public ExynosDisplayDrmInterface {
     protected:
         class SaveBlob {
             public:
+                SaveBlob(const char *blobClassName) : mBlobClassName(blobClassName) {}
                 ~SaveBlob();
                 void init(DrmDevice *drmDevice, uint32_t size) {
                     mDrmDevice = drmDevice;
@@ -75,6 +76,7 @@ class ExynosDisplayDrmInterfaceModule : public ExynosDisplayDrmInterface {
                 void clearBlobs();
 
             private:
+                const char *mBlobClassName;
                 DrmDevice *mDrmDevice = NULL;
                 std::vector<uint32_t> blobs;
         };
@@ -90,6 +92,7 @@ class ExynosDisplayDrmInterfaceModule : public ExynosDisplayDrmInterface {
                     CGC_DITHER,
                     DQE_BLOB_NUM // number of DQE blobs
                 };
+                DqeBlobs() : SaveBlob("DqeBlobs") {}
                 void init(DrmDevice *drmDevice) {
                     SaveBlob::init(drmDevice, DQE_BLOB_NUM);
                 };
@@ -103,7 +106,7 @@ class ExynosDisplayDrmInterfaceModule : public ExynosDisplayDrmInterface {
                     OETF,
                     DPP_BLOB_NUM // number of DPP blobs
                 };
-                DppBlobs(DrmDevice *drmDevice, uint32_t pid) : planeId(pid) {
+                DppBlobs(DrmDevice *drmDevice, uint32_t pid) : SaveBlob("DppBlobs"), planeId(pid) {
                     SaveBlob::init(drmDevice, DPP_BLOB_NUM);
                 };
                 uint32_t planeId;
@@ -150,6 +153,7 @@ class ExynosDisplayDrmInterfaceModule : public ExynosDisplayDrmInterface {
                 WEIGHTS,
                 HISTO_BLOB_NUM // number of Histogram blobs
             };
+            HistoBlobs() : SaveBlob("HistoBlobs") {}
             void init(DrmDevice *drmDevice) { SaveBlob::init(drmDevice, HISTO_BLOB_NUM); }
         };
         int32_t setDisplayHistoBlob(const DrmProperty &prop, const uint32_t type,
```

