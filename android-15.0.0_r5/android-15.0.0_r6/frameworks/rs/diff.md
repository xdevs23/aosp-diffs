```diff
diff --git a/cpp/Allocation.cpp b/cpp/Allocation.cpp
index 2f5ca64d..9263bb12 100644
--- a/cpp/Allocation.cpp
+++ b/cpp/Allocation.cpp
@@ -19,7 +19,6 @@
 
 using android::RSC::Allocation;
 using android::RSC::sp;
-using android::Surface;
 
 void * Allocation::getIDSafe() const {
     return getID();
@@ -492,29 +491,3 @@ void Allocation::ioGetInput() {
     tryDispatch(mRS, RS::dispatch->AllocationIoReceive(mRS->getContext(), getID()));
 #endif
 }
-
-#ifndef RS_COMPATIBILITY_LIB
-#include <gui/Surface.h>
-
-sp<Surface> Allocation::getSurface() {
-    if ((mUsage & RS_ALLOCATION_USAGE_IO_INPUT) == 0) {
-        mRS->throwError(RS_ERROR_INVALID_PARAMETER, "Can only get Surface if IO_INPUT usage specified.");
-        return nullptr;
-    }
-    ANativeWindow *anw = (ANativeWindow *)RS::dispatch->AllocationGetSurface(mRS->getContext(),
-                                                                             getID());
-    sp<Surface> surface(static_cast<Surface*>(anw));
-    return surface;
-}
-
-void Allocation::setSurface(const sp<Surface>& s) {
-    if ((mUsage & RS_ALLOCATION_USAGE_IO_OUTPUT) == 0) {
-        mRS->throwError(RS_ERROR_INVALID_PARAMETER, "Can only set Surface if IO_OUTPUT usage specified.");
-        return;
-    }
-    tryDispatch(mRS, RS::dispatch->AllocationSetSurface(mRS->getContext(), getID(),
-                                                        static_cast<ANativeWindow *>(s.get())));
-}
-
-#endif
-
diff --git a/cpp/rsCppStructs.h b/cpp/rsCppStructs.h
index 03f911ed..b5846108 100644
--- a/cpp/rsCppStructs.h
+++ b/cpp/rsCppStructs.h
@@ -32,7 +32,6 @@
 struct dispatchTable;
 
 namespace android {
-class Surface;
 
 namespace RSC {
 
@@ -651,22 +650,6 @@ public:
      */
     void ioGetInput();
 
-#ifndef RS_COMPATIBILITY_LIB
-    /**
-     * Returns the handle to a raw buffer that is being managed by the screen
-     * compositor. This operation is only valid for Allocations with USAGE_IO_INPUT.
-     * @return Surface associated with allocation
-     */
-    sp<Surface> getSurface();
-
-    /**
-     * Associate a Surface with this Allocation. This
-     * operation is only valid for Allocations with USAGE_IO_OUTPUT.
-     * @param[in] s Surface to associate with allocation
-     */
-    void setSurface(const sp<Surface>& s);
-#endif
-
     /**
      * Generate a mipmap chain. This is only valid if the Type of the Allocation
      * includes mipmaps. This function will generate a complete set of mipmaps
```

