```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..c557b22
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,160 @@
+// Copyright (c) 2024, Intel Corporation
+
+// Permission is hereby granted, free of charge, to any person obtaining a
+// copy of this software and associated documentation files (the "Software"),
+// to deal in the Software without restriction, including without limitation
+// the rights to use, copy, modify, merge, publish, distribute, sublicense,
+// and/or sell copies of the Software, and to permit persons to whom the
+// Software is furnished to do so, subject to the following conditions:
+
+// The above copyright notice and this permission notice shall be included
+// in all copies or substantial portions of the Software.
+
+// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
+// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
+// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+// OTHER DEALINGS IN THE SOFTWARE.
+
+package {
+    default_applicable_licenses: ["external_gmmlib_license"],
+}
+
+license {
+    name: "external_gmmlib_license",
+    visibility: [":__subpackages__"],
+    license_text: [
+        "LICENSE.md",
+    ],
+}
+
+cc_library_shared {
+    name: "libigdgmm_android",
+    vendor: true,
+    srcs: [
+        "Source/GmmLib/CachePolicy/GmmCachePolicy.cpp",
+        "Source/GmmLib/CachePolicy/GmmCachePolicyCommon.cpp",
+        "Source/GmmLib/CachePolicy/GmmGen10CachePolicy.cpp",
+        "Source/GmmLib/CachePolicy/GmmGen11CachePolicy.cpp",
+        "Source/GmmLib/CachePolicy/GmmGen12CachePolicy.cpp",
+        "Source/GmmLib/CachePolicy/GmmGen12dGPUCachePolicy.cpp",
+        "Source/GmmLib/CachePolicy/GmmGen8CachePolicy.cpp",
+        "Source/GmmLib/CachePolicy/GmmGen9CachePolicy.cpp",
+        "Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.cpp",
+        "Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp",
+        "Source/GmmLib/GlobalInfo/GmmClientContext.cpp",
+        "Source/GmmLib/GlobalInfo/GmmInfo.cpp",
+        "Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp",
+        "Source/GmmLib/Platform/GmmGen10Platform.cpp",
+        "Source/GmmLib/Platform/GmmGen11Platform.cpp",
+        "Source/GmmLib/Platform/GmmGen12Platform.cpp",
+        "Source/GmmLib/Platform/GmmGen8Platform.cpp",
+        "Source/GmmLib/Platform/GmmGen9Platform.cpp",
+        "Source/GmmLib/Platform/GmmPlatform.cpp",
+        "Source/GmmLib/Resource/GmmResourceInfo.cpp",
+        "Source/GmmLib/Resource/GmmResourceInfoCommon.cpp",
+        "Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp",
+        "Source/GmmLib/Resource/GmmRestrictions.cpp",
+        "Source/GmmLib/Resource/Linux/GmmResourceInfoLinCWrapper.cpp",
+        "Source/GmmLib/Texture/GmmGen10Texture.cpp",
+        "Source/GmmLib/Texture/GmmGen11Texture.cpp",
+        "Source/GmmLib/Texture/GmmGen12Texture.cpp",
+        "Source/GmmLib/Texture/GmmGen7Texture.cpp",
+        "Source/GmmLib/Texture/GmmGen8Texture.cpp",
+        "Source/GmmLib/Texture/GmmGen9Texture.cpp",
+        "Source/GmmLib/Texture/GmmTexture.cpp",
+        "Source/GmmLib/Texture/GmmTextureAlloc.cpp",
+        "Source/GmmLib/Texture/GmmTextureOffset.cpp",
+        "Source/GmmLib/Texture/GmmTextureSpecialCases.cpp",
+        "Source/GmmLib/Texture/GmmXe_LPGTexture.cpp",
+        "Source/GmmLib/TranslationTable/GmmAuxTable.cpp",
+        "Source/GmmLib/TranslationTable/GmmPageTableMgr.cpp",
+        "Source/GmmLib/TranslationTable/GmmUmdTranslationTable.cpp",
+        "Source/GmmLib/Utility/CpuSwizzleBlt/CpuSwizzleBlt.c",
+        "Source/GmmLib/Utility/GmmLog/GmmLog.cpp",
+        "Source/GmmLib/Utility/GmmUtility.cpp",
+        "Source/Common/AssertTracer/AssertTracer.cpp",
+    ],
+
+    cflags: [
+        "-DGMM_LIB_DLL",
+        "-DGMM_LIB_DLL_EXPORTS",
+        "-DGMM_UNIFIED_LIB",
+        "-DGMM_UNIFY_DAF_API",
+        "-DISTDLIB_UMD",
+        "-DSMALL_POOL_ALLOC",
+        "-DUNUSED_ISTDLIB_MT",
+        "-D_ATL_NO_WIN_SUPPORT",
+        "-D_RELEASE",
+        "-D_X64",
+        "-D__GFX_MACRO_C__",
+        "-D__GMM",
+        "-D__STDC_CONSTANT_MACROS",
+        "-D__STDC_LIMIT_MACROS",
+        "-D__UMD",
+        "-Digfx_gmmumd_dll_EXPORTS",
+        "-fvisibility=hidden",
+        "-fno-omit-frame-pointer",
+        "-march=corei7",
+        "-Werror",
+        "-Wno-logical-op-parentheses",
+        "-Wno-shift-negative-value",
+        "-Wno-unused-parameter",
+    ],
+
+    cppflags: [
+        "-Wno-implicit-fallthrough",
+        "-Wno-missing-braces",
+        "-Wno-unknown-pragmas",
+        "-Wno-parentheses",
+        "-Wno-pragma-pack",
+        "-fexceptions",
+        "-std=c++11",
+        "-fvisibility-inlines-hidden",
+        "-fno-use-cxa-atexit",
+        "-fno-rtti",
+        "-fcheck-new",
+        "-pthread",
+    ],
+
+    local_include_dirs: [
+        "Source/GmmLib",
+        "Source/GmmLib/Utility/GmmLog",
+        "Source/GmmLib/inc",
+        "Source/GmmLib/Utility",
+        "Source/GmmLib/GlobalInfo",
+        "Source/GmmLib/Texture",
+        "Source/GmmLib/Resource",
+        "Source/GmmLib/Platform",
+        "Source/util",
+        "Source/inc",
+        "Source/inc/common",
+        "Source/inc/umKmInc",
+    ],
+
+    enabled: false,
+    arch: {
+        x86_64: {
+            enabled: true,
+        },
+    },
+}
+
+cc_library_headers {
+    name: "libigdgmm_headers",
+    vendor: true,
+    export_include_dirs: [
+        "Source/GmmLib/inc",
+        "Source/inc",
+        "Source/inc/common",
+    ],
+
+    enabled: false,
+    arch: {
+        x86_64: {
+            enabled: true,
+        },
+    },
+}
diff --git a/METADATA b/METADATA
index d8c9852..3371cea 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,20 @@
-name: "gmmlib"
-description:
-    "The Intel(R) Graphics Memory Management Library provides device specific "
-    "and buffer management for the Intel(R) Graphics Compute Runtime for "
-    "OpenCL(TM) and the Intel(R) Media Driver for VAAPI."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/gmmlib
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "gmmlib"
+description: "The Intel(R) Graphics Memory Management Library provides device specific and buffer management for the Intel(R) Graphics Compute Runtime for OpenCL(TM) and the Intel(R) Media Driver for VAAPI."
 third_party {
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 10
+    day: 22
+  }
   identifier {
     type: "Git"
     value: "https://github.com/intel/gmmlib"
+    version: "intel-gmmlib-22.5.2"
     primary_source: true
-    version: "5fb4180e22695ad4e3c155cf680119913c9f44bc"
   }
-  version: "5fb4180e22695ad4e3c155cf680119913c9f44bc"
-  last_upgrade_date { year: 2024 month: 7 day: 9 }
-  license_type: NOTICE
 }
diff --git a/README.rst b/README.rst
index 9b464e8..ddad599 100644
--- a/README.rst
+++ b/README.rst
@@ -22,6 +22,8 @@ https://opensource.org/licenses/MIT
 Building
 ========
 1) Get gmmlib repository
+   
+   git clone https://github.com/intel/gmmlib.git
 
 2) Change it to root directory
 
@@ -33,7 +35,11 @@ Building
 
 4) Run the cmake command to prepare build files
 
-   ``$ cmake [-DCMAKE_BUILD_TYPE= Release | Debug | ReleaseInternal] ..``
+|        ``$ cmake [-DCMAKE_BUILD_TYPE=Release | Debug | ReleaseInternal] ..``  
+|        where,
+|        -DCMAKE_BUILD_TYPE can be set to one build type flag at a time.
+|        Example:
+|        ``$ cmake -DCMAKE_BUILD_TYPE=Release ..``, For Release build
 
 5) Build the project
 
@@ -82,6 +88,10 @@ XE_HPC (PVC: Ponte Vecchio)
 
 XE_HPG (DG2, ACM: Alchemist)
 
+Xe_LPG (MTL: Meteor Lake, ARL: Arrow Lake)
+
+Xe2_HPG (BMG: Battlemage, LNL: Lunar Lake)
+
 Release Tags
 ============
 
diff --git a/Source/GmmLib/CMakeLists.txt b/Source/GmmLib/CMakeLists.txt
index 8271b47..fcb4782 100644
--- a/Source/GmmLib/CMakeLists.txt
+++ b/Source/GmmLib/CMakeLists.txt
@@ -25,14 +25,14 @@ project(igfx_gmmumd)
 
 # GmmLib Api Version used for so naming
 set(GMMLIB_API_MAJOR_VERSION 12)
-set(GMMLIB_API_MINOR_VERSION 3)
+set(GMMLIB_API_MINOR_VERSION 5)
 
 if(NOT DEFINED MAJOR_VERSION)
 	set(MAJOR_VERSION 12)
 endif()
 
 if(NOT DEFINED MINOR_VERSION)
-	set(MINOR_VERSION 3)
+	set(MINOR_VERSION 5)
 endif()
 
 if(NOT DEFINED PATCH_VERSION)
@@ -125,14 +125,13 @@ set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
 set (GMM_LIB_DLL_NAME igfx_gmmumd_dll)
 
 macro(GmmLibSetTargetConfig libTarget)
-	if (TARGET ${libTarget})
-			set_property(TARGET ${libTarget} APPEND PROPERTY COMPILE_DEFINITIONS
-				$<$<CONFIG:Release>: _RELEASE>
-				$<$<CONFIG:ReleaseInternal>: _RELEASE_INTERNAL>
-				$<$<CONFIG:Debug>: _DEBUG>
-			)
-		endif()
-
+    if(TARGET ${libTarget})
+        set_property(TARGET ${libTarget} APPEND PROPERTY COMPILE_DEFINITIONS
+           $<$<CONFIG:Release>: _RELEASE>
+           $<$<CONFIG:ReleaseInternal>: _RELEASE_INTERNAL>
+           $<$<CONFIG:Debug>: _DEBUG>
+           )
+    endif()
 endmacro()
 
 if(CMAKE_CONFIGURATION_TYPES)
@@ -205,6 +204,7 @@ set(HEADERS_
 	${BS_DIR_GMMLIB}/CachePolicy/GmmGen11CachePolicy.h
 	${BS_DIR_GMMLIB}/CachePolicy/GmmGen12CachePolicy.h
         ${BS_DIR_GMMLIB}/CachePolicy/GmmXe_LPGCachePolicy.h
+        ${BS_DIR_GMMLIB}/CachePolicy/GmmXe2_LPGCachePolicy.h	
 	${BS_DIR_GMMLIB}/CachePolicy/GmmGen12dGPUCachePolicy.h
 	${BS_DIR_GMMLIB}/CachePolicy/GmmGen8CachePolicy.h
 	${BS_DIR_GMMLIB}/CachePolicy/GmmGen9CachePolicy.h
@@ -212,6 +212,7 @@ set(HEADERS_
 	${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen11.h
 	${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen12.h
 	${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyXe_LPG.h
+        ${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyXe2_LPG.h
 	${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen12dGPU.h
 	${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen8.h
 	${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen9.h
@@ -276,6 +277,7 @@ set(SOURCES_
   ${BS_DIR_GMMLIB}/CachePolicy/GmmGen11CachePolicy.cpp
   ${BS_DIR_GMMLIB}/CachePolicy/GmmGen12CachePolicy.cpp
   ${BS_DIR_GMMLIB}/CachePolicy/GmmXe_LPGCachePolicy.cpp
+  ${BS_DIR_GMMLIB}/CachePolicy/GmmXe2_LPGCachePolicy.cpp
   ${BS_DIR_GMMLIB}/CachePolicy/GmmGen12dGPUCachePolicy.cpp
   ${BS_DIR_GMMLIB}/Platform/GmmGen11Platform.cpp
   ${BS_DIR_GMMLIB}/Platform/GmmGen12Platform.cpp
@@ -320,6 +322,7 @@ source_group("Source Files\\Cache Policy\\Client Files" FILES
 			${BS_DIR_GMMLIB}/CachePolicy/GmmGen11CachePolicy.h
 			${BS_DIR_GMMLIB}/CachePolicy/GmmGen12CachePolicy.h
                         ${BS_DIR_GMMLIB}/CachePolicy/GmmXe_LPGCachePolicy.h
+                        ${BS_DIR_GMMLIB}/CachePolicy/GmmXe2_LPGCachePolicy.h
 			${BS_DIR_GMMLIB}/CachePolicy/GmmGen12dGPUCachePolicy.h
 			${BS_DIR_GMMLIB}/CachePolicy/GmmGen8CachePolicy.h
 			${BS_DIR_GMMLIB}/CachePolicy/GmmGen9CachePolicy.h
@@ -383,6 +386,7 @@ source_group("Header Files\\External\\Common\\Cache Policy" FILES
 			${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen11.h
 			${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen12.h
 			${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyXe_LPG.h
+                        ${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyXe2_LPG.h
                         ${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen12dGPU.h
 			${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen8.h
 			${BS_DIR_GMMLIB}/inc/External/Common/CachePolicy/GmmCachePolicyGen9.h
@@ -435,8 +439,6 @@ include_directories(BEFORE ${PROJECT_SOURCE_DIR})
   ${BS_DIR_INC}
   ${BS_DIR_INC}/common
   ${BS_DIR_INC}/umKmInc
-  ${BS_DIR_INSTALL}
-  #${BS_DIR_ANDROID}/include
   )
 
 if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^aarch")
@@ -459,12 +461,13 @@ include(Linux.cmake)
 ###################################################################################
 add_library( ${GMM_LIB_DLL_NAME} SHARED igdgmm.rc ${UMD_SOURCES} ${UMD_HEADERS})
 
+GmmLibSetTargetConfig(${GMM_LIB_DLL_NAME})
+
 if(MSVC)
 
 set_target_properties(${GMM_LIB_DLL_NAME} PROPERTIES OUTPUT_NAME "igdgmm${GMMLIB_ARCH}")
 
 bs_set_wdk(${GMM_LIB_DLL_NAME})
-GmmLibSetTargetConfig( ${GMM_LIB_DLL_NAME} )
 
 set_target_properties(${GMM_LIB_DLL_NAME} PROPERTIES VS_GLOBAL_DriverTargetPlatform Universal)
 set_target_properties(${GMM_LIB_DLL_NAME} PROPERTIES VS_PLATFORM_TOOLSET WindowsApplicationForDrivers10.0)
diff --git a/Source/GmmLib/CachePolicy/GmmCachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmCachePolicy.cpp
index b1c8edc..d49bb7e 100644
--- a/Source/GmmLib/CachePolicy/GmmCachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmCachePolicy.cpp
@@ -54,6 +54,7 @@ uint32_t GMM_STDCALL GmmCachePolicyGetPATIndex(void *pLibContext, GMM_RESOURCE_U
     GMM_LIB_CONTEXT *pGmmLibContext = (GMM_LIB_CONTEXT *)pLibContext;
     return pGmmLibContext->GetCachePolicyObj()->CachePolicyGetPATIndex(NULL, Usage, pCompressionEnable, IsCpuCacheable);
 }
+
 /////////////////////////////////////////////////////////////////////////////////////
 /// C Wrapper function for GmmLib::GmmCachePolicyIsUsagePTECached
 /// @see           GmmLib::GmmCachePolicyCommon::CachePolicyIsUsagePTECached()
@@ -79,7 +80,7 @@ uint8_t GMM_STDCALL GmmCachePolicyIsUsagePTECached(void *pLibContext, GMM_RESOUR
 uint8_t GMM_STDCALL GmmGetSurfaceStateL1CachePolicy(void *pLibContext, GMM_RESOURCE_USAGE_TYPE Usage)
 {
     GMM_LIB_CONTEXT *pGmmLibContext = (GMM_LIB_CONTEXT *)pLibContext;
-    return pGmmLibContext->GetCachePolicyElement(Usage).L1CC;
+    return (uint8_t)pGmmLibContext->GetCachePolicyObj()->GetSurfaceStateL1CachePolicy(Usage);
 }
 
 /////////////////////////////////////////////////////////////////////////////////////
diff --git a/Source/GmmLib/CachePolicy/GmmCachePolicyCommon.cpp b/Source/GmmLib/CachePolicy/GmmCachePolicyCommon.cpp
index b708660..44fba50 100644
--- a/Source/GmmLib/CachePolicy/GmmCachePolicyCommon.cpp
+++ b/Source/GmmLib/CachePolicy/GmmCachePolicyCommon.cpp
@@ -32,6 +32,7 @@ GmmLib::GmmCachePolicyCommon::GmmCachePolicyCommon(GMM_CACHE_POLICY_ELEMENT *pCa
     this->pCachePolicy   = pCachePolicy;
     this->pGmmLibContext = pGmmLibContext;
     NumPATRegisters      = GMM_NUM_PAT_ENTRIES_LEGACY;
+    NumMOCSRegisters     = GMM_MAX_NUMBER_MOCS_INDEXES;
 }
 
 /////////////////////////////////////////////////////////////////////////////////////
@@ -100,7 +101,7 @@ MEMORY_OBJECT_CONTROL_STATE GMM_STDCALL GmmLib::GmmCachePolicyCommon::CachePolic
     // when they add it someone could call it without knowing the restriction.
     if(pResInfo &&
        pResInfo->GetResFlags().Info.XAdapter &&
-       Usage != GMM_RESOURCE_USAGE_XADAPTER_SHARED_RESOURCE)
+       (Usage != GMM_RESOURCE_USAGE_XADAPTER_SHARED_RESOURCE))
     {
         __GMM_ASSERT(false);
     }
@@ -115,8 +116,6 @@ MEMORY_OBJECT_CONTROL_STATE GMM_STDCALL GmmLib::GmmCachePolicyCommon::CachePolic
     {
         return CachePolicy[Usage].MemoryObjectNoOverride;
     }
-
-    return CachePolicy[GMM_RESOURCE_USAGE_UNKNOWN].MemoryObjectOverride;
 }
 /////////////////////////////////////////////////////////////////////////////////////
 ///      A simple getter function returning the PAT (cache policy) for a given
@@ -160,3 +159,14 @@ uint32_t GMM_STDCALL GmmLib::GmmCachePolicyCommon::CachePolicyGetNumPATRegisters
 {
     return NumPATRegisters;
 }
+
+/////////////////////////////////////////////////////////////////////////////////////
+/// Returns L1 cache attribute based on resource usage
+///
+/// @return        uint32_t
+/////////////////////////////////////////////////////////////////////////////////////
+uint32_t GMM_STDCALL GmmLib::GmmCachePolicyCommon::GetSurfaceStateL1CachePolicy(GMM_RESOURCE_USAGE_TYPE Usage)
+{
+    __GMM_ASSERT(pCachePolicy[Usage].Initialized);
+    return pCachePolicy[Usage].L1CC;
+}
diff --git a/Source/GmmLib/CachePolicy/GmmCachePolicyResourceUsageDefinitions.h b/Source/GmmLib/CachePolicy/GmmCachePolicyResourceUsageDefinitions.h
index 2513488..54cc37a 100644
--- a/Source/GmmLib/CachePolicy/GmmCachePolicyResourceUsageDefinitions.h
+++ b/Source/GmmLib/CachePolicy/GmmCachePolicyResourceUsageDefinitions.h
@@ -92,7 +92,6 @@ DEFINE_RESOURCE_USAGE( GMM_RESOURCE_USAGE_CCS_MEDIA_WRITABLE )
 DEFINE_RESOURCE_USAGE( GMM_RESOURCE_USAGE_SHADER_RESOURCE_LLC_BYPASS )
 DEFINE_RESOURCE_USAGE( GMM_RESOURCE_USAGE_PROCEDURAL_TEXTURE )
 DEFINE_RESOURCE_USAGE( GMM_RESOURCE_USAGE_UNCACHED )
-
 // Tiled Resource
 DEFINE_RESOURCE_USAGE( GMM_RESOURCE_USAGE_TILED_CCS )
 DEFINE_RESOURCE_USAGE( GMM_RESOURCE_USAGE_TILED_DEPTH_BUFFER )
@@ -351,3 +350,5 @@ DEFINE_RESOURCE_USAGE(GMM_RESOURCE_USAGE_COPY_DEST)
 
 // Shader resource uncachable, needed for WA_18013889147
 DEFINE_RESOURCE_USAGE(GMM_RESOURCE_USAGE_SHADER_RESOURCE_L1_NOT_CACHED)
+
+DEFINE_RESOURCE_USAGE(GMM_RESOURCE_USAGE_UMD_OCA_BUFFER)	
diff --git a/Source/GmmLib/CachePolicy/GmmGen10CachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmGen10CachePolicy.cpp
index f81a534..b5d6e08 100644
--- a/Source/GmmLib/CachePolicy/GmmGen10CachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmGen10CachePolicy.cpp
@@ -40,7 +40,7 @@ GMM_STATUS GmmLib::GmmGen10CachePolicy::InitCachePolicy()
 
     __GMM_ASSERTPTR(pCachePolicy, GMM_ERROR);
 
-#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, wt, age, lecc_scc, l3_scc, sso, cos, hdcl1) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, wt, age, 0, lecc_scc, l3_scc, 0, sso, cos, hdcl1, 0, 0, 0, 0, 0, 0, 0, 0)
+#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, wt, age, lecc_scc, l3_scc, sso, cos, hdcl1) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, wt, age, 0, lecc_scc, l3_scc, 0, sso, cos, hdcl1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
 #include "GmmGen10CachePolicy.h"
 
 #define TC_LLC (1)
diff --git a/Source/GmmLib/CachePolicy/GmmGen11CachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmGen11CachePolicy.cpp
index 96965c2..42c3228 100644
--- a/Source/GmmLib/CachePolicy/GmmGen11CachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmGen11CachePolicy.cpp
@@ -77,7 +77,7 @@ GMM_STATUS GmmLib::GmmGen11CachePolicy::InitCachePolicy()
 {
     __GMM_ASSERTPTR(pCachePolicy, GMM_ERROR);
 
-#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos, 0, 0, 0, 0, 0, 0, 0, 0, 0)
+#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
 #include "GmmGen11CachePolicy.h"
 
 #define TC_LLC (1)
diff --git a/Source/GmmLib/CachePolicy/GmmGen12CachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmGen12CachePolicy.cpp
index 866e42e..b3c207b 100644
--- a/Source/GmmLib/CachePolicy/GmmGen12CachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmGen12CachePolicy.cpp
@@ -126,7 +126,7 @@ GMM_STATUS GmmLib::GmmGen12CachePolicy::InitCachePolicy()
 
     __GMM_ASSERTPTR(pCachePolicy, GMM_ERROR);
 
-#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos, hdcl1, l3evict) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos, hdcl1, l3evict, 0, 0, 0, 0, 0, 0, 0)
+#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos, hdcl1, l3evict) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos, hdcl1, l3evict, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
 
 #include "GmmGen12CachePolicy.h"
 
diff --git a/Source/GmmLib/CachePolicy/GmmGen12dGPUCachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmGen12dGPUCachePolicy.cpp
index daa2996..b5eaf19 100644
--- a/Source/GmmLib/CachePolicy/GmmGen12dGPUCachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmGen12dGPUCachePolicy.cpp
@@ -89,7 +89,7 @@ GMM_STATUS GmmLib::GmmGen12dGPUCachePolicy::InitCachePolicy()
 
     __GMM_ASSERTPTR(pCachePolicy, GMM_ERROR);
 
-#define DEFINE_CACHE_ELEMENT(usage, l3, l3_scc, hdcl1, go, uclookup, l1cc) DEFINE_CP_ELEMENT(usage, 0, 0, l3, 0, 0, 0, 0, l3_scc, 0, 0, 0, hdcl1, 0, 0, go, uclookup, l1cc, 0, 0, 0)
+#define DEFINE_CACHE_ELEMENT(usage, l3, l3_scc, hdcl1, go, uclookup, l1cc) DEFINE_CP_ELEMENT(usage, 0, 0, l3, 0, 0, 0, 0, l3_scc, 0, 0, 0, hdcl1, 0, 0, go, uclookup, l1cc, 0, 0, 0, 0, 0, 0)
 
 #include "GmmGen12dGPUCachePolicy.h"
 
diff --git a/Source/GmmLib/CachePolicy/GmmGen8CachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmGen8CachePolicy.cpp
index 76ae925..7dfcb4b 100644
--- a/Source/GmmLib/CachePolicy/GmmGen8CachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmGen8CachePolicy.cpp
@@ -39,7 +39,7 @@ GMM_STATUS GmmLib::GmmGen8CachePolicy::InitCachePolicy()
 
     __GMM_ASSERTPTR(pCachePolicy, GMM_ERROR);
 
-#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, wt, age) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, wt, age, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
+#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, wt, age) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, wt, age, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
 #include "GmmGen8CachePolicy.h"
 
     {
diff --git a/Source/GmmLib/CachePolicy/GmmGen9CachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmGen9CachePolicy.cpp
index fe0c660..f1fa916 100644
--- a/Source/GmmLib/CachePolicy/GmmGen9CachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmGen9CachePolicy.cpp
@@ -40,7 +40,7 @@ GMM_STATUS GmmLib::GmmGen9CachePolicy::InitCachePolicy()
     __GMM_ASSERTPTR(pCachePolicy, GMM_ERROR);
 
 #if defined(GMM_DYNAMIC_MOCS_TABLE)
-#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, age, i915) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, 0, age, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
+#define DEFINE_CACHE_ELEMENT(usage, llc, ellc, l3, age, i915) DEFINE_CP_ELEMENT(usage, llc, ellc, l3, 0, age, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
 #else
 // i915 only supports three GEN9 MOCS entires:
 //     MOCS[0]...LLC=0, ELLC=0, L3=0, AGE=0
@@ -51,11 +51,11 @@ GMM_STATUS GmmLib::GmmGen9CachePolicy::InitCachePolicy()
     {                                                                                   \
         if((i915) == 0)                                                                 \
         {                                                                               \
-            DEFINE_CP_ELEMENT(usage, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);\
+            DEFINE_CP_ELEMENT(usage, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);\
         }                                                                               \
         else if((i915) == 2)                                                            \
         {                                                                               \
-            DEFINE_CP_ELEMENT(usage, 1, 1, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);\
+            DEFINE_CP_ELEMENT(usage, 1, 1, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);\
         }                                                                               \
         else                                                                            \
         {                                                                               \
diff --git a/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.cpp
new file mode 100644
index 0000000..6552d22
--- /dev/null
+++ b/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.cpp
@@ -0,0 +1,620 @@
+/*==============================================================================
+Copyright(c) 2024 Intel Corporation
+Permission is hereby granted, free of charge, to any person obtaining a
+copy of this software and associated documentation files(the "Software"),
+to deal in the Software without restriction, including without limitation
+the rights to use, copy, modify, merge, publish, distribute, sublicense,
+and / or sell copies of the Software, and to permit persons to whom the
+Software is furnished to do so, subject to the following conditions:
+
+The above copyright notice and this permission notice shall be included
+in all copies or substantial portions of the Software.
+
+THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
+THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
+OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+OTHER DEALINGS IN THE SOFTWARE.
+============================================================================*/
+#include "Internal/Common/GmmLibInc.h"
+#include "External/Common/GmmCachePolicy.h"
+#include "External/Common/CachePolicy/GmmCachePolicyXe2_LPG.h"
+//=============================================================================
+//
+// Function: GmmXe2_LPGCachePolicy::InitCachePolicy()
+//
+// Desc: This function initializes the Xe2 cache policy
+//
+// Return: GMM_STATUS
+//
+//-----------------------------------------------------------------------------
+GMM_STATUS GmmLib::GmmXe2_LPGCachePolicy::InitCachePolicy()
+{
+    __GMM_ASSERTPTR(pCachePolicy, GMM_ERROR);
+
+#define DEFINE_CACHE_ELEMENT(usage, l3_cc, l3_clos, l1cc, l2cc, l4cc, coherency, igPAT, segov) DEFINE_CP_ELEMENT(usage, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, segov, 0, 0, l1cc, l2cc, l4cc, coherency, l3_cc, l3_clos, igPAT)
+
+#include "GmmXe2_LPGCachePolicy.h"
+
+    SetUpMOCSTable();
+    SetupPAT();
+
+    // Define index of cache element
+    uint32_t Usage          = 0;
+    uint32_t ReservedPATIdx = 13; /* Rsvd PAT section 13-19 */
+
+#if (_WIN32 && (_DEBUG || _RELEASE_INTERNAL))
+    void *pKmdGmmContext = NULL;
+#if (defined(__GMM_KMD__))
+    pKmdGmmContext = pGmmLibContext->GetGmmKmdContext();
+#endif
+    OverrideCachePolicy(pKmdGmmContext);
+#endif
+    // Process the cache policy and fill in the look up table
+    for (; Usage < GMM_RESOURCE_USAGE_MAX; Usage++)
+    {
+        bool                         CachePolicyError = false;
+        int32_t                      PATIdx = -1, CPTblIdx = -1, PATIdxCompressed = -1, CoherentPATIdx = -1;
+        uint32_t                     i, j;
+        GMM_XE2_PRIVATE_PAT          UsagePATElement = {0};
+        GMM_CACHE_POLICY_TBL_ELEMENT UsageEle        = {0};
+        GMM_PTE_CACHE_CONTROL_BITS   PTE             = {0};
+
+        // MOCS data
+        {
+
+            // Get L3 ,L4 and Convert  GMM indicative values to actual regiser values.
+            GetL3L4(&UsageEle, &UsagePATElement, Usage);
+            // Convert L1  GMM indicative values to actual regiser values and store into pCachePolicy to return to UMD's.
+            SetL1CachePolicy(Usage);
+
+            if ((!pGmmLibContext->GetSkuTable().FtrL3TransientDataFlush) && (UsageEle.L3.PhysicalL3.L3CC == GMM_GFX_PHY_L3_MT_WB_XD))
+            {
+                UsageEle.L3.PhysicalL3.L3CC = GMM_GFX_PHY_L3_MT_WB; // No Transient Flush Support
+            }
+
+            /* If MOCS is not needed fall back to Defer to PAT i.e MOCS#0 */
+            if (false == UsageEle.L3.PhysicalL3.igPAT)
+            {
+                /* Set cache policy index to defered to PAT i.e. MOCS Index 0 */
+                CPTblIdx = 0;
+            }
+            else
+            {
+                /* MOCS Index 1-3 are valid */
+                for (j = 1; j <= CurrentMaxMocsIndex; j++)
+                {
+                    GMM_CACHE_POLICY_TBL_ELEMENT *TblEle = &pGmmLibContext->GetCachePolicyTlbElement()[j];
+                    if (UsageEle.L3.PhysicalL3.L4CC == TblEle->L3.PhysicalL3.L4CC &&
+                        UsageEle.L3.PhysicalL3.L3CC == TblEle->L3.PhysicalL3.L3CC &&
+                        UsageEle.L3.PhysicalL3.L3CLOS == TblEle->L3.PhysicalL3.L3CLOS &&
+                        UsageEle.L3.PhysicalL3.igPAT == true)
+                    {
+                        CPTblIdx = j;
+                        break;
+                    }
+                }
+            }
+
+            if (CPTblIdx == -1)
+            {
+
+                {
+                    /* Invalid MOCS setting Fail the GMM Initialzation */
+                    GMM_ASSERTDPF(false, "CRITICAL: Cache Policy Usage value for L3/L4 specified by Client is not defined in Fixed MOCS Table");
+                    CachePolicyError = true;
+
+                }
+            }
+        }
+
+        /*
+            Validate Caching restrictions as below
+            1. MemoryType WB-XD must be used in Non-Coherent and allowed only for displayable surfaces
+            2. Coherent mode(1-way/2-way) must be Memory Type WB
+            3. No 2-way coherency on dGPU
+            4. Memory Type WT is available only for L4 in Non Coherent Mode
+            5. Memory Type UC must be used in Non-Coherent Mode
+        */
+
+        // PAT data
+        {
+            if (!pGmmLibContext->GetSkuTable().FtrL3TransientDataFlush && (UsagePATElement.Xe2.L3CC == GMM_GFX_PHY_L3_MT_WB_XD))
+            {
+                UsagePATElement.Xe2.L3CC = GMM_GFX_PHY_L3_MT_WB; // No Transient Flush Support
+            }
+
+            /* Find a PATIndex from the PAT table for uncompressed case*/
+            if ((UsagePATElement.Xe2.L4CC == GMM_GFX_PHY_L4_MT_WT) && (UsagePATElement.Xe2.L3CC == GMM_GFX_PHY_L3_MT_WB_XD))
+            {
+
+                // With L3:XD, L4:WT, NC combination
+                if (pGmmLibContext->GetSkuTable().FtrDiscrete)
+                {
+                    // On BMG, L4 is a pass through, demote L4 to UC, keep L3 at XD
+                    PATIdx = PAT6;
+                }
+                else
+                {
+                    // On LNL, L3:XD is not needed
+                    PATIdx = PAT13;
+                }
+            }
+            else
+            {
+                for (i = 0; i <= CurrentMaxPATIndex; i++)
+                {
+                    GMM_PRIVATE_PAT PAT = GetPrivatePATEntry(i);
+                    if (UsagePATElement.Xe2.L4CC == PAT.Xe2.L4CC &&
+                        UsagePATElement.Xe2.Coherency == PAT.Xe2.Coherency &&
+                        UsagePATElement.Xe2.L3CC == PAT.Xe2.L3CC &&
+                        UsagePATElement.Xe2.L3CLOS == PAT.Xe2.L3CLOS &&
+                        false == PAT.Xe2.LosslessCompressionEn)
+                    {
+                        PATIdx = i;
+                        break;
+                    }
+                }
+            }
+
+            /* Find a PATIndex from the PAT table for compressed case*/
+            for (i = 0; i <= CurrentMaxPATIndex; i++)
+            {
+                GMM_PRIVATE_PAT PAT = GetPrivatePATEntry(i);
+                if (UsagePATElement.Xe2.L4CC == PAT.Xe2.L4CC &&
+                    UsagePATElement.Xe2.Coherency == PAT.Xe2.Coherency &&
+                    UsagePATElement.Xe2.L3CC == PAT.Xe2.L3CC &&
+                    UsagePATElement.Xe2.L3CLOS == PAT.Xe2.L3CLOS &&
+                    true == PAT.Xe2.LosslessCompressionEn)
+                {
+                    PATIdxCompressed = i;
+                    break;
+                }
+            }
+
+            if (PATIdx == -1)
+            {
+// Didn't find the caching settings in one of the already programmed PAT table entries.
+// Need to add a new lookup table entry.
+                    GMM_ASSERTDPF(
+                    "Cache Policy Init Error: Invalid Cache Programming, too many unique caching combinations"
+                    "(we only support NumPATRegisters = %d)",
+                    CurrentMaxPATIndex);
+                    CachePolicyError = true;
+
+                    PATIdx = GMM_PAT_ERROR;
+            }
+
+            /* Find a PATIndex for a coherent uncompressed case, if usage is 2-way or 1-way already, take that, otherwise search for oneway*/
+            if ((UsagePATElement.Xe2.Coherency == GMM_GFX_PHY_COHERENT_ONE_WAY_IA_SNOOP) ||
+                (UsagePATElement.Xe2.Coherency == GMM_GFX_PHY_COHERENT_TWO_WAY_IA_GPU_SNOOP))
+            {
+                //Already coherent
+                CoherentPATIdx = PATIdx;
+            }
+            else
+            {
+                // search for equivalent one way coherent index
+                for (i = 0; i <= CurrentMaxPATIndex; i++)
+                {
+                    GMM_PRIVATE_PAT PAT = GetPrivatePATEntry(i);
+                    if (UsagePATElement.Xe2.L4CC == PAT.Xe2.L4CC &&
+                        UsagePATElement.Xe2.L3CC == PAT.Xe2.L3CC &&
+                        UsagePATElement.Xe2.L3CLOS == PAT.Xe2.L3CLOS &&
+                        GMM_GFX_PHY_COHERENT_ONE_WAY_IA_SNOOP == PAT.Xe2.Coherency)
+                    {
+                        if ((false == PAT.Xe2.LosslessCompressionEn) && (CoherentPATIdx == -1))
+                        {
+                            CoherentPATIdx = i;
+                        }
+                        if (CoherentPATIdx != -1)
+                        {
+                            break;
+                        }
+                    }
+                }
+                if (CoherentPATIdx == -1)
+                {
+                    //redo matching based on L3:UC, L4:UC, we should find one
+                    for (i = 0; i <= CurrentMaxPATIndex; i++)
+                    {
+                        GMM_PRIVATE_PAT PAT = GetPrivatePATEntry(i);
+                        if (GMM_GFX_PHY_L4_MT_UC == PAT.Xe2.L4CC &&
+                            GMM_GFX_PHY_L3_MT_UC == PAT.Xe2.L3CC &&
+                            UsagePATElement.Xe2.L3CLOS == PAT.Xe2.L3CLOS &&
+                            GMM_GFX_PHY_COHERENT_ONE_WAY_IA_SNOOP == PAT.Xe2.Coherency)
+                        {
+                            if ((false == PAT.Xe2.LosslessCompressionEn) && (CoherentPATIdx == -1))
+                            {
+                                CoherentPATIdx = i;
+                            }
+
+                            if (CoherentPATIdx != -1)
+                            {
+                                break;
+                            }
+                        }
+                    }
+                }
+            }
+        }
+
+        pCachePolicy[Usage].PATIndex                                 = PATIdx;
+        pCachePolicy[Usage].CoherentPATIndex                         = GET_COHERENT_PATINDEX_LOWER_BITS(CoherentPATIdx); // Coherent uncompressed lower bits
+        pCachePolicy[Usage].CoherentPATIndexHigherBit                = GET_COHERENT_PATINDEX_HIGHER_BIT(CoherentPATIdx); // Coherent uncompressed higher bits
+        pCachePolicy[Usage].PATIndexCompressed                       = PATIdxCompressed;
+        pCachePolicy[Usage].PTE.DwordValue                           = GMM_GET_PTE_BITS_FROM_PAT_IDX(PATIdx) & 0xFFFFFFFF;
+        pCachePolicy[Usage].PTE.HighDwordValue                       = GMM_GET_PTE_BITS_FROM_PAT_IDX(PATIdx) >> 32;
+        pCachePolicy[Usage].MemoryObjectOverride.XE_HP.Index         = CPTblIdx;
+        pCachePolicy[Usage].MemoryObjectOverride.XE_HP.EncryptedData = 0;
+        pCachePolicy[Usage].Override                                 = ALWAYS_OVERRIDE;
+
+
+        if (CachePolicyError)
+        {
+            GMM_ASSERTDPF(false, "Cache Policy Init Error: Invalid Cache Programming ");
+
+            return GMM_INVALIDPARAM;
+        }
+    }
+    return GMM_SUCCESS;
+}
+
+//=============================================================================
+//
+// Function: __:GetL3L4
+//
+// Desc: This function // converting  GMM indicative values to actual register values
+//
+// Parameters:
+//
+// Return: GMM_STATUS
+//
+//-----------------------------------------------------------------------------
+
+void GmmLib::GmmXe2_LPGCachePolicy::GetL3L4(GMM_CACHE_POLICY_TBL_ELEMENT *pUsageEle, GMM_XE2_PRIVATE_PAT *pUsagePATElement, uint32_t Usage)
+{
+
+    //MOCS
+    pUsageEle->L3.PhysicalL3.Reserved0 = pUsageEle->L3.PhysicalL3.Reserved = 0;
+    //L3CLOS
+    pUsageEle->L3.PhysicalL3.L3CLOS = 0; 
+    //IgPAT
+    pUsageEle->L3.PhysicalL3.igPAT = pCachePolicy[Usage].IgnorePAT;
+
+
+    //PAT
+    pUsagePATElement->Xe2.Reserved1 = 0;
+    pUsagePATElement->Xe2.Reserved2 = 0;
+
+    pUsagePATElement->Xe2.L3CLOS = 0; 
+    switch (pCachePolicy[Usage].L3CC)
+    {
+    case GMM_UC:
+        pUsageEle->L3.PhysicalL3.L3CC = GMM_GFX_PHY_L3_MT_UC;
+        pUsagePATElement->Xe2.L3CC    = GMM_GFX_PHY_L3_MT_UC;
+        break;
+    case GMM_WB:
+        pUsageEle->L3.PhysicalL3.L3CC = GMM_GFX_PHY_L3_MT_WB;
+        pUsagePATElement->Xe2.L3CC    = GMM_GFX_PHY_L3_MT_WB;
+        break;
+    case GMM_WBTD:
+        pUsageEle->L3.PhysicalL3.L3CC = GMM_GFX_PHY_L3_MT_WB_XD; // Transient:Display on Xe2
+        pUsagePATElement->Xe2.L3CC    = GMM_GFX_PHY_L3_MT_WB_XD;
+        break;
+    default:
+        pUsageEle->L3.PhysicalL3.L3CC = GMM_GFX_PHY_L3_MT_UC;
+        pUsagePATElement->Xe2.L3CC    = GMM_GFX_PHY_L3_MT_UC;
+    }
+
+    switch (pCachePolicy[Usage].L4CC)
+    {
+    case GMM_UC:
+        pUsageEle->L3.PhysicalL3.L4CC = GMM_GFX_PHY_L4_MT_UC;
+        pUsagePATElement->Xe2.L4CC    = GMM_GFX_PHY_L4_MT_UC;
+        break;
+    case GMM_WB:
+        pUsageEle->L3.PhysicalL3.L4CC = GMM_GFX_PHY_L4_MT_WB;
+        pUsagePATElement->Xe2.L4CC    = GMM_GFX_PHY_L4_MT_WB;
+        break;
+    case GMM_WT:
+        pUsageEle->L3.PhysicalL3.L4CC = GMM_GFX_PHY_L4_MT_WT;
+        pUsagePATElement->Xe2.L4CC    = GMM_GFX_PHY_L4_MT_WT;
+        break;
+    default:
+        pUsageEle->L3.PhysicalL3.L4CC = GMM_GFX_PHY_L4_MT_UC;
+        pUsagePATElement->Xe2.L4CC    = GMM_GFX_PHY_L4_MT_UC;
+    }
+
+    switch (pCachePolicy[Usage].Coherency)
+    {
+    case GMM_NON_COHERENT_NO_SNOOP:
+        pUsagePATElement->Xe2.Coherency = GMM_GFX_NON_COHERENT_NO_SNOOP;
+        break;
+    case GMM_COHERENT_ONE_WAY_IA_SNOOP:
+        pUsagePATElement->Xe2.Coherency = GMM_GFX_COHERENT_ONE_WAY_IA_SNOOP;
+        break;
+    case GMM_COHERENT_TWO_WAY_IA_GPU_SNOOP:
+        pUsagePATElement->Xe2.Coherency = GMM_GFX_COHERENT_TWO_WAY_IA_GPU_SNOOP;
+        break;
+    default:
+        pUsagePATElement->Xe2.Coherency = GMM_GFX_NON_COHERENT_NO_SNOOP;
+        break;
+    }
+
+    if (pGmmLibContext->GetWaTable().Wa_14018443005 &&
+        (pCachePolicy[Usage].L3CC == GMM_UC) &&
+        (ISWA_1401844305USAGE(Usage)) &&
+        (pGmmLibContext->GetClientType() != GMM_KMD_VISTA) &&
+        (pGmmLibContext->GetClientType() != GMM_OCL_VISTA))
+    {
+        pUsageEle->L3.PhysicalL3.L3CC = GMM_GFX_PHY_L3_MT_WB;
+        pUsagePATElement->Xe2.L3CC    = GMM_GFX_PHY_L3_MT_WB;
+        pCachePolicy[Usage].L3CC      = GMM_WB;
+    }
+}
+
+/////////////////////////////////////////////////////////////////////////////////////
+///      A simple getter function returning the PAT (cache policy) for a given
+///      use Usage of the named resource pResInfo.
+///      Typically used to populate PPGTT/GGTT.
+///
+/// @param[in]     pResInfo: Resource info for resource, can be NULL.
+/// @param[in]     Usage: Current usage for resource.
+/// @param[in]     pCompressionEnabl: for Xe2 compression parameter
+/// @param[in]     IsCpuCacheable: Indicates Cacheability
+/// @return        PATIndex
+/////////////////////////////////////////////////////////////////////////////////////
+uint32_t GMM_STDCALL GmmLib::GmmXe2_LPGCachePolicy::CachePolicyGetPATIndex(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage, bool *pCompressionEnable, bool IsCpuCacheable)
+{
+    __GMM_ASSERT(pGmmLibContext->GetCachePolicyElement(Usage).Initialized);
+
+    uint32_t                 PATIndex             = pGmmLibContext->GetCachePolicyElement(Usage).PATIndex;
+    GMM_CACHE_POLICY_ELEMENT TempElement          = pGmmLibContext->GetCachePolicyElement(Usage);
+    uint32_t                 TempCoherentPATIndex = 0;
+
+    // This is to check if PATIndexCompressed, CoherentPATIndex are valid
+    // Increment by 1 to have the rollover and value resets to 0 if the PAT in not valid.
+    TempElement.PATIndexCompressed += 1;
+    TempCoherentPATIndex = (uint32_t)GET_COHERENT_PATINDEX_VALUE(pGmmLibContext, Usage);
+
+    // Higher bit of CoherentPATIndex would tell us if its a valid or not.0--> valid, 1-->invalid
+    uint32_t CoherentPATIndex = (uint32_t)((GET_COHERENT_PATINDEX_HIGHER_BIT(TempCoherentPATIndex) == 1) ? GMM_PAT_ERROR : GET_COHERENT_PATINDEX_VALUE(pGmmLibContext, Usage));
+    //For PATIndexCompressed, rollover value would be 0 if its invalid
+    uint32_t PATIndexCompressed = (uint32_t)(TempElement.PATIndexCompressed == 0 ? GMM_PAT_ERROR : pGmmLibContext->GetCachePolicyElement(Usage).PATIndexCompressed);
+    uint32_t ReturnPATIndex     = GMM_PAT_ERROR;
+    bool     CompressionEnable  = (pCompressionEnable) ? *pCompressionEnable : false;
+
+    // Prevent wrong Usage for XAdapter resources. UMD does not call GetMemoryObject on shader resources but,
+    // when they add it someone could call it without knowing the restriction.
+    if (pResInfo &&
+        pResInfo->GetResFlags().Info.XAdapter &&
+        (Usage != GMM_RESOURCE_USAGE_XADAPTER_SHARED_RESOURCE))
+    {
+        __GMM_ASSERT(false);
+    }
+
+#if (defined __linux__ || defined(WDDM_LINUX))
+    IsCpuCacheable = false;
+#endif
+    // requested compressed and coherent
+    if (CompressionEnable && IsCpuCacheable)
+    {
+        // return coherent uncompressed
+        ReturnPATIndex    = CoherentPATIndex;
+        CompressionEnable = false;
+        GMM_ASSERTDPF(false, "Coherent Compressed is not supported on Xe2. However, respecting the coherency and returning CoherentPATIndex");
+    }
+    // requested compressed only
+    else if (CompressionEnable)
+    {
+
+        if (GMM_PAT_ERROR != PATIndexCompressed)
+        {
+            // return compresed, may or may not coherent which depends on orinigal usage
+            ReturnPATIndex    = PATIndexCompressed;
+            CompressionEnable = true;
+        }
+        else
+        {
+            // return original index
+            ReturnPATIndex    = PATIndex;
+            CompressionEnable = false;
+        }
+    }
+    // requested coherent only
+    else if (IsCpuCacheable)
+    {
+        //return coherent uncompressed
+        ReturnPATIndex    = CoherentPATIndex;
+        CompressionEnable = false;
+    }
+    /* Requested UnCompressed PAT */
+    else
+    {
+        if (GMM_PAT_ERROR != PATIndex)
+        {
+            ReturnPATIndex    = PATIndex;
+            CompressionEnable = false;
+        }
+    }
+
+    /* No valid PAT Index found */
+    if (GMM_PAT_ERROR == ReturnPATIndex)
+    {
+        ReturnPATIndex    = GMM_XE2_DEFAULT_PAT_INDEX; //default to uncached PAT index 2: GMM_CP_NON_COHERENT_UC
+        CompressionEnable = false;
+        __GMM_ASSERT(false);
+    }
+
+    if (pCompressionEnable)
+    {
+        *pCompressionEnable = CompressionEnable;
+    }
+
+    return ReturnPATIndex;
+}
+
+//=============================================================================
+//
+// Function: SetUpMOCSTable
+//
+// Desc:
+//
+// Parameters:
+//
+// Return: GMM_STATUS
+//
+//-----------------------------------------------------------------------------
+void GmmLib::GmmXe2_LPGCachePolicy::SetUpMOCSTable()
+{
+    GMM_CACHE_POLICY_TBL_ELEMENT *pCachePolicyTlbElement = &(pGmmLibContext->GetCachePolicyTlbElement()[0]);
+
+#define L4_WB (0x0)
+#define L4_WT (0x1)
+#define L4_UC (0x3)
+
+#define L3_WB (0x0)
+#define L3_XD (pGmmLibContext->GetSkuTable().FtrL3TransientDataFlush ? 0x1 : 0x0)
+#define L3_UC (0x3)
+
+#define GMM_DEFINE_MOCS(indx, L4Caching, L3Caching, L3ClassOfService, ignorePAT) \
+    {                                                                            \
+        pCachePolicyTlbElement[indx].L3.PhysicalL3.L4CC      = L4Caching;        \
+        pCachePolicyTlbElement[indx].L3.PhysicalL3.Reserved0 = 0;                \
+        pCachePolicyTlbElement[indx].L3.PhysicalL3.L3CC      = L3Caching;        \
+        pCachePolicyTlbElement[indx].L3.PhysicalL3.L3CLOS    = L3ClassOfService; \
+        pCachePolicyTlbElement[indx].L3.PhysicalL3.igPAT     = ignorePAT;        \
+    }
+
+    // clang-format off
+    // Default MOCS Table
+    for(uint32_t j = 0; j < GMM_XE2_NUM_MOCS_ENTRIES; j++)
+    {   //               Index            CachingPolicy   L3Caching      L3ClassOfService    ignorePAT
+        GMM_DEFINE_MOCS( j,               L4_UC,          L3_UC,             0          ,     0  )
+    }
+
+    //             Index    L4 CachingPolicy   L3 CachingPolicy   L3 CLOS   ignorePAT
+    GMM_DEFINE_MOCS( 0      , L4_UC              , L3_WB           , 0     , 0)   // Defer to PAT
+    GMM_DEFINE_MOCS( 1      , L4_UC              , L3_WB           , 0     , 1)   // L3
+    GMM_DEFINE_MOCS( 2      , L4_WB              , L3_UC           , 0     , 1)   // L4
+    GMM_DEFINE_MOCS( 3      , L4_UC              , L3_UC           , 0     , 1)   // UC
+    GMM_DEFINE_MOCS( 4      , L4_WB              , L3_WB           , 0     , 1)   // L3+L4
+
+    CurrentMaxMocsIndex = 4;
+    CurrentMaxL1HdcMocsIndex   = 0;
+    CurrentMaxSpecialMocsIndex = 0;
+    // clang-format on
+
+#undef GMM_DEFINE_MOCS
+#undef L4_WB
+#undef L4_WT
+#undef L4_UC
+
+#undef L3_WB
+#undef L3_XD
+#undef L3_UC
+}
+
+
+//=============================================================================
+//
+// Function: SetupPAT
+//
+// Desc:
+//
+// Parameters:
+//
+// Return: GMM_STATUS
+//
+//-----------------------------------------------------------------------------
+GMM_STATUS GmmLib::GmmXe2_LPGCachePolicy::SetupPAT()
+{
+    GMM_PRIVATE_PAT *pPATTlbElement = &(pGmmLibContext->GetPrivatePATTable()[0]);
+
+#define L4_WB (0x0)
+#define L4_WT (0x1)
+#define L4_UC (0x3)
+
+#define L3_WB (0x0)
+#define L3_XD (pGmmLibContext->GetSkuTable().FtrL3TransientDataFlush ? 0x1 : 0x0)
+#define L3_UC (0x3)
+#define L3_XA (0x2) // WB Transient App
+
+#define GMM_DEFINE_PAT_ELEMENT(indx, Coh, L4Caching, L3Caching, L3ClassOfService, CompressionEn, NoCachePromote) \
+    {                                                                                                            \
+        pPATTlbElement[indx].Xe2.Coherency             = Coh;                                                    \
+        pPATTlbElement[indx].Xe2.L4CC                  = L4Caching;                                              \
+        pPATTlbElement[indx].Xe2.Reserved1             = 0;                                                      \
+        pPATTlbElement[indx].Xe2.Reserved2             = 0;                                                      \
+        pPATTlbElement[indx].Xe2.L3CC                  = L3Caching;                                              \
+        pPATTlbElement[indx].Xe2.L3CLOS                = L3ClassOfService;                                       \
+        pPATTlbElement[indx].Xe2.LosslessCompressionEn = CompressionEn;                                          \
+        pPATTlbElement[indx].Xe2.NoCachingPromote      = NoCachePromote;                                         \
+    }
+
+    // clang-format off
+
+    // Default PAT Table
+    // 32 nos
+    for (uint32_t i = 0; i < (NumPATRegisters); i++)
+    {   //                      Index  Coherency  CachingPolicy  L3Caching  L3ClassOfService  CompressionEn  NoCachingPromote
+        GMM_DEFINE_PAT_ELEMENT( i,     3,         L4_UC,         L3_UC,     0,                0,             0);
+    }
+
+    // Fixed PAT Table
+    //                      Index  Coherency  L4 CachingPolicy   L3 CachingPolicy   L3 CLOS      CompressionEn   NoCachingPromote
+    //Group: GGT/PPGTT[4]
+    GMM_DEFINE_PAT_ELEMENT( 0      , 0      , L4_UC              , L3_WB           , 0          , 0             , 0)    //          | L3_WB 
+    GMM_DEFINE_PAT_ELEMENT( 1      , 2      , L4_UC              , L3_WB           , 0          , 0             , 0)    //          | L3_WB | 1 way coherent
+    GMM_DEFINE_PAT_ELEMENT( 2      , 3      , L4_UC              , L3_WB           , 0          , 0             , 0)    //          | L3_WB | 2 way coherent
+    GMM_DEFINE_PAT_ELEMENT( 3      , 0      , L4_UC              , L3_UC           , 0          , 0             , 0)    // **UC   
+    //Group: 1 way Coh
+    GMM_DEFINE_PAT_ELEMENT( 4      , 2      , L4_WB              , L3_UC           , 0          , 0             , 0)    // L4_WB            | 1 way coherent
+    GMM_DEFINE_PAT_ELEMENT( 5      , 2      , L4_UC              , L3_UC           , 0          , 0             , 0)    // **UC             | 1 way coherent
+    //Group: Compression Disabled
+    GMM_DEFINE_PAT_ELEMENT( 6      , 0      , L4_UC              , L3_XD           , 0          , 0             , 1)    //          | L3_XD 
+    GMM_DEFINE_PAT_ELEMENT( 7      , 3      , L4_WB              , L3_UC           , 0          , 0             , 0)    // L4_WB            | 2 way coherent
+    GMM_DEFINE_PAT_ELEMENT( 8      , 0      , L4_WB              , L3_UC           , 0          , 0             , 0)    // L4_WB  
+    //Group: Compression Enabled
+    GMM_DEFINE_PAT_ELEMENT( 9      , 0      , L4_UC              , L3_WB           , 0          , 1             , 0)    //          | L3_WB | Comp 
+    GMM_DEFINE_PAT_ELEMENT( 10     , 0      , L4_WB              , L3_UC           , 0          , 1             , 0)    // L4_WB            | Comp
+    GMM_DEFINE_PAT_ELEMENT( 11     , 0      , L4_UC              , L3_XD           , 0          , 1             , 1)    //          | L3_XD | Comp 
+    GMM_DEFINE_PAT_ELEMENT( 12     , 0      , L4_UC              , L3_UC           , 0          , 1             , 0)    // **UC             | Comp 
+
+    GMM_DEFINE_PAT_ELEMENT( 13     , 0      , L4_WB              , L3_WB           , 0          , 0             , 0)     // L4_WB    | L3_WB 
+    GMM_DEFINE_PAT_ELEMENT( 14     , 0      , L4_WB              , L3_WB           , 0          , 1             , 0)    // L4_WB    | L3_WB | Comp
+    GMM_DEFINE_PAT_ELEMENT( 15     , 0      , L4_WT              , L3_XD           , 0          , 1             , 1)    // L4_WT    | L3_XD | Comp 
+    
+    //Reserved 16-19
+    //Group: CLOS1
+    GMM_DEFINE_PAT_ELEMENT( 20      , 0      , L4_UC             , L3_WB           , 1          , 0             , 0)    //          | L3_WB   
+    GMM_DEFINE_PAT_ELEMENT( 21      , 0      , L4_UC             , L3_WB           , 1          , 1             , 0)    //          | L3_WB | Comp 
+    GMM_DEFINE_PAT_ELEMENT( 22      , 2      , L4_UC             , L3_WB           , 1          , 0             , 0)    //          | L3_WB | 1 way coherent
+    GMM_DEFINE_PAT_ELEMENT( 23      , 3      , L4_UC             , L3_WB           , 1          , 0             , 0)    //          | L3_WB | 2 way coherent 
+    //Group:CLOS2=>Clone of CLOS1
+    GMM_DEFINE_PAT_ELEMENT( 24      , 0      , L4_UC             , L3_WB           , 2          , 0             , 0)    //          | L3_WB   
+    GMM_DEFINE_PAT_ELEMENT( 25      , 0      , L4_UC             , L3_WB           , 2          , 1             , 0)    //          | L3_WB | Comp 
+    GMM_DEFINE_PAT_ELEMENT( 26      , 2      , L4_UC             , L3_WB           , 2          , 0             , 0)    //          | L3_WB | 1 way coherent
+    GMM_DEFINE_PAT_ELEMENT( 27      , 3      , L4_UC             , L3_WB           , 2          , 0             , 0)    //          | L3_WB | 2 way coherent 
+    //Group:CLOS3=>Clone of CLOS1
+    GMM_DEFINE_PAT_ELEMENT( 28      , 0      , L4_UC             , L3_WB           , 3          , 0             , 0)    //          | L3_WB    
+    GMM_DEFINE_PAT_ELEMENT( 29      , 0      , L4_UC             , L3_WB           , 3          , 1             , 0)    //          | L3_WB | Comp 
+    GMM_DEFINE_PAT_ELEMENT( 30      , 2      , L4_UC             , L3_WB           , 3          , 0             , 0)    //          | L3_WB | 1 way coherent
+    GMM_DEFINE_PAT_ELEMENT( 31      , 3      , L4_UC             , L3_WB           , 3          , 0             , 0)    //          | L3_WB | 2 way coherent 
+
+    CurrentMaxPATIndex = 31;
+
+// clang-format on
+#undef GMM_DEFINE_PAT
+#undef L4_WB
+#undef L4_WT
+#undef L4_UC
+
+#undef L3_WB
+#undef L3_XD
+#undef L3_UC
+    return GMM_SUCCESS;
+}
diff --git a/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.h b/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.h
new file mode 100644
index 0000000..4b07a4a
--- /dev/null
+++ b/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.h
@@ -0,0 +1,295 @@
+/*==============================================================================
+Copyright(c) 2024 Intel Corporation
+Permission is hereby granted, free of charge, to any person obtaining a
+copy of this software and associated documentation files(the "Software"),
+to deal in the Software without restriction, including without limitation
+the rights to use, copy, modify, merge, publish, distribute, sublicense,
+and / or sell copies of the Software, and to permit persons to whom the
+Software is furnished to do so, subject to the following conditions:
+
+The above copyright notice and this permission notice shall be included
+in all copies or substantial portions of the Software.
+
+THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
+THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
+OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+OTHER DEALINGS IN THE SOFTWARE.
+============================================================================*/
+#include "GmmCachePolicyConditionals.h"
+
+#define _SN        0x1
+#define _IA_GPU_SN 0x2
+#define _WT        0x2
+#define _L1_WB     0x2
+#define dGPU       SKU(FtrDiscrete)
+
+#if (_DEBUG || _RELEASE_INTERNAL)
+#define _WA_WB_Emu (WA(Wa_EmuMufasaSupportOnBmg))
+#else
+#define _WA_WB_Emu 0
+#endif
+
+// GmmLib can apply 2Way WA to GMM_RESOURCE_USAGE_HW_CONTEXT.
+#define _WA_2W (WA(Wa_14018976079) || WA(Wa_14018984349)) ? 2 : 0
+#define _L3_P  ((_WA_2W == 2) ? 1 : 0) // L3 Promotion to WB if 2Way Coh WA is set
+
+// clang-format off
+//typedef enum GMM_CACHING_POLICY_REC
+//{
+//    GMM_UC   = 0x0, //uncached
+//    GMM_WB   = 0x1, // Write back
+//    GMM_WT   = 0x2, // write-through
+//    GMM_WBTD = 0x3, // WB_T_Display
+//    GMM_WBTA = 0x4, // WB_T_App
+//    GMM_WBP  = 0x5, // write bypass mode
+//    GMM_WS   = 0x6, // Write-Streaming
+//} GMM_CACHING_POLICY;
+//
+// typedef enum GMM_COHERENCY_TYPE_REC
+//{
+//GMM_NON_COHERENT_NO_SNOOP         = 0x0,
+//GMM_COHERENT_ONE_WAY_IA_SNOOP     = 0x1,
+//GMM_COHERENT_TWO_WAY_IA_GPU_SNOOP = 0x2
+//} GMM_COHERENCY_TYPE;
+// Cache Policy Definition
+// L3_CLOS      : L3 class of service (0,1,2,3)
+// IgPAT        : Ignore PAT 1 = Override by MOCS, 0 = Defer to PAT
+//Macros for segment-preference
+#define NoP                          0x0
+//Wa_14018443005
+#define COMPRESSED_PAT_WITH_L4WB_L3UC_0 PAT10
+#define COMPRESSED_PAT_WITH_L4WB_L3WB_0 PAT14
+#define COMPRESSED_PAT_WITH_L4UC_L3UC_0 PAT12
+#define COMPRESSED_PAT_WITH_L4UC_L3WB_0 PAT9
+
+#define ISWA_1401844305USAGE(usage)       ((Usage == GMM_RESOURCE_USAGE_BLT_SOURCE) ||      \
+                                           (Usage == GMM_RESOURCE_USAGE_BLT_DESTINATION) || \
+                                           (Usage == GMM_RESOURCE_USAGE_COPY_SOURCE) ||     \
+                                           (Usage == GMM_RESOURCE_USAGE_COPY_DEST))
+//******************************************************************************************************************************************************************/
+//                   USAGE TYPE                                                               L3_CC, L3_CLOS, L1CC,   L2CC,   L4CC,     Coherency,   IgPAT,  SegOv)
+/*******************************************************************************************************************************************************************/
+// KMD Usages
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_BATCH_BUFFER                                          ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_COMP_FRAME_BUFFER                                     ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_CONTEXT_SWITCH_BUFFER                                 ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_CURSOR                                                ,  3,     0,     0,      0    ,  0			,  0     , 0,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DISPLAY_STATIC_IMG_FOR_SMOOTH_ROTATION_BUFFER         ,  3,     0,     0,      0    ,  0			,  0     , 0,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DUMMY_PAGE                                            ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GDI_SURFACE                                           ,  1,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GENERIC_KMD_RESOURCE                                  ,  1,		0,     0,      0    ,  0    		,  _WA_2W, 1,    NoP);
+// GMM_RESOURCE_USAGE_GFX_RING is only used if WaEnableRingHostMapping is enabled .
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GFX_RING                                              ,  0,     0,     0,      0    ,  0			,  0     , 1,	  NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GTT_TRANSFER_REGION                                   ,  0,     0,     0,      0    ,  0			,  0     , 1,	  NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HW_CONTEXT                                            ,  1,		0,     0,	   0    ,  0			,  _WA_2W, 1,     NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_STATE_MANAGER_KERNEL_STATE                            ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_KMD_STAGING_SURFACE                                   ,  1,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_MBM_BUFFER                                            ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_NNDI_BUFFER                                           ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OVERLAY_MBM                                           ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_PRIMARY_SURFACE                                       ,  3,     0,     0,      0    ,  0			,  0     , 0,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_SCREEN_PROTECTION_INTERMEDIATE_SURFACE                ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_SHADOW_SURFACE                                        ,  1,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_SM_SCRATCH_STATE                                      ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_STATUS_PAGE                                           ,  1,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TIMER_PERF_QUEUE                                      ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_UNKNOWN                                               ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_UNMAP_PAGING_RESERVED_GTT_DMA_BUFFER                  ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VSC_BATCH_BUFFER                                      ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_WA_BATCH_BUFFER                                       ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_KMD_OCA_BUFFER                                        ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
+
+//
+// 3D Usages
+//
+//                   USAGE TYPE                                                               L3_CC, L3_CLOS,L1CC,   L2CC,   L4CC,     Coherency , IgPAT)
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_DEPTH_BUFFER                                    ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_HIZ                                             ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_UMD_BATCH_BUFFER                                      ,  0,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_BINDING_TABLE_POOL                                    ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_CCS                                                   ,  0,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_CONSTANT_BUFFER_POOL                                  ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DEPTH_BUFFER                                          ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DISPLAYABLE_RENDER_TARGET                             ,  3,     0,     0,      0    , 0		,  0     ,   0,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GATHER_POOL                                           ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HEAP_SURFACE_STATE                                    ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HEAP_DYNAMIC_STATE                                    ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HEAP_GENERAL_STATE                                    ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HEAP_GENERAL_STATE_UC                                 ,  0,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HEAP_STATELESS_DATA_PORT                              ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HEAP_STATELESS_DATA_PORT_L1_CACHED                    ,  1,     0,     1,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HEAP_INDIRECT_OBJECT                                  ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HEAP_INSTRUCTION                                      ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HIZ                                                   ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_INDEX_BUFFER                                          ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_INDEX_BUFFER_L3_COHERENT_UC                           ,  0,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_INDEX_BUFFER_L3_CACHED                                ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_MCS                                                   ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_PUSH_CONSTANT_BUFFER                                  ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_PULL_CONSTANT_BUFFER                                  ,  1,     0,     5,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_QUERY                                                 ,  _WA_WB_Emu,     0,     0,      0    , 0		,  1     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_RENDER_TARGET                                         ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_SHADER_RESOURCE                                       ,  1,     0,     5,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_STAGING                                               ,  _WA_WB_Emu,     0,     0,      0    , 0		,  1     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_STENCIL_BUFFER                                        ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_STREAM_OUTPUT_BUFFER                                  ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILE_POOL                                             ,  1,     0,     0,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_SHADER_RESOURCE_LLC_BYPASS                            ,  1,     0,     5,      0    , 0		,  0     ,   1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_MOCS_62                                               ,  0,     0,     0,      0    , 0		,  0     ,   1,	   NoP); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_L3_EVICTION                                           ,  0,     0,     0,      0    , 0		,  0     ,   1,	   NoP); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_L3_EVICTION_SPECIAL                                   ,  0,     0,     0,      0    , 0		,  0     ,   1,	   NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_UMD_OCA_BUFFER                                        ,  0,     0,     0,      0    , 0		,  0     ,   1,	   NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_PROCEDURAL_TEXTURE                                    ,  1,     0,     0,      0    , 0		,  0     ,   1,	   NoP);
+
+// Tiled Resource
+//
+//                   USAGE TYPE                                                               L3_CC, L3_CLOS,L1CC,   L2CC,   L4CC,     Coherency,  IgPAT)
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_DEPTH_BUFFER                                    ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_HIZ                                             ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_MCS                                             ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_CCS                                             ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_RENDER_TARGET                                   ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_RENDER_TARGET_AND_SHADER_RESOURCE               ,  1,     0,     5,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_SHADER_RESOURCE                                 ,  1,     0,     5,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_TILED_UAV                                             ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_UAV                                                   ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VERTEX_BUFFER                                         ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VERTEX_BUFFER_L3_COHERENT_UC                          ,  0,     0,     0,      0    , 0      ,  0     ,    1,    NoP); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VERTEX_BUFFER_L3_CACHED                               ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OGL_WSTN_VERTEX_BUFFER                                ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_POSH_VERTEX_BUFFER                                    ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_RENDER_TARGET_AND_SHADER_RESOURCE                     ,  1,     0,     5,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_WDDM_HISTORY_BUFFER                                   ,  1,     0,     0,      0    , 0      ,  0     ,    1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_CONTEXT_SAVE_RESTORE                                  ,  1,     0,     0,      0    , 0      ,  0     ,    1,	 NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_PTBR_PAGE_POOL                                        ,  1,     0,     0,      0    , 0      ,  0     ,    1,	 NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_PTBR_BATCH_BUFFER                                     ,  1,     0,     0,      0    , 0      ,  0     ,    1,	 NoP);
+
+//
+// CM USAGES
+//
+//                   USAGE TYPE                                                                L3_CC, L3_CLOS,L1CC,   L2CC,   L4CC,     Coherency, IgPAT)
+DEFINE_CACHE_ELEMENT(CM_RESOURCE_USAGE_SurfaceState,                                            1,     0,     0,      0    , 1      ,  0     ,     1,	NoP);
+DEFINE_CACHE_ELEMENT(CM_RESOURCE_USAGE_L1_Enabled_SurfaceState,                                 1,     0,     1,      0    , 1      ,  0     ,     1,	NoP);
+DEFINE_CACHE_ELEMENT(CM_RESOURCE_USAGE_StateHeap,                                               1,     0,     0,      0    , 1      ,  0     ,     1,	NoP);
+DEFINE_CACHE_ELEMENT(CM_RESOURCE_USAGE_NO_L3_SurfaceState,                                      0,     0,     0,      0    , 1      ,  0     ,     1,	NoP);
+DEFINE_CACHE_ELEMENT(CM_RESOURCE_USAGE_NO_CACHE_SurfaceState,                                   0,     0,     0,      0    , 0      ,  0     ,     1,	NoP);
+
+//
+// MP USAGES
+//
+//                   USAGE TYPE                                                               L3_CC, L3_CLOS,L1CC,   L2CC,   L4CC,     Coherency,  IgPAT )
+DEFINE_CACHE_ELEMENT(MP_RESOURCE_USAGE_BEGIN,                                                   0,     0,     0,      0    ,  0       ,  0     ,    1,	NoP);
+DEFINE_CACHE_ELEMENT(MP_RESOURCE_USAGE_DEFAULT,                                                 0,     0,     0,      0    ,  0       ,  0     ,    1,	NoP);
+DEFINE_CACHE_ELEMENT(MP_RESOURCE_USAGE_DEFAULT_FF,                                              0,     0,     0,      0    ,  0       ,  0     ,    1,	NoP);
+DEFINE_CACHE_ELEMENT(MP_RESOURCE_USAGE_DEFAULT_RCS,                                             0,     0,     0,      0    ,  0       ,  0     ,    1,	NoP);
+DEFINE_CACHE_ELEMENT(MP_RESOURCE_USAGE_SurfaceState,                                            1,     0,     0,      0    ,  1       ,  0     ,    1,	NoP);
+DEFINE_CACHE_ELEMENT(MP_RESOURCE_USAGE_SurfaceState_FF,                                         0,     0,     0,      0    ,  0       ,  0     ,    1,	NoP);
+DEFINE_CACHE_ELEMENT(MP_RESOURCE_USAGE_SurfaceState_RCS,                                        1,     0,     0,      0    ,  1       ,  0     ,    1,	NoP);
+DEFINE_CACHE_ELEMENT(MP_RESOURCE_USAGE_END,                                                     0,     0,     0,      0    ,  0       ,  0     ,    1,	NoP); 
+
+// MHW - SFC
+//                   USAGE TYPE                                                               , L3_CC, L3_CLOS,L1CC,   L2CC,   L4CC,     Coherency, IgPAT)
+DEFINE_CACHE_ELEMENT(MHW_RESOURCE_USAGE_Sfc_CurrentOutputSurface,                               0,     0,     0,      0    ,  0       ,  0     ,   1,	  NoP);
+DEFINE_CACHE_ELEMENT(MHW_RESOURCE_USAGE_Sfc_AvsLineBufferSurface,                               0,     0,     0,      0    ,  0       ,  0     ,   1,	  NoP);
+DEFINE_CACHE_ELEMENT(MHW_RESOURCE_USAGE_Sfc_IefLineBufferSurface,                               0,     0,     0,      0    ,  0       ,  0     ,   1,	  NoP);
+
+
+
+/**********************************************************************************/
+
+//
+// OCL Usages
+//
+//                   USAGE TYPE                                                               L3_CC, L3_CLOS,L1CC,   L2CC,   L4CC,     Coherency , IgPAT)
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER                                            ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER_CONST                                      ,  1,     0,      5,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER_CSR_UC                                     ,  0,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER_CACHELINE_MISALIGNED                       ,  0,     0,      0,      0    , 0		,  0       ,  1,    NoP); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_IMAGE                                             ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_INLINE_CONST                                      ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_INLINE_CONST_HDC                                  ,  1,     0,      5,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_SCRATCH                                           ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_PRIVATE_MEM                                       ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_PRINTF_BUFFER                                     ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_STATE_HEAP_BUFFER                                 ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_SYSTEM_MEMORY_BUFFER                              ,  1,     0,      0,      0    , 0		,  1       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_SYSTEM_MEMORY_BUFFER_CACHELINE_MISALIGNED         ,  0,     0,      0,      0    , 0		,  0       ,  1,    NoP); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_ISH_HEAP_BUFFER                                   ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_TAG_MEMORY_BUFFER                                 ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_TEXTURE_BUFFER                                    ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_SELF_SNOOP_BUFFER                                 ,  1,     0,      0,      0    , 0		,  0       ,  1,    NoP);
+/**********************************************************************************/
+
+// Cross Adapter
+//                   USAGE TYPE                                                               ,L3_CC, L3_CLOS,L1CC,   L2CC,   L4CC,     Coherency , IgPAT)
+DEFINE_CACHE_ELEMENT( GMM_RESOURCE_USAGE_XADAPTER_SHARED_RESOURCE                             ,  0,     0,     1,      0    ,  0		,  0       , 1, NoP);
+/**********************************************************************************/
+
+// BCS
+//                   USAGE TYPE                                                                L3_CC,  L3_CLOS, L1CC,   L2CC,   L4CC,     Coherency, IgPAT)
+DEFINE_CACHE_ELEMENT( GMM_RESOURCE_USAGE_BLT_SOURCE                                           ,  0,      0,      0,      0,      0,           0,       1, NoP);
+DEFINE_CACHE_ELEMENT( GMM_RESOURCE_USAGE_BLT_DESTINATION                                      ,  0,      0,      0,      0,      0,           0,       1, NoP);
+
+/**********************************************************************************/
+//
+// MEDIA USAGES
+//                   USAGE TYPE                                                         L3_CC,   L3_CLOS,L1CC,   L2CC,   L4CC,     Coherency,	IgPAT )
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_MEDIA_BATCH_BUFFERS                             ,  0,     0,      0,      0,		0,         0 ,        1,	  NoP	 );
+// DECODE
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_INPUT_BITSTREAM                          ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_INPUT_REFERENCE                          ,  dGPU,  0,     0,      1,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_INTERNAL_READ                            ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_INTERNAL_WRITE                           ,  0,     0,     0,      0,			0,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_INTERNAL_READ_WRITE_CACHE                ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    ); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_INTERNAL_READ_WRITE_NOCACHE              ,  0,     0,     0,      0,			0,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_OUTPUT_PICTURE                           ,  3,     0,     0,      0,			2,         0  ,        0,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_OUTPUT_STATISTICS_WRITE                  ,  0,     0,     0,      0,			0,         1  ,        1,    NoP    );  
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DECODE_OUTPUT_STATISTICS_READ_WRITE             ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP	 );
+// ENCODE
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_INPUT_RAW                                ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_INPUT_RECON                              ,  dGPU,  0,     0,      1,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_INTERNAL_READ                            ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_INTERNAL_WRITE                           ,  0,     0,     0,      0,			0,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_INTERNAL_READ_WRITE_CACHE                ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_INTERNAL_READ_WRITE_NOCACHE              ,  0,     0,     0,      0,			0,         0  ,        1,    NoP    );  
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_EXTERNAL_READ                            ,  0,     0,     0,      0,			0,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_OUTPUT_PICTURE                           ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_OUTPUT_BITSTREAM                         ,  0,     0,     0,      0,			0,         1  ,        1,	  NoP    ); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_OUTPUT_STATISTICS_WRITE                  ,  0,     0,     0,      0,			0,         1  ,        1,	  NoP    ); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_ENCODE_OUTPUT_STATISTICS_READ_WRITE             ,  dGPU,  0,     0,      0,			1,         0  ,        1,	  NoP    );
+// VP
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INPUT_PICTURE_FF                             ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INPUT_REFERENCE_FF                           ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INTERNAL_READ_FF                             ,  0,     0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INTERNAL_WRITE_FF                            ,  0,     0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INTERNAL_READ_WRITE_FF                       ,  dGPU,  0,     0,      0,			1,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_OUTPUT_PICTURE_FF                            ,  3,     0,     0,      0,			2,         0  ,        0,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INPUT_PICTURE_RENDER                         ,  1,     0,     0,      0,			0,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INPUT_REFERENCE_RENDER                       ,  1,     0,     0,      0,			0,         0  ,        1,    NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INTERNAL_READ_RENDER                         ,  0,     0,     0,      0,			0,         0  ,        1,	  NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INTERNAL_WRITE_RENDER                        ,  0,     0,     0,      0,			0,         0  ,        1,	  NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_INTERNAL_READ_WRITE_RENDER                   ,  1,     0,     0,      0,			0,         0  ,        1,	  NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_VP_OUTPUT_PICTURE_RENDER                        ,  3,     0,     0,      0,			0,         0  ,        0,	  NoP    ); 
+// CP
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_CP_EXTERNAL_READ                                ,  0,     0,     0,      0,			0,         0  ,        1,	  NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_CP_INTERNAL_WRITE                               ,  0,     0,     0,      0,			0,         0  ,        1,	  NoP    );
+
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GSC_KMD_RESOURCE                                ,  0,     0,     0,      0,			0,         0  ,        1,	  NoP    );
+
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_KMD_NULL_CONTEXT_BB                             ,  0,     0,     0,      0    ,		0,         0  ,        1,	  NoP    );
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_COMMAND_STREAMER                                ,  0,     0,     0,      0    ,		0,         0  ,        1,	  NoP    );
+
+//                   USAGE TYPE                                                        , L3_CC,   L3_CLOS, L1CC,   L2CC,   L4CC,   Coherency, IgPAT)
+// Uncacheable copies
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_COPY_SOURCE                                     , 0,         0,     0 ,      0,	     0,       0,        1,	  NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_COPY_DEST                                       , 0,         0,     0 ,      0,      0,       0,        1,	  NoP);
+
+// clang-format on
+
+#undef _WT
+#include "GmmCachePolicyUndefineConditionals.h"
+
diff --git a/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp
index 2040294..2593a06 100644
--- a/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp
@@ -39,7 +39,7 @@ GMM_STATUS GmmLib::GmmXe_LPGCachePolicy::InitCachePolicy()
 {
     __GMM_ASSERTPTR(pCachePolicy, GMM_ERROR);
 
-#define DEFINE_CACHE_ELEMENT(usage, l3, l3_scc, go, uclookup, l1cc, l2cc, l4cc, coherency) DEFINE_CP_ELEMENT(usage, 0, 0, l3, 0, 0, 0, 0, l3_scc, 0, 0, 0, 0, 0, 0, go, uclookup, l1cc, l2cc, l4cc, coherency)
+#define DEFINE_CACHE_ELEMENT(usage, l3, l3_scc, go, uclookup, l1cc, l2cc, l4cc, coherency) DEFINE_CP_ELEMENT(usage, 0, 0, l3, 0, 0, 0, 0, l3_scc, 0, 0, 0, 0, 0, 0, go, uclookup, l1cc, l2cc, l4cc, coherency, l3, 0, 0)
 
 #include "GmmXe_LPGCachePolicy.h"
 
@@ -245,7 +245,8 @@ GMM_STATUS GmmLib::GmmXe_LPGCachePolicy::InitCachePolicy()
         }
 
         pCachePolicy[Usage].PATIndex                          = PATIdx;
-        pCachePolicy[Usage].CoherentPATIndex                  = CoherentPATIdx;
+        pCachePolicy[Usage].CoherentPATIndex                  = GET_COHERENT_PATINDEX_LOWER_BITS(CoherentPATIdx);
+        pCachePolicy[Usage].CoherentPATIndexHigherBit         = GET_COHERENT_PATINDEX_HIGHER_BIT(CoherentPATIdx);
         pCachePolicy[Usage].PTE.DwordValue                    = GMM_GET_PTE_BITS_FROM_PAT_IDX(PATIdx) & 0xFFFFFFFF;
         pCachePolicy[Usage].PTE.HighDwordValue                = GMM_GET_PTE_BITS_FROM_PAT_IDX(PATIdx) >> 32;
         pCachePolicy[Usage].MemoryObjectOverride.XE_LPG.Index = CPTblIdx;
@@ -260,8 +261,55 @@ GMM_STATUS GmmLib::GmmXe_LPGCachePolicy::InitCachePolicy()
     return GMM_SUCCESS;
 }
 
+//=============================================================================
+//
+// Function: __:SetL1CachePolicy
+//
+// Desc: This function converting indicator values to actual register values and store into pCachePolicy to return to UMD's.
+// Gmm not using this values. UMD's queries for this values.
+//
+// Parameters: Usage
+//
+// Return: VOID
+//
+//-----------------------------------------------------------------------------
+void GmmLib::GmmXe_LPGCachePolicy::SetL1CachePolicy(uint32_t Usage)
+{
 
+// As per HW, L1 cache control(L1CC) values  (0: WBP write bypass mode, 1: 0 uncached, 2: WB Write back, 3:WT write-through, 4: WS Write-Streaming).
+#define L1_WBP_CACHEABLE (0x0)
+#define L1_UNCACHEABLE   (0x1)
+#define L1_WB_CACHEABLE  (0x2)
+#define L1_WT_CACHEABLE  (0x3)
+#define L1_WS_CACHEABLE  (0x4)
 
+    switch (pCachePolicy[Usage].L1CC)
+    {
+    case GMM_UC:
+        pCachePolicy[Usage].L1CC = L1_UNCACHEABLE;
+        break;
+    case GMM_WB:
+        pCachePolicy[Usage].L1CC = L1_WB_CACHEABLE;
+        break;
+    case GMM_WT:
+        pCachePolicy[Usage].L1CC = L1_WT_CACHEABLE;
+        break;
+    case GMM_WBP:
+        pCachePolicy[Usage].L1CC = L1_WBP_CACHEABLE;
+        break;
+    case GMM_WS:
+        pCachePolicy[Usage].L1CC = L1_WS_CACHEABLE;
+        break;
+    default:
+        pCachePolicy[Usage].L1CC = L1_UNCACHEABLE;
+    }
+
+#undef L1_WBP_CACHEABLE
+#undef L1_UNCACHEABLE
+#undef L1_WB_CACHEABLE
+#undef L1_WT_CACHEABLE
+#undef L1_WS_CACHEABLE
+}
 /////////////////////////////////////////////////////////////////////////////////////
 ///      A simple getter function returning the PAT (cache policy) for a given
 ///      use Usage of the named resource pResInfo.
@@ -289,7 +337,7 @@ uint32_t GMM_STDCALL GmmLib::GmmXe_LPGCachePolicy::CachePolicyGetPATIndex(GMM_RE
 
     if(IsCpuCacheable)
     {
-        return pGmmLibContext->GetCachePolicyElement(Usage).CoherentPATIndex;
+        return (uint32_t)(GET_COHERENT_PATINDEX_VALUE(pGmmLibContext, Usage));
     }
     else
     {
@@ -417,4 +465,46 @@ GMM_STATUS GmmLib::GmmXe_LPGCachePolicy::SetupPAT()
     return GMM_SUCCESS;
 }
 
+uint32_t GMM_STDCALL GmmLib::GmmXe_LPGCachePolicy::GetSurfaceStateL1CachePolicy(GMM_RESOURCE_USAGE_TYPE Usage)
+{
+    __GMM_ASSERT(pCachePolicy[Usage].Initialized);
+
+    return pCachePolicy[Usage].L1CC;
+}
+
+/////////////////////////////////////////////////////////////////////////////////////
+///      A simple getter function returning the MOCS (cache policy) for a given
+///      use Usage of the named resource pResInfo.
+///      Typically used to populate a SURFACE_STATE for a GPU task.
+///
+/// @param[in]     pResInfo: Resource info for resource, can be NULL.
+/// @param[in]     Usage: Current usage for resource.
+///
+/// @return        MEMORY_OBJECT_CONTROL_STATE: Gen adjusted MOCS structure (cache
+///                                             policy) for the given buffer use.
+/////////////////////////////////////////////////////////////////////////////////////
+MEMORY_OBJECT_CONTROL_STATE GMM_STDCALL GmmLib::GmmXe_LPGCachePolicy::CachePolicyGetMemoryObject(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage)
+{
+    __GMM_ASSERT(pCachePolicy[Usage].Initialized);
+
+    // Prevent wrong Usage for XAdapter resources. UMD does not call GetMemoryObject on shader resources but,
+    // when they add it someone could call it without knowing the restriction.
+    if (pResInfo &&
+        pResInfo->GetResFlags().Info.XAdapter &&
+         (Usage != GMM_RESOURCE_USAGE_XADAPTER_SHARED_RESOURCE))
+    {
+        __GMM_ASSERT(false);
+    }
+
+    if (!pResInfo ||
+        (pCachePolicy[Usage].Override & pCachePolicy[Usage].IDCode) ||
+        (pCachePolicy[Usage].Override == ALWAYS_OVERRIDE))
+    {
+        return pCachePolicy[Usage].MemoryObjectOverride;
+    }
+    else
+    {
+        return pCachePolicy[Usage].MemoryObjectNoOverride;
+    }
+}
 
diff --git a/Source/GmmLib/GlobalInfo/GmmClientContext.cpp b/Source/GmmLib/GlobalInfo/GmmClientContext.cpp
index b01181e..8215295 100644
--- a/Source/GmmLib/GlobalInfo/GmmClientContext.cpp
+++ b/Source/GmmLib/GlobalInfo/GmmClientContext.cpp
@@ -67,7 +67,6 @@ MEMORY_OBJECT_CONTROL_STATE GMM_STDCALL GmmLib::GmmClientContext::CachePolicyGet
 {
     return pGmmLibContext->GetCachePolicyObj()->CachePolicyGetMemoryObject(pResInfo, Usage);
 }
-
 /////////////////////////////////////////////////////////////////////////////////////
 /// Member function of ClientContext class for returning
 /// GMM_PTE_CACHE_CONTROL_BITS for a given Resource Usage Type
@@ -126,7 +125,127 @@ uint8_t GMM_STDCALL GmmLib::GmmClientContext::CachePolicyIsUsagePTECached(GMM_RE
 /////////////////////////////////////////////////////////////////////////////////////
 uint8_t GMM_STDCALL GmmLib::GmmClientContext::GetSurfaceStateL1CachePolicy(GMM_RESOURCE_USAGE_TYPE Usage)
 {
-    return pGmmLibContext->GetCachePolicyElement(Usage).L1CC;
+    return pGmmLibContext->GetCachePolicyObj()->GetSurfaceStateL1CachePolicy(Usage);
+}
+
+/////////////////////////////////////////////////////////////////////////////////////
+/// Member function of ClientContext class to return Swizzle Descriptor
+/// given Swizzle name , ResType and bpe
+///
+/// @param[in] EXTERNAL_SWIZZLE_NAME
+/// @param[in] EXTERNAL_RES_TYPE
+/// @param[in] bpe
+/// @return  SWIZZLE_DESCRIPTOR*
+/////////////////////////////////////////////////////////////////////////////////////
+const SWIZZLE_DESCRIPTOR *GMM_STDCALL GmmLib::GmmClientContext::GetSwizzleDesc(EXTERNAL_SWIZZLE_NAME ExternalSwizzleName, EXTERNAL_RES_TYPE ResType, uint8_t bpe, bool isStdSwizzle)
+{
+    const SWIZZLE_DESCRIPTOR *pSwizzleDesc;
+    pSwizzleDesc = NULL;
+    /*#define SWITCH_SWIZZLE(Layout, res, bpe) \
+        pSwizzleDesc = &Layout##_##res##bpe;*/
+
+#define CASE_BPP(Layout, Tile, msaa, xD, bpe)       \
+    case bpe:                                       \
+        pSwizzleDesc = &Layout##_##Tile##msaa##bpe; \
+        break;
+
+#define SWITCH_SWIZZLE(Layout, Tile, msaa, bpe) \
+    switch (bpe)                                \
+    {                                           \
+        CASE_BPP(Layout, Tile, msaa, xD, 8);    \
+        CASE_BPP(Layout, Tile, msaa, xD, 16);   \
+        CASE_BPP(Layout, Tile, msaa, xD, 32);   \
+        CASE_BPP(Layout, Tile, msaa, xD, 64);   \
+        CASE_BPP(Layout, Tile, msaa, xD, 128);  \
+    }
+#define SWIZZLE_DESC(pGmmLibContext, ExternalSwizzleName, ResType, bpe, pSwizzleDesc) \
+    switch (ExternalSwizzleName)                                                      \
+    {                                                                                 \
+    case TILEX:                                                                       \
+        pSwizzleDesc = &INTEL_TILE_X;                                                 \
+        break;                                                                        \
+    case TILEY:                                                                       \
+        if (GmmGetSkuTable(pGmmLibContext)->FtrTileY)                                 \
+            pSwizzleDesc = &INTEL_TILE_Y;                                             \
+        else                                                                          \
+            pSwizzleDesc = &INTEL_TILE_4;                                             \
+        break;                                                                        \
+    case TILEYS:                                                                      \
+        if (GmmGetSkuTable(pGmmLibContext)->FtrTileY || isStdSwizzle)                 \
+        {                                                                             \
+            switch (ResType)                                                          \
+            {                                                                         \
+            case 0:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_YS, , , bpe);                               \
+                break;                                                                \
+            case 1:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_YS, 3D_, , bpe);                            \
+                break;                                                                \
+            case 2:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_YS, , MSAA2_, bpe);                         \
+                break;                                                                \
+            case 3:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_YS, , MSAA4_, bpe);                         \
+                break;                                                                \
+            case 4:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_YS, , MSAA8_, bpe);                         \
+                break;                                                                \
+            case 5:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_YS, , MSAA16_, bpe);                        \
+                break;                                                                \
+            }                                                                         \
+        }                                                                             \
+        else if (GmmGetSkuTable(pGmmLibContext)->FtrXe2PlusTiling)                    \
+        {                                                                             \
+            switch (ResType)                                                          \
+            {                                                                         \
+            case 0:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64, , , bpe);                               \
+                break;                                                                \
+            case 1:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64_V2, 3D_, , bpe);                         \
+                break;                                                                \
+            case 2:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64_V2, , MSAA2_, bpe);                      \
+                break;                                                                \
+            case 3:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64_V2, , MSAA4_, bpe);                      \
+                break;                                                                \
+            case 4:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64_V2, , MSAA8_, bpe);                      \
+                break;                                                                \
+            case 5:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64_V2, , MSAA16_, bpe);                     \
+                break;                                                                \
+            }                                                                         \
+        }                                                                             \
+        else                                                                          \
+        {                                                                             \
+            switch (ResType)                                                          \
+            {                                                                         \
+            case 0:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64, , , bpe);                               \
+                break;                                                                \
+            case 1:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64, 3D_, , bpe);                            \
+                break;                                                                \
+            case 2:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64, , MSAA2_, bpe);                         \
+                break;                                                                \
+            case 3:                                                                   \
+            case 4:                                                                   \
+            case 5:                                                                   \
+                SWITCH_SWIZZLE(INTEL_TILE_64, , MSAA_, bpe);                          \
+                break;                                                                \
+            }                                                                         \
+        }                                                                             \
+    case TILEW:                                                                       \
+    case TILEYF:                                                                      \
+    default: break;                                                                   \
+    }                                                                                 \
+
+    SWIZZLE_DESC(pGmmLibContext, ExternalSwizzleName, ResType, bpe, pSwizzleDesc);
+    return pSwizzleDesc;
 }
 
 /////////////////////////////////////////////////////////////////////////////////////
@@ -355,7 +474,7 @@ GMM_E2ECOMP_FORMAT GMM_STDCALL GmmLib::GmmClientContext::GetLosslessCompressionT
 
 /////////////////////////////////////////////////////////////////////////////////////
 /// Member function of ClientContext class to return InternalGpuVaMax value
-/// stored in pGmmGlobalContext
+/// stored in pGmmLibContext
 ///
 /// @return    GMM_SUCCESS
 /////////////////////////////////////////////////////////////////////////////////////
@@ -843,8 +962,11 @@ extern "C" GMM_CLIENT_CONTEXT *GMM_STDCALL GmmCreateClientContextForAdapter(GMM_
     GMM_CLIENT_CONTEXT *pGmmClientContext = nullptr;
     GMM_LIB_CONTEXT *   pLibContext       = pGmmMALibContext->GetAdapterLibContext(sBdf);
 
-    pGmmClientContext = new GMM_CLIENT_CONTEXT(ClientType, pLibContext);
+    if (pLibContext)
+    {
+        pGmmClientContext = new GMM_CLIENT_CONTEXT(ClientType, pLibContext);
 
+    }
     return pGmmClientContext;
 }
 /////////////////////////////////////////////////////////////////////////////////////
diff --git a/Source/GmmLib/GlobalInfo/GmmInfo.cpp b/Source/GmmLib/GlobalInfo/GmmInfo.cpp
index db81fd6..8876890 100644
--- a/Source/GmmLib/GlobalInfo/GmmInfo.cpp
+++ b/Source/GmmLib/GlobalInfo/GmmInfo.cpp
@@ -128,7 +128,8 @@ extern "C" GMM_STATUS GMM_STDCALL GmmCreateLibContext(const PLATFORM Platform,
                                                       const void *   pSkuTable,
                                                       const void *   pWaTable,
                                                       const void *   pGtSysInfo,
-                                                      ADAPTER_BDF    sBdf)
+                                                      ADAPTER_BDF    sBdf,
+                                                      const GMM_CLIENT ClientType)
 #endif
 {
     __GMM_ASSERTPTR(pSkuTable, GMM_ERROR);
@@ -144,7 +145,7 @@ extern "C" GMM_STATUS GMM_STDCALL GmmCreateLibContext(const PLATFORM Platform,
 #if LHDM
     return pGmmMALibContext->AddContext(Platform, pSkuTable, pWaTable, pGtSysInfo, sBdf, DeviceRegistryPath);
 #else
-    return pGmmMALibContext->AddContext(Platform, pSkuTable, pWaTable, pGtSysInfo, sBdf);
+    return pGmmMALibContext->AddContext(Platform, pSkuTable, pWaTable, pGtSysInfo, sBdf, ClientType);
 #endif
 }
 
@@ -228,7 +229,8 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmMultiAdapterContext::AddContext(const PLATFORM
                                                                   const void    *_pSkuTable,
                                                                   const void    *_pWaTable,
                                                                   const void    *_pGtSysInfo,
-                                                                  ADAPTER_BDF    sBdf)
+                                                                  ADAPTER_BDF    sBdf,
+                                                                  const GMM_CLIENT ClientType)
 #endif
 {
     __GMM_ASSERTPTR(_pSkuTable, GMM_ERROR);
@@ -284,7 +286,7 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmMultiAdapterContext::AddContext(const PLATFORM
 
     pGmmLibContext->IncrementRefCount();
 
-    Status = (pGmmLibContext->InitContext(Platform, pSkuTable, pWaTable, pSysInfo, GMM_KMD_VISTA));
+    Status = (pGmmLibContext->InitContext(Platform, pSkuTable, pWaTable, pSysInfo, ClientType));
     if (Status != GMM_SUCCESS)
     {
         //clean everything and return error
@@ -1005,6 +1007,10 @@ GMM_CLIENT               ClientType)
     this->GtSysInfo = *pGtSysInfo;
     
     this->pPlatformInfo = CreatePlatformInfo(Platform, false);
+    if(this->pPlatformInfo == NULL)
+    {
+        return GMM_ERROR;
+    }
 
     OverrideSkuWa();
 
@@ -1062,6 +1068,12 @@ void GMM_STDCALL GmmLib::Context::OverrideSkuWa()
     {
         SkuTable.Ftr57bGPUAddressing = true;
     }
+
+    if (GFX_GET_CURRENT_PRODUCT(this->GetPlatformInfo().Platform) >= IGFX_BMG)
+    {
+        // FtrL3TransientDataFlush is always enabled for XE2 adding GMM Override if UMDs might have reset this.
+        SkuTable.FtrL3TransientDataFlush = true;
+    }
 }
 
 GMM_CACHE_POLICY *GMM_STDCALL GmmLib::Context::CreateCachePolicyCommon()
@@ -1069,13 +1081,18 @@ GMM_CACHE_POLICY *GMM_STDCALL GmmLib::Context::CreateCachePolicyCommon()
     GMM_CACHE_POLICY *        pGmmCachePolicy = NULL;
     GMM_CACHE_POLICY_ELEMENT *CachePolicy     = NULL;
     CachePolicy                               = GetCachePolicyUsage();
+    PRODUCT_FAMILY ProductFamily              = GFX_GET_CURRENT_PRODUCT(GetPlatformInfo().Platform);
 
     if(GetCachePolicyObj())
     {
         return GetCachePolicyObj();
     }
-
-    if((GFX_GET_CURRENT_PRODUCT(GetPlatformInfo().Platform) == IGFX_METEORLAKE) || (GFX_GET_CURRENT_PRODUCT(GetPlatformInfo().Platform) == IGFX_ARROWLAKE))
+	
+    if(ProductFamily >= IGFX_BMG)
+    {
+        pGmmCachePolicy = new GmmLib::GmmXe2_LPGCachePolicy(CachePolicy, this);
+    }
+    else if((ProductFamily == IGFX_METEORLAKE) || (ProductFamily == IGFX_ARROWLAKE))
     {
         pGmmCachePolicy = new GmmLib::GmmXe_LPGCachePolicy(CachePolicy, this);
     }
@@ -1083,6 +1100,9 @@ GMM_CACHE_POLICY *GMM_STDCALL GmmLib::Context::CreateCachePolicyCommon()
     {
         switch(GFX_GET_CURRENT_RENDERCORE(this->GetPlatformInfo().Platform))
         {
+            case IGFX_XE2_HPG_CORE:
+                pGmmCachePolicy = new GmmLib::GmmXe2_LPGCachePolicy(CachePolicy, this);
+                break;
             case IGFX_GEN12LP_CORE:
             case IGFX_GEN12_CORE:
             case IGFX_XE_HP_CORE:
@@ -1158,8 +1178,11 @@ GMM_TEXTURE_CALC *GMM_STDCALL GmmLib::Context::CreateTextureCalc(PLATFORM Platfo
             case IGFX_XE_HP_CORE:
             case IGFX_XE_HPG_CORE:
             case IGFX_XE_HPC_CORE:
+                 return new GmmGen12TextureCalc(this);
+				 break;
+            case IGFX_XE2_HPG_CORE:
             default:
-                return new GmmGen12TextureCalc(this);
+                return new GmmXe_LPGTextureCalc(this);
                 break;
         }
     }
@@ -1169,6 +1192,8 @@ GMM_PLATFORM_INFO_CLASS *GMM_STDCALL GmmLib::Context::CreatePlatformInfo(PLATFOR
 {
     GMM_DPF_ENTER;
 
+    PRODUCT_FAMILY ProductFamily = GFX_GET_CURRENT_PRODUCT(Platform);
+
     if(Override == false)
     {
         if(pPlatformInfo != NULL)
@@ -1176,13 +1201,21 @@ GMM_PLATFORM_INFO_CLASS *GMM_STDCALL GmmLib::Context::CreatePlatformInfo(PLATFOR
             return pPlatformInfo;
         }
     }
-   switch(GFX_GET_CURRENT_RENDERCORE(Platform))
+
+    if (ProductFamily >= IGFX_LUNARLAKE)
     {
+        return new GmmLib::PlatformInfoGen12(Platform, (GMM_LIB_CONTEXT *)this);
+    }
+    else
+    {
+        switch (GFX_GET_CURRENT_RENDERCORE(Platform))
+        {
         case IGFX_GEN12LP_CORE:
         case IGFX_GEN12_CORE:
         case IGFX_XE_HP_CORE:
         case IGFX_XE_HPG_CORE:
         case IGFX_XE_HPC_CORE:
+        case IGFX_XE2_HPG_CORE:
             return new GmmLib::PlatformInfoGen12(Platform, (GMM_LIB_CONTEXT *)this);
             break;
         case IGFX_GEN11_CORE:
@@ -1197,7 +1230,8 @@ GMM_PLATFORM_INFO_CLASS *GMM_STDCALL GmmLib::Context::CreatePlatformInfo(PLATFOR
         default:
             return new GmmLib::PlatformInfoGen8(Platform, (GMM_LIB_CONTEXT *)this);
             break;
-    }
+        }
+    }    
 }
 
 //C - Wrappers
diff --git a/Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp b/Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp
index 117a5d8..11cb89a 100755
--- a/Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp
+++ b/Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp
@@ -55,7 +55,7 @@ extern "C" GMM_LIB_API GMM_STATUS GMM_STDCALL InitializeGmm(GMM_INIT_IN_ARGS *pI
 #endif
 
         Status = GmmCreateLibContext(pInArgs->Platform, pInArgs->pSkuTable, pInArgs->pWaTable, 
-			                                   pInArgs->pGtSysInfo, stAdapterBDF);
+                                     pInArgs->pGtSysInfo, stAdapterBDF, pInArgs->ClientType);
 
         if(Status == GMM_SUCCESS)
         {
diff --git a/Source/GmmLib/Platform/GmmGen12Platform.cpp b/Source/GmmLib/Platform/GmmGen12Platform.cpp
index e872369..4368c0a 100644
--- a/Source/GmmLib/Platform/GmmGen12Platform.cpp
+++ b/Source/GmmLib/Platform/GmmGen12Platform.cpp
@@ -151,7 +151,15 @@ GmmLib::PlatformInfoGen12::PlatformInfoGen12(PLATFORM &Platform, Context *pGmmLi
     SET_TILE_MODE_INFO(TILE__64_2D_8bpe,          256,      256,        1,       128,       256,         1)
 
     // TILE__64 2D 2X
-    SET_TILE_MODE_INFO(TILE__64_2D_2X_128bpe,     512,       64,        1,        32,        32,         1)
+    if(pGmmLibContext->GetSkuTable().FtrXe2PlusTiling)
+    {
+        SET_TILE_MODE_INFO(TILE__64_2D_2X_128bpe,     1024,      32,        1,        32,        32,         1) 
+    }
+    else
+    {
+        SET_TILE_MODE_INFO(TILE__64_2D_2X_128bpe,     512,       64,        1,        32,        32,         1) 
+    }
+
     SET_TILE_MODE_INFO(TILE__64_2D_2X_64bpe,      512,       64,        1,        64,        32,         1)
     SET_TILE_MODE_INFO(TILE__64_2D_2X_32bpe,      256,      128,        1,        64,        64,         1)
     SET_TILE_MODE_INFO(TILE__64_2D_2X_16bpe,      256,      128,        1,       128,        64,         1)
@@ -164,6 +172,20 @@ GmmLib::PlatformInfoGen12::PlatformInfoGen12(PLATFORM &Platform, Context *pGmmLi
     SET_TILE_MODE_INFO(TILE__64_2D_4X_16bpe,      256,       64,        1,        64,        64,         1)
     SET_TILE_MODE_INFO(TILE__64_2D_4X_8bpe,       128,      128,        1,        64,       128,         1)
 
+    // TILE__64 2D 8X
+    SET_TILE_MODE_INFO(TILE__64_2D_8X_128bpe,     256,       32,        1,        8,         32,         1)
+    SET_TILE_MODE_INFO(TILE__64_2D_8X_64bpe,      256,       32,        1,        16,        32,         1)
+    SET_TILE_MODE_INFO(TILE__64_2D_8X_32bpe,      256,       32,        1,        16,        64,         1)
+    SET_TILE_MODE_INFO(TILE__64_2D_8X_16bpe,      128,       64,        1,        32,        64,         1)
+    SET_TILE_MODE_INFO(TILE__64_2D_8X_8bpe,       128,       64,        1,        32,       128,         1)
+
+    // TILE__64 2D 16X
+    SET_TILE_MODE_INFO(TILE__64_2D_16X_128bpe,     256,       16,        1,        8,         16,         1)
+    SET_TILE_MODE_INFO(TILE__64_2D_16X_64bpe,      128,       32,        1,        16,        16,         1)
+    SET_TILE_MODE_INFO(TILE__64_2D_16X_32bpe,      128,       32,        1,        16,        32,         1)
+    SET_TILE_MODE_INFO(TILE__64_2D_16X_16bpe,      128,       32,        1,        32,        32,         1)
+    SET_TILE_MODE_INFO(TILE__64_2D_16X_8bpe,        64,       64,        1,        32,        64,         1)
+
     // TILE__64 3D
     SET_TILE_MODE_INFO(TILE__64_3D_128bpe,        256,       16,       16,         8,        16,         16)
     SET_TILE_MODE_INFO(TILE__64_3D_64bpe,         256,       16,       16,        16,        16,         16)
@@ -260,52 +282,89 @@ CCSRTALIGN(TILE_YS_2D_16X_128bpe,  16,     16,      4,          1,         4 );
 #undef CCSRTALIGN
 // clang-format on
 
-#define FCRECTALIGN(TileMode, bpp, HAlign, VAlign, HDownscale, VDownscale) \
-    {                                                                      \
-        FCTileMode[FCMode(TileMode, bpp)].Align.Width      = HAlign;       \
-        FCTileMode[FCMode(TileMode, bpp)].Align.Height     = VAlign;       \
-        FCTileMode[FCMode(TileMode, bpp)].Align.Depth      = 1;            \
-        FCTileMode[FCMode(TileMode, bpp)].Downscale.Width  = HDownscale;   \
-        FCTileMode[FCMode(TileMode, bpp)].Downscale.Height = VDownscale;   \
-        FCTileMode[FCMode(TileMode, bpp)].Downscale.Depth  = 1;            \
+#define FCRECTALIGN(TileMode, bpp, HAlign, VAlign, DAlign, HDownscale, VDownscale) \
+    {                                                                              \
+        FCTileMode[FCMode(TileMode, bpp)].Align.Width      = HAlign;               \
+        FCTileMode[FCMode(TileMode, bpp)].Align.Height     = VAlign;               \
+        FCTileMode[FCMode(TileMode, bpp)].Align.Depth      = DAlign;               \
+        FCTileMode[FCMode(TileMode, bpp)].Downscale.Width  = HDownscale;           \
+        FCTileMode[FCMode(TileMode, bpp)].Downscale.Height = VDownscale;           \
+        FCTileMode[FCMode(TileMode, bpp)].Downscale.Depth  = 1;                    \
     }
 
     // clang-format off
-FCRECTALIGN(LEGACY_TILE_Y    ,   8, 512,  32, 256, 16);
-FCRECTALIGN(LEGACY_TILE_Y    ,  16, 256,  32, 128, 16);
-FCRECTALIGN(LEGACY_TILE_Y    ,  32, 128,  32,  64, 16);
-FCRECTALIGN(LEGACY_TILE_Y    ,  64,  64,  32,  32, 16);
-FCRECTALIGN(LEGACY_TILE_Y    , 128,  32,  32,  16, 16);
-
-FCRECTALIGN(TILE_YF_2D_8bpe  ,   8, 256,  64, 128, 32);
-FCRECTALIGN(TILE_YF_2D_16bpe ,  16, 256,  32, 128, 16);
-FCRECTALIGN(TILE_YF_2D_32bpe ,  32, 128,  32,  64, 16);
-FCRECTALIGN(TILE_YF_2D_64bpe ,  64, 128,  16,  64,  8);
-FCRECTALIGN(TILE_YF_2D_128bpe, 128,  64,  16,  32,  8);
-
-FCRECTALIGN(TILE_YS_2D_8bpe  ,   8, 128, 128,  64, 64);
-FCRECTALIGN(TILE_YS_2D_16bpe ,  16, 128,  64,  64, 32);
-FCRECTALIGN(TILE_YS_2D_32bpe ,  32,  64,  64,  32, 32);
-FCRECTALIGN(TILE_YS_2D_64bpe ,  64,  64,  32,  32, 16);
-FCRECTALIGN(TILE_YS_2D_128bpe, 128,  32,  32,  16, 16);
-
-FCRECTALIGN(TILE4           ,   8, 1024, 16, 1024, 16);
-FCRECTALIGN(TILE4           ,  16,  512, 16,  512, 16);
-FCRECTALIGN(TILE4           ,  32,  256,  16, 256, 16);
-FCRECTALIGN(TILE4           ,  64,  128,  16, 128, 16);
-FCRECTALIGN(TILE4           , 128,   64,  16,  64, 16);
-
-FCRECTALIGN(TILE__64_2D_8bpe  ,   8, 128, 128,  128, 128);
-FCRECTALIGN(TILE__64_2D_16bpe ,  16, 128,  64,  128, 64);
-FCRECTALIGN(TILE__64_2D_32bpe ,  32,  64,  64,   64, 64);
-FCRECTALIGN(TILE__64_2D_64bpe ,  64,  64,  32,   64, 32);
-FCRECTALIGN(TILE__64_2D_128bpe, 128,  32,  32,   32, 32);
+FCRECTALIGN(LEGACY_TILE_Y    ,   8, 512,  32, 1,  256, 16);
+FCRECTALIGN(LEGACY_TILE_Y    ,  16, 256,  32, 1, 128, 16);
+FCRECTALIGN(LEGACY_TILE_Y    ,  32, 128,  32, 1,  64, 16);
+FCRECTALIGN(LEGACY_TILE_Y    ,  64,  64,  32, 1, 32, 16);
+FCRECTALIGN(LEGACY_TILE_Y    , 128,  32,  32, 1, 16, 16);
+
+FCRECTALIGN(TILE_YF_2D_8bpe  ,   8, 256,  64, 1, 128, 32);
+FCRECTALIGN(TILE_YF_2D_16bpe ,  16, 256,  32, 1, 128, 16);
+FCRECTALIGN(TILE_YF_2D_32bpe ,  32, 128,  32, 1,  64, 16);
+FCRECTALIGN(TILE_YF_2D_64bpe ,  64, 128,  16, 1,  64,  8);
+FCRECTALIGN(TILE_YF_2D_128bpe, 128,  64,  16, 1,  32,  8);
+
+FCRECTALIGN(TILE_YS_2D_8bpe  ,   8, 128, 128,  1, 64, 64);
+FCRECTALIGN(TILE_YS_2D_16bpe ,  16, 128,  64,  1, 64, 32);
+FCRECTALIGN(TILE_YS_2D_32bpe ,  32,  64,  64,  1, 32, 32);
+FCRECTALIGN(TILE_YS_2D_64bpe ,  64,  64,  32,  1, 32, 16);
+FCRECTALIGN(TILE_YS_2D_128bpe, 128,  32,  32,  1, 16, 16);
+
+if(pGmmLibContext->GetSkuTable().FtrXe2Compression)
+{   
+
+    FCRECTALIGN(TILE4           ,   8, 64, 4, 1, 64, 4);
+    FCRECTALIGN(TILE4           ,  16, 32, 4, 1, 32, 4);
+    FCRECTALIGN(TILE4           ,  32, 16, 4, 1, 16, 4);
+    FCRECTALIGN(TILE4           ,  64, 8,  4, 1, 8, 4);
+    FCRECTALIGN(TILE4           , 128, 4,  4, 1, 4, 4);
+
+    FCRECTALIGN(TILE__64_2D_8bpe  ,   8, 64, 4, 1, 64, 4);
+    FCRECTALIGN(TILE__64_2D_16bpe ,  16, 32, 4, 1, 32, 4);
+    FCRECTALIGN(TILE__64_2D_32bpe ,  32, 16, 4, 1, 16, 4);
+    FCRECTALIGN(TILE__64_2D_64bpe ,  64,  8, 4, 1, 8,  4);
+    FCRECTALIGN(TILE__64_2D_128bpe, 128,  4, 4, 1, 4,  4);
+
+    FCRECTALIGN(TILE__64_3D_8bpe  ,   8,  64,  32, 32,  4, 8);
+    FCRECTALIGN(TILE__64_3D_16bpe ,  16,  32,  32, 32,  8, 4);
+    FCRECTALIGN(TILE__64_3D_32bpe ,  32,  32,  32, 16,  4, 4);
+    FCRECTALIGN(TILE__64_3D_64bpe ,  64,  32,  16, 16,  4, 4);
+    FCRECTALIGN(TILE__64_3D_128bpe, 128,  16,  16, 16,  4, 4);
+}
+else
+{
+    FCRECTALIGN(TILE4           ,   8, 1024, 16,  1, 1024, 16);
+    FCRECTALIGN(TILE4           ,  16,  512, 16,  1, 512, 16);
+    FCRECTALIGN(TILE4           ,  32,  256,  16, 1,  256, 16);
+    FCRECTALIGN(TILE4           ,  64,  128,  16, 1, 128, 16);
+    FCRECTALIGN(TILE4           , 128,   64,  16, 1,  64, 16);
+
+    FCRECTALIGN(TILE__64_2D_8bpe  ,   8, 128, 128, 1,  128, 128);
+    FCRECTALIGN(TILE__64_2D_16bpe ,  16, 128,  64, 1,  128, 64);
+    FCRECTALIGN(TILE__64_2D_32bpe ,  32,  64,  64, 1,   64, 64);
+    FCRECTALIGN(TILE__64_2D_64bpe ,  64,  64,  32, 1,  64, 32);
+    FCRECTALIGN(TILE__64_2D_128bpe, 128,  32,  32, 1,  32, 32);
+
+    FCRECTALIGN(TILE__64_3D_8bpe  ,   8,  1,  1, 1,  1, 1);
+    FCRECTALIGN(TILE__64_3D_16bpe ,  16,  1,  1, 1,  1, 1);
+    FCRECTALIGN(TILE__64_3D_32bpe ,  32,  1,  1, 1,  1, 1);
+    FCRECTALIGN(TILE__64_3D_64bpe ,  64,  1,  1, 1,  1, 1);
+    FCRECTALIGN(TILE__64_3D_128bpe, 128,  1,  1, 1,  1, 1);
+
+    
+}
 #undef FCRECTALIGN
 
     // clang-format on
     Data.NoOfBitsSupported                = 39;
     Data.HighestAcceptablePhysicalAddress = GFX_MASK_LARGE(0, 38);
-
+	
+    if (GFX_GET_CURRENT_PRODUCT(Data.Platform) >= IGFX_BMG)
+    {
+        Data.NoOfBitsSupported                = 52;
+        Data.HighestAcceptablePhysicalAddress = GFX_MASK_LARGE(0, 51);
+    }
     if(GFX_GET_CURRENT_PRODUCT(Data.Platform) == IGFX_PVC)
     {
         Data.NoOfBitsSupported                = 52;
@@ -372,21 +431,30 @@ uint8_t GmmLib::PlatformInfoGen12::ValidateMMC(GMM_TEXTURE_INFO &Surf)
 uint8_t GmmLib::PlatformInfoGen12::ValidateCCS(GMM_TEXTURE_INFO &Surf)
 {
 
-    if(!(                                                                          //--- Legitimate CCS Case ----------------------------------------
-       ((Surf.Type >= RESOURCE_2D && Surf.Type <= RESOURCE_BUFFER) &&              ////Not supported: 1D; Supported: Buffer, 2D, 3D, cube, Arrays, mip-maps, MSAA, Depth/Stencil
-        (!(Surf.Flags.Info.RenderCompressed || Surf.Flags.Info.MediaCompressed) || //Not compressed surface eg separate Aux Surf
-         (GMM_IS_4KB_TILE(Surf.Flags) || GMM_IS_64KB_TILE(Surf.Flags)) ||          //Only on Y/Ys
-         (Surf.Flags.Info.Linear && Surf.Type == RESOURCE_BUFFER &&                //Machine-Learning compression on untyped linear buffer
-          Surf.Flags.Info.RenderCompressed)))))
+    if (!(                                    //--- Legitimate CCS Case ----------------------------------------
+        ((Surf.Flags.Gpu.ProceduralTexture || //procedural texture, or compressed surface (no more separate Aux-CCS)
+          Surf.Flags.Info.RenderCompressed || Surf.Flags.Info.MediaCompressed) ||
+         pGmmLibContext->GetSkuTable().FtrXe2Compression && !Surf.Flags.Info.NotCompressed) &&
+        (((Surf.Type >= RESOURCE_2D && Surf.Type <= RESOURCE_CUBE) &&       //Not supported: 1D (until Flat CCS); Others Supported: Buffer, 2D, 3D, cube, Arrays, mip-maps, MSAA, Depth/Stencil
+          (GMM_IS_4KB_TILE(Surf.Flags) || GMM_IS_64KB_TILE(Surf.Flags))) || //Only on 2D + Y/Ys or Lienar buffer (until Flat CCS)
+         (Surf.Flags.Info.Linear && Surf.Type == RESOURCE_BUFFER) ||
+         ((pGmmLibContext->GetSkuTable().FtrFlatPhysCCS) && !Surf.Flags.Info.TiledX))))
     {
         GMM_ASSERTDPF(0, "Invalid CCS usage!");
         return 0;
     }
 
+    if (!pGmmLibContext->GetSkuTable().FtrFlatPhysCCS &&
+        Surf.Flags.Info.Linear && Surf.Type == RESOURCE_BUFFER && !Surf.Flags.Info.RenderCompressed)
+    {
+        GMM_ASSERTDPF(0, "Invalid CCS usage - MLC only supported as RC!");
+        return 0;
+    }
+
     //Compressed resource (main surf) must pre-define MC/RC type
     if(!(Surf.Flags.Gpu.__NonMsaaTileYCcs || Surf.Flags.Gpu.__NonMsaaLinearCCS) &&
        !Surf.Flags.Gpu.ProceduralTexture &&
-       !(Surf.Flags.Info.RenderCompressed || Surf.Flags.Info.MediaCompressed))
+        !(Surf.Flags.Info.RenderCompressed || Surf.Flags.Info.MediaCompressed || !Surf.Flags.Info.NotCompressed))
     {
         GMM_ASSERTDPF(0, "Invalid CCS usage - RC/MC type unspecified!");
         return 0;
@@ -456,7 +524,7 @@ uint8_t GmmLib::PlatformInfoGen12::CheckFmtDisplayDecompressible(GMM_TEXTURE_INF
 {
 
     //Check fmt is display decompressible
-    if(((Surf.Flags.Info.RenderCompressed || Surf.Flags.Info.MediaCompressed) &&
+    if (((Surf.Flags.Info.RenderCompressed || Surf.Flags.Info.MediaCompressed || !Surf.Flags.Info.NotCompressed) &&
         (IsSupportedRGB64_16_16_16_16 ||                             //RGB64 16:16 : 16 : 16 FP16
          IsSupportedRGB32_8_8_8_8 ||                                 //RGB32 8 : 8 : 8 : 8
          IsSupportedRGB32_2_10_10_10)) ||                            //RGB32 2 : 10 : 10 : 10) ||
@@ -489,7 +557,16 @@ uint8_t GmmLib::PlatformInfoGen12::OverrideCompressionFormat(GMM_RESOURCE_FORMAT
 {
 
     uint8_t CompressionFormat = Data.FormatTable[Format].CompressionFormat.CompressionFormat;
-    if(pGmmLibContext->GetSkuTable().FtrFlatPhysCCS || pGmmLibContext->GetSkuTable().FtrUnified3DMediaCompressionFormats)
+    if (pGmmLibContext->GetSkuTable().FtrXe2Compression)
+    {
+        if ((CompressionFormat < GMM_XE2_UNIFIED_COMP_MIN_FORMAT) ||
+            (CompressionFormat > GMM_XE2_UNIFIED_COMP_MAX_FORMAT))
+        {
+            CompressionFormat = GMM_XE2_UNIFIED_COMP_FORMAT_INVALID;
+        }
+        __GMM_ASSERT(CompressionFormat != GMM_XE2_UNIFIED_COMP_FORMAT_INVALID);
+    }
+    else if (pGmmLibContext->GetSkuTable().FtrFlatPhysCCS || pGmmLibContext->GetSkuTable().FtrUnified3DMediaCompressionFormats)
     {
         if(!IsMC &&
            !pGmmLibContext->GetSkuTable().FtrUnified3DMediaCompressionFormats &&
diff --git a/Source/GmmLib/Platform/GmmPlatform.cpp b/Source/GmmLib/Platform/GmmPlatform.cpp
index 10e4404..bf23bb2 100644
--- a/Source/GmmLib/Platform/GmmPlatform.cpp
+++ b/Source/GmmLib/Platform/GmmPlatform.cpp
@@ -69,6 +69,7 @@ void GmmLib::PlatformInfo::SetCCSFlag(GMM_RESOURCE_FLAG &Flags)
         Flags.Gpu.CCS = Flags.Gpu.MCS;
     }
     Flags.Info.RenderCompressed = Flags.Info.MediaCompressed = 0;
+    Flags.Info.NotCompressed                                 = 1;
 }
 
 /////////////////////////////////////////////////////////////////////////////////////
diff --git a/Source/GmmLib/Resource/GmmResourceInfo.cpp b/Source/GmmLib/Resource/GmmResourceInfo.cpp
index be0998f..5165862 100644
--- a/Source/GmmLib/Resource/GmmResourceInfo.cpp
+++ b/Source/GmmLib/Resource/GmmResourceInfo.cpp
@@ -1134,6 +1134,25 @@ GMM_SURFACESTATE_FORMAT GMM_STDCALL GmmGetSurfaceStateFormat(GMM_RESOURCE_FORMAT
            GMM_SURFACESTATE_FORMAT_INVALID;
 }
 
+
+//=============================================================================
+//
+// Function: GmmGetCompressionFormat
+//
+// Desc: See below.
+//
+// Returns:
+//      CompressionFormat.CompressionFormat
+//
+//-----------------------------------------------------------------------------
+uint8_t GMM_STDCALL GmmGetCompressionFormat(GMM_RESOURCE_FORMAT Format, GMM_LIB_CONTEXT *pGmmLibContext)
+{
+    return (((Format > GMM_FORMAT_INVALID) &&
+             (Format < GMM_RESOURCE_FORMATS)) ?
+            pGmmLibContext->GetPlatformInfo().FormatTable[Format].CompressionFormat.CompressionFormat :
+            GMM_UNIFIED_CMF_INVALID);
+}
+
 /////////////////////////////////////////////////////////////////////////////////////
 /// C wrapper for GmmResourceInfoCommon::GetHAlignSurfaceState
 /// @see    GmmLib::GmmResourceInfoCommon::GetHAlignSurfaceState()
@@ -1698,6 +1717,17 @@ void GMM_STDCALL GmmResSetLibContext(GMM_RESOURCE_INFO *pGmmResource, void *pLib
     }
 }
 
+/////////////////////////////////////////////////////////////////////////////////////
+/// C wrapper for GmmResourceInfoCommon::IsResourceMappedCompressible
+/// @see    GmmLib::GmmResourceInfoCommon::IsResourceMappedCompressible()
+///
+/// @param[in]  pGmmResource: Pointer to GmmResourceInfo class
+/////////////////////////////////////////////////////////////////////////////////////
+uint32_t GMM_STDCALL GmmResIsMappedCompressible(GMM_RESOURCE_INFO *pGmmResource)
+{
+    return pGmmResource->IsResourceMappedCompressible();
+}
+
 //=============================================================================
 //
 // Function: __CanSupportStdTiling
diff --git a/Source/GmmLib/Resource/GmmResourceInfoCommon.cpp b/Source/GmmLib/Resource/GmmResourceInfoCommon.cpp
index acc279e..b1e428f 100644
--- a/Source/GmmLib/Resource/GmmResourceInfoCommon.cpp
+++ b/Source/GmmLib/Resource/GmmResourceInfoCommon.cpp
@@ -54,9 +54,9 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::Is64KBPageSuitable()
 
     if(GetGmmLibContext()->GetSkuTable().FtrLocalMemory)
      {
-        Ignore64KBPadding |= (Surf.Flags.Info.NonLocalOnly || (Surf.Flags.Info.Shared && !Surf.Flags.Info.NotLockable));
+        Ignore64KBPadding |= (Surf.Flags.Info.Shared && !Surf.Flags.Info.NotLockable);
         Ignore64KBPadding |= ((GetGmmLibContext()->GetSkuTable().FtrLocalMemoryAllows4KB) && Surf.Flags.Info.NoOptimizationPadding);
-	Ignore64KBPadding |= ((GetGmmLibContext()->GetSkuTable().FtrLocalMemoryAllows4KB) && (((Size * (100 + (GMM_GFX_SIZE_T)GetGmmLibContext()->GetAllowedPaddingFor64KbPagesPercentage())) / 100) < GFX_ALIGN(Size, GMM_KBYTE(64)))); 
+        Ignore64KBPadding |= ((GetGmmLibContext()->GetSkuTable().FtrLocalMemoryAllows4KB || Surf.Flags.Info.NonLocalOnly) && (((Size * (100 + (GMM_GFX_SIZE_T)GetGmmLibContext()->GetAllowedPaddingFor64KbPagesPercentage())) / 100) < GFX_ALIGN(Size, GMM_KBYTE(64))));
     }
     else
     {
@@ -447,6 +447,13 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmResourceInfoCommon::Create(Context &GmmLibCont
     pPlatform    = GMM_OVERRIDE_PLATFORM_INFO(&Surf, GetGmmLibContext());
     pTextureCalc = GMM_OVERRIDE_TEXTURE_CALC(&Surf, GetGmmLibContext());
 
+    if (!pTextureCalc)
+    {
+        Status = GMM_ERROR;
+        GMM_ASSERTDPF(0, "Texture Calculation pointer is NULL.");
+        goto ERROR_CASE;
+    }
+
 #if defined(__GMM_KMD__) || !defined(_WIN32)
     if(!CreateParams.Flags.Info.ExistingSysMem)
 #else
@@ -493,21 +500,47 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmResourceInfoCommon::Create(Context &GmmLibCont
                 if(GetGmmLibContext()->GetSkuTable().FtrFlatPhysCCS && AuxSurf.Type == RESOURCE_INVALID)
                 {
                     //ie only AuxType is CCS, doesn't exist with FlatCCS, enable it for CC
-                    AuxSurf.Type = Surf.Type;
+                    if (!GetGmmLibContext()->GetSkuTable().FtrXe2Compression || (GetGmmLibContext()->GetSkuTable().FtrXe2Compression && (Surf.MSAA.NumSamples > 1)))
+                    {
+                        AuxSurf.Type = Surf.Type;
+                    }
                 }
-                if(!Surf.Flags.Gpu.TiledResource)
+                if (!Surf.Flags.Gpu.TiledResource)
                 {
-                    AuxSurf.CCSize = PAGE_SIZE; // 128bit Float Value + 32bit RT Native Value + Padding.
-                    AuxSurf.Size += PAGE_SIZE;
+                    if (!GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+                    {
+                        AuxSurf.CCSize = PAGE_SIZE; // 128bit Float Value + 32bit RT Native Value + Padding.
+                        AuxSurf.Size += PAGE_SIZE;
+                    }
+                    else
+                    {
+
+                        if (Surf.MSAA.NumSamples > 1)
+                        {
+                            AuxSurf.UnpaddedSize += PAGE_SIZE;
+                            AuxSurf.Size += PAGE_SIZE;              // Clear Color stored only for MSAA surfaces
+                        }
+                    }
                 }
                 else
                 {
-                    AuxSurf.CCSize = GMM_KBYTE(64); // 128bit Float Value + 32bit RT Native Value + Padding.
-                    AuxSurf.Size += GMM_KBYTE(64);
+                    if (!GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+                    {
+                        AuxSurf.CCSize = GMM_KBYTE(64); // 128bit Float Value + 32bit RT Native Value + Padding.
+                        AuxSurf.Size += GMM_KBYTE(64);
+                    }
+                    else
+                    {
+                        if (Surf.MSAA.NumSamples > 1)
+                        {
+                            AuxSurf.UnpaddedSize += GMM_KBYTE(64);
+                            AuxSurf.Size += GMM_KBYTE(64);              // Clear Color stored only for MSAA surfaces, stored as part of MCS
+                        }
+                    }
                 }
             }
-	    
-	    if(Surf.Flags.Gpu.ProceduralTexture)
+				    
+  	    if(Surf.Flags.Gpu.ProceduralTexture)
             {
                 //Do not require main surface access either in GPUVA/physical space.
                 Surf.Size = 0;
@@ -520,7 +553,7 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmResourceInfoCommon::Create(Context &GmmLibCont
             // ensure the entire surface can be described with a constant pitch (for GGTT aliasing, clean FENCE'ing and
             // AcquireSwizzlingRange, even though the aux isn't intentionally part of such fencing).
             if(Surf.Flags.Gpu.FlipChain &&
-               !__GMM_IS_ALIGN(TotalSize, Alignment))
+               (!__GMM_IS_ALIGN(TotalSize, Alignment)))
             {
                 AuxSurf.Size += (GFX_ALIGN_NP2(TotalSize, Alignment) - TotalSize);
             }
@@ -869,15 +902,36 @@ uint64_t GmmLib::GmmResourceInfoCommon::GetFastClearWidth(uint32_t MipLevel)
     }
     else if(numSamples == 2 || numSamples == 4)
     {
-        width = GFX_ALIGN(mipWidth, 8) / 8;
+        if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+        {
+            width = GFX_ALIGN(mipWidth, 64) / 64;
+        }
+        else
+        {
+            width = GFX_ALIGN(mipWidth, 8) / 8;
+        }
     }
     else if(numSamples == 8)
     {
-        width = GFX_ALIGN(mipWidth, 2) / 2;
+        if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+        {
+            width = GFX_ALIGN(mipWidth, 16) / 16;
+        }
+        else
+        {
+            width = GFX_ALIGN(mipWidth, 2) / 2;
+        }
     }
     else // numSamples == 16
     {
-        width = mipWidth;
+        if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+        {
+            width = GFX_ALIGN(mipWidth, 8) / 8;
+        }
+        else
+        {
+            width = mipWidth;
+        }
     }
 
     return width;
@@ -904,12 +958,49 @@ uint32_t GmmLib::GmmResourceInfoCommon::GetFastClearHeight(uint32_t MipLevel)
     }
     else
     {
-        height = GFX_ALIGN(mipHeight, 2) / 2;
+        if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+        {
+            height = GFX_ALIGN(mipHeight, 4) / 4;
+        }
+        else
+        {
+            height = GFX_ALIGN(mipHeight, 2) / 2;
+        }
     }
 
     return height;
 }
 
+
+/////////////////////////////////////////////////////////////////////////////////////
+/// Returns 2D Surface width to be used for fast clear for a given 3D surface
+/// @param[in]  uint32_t : MipLevel
+/// @return     height
+/////////////////////////////////////////////////////////////////////////////////////
+uint64_t GmmLib::GmmResourceInfoCommon::Get2DFastClearSurfaceWidthFor3DSurface(uint32_t MipLevel)
+{
+    uint64_t width    = 0;
+    uint64_t mipWidth = GetMipWidth(MipLevel);
+
+    GMM_TEXTURE_CALC *pTextureCalc;
+    pTextureCalc = GMM_OVERRIDE_TEXTURE_CALC(&Surf, GetGmmLibContext());
+    width        = pTextureCalc->Get2DFCSurfaceWidthFor3DSurface(&Surf, mipWidth);
+    return width;
+}
+
+
+uint64_t GmmLib::GmmResourceInfoCommon::Get2DFastClearSurfaceHeightFor3DSurface(uint32_t MipLevel)
+{
+    uint64_t          height    = 0;
+    uint32_t          mipHeight = GetMipHeight(MipLevel);
+    uint32_t          mipDepth  = GetMipDepth(MipLevel);
+    GMM_TEXTURE_CALC *pTextureCalc;
+
+    pTextureCalc = GMM_OVERRIDE_TEXTURE_CALC(&Surf, GetGmmLibContext());
+    height       = pTextureCalc->Get2DFCSurfaceHeightFor3DSurface(&Surf, mipHeight, mipDepth);
+    return height;
+}
+
 /////////////////////////////////////////////////////////////////////////////////////
 /// Returns the Platform info.  If Platform has been overriden by the clients, then
 /// it returns the overriden Platform Info struct.
@@ -1655,21 +1746,53 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::CpuBlt(GMM_RES_COPY_BLT *pBlt
                     switch(pTexInfo->MSAA.NumSamples)           \
                     {                                           \
                         case 0:                                 \
-                            SWITCH_BPP(Layout, Tile,  , xD);    \
+                            SWITCH_BPP(Layout, TILE_64, , xD);    \
                             break;                              \
                         case 1:                                 \
-                            SWITCH_BPP(Layout, Tile,  , xD);    \
+                            SWITCH_BPP(Layout, TILE_64, , xD);    \
                             break;                              \
                         case 2:                                 \
-                            SWITCH_BPP(Layout, Tile, MSAA2_, xD);  \
+                            if(GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)\
+                            { \
+                                SWITCH_BPP(Layout, TILE_64_V2, MSAA2_, xD); \
+                            }\
+                            else\
+                            { \
+                                SWITCH_BPP(Layout, TILE_64, MSAA2_, xD); \
+                            } \
                             break;                              \
                         case 4:                                 \
+                            if(GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)\
+                            { \
+                                SWITCH_BPP(Layout, TILE_64_V2, MSAA4_, xD); \
+                            }\
+                            else\
+                            { \
+                                SWITCH_BPP(Layout, TILE_64, MSAA_, xD); \
+                            } \
+                            break; \
                         case 8:                                 \
+                            if(GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)\
+                            { \
+                                SWITCH_BPP(Layout, TILE_64_V2, MSAA8_, xD); \
+                            }\
+                            else\
+                            { \
+                                SWITCH_BPP(Layout, TILE_64, MSAA_, xD); \
+                            } \
+                            break; \
                         case 16:                                \
-                            SWITCH_BPP(Layout, Tile, MSAA_, xD);  \
-                            break;                              \
-                    }\
-                }
+                            if(GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)\
+                            { \
+                                SWITCH_BPP(Layout, TILE_64_V2, MSAA16_, xD); \
+                            }\
+                            else\
+                            { \
+                                SWITCH_BPP(Layout, TILE_64, MSAA_, xD); \
+                            } \
+                            break; \
+                    }                                           \
+                } \
 
                 #define SWITCH_MSAA(Layout, Tile, xD)           \
                 {\
@@ -1711,7 +1834,14 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::CpuBlt(GMM_RES_COPY_BLT *pBlt
                         }
                         else
                         {
-                            SWITCH_BPP(INTEL, TILE_64, , 3D_);
+                            if (GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)
+                            {
+                                SWITCH_BPP(INTEL, TILE_64_V2, , 3D_);
+                            }
+                            else
+                            {
+                                SWITCH_BPP(INTEL, TILE_64, , 3D_);
+                            }
                         }
                     }
                 }
@@ -1807,9 +1937,11 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::GetMappingSpanDesc(GMM_GET_MA
         {
             if(pMapping->Scratch.Plane == GMM_NO_PLANE)
             {
+                uint32_t ArrayIndex = pMapping->Scratch.Slice;
                 memset(pMapping, 0, sizeof(*pMapping));
                 pMapping->Type = GMM_MAPPING_YUVPLANAR;
 		pMapping->Scratch.Plane      = GMM_PLANE_Y;
+                pMapping->Scratch.Slice = ArrayIndex;
 
                 SpanPhysicalOffset = SpanVirtualOffset = 0;
                 if(GmmLib::Utility::GmmGetNumPlanes(Surf.Format) == GMM_PLANE_V)
@@ -1833,17 +1965,20 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::GetMappingSpanDesc(GMM_GET_MA
                 GMM_YUV_PLANE LastPlane = pMapping->Scratch.LastPlane;
                 SpanPhysicalOffset      = pMapping->__NextSpan.PhysicalOffset;
                 SpanVirtualOffset       = pMapping->__NextSpan.VirtualOffset;
+                uint32_t ArrayIndex     = pMapping->Scratch.Slice;
                 memset(pMapping, 0, sizeof(*pMapping));
 
                 pMapping->Type               = GMM_MAPPING_YUVPLANAR;
                 pMapping->Scratch.Plane      = GMM_YUV_PLANE(Plane);
                 pMapping->Scratch.LastPlane  = LastPlane;
+                pMapping->Scratch.Slice     = ArrayIndex;
             }
             {
                 if(pMapping->Scratch.Plane == GMM_PLANE_Y)
                 {
                     ReqInfo.ReqRender = ReqInfo.ReqLock = 1;
                     ReqInfo.Plane                       = GMM_YUV_PLANE(Plane);
+                    ReqInfo.ArrayIndex                  = pMapping->Scratch.Slice;
                     this->GetOffset(ReqInfo);
                     SpanPhysicalOffset = ReqInfo.Lock.Offset64;
                     SpanVirtualOffset  = ReqInfo.Render.Offset64;
@@ -1852,12 +1987,13 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::GetMappingSpanDesc(GMM_GET_MA
                 {
                     NextSpanReqInfo.ReqRender = NextSpanReqInfo.ReqLock = 1;
                     NextSpanReqInfo.Plane                               = GMM_YUV_PLANE(Plane + 1);
+                    NextSpanReqInfo.ArrayIndex                          = pMapping->Scratch.Slice;
                     this->GetOffset(NextSpanReqInfo);
                 }
                 else // last plane of that array
                 {
-                    NextSpanReqInfo.Lock.Offset64   = (GetSizeMainSurfacePhysical() / GFX_MAX(Surf.ArraySize, 1));
-                    NextSpanReqInfo.Render.Offset64 = (GetSizeMainSurface() / GFX_MAX(Surf.ArraySize, 1));
+                    NextSpanReqInfo.Lock.Offset64   = (GetSizeMainSurfacePhysical() / GFX_MAX(Surf.ArraySize, 1)) * (pMapping->Scratch.Slice + 1);
+                    NextSpanReqInfo.Render.Offset64 = (GetSizeMainSurface() / GFX_MAX(Surf.ArraySize, 1)) * (pMapping->Scratch.Slice + 1);
                     WasFinalSpan                    = 1;
                 }
             }
diff --git a/Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp b/Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp
index 825318a..e22154d 100644
--- a/Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp
+++ b/Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp
@@ -286,17 +286,32 @@ bool GmmLib::GmmResourceInfoCommon::CopyClientParams(GMM_RESCREATE_PARAMS &Creat
     // Memory optimization for 64KB tiled Surface.
     if (!GetGmmLibContext()->GetSkuTable().FtrTileY)
     {
-        if ((GetGmmLibContext()->GetWaTable().WaTile64Optimization || GetGmmLibContext()->GetSkuTable().FtrTile64Optimization) && Optimize64KBTile)
+        if ((GetGmmLibContext()->GetSkuTable().FtrTile64Optimization) && Optimize64KBTile)
         {
-            if (pTextureCalc->SurfaceRequires64KBTileOptimization(&Surf))
+            if ((GetGmmLibContext()->GetWaTable().Wa_14020040029) && (Surf.Flags.Gpu.Depth))
             {
-                GMM_SET_64KB_TILE(Surf.Flags, 0, GetGmmLibContext());
-                GMM_SET_4KB_TILE(Surf.Flags, 1, GetGmmLibContext());
+                // if SW uses Tile4 merely to reduce surface size for Depth buffers,
+                // then use Tile64 instead
+                GMM_SET_64KB_TILE(Surf.Flags, 1, GetGmmLibContext());
+                GMM_SET_4KB_TILE(Surf.Flags, 0, GetGmmLibContext());
 
                 //Also update CreateParams, if client reuses the modified struct, it'd see final tile-selection by Gmm.
                 //Gmm's auto-tile-selection & tile-mode for size-optimization doesn't work for explicit tile-selection
-                GMM_SET_64KB_TILE(CreateParams.Flags, 0, GetGmmLibContext());
-                GMM_SET_4KB_TILE(CreateParams.Flags, 1, GetGmmLibContext());
+                GMM_SET_64KB_TILE(CreateParams.Flags, 1, GetGmmLibContext());
+                GMM_SET_4KB_TILE(CreateParams.Flags, 0, GetGmmLibContext());
+            }
+            else
+            {
+                if (pTextureCalc->SurfaceRequires64KBTileOptimization(&Surf))
+                {
+                    GMM_SET_64KB_TILE(Surf.Flags, 0, GetGmmLibContext());
+                    GMM_SET_4KB_TILE(Surf.Flags, 1, GetGmmLibContext());
+
+                    //Also update CreateParams, if client reuses the modified struct, it'd see final tile-selection by Gmm.
+                    //Gmm's auto-tile-selection & tile-mode for size-optimization doesn't work for explicit tile-selection
+                    GMM_SET_64KB_TILE(CreateParams.Flags, 0, GetGmmLibContext());
+                    GMM_SET_4KB_TILE(CreateParams.Flags, 1, GetGmmLibContext());
+                }
             }
         }
     }
@@ -317,6 +332,7 @@ bool GmmLib::GmmResourceInfoCommon::CopyClientParams(GMM_RESCREATE_PARAMS &Creat
             AuxSurf.Flags.Gpu.CCS                = 0;
             AuxSurf.Type                         = (AuxSurf.Flags.Gpu.HiZ) ? AuxSurf.Type : RESOURCE_INVALID;
             AuxSurf.Flags.Info.RenderCompressed = AuxSurf.Flags.Info.MediaCompressed = 0;
+            AuxSurf.Flags.Info.NotCompressed                                         = 1;
         }
         else if(Surf.Flags.Gpu.Depth && Surf.Flags.Gpu.HiZ && !Surf.Flags.Gpu.CCS) // Depth + HiZ only, CCS is disabled
         {
@@ -343,6 +359,7 @@ bool GmmLib::GmmResourceInfoCommon::CopyClientParams(GMM_RESCREATE_PARAMS &Creat
             AuxSecSurf.Flags.Gpu.MCS            = 0;
             AuxSurf.Flags.Gpu.CCS               = 0;
             AuxSurf.Flags.Info.RenderCompressed = AuxSurf.Flags.Info.MediaCompressed = 0;
+            AuxSurf.Flags.Info.NotCompressed                                         = 1;
         }
         else if(Surf.Flags.Gpu.CCS)
         {
@@ -375,6 +392,13 @@ bool GmmLib::GmmResourceInfoCommon::CopyClientParams(GMM_RESCREATE_PARAMS &Creat
         MultiTileArch = CreateParams.MultiTileArch;
     }
 
+    // For Xe2 RenderCompressed and MediaCompressed to be unset
+    if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+    {
+        //Deny compression
+        Surf.Flags.Info.RenderCompressed = 0;
+        Surf.Flags.Info.MediaCompressed  = 0;
+    }
     return true;
 }
 
@@ -443,6 +467,12 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::ValidateParams()
     pPlatformResource = GMM_OVERRIDE_PLATFORM_INFO(&Surf, GetGmmLibContext());
     pTextureCalc      = GMM_OVERRIDE_TEXTURE_CALC(&Surf, GetGmmLibContext());
 
+    if (!pTextureCalc)
+    {
+        GMM_ASSERTDPF(0, "Texture Calculation pointer is NULL.");
+        goto ERROR_CASE;
+    }
+
     __GMM_ASSERT(!(
     Surf.Flags.Gpu.Query &&
     !Surf.Flags.Info.Cacheable)); // Why query not set as cacheable? If not cacheable, what keeps from stolen memory (because STORE_DWORD/PIPE_CONTROL/etc. targets can't be in stolen)?
@@ -558,6 +588,7 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::ValidateParams()
             Surf.Flags.Info.NonLocalOnly = 0;
         }
         if(GetGmmLibContext()->GetSkuTable().FtrFlatPhysCCS &&
+            !GetGmmLibContext()->GetSkuTable().FtrXe2Compression &&
            (Surf.Flags.Info.RenderCompressed ||
             Surf.Flags.Info.MediaCompressed))
         {
@@ -603,6 +634,30 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::ValidateParams()
     else
     {
         Surf.Flags.Info.LocalOnly = false; //Zero out on iGPU
+        if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression && Surf.Flags.Info.XAdapter)
+        {
+            Surf.Flags.Info.NotCompressed     = 1; // disable compression for XAdapter resources on iGPU,
+            Surf.Flags.Gpu.CCS                = 0;
+            Surf.Flags.Gpu.UnifiedAuxSurface  = 0;
+            Surf.Flags.Gpu.IndirectClearColor = 0;
+            Surf.Flags.Gpu.MCS                = 0;
+        }
+    }
+    if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+    {
+        if (Surf.Flags.Info.TiledX)
+        {
+            if (!(Surf.Flags.Gpu.FlipChain || Surf.Flags.Gpu.Overlay))
+            {
+                GMM_ASSERTDPF(0, "TiledX request for non displayable");
+            }
+            Surf.Flags.Info.NotCompressed = 1; // disable compression for TileX resources
+        }
+
+        if ((Surf.Flags.Gpu.FlipChain || Surf.Flags.Gpu.Overlay) && !Surf.Flags.Info.Tile4)
+        {
+            Surf.Flags.Info.NotCompressed = 1; //Disable compression if displayable are not tile4
+        }
     }
 
     if((GFX_GET_CURRENT_RENDERCORE(pPlatformResource->Platform) < IGFX_GEN8_CORE) &&
@@ -837,10 +892,9 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::ValidateParams()
     // IndirectClearColor Restrictions
     if((Surf.Flags.Gpu.IndirectClearColor) &&
        !( //--- Legitimate IndirectClearColor Case ------------------------------------------
-       ((GFX_GET_CURRENT_RENDERCORE(pPlatformResource->Platform) >= IGFX_GEN9_CORE) &&
-        Surf.Flags.Gpu.UnifiedAuxSurface) ||
-       ((GFX_GET_CURRENT_RENDERCORE(pPlatformResource->Platform) > IGFX_GEN11_CORE) &&
-        (Surf.Flags.Gpu.HiZ || Surf.Flags.Gpu.SeparateStencil))))
+        (((GFX_GET_CURRENT_RENDERCORE(pPlatformResource->Platform) >= IGFX_GEN9_CORE) && Surf.Flags.Gpu.UnifiedAuxSurface) ||
+         ((GFX_GET_CURRENT_RENDERCORE(pPlatformResource->Platform) > IGFX_GEN11_CORE) && (Surf.Flags.Gpu.HiZ || Surf.Flags.Gpu.SeparateStencil)))))
+
     {
         GMM_ASSERTDPF(0, "Invalid IndirectClearColor usage!");
         goto ERROR_CASE;
@@ -920,6 +974,11 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::ValidateParams()
             break;
         }
         default:
+            if (!Surf.BaseWidth || !Surf.BaseHeight)
+            {
+                GMM_ASSERTDPF(0, "Width or Height is 0!");
+                goto ERROR_CASE;
+            }
             break;
     }
 
diff --git a/Source/GmmLib/Resource/GmmRestrictions.cpp b/Source/GmmLib/Resource/GmmRestrictions.cpp
index 6d05d55..0efcc52 100644
--- a/Source/GmmLib/Resource/GmmRestrictions.cpp
+++ b/Source/GmmLib/Resource/GmmRestrictions.cpp
@@ -76,7 +76,10 @@ void GmmLib::GmmResourceInfoCommon::GetRestrictions(__GMM_BUFFER_TYPE &Restricti
 
     GMM_TEXTURE_CALC *pTextureCalc = NULL;
     pTextureCalc                   = GMM_OVERRIDE_TEXTURE_CALC(&Surf, GetGmmLibContext());
-    pTextureCalc->GetResRestrictions(&Surf, Restrictions);
+    if (pTextureCalc)
+    {
+        pTextureCalc->GetResRestrictions(&Surf, Restrictions);
+    }
 
     GMM_DPF_EXIT;
 }
@@ -565,16 +568,16 @@ void GmmLib::GmmTextureCalc::GetResRestrictions(GMM_TEXTURE_INFO * pTexinfo,
     }
 
     if(pTexinfo->Flags.Info.RenderCompressed ||
-       pTexinfo->Flags.Info.MediaCompressed)
+        pTexinfo->Flags.Info.MediaCompressed || (pGmmLibContext->GetSkuTable().FtrXe2Compression && !pTexinfo->Flags.Info.NotCompressed))
     {
-      if(pGmmLibContext->GetSkuTable().FtrFlatPhysCCS)
+        if(pGmmLibContext->GetSkuTable().FtrFlatPhysCCS)
         {
-            Restrictions.Alignment = GFX_ALIGN(Restrictions.Alignment, GMM_KBYTE(64));
+            Restrictions.Alignment = pGmmLibContext->GetSkuTable().FtrXe2Compression ? GFX_ALIGN(Restrictions.Alignment, GMM_BYTES(256)) : GFX_ALIGN(Restrictions.Alignment, GMM_BYTES(128));
         }
         else // only for platforms having auxtable
         {
             Restrictions.Alignment = GFX_ALIGN(Restrictions.Alignment, (WA16K(pGmmLibContext) ? GMM_KBYTE(16) : WA64K(pGmmLibContext) ? GMM_KBYTE(64) : GMM_MBYTE(1)));
-	}
+	    }
     }
 
     GMM_DPF_EXIT;
diff --git a/Source/GmmLib/Texture/GmmGen12Texture.cpp b/Source/GmmLib/Texture/GmmGen12Texture.cpp
index 31fa953..20bdd2b 100644
--- a/Source/GmmLib/Texture/GmmGen12Texture.cpp
+++ b/Source/GmmLib/Texture/GmmGen12Texture.cpp
@@ -178,8 +178,9 @@ GMM_STATUS GmmLib::GmmGen12TextureCalc::FillTexCCS(GMM_TEXTURE_INFO *pSurf,
           GMM_IS_64KB_TILE(Surf.Flags) || Surf.Flags.Info.TiledYf) ?
          1 :
          Surf.MSAA.NumSamples) *                                                                                         // MSAA (non-Depth/Stencil) RT samples stored as array planes.
-        ((GMM_IS_64KB_TILE(Surf.Flags) && !pGmmLibContext->GetSkuTable().FtrTileY && (Surf.MSAA.NumSamples == 16)) ? 4 : // MSAA x8/x16 stored as pseudo array planes each with 4x samples
-         (GMM_IS_64KB_TILE(Surf.Flags) && !pGmmLibContext->GetSkuTable().FtrTileY && (Surf.MSAA.NumSamples == 8)) ? 2 : 1);
+        ((GMM_IS_64KB_TILE(Surf.Flags) && !pGmmLibContext->GetSkuTable().FtrTileY && !pGmmLibContext->GetSkuTable().FtrXe2PlusTiling && (Surf.MSAA.NumSamples == 16)) ? 4 : // MSAA x8/x16 stored as pseudo array planes each with 4x samples
+         (GMM_IS_64KB_TILE(Surf.Flags) && !pGmmLibContext->GetSkuTable().FtrTileY && !pGmmLibContext->GetSkuTable().FtrXe2PlusTiling && (Surf.MSAA.NumSamples == 8)) ? 2 :
+                                                                                                                                                                       1);
 
         if(GMM_IS_64KB_TILE(Surf.Flags) || Surf.Flags.Info.TiledYf)
         {
@@ -246,7 +247,7 @@ GMM_STATUS GmmLib::GmmGen12TextureCalc::FillTexCCS(GMM_TEXTURE_INFO *pSurf,
                 if(Surf.MSAA.NumSamples && !pGmmLibContext->GetSkuTable().FtrTileY)
                 {
                     //MSAA Qpitch is sample-distance, multiply NumSamples in a tile
-                    qPitch *= GFX_MIN(Surf.MSAA.NumSamples, 4);
+                    qPitch *= (pGmmLibContext->GetSkuTable().FtrXe2PlusTiling ? Surf.MSAA.NumSamples : GFX_MIN(Surf.MSAA.NumSamples, 4));
                 }
             }
             else
@@ -271,6 +272,7 @@ GMM_STATUS GmmLib::GmmGen12TextureCalc::FillTexCCS(GMM_TEXTURE_INFO *pSurf,
         //Clear compression request in CCS
         pAuxTexInfo->Flags.Info.RenderCompressed = 0;
         pAuxTexInfo->Flags.Info.MediaCompressed  = 0;
+        pAuxTexInfo->Flags.Info.NotCompressed    = 1;
         pAuxTexInfo->Flags.Info.RedecribedPlanes = 0;
         SetTileMode(pAuxTexInfo);
 
@@ -329,9 +331,11 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmGen12TextureCalc::FillTex2D(GMM_TEXTURE_INFO *
       (GMM_IS_64KB_TILE(pTexInfo->Flags) || pTexInfo->Flags.Info.TiledYf)) ? // MSAA Ys/Yf samples are ALSO stored as array planes, calculate size for single sample and expand it later.
      1 :
      pTexInfo->MSAA.NumSamples) *                                                                                              // MSAA (non-Depth/Stencil) RT samples stored as array planes.
-    ((GMM_IS_64KB_TILE(pTexInfo->Flags) && !pGmmLibContext->GetSkuTable().FtrTileY && (pTexInfo->MSAA.NumSamples == 16)) ? 4 : // MSAA x8/x16 stored as pseudo array planes each with 4x samples
-     (GMM_IS_64KB_TILE(pTexInfo->Flags) && !pGmmLibContext->GetSkuTable().FtrTileY && (pTexInfo->MSAA.NumSamples == 8)) ? 2 : 1);
-
+    ((pTexInfo->Flags.Gpu.Depth || pTexInfo->Flags.Gpu.SeparateStencil) ? // Depth/Stencil MSAA surface is expanded through Width and Depth
+     1 :
+     ((GMM_IS_64KB_TILE(pTexInfo->Flags) && !pGmmLibContext->GetSkuTable().FtrTileY && !pGmmLibContext->GetSkuTable().FtrXe2PlusTiling && (pTexInfo->MSAA.NumSamples == 16)) ? 4 : // MSAA x8/x16 stored as pseudo array planes each with 4x samples
+      (GMM_IS_64KB_TILE(pTexInfo->Flags) && !pGmmLibContext->GetSkuTable().FtrTileY && !pGmmLibContext->GetSkuTable().FtrXe2PlusTiling && (pTexInfo->MSAA.NumSamples == 8)) ? 2 :
+                                                                                                                                                                              1));
     if(GMM_IS_64KB_TILE(pTexInfo->Flags) || pTexInfo->Flags.Info.TiledYf)
     {
         ExpandedArraySize = GFX_CEIL_DIV(ExpandedArraySize, pPlatform->TileInfo[pTexInfo->TileMode].LogicalTileDepth);
@@ -497,7 +501,6 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmGen12TextureCalc::FillTex2D(GMM_TEXTURE_INFO *
     {
         Fill2DTexOffsetAddress(pTexInfo);
     }
-
     GMM_DPF_EXIT;
 
     return (Status);
@@ -1149,6 +1152,55 @@ uint64_t GMM_STDCALL GmmLib::GmmGen12TextureCalc::ScaleFCRectWidth(GMM_TEXTURE_I
     return ScaledWidth;
 }
 
+
+uint64_t GMM_STDCALL GmmLib::GmmGen12TextureCalc::Get2DFCSurfaceWidthFor3DSurface(GMM_TEXTURE_INFO *pTexInfo,
+                                                                                  uint64_t          Width)
+{
+    uint64_t Width2D = Width;
+    if (pTexInfo->Flags.Gpu.CCS)
+    {
+        CCS_UNIT *FCRectAlign = static_cast<PlatformInfoGen12 *>(pGmmLibContext->GetPlatformInfoObj())->GetFCRectAlign();
+        uint8_t   index       = FCMaxModes;
+        if ((index = FCMode(pTexInfo->TileMode, pTexInfo->BitsPerPixel)) < FCMaxModes)
+        {
+            Width2D = GFX_ALIGN(Width2D, FCRectAlign[index].Align.Width);
+            Width2D *= FCRectAlign[index].Downscale.Width;
+        }
+        else
+        {
+            
+            __GMM_ASSERT(0);
+        }
+    }
+    return Width2D;
+}
+uint64_t GMM_STDCALL GmmLib::GmmGen12TextureCalc::Get2DFCSurfaceHeightFor3DSurface(GMM_TEXTURE_INFO *pTexInfo,
+                                                                                   uint32_t          Height,
+                                                                                   uint32_t          Depth)
+{
+    uint64_t Height2D = Height;
+    uint32_t Depth3D  = Depth;
+
+    if (pTexInfo->Flags.Gpu.CCS && (Depth > 1))
+    {
+        CCS_UNIT *FCRectAlign = static_cast<PlatformInfoGen12 *>(pGmmLibContext->GetPlatformInfoObj())->GetFCRectAlign();
+        uint8_t   index       = FCMaxModes;
+        if ((index = FCMode(pTexInfo->TileMode, pTexInfo->BitsPerPixel)) < FCMaxModes)
+        {
+            Height2D = GFX_ALIGN(Height2D, FCRectAlign[index].Align.Height);
+            Height2D *= FCRectAlign[index].Downscale.Height;
+            Depth3D = GFX_ALIGN(Depth3D, FCRectAlign[index].Align.Depth) / FCRectAlign[index].Align.Depth;
+            Height2D *= Depth3D;
+        }
+        else
+        {
+            
+            __GMM_ASSERT(0);
+        }
+    }
+    return Height2D;
+}
+
 /////////////////////////////////////////////////////////////////////////////////////
 /// This function does any special-case conversion from client-provided pseudo creation
 /// parameters to actual parameters for CCS.
diff --git a/Source/GmmLib/Texture/GmmGen9Texture.cpp b/Source/GmmLib/Texture/GmmGen9Texture.cpp
index 6dc0659..f3b6012 100644
--- a/Source/GmmLib/Texture/GmmGen9Texture.cpp
+++ b/Source/GmmLib/Texture/GmmGen9Texture.cpp
@@ -592,7 +592,7 @@ void GmmLib::GmmGen9TextureCalc::Fill2DTexOffsetAddress(GMM_TEXTURE_INFO *pTexIn
         ArrayQPitch = GFX_ALIGN_NP2(ArrayQPitch, Alignment);
 	    
 	// Color Surf with MSAA Enabled Mutiply 4
-        if(GMM_IS_64KB_TILE(pTexInfo->Flags) && (!pGmmLibContext->GetSkuTable().FtrTileY) &&
+        if (GMM_IS_64KB_TILE(pTexInfo->Flags) && (!pGmmLibContext->GetSkuTable().FtrTileY) && (!pGmmLibContext->GetSkuTable().FtrXe2PlusTiling) &&
            ((pTexInfo->MSAA.NumSamples == 8) || (pTexInfo->MSAA.NumSamples == 16)) &&
            ((pTexInfo->Flags.Gpu.Depth == 0) && (pTexInfo->Flags.Gpu.SeparateStencil == 0)))
         {
diff --git a/Source/GmmLib/Texture/GmmTexture.h b/Source/GmmLib/Texture/GmmTexture.h
index fed1b52..cbbd3f9 100644
--- a/Source/GmmLib/Texture/GmmTexture.h
+++ b/Source/GmmLib/Texture/GmmTexture.h
@@ -91,6 +91,7 @@ GMM_INLINE GMM_STATUS __GmmTexFillHAlignVAlign(GMM_TEXTURE_INFO *pTexInfo,GMM_LI
         }                                                       \
     }
 
+
     if (!((pTexInfo->Format > GMM_FORMAT_INVALID) &&
         (pTexInfo->Format < GMM_RESOURCE_FORMATS)))
     {
@@ -149,22 +150,89 @@ GMM_INLINE GMM_STATUS __GmmTexFillHAlignVAlign(GMM_TEXTURE_INFO *pTexInfo,GMM_LI
                     {
                         switch(pTexInfo->MSAA.NumSamples)
                         {
-                            case 16: UnitAlignWidth /= 4; UnitAlignHeight /= 4; break;
-                            case 8:  UnitAlignWidth /= 4; UnitAlignHeight /= 2; break;
-                            case 4:  UnitAlignWidth /= 2; UnitAlignHeight /= 2; break;
-                            case 2:  UnitAlignWidth /= 2; break;
-                            default: __GMM_ASSERT(0);
+                        case 16:
+                            UnitAlignWidth /= 4;
+                            UnitAlignHeight /= 4;
+                            break;
+                        case 8:
+                            UnitAlignWidth /= 4;
+                            UnitAlignHeight /= 2;
+                            break;
+                        case 4:
+                            UnitAlignWidth /= 2;
+                            UnitAlignHeight /= 2;
+                            break;
+                        case 2:
+                            UnitAlignWidth /= 2;
+                            break;
+                        default:
+                            __GMM_ASSERT(0);
                         }
                     }
                     else
                     {
-                        switch (pTexInfo->MSAA.NumSamples)
+                        if (pGmmLibContext->GetSkuTable().FtrXe2PlusTiling)
+                        {
+                            switch (pTexInfo->MSAA.NumSamples)
+                            {
+                            case 16:
+                                if (pTexInfo->BitsPerPixel == 64)
+                                {
+                                    UnitAlignWidth /= 8;
+                                    UnitAlignHeight /= 2;
+                                }
+                                else
+                                {
+                                    UnitAlignWidth /= 4;
+                                    UnitAlignHeight /= 4;
+                                }
+                                break;
+                            case 8:
+                                if ((pTexInfo->BitsPerPixel == 8) || (pTexInfo->BitsPerPixel == 32))
+                                {
+                                    UnitAlignWidth /= 2;
+                                    UnitAlignHeight /= 4;
+                                }
+                                else
+                                {
+                                    UnitAlignWidth /= 4;
+                                    UnitAlignHeight /= 2;
+                                }
+                                break;
+                            case 4:
+                                UnitAlignWidth /= 2;
+                                UnitAlignHeight /= 2;
+                                break;
+                            case 2:
+                                if (pTexInfo->BitsPerPixel == 128)
+                                {
+                                    UnitAlignHeight /= 2;
+                                }
+                                else
+                                {
+                                    UnitAlignWidth /= 2;
+                                }
+                                break;
+                            default:
+                                __GMM_ASSERT(0);
+                            }
+                        }
+                        else
                         {
+                            switch (pTexInfo->MSAA.NumSamples)
+                            {
                             case 4:
                             case 8:
-                            case 16: UnitAlignWidth /= 2; UnitAlignHeight /= 2; break;
-                            case 2:  UnitAlignWidth /= 2; break;
-                            default: __GMM_ASSERT(0);
+                            case 16:
+                                UnitAlignWidth /= 2;
+                                UnitAlignHeight /= 2;
+                                break;
+                            case 2:
+                                UnitAlignWidth /= 2;
+                                break;
+                            default:
+                                __GMM_ASSERT(0);
+                            }
                         }
                     }
                 }
diff --git a/Source/GmmLib/Texture/GmmTextureAlloc.cpp b/Source/GmmLib/Texture/GmmTextureAlloc.cpp
index 6184032..b471cf8 100644
--- a/Source/GmmLib/Texture/GmmTextureAlloc.cpp
+++ b/Source/GmmLib/Texture/GmmTextureAlloc.cpp
@@ -104,7 +104,14 @@ void GmmLib::GmmTextureCalc::SetTileMode(GMM_TEXTURE_INFO *pTexInfo)
             }
             else
             {
-                GENERATE_TILE_MODE(_64, 1D, 2D, 2D_2X, 2D_4X, 2D_4X, 2D_4X, 3D);
+                if (pGmmLibContext->GetSkuTable().FtrXe2PlusTiling)
+                {
+                    GENERATE_TILE_MODE(_64, 1D, 2D, 2D_2X, 2D_4X, 2D_8X, 2D_16X, 3D);
+                }
+                else
+                {
+                    GENERATE_TILE_MODE(_64, 1D, 2D, 2D_2X, 2D_4X, 2D_4X, 2D_4X, 3D);
+                }
             }
 
             pTexInfo->Flags.Info.TiledYf = 0;
@@ -714,7 +721,7 @@ GMM_STATUS GmmLib::GmmTextureCalc::FillTexPitchAndSize(GMM_TEXTURE_INFO * pTexIn
                 else
                 {
                     //XeHP, DG2
-                    if((pTexInfo->MSAA.NumSamples == 8 || pTexInfo->MSAA.NumSamples == 16))
+                    if (!pGmmLibContext->GetSkuTable().FtrXe2PlusTiling && (pTexInfo->MSAA.NumSamples == 8 || pTexInfo->MSAA.NumSamples == 16))
                     {
                         uint64_t SliceSize = pTexInfo->Pitch * Height;
                         SliceSize *= 4; // multiple by samples per tile
@@ -733,6 +740,13 @@ GMM_STATUS GmmLib::GmmTextureCalc::FillTexPitchAndSize(GMM_TEXTURE_INFO * pTexIn
                 Size = GFX_ALIGN(Size, GMM_KBYTE(64));
             }
 
+            if (pGmmLibContext->GetSkuTable().FtrXe2Compression && pTexInfo->Flags.Info.Linear)
+            {
+                Size = GFX_ALIGN(Size, GMM_BYTES(256)); // for all linear resources starting Xe2, align overall size to compression block size. For subresources, 256B alignment is not needed, needed only for overall resource
+                                                        // on older platforms, all linear resources get Halign = 128B which ensures overall size to be a multiple of compression block size of 128B,
+                                                        // so this is needed only for linear resources on Xe2 where HAlign continues to be at 128B, but compression block size has doubled to 256B
+            }
+
             // Buffer Sampler Padding...
             if((pTexInfo->Type == RESOURCE_BUFFER) &&
                pGmmLibContext->GetWaTable().WaNoMinimizedTrivialSurfacePadding &&
diff --git a/Source/GmmLib/Texture/GmmTextureOffset.cpp b/Source/GmmLib/Texture/GmmTextureOffset.cpp
index da495ba..95d4aaf 100644
--- a/Source/GmmLib/Texture/GmmTextureOffset.cpp
+++ b/Source/GmmLib/Texture/GmmTextureOffset.cpp
@@ -237,7 +237,7 @@ GMM_STATUS GmmLib::GmmTextureCalc::GetTexStdLayoutOffset(GMM_TEXTURE_INFO *   pT
                     pReqInfo->StdLayout.TileDepthPitch = DepthPitch;
                 }
 
-                PrevMipSize = DepthPitch * MipDepthTiles;
+                PrevMipSize = (GMM_GFX_SIZE_T)DepthPitch * MipDepthTiles;
                 SlicePitch += DepthPitch;
             }
 
@@ -352,12 +352,12 @@ GMM_STATUS GmmLib::GmmTextureCalc::GetTexLockOffset(GMM_TEXTURE_INFO *   pTexInf
                 pReqInfo->Lock.Mip0SlicePitch = GFX_ULONG_CAST(pTexInfo->OffsetInfo.Texture3DOffsetInfo.Mip0SlicePitch);
 
                 // Actual address is offset based on requested slice
-                AddressOffset += SliceRow * MipHeight * Pitch;
+                AddressOffset += (GMM_GFX_SIZE_T)SliceRow * MipHeight * Pitch;
 
                 // Get to particular slice
                 if(Slice % NumberOfMipsInSingleRow)
                 {
-                    AddressOffset += (((Slice % NumberOfMipsInSingleRow) *
+                    AddressOffset += (((GMM_GFX_SIZE_T)(Slice % NumberOfMipsInSingleRow) *
                                        MipWidth * pTexInfo->BitsPerPixel) >>
                                       3);
                 }
@@ -788,9 +788,9 @@ GMM_GFX_SIZE_T GmmLib::GmmTextureCalc::Get3DMipByteAddress(GMM_TEXTURE_INFO *
             MipHeight /= 2;
         }
 
-        ExtraBytes = PlaneRows * MipHeight * Pitch;
+        ExtraBytes = (GMM_GFX_SIZE_T)PlaneRows * MipHeight * Pitch;
 
-        ExtraBytes += ((Slice % MipsInThisRow) *
+        ExtraBytes += ((GMM_GFX_SIZE_T)(Slice % MipsInThisRow) *
                        MipWidth * pTexInfo->BitsPerPixel) >>
                       3;
 
diff --git a/Source/GmmLib/Texture/GmmXe_LPGTexture.cpp b/Source/GmmLib/Texture/GmmXe_LPGTexture.cpp
index d689c3d..4a83600 100644
--- a/Source/GmmLib/Texture/GmmXe_LPGTexture.cpp
+++ b/Source/GmmLib/Texture/GmmXe_LPGTexture.cpp
@@ -1024,12 +1024,12 @@ GMM_STATUS GmmLib::GmmXe_LPGTextureCalc::GetTexLockOffset(GMM_TEXTURE_INFO *   p
                 pReqInfo->Lock.Mip0SlicePitch = GFX_ULONG_CAST(pTexInfo->OffsetInfo.Texture3DOffsetInfo.Mip0SlicePitch);
 
                 // Actual address is offset based on requested slice
-                AddressOffset += SliceRow * MipHeight * Pitch;
+                AddressOffset += (GMM_GFX_SIZE_T)SliceRow * MipHeight * Pitch;
 
                 // Get to particular slice
                 if(Slice % NumberOfMipsInSingleRow)
                 {
-                    AddressOffset += (((Slice % NumberOfMipsInSingleRow) *
+                    AddressOffset += (((GMM_GFX_SIZE_T)(Slice % NumberOfMipsInSingleRow) *
                                        MipWidth * pTexInfo->BitsPerPixel) >>
                                       3);
                 }
@@ -1339,4 +1339,3 @@ void GmmLib::GmmXe_LPGTextureCalc::GetBltInfoPerPlane(GMM_TEXTURE_INFO *pTexInfo
         pBlt->Sys.pData   = (char *)pBlt->Sys.pData + uint32_t(pBlt->Blt.Height * pBlt->Sys.RowPitch);
     }
 }
-
diff --git a/Source/GmmLib/TranslationTable/GmmAuxTable.cpp b/Source/GmmLib/TranslationTable/GmmAuxTable.cpp
index 98aceea..414ba72 100644
--- a/Source/GmmLib/TranslationTable/GmmAuxTable.cpp
+++ b/Source/GmmLib/TranslationTable/GmmAuxTable.cpp
@@ -828,7 +828,11 @@ GMM_STATUS GmmLib::AuxTable::MapValidEntry(GMM_UMD_SYNCCONTEXT *UmdContext, GMM_
 
 GMM_AUXTTL1e GmmLib::AuxTable::CreateAuxL1Data(GMM_RESOURCE_INFO *BaseResInfo)
 {
-    GMM_FORMAT_ENTRY FormatInfo = pClientContext->GetLibContext()->GetPlatformInfo().FormatTable[BaseResInfo->GetResourceFormat()];
+    GMM_RESOURCE_FORMAT Format;
+    Format = BaseResInfo->GetResourceFormat();
+    Format = ((Format > GMM_FORMAT_INVALID) && (Format < GMM_RESOURCE_FORMATS)) ? Format : GMM_FORMAT_INVALID;
+
+    GMM_FORMAT_ENTRY FormatInfo = pClientContext->GetLibContext()->GetPlatformInfo().FormatTable[Format];
     GMM_AUXTTL1e     L1ePartial = {0};
 #define GMM_REGISTRY_UMD_PATH "SOFTWARE\\Intel\\IGFX\\GMM\\"
 #define GMM_E2EC_OVERRIDEDEPTH16BPPTO12 "ForceYUV16To12BPP"
@@ -845,7 +849,7 @@ GMM_AUXTTL1e GmmLib::AuxTable::CreateAuxL1Data(GMM_RESOURCE_INFO *BaseResInfo)
     L1ePartial.TileMode = BaseResInfo->GetResFlags().Info.TiledYs ? 0 : 1;
 
     L1ePartial.Format     = FormatInfo.CompressionFormat.AuxL1eFormat;
-    L1ePartial.LumaChroma = GmmIsPlanar(BaseResInfo->GetResourceFormat());
+    L1ePartial.LumaChroma = GmmIsPlanar(Format);
 
     if(pClientContext->GetLibContext()->GetWaTable().WaUntypedBufferCompression && BaseResInfo->GetResourceType() == RESOURCE_BUFFER)
     {
@@ -886,7 +890,7 @@ GMM_AUXTTL1e GmmLib::AuxTable::CreateAuxL1Data(GMM_RESOURCE_INFO *BaseResInfo)
     }
     else
     {
-        switch(BaseResInfo->GetResourceFormat())
+        switch(Format)
         {
             case GMM_FORMAT_P012:
             case GMM_FORMAT_Y412:
@@ -934,8 +938,17 @@ GMM_GFX_ADDRESS GMM_INLINE GmmLib::AuxTable::__GetCCSCacheline(GMM_RESOURCE_INFO
     if(BaseIsYF)
     {
         uint32_t PitchIn4YF = BasePitchInTiles / 4; //Base Pitch is physically padded to 4x1 YF width
-        i                   = static_cast<uint32_t>(AdrOffset % PitchIn4YF);
-        j                   = static_cast<uint32_t>(AdrOffset / PitchIn4YF);
+        
+	if (PitchIn4YF != 0)
+        {
+            i = static_cast<uint32_t>(AdrOffset % PitchIn4YF);
+            j = static_cast<uint32_t>(AdrOffset / PitchIn4YF);
+        }
+        else
+        {
+            __GMM_ASSERT(PitchIn4YF != 0);
+            return 0;
+        }
     }
     else if(BasePitchInTiles != 0) //TileYs
     {
diff --git a/Source/GmmLib/ULT/CMakeLists.txt b/Source/GmmLib/ULT/CMakeLists.txt
index 52e0944..6ddd802 100644
--- a/Source/GmmLib/ULT/CMakeLists.txt
+++ b/Source/GmmLib/ULT/CMakeLists.txt
@@ -30,6 +30,7 @@ set(GMMULT_HEADERS
      GmmGen11ResourceULT.h
      GmmGen12ResourceULT.h
      GmmGen12dGPUResourceULT.h
+     GmmXe2_LPGResourceULT.h
      GmmGen12CachePolicyULT.h
      GmmGen12dGPUCachePolicyULT.h
      GmmXe_LPGCachePolicyULT.h
@@ -54,6 +55,7 @@ set(GMMULT_SOURCES
     GmmGen11ResourceULT.cpp
     GmmGen12ResourceULT.cpp
     GmmGen12dGPUResourceULT.cpp
+    GmmXe2_LPGResourceULT.cpp    
     GmmGen9CachePolicyULT.cpp
     GmmGen9ResourceULT.cpp
     GmmResourceCpuBltULT.cpp
@@ -78,6 +80,7 @@ source_group("Source Files\\Resource" FILES
             GmmGen11ResourceULT.cpp
             GmmGen12ResourceULT.cpp
             GmmGen12dGPUResourceULT.cpp
+            GmmXe2_LPGResourceULT.cpp
             GmmGen9ResourceULT.cpp
             GmmResourceCpuBltULT.cpp
             GmmResourceULT.cpp
@@ -110,6 +113,7 @@ source_group("Header Files\\Resource" FILES
              GmmGen11ResourceULT.h
              GmmGen12ResourceULT.h
              GmmGen12dGPUResourceULT.h
+             GmmXe2_LPGResourceULT.h	     
              GmmGen9ResourceULT.h
              GmmResourceULT.h
             )
diff --git a/Source/GmmLib/ULT/GmmGen10ResourceULT.cpp b/Source/GmmLib/ULT/GmmGen10ResourceULT.cpp
index 0f56657..d67910e 100644
--- a/Source/GmmLib/ULT/GmmGen10ResourceULT.cpp
+++ b/Source/GmmLib/ULT/GmmGen10ResourceULT.cpp
@@ -100,7 +100,7 @@ TEST_F(CTestGen10Resource, TestMSAA)
     uint32_t MCSHAlign = 0, MCSVAlign = 0, TileSize = 0;
     uint32_t ExpectedMCSBpp = 0;
     std::vector<tuple<int, int, int, bool, int, int>> List; //TEST_TILE_TYPE, TEST_BPP, TEST_RESOURCE_TYPE, Depth or RT, TestDimension index, ArraySize
-    auto Size = BuildInputIterator(List, 4, 2);             // Size of arrays TestDimensions, TestArraySize
+    auto Size = BuildInputIterator(List, 4, 2, false);             // Size of arrays TestDimensions, TestArraySize
 
     for(auto element : List)
     {
@@ -169,7 +169,7 @@ TEST_F(CTestGen10Resource, TestMSAA)
                 else // Interleaved MSS
                 {
                     uint32_t WidthMultiplier, HeightMultiplier;
-                    GetInterleaveMSSPattern((TEST_MSAA)k, WidthMultiplier, HeightMultiplier);
+                    GetInterleaveMSSPattern((TEST_MSAA)k, WidthMultiplier, HeightMultiplier, IsRT, Bpp);
                     gmmParams.BaseWidth64 = WidthMultiplier > 1 ? GMM_ULT_ALIGN(gmmParams.BaseWidth64, 2) : gmmParams.BaseWidth64;
                     gmmParams.BaseHeight  = HeightMultiplier > 1 ? GMM_ULT_ALIGN(gmmParams.BaseHeight, 2) : gmmParams.BaseHeight;
 
diff --git a/Source/GmmLib/ULT/GmmGen12ResourceULT.cpp b/Source/GmmLib/ULT/GmmGen12ResourceULT.cpp
index 5d3fb16..c0c05e7 100644
--- a/Source/GmmLib/ULT/GmmGen12ResourceULT.cpp
+++ b/Source/GmmLib/ULT/GmmGen12ResourceULT.cpp
@@ -2856,7 +2856,7 @@ TEST_F(CTestGen12Resource, TestColorMSAA)
     uint32_t HAlign, VAlign, TileDimX, TileDimY, MCSHAlign, MCSVAlign, TileSize;
     uint32_t ExpectedMCSBpp;
     std::vector<tuple<int, int, int, bool, int, int>> List; //TEST_TILE_TYPE, TEST_BPP, TEST_RESOURCE_TYPE, Depth or RT, TestDimension index, ArraySize
-    auto Size = BuildInputIterator(List, 4, 2);             // Size of arrays TestDimensions, TestArraySize
+    auto Size = BuildInputIterator(List, 4, 2, false);      // Size of arrays TestDimensions, TestArraySize
 
     for(auto element : List)
     {
diff --git a/Source/GmmLib/ULT/GmmGen12dGPUResourceULT.cpp b/Source/GmmLib/ULT/GmmGen12dGPUResourceULT.cpp
index ff069be..5031cd9 100644
--- a/Source/GmmLib/ULT/GmmGen12dGPUResourceULT.cpp
+++ b/Source/GmmLib/ULT/GmmGen12dGPUResourceULT.cpp
@@ -3141,7 +3141,7 @@ TEST_F(CTestGen12dGPUResource, DISABLED_TestColorMSAA)
     uint32_t HAlign, VAlign, TileDimX, TileDimY, MCSHAlign, MCSVAlign, TileSize;
     uint32_t ExpectedMCSBpp;
     std::vector<tuple<int, int, int, bool, int, int>> List; //TEST_TILE_TYPE, TEST_BPP, TEST_RESOURCE_TYPE, Depth or RT, TestDimension index, ArraySize
-    auto Size = BuildInputIterator(List, 4, 2);             // Size of arrays TestDimensions, TestArraySize
+    auto Size = BuildInputIterator(List, 4, 2, false);      // Size of arrays TestDimensions, TestArraySize
 
     for(auto element : List)
     {
diff --git a/Source/GmmLib/ULT/GmmGen9ResourceULT.cpp b/Source/GmmLib/ULT/GmmGen9ResourceULT.cpp
index 970315b..a7be6be 100644
--- a/Source/GmmLib/ULT/GmmGen9ResourceULT.cpp
+++ b/Source/GmmLib/ULT/GmmGen9ResourceULT.cpp
@@ -3868,9 +3868,21 @@ TEST_F(CTestGen9Resource, TestPlanar2DTileYf)
 {
 }
 
-int BuildInputIterator(std::vector<std::tuple<int, int, int, bool, int, int>> &List, int maxTestDimension, int TestArray)
+int BuildInputIterator(std::vector<std::tuple<int, int, int, bool, int, int>> &List, int maxTestDimension, int TestArray, bool XEHPPlus)
 {
     for(uint32_t i = TEST_LINEAR; i < TEST_TILE_MAX; i++)
+	{
+        if(XEHPPlus)
+        {
+            if(i >= TEST_TILEX && i <= TEST_TILEY_MAX)
+                continue;
+        }
+        else
+        {
+            if(i > TEST_TILEY_MAX)
+                break;
+        }
+			
         for(uint32_t j = TEST_BPP_8; j < TEST_BPP_MAX; j++)
             for(uint32_t k = TEST_RESOURCE_1D; k < TEST_RESOURCE_MAX; k++)
                 for(uint32_t l = 0; l < maxTestDimension; l++)
@@ -3879,6 +3891,7 @@ int BuildInputIterator(std::vector<std::tuple<int, int, int, bool, int, int>> &L
                         List.emplace_back(std::make_tuple(i, j, k, true, l, m));
                         List.emplace_back(std::make_tuple(i, j, k, false, l, m));
                     }
+	}
 
     return List.size();
 }
@@ -3916,7 +3929,7 @@ TEST_F(CTestGen9Resource, TestMSAA)
     uint32_t MCSHAlign = 0, MCSVAlign = 0, TileSize = 0;
     uint32_t ExpectedMCSBpp;
     std::vector<tuple<int, int, int, bool, int, int>> List; //TEST_TILE_TYPE, TEST_BPP, TEST_RESOURCE_TYPE, Depth or RT, TestDimension index, ArraySize
-    auto Size = BuildInputIterator(List, 4, 2);             // Size of arrays TestDimensions, TestArraySize
+    auto Size = BuildInputIterator(List, 4, 2, false);             // Size of arrays TestDimensions, TestArraySize
 
     for(auto element : List)
     {
@@ -3984,7 +3997,7 @@ TEST_F(CTestGen9Resource, TestMSAA)
                 else // Interleaved MSS
                 {
                     uint32_t WidthMultiplier, HeightMultiplier;
-                    GetInterleaveMSSPattern((TEST_MSAA)k, WidthMultiplier, HeightMultiplier);
+                    GetInterleaveMSSPattern((TEST_MSAA)k, WidthMultiplier, HeightMultiplier, IsRT, Bpp);
                     gmmParams.BaseWidth64 = WidthMultiplier > 1 ? GMM_ULT_ALIGN(gmmParams.BaseWidth64, 2) : gmmParams.BaseWidth64;
                     gmmParams.BaseHeight  = HeightMultiplier > 1 ? GMM_ULT_ALIGN(gmmParams.BaseHeight, 2) : gmmParams.BaseHeight;
 
diff --git a/Source/GmmLib/ULT/GmmResourceULT.cpp b/Source/GmmLib/ULT/GmmResourceULT.cpp
index 1bf1c91..895ae5d 100644
--- a/Source/GmmLib/ULT/GmmResourceULT.cpp
+++ b/Source/GmmLib/ULT/GmmResourceULT.cpp
@@ -2692,7 +2692,7 @@ TEST_F(CTestResource, TestMSAA)
     uint32_t ExpectedMCSBpp;
 
     std::vector<std::tuple<int, int, int, bool, int, int>> List; //TEST_TILE_TYPE, TEST_BPP, TEST_RESOURCE_TYPE, Depth or RT, TestDimension index, TestArraySize index
-    auto Size = BuildInputIterator(List, 3, 2);                  // Size of arrays TestDimensions, TestArraySize
+    auto Size = BuildInputIterator(List, 3, 2, false);                  // Size of arrays TestDimensions, TestArraySize
 
     for(auto element : List)
     {
@@ -2762,7 +2762,7 @@ TEST_F(CTestResource, TestMSAA)
                 else // Interleaved MSS
                 {
                     uint32_t WidthMultiplier, HeightMultiplier;
-                    GetInterleaveMSSPattern((TEST_MSAA)k, WidthMultiplier, HeightMultiplier);
+                    GetInterleaveMSSPattern((TEST_MSAA)k, WidthMultiplier, HeightMultiplier, IsRT, Bpp);
                     gmmParams.BaseWidth64 = WidthMultiplier > 1 ? GMM_ULT_ALIGN(gmmParams.BaseWidth64, 2) : gmmParams.BaseWidth64;
                     gmmParams.BaseHeight  = HeightMultiplier > 1 ? GMM_ULT_ALIGN(gmmParams.BaseHeight, 2) : gmmParams.BaseHeight;
 
diff --git a/Source/GmmLib/ULT/GmmResourceULT.h b/Source/GmmLib/ULT/GmmResourceULT.h
index d07360f..acd4be0 100644
--- a/Source/GmmLib/ULT/GmmResourceULT.h
+++ b/Source/GmmLib/ULT/GmmResourceULT.h
@@ -59,6 +59,9 @@ typedef enum TEST_TILE_TYPE_ENUM
     TEST_TILEY,
     TEST_TILEYS,
     TEST_TILEYF,
+    TEST_TILEY_MAX = TEST_TILEYF,
+    TEST_TILE4,
+    TEST_TILE64,
     TEST_TILE_MAX
 }TEST_TILE_TYPE;
 
@@ -137,12 +140,18 @@ protected:
     {
         switch (Bpp)
         {
-            case TEST_BPP_8:    return GMM_FORMAT_GENERIC_8BIT;
-            case TEST_BPP_16:   return GMM_FORMAT_GENERIC_16BIT;
-            case TEST_BPP_32:   return GMM_FORMAT_GENERIC_32BIT;
-            case TEST_BPP_64:   return GMM_FORMAT_GENERIC_64BIT;
-            case TEST_BPP_128:  return GMM_FORMAT_GENERIC_128BIT;
-            default: break;
+        case TEST_BPP_8:
+            return GMM_FORMAT_GENERIC_8BIT;
+        case TEST_BPP_16:
+            return GMM_FORMAT_GENERIC_16BIT;
+        case TEST_BPP_32:
+            return GMM_FORMAT_GENERIC_32BIT;
+        case TEST_BPP_64:
+            return GMM_FORMAT_GENERIC_64BIT;
+        case TEST_BPP_128:
+            return GMM_FORMAT_GENERIC_128BIT;
+        default:
+            break;
         }
 
         return GMM_FORMAT_INVALID;
@@ -160,12 +169,23 @@ protected:
         uint32_t Bpp = 0;
         switch (bpp)
         {
-            case TEST_BPP_8:    Bpp = 8;    break;
-            case TEST_BPP_16:   Bpp = 16;   break;
-            case TEST_BPP_32:   Bpp = 32;   break;
-            case TEST_BPP_64:   Bpp = 64;   break;
-            case TEST_BPP_128:  Bpp = 128;  break;
-            default: break;
+        case TEST_BPP_8:
+            Bpp = 8;
+            break;
+        case TEST_BPP_16:
+            Bpp = 16;
+            break;
+        case TEST_BPP_32:
+            Bpp = 32;
+            break;
+        case TEST_BPP_64:
+            Bpp = 64;
+            break;
+        case TEST_BPP_128:
+            Bpp = 128;
+            break;
+        default:
+            break;
         }
 
         return Bpp >> 3;
@@ -189,17 +209,32 @@ protected:
                 Params.Flags.Info.TiledX = 1;
                 break;
             case TEST_TILEY:
-                Params.Flags.Info.TiledY = 1;
-                break;
-            case TEST_TILEYF:
-                Params.Flags.Info.TiledY  = 1;
-                Params.Flags.Info.TiledYf = 1;
-                break;
-            case TEST_TILEYS:
+	            if (pGfxAdapterInfo->SkuTable.FtrTileY)
+	            {
+	                Params.Flags.Info.TiledY = 1;
+	            }
+	            else
+	            {
+	                Params.Flags.Info.Tile4 = 1;
+	            }
+	            break;
+        case TEST_TILEYF:
+            Params.Flags.Info.TiledY  = 1;
+            Params.Flags.Info.TiledYf = 1;
+            break;
+        case TEST_TILEYS:
+            if (pGfxAdapterInfo->SkuTable.FtrTileY)
+            {
                 Params.Flags.Info.TiledY  = 1;
                 Params.Flags.Info.TiledYs = 1;
-                break;
-            default: break;
+            }
+            else
+            {
+                Params.Flags.Info.Tile64 = 1;
+            }
+            break;
+        default:
+            break;
         }
     }
 
@@ -221,17 +256,32 @@ protected:
             Params.Flags.Info.TiledX = 1;
             break;
         case TEST_TILEY:
-            Params.Flags.Info.TiledY = 1;
+            if (pGfxAdapterInfo->SkuTable.FtrTileY)
+            {
+                Params.Flags.Info.TiledY = 1;
+            }
+            else
+            {
+                Params.Flags.Info.Tile4 = 1;
+            }
             break;
         case TEST_TILEYF:
             Params.Flags.Info.TiledY = 1;
             Params.Flags.Info.TiledYf = 1;
             break;
         case TEST_TILEYS:
-            Params.Flags.Info.TiledY = 1;
-            Params.Flags.Info.TiledYs = 1;
+            if (pGfxAdapterInfo->SkuTable.FtrTileY)
+            {
+                Params.Flags.Info.TiledY  = 1;
+                Params.Flags.Info.TiledYs = 1;
+            }
+            else
+            {
+                Params.Flags.Info.Tile64 = 1;
+            }
+            break;
+        default:
             break;
-        default: break;
         }
     }
 
@@ -300,12 +350,14 @@ protected:
         uint32_t& ExpectedMCSBpp, uint32_t &MCSHAlign, uint32_t &MCSVAlign)
     {
         const uint32_t MSSTileSize[TEST_TILE_MAX][TEST_BPP_MAX][2] = {
-            { { 64, 1 },{ 64, 1 },{ 64, 1 },{ 64, 1 },{ 64, 1 } },             //Linear - no Tile Size, but min PitchAlign = 64
-            { { 512, 8 },{ 512, 8 },{ 512, 8 },{ 512, 8 },{ 512, 8 } },        //TileX
-            { { 128, 32 },{ 128, 32 },{ 128, 32 },{ 128, 32 },{ 128, 32 } },   //TileY
-            { { 256, 256 },{ 512, 128 },{ 512, 128 },{ 1024, 64 },{ 1024, 64 } },   //TileYs
-            { { 64, 64 },{ 128, 32 },{ 128, 32 },{ 256, 16 },{ 256, 16 } }     //TileYf
-        };
+        {{64, 1}, {64, 1}, {64, 1}, {64, 1}, {64, 1}},                //Linear - no Tile Size, but min PitchAlign = 64
+        {{512, 8}, {512, 8}, {512, 8}, {512, 8}, {512, 8}},           //TileX
+        {{128, 32}, {128, 32}, {128, 32}, {128, 32}, {128, 32}},      //TileY
+        {{256, 256}, {512, 128}, {512, 128}, {1024, 64}, {1024, 64}}, //TileYs
+        {{64, 64}, {128, 32}, {128, 32}, {256, 16}, {256, 16}},       //TileYf
+        {{128, 32}, {128, 32}, {128, 32}, {128, 32}, {128, 32}},      //Tile4
+        {{256, 256}, {512, 128}, {512, 128}, {1024, 64}, {1024, 64}}  //Tile64
+		};
         uint32_t WMul = 1, HMul = 1;
 
         HAlign = 16;                              // RT H/VAlign
@@ -318,10 +370,10 @@ protected:
             MCSHAlign = 4;                            //MCS uses base H/VAlign for 8bpp
         }
 
-        uint32_t Tile[2] = { MSSTileSize[Tiling][Bpp][0], MSSTileSize[Tiling][Bpp][1] };
-        if (Tiling == TEST_TILEYS || Tiling == TEST_TILEYF)
+        uint32_t Tile[2] = {MSSTileSize[Tiling][Bpp][0], MSSTileSize[Tiling][Bpp][1]};
+        if (Tiling == TEST_TILEYS || Tiling == TEST_TILEYF || Tiling == TEST_TILE64)
         {
-            GetInterleaveMSSPattern(MSAA, WMul, HMul);
+            GetInterleaveMSSPattern(MSAA, WMul, HMul, isRT, Bpp);
 
             //Std Tiling interleaves MSAA into 1x, decreasing std Tile size for MSAA'd sample
             //Std Tiling types should have std size alignment always
@@ -353,21 +405,62 @@ protected:
     /// Get the interleave pattern for given Num Samples
     ///
     /// @param[in]  MSAA: Num of Samples
+    /// @param[in]  IsRT: !RT means Depth resource
     /// @param[out] WidthMultiplier: Number of samples arranged side-by-side
     /// @param[out] HeightMultiplier: Number of samples arranged top-bottom
     ///
     /////////////////////////////////////////////////////////////////////////////////////
-    void GetInterleaveMSSPattern(TEST_MSAA MSAA, uint32_t& WidthMultiplier, uint32_t& HeightMultiplier)
+    void GetInterleaveMSSPattern(TEST_MSAA MSAA, uint32_t &WidthMultiplier, uint32_t &HeightMultiplier, bool IsRT, TEST_BPP Bpp)
     {
         WidthMultiplier = 1; HeightMultiplier = 1;
 
         switch (MSAA)
         {
-        case MSAA_2x: WidthMultiplier = 2; break;
-        case MSAA_4x: WidthMultiplier = 2; HeightMultiplier = 2; break;
-        case MSAA_8x: WidthMultiplier = 4; HeightMultiplier = 2; break;
-        case MSAA_16x:WidthMultiplier = 4; HeightMultiplier = 4; break;
-        default: break;
+        case MSAA_2x:
+	            if (IsRT && pGfxAdapterInfo->SkuTable.FtrXe2PlusTiling && (Bpp == TEST_BPP_128))
+	            {
+	                HeightMultiplier = 2;
+	            }
+	            else
+	            {
+	                WidthMultiplier = 2;
+	            }
+                break;
+            case MSAA_4x:
+                WidthMultiplier  = 2;
+                HeightMultiplier = 2;
+                break;
+            case MSAA_8x:
+                WidthMultiplier  = 4;
+                HeightMultiplier = 2;
+	            if (IsRT && pGfxAdapterInfo->SkuTable.FtrXe2PlusTiling && ((Bpp == TEST_BPP_8) || (Bpp == TEST_BPP_32)))
+	            {
+	                WidthMultiplier  = 2;
+	                HeightMultiplier = 4;
+	            }
+	            else if (IsRT && !pGfxAdapterInfo->SkuTable.FtrTileY && !pGfxAdapterInfo->SkuTable.FtrXe2PlusTiling)
+                {
+                    WidthMultiplier  = 2;
+                    HeightMultiplier = 2;
+                }
+                break;
+            case MSAA_16x:
+                WidthMultiplier  = 4;
+                HeightMultiplier = 4;
+	            if (IsRT && pGfxAdapterInfo->SkuTable.FtrXe2PlusTiling && (Bpp == TEST_BPP_64))
+	            {
+	                WidthMultiplier  = 8;
+	                HeightMultiplier = 2;
+	            }
+	            else if (IsRT && !pGfxAdapterInfo->SkuTable.FtrTileY && !pGfxAdapterInfo->SkuTable.FtrXe2PlusTiling)
+                {
+                    WidthMultiplier  = 2;
+                    HeightMultiplier = 2;
+                }
+                break;
+            default:
+                break;
+
         }
     }
 
@@ -529,4 +622,4 @@ public:
 /// @return   Number of tuples in the list
 /// @see      GmmGen9ResourceULT.cpp
 /////////////////////////////////////////////////////////////////////////
-int BuildInputIterator(std::vector<std::tuple<int, int, int, bool, int, int>> &List, int maxTestDimension, int TestArray);
+int BuildInputIterator(std::vector<std::tuple<int, int, int, bool, int, int>> &List, int maxTestDimension, int TestArray, bool XEHPPlus);
diff --git a/Source/GmmLib/ULT/GmmXe2_LPGResourceULT.cpp b/Source/GmmLib/ULT/GmmXe2_LPGResourceULT.cpp
new file mode 100644
index 0000000..bd84c33
--- /dev/null
+++ b/Source/GmmLib/ULT/GmmXe2_LPGResourceULT.cpp
@@ -0,0 +1,248 @@
+/*==============================================================================
+Copyright(c) 2024 Intel Corporation
+
+Permission is hereby granted, free of charge, to any person obtaining a
+copy of this software and associated documentation files(the "Software"),
+to deal in the Software without restriction, including without limitation
+the rights to use, copy, modify, merge, publish, distribute, sublicense,
+and / or sell copies of the Software, and to permit persons to whom the
+Software is furnished to do so, subject to the following conditions:
+
+The above copyright notice and this permission notice shall be included
+in all copies or substantial portions of the Software.
+
+THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
+THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
+OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+OTHER DEALINGS IN THE SOFTWARE.
+============================================================================*/
+
+#include "GmmXe2_LPGResourceULT.h"
+
+using namespace std;
+
+/////////////////////////////////////////////////////////////////////////////////////
+/// Sets up common environment for Resource fixture tests. this is called once per
+/// test case before executing all tests under resource fixture test case.
+//  It also calls SetupTestCase from CommonULT to initialize global context and others.
+///
+///
+/////////////////////////////////////////////////////////////////////////////////////
+void CTestXe2_LPGResource::SetUpTestCase()
+{
+}
+
+/////////////////////////////////////////////////////////////////////////////////////
+/// cleans up once all the tests finish execution.  It also calls TearDownTestCase
+/// from CommonULT to destroy global context and others.
+///
+/////////////////////////////////////////////////////////////////////////////////////
+void CTestXe2_LPGResource::TearDownTestCase()
+{
+}
+
+void CTestXe2_LPGResource::SetUp_Xe2Variant(PRODUCT_FAMILY platform)
+{
+    printf("%s\n", __FUNCTION__);
+
+    if (platform == IGFX_BMG)
+    {
+        GfxPlatform.eProductFamily    = IGFX_BMG;
+        GfxPlatform.eRenderCoreFamily = IGFX_XE2_HPG_CORE;
+    }
+    else if (platform == IGFX_LUNARLAKE)
+    {
+        GfxPlatform.eProductFamily = IGFX_LUNARLAKE;
+        GfxPlatform.eRenderCoreFamily = IGFX_XE2_LPG_CORE;
+    }
+
+    pGfxAdapterInfo = (ADAPTER_INFO*)malloc(sizeof(ADAPTER_INFO));
+    if (pGfxAdapterInfo)
+    {
+        memset(pGfxAdapterInfo, 0, sizeof(ADAPTER_INFO));
+
+        pGfxAdapterInfo->SkuTable.FtrLinearCCS = 1; //legacy y =>0 
+        pGfxAdapterInfo->SkuTable.FtrStandardMipTailFormat = 1;
+        pGfxAdapterInfo->SkuTable.FtrTileY = 0;
+        pGfxAdapterInfo->SkuTable.FtrXe2PlusTiling = 1;
+        pGfxAdapterInfo->SkuTable.FtrXe2Compression = 1;
+        pGfxAdapterInfo->SkuTable.FtrFlatPhysCCS = 1;
+        pGfxAdapterInfo->SkuTable.FtrLocalMemory = 0;
+        pGfxAdapterInfo->SkuTable.FtrDiscrete = 0;
+        pGfxAdapterInfo->SkuTable.FtrE2ECompression = 1;
+
+        if (platform == IGFX_BMG)
+        {
+            pGfxAdapterInfo->SkuTable.FtrLocalMemory = 1;
+            pGfxAdapterInfo->SkuTable.FtrDiscrete    = 1;
+        }
+
+        if (platform == IGFX_LUNARLAKE || platform == IGFX_BMG)
+        {
+            pGfxAdapterInfo->WaTable.Wa_14018976079           = 1;
+            pGfxAdapterInfo->WaTable.Wa_14018984349           = 1;
+            pGfxAdapterInfo->SkuTable.FtrL3TransientDataFlush = 1;
+        }
+
+        CommonULT::SetUpTestCase();
+    }
+}
+
+void CTestXe2_LPGResource::TearDown_Xe2Variant()
+{
+    printf("%s\n", __FUNCTION__);
+    CommonULT::TearDownTestCase();
+}
+
+TEST_F(CTestXe2_LPGResource, TestMSAA_BMG)
+{
+    SetUp_Xe2Variant(IGFX_BMG);
+    TestMSAA();
+    TearDown_Xe2Variant();
+}
+
+TEST_F(CTestXe2_LPGResource, TestMSAA_LNL)
+{
+    SetUp_Xe2Variant(IGFX_LUNARLAKE);
+    TestMSAA();
+    TearDown_Xe2Variant();
+}
+
+/// @brief ULT for MSAA Resource - Depth and Colour MSAA verification for Tile64 resources
+//  Note: Verify with and without FtrXe2PlusTiling in Setup, Default: FtrXe2PlusTiling
+void CTestXe2_LPGResource::TestMSAA()
+{	
+    GMM_GFX_SIZE_T AuxCC, AuxCCS, AuxMCS;
+    const uint32_t TestDimensions[4][2] = {
+    //Input dimensions in #Tiles
+    {16, 4},    //occupies single tile for Depth for all MSAAs and BPPs, multiple tiles for colours
+    {128, 128}, // crosses a tile for > 4X MSAA for depth
+    {128, 257}, // Crosses a tile in Y direction and for >4X MSAA, crosses in X direction too for depth
+    {1, 1},
+    };
+
+    uint32_t TestArraySize[2] = {1, 5};
+    uint32_t MinPitch         = 32;
+
+    uint32_t HAlign, VAlign, TileDimX, TileDimY, MCSHAlign, MCSVAlign, TileSize;
+    uint32_t ExpectedMCSBpp;
+    std::vector<tuple<int, int, int, bool, int, int>> List; //TEST_TILE_TYPE, TEST_BPP, TEST_RESOURCE_TYPE, Depth or RT, TestDimension index, ArraySize
+    auto Size = BuildInputIterator(List, 4, 2, true);       // Size of arrays TestDimensions, TestArraySize
+
+    for(auto element : List)
+    {
+        GMM_RESCREATE_PARAMS gmmParams = {};
+        gmmParams.Flags.Info           = {0};
+
+        TEST_TILE_TYPE     Tiling     = (TEST_TILE_TYPE)std::get<0>(element);
+        TEST_BPP           Bpp        = (TEST_BPP)std::get<1>(element);
+        TEST_RESOURCE_TYPE ResType    = (TEST_RESOURCE_TYPE)std::get<2>(element);
+        bool               IsRT       = std::get<3>(element); // True for RT, False for Depth
+        int                TestDimIdx = std::get<4>(element); //index into TestDimensions array
+        int                ArrayIdx   = std::get<5>(element); //index into TestArraySize
+        TileSize                      = (Tiling == TEST_TILE64) ? GMM_KBYTE(64) : GMM_KBYTE(4);
+
+        //Discard un-supported Tiling/Res_type/bpp for this test
+        if((ResType != TEST_RESOURCE_2D) || //No 1D/3D/Cube. Supported 2D mip-maps/array
+                                            // depth tested outside this function due to diff in halign/valign
+           (Tiling != TEST_TILE64))         // MSAA not supported on Tile4
+            continue;
+
+        SetTileFlag(gmmParams, Tiling);
+        SetResType(gmmParams, ResType);
+        SetResGpuFlags(gmmParams, IsRT);
+        SetResArraySize(gmmParams, TestArraySize[ArrayIdx]);
+
+        gmmParams.NoGfxMemory = 1;
+        gmmParams.Format      = SetResourceFormat(Bpp);
+        for(uint32_t k = MSAA_2x; k <= MSAA_16x; k++)
+        {
+            GetAlignmentAndTileDimensionsForMSAA(Bpp, IsRT, Tiling, (TEST_MSAA)k,
+                                                 TileDimX, TileDimY, HAlign, VAlign,
+                                                 ExpectedMCSBpp, MCSHAlign, MCSVAlign);
+            gmmParams.BaseWidth64     = TestDimensions[TestDimIdx][0] * (unsigned int)pow(2.0, Bpp);
+            gmmParams.BaseHeight                   = TestDimensions[TestDimIdx][1];
+            gmmParams.Depth                        = 0x1;
+            gmmParams.MSAA.NumSamples              = static_cast<uint32_t>(pow((double)2, k));
+            gmmParams.Flags.Gpu.MCS                = 1;
+            gmmParams.Flags.Gpu.CCS                = 1;
+            gmmParams.Flags.Gpu.UnifiedAuxSurface  = 1;
+            gmmParams.Flags.Gpu.IndirectClearColor = 1;
+            //MSS surface
+            GMM_RESOURCE_INFO *MSSResourceInfo;
+            MSSResourceInfo = pGmmULTClientContext->CreateResInfoObject(&gmmParams);
+
+            if(MSSResourceInfo)
+            {
+                VerifyResourceHAlign<true>(MSSResourceInfo, HAlign);
+                VerifyResourceVAlign<true>(MSSResourceInfo, VAlign);
+
+                if (gmmParams.Flags.Gpu.IndirectClearColor && pGfxAdapterInfo->SkuTable.FtrXe2Compression && (gmmParams.MSAA.NumSamples > 1))
+                {
+                    AuxCC  = MSSResourceInfo->GetUnifiedAuxSurfaceOffset(GMM_AUX_CC);
+                    AuxMCS = MSSResourceInfo->GetUnifiedAuxSurfaceOffset(GMM_AUX_MCS);
+                    AuxCCS = MSSResourceInfo->GetUnifiedAuxSurfaceOffset(GMM_AUX_CCS);
+
+                    EXPECT_EQ(AuxCC, AuxMCS);
+                    EXPECT_EQ(AuxCCS, 0);
+
+                    AuxCC  = MSSResourceInfo->GetSizeAuxSurface(GMM_AUX_CC);
+                    AuxMCS = MSSResourceInfo->GetSizeAuxSurface(GMM_AUX_MCS);
+                    AuxCCS = MSSResourceInfo->GetSizeAuxSurface(GMM_AUX_CCS);
+
+                    EXPECT_EQ(AuxCC, AuxMCS);
+                    EXPECT_EQ(AuxCCS, 0);
+                }
+                if(IsRT) //Arrayed MSS
+                {
+                    uint32_t ExpectedPitch = 0, ExpectedQPitch = 0, ExpectedHeight = 0;
+                    ExpectedPitch = GMM_ULT_ALIGN(GMM_ULT_ALIGN(gmmParams.BaseWidth64, HAlign) * (unsigned int)pow(2.0, Bpp), TileDimX); // Aligned width * bpp, aligned to TileWidth
+                    ExpectedPitch = GFX_MAX(ExpectedPitch, MinPitch);
+                    VerifyResourcePitch<true>(MSSResourceInfo, ExpectedPitch);
+                    if(Tiling != TEST_LINEAR)
+                        VerifyResourcePitchInTiles<true>(MSSResourceInfo, ExpectedPitch / TileDimX);
+
+                    ExpectedQPitch = GMM_ULT_ALIGN(gmmParams.BaseHeight, VAlign);
+                    if(gmmParams.ArraySize > 1) //Gen9: Qpitch is distance between array slices (not sample slices)
+                    {
+                        VerifyResourceQPitch<true>(MSSResourceInfo, ExpectedQPitch);
+                    }
+
+                    ExpectedHeight = GMM_ULT_ALIGN(ExpectedQPitch * gmmParams.MSAA.NumSamples * gmmParams.ArraySize, TileDimY); // For Tile64 layout prior to Xe2Tiling, MSAA8x and 16x follows MSAA4x. MSAA4x*2 for MSAA8x and MSAA4x*4 for MSAA16x.
+                                                                                                                                // Height getting multiplied by numsamples here is good enough for these special layouts too
+                    VerifyResourceSize<true>(MSSResourceInfo, GMM_ULT_ALIGN(ExpectedPitch * ExpectedHeight, TileSize));
+                }
+                else
+                {
+                    uint32_t WidthMultiplier, HeightMultiplier;
+                    GetInterleaveMSSPattern((TEST_MSAA)k, WidthMultiplier, HeightMultiplier, IsRT, Bpp);
+                    gmmParams.BaseWidth64 = WidthMultiplier > 1 ? GMM_ULT_ALIGN(gmmParams.BaseWidth64, 2) : gmmParams.BaseWidth64;
+                    gmmParams.BaseHeight  = HeightMultiplier > 1 ? GMM_ULT_ALIGN(gmmParams.BaseHeight, 2) : gmmParams.BaseHeight;
+
+                    uint32_t ExpectedPitch = GMM_ULT_ALIGN(GMM_ULT_ALIGN(gmmParams.BaseWidth64 * WidthMultiplier, HAlign) * (uint32_t)pow(2.0, Bpp), TileDimX);
+                    VerifyResourcePitch<true>(MSSResourceInfo, ExpectedPitch);
+                    if(Tiling != TEST_LINEAR)
+                    {
+                        VerifyResourcePitchInTiles<true>(MSSResourceInfo, ExpectedPitch / TileDimX);
+                    }
+
+                    uint64_t ExpectedQPitch    = GMM_ULT_ALIGN(gmmParams.BaseHeight * HeightMultiplier, VAlign);
+                    uint32_t ExpandedArraySize = gmmParams.ArraySize * (((MSSResourceInfo->GetTileType() == GMM_TILED_64) && !pGfxAdapterInfo->SkuTable.FtrTileY && !pGfxAdapterInfo->SkuTable.FtrXe2PlusTiling && (gmmParams.MSAA.NumSamples == 16)) ? 4 : // MSAA x8/x16 stored as pseudo array planes each with 4x samples
+                                                                        ((MSSResourceInfo->GetTileType() == GMM_TILED_64) && !pGfxAdapterInfo->SkuTable.FtrTileY && !pGfxAdapterInfo->SkuTable.FtrXe2PlusTiling && (gmmParams.MSAA.NumSamples == 8)) ? 2 : 1);
+                    if(ExpandedArraySize > 1)
+                    {
+                        VerifyResourceQPitch<true>(MSSResourceInfo, ExpectedQPitch);
+                    }
+                    uint64_t ExpectedHeight = GMM_ULT_ALIGN(ExpectedQPitch * ExpandedArraySize, TileDimY);              //Align Height = ExpectedQPitch*ArraySize, to Tile-Height
+                    VerifyResourceSize<true>(MSSResourceInfo, GMM_ULT_ALIGN(ExpectedPitch * ExpectedHeight, TileSize)); //ExpectedPitch *ExpectedHeight
+                }
+            }
+
+            pGmmULTClientContext->DestroyResInfoObject(MSSResourceInfo);
+        } //NumSamples = k
+    }     //Iterate through all Input types{
+
+}
diff --git a/Source/GmmLib/ULT/GmmXe2_LPGResourceULT.h b/Source/GmmLib/ULT/GmmXe2_LPGResourceULT.h
new file mode 100644
index 0000000..4d204ab
--- /dev/null
+++ b/Source/GmmLib/ULT/GmmXe2_LPGResourceULT.h
@@ -0,0 +1,38 @@
+/*==============================================================================
+Copyright(c) 2024 Intel Corporation
+
+Permission is hereby granted, free of charge, to any person obtaining a
+copy of this software and associated documentation files(the "Software"),
+to deal in the Software without restriction, including without limitation
+the rights to use, copy, modify, merge, publish, distribute, sublicense,
+and / or sell copies of the Software, and to permit persons to whom the
+Software is furnished to do so, subject to the following conditions:
+
+The above copyright notice and this permission notice shall be included
+in all copies or substantial portions of the Software.
+
+THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
+THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
+OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+OTHER DEALINGS IN THE SOFTWARE.
+============================================================================*/
+
+#pragma once
+
+#include "GmmGen12dGPUResourceULT.h"
+
+class CTestXe2_LPGResource : public CTestGen12dGPUResource
+{
+
+protected:
+    virtual void SetUp_Xe2Variant(PRODUCT_FAMILY platform);
+    virtual void TearDown_Xe2Variant();
+    virtual void TestMSAA();
+
+public:
+    static void SetUpTestCase();
+    static void TearDownTestCase();
+};
\ No newline at end of file
diff --git a/Source/GmmLib/ULT/GmmXe_LPGCachePolicyULT.cpp b/Source/GmmLib/ULT/GmmXe_LPGCachePolicyULT.cpp
index dd3a9fa..3e66bc3 100644
--- a/Source/GmmLib/ULT/GmmXe_LPGCachePolicyULT.cpp
+++ b/Source/GmmLib/ULT/GmmXe_LPGCachePolicyULT.cpp
@@ -48,7 +48,18 @@ void CTestXe_LPGCachePolicy::SetUpXe_LPGVariant(PRODUCT_FAMILY platform)
 
     GfxPlatform.eProductFamily = platform;
 
-    GfxPlatform.eRenderCoreFamily = IGFX_XE_HPG_CORE;
+    if (platform == IGFX_LUNARLAKE)
+    {
+        GfxPlatform.eRenderCoreFamily = IGFX_XE2_LPG_CORE;
+    }
+    else if (platform >= IGFX_BMG)
+    {
+        GfxPlatform.eRenderCoreFamily = IGFX_XE2_HPG_CORE;
+    }
+    else
+    {
+        GfxPlatform.eRenderCoreFamily = IGFX_XE_HPG_CORE;
+    }
 
     pGfxAdapterInfo = (ADAPTER_INFO *)malloc(sizeof(ADAPTER_INFO));
     if(pGfxAdapterInfo)
@@ -59,7 +70,24 @@ void CTestXe_LPGCachePolicy::SetUpXe_LPGVariant(PRODUCT_FAMILY platform)
         pGfxAdapterInfo->SkuTable.FtrStandardMipTailFormat = 1;
         pGfxAdapterInfo->SkuTable.FtrTileY                 = 0;
         pGfxAdapterInfo->SkuTable.FtrLocalMemory           = 0;
+        pGfxAdapterInfo->SkuTable.FtrDiscrete              = 0;
         pGfxAdapterInfo->SkuTable.FtrIA32eGfxPTEs          = 1;
+        pGfxAdapterInfo->SkuTable.FtrL4Cache               = 1;
+        pGfxAdapterInfo->SkuTable.FtrL3TransientDataFlush  = 0;
+
+        if (platform == IGFX_BMG)
+        {
+            pGfxAdapterInfo->SkuTable.FtrLocalMemory = 1;
+            pGfxAdapterInfo->SkuTable.FtrDiscrete    = 1;
+        }
+
+        if (platform >= IGFX_BMG)
+        {
+            pGfxAdapterInfo->SkuTable.FtrL3TransientDataFlush = 1;
+	    pGfxAdapterInfo->WaTable.Wa_14018976079           = 1;
+	    pGfxAdapterInfo->WaTable.Wa_14018984349           = 1;
+	}
+
         CommonULT::SetUpTestCase();
     }
 }
@@ -80,6 +108,26 @@ TEST_F(CTestXe_LPGCachePolicy, TestXe_LPGCachePolicy_FtrL4CacheEnabled)
     TearDownXe_LPGVariant();
 }
 
+/***********************Xe2_HPG***********************************/
+TEST_F(CTestXe_LPGCachePolicy, TestXe2_HPGCachePolicy_FtrL4CacheEnabled)
+{
+    SetUpXe_LPGVariant(IGFX_BMG);
+    CheckXe2_HPGVirtualL3CachePolicy();
+    CheckPAT(); // Has both L3 and PAT within
+    Check_Xe2_HPG_PATCompressed();
+
+    TearDownXe_LPGVariant();
+}
+TEST_F(CTestXe_LPGCachePolicy, TestXe2_LPGCachePolicy_FtrL4CacheEnabled)
+{
+    SetUpXe_LPGVariant(IGFX_LUNARLAKE);
+
+    CheckXe2_HPGVirtualL3CachePolicy();
+    CheckPAT(); // Has both L3 and PAT within
+    Check_Xe2_HPG_PATCompressed();
+
+    TearDownXe_LPGVariant();
+}
 void CTestXe_LPGCachePolicy::CheckVirtualL3CachePolicy()
 {
     const uint32_t L4_WB_CACHEABLE = 0x0;
@@ -100,7 +148,7 @@ void CTestXe_LPGCachePolicy::CheckVirtualL3CachePolicy()
     for(uint32_t Usage = GMM_RESOURCE_USAGE_UNKNOWN; Usage < GMM_RESOURCE_USAGE_MAX; Usage++)
     {
         GMM_CACHE_POLICY_ELEMENT     ClientRequest   = pGmmULTClientContext->GetCachePolicyElement((GMM_RESOURCE_USAGE_TYPE)Usage);
-        uint32_t                AssignedMocsIdx = ClientRequest.MemoryObjectOverride.Gen12.Index;
+        uint32_t                AssignedMocsIdx = ClientRequest.MemoryObjectOverride.XE_LPG.Index;
         GMM_CACHE_POLICY_TBL_ELEMENT Mocs            = pGmmULTClientContext->GetCachePolicyTlbElement(AssignedMocsIdx);
         uint32_t                     StartMocsIdx    = 0;
 
@@ -118,7 +166,7 @@ void CTestXe_LPGCachePolicy::CheckVirtualL3CachePolicy()
         //printf("Xe LPG: Usage: %d --> Index: [%d]\n", Usage, AssignedMocsIdx);
 
         //L3
-        if(ClientRequest.L3)
+        if (ClientRequest.L3CC)
         {
             EXPECT_EQ(L3_WB_CACHEABLE, Mocs.L3.Cacheability) << "Usage# " << Usage << ": Incorrect L3 cachebility setting";
         }
@@ -127,8 +175,7 @@ void CTestXe_LPGCachePolicy::CheckVirtualL3CachePolicy()
             EXPECT_EQ(L3_UNCACHEABLE, Mocs.L3.Cacheability) << "Usage# " << Usage << ": Incorrect L3 cachebility setting";
         }
 
-        //L4
-        // ADM memory cache 0: UC, 1:WB, 2: WT
+        // L4 cache memory- 0: UC, 1:WB, 2: WT
         switch(ClientRequest.L4CC)
         {
             case 0x1:
@@ -163,3 +210,91 @@ void CTestXe_LPGCachePolicy::CheckPAT()
     }
 }
 
+void CTestXe_LPGCachePolicy::Check_Xe2_HPG_PATCompressed()
+{
+    bool CompressionEnReq = true;
+
+    // Check Usage PAT index against PAT settings
+    for (uint32_t Usage = GMM_RESOURCE_USAGE_UNKNOWN; Usage < GMM_RESOURCE_USAGE_MAX; Usage++)
+    {
+        GMM_CACHE_POLICY_ELEMENT ClientRequest = pGmmULTClientContext->GetCachePolicyElement((GMM_RESOURCE_USAGE_TYPE)Usage);
+        CompressionEnReq                       = true;
+        if (ClientRequest.Initialized == false) // undefined resource in platform
+        {
+            continue;
+        }
+        uint32_t PATIndex = pGmmULTClientContext->CachePolicyGetPATIndex(NULL, (GMM_RESOURCE_USAGE_TYPE)Usage, &CompressionEnReq, false);
+        //printf("Xe HPG: Usage: %d --> Compressed PAT Index: [%d], ComEn: [%d]\n", Usage, PATIndex, CompressionEnReq);
+        EXPECT_NE(PATIndex, GMM_PAT_ERROR) << "Usage# " << Usage << ": No matching PAT Index";
+    }
+}
+
+void CTestXe_LPGCachePolicy::CheckXe2_HPGVirtualL3CachePolicy()
+{
+    const uint32_t L4_WB_CACHEABLE = 0x0;
+    const uint32_t L4_WT_CACHEABLE = 0x1;
+    const uint32_t L4_UNCACHEABLE  = 0x3;
+
+    const uint32_t L3_WB_CACHEABLE = 0x0;
+    const uint32_t L3_XD_CACHEABLE = pGmmULTClientContext->GetSkuTable().FtrL3TransientDataFlush ? 0x1 : 0x0;
+    const uint32_t L3_UNCACHEABLE  = 0x3;
+
+    // Check Usage MOCS index against MOCS settings
+    for (uint32_t Usage = GMM_RESOURCE_USAGE_UNKNOWN; Usage < GMM_RESOURCE_USAGE_MAX; Usage++)
+    {
+        GMM_CACHE_POLICY_ELEMENT     ClientRequest   = pGmmULTClientContext->GetCachePolicyElement((GMM_RESOURCE_USAGE_TYPE)Usage);
+        uint32_t                     AssignedMocsIdx = ClientRequest.MemoryObjectOverride.XE_HP.Index;
+        GMM_CACHE_POLICY_TBL_ELEMENT Mocs            = pGmmULTClientContext->GetCachePolicyTlbElement(AssignedMocsIdx);
+        uint32_t                     StartMocsIdx    = 0;
+
+        EXPECT_EQ(0, Mocs.L3.PhysicalL3.Reserved) << "Usage# " << Usage << ": Reserved field is non-zero";
+        EXPECT_EQ(0, Mocs.L3.PhysicalL3.Reserved0) << "Usage# " << Usage << ": Reserved field is non-zero";
+        EXPECT_EQ(0, Mocs.L3.PhysicalL3.L3CLOS) << "Usage# " << Usage << ": L3CLOS field is non-zero";
+        // Check if Mocs Index is not greater than GMM_MAX_NUMBER_MOCS_INDEXES
+        EXPECT_GT(GMM_XE2_NUM_MOCS_ENTRIES, AssignedMocsIdx) << "Usage# " << Usage << ": MOCS Index greater than MAX allowed (16)";
+
+        //printf("Xe HPG: Usage: %d --> Index: [%d]\n", Usage, AssignedMocsIdx);
+
+        if (ClientRequest.IgnorePAT == true)
+        {
+            EXPECT_EQ(1, Mocs.L3.PhysicalL3.igPAT) << "Usage# " << Usage << ": Incorrect igPAT cachebility setting";
+
+            // L4  memory cache 0: UC, 1:WB, 2: WT
+            switch (ClientRequest.L4CC)
+            {
+            case 0x1:
+                {
+                    EXPECT_EQ(L4_WB_CACHEABLE, Mocs.L3.PhysicalL3.L4CC) << "Usage# " << Usage << ": Incorrect L4CC cachebility setting";
+                    break;
+                }
+            case 0x2:
+                {
+                    EXPECT_EQ(L4_WT_CACHEABLE, Mocs.L3.PhysicalL3.L4CC) << "Usage# " << Usage << ": Incorrect L4CC cachebility setting";
+                    break;
+                }
+            default:
+                EXPECT_EQ(L4_UNCACHEABLE, Mocs.L3.PhysicalL3.L4CC) << "Usage# " << Usage << ": Incorrect L4CC cachebility setting";
+            }
+
+            // 0:UC, 1:WB  2:WB_T_Display, 3:WB_T_App
+            switch (ClientRequest.L3CC)
+            {
+
+            case 0x1:
+                EXPECT_EQ(L3_WB_CACHEABLE, Mocs.L3.PhysicalL3.L3CC) << "Usage# " << Usage << ": Incorrect L3CC cachebility setting";
+                break;
+            case 0x3:
+                {
+                    EXPECT_EQ(L3_XD_CACHEABLE, Mocs.L3.PhysicalL3.L3CC) << "Usage# " << Usage << ": Incorrect L3CC cachebility setting";
+                    break;
+                }
+            default:
+                EXPECT_EQ(L3_UNCACHEABLE, Mocs.L3.PhysicalL3.L3CC) << "Usage# " << Usage << ": Incorrect L3CC cachebility setting";
+            }
+        }
+        else
+        {
+            EXPECT_EQ(0, Mocs.L3.PhysicalL3.igPAT) << "Usage# " << Usage << ": Incorrect igPAT cachebility setting";
+        }
+    }
+}
diff --git a/Source/GmmLib/ULT/GmmXe_LPGCachePolicyULT.h b/Source/GmmLib/ULT/GmmXe_LPGCachePolicyULT.h
index 67d1404..7e796cb 100644
--- a/Source/GmmLib/ULT/GmmXe_LPGCachePolicyULT.h
+++ b/Source/GmmLib/ULT/GmmXe_LPGCachePolicyULT.h
@@ -30,6 +30,8 @@ protected:
     virtual void TearDownXe_LPGVariant();
     virtual void CheckVirtualL3CachePolicy();
     virtual void CheckPAT();
+    virtual void Check_Xe2_HPG_PATCompressed();
+    virtual void CheckXe2_HPGVirtualL3CachePolicy();
 
 public:
     static void SetUpTestCase();
diff --git a/Source/GmmLib/Utility/CpuSwizzleBlt/CpuSwizzleBlt.c b/Source/GmmLib/Utility/CpuSwizzleBlt/CpuSwizzleBlt.c
index cd87809..e090fd6 100644
--- a/Source/GmmLib/Utility/CpuSwizzleBlt/CpuSwizzleBlt.c
+++ b/Source/GmmLib/Utility/CpuSwizzleBlt/CpuSwizzleBlt.c
@@ -132,6 +132,24 @@ spatial locality for 3D or MSAA sample neighbors can be controlled, also. */
         }               Mask;
     }               SWIZZLE_DESCRIPTOR;
 
+    typedef enum _EXTERNAL_SWIZZLE_NAME
+    {
+        TILEX = 0,
+        TILEY,
+        TILEW,
+        TILEYS,
+        TILEYF
+    }EXTERNAL_SWIZZLE_NAME;
+
+    typedef enum  _EXTERNAL_RES_TYPE{
+        Res_2D = 0,
+        Res_3D = 1,
+        MSAA_2X,
+        MSAA_4X,
+        MSAA_8X,
+        MSAA_16X
+    }EXTERNAL_RES_TYPE;
+
     // Definition Helper Macros...
     #define X ,'x'
     #define Y ,'y'
@@ -257,6 +275,39 @@ spatial locality for 3D or MSAA sample neighbors can be controlled, also. */
     SWIZZLE(( INTEL_TILE_64_3D_16       Z Z Z Y Y X Z Y Z X Y Y X X X X ));
     SWIZZLE(( INTEL_TILE_64_3D_8        Z Z Z X Y Y Z Y Z X Y Y X X X X ));
 
+    //Tile64 updated layout for Render Compression 256B and Physical L3
+
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA2_128   Y X X X Y Y X S X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA2_64    Y Y X X Y Y X S X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA2_32    Y Y Y X Y Y X S X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA2_16    Y Y Y X Y Y X S X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA2_8     Y Y Y Y Y Y X S X X Y Y X X X X ));
+
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA4_128   Y X X X Y Y S S X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA4_64    Y X X X Y Y S S X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA4_32    Y Y X X Y Y S S X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA4_16    Y Y X X Y Y S S X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA4_8     Y Y Y X Y Y S S X X Y Y X X X X ));
+
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA8_128   Y Y X X Y X S S S X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA8_64    Y Y X X Y X S S S X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA8_32    Y Y X X Y X S S S X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA8_16    Y Y Y X Y X S S S X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA8_8     Y Y Y X Y X S S S X Y Y X X X X ));
+
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA16_128   Y X X X Y X S S S S Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA16_64    Y Y X X Y X S S S S Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA16_32    Y Y X X Y X S S S S Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA16_16    Y Y X X Y X S S S S Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_MSAA16_8     Y Y Y X Y X S S S S Y Y X X X X ));
+
+    SWIZZLE(( INTEL_TILE_64_V2_3D_128      Z Z Y X X Y Z Z X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_3D_64       Z Z Y X X Y Z Z X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_3D_32       Z Z Y X Y Y Z Z X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_3D_16       Z Z Z Y Y Y Z Z X X Y Y X X X X ));
+    SWIZZLE(( INTEL_TILE_64_V2_3D_8        Z Z Z Y Y Y Z Z X X Y Y X X X X ));
+
+
     #undef X
     #undef Y
     #undef Z
diff --git a/Source/GmmLib/Utility/GmmUtility.h b/Source/GmmLib/Utility/GmmUtility.h
index b65b3dd..4e15404 100644
--- a/Source/GmmLib/Utility/GmmUtility.h
+++ b/Source/GmmLib/Utility/GmmUtility.h
@@ -42,7 +42,8 @@ namespace GmmLib
     #define GMM_FREE(p)         free(p)
 
 #define GMM_COMPR_FORMAT_INVALID(pGmmLibContext)                                                                          \
-     ((pGmmLibContext->GetSkuTable().FtrFlatPhysCCS != 0)    ? static_cast<uint8_t>(GMM_FLATCCS_FORMAT_INVALID) :          \
+    ((pGmmLibContext->GetSkuTable().FtrXe2Compression != 0) ? static_cast<uint8_t>(GMM_XE2_UNIFIED_COMP_FORMAT_INVALID) : \
+     (pGmmLibContext->GetSkuTable().FtrFlatPhysCCS != 0)    ? static_cast<uint8_t>(GMM_FLATCCS_FORMAT_INVALID) :          \
                                                               static_cast<uint8_t>(GMM_E2ECOMP_FORMAT_INVALID))
 
 #else
diff --git a/Source/GmmLib/inc/External/Common/CachePolicy/GmmCachePolicyXe2_LPG.h b/Source/GmmLib/inc/External/Common/CachePolicy/GmmCachePolicyXe2_LPG.h
new file mode 100644
index 0000000..c3e5a3a
--- /dev/null
+++ b/Source/GmmLib/inc/External/Common/CachePolicy/GmmCachePolicyXe2_LPG.h
@@ -0,0 +1,104 @@
+/*==============================================================================
+Copyright(c) 2024 Intel Corporation
+Permission is hereby granted, free of charge, to any person obtaining a
+copy of this software and associated documentation files(the "Software"),
+to deal in the Software without restriction, including without limitation
+the rights to use, copy, modify, merge, publish, distribute, sublicense,
+and / or sell copies of the Software, and to permit persons to whom the
+Software is furnished to do so, subject to the following conditions:
+
+The above copyright notice and this permission notice shall be included
+in all copies or substantial portions of the Software.
+
+THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
+THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
+OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+OTHER DEALINGS IN THE SOFTWARE.
+============================================================================*/
+
+#pragma once
+
+#ifdef __cplusplus
+#include "../GmmCachePolicyCommon.h"
+
+#define GMM_XE2_NUM_MOCS_ENTRIES  (16)
+#define GMM_XE2_DEFAULT_PAT_INDEX (PAT2)
+
+
+#ifdef __cplusplus
+extern "C" {
+#endif /*__cplusplus*/
+
+typedef enum GMM_GFX_PHY_L4_MEMORY_TYPE_REC
+{
+    GMM_GFX_PHY_L4_MT_WB = 0x0,
+    GMM_GFX_PHY_L4_MT_WT = 0x1,
+    GMM_GFX_PHY_L4_MT_UC = 0x3,
+} GMM_GFX_PHY_L4_MEMORY_TYPE;
+
+typedef enum GMM_GFX_PHY_L3_MEMORY_TYPE_REC
+{
+    GMM_GFX_PHY_L3_MT_WB    = 0x0,
+    GMM_GFX_PHY_L3_MT_WB_XD = 0x1, // Transient Flush Display
+    GMM_GFX_PHY_L3_MT_UC    = 0x3,
+} GMM_GFX_PHY_L3_MEMORY_TYPE;
+
+typedef enum GMM_GFX_PHY_CACHE_COHERENCY_TYPE_REC
+{
+    GMM_GFX_PHY_NON_COHERENT_NO_SNOOP         = 0x0,
+    GMM_GFX_PHY_NON_COHERENT                  = 0x1,
+    GMM_GFX_PHY_COHERENT_ONE_WAY_IA_SNOOP     = 0x2,
+    GMM_GFX_PHY_COHERENT_TWO_WAY_IA_GPU_SNOOP = 0x3
+} GMM_GFX_PHY_CACHE_COHERENCY_TYPE;
+
+typedef union GMM_XE2_PRIVATE_PAT_REC
+{
+    struct
+    {
+        uint32_t Coherency            : 2;
+        uint32_t L4CC                 : 2;
+        uint32_t L3CC                 : 2;
+        uint32_t L3CLOS               : 2;
+        uint32_t Reserved1            : 1;
+        uint32_t LosslessCompressionEn: 1;
+        uint32_t Reserved2            : 22;
+    } Xe2;
+    uint32_t Value;
+} GMM_XE2_PRIVATE_PAT;
+
+namespace GmmLib
+{
+    class NON_PAGED_SECTION GmmXe2_LPGCachePolicy : public GmmXe_LPGCachePolicy
+    {
+    protected:
+
+    public:
+        /* Constructors */
+        GmmXe2_LPGCachePolicy(GMM_CACHE_POLICY_ELEMENT *pCachePolicyContext, Context *pGmmLibContext)
+            : GmmXe_LPGCachePolicy(pCachePolicyContext, pGmmLibContext)
+        {
+            NumPATRegisters     = GMM_NUM_PAT_ENTRIES;
+            NumMOCSRegisters    = GMM_XE2_NUM_MOCS_ENTRIES;
+            CurrentMaxPATIndex  = 0;
+            CurrentMaxMocsIndex = 0;
+        }
+        virtual ~GmmXe2_LPGCachePolicy()
+        {
+        }
+
+        /* Function prototypes */
+        GMM_STATUS           InitCachePolicy();
+        GMM_STATUS           SetupPAT();
+        void                 SetUpMOCSTable();
+        void                 GetL3L4(GMM_CACHE_POLICY_TBL_ELEMENT *pUsageEle, GMM_XE2_PRIVATE_PAT *pUsagePATElement, uint32_t Usage);
+        uint32_t GMM_STDCALL CachePolicyGetPATIndex(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage, bool *pCompressionEnable, bool IsCpuCacheable);
+    };
+} // namespace GmmLib
+#endif // #ifdef __cplusplus
+
+#ifdef __cplusplus
+}
+#endif /* end__cplusplus*/
diff --git a/Source/GmmLib/inc/External/Common/CachePolicy/GmmCachePolicyXe_LPG.h b/Source/GmmLib/inc/External/Common/CachePolicy/GmmCachePolicyXe_LPG.h
index 0dd78e5..e700317 100644
--- a/Source/GmmLib/inc/External/Common/CachePolicy/GmmCachePolicyXe_LPG.h
+++ b/Source/GmmLib/inc/External/Common/CachePolicy/GmmCachePolicyXe_LPG.h
@@ -52,6 +52,11 @@ namespace GmmLib
             uint32_t GMM_STDCALL CachePolicyGetPATIndex(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage, bool *pCompressionEnable, bool IsCpuCacheable);
             GMM_STATUS SetupPAT();
             void       SetUpMOCSTable();
-    };
+            void GMM_STDCALL                                SetL1CachePolicy(uint32_t Usage);
+            virtual uint32_t GMM_STDCALL                    GetSurfaceStateL1CachePolicy(GMM_RESOURCE_USAGE_TYPE Usage);
+            virtual MEMORY_OBJECT_CONTROL_STATE GMM_STDCALL CachePolicyGetMemoryObject(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage);
+
+};
+
 }
 #endif // #ifdef __cplusplus
diff --git a/Source/GmmLib/inc/External/Common/GmmCachePolicy.h b/Source/GmmLib/inc/External/Common/GmmCachePolicy.h
index 099453b..1b9ab9a 100644
--- a/Source/GmmLib/inc/External/Common/GmmCachePolicy.h
+++ b/Source/GmmLib/inc/External/Common/GmmCachePolicy.h
@@ -58,12 +58,16 @@ typedef struct GMM_CACHE_POLICY_ELEMENT_REC
             uint64_t                   L1CC        : 3; // L1 Cache Control
 	    uint64_t                   Initialized : 1;
             uint64_t                   L2CC        : 2; // media internal cache 0:UC, 1:WB
-            uint64_t                   L4CC        : 2; // ADM memory cache 0: UC, 1:WB, 2: WT
+            uint64_t                   L4CC        : 2; // L4 memory cache 0: UC, 1:WB, 2: WT
             uint64_t                   Coherency   : 2; // 0 non-coh, 1: 1 way coh IA snoop 2: 2 way coh IA GPU snopp
 	    uint64_t                   CoherentPATIndex : 5;
-	    uint64_t                   Reserved    : 23;
-
-	};
+            uint64_t CoherentPATIndexHigherBit     : 1; // From Xe2 onwards it requires 6 bit to represent PATIndex. Hence using this single bit (MSB) as extension of the above field CoherentPATIndex:5
+            uint64_t PATIndexCompressed            : 6;	    
+            uint64_t L3CC                          : 2; // 0:UC, 1:WB  2:WB_T_Display, 3:WB_T_App
+            uint64_t L3CLOS                        : 2; // Class of service
+	    uint64_t IgnorePAT                     : 1; // Ignore PAT 1 = Override by MOCS, 0 = Defer to PAT
+	    uint64_t Reserved                      : 11;
+       };
         uint64_t Value;    
     };
 
@@ -128,6 +132,19 @@ typedef struct GMM_CACHE_POLICY_TBL_ELEMENT_REC {
             uint16_t Reserved           : 8;
         } ;
         uint16_t UshortValue;
+
+        union
+        {
+            struct
+            {
+                uint16_t Reserved : 2;
+                uint16_t L4CC     : 2;
+                uint16_t L3CC     : 2;
+                uint16_t L3CLOS   : 2;
+                uint16_t igPAT    : 1; // selection between MOCS and PAT
+                uint16_t Reserved0: 7;
+            };
+        } PhysicalL3;
     } L3;
 
     uint8_t    HDCL1;
@@ -160,6 +177,25 @@ typedef enum GMM_L4_CACHING_POLICY_REC
     GMM_CP_NON_COHERENT_UC                = 0x3,
 } GMM_L4_CACHING_POLICY;
 
+// This Enums represent the GMM indicative values for L1/L3/L4 cache attributes.
+typedef enum GMM_CACHING_POLICY_REC
+{
+    GMM_UC   = 0x0, //uncached
+    GMM_WB   = 0x1, // Write back
+    GMM_WT   = 0x2, // write-through
+    GMM_WBTD = 0x3, // WB_T_Display
+    GMM_WBTA = 0x4, // WB_T_App
+    GMM_WBP  = 0x5, // write bypass mode
+    GMM_WS   = 0x6, // Write-Streaming
+} GMM_CACHING_POLICY;
+
+typedef enum GMM_COHERENCY_TYPE_REC
+{
+    GMM_NON_COHERENT_NO_SNOOP         = 0x0,
+    GMM_COHERENT_ONE_WAY_IA_SNOOP     = 0x1,
+    GMM_COHERENT_TWO_WAY_IA_GPU_SNOOP = 0x2
+} GMM_COHERENCY_TYPE;
+
 typedef enum GMM_GFX_COHERENCY_TYPE_REC
 {
     GMM_GFX_NON_COHERENT_NO_SNOOP           = 0x0,
@@ -196,8 +232,8 @@ typedef enum GMM_GFX_PAT_IDX_REC
     PAT12,
     PAT13,
     PAT14,
-    PAT15	    
-}GMM_GFX_PAT_IDX;
+    PAT15
+} GMM_GFX_PAT_IDX;
 
 #define GFX_IS_ATOM_PLATFORM(pGmmLibContext) (GmmGetSkuTable(pGmmLibContext)->FtrLCIA)
 
@@ -249,6 +285,18 @@ typedef union GMM_PRIVATE_PAT_REC {
         uint32_t Reserved           : 28;
     }Xe_LPG;
 
+    struct
+    {
+        uint32_t Coherency            : 2;
+        uint32_t L4CC                 : 2;
+        uint32_t L3CC                 : 2;
+        uint32_t L3CLOS               : 2;
+        uint32_t Reserved1            : 1;
+        uint32_t LosslessCompressionEn: 1;
+        uint32_t NoCachingPromote     : 1;
+        uint32_t Reserved2            : 21;
+    } Xe2;
+
     uint32_t   Value;
 
 } GMM_PRIVATE_PAT;
diff --git a/Source/GmmLib/inc/External/Common/GmmCachePolicyCommon.h b/Source/GmmLib/inc/External/Common/GmmCachePolicyCommon.h
index 118734d..49b2d37 100644
--- a/Source/GmmLib/inc/External/Common/GmmCachePolicyCommon.h
+++ b/Source/GmmLib/inc/External/Common/GmmCachePolicyCommon.h
@@ -50,6 +50,7 @@ namespace GmmLib
         protected:
             Context * pGmmLibContext;
             uint32_t  NumPATRegisters;
+            uint32_t NumMOCSRegisters;
 
         public:
             GMM_CACHE_POLICY_ELEMENT *pCachePolicy;
@@ -60,10 +61,10 @@ namespace GmmLib
             /* Function prototypes */
             GMM_GFX_MEMORY_TYPE GetWantedMemoryType(GMM_CACHE_POLICY_ELEMENT CachePolicy);
 
-            #define DEFINE_CP_ELEMENT(Usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos, hdcl1, l3evict, segov, glbgo, uclookup, l1cc, l2cc, l4cc, coherency)\
-            do {                                                                                                                                           \
-                    pCachePolicy[Usage].LLC         = (llc);                                                                                               \
-                    pCachePolicy[Usage].ELLC        = (ellc);                                                                                              \
+            #define DEFINE_CP_ELEMENT(Usage, llc, ellc, l3, wt, age, aom, lecc_scc, l3_scc, scf, sso, cos, hdcl1, l3evict, segov, glbgo, uclookup, l1cc, l2cc, l4cc, coherency, l3cc, l3clos, igPAT)\
+            do {                                                                                                                                                                                    \
+                    pCachePolicy[Usage].LLC         = (llc);                                                                                                                                        \
+                    pCachePolicy[Usage].ELLC        = (ellc);                                                                                                                                       \
                     pCachePolicy[Usage].L3          = (l3);                                                                                                \
                     pCachePolicy[Usage].WT          = (wt);                                                                                                \
                     pCachePolicy[Usage].AGE         = (age);                                                                                               \
@@ -83,7 +84,10 @@ namespace GmmLib
 		    pCachePolicy[Usage].L2CC        = (l2cc);                                                                                              \
 		    pCachePolicy[Usage].L4CC        = (l4cc);                                                                                              \
 		    pCachePolicy[Usage].Coherency   = (coherency);                                                                                         \
-            } while(0)
+                    pCachePolicy[Usage].L3CC        = (l3cc);                                                                                              \
+                    pCachePolicy[Usage].L3CLOS      = (l3clos);                                                                                            \
+                    pCachePolicy[Usage].IgnorePAT   = (igPAT);                                                                                             \
+    } while (0)
 
             MEMORY_OBJECT_CONTROL_STATE GMM_STDCALL CachePolicyGetOriginalMemoryObject(GMM_RESOURCE_INFO *pResInfo);
             MEMORY_OBJECT_CONTROL_STATE GMM_STDCALL CachePolicyGetMemoryObject(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage);
@@ -101,7 +105,7 @@ namespace GmmLib
             }
             virtual uint32_t GMM_STDCALL CachePolicyGetPATIndex(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage, bool *pCompressionEnable, bool IsCpuCacheable);
             uint32_t GMM_STDCALL CachePolicyGetNumPATRegisters();
-
+            virtual uint32_t GMM_STDCALL GetSurfaceStateL1CachePolicy(GMM_RESOURCE_USAGE_TYPE Usage);
     };
 }
 #endif // #ifdef __cplusplus
diff --git a/Source/GmmLib/inc/External/Common/GmmClientContext.h b/Source/GmmLib/inc/External/Common/GmmClientContext.h
index 845b14a..a00f7c4 100644
--- a/Source/GmmLib/inc/External/Common/GmmClientContext.h
+++ b/Source/GmmLib/inc/External/Common/GmmClientContext.h
@@ -176,6 +176,7 @@ namespace GmmLib
         GMM_VIRTUAL GMM_RESOURCE_INFO *GMM_STDCALL      CreateCustomResInfoObject_2(GMM_RESCREATE_CUSTOM_PARAMS_2 *pCreateParams);
 #endif
 	GMM_VIRTUAL uint32_t GMM_STDCALL CachePolicyGetPATIndex(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage, bool *pCompressionEnable, bool IsCpuCacheable);
+        GMM_VIRTUAL const SWIZZLE_DESCRIPTOR *GMM_STDCALL GetSwizzleDesc(EXTERNAL_SWIZZLE_NAME ExternalSwizzleName, EXTERNAL_RES_TYPE ResType, uint8_t bpe, bool isStdSwizzle = false);
     };
 }
 
@@ -211,7 +212,8 @@ extern "C" {
                                                const void *   pSkuTable,
                                                const void *   pWaTable,
                                                const void *   pGtSysInfo,
-                                               ADAPTER_BDF    sBdf);
+                                               ADAPTER_BDF    sBdf,
+                                               const GMM_CLIENT ClientType);
 #endif
 
     void GMM_STDCALL GmmLibContextFree(ADAPTER_BDF sBdf);
diff --git a/Source/GmmLib/inc/External/Common/GmmCommonExt.h b/Source/GmmLib/inc/External/Common/GmmCommonExt.h
index 4626f4f..a59a43c 100644
--- a/Source/GmmLib/inc/External/Common/GmmCommonExt.h
+++ b/Source/GmmLib/inc/External/Common/GmmCommonExt.h
@@ -132,8 +132,9 @@ typedef uint32_t GMM_GLOBAL_GFX_ADDRESS, GMM_GLOBAL_GFX_SIZE_T;
 #define GMM_GFX_PLATFORM_VA_SIZE(pClientContext)        (((pClientContext)->GetLibContext()->GetSkuTable().Ftr57bGPUAddressing) ? 57 : 48)
 #define VASize(pCC)                                     GMM_GFX_PLATFORM_VA_SIZE(pCC)
 
-#define GMM_BIT_RANGE(endbit, startbit)     ((endbit)-(startbit)+1)
-#define GMM_BIT(bit)                        (1)
+#define GMM_BIT_RANGE(endbit, startbit) ((endbit) - (startbit) + 1)
+#define GMM_BIT(bit)                    (1)
+
 #define GMM_GET_PTE_BITS_FROM_PAT_IDX(idx)         ((((idx)&__BIT(4))   ? __BIT64(61)   : 0) |  \
                                                     (((idx)&__BIT(3))   ? __BIT64(62)   : 0) |  \
                                                     (((idx)&__BIT(2))   ? __BIT64(7)    : 0) |  \
@@ -414,7 +415,7 @@ C_ASSERT(GMM_FORMAT_INVALID == 0); // GMM_FORMAT_INVALID needs to stay zero--How
 #define GMM_FORMAT_VYUY     GMM_FORMAT_YCRCB_SWAPUVY
 #define GMM_FORMAT_YUY2     GMM_FORMAT_YCRCB_NORMAL
 #define GMM_FORMAT_YVYU     GMM_FORMAT_YCRCB_SWAPUV
-
+#define GMM_UNIFIED_CMF_INVALID 0xD
 
 //===========================================================================
 // typedef:
@@ -436,8 +437,9 @@ typedef enum GMM_SURFACESTATE_FORMAT_ENUM
 typedef enum GMM_E2ECOMP_FORMAT_ENUM
 {
     GMM_E2ECOMP_FORMAT_INVALID = 0,
-    GMM_E2ECOMP_FORMAT_RGB64,       //1h - Reserved
-    GMM_E2ECOMP_FORMAT_RGB32,       //2h - Reserved
+    GMM_E2ECOMP_FORMAT_ML8     = GMM_E2ECOMP_FORMAT_INVALID,
+    GMM_E2ECOMP_FORMAT_RGB64, //1h - Reserved
+    GMM_E2ECOMP_FORMAT_RGB32, //2h - Reserved
 
     GMM_E2ECOMP_MIN_FORMAT = GMM_E2ECOMP_FORMAT_RGB32,
 
@@ -450,7 +452,11 @@ typedef enum GMM_E2ECOMP_FORMAT_ENUM
 
     GMM_E2ECOMP_FORMAT_Y416,       //6h
     GMM_E2ECOMP_FORMAT_P010,       //7h
+    GMM_E2ECOMP_FORMAT_P010_L = GMM_E2ECOMP_FORMAT_P010,
+    GMM_E2ECOMP_FORMAT_P010_C = GMM_E2ECOMP_FORMAT_P010,
     GMM_E2ECOMP_FORMAT_P016,       //8h
+    GMM_E2ECOMP_FORMAT_P016_L = GMM_E2ECOMP_FORMAT_P016,
+    GMM_E2ECOMP_FORMAT_P016_C = GMM_E2ECOMP_FORMAT_P016,
     GMM_E2ECOMP_FORMAT_AYUV,       //9h
 
     GMM_E2ECOMP_FORMAT_ARGB8b,     //Ah
@@ -467,6 +473,8 @@ typedef enum GMM_E2ECOMP_FORMAT_ENUM
     
     GMM_E2ECOMP_FORMAT_RGB10b,     //Eh  --Which media format is it?
     GMM_E2ECOMP_FORMAT_NV12,       //Fh
+    GMM_E2ECOMP_FORMAT_NV12_L = GMM_E2ECOMP_FORMAT_NV12,
+    GMM_E2ECOMP_FORMAT_NV12_C = GMM_E2ECOMP_FORMAT_NV12,
 
     GMM_E2ECOMP_FORMAT_RGBAFLOAT16,            //0x10h
 
@@ -495,6 +503,7 @@ typedef enum GMM_E2ECOMP_FORMAT_ENUM
     GMM_E2ECOMP_FORMAT_RGBA = GMM_E2ECOMP_FORMAT_INVALID,
     GMM_E2ECOMP_FORMAT_R = GMM_E2ECOMP_FORMAT_INVALID,
     GMM_E2ECOMP_FORMAT_RG = GMM_E2ECOMP_FORMAT_INVALID,
+    GMM_E2ECOMP_FORMAT_D    = GMM_E2ECOMP_FORMAT_INVALID,
 
 } GMM_E2ECOMP_FORMAT;
 
@@ -671,3 +680,4 @@ typedef enum GMM_RESOURCE_TYPE_ENUM
 
     GMM_MAX_HW_RESOURCE_TYPE
 } GMM_RESOURCE_TYPE;
+
diff --git a/Source/GmmLib/inc/External/Common/GmmConst.h b/Source/GmmLib/inc/External/Common/GmmConst.h
index 8ae77e3..01ba6cb 100644
--- a/Source/GmmLib/inc/External/Common/GmmConst.h
+++ b/Source/GmmLib/inc/External/Common/GmmConst.h
@@ -41,8 +41,9 @@ OTHER DEALINGS IN THE SOFTWARE.
 #define GMM_MAX_NUMBER_MOCS_INDEXES                    (64)
 #define GMM_XE_NUM_MOCS_ENTRIES                        (16)
 #define GMM_GEN9_MAX_NUMBER_MOCS_INDEXES               (62)     // On SKL there are 64 MOCS indexes, but the last two are reserved by h/w.
+#define GMM_XE2_NUM_MOCS_ENTRIES                       (16)
 #define GMM_NUM_PAT_ENTRIES_LEGACY                     (8)
-#define GMM_NUM_PAT_ENTRIES                            (16)
+#define GMM_NUM_PAT_ENTRIES                            (32)
 #define GMM_NUM_MEMORY_TYPES                            4
 #define GMM_NUM_GFX_PAT_TYPES                           6
 #define GMM_TILED_RESOURCE_NO_MIP_TAIL                 0xF
diff --git a/Source/GmmLib/inc/External/Common/GmmFormatTable.h b/Source/GmmLib/inc/External/Common/GmmFormatTable.h
index 98e84fa..f56884e 100644
--- a/Source/GmmLib/inc/External/Common/GmmFormatTable.h
+++ b/Source/GmmLib/inc/External/Common/GmmFormatTable.h
@@ -52,17 +52,20 @@ OTHER DEALINGS IN THE SOFTWARE.
 #define NC GMM_COMPR_FORMAT_INVALID
 #endif
 #define MC(n)           n | (0x1 << 5) //GMM_FLATCCS_MIN_MC_FORMAT - 1
-#define FC(ver, bpc, fmtstr, bpcstr, typestr)                               \
-    (ver == 1 || (SKU(FtrE2ECompression) && !(SKU(FtrFlatPhysCCS) || SKU(FtrUnified3DMediaCompressionFormats)))) ?\
-        ((bpc == 16) ? GMM_E2ECOMP_FORMAT_RGBAFLOAT16 :                     \
-         (bpc == 32) ? GMM_E2ECOMP_FORMAT_R32G32B32A32_FLOAT :              \
-         (bpc == 8) ? GMM_E2ECOMP_FORMAT_ARGB8b :                           \
-         (bpc == x) ? GMM_E2ECOMP_FORMAT_##fmtstr : NC) :                   \
-    (ver == 2 || (SKU(FtrFlatPhysCCS) && !(SKU(FtrUnified3DMediaCompressionFormats)))) ?                 \
-        (GMM_FLATCCS_FORMAT_##fmtstr##bpcstr##typestr) :                               \
-    (ver == 3 || (SKU(FtrUnified3DMediaCompressionFormats))) ?                         \
-        (GMM_UNIFIED_COMP_FORMAT_##fmtstr##bpcstr##typestr) :                          \
-         NC
+#define FC(ver, bpc, fmtstr, bpcstr, typestr)                                                                                                \
+    (ver == 1 || (SKU(FtrE2ECompression) && !(SKU(FtrFlatPhysCCS) || SKU(FtrUnified3DMediaCompressionFormats) || SKU(FtrXe2Compression)))) ? \
+    ((bpc == 16) ? GMM_E2ECOMP_FORMAT_RGBAFLOAT16 :                                                                                          \
+     (bpc == 32) ? GMM_E2ECOMP_FORMAT_R32G32B32A32_FLOAT :                                                                                   \
+     (bpc == 8)  ? GMM_E2ECOMP_FORMAT_ARGB8b :                                                                                               \
+     (bpc == x)  ? GMM_E2ECOMP_FORMAT_##fmtstr :                                                                                             \
+                   NC) :                                                                                                                      \
+    (ver == 2 || (SKU(FtrFlatPhysCCS) && !(SKU(FtrUnified3DMediaCompressionFormats) || SKU(FtrXe2Compression)))) ?                           \
+    (GMM_FLATCCS_FORMAT_##fmtstr##bpcstr##typestr) :                                                                                         \
+    (ver == 3 || (SKU(FtrUnified3DMediaCompressionFormats) && !SKU(FtrXe2Compression))) ?                                                    \
+    (GMM_UNIFIED_COMP_FORMAT_##fmtstr##bpcstr##typestr) :                                                                                    \
+    (ver == 4 || SKU(FtrXe2Compression)) ?                                                                                                   \
+    (GMM_XE2_UNIFIED_COMP_FORMAT_##fmtstr##bpcstr##typestr) :                                                                                \
+    NC
 
 /****************************************************************************\
   GMM FORMAT TABLE
@@ -81,11 +84,11 @@ OTHER DEALINGS IN THE SOFTWARE.
             Name                           bpe   w   h  d  R  A  RCS.SS  CompressFormat   Available
 ------------------------------------------------------------------------------------------*/
 #ifdef INCLUDE_SURFACESTATE_FORMATS
-GMM_FORMAT( A1B5G5R5_UNORM               ,  16,  1,  1, 1, R, x, 0x124, FC(3,  x,  RGB5A1,   ,   ), GEN(8) || VLV2  )
-GMM_FORMAT( A4B4G4R4_UNORM               ,  16,  1,  1, 1, R, x, 0x125, FC(3,  x,  RGB5A1,   ,   ),     GEN(8)      )
+GMM_FORMAT( A1B5G5R5_UNORM               ,  16,  1,  1, 1, R, x, 0x124, FC(4,  x,  RGB5A1,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( A4B4G4R4_UNORM               ,  16,  1,  1, 1, R, x, 0x125, FC(4,  x,  RGB5A1,   ,   ),     GEN(8)      )
 GMM_FORMAT( A4P4_UNORM_PALETTE0          ,   8,  1,  1, 1, R, x, 0x148, NC                        ,     ALWAYS      )
 GMM_FORMAT( A4P4_UNORM_PALETTE1          ,   8,  1,  1, 1, R, x, 0x14F, NC                        ,     ALWAYS      )
-GMM_FORMAT( A8_UNORM                     ,   8,  1,  1, 1, R, x, 0x144, FC(3,  8,       R,  8,  U),     GEN(7)      )
+GMM_FORMAT( A8_UNORM                     ,   8,  1,  1, 1, R, x, 0x144, FC(4,  8,       R,  8,  U),     GEN(7)      )
 GMM_FORMAT( A8P8_UNORM_PALETTE0          ,  16,  1,  1, 1, R, x, 0x10F, NC                        ,     ALWAYS      )
 GMM_FORMAT( A8P8_UNORM_PALETTE1          ,  16,  1,  1, 1, R, x, 0x110, NC                        ,     ALWAYS      )
 GMM_FORMAT( A8X8_UNORM_G8R8_SNORM        ,  32,  1,  1, 1, R, x, 0x0E7, NC                        ,     ALWAYS      )
@@ -95,55 +98,55 @@ GMM_FORMAT( A24X8_UNORM                  ,  32,  1,  1, 1, R, x, 0x0E2, NC
 GMM_FORMAT( A32_FLOAT                    ,  32,  1,  1, 1, R, x, 0x0E5, NC                        ,     GEN(7)      )
 GMM_FORMAT( A32_UNORM                    ,  32,  1,  1, 1, R, x, 0x0DE, NC                        ,     GEN(7)      )
 GMM_FORMAT( A32X32_FLOAT                 ,  64,  1,  1, 1, R, x, 0x090, NC                        ,     ALWAYS      )
-GMM_FORMAT( B4G4R4A4_UNORM               ,  16,  1,  1, 1, R, x, 0x104, FC(3,  x,   RGBA4,   ,   ),     ALWAYS      )
-GMM_FORMAT( B4G4R4A4_UNORM_SRGB          ,  16,  1,  1, 1, R, x, 0x105, FC(3,  x,   RGBA4,   ,   ),     ALWAYS      )
-GMM_FORMAT( B5G5R5A1_UNORM               ,  16,  1,  1, 1, R, x, 0x102, FC(3,  x,  RGB5A1,   ,   ),     ALWAYS      )
-GMM_FORMAT( B5G5R5A1_UNORM_SRGB          ,  16,  1,  1, 1, R, x, 0x103, FC(3,  x,  RGB5A1,   ,   ),     ALWAYS      )
-GMM_FORMAT( B5G5R5X1_UNORM               ,  16,  1,  1, 1, R, x, 0x11A, FC(3,  x,  RGB5A1,   ,   ),     ALWAYS      )
-GMM_FORMAT( B5G5R5X1_UNORM_SRGB          ,  16,  1,  1, 1, R, x, 0x11B, FC(3,  x,  RGB5A1,   ,   ),     ALWAYS      )
-GMM_FORMAT( B5G6R5_UNORM                 ,  16,  1,  1, 1, R, x, 0x100, FC(3,  x,  B5G6R5,   ,   ),     ALWAYS      )
-GMM_FORMAT( B5G6R5_UNORM_SRGB            ,  16,  1,  1, 1, R, x, 0x101, FC(3,  x,  B5G6R5,   ,   ),     ALWAYS      )
-GMM_FORMAT( B8G8R8A8_UNORM               ,  32,  1,  1, 1, R, x, 0x0C0, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
-GMM_FORMAT( B8G8R8A8_UNORM_SRGB          ,  32,  1,  1, 1, R, x, 0x0C1, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
-GMM_FORMAT( B8G8R8X8_UNORM               ,  32,  1,  1, 1, R, x, 0x0E9, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
-GMM_FORMAT( B8G8R8X8_UNORM_SRGB          ,  32,  1,  1, 1, R, x, 0x0EA, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( B4G4R4A4_UNORM               ,  16,  1,  1, 1, R, x, 0x104, FC(4,  x,   RGBA4,   ,   ),     ALWAYS      )
+GMM_FORMAT( B4G4R4A4_UNORM_SRGB          ,  16,  1,  1, 1, R, x, 0x105, FC(4,  x,   RGBA4,   ,   ),     ALWAYS      )
+GMM_FORMAT( B5G5R5A1_UNORM               ,  16,  1,  1, 1, R, x, 0x102, FC(4,  x,  RGB5A1,   ,   ),     ALWAYS      )
+GMM_FORMAT( B5G5R5A1_UNORM_SRGB          ,  16,  1,  1, 1, R, x, 0x103, FC(4,  x,  RGB5A1,   ,   ),     ALWAYS      )
+GMM_FORMAT( B5G5R5X1_UNORM               ,  16,  1,  1, 1, R, x, 0x11A, FC(4,  x,  RGB5A1,   ,   ),     ALWAYS      )
+GMM_FORMAT( B5G5R5X1_UNORM_SRGB          ,  16,  1,  1, 1, R, x, 0x11B, FC(4,  x,  RGB5A1,   ,   ),     ALWAYS      )
+GMM_FORMAT( B5G6R5_UNORM                 ,  16,  1,  1, 1, R, x, 0x100, FC(4,  x,  B5G6R5,   ,   ),     ALWAYS      )
+GMM_FORMAT( B5G6R5_UNORM_SRGB            ,  16,  1,  1, 1, R, x, 0x101, FC(4,  x,  B5G6R5,   ,   ),     ALWAYS      )
+GMM_FORMAT( B8G8R8A8_UNORM               ,  32,  1,  1, 1, R, x, 0x0C0, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( B8G8R8A8_UNORM_SRGB          ,  32,  1,  1, 1, R, x, 0x0C1, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( B8G8R8X8_UNORM               ,  32,  1,  1, 1, R, x, 0x0E9, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( B8G8R8X8_UNORM_SRGB          ,  32,  1,  1, 1, R, x, 0x0EA, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
 GMM_FORMAT( B8X8_UNORM_G8R8_SNORM        ,  32,  1,  1, 1, R, x, 0x0E8, NC                        ,     ALWAYS      )
-GMM_FORMAT( B10G10R10A2_SINT             ,  32,  1,  1, 1, R, x, 0x1BB, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( B10G10R10A2_SNORM            ,  32,  1,  1, 1, R, x, 0x1B7, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( B10G10R10A2_SSCALED          ,  32,  1,  1, 1, R, x, 0x1B9, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( B10G10R10A2_UINT             ,  32,  1,  1, 1, R, x, 0x1BA, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( B10G10R10A2_UNORM            ,  32,  1,  1, 1, R, x, 0x0D1, FC(3,  x, RGB10A2,   ,   ),     ALWAYS      )
-GMM_FORMAT( B10G10R10A2_UNORM_SRGB       ,  32,  1,  1, 1, R, x, 0x0D2, FC(3,  x, RGB10A2,   ,   ),     ALWAYS      )
-GMM_FORMAT( B10G10R10A2_USCALED          ,  32,  1,  1, 1, R, x, 0x1B8, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( B10G10R10X2_UNORM            ,  32,  1,  1, 1, R, x, 0x0EE, FC(3,  x, RGB10A2,   ,   ),     ALWAYS      )
-GMM_FORMAT( BC1_UNORM                    ,  64,  4,  4, 1, x, x, 0x186, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC1_UNORM_SRGB               ,  64,  4,  4, 1, x, x, 0x18B, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC2_UNORM                    , 128,  4,  4, 1, x, x, 0x187, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC2_UNORM_SRGB               , 128,  4,  4, 1, x, x, 0x18C, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC3_UNORM                    , 128,  4,  4, 1, x, x, 0x188, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC3_UNORM_SRGB               , 128,  4,  4, 1, x, x, 0x18D, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC4_SNORM                    ,  64,  4,  4, 1, x, x, 0x199, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC4_UNORM                    ,  64,  4,  4, 1, x, x, 0x189, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC5_SNORM                    , 128,  4,  4, 1, x, x, 0x19A, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC5_UNORM                    , 128,  4,  4, 1, x, x, 0x18A, NC                        ,     ALWAYS      )
-GMM_FORMAT( BC6H_SF16                    , 128,  4,  4, 1, x, x, 0x1A1, NC                        ,     GEN(7)      )
-GMM_FORMAT( BC6H_UF16                    , 128,  4,  4, 1, x, x, 0x1A4, NC                        ,     GEN(7)      )
-GMM_FORMAT( BC7_UNORM                    , 128,  4,  4, 1, x, x, 0x1A2, NC                        ,     GEN(7)      )
-GMM_FORMAT( BC7_UNORM_SRGB               , 128,  4,  4, 1, x, x, 0x1A3, NC                        ,     GEN(7)      )
-GMM_FORMAT( DXT1_RGB                     ,  64,  4,  4, 1, x, x, 0x191, NC                        ,     ALWAYS      )
-GMM_FORMAT( DXT1_RGB_SRGB                ,  64,  4,  4, 1, x, x, 0x180, NC                        ,     ALWAYS      )
-GMM_FORMAT( EAC_R11                      ,  64,  4,  4, 1, x, x, 0x1AB, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( EAC_RG11                     , 128,  4,  4, 1, x, x, 0x1AC, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( EAC_SIGNED_R11               ,  64,  4,  4, 1, x, x, 0x1AD, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( EAC_SIGNED_RG11              , 128,  4,  4, 1, x, x, 0x1AE, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( ETC1_RGB8                    ,  64,  4,  4, 1, x, x, 0x1A9, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( ETC2_EAC_RGBA8               , 128,  4,  4, 1, x, x, 0x1C2, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( ETC2_EAC_SRGB8_A8            , 128,  4,  4, 1, x, x, 0x1C3, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( ETC2_RGB8                    ,  64,  4,  4, 1, x, x, 0x1AA, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( ETC2_RGB8_PTA                ,  64,  4,  4, 1, x, x, 0x1C0, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( ETC2_SRGB8                   ,  64,  4,  4, 1, x, x, 0x1AF, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( ETC2_SRGB8_PTA               ,  64,  4,  4, 1, x, x, 0x1C1, NC                        , GEN(8) || VLV2  )
-GMM_FORMAT( FXT1                         , 128,  8,  4, 1, x, x, 0x192, NC                        ,     ALWAYS      )
+GMM_FORMAT( B10G10R10A2_SINT             ,  32,  1,  1, 1, R, x, 0x1BB, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( B10G10R10A2_SNORM            ,  32,  1,  1, 1, R, x, 0x1B7, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( B10G10R10A2_SSCALED          ,  32,  1,  1, 1, R, x, 0x1B9, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( B10G10R10A2_UINT             ,  32,  1,  1, 1, R, x, 0x1BA, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( B10G10R10A2_UNORM            ,  32,  1,  1, 1, R, x, 0x0D1, FC(4,  x, RGB10A2,   ,   ),     ALWAYS      )
+GMM_FORMAT( B10G10R10A2_UNORM_SRGB       ,  32,  1,  1, 1, R, x, 0x0D2, FC(4,  x, RGB10A2,   ,   ),     ALWAYS      )
+GMM_FORMAT( B10G10R10A2_USCALED          ,  32,  1,  1, 1, R, x, 0x1B8, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( B10G10R10X2_UNORM            ,  32,  1,  1, 1, R, x, 0x0EE, FC(4,  x, RGB10A2,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC1_UNORM                    ,  64,  4,  4, 1, x, x, 0x186, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC1_UNORM_SRGB               ,  64,  4,  4, 1, x, x, 0x18B, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC2_UNORM                    , 128,  4,  4, 1, x, x, 0x187, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC2_UNORM_SRGB               , 128,  4,  4, 1, x, x, 0x18C, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC3_UNORM                    , 128,  4,  4, 1, x, x, 0x188, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC3_UNORM_SRGB               , 128,  4,  4, 1, x, x, 0x18D, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC4_SNORM                    ,  64,  4,  4, 1, x, x, 0x199, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC4_UNORM                    ,  64,  4,  4, 1, x, x, 0x189, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC5_SNORM                    , 128,  4,  4, 1, x, x, 0x19A, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC5_UNORM                    , 128,  4,  4, 1, x, x, 0x18A, FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( BC6H_SF16                    , 128,  4,  4, 1, x, x, 0x1A1, FC(4,  x,     ML8,   ,   ),     GEN(7)      )
+GMM_FORMAT( BC6H_UF16                    , 128,  4,  4, 1, x, x, 0x1A4, FC(4,  x,     ML8,   ,   ),     GEN(7)      )
+GMM_FORMAT( BC7_UNORM                    , 128,  4,  4, 1, x, x, 0x1A2, FC(4,  x,     ML8,   ,   ),     GEN(7)      )
+GMM_FORMAT( BC7_UNORM_SRGB               , 128,  4,  4, 1, x, x, 0x1A3, FC(4,  x,     ML8,   ,   ),     GEN(7)      )
+GMM_FORMAT( DXT1_RGB                     ,  64,  4,  4, 1, x, x, 0x191, NC                        ,     ALWAYS      ) // verify for ML8
+GMM_FORMAT( DXT1_RGB_SRGB                ,  64,  4,  4, 1, x, x, 0x180, NC                        ,     ALWAYS      ) // verify for ML8
+GMM_FORMAT( EAC_R11                      ,  64,  4,  4, 1, x, x, 0x1AB, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( EAC_RG11                     , 128,  4,  4, 1, x, x, 0x1AC, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( EAC_SIGNED_R11               ,  64,  4,  4, 1, x, x, 0x1AD, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( EAC_SIGNED_RG11              , 128,  4,  4, 1, x, x, 0x1AE, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( ETC1_RGB8                    ,  64,  4,  4, 1, x, x, 0x1A9, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( ETC2_EAC_RGBA8               , 128,  4,  4, 1, x, x, 0x1C2, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( ETC2_EAC_SRGB8_A8            , 128,  4,  4, 1, x, x, 0x1C3, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( ETC2_RGB8                    ,  64,  4,  4, 1, x, x, 0x1AA, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( ETC2_RGB8_PTA                ,  64,  4,  4, 1, x, x, 0x1C0, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( ETC2_SRGB8                   ,  64,  4,  4, 1, x, x, 0x1AF, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( ETC2_SRGB8_PTA               ,  64,  4,  4, 1, x, x, 0x1C1, FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  )
+GMM_FORMAT( FXT1                         ,  128, 8,  4, 1, x, x, 0x192, NC                        ,     ALWAYS      )
 GMM_FORMAT( I8_SINT                      ,   8,  1,  1, 1, R, x, 0x155, NC                        ,     GEN(9)      )
 GMM_FORMAT( I8_UINT                      ,   8,  1,  1, 1, R, x, 0x154, NC                        ,     GEN(9)      )
 GMM_FORMAT( I8_UNORM                     ,   8,  1,  1, 1, R, x, 0x145, NC                        ,     ALWAYS      )
@@ -183,18 +186,18 @@ GMM_FORMAT( PLANAR_420_8                 ,   8,  1,  1, 1, R, x, 0x1A5, NC
 GMM_FORMAT( PLANAR_420_16                ,  16,  1,  1, 1, R, x, 0x1A6, NC                        ,       x         ) // "
 GMM_FORMAT( PLANAR_422_8                 ,   8,  1,  1, 1, R, x, 0x00F, NC                        ,       x         )           // <-- TODO(Minor): Remove this HW-internal format.
 GMM_FORMAT( R1_UNORM                     ,   1,  1,  1, 1, R, x, 0x181, NC                        ,       x         ) // "
-GMM_FORMAT( R8_SINT                      ,   8,  1,  1, 1, R, x, 0x142, FC(3,  8,       R,  8, S1),     ALWAYS      )
-GMM_FORMAT( R8_SNORM                     ,   8,  1,  1, 1, R, x, 0x141, FC(3,  8,       R,  8,  S),     ALWAYS      )
-GMM_FORMAT( R8_SSCALED                   ,   8,  1,  1, 1, R, x, 0x149, FC(3,  8,       R,  8,  S),     ALWAYS      )
-GMM_FORMAT( R8_UINT                      ,   8,  1,  1, 1, R, x, 0x143, FC(3,  8,       R,  8, U1),     ALWAYS      )
-GMM_FORMAT( R8_UNORM                     ,   8,  1,  1, 1, R, x, 0x140, FC(3,  8,       R,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8_USCALED                   ,   8,  1,  1, 1, R, x, 0x14A, FC(3,  8,       R,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8G8_SINT                    ,  16,  1,  1, 1, R, x, 0x108, FC(3,  8,      RG,  8,  S),     ALWAYS      )
-GMM_FORMAT( R8G8_SNORM                   ,  16,  1,  1, 1, R, x, 0x107, FC(3,  8,      RG,  8,  S),     ALWAYS      )
-GMM_FORMAT( R8G8_SSCALED                 ,  16,  1,  1, 1, R, x, 0x11C, FC(3,  8,      RG,  8,  S),     ALWAYS      )
-GMM_FORMAT( R8G8_UINT                    ,  16,  1,  1, 1, R, x, 0x109, FC(3,  8,      RG,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8G8_UNORM                   ,  16,  1,  1, 1, R, x, 0x106, FC(3,  8,      RG,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8G8_USCALED                 ,  16,  1,  1, 1, R, x, 0x11D, FC(3,  8,      RG,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8_SINT                      ,   8,  1,  1, 1, R, x, 0x142, FC(4,  8,       R,  8, S1),     ALWAYS      )
+GMM_FORMAT( R8_SNORM                     ,   8,  1,  1, 1, R, x, 0x141, FC(4,  8,       R,  8,  S),     ALWAYS      )
+GMM_FORMAT( R8_SSCALED                   ,   8,  1,  1, 1, R, x, 0x149, FC(4,  8,       R,  8,  S),     ALWAYS      )
+GMM_FORMAT( R8_UINT                      ,   8,  1,  1, 1, R, x, 0x143, FC(4,  8,       R,  8, U1),     ALWAYS      )
+GMM_FORMAT( R8_UNORM                     ,   8,  1,  1, 1, R, x, 0x140, FC(4,  8,       R,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8_USCALED                   ,   8,  1,  1, 1, R, x, 0x14A, FC(4,  8,       R,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8_SINT                    ,  16,  1,  1, 1, R, x, 0x108, FC(4,  8,      RG,  8,  S),     ALWAYS      )
+GMM_FORMAT( R8G8_SNORM                   ,  16,  1,  1, 1, R, x, 0x107, FC(4,  8,      RG,  8,  S),     ALWAYS      )
+GMM_FORMAT( R8G8_SSCALED                 ,  16,  1,  1, 1, R, x, 0x11C, FC(4,  8,      RG,  8,  S),     ALWAYS      )
+GMM_FORMAT( R8G8_UINT                    ,  16,  1,  1, 1, R, x, 0x109, FC(4,  8,      RG,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8_UNORM                   ,  16,  1,  1, 1, R, x, 0x106, FC(4,  8,      RG,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8_USCALED                 ,  16,  1,  1, 1, R, x, 0x11D, FC(4,  8,      RG,  8,  U),     ALWAYS      )
 GMM_FORMAT( R8G8B8_SINT                  ,  24,  1,  1, 1, R, x, 0x1C9, NC                        ,     GEN(8)      )
 GMM_FORMAT( R8G8B8_SNORM                 ,  24,  1,  1, 1, R, x, 0x194, NC                        ,     ALWAYS      )
 GMM_FORMAT( R8G8B8_SSCALED               ,  24,  1,  1, 1, R, x, 0x195, NC                        ,     ALWAYS      )
@@ -202,41 +205,41 @@ GMM_FORMAT( R8G8B8_UINT                  ,  24,  1,  1, 1, R, x, 0x1C8, NC
 GMM_FORMAT( R8G8B8_UNORM                 ,  24,  1,  1, 1, R, x, 0x193, NC                        ,     ALWAYS      )
 GMM_FORMAT( R8G8B8_UNORM_SRGB            ,  24,  1,  1, 1, R, x, 0x1A8, NC                        ,     GEN(7_5)    )
 GMM_FORMAT( R8G8B8_USCALED               ,  24,  1,  1, 1, R, x, 0x196, NC                        ,     ALWAYS      )
-GMM_FORMAT( R8G8B8A8_SINT                ,  32,  1,  1, 1, R, x, 0x0CA, FC(3,  8,    RGBA,  8,  S),     ALWAYS      )
-GMM_FORMAT( R8G8B8A8_SNORM               ,  32,  1,  1, 1, R, x, 0x0C9, FC(3,  8,    RGBA,  8,  S),     ALWAYS      )
-GMM_FORMAT( R8G8B8A8_SSCALED             ,  32,  1,  1, 1, R, x, 0x0F4, FC(3,  8,    RGBA,  8,  S),     ALWAYS      )
-GMM_FORMAT( R8G8B8A8_UINT                ,  32,  1,  1, 1, R, x, 0x0CB, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8G8B8A8_UNORM               ,  32,  1,  1, 1, R, x, 0x0C7, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8G8B8A8_UNORM_SRGB          ,  32,  1,  1, 1, R, x, 0x0C8, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8G8B8A8_USCALED             ,  32,  1,  1, 1, R, x, 0x0F5, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8G8B8X8_UNORM               ,  32,  1,  1, 1, R, x, 0x0EB, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
-GMM_FORMAT( R8G8B8X8_UNORM_SRGB          ,  32,  1,  1, 1, R, x, 0x0EC, FC(3,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8B8A8_SINT                ,  32,  1,  1, 1, R, x, 0x0CA, FC(4,  8,    RGBA,  8,  S),     ALWAYS      )
+GMM_FORMAT( R8G8B8A8_SNORM               ,  32,  1,  1, 1, R, x, 0x0C9, FC(4,  8,    RGBA,  8,  S),     ALWAYS      )
+GMM_FORMAT( R8G8B8A8_SSCALED             ,  32,  1,  1, 1, R, x, 0x0F4, FC(4,  8,    RGBA,  8,  S),     ALWAYS      )
+GMM_FORMAT( R8G8B8A8_UINT                ,  32,  1,  1, 1, R, x, 0x0CB, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8B8A8_UNORM               ,  32,  1,  1, 1, R, x, 0x0C7, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8B8A8_UNORM_SRGB          ,  32,  1,  1, 1, R, x, 0x0C8, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8B8A8_USCALED             ,  32,  1,  1, 1, R, x, 0x0F5, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8B8X8_UNORM               ,  32,  1,  1, 1, R, x, 0x0EB, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
+GMM_FORMAT( R8G8B8X8_UNORM_SRGB          ,  32,  1,  1, 1, R, x, 0x0EC, FC(4,  8,    RGBA,  8,  U),     ALWAYS      )
 GMM_FORMAT( R9G9B9E5_SHAREDEXP           ,  32,  1,  1, 1, R, x, 0x0ED, NC                        ,     ALWAYS      )
-GMM_FORMAT( R10G10B10_FLOAT_A2_UNORM     ,  32,  1,  1, 1, R, x, 0x0D5, FC(3,  x, RGB10A2,   ,   ),     GEN(12)     )
-GMM_FORMAT( R10G10B10_SNORM_A2_UNORM     ,  32,  1,  1, 1, R, x, 0x0C5, FC(3,  x, RGB10A2,   ,   ),     ALWAYS      )
-GMM_FORMAT( R10G10B10A2_SINT             ,  32,  1,  1, 1, R, x, 0x1B6, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( R10G10B10A2_SNORM            ,  32,  1,  1, 1, R, x, 0x1B3, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( R10G10B10A2_SSCALED          ,  32,  1,  1, 1, R, x, 0x1B5, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( R10G10B10A2_UINT             ,  32,  1,  1, 1, R, x, 0x0C4, FC(3,  x, RGB10A2,   ,   ),     ALWAYS      )
-GMM_FORMAT( R10G10B10A2_UNORM            ,  32,  1,  1, 1, R, x, 0x0C2, FC(3,  x, RGB10A2,   ,   ),     ALWAYS      )
-GMM_FORMAT( R10G10B10A2_UNORM_SRGB       ,  32,  1,  1, 1, R, x, 0x0C3, FC(3,  x, RGB10A2,   ,   ),     ALWAYS      )
-GMM_FORMAT( R10G10B10A2_USCALED          ,  32,  1,  1, 1, R, x, 0x1B4, FC(3,  x, RGB10A2,   ,   ),     GEN(8)      )
-GMM_FORMAT( R10G10B10X2_USCALED          ,  32,  1,  1, 1, R, x, 0x0F3, FC(3,  x, RGB10A2,   ,   ),     ALWAYS      )
-GMM_FORMAT( R11G11B10_FLOAT              ,  32,  1,  1, 1, R, x, 0x0D3, FC(3,  x, RG11B10,   ,   ),     ALWAYS      )
-GMM_FORMAT( R16_FLOAT                    ,  16,  1,  1, 1, R, x, 0x10E, FC(3, 16,       R, 16, F1),     ALWAYS      )
-GMM_FORMAT( R16_SINT                     ,  16,  1,  1, 1, R, x, 0x10C, FC(3, 16,       R, 16, S1),     ALWAYS      )
-GMM_FORMAT( R16_SNORM                    ,  16,  1,  1, 1, R, x, 0x10B, FC(3, 16,       R, 16,  S),     ALWAYS      )
-GMM_FORMAT( R16_SSCALED                  ,  16,  1,  1, 1, R, x, 0x11E, FC(3, 16,       R, 16,  S),     ALWAYS      )
-GMM_FORMAT( R16_UINT                     ,  16,  1,  1, 1, R, x, 0x10D, FC(3, 16,       R, 16, U1),     ALWAYS      )
-GMM_FORMAT( R16_UNORM                    ,  16,  1,  1, 1, R, x, 0x10A, FC(3, 16,       R, 16,  U),     ALWAYS      )
-GMM_FORMAT( R16_USCALED                  ,  16,  1,  1, 1, R, x, 0x11F, FC(3, 16,        R, 16,  U),     ALWAYS      )
-GMM_FORMAT( R16G16_FLOAT                 ,  32,  1,  1, 1, R, x, 0x0D0, FC(3, 16,      RG, 16,  F),     ALWAYS      )
-GMM_FORMAT( R16G16_SINT                  ,  32,  1,  1, 1, R, x, 0x0CE, FC(3, 16,      RG, 16,  S),     ALWAYS      )
-GMM_FORMAT( R16G16_SNORM                 ,  32,  1,  1, 1, R, x, 0x0CD, FC(3, 16,      RG, 16,  S),     ALWAYS      )
-GMM_FORMAT( R16G16_SSCALED               ,  32,  1,  1, 1, R, x, 0x0F6, FC(3, 16,      RG, 16,  S),     ALWAYS      )
-GMM_FORMAT( R16G16_UINT                  ,  32,  1,  1, 1, R, x, 0x0CF, FC(3, 16,      RG, 16,  U),     ALWAYS      )
-GMM_FORMAT( R16G16_UNORM                 ,  32,  1,  1, 1, R, x, 0x0CC, FC(3, 16,      RG, 16,  U),     ALWAYS      )
-GMM_FORMAT( R16G16_USCALED               ,  32,  1,  1, 1, R, x, 0x0F7, FC(3, 16,      RG, 16,  U),     ALWAYS      )
+GMM_FORMAT( R10G10B10_FLOAT_A2_UNORM     ,  32,  1,  1, 1, R, x, 0x0D5, FC(4,  x, RGB10A2,   ,   ),     GEN(12)     )
+GMM_FORMAT( R10G10B10_SNORM_A2_UNORM     ,  32,  1,  1, 1, R, x, 0x0C5, FC(4,  x, RGB10A2,   ,   ),     ALWAYS      )
+GMM_FORMAT( R10G10B10A2_SINT             ,  32,  1,  1, 1, R, x, 0x1B6, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( R10G10B10A2_SNORM            ,  32,  1,  1, 1, R, x, 0x1B3, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( R10G10B10A2_SSCALED          ,  32,  1,  1, 1, R, x, 0x1B5, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( R10G10B10A2_UINT             ,  32,  1,  1, 1, R, x, 0x0C4, FC(4,  x, RGB10A2,   ,   ),     ALWAYS      )
+GMM_FORMAT( R10G10B10A2_UNORM            ,  32,  1,  1, 1, R, x, 0x0C2, FC(4,  x, RGB10A2,   ,   ),     ALWAYS      )
+GMM_FORMAT( R10G10B10A2_UNORM_SRGB       ,  32,  1,  1, 1, R, x, 0x0C3, FC(4,  x, RGB10A2,   ,   ),     ALWAYS      )
+GMM_FORMAT( R10G10B10A2_USCALED          ,  32,  1,  1, 1, R, x, 0x1B4, FC(4,  x, RGB10A2,   ,   ),     GEN(8)      )
+GMM_FORMAT( R10G10B10X2_USCALED          ,  32,  1,  1, 1, R, x, 0x0F3, FC(4,  x, RGB10A2,   ,   ),     ALWAYS      )
+GMM_FORMAT( R11G11B10_FLOAT              ,  32,  1,  1, 1, R, x, 0x0D3, FC(4,  x, RG11B10,   ,   ),     ALWAYS      )
+GMM_FORMAT( R16_FLOAT                    ,  16,  1,  1, 1, R, x, 0x10E, FC(4, 16,       R, 16, F1),     ALWAYS      )
+GMM_FORMAT( R16_SINT                     ,  16,  1,  1, 1, R, x, 0x10C, FC(4, 16,       R, 16, S1),     ALWAYS      )
+GMM_FORMAT( R16_SNORM                    ,  16,  1,  1, 1, R, x, 0x10B, FC(4, 16,       R, 16,  S),     ALWAYS      )
+GMM_FORMAT( R16_SSCALED                  ,  16,  1,  1, 1, R, x, 0x11E, FC(4, 16,       R, 16,  S),     ALWAYS      )
+GMM_FORMAT( R16_UINT                     ,  16,  1,  1, 1, R, x, 0x10D, FC(4, 16,       R, 16, U1),     ALWAYS      )
+GMM_FORMAT( R16_UNORM                    ,  16,  1,  1, 1, R, x, 0x10A, FC(4, 16,       R, 16,  U),     ALWAYS      )
+GMM_FORMAT( R16_USCALED                  ,  16,  1,  1, 1, R, x, 0x11F, FC(4, 16,        R, 16,  U),     ALWAYS      )
+GMM_FORMAT( R16G16_FLOAT                 ,  32,  1,  1, 1, R, x, 0x0D0, FC(4, 16,      RG, 16,  F),     ALWAYS      )
+GMM_FORMAT( R16G16_SINT                  ,  32,  1,  1, 1, R, x, 0x0CE, FC(4, 16,      RG, 16,  S),     ALWAYS      )
+GMM_FORMAT( R16G16_SNORM                 ,  32,  1,  1, 1, R, x, 0x0CD, FC(4, 16,      RG, 16,  S),     ALWAYS      )
+GMM_FORMAT( R16G16_SSCALED               ,  32,  1,  1, 1, R, x, 0x0F6, FC(4, 16,      RG, 16,  S),     ALWAYS      )
+GMM_FORMAT( R16G16_UINT                  ,  32,  1,  1, 1, R, x, 0x0CF, FC(4, 16,      RG, 16,  U),     ALWAYS      )
+GMM_FORMAT( R16G16_UNORM                 ,  32,  1,  1, 1, R, x, 0x0CC, FC(4, 16,      RG, 16,  U),     ALWAYS      )
+GMM_FORMAT( R16G16_USCALED               ,  32,  1,  1, 1, R, x, 0x0F7, FC(4, 16,      RG, 16,  U),     ALWAYS      )
 GMM_FORMAT( R16G16B16_FLOAT              ,  48,  1,  1, 1, R, x, 0x19B, NC                        ,     ALWAYS      )
 GMM_FORMAT( R16G16B16_SINT               ,  48,  1,  1, 1, R, x, 0x1B1, NC                        ,     GEN(8)      )
 GMM_FORMAT( R16G16B16_SNORM              ,  48,  1,  1, 1, R, x, 0x19D, NC                        ,     ALWAYS      )
@@ -244,33 +247,33 @@ GMM_FORMAT( R16G16B16_SSCALED            ,  48,  1,  1, 1, R, x, 0x19E, NC
 GMM_FORMAT( R16G16B16_UINT               ,  48,  1,  1, 1, R, x, 0x1B0, NC                        , GEN(8) || VLV2  )
 GMM_FORMAT( R16G16B16_UNORM              ,  48,  1,  1, 1, R, x, 0x19C, NC                        ,     ALWAYS      )
 GMM_FORMAT( R16G16B16_USCALED            ,  48,  1,  1, 1, R, x, 0x19F, NC                        ,     ALWAYS      )
-GMM_FORMAT( R16G16B16A16_FLOAT           ,  64,  1,  1, 1, R, x, 0x084, FC(3, 16,    RGBA, 16,  F),     ALWAYS      )
-GMM_FORMAT( R16G16B16A16_SINT            ,  64,  1,  1, 1, R, x, 0x082, FC(3, 16,    RGBA, 16,  S),     ALWAYS      )
-GMM_FORMAT( R16G16B16A16_SNORM           ,  64,  1,  1, 1, R, x, 0x081, FC(3, 16,    RGBA, 16,  S),     ALWAYS      )
-GMM_FORMAT( R16G16B16A16_SSCALED         ,  64,  1,  1, 1, R, x, 0x093, FC(3, 16,    RGBA, 16,  S),     ALWAYS      )
-GMM_FORMAT( R16G16B16A16_UINT            ,  64,  1,  1, 1, R, x, 0x083, FC(3, 16,    RGBA, 16,  U),     ALWAYS      )
-GMM_FORMAT( R16G16B16A16_UNORM           ,  64,  1,  1, 1, R, x, 0x080, FC(3, 16,    RGBA, 16,  U),     ALWAYS      )
-GMM_FORMAT( R16G16B16A16_USCALED         ,  64,  1,  1, 1, R, x, 0x094, FC(3, 16,    RGBA, 16,  U),     ALWAYS      )
-GMM_FORMAT( R16G16B16X16_FLOAT           ,  64,  1,  1, 1, R, x, 0x08F, FC(3, 16,    RGBA, 16,  F),     ALWAYS      )
-GMM_FORMAT( R16G16B16X16_UNORM           ,  64,  1,  1, 1, R, x, 0x08E, FC(3, 16,    RGBA, 16,  U),     ALWAYS      )
-GMM_FORMAT( R24_UNORM_X8_TYPELESS        ,  32,  1,  1, 1, R, x, 0x0D9, FC(3, 32,       R, 32, U1),     ALWAYS      )
-GMM_FORMAT( R32_FLOAT                    ,  32,  1,  1, 1, R, x, 0x0D8, FC(3, 32,       R, 32, F1),     ALWAYS      )
-GMM_FORMAT( R32_FLOAT_X8X24_TYPELESS     ,  64,  1,  1, 1, R, x, 0x088, FC(3, 32,       R, 32,  F),     ALWAYS      )
-GMM_FORMAT( R32_SFIXED                   ,  32,  1,  1, 1, R, x, 0x1B2, FC(3, 32,       R, 32,  S),     GEN(8)      )
-GMM_FORMAT( R32_SINT                     ,  32,  1,  1, 1, R, x, 0x0D6, FC(3, 32,       R, 32, S1),     ALWAYS      )
-GMM_FORMAT( R32_SNORM                    ,  32,  1,  1, 1, R, x, 0x0F2, FC(3, 32,       R, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32_SSCALED                  ,  32,  1,  1, 1, R, x, 0x0F8, FC(3, 32,       R, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32_UINT                     ,  32,  1,  1, 1, R, x, 0x0D7, FC(3, 32,       R, 32, U1),     ALWAYS      )
-GMM_FORMAT( R32_UNORM                    ,  32,  1,  1, 1, R, x, 0x0F1, FC(3, 32,       R, 32,  U),     ALWAYS      )
-GMM_FORMAT( R32_USCALED                  ,  32,  1,  1, 1, R, x, 0x0F9, FC(3, 32,       R, 32,  U),     ALWAYS      )
-GMM_FORMAT( R32G32_FLOAT                 ,  64,  1,  1, 1, R, x, 0x085, FC(3, 32,      RG, 32,  F),     ALWAYS      )
-GMM_FORMAT( R32G32_SFIXED                ,  64,  1,  1, 1, R, x, 0x0A0, FC(3, 32,      RG, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32G32_SINT                  ,  64,  1,  1, 1, R, x, 0x086, FC(3, 32,      RG, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32G32_SNORM                 ,  64,  1,  1, 1, R, x, 0x08C, FC(3, 32,      RG, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32G32_SSCALED               ,  64,  1,  1, 1, R, x, 0x095, FC(3, 32,      RG, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32G32_UINT                  ,  64,  1,  1, 1, R, x, 0x087, FC(3, 32,      RG, 32,  U),     ALWAYS      )
-GMM_FORMAT( R32G32_UNORM                 ,  64,  1,  1, 1, R, x, 0x08B, FC(3, 32,      RG, 32,  U),     ALWAYS      )
-GMM_FORMAT( R32G32_USCALED               ,  64,  1,  1, 1, R, x, 0x096, FC(3, 32,      RG, 32,  U),     ALWAYS      )
+GMM_FORMAT( R16G16B16A16_FLOAT           ,  64,  1,  1, 1, R, x, 0x084, FC(4, 16,    RGBA, 16,  F),     ALWAYS      )
+GMM_FORMAT( R16G16B16A16_SINT            ,  64,  1,  1, 1, R, x, 0x082, FC(4, 16,    RGBA, 16,  S),     ALWAYS      )
+GMM_FORMAT( R16G16B16A16_SNORM           ,  64,  1,  1, 1, R, x, 0x081, FC(4, 16,    RGBA, 16,  S),     ALWAYS      )
+GMM_FORMAT( R16G16B16A16_SSCALED         ,  64,  1,  1, 1, R, x, 0x093, FC(4, 16,    RGBA, 16,  S),     ALWAYS      )
+GMM_FORMAT( R16G16B16A16_UINT            ,  64,  1,  1, 1, R, x, 0x083, FC(4, 16,    RGBA, 16,  U),     ALWAYS      )
+GMM_FORMAT( R16G16B16A16_UNORM           ,  64,  1,  1, 1, R, x, 0x080, FC(4, 16,    RGBA, 16,  U),     ALWAYS      )
+GMM_FORMAT( R16G16B16A16_USCALED         ,  64,  1,  1, 1, R, x, 0x094, FC(4, 16,    RGBA, 16,  U),     ALWAYS      )
+GMM_FORMAT( R16G16B16X16_FLOAT           ,  64,  1,  1, 1, R, x, 0x08F, FC(4, 16,    RGBA, 16,  F),     ALWAYS      )
+GMM_FORMAT( R16G16B16X16_UNORM           ,  64,  1,  1, 1, R, x, 0x08E, FC(4, 16,    RGBA, 16,  U),     ALWAYS      )
+GMM_FORMAT( R24_UNORM_X8_TYPELESS        ,  32,  1,  1, 1, R, x, 0x0D9, FC(4, 32,       R, 32, U1),     ALWAYS      )
+GMM_FORMAT( R32_FLOAT                    ,  32,  1,  1, 1, R, x, 0x0D8, FC(4, 32,       R, 32, F1),     ALWAYS      )
+GMM_FORMAT( R32_FLOAT_X8X24_TYPELESS     ,  64,  1,  1, 1, R, x, 0x088, FC(4, 32,       R, 32,  F),     ALWAYS      )
+GMM_FORMAT( R32_SFIXED                   ,  32,  1,  1, 1, R, x, 0x1B2, FC(4, 32,       R, 32,  S),     GEN(8)      )
+GMM_FORMAT( R32_SINT                     ,  32,  1,  1, 1, R, x, 0x0D6, FC(4, 32,       R, 32, S1),     ALWAYS      )
+GMM_FORMAT( R32_SNORM                    ,  32,  1,  1, 1, R, x, 0x0F2, FC(4, 32,       R, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32_SSCALED                  ,  32,  1,  1, 1, R, x, 0x0F8, FC(4, 32,       R, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32_UINT                     ,  32,  1,  1, 1, R, x, 0x0D7, FC(4, 32,       R, 32, U1),     ALWAYS      )
+GMM_FORMAT( R32_UNORM                    ,  32,  1,  1, 1, R, x, 0x0F1, FC(4, 32,       R, 32,  U),     ALWAYS      )
+GMM_FORMAT( R32_USCALED                  ,  32,  1,  1, 1, R, x, 0x0F9, FC(4, 32,       R, 32,  U),     ALWAYS      )
+GMM_FORMAT( R32G32_FLOAT                 ,  64,  1,  1, 1, R, x, 0x085, FC(4, 32,      RG, 32,  F),     ALWAYS      )
+GMM_FORMAT( R32G32_SFIXED                ,  64,  1,  1, 1, R, x, 0x0A0, FC(4, 32,      RG, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32G32_SINT                  ,  64,  1,  1, 1, R, x, 0x086, FC(4, 32,      RG, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32G32_SNORM                 ,  64,  1,  1, 1, R, x, 0x08C, FC(4, 32,      RG, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32G32_SSCALED               ,  64,  1,  1, 1, R, x, 0x095, FC(4, 32,      RG, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32G32_UINT                  ,  64,  1,  1, 1, R, x, 0x087, FC(4, 32,      RG, 32,  U),     ALWAYS      )
+GMM_FORMAT( R32G32_UNORM                 ,  64,  1,  1, 1, R, x, 0x08B, FC(4, 32,      RG, 32,  U),     ALWAYS      )
+GMM_FORMAT( R32G32_USCALED               ,  64,  1,  1, 1, R, x, 0x096, FC(4, 32,      RG, 32,  U),     ALWAYS      )
 GMM_FORMAT( R32G32B32_FLOAT              ,  96,  1,  1, 1, R, x, 0x040, NC                        ,     ALWAYS      )
 GMM_FORMAT( R32G32B32_SFIXED             ,  96,  1,  1, 1, R, x, 0x050, NC                        ,     ALWAYS      )
 GMM_FORMAT( R32G32B32_SINT               ,  96,  1,  1, 1, R, x, 0x041, NC                        ,     ALWAYS      )
@@ -279,15 +282,15 @@ GMM_FORMAT( R32G32B32_SSCALED            ,  96,  1,  1, 1, R, x, 0x045, NC
 GMM_FORMAT( R32G32B32_UINT               ,  96,  1,  1, 1, R, x, 0x042, NC                        ,     ALWAYS      )
 GMM_FORMAT( R32G32B32_UNORM              ,  96,  1,  1, 1, R, x, 0x043, NC                        ,     ALWAYS      )
 GMM_FORMAT( R32G32B32_USCALED            ,  96,  1,  1, 1, R, x, 0x046, NC                        ,     ALWAYS      )
-GMM_FORMAT( R32G32B32A32_FLOAT           , 128,  1,  1, 1, R, x, 0x000, FC(3, 32,    RGBA, 32,  F),     ALWAYS      )
-GMM_FORMAT( R32G32B32A32_SFIXED          , 128,  1,  1, 1, R, x, 0x020, FC(3, 32,    RGBA, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32G32B32A32_SINT            , 128,  1,  1, 1, R, x, 0x001, FC(3, 32,    RGBA, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32G32B32A32_SNORM           , 128,  1,  1, 1, R, x, 0x004, FC(3, 32,    RGBA, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32G32B32A32_SSCALED         , 128,  1,  1, 1, R, x, 0x007, FC(3, 32,    RGBA, 32,  S),     ALWAYS      )
-GMM_FORMAT( R32G32B32A32_UINT            , 128,  1,  1, 1, R, x, 0x002, FC(3, 32,    RGBA, 32,  U),     ALWAYS      )
-GMM_FORMAT( R32G32B32A32_UNORM           , 128,  1,  1, 1, R, x, 0x003, FC(3, 32,    RGBA, 32,  U),     ALWAYS      )
-GMM_FORMAT( R32G32B32A32_USCALED         , 128,  1,  1, 1, R, x, 0x008, FC(3, 32,    RGBA, 32,  U),     ALWAYS      )
-GMM_FORMAT( R32G32B32X32_FLOAT           , 128,  1,  1, 1, R, x, 0x006, FC(3, 32,    RGBA, 32,  F),     ALWAYS      )
+GMM_FORMAT( R32G32B32A32_FLOAT           , 128,  1,  1, 1, R, x, 0x000, FC(4, 32,    RGBA, 32,  F),     ALWAYS      )
+GMM_FORMAT( R32G32B32A32_SFIXED          , 128,  1,  1, 1, R, x, 0x020, FC(4, 32,    RGBA, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32G32B32A32_SINT            , 128,  1,  1, 1, R, x, 0x001, FC(4, 32,    RGBA, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32G32B32A32_SNORM           , 128,  1,  1, 1, R, x, 0x004, FC(4, 32,    RGBA, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32G32B32A32_SSCALED         , 128,  1,  1, 1, R, x, 0x007, FC(4, 32,    RGBA, 32,  S),     ALWAYS      )
+GMM_FORMAT( R32G32B32A32_UINT            , 128,  1,  1, 1, R, x, 0x002, FC(4, 32,    RGBA, 32,  U),     ALWAYS      )
+GMM_FORMAT( R32G32B32A32_UNORM           , 128,  1,  1, 1, R, x, 0x003, FC(4, 32,    RGBA, 32,  U),     ALWAYS      )
+GMM_FORMAT( R32G32B32A32_USCALED         , 128,  1,  1, 1, R, x, 0x008, FC(4, 32,    RGBA, 32,  U),     ALWAYS      )
+GMM_FORMAT( R32G32B32X32_FLOAT           , 128,  1,  1, 1, R, x, 0x006, FC(4, 32,    RGBA, 32,  F),     ALWAYS      )
 GMM_FORMAT( R5G5_SNORM_B6_UNORM          ,  16,  1,  1, 1, R, x, 0x119, NC                        ,     ALWAYS      )
 GMM_FORMAT( R64_FLOAT                    ,  64,  1,  1, 1, R, x, 0x08D, NC                        ,     ALWAYS      )
 GMM_FORMAT( R64_PASSTHRU                 ,  64,  1,  1, 1, R, x, 0x0A1, NC                        ,     ALWAYS      )
@@ -298,14 +301,14 @@ GMM_FORMAT( R64G64B64_PASSTHRU           , 192,  1,  1, 1, R, x, 0x1BD, NC
 GMM_FORMAT( R64G64B64A64_FLOAT           , 256,  1,  1, 1, R, x, 0x197, NC                        ,     ALWAYS      )
 GMM_FORMAT( R64G64B64A64_PASSTHRU        , 256,  1,  1, 1, R, x, 0x1BC, NC                        ,     GEN(8)      )
 GMM_FORMAT( RAW                          ,   8,  1,  1, 1, R, x, 0x1FF, NC                        ,     GEN(7)      ) // "8bpp" for current GMM implementation.
-GMM_FORMAT( X24_TYPELESS_G8_UINT         ,  32,  1,  1, 1, R, x, 0x0DA, FC(3, 32,       R, 32, U1),     ALWAYS      )
-GMM_FORMAT( X32_TYPELESS_G8X24_UINT      ,  64,  1,  1, 1, R, x, 0x089, FC(3, 32,      RG, 32,  U),     ALWAYS      )
+GMM_FORMAT( X24_TYPELESS_G8_UINT         ,  32,  1,  1, 1, R, x, 0x0DA, FC(4, 32,       R, 32, U1),     ALWAYS      )
+GMM_FORMAT( X32_TYPELESS_G8X24_UINT      ,  64,  1,  1, 1, R, x, 0x089, FC(4, 32,      RG, 32,  U),     ALWAYS      )
 GMM_FORMAT( X8B8_UNORM_G8R8_SNORM        ,  32,  1,  1, 1, R, x, 0x0E6, NC                        ,     ALWAYS      )
-GMM_FORMAT( Y8_UNORM                     ,   8,  1,  1, 1, R, x, 0x150, FC(2,  x,    NV12,   ,   ),     ALWAYS      )
-GMM_FORMAT( YCRCB_NORMAL                 ,  16,  1,  1, 1, R, x, 0x182, FC(2,  x,    YUY2,   ,   ),     ALWAYS      )
-GMM_FORMAT( YCRCB_SWAPUV                 ,  16,  1,  1, 1, R, x, 0x18F, FC(2,  x, YCRCB_SWAPUV, ,),     ALWAYS      )
-GMM_FORMAT( YCRCB_SWAPUVY                ,  16,  1,  1, 1, R, x, 0x183, FC(2,  x, YCRCB_SWAPUVY,,),     ALWAYS      )
-GMM_FORMAT( YCRCB_SWAPY                  ,  16,  1,  1, 1, R, x, 0x190, FC(2,  x, YCRCB_SWAPY, , ),     ALWAYS      )
+GMM_FORMAT( Y8_UNORM                     ,   8,  1,  1, 1, R, x, 0x150, FC(4,  x,    NV12,   ,_L ),     ALWAYS      )
+GMM_FORMAT( YCRCB_NORMAL                 ,  16,  1,  1, 1, R, x, 0x182, FC(4,  x,    YUY2,   ,   ),     ALWAYS      )
+GMM_FORMAT( YCRCB_SWAPUV                 ,  16,  1,  1, 1, R, x, 0x18F, FC(4,  x, YCRCB_SWAPUV, ,),     ALWAYS      )
+GMM_FORMAT( YCRCB_SWAPUVY                ,  16,  1,  1, 1, R, x, 0x183, FC(4,  x, YCRCB_SWAPUVY,,),     ALWAYS      )
+GMM_FORMAT( YCRCB_SWAPY                  ,  16,  1,  1, 1, R, x, 0x190, FC(4,  x, YCRCB_SWAPY, , ),     ALWAYS      )
 #endif // INCLUDE_SURFACESTATE_FORMATS
 #ifdef INCLUDE_ASTC_FORMATS
 GMM_FORMAT( ASTC_FULL_2D_4x4_FLT16       , 128,  4,  4, 1, x, A, 0x140, NC                        ,   ASTC_HDR_2D   )
@@ -383,7 +386,7 @@ GMM_FORMAT( ASTC_LDR_3D_6x6x6_FLT16      , 128,  6,  6, 6, x, A, 0x0ff, NC
 #endif // INCLUDE_ASTC_FORMATS
 #ifdef INCLUDE_MISC_FORMATS
 GMM_FORMAT( AUYV                         ,  32,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( AYUV                         ,  32,  1,  1, 1, R, x,   NA , FC(2,  x,    AYUV,   ,   ),     ALWAYS      )
+GMM_FORMAT( AYUV                         ,  32,  1,  1, 1, R, x,   NA , FC(4,  x,    AYUV,   ,   ),     ALWAYS      )
 GMM_FORMAT( BAYER_BGGR8                  ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      ) // (0, 0) = B
 GMM_FORMAT( BAYER_BGGR16                 ,  16,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      ) // (0, 0) = B
 GMM_FORMAT( BAYER_GBRG8                  ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      ) // (0, 0) = G, (1, 0) = B
@@ -392,26 +395,26 @@ GMM_FORMAT( BAYER_GRBG8                  ,   8,  1,  1, 1, R, x,   NA , NC
 GMM_FORMAT( BAYER_GRBG16                 ,  16,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      ) // (0, 0) = G, (1, 0) = R
 GMM_FORMAT( BAYER_RGGB8                  ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      ) // (0, 0) = R
 GMM_FORMAT( BAYER_RGGB16                 ,  16,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      ) // (0, 0) = R
-GMM_FORMAT( BC1                          ,  64,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // Legacy GMM name for related HW format.
-GMM_FORMAT( BC2                          , 128,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // "
-GMM_FORMAT( BC3                          , 128,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // "
-GMM_FORMAT( BC4                          ,  64,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // "
-GMM_FORMAT( BC5                          , 128,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // "
-GMM_FORMAT( BC6                          , 128,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // "
-GMM_FORMAT( BC6H                         , 128,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // "
-GMM_FORMAT( BC7                          , 128,  4,  4, 1, x, x,   NA , NC                        ,     GEN(7)      ) // "
+GMM_FORMAT( BC1                          ,  64,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      ) // Legacy GMM name for related HW format.
+GMM_FORMAT( BC2                          , 128,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      ) // "
+GMM_FORMAT( BC3                          , 128,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      ) // "
+GMM_FORMAT( BC4                          ,  64,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      ) // "
+GMM_FORMAT( BC5                          , 128,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      ) // "
+GMM_FORMAT( BC6                          , 128,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      ) // "
+GMM_FORMAT( BC6H                         , 128,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      ) // "
+GMM_FORMAT( BC7                          , 128,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     GEN(7)      ) // "
 GMM_FORMAT( BGRP                         ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      ) // FOURCC:BGRP
-GMM_FORMAT( D16_UNORM                    ,  16,  1,  1, 1, x, x,   NA , FC(3, 16,       R, 16,  U),     ALWAYS      ) //Depth uses color format L1e.En
-GMM_FORMAT( D24_UNORM_X8_UINT            ,  32,  1,  1, 1, x, x,   NA , FC(3, 32,       R, 32, U1),     ALWAYS      )
-GMM_FORMAT( D32_FLOAT                    ,  32,  1,  1, 1, x, x,   NA , FC(3, 32,       R, 32, F1),     ALWAYS      )
+GMM_FORMAT( D16_UNORM                    ,  16,  1,  1, 1, x, x,   NA , FC(4, 16,       R, 16,  U),     ALWAYS      ) //Depth uses color format L1e.En
+GMM_FORMAT( D24_UNORM_X8_UINT            ,  32,  1,  1, 1, x, x,   NA , FC(4, 32,       D, 32,  U),     ALWAYS      )
+GMM_FORMAT( D32_FLOAT                    ,  32,  1,  1, 1, x, x,   NA , FC(4, 32,       R, 32, F1),     ALWAYS      )
 GMM_FORMAT( DXT1                         ,  64,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // Legacy GMM name for related HW format.
 GMM_FORMAT( DXT2_5                       , 128,  4,  4, 1, x, x,   NA , NC                        ,     ALWAYS      ) // "
-GMM_FORMAT( ETC1                         ,  64,  4,  4, 1, x, x,   NA , NC                        , GEN(8) || VLV2  ) // "
-GMM_FORMAT( ETC2                         ,  64,  4,  4, 1, x, x,   NA , NC                        , GEN(8) || VLV2  ) // "
-GMM_FORMAT( ETC2_EAC                     , 128,  4,  4, 1, x, x,   NA , NC                        , GEN(8) || VLV2  ) // "
-GMM_FORMAT( GENERIC_8BIT                 ,   8,  1,  1, 1, x, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( GENERIC_16BIT                ,  16,  1,  1, 1, x, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( GENERIC_24BIT                ,  24,  1,  1, 1, x, x,   NA , NC                        ,     ALWAYS      )
+GMM_FORMAT( ETC1                         ,  64,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  ) // "
+GMM_FORMAT( ETC2                         ,  64,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  ) // "
+GMM_FORMAT( ETC2_EAC                     , 128,  4,  4, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ), GEN(8) || VLV2  ) // "
+GMM_FORMAT( GENERIC_8BIT                 ,   8,  1,  1, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( GENERIC_16BIT                ,  16,  1,  1, 1, x, x,   NA , FC(4,  x,     ML8,   ,   ),     ALWAYS      )
+GMM_FORMAT( GENERIC_24BIT                ,  24,  1,  1, 1, x, x,   NA , NC                        ,     ALWAYS      )    // verify ML8 for > 16 bit
 GMM_FORMAT( GENERIC_32BIT                ,  32,  1,  1, 1, x, x,   NA , NC                        ,     ALWAYS      )
 GMM_FORMAT( GENERIC_48BIT                ,  48,  1,  1, 1, x, x,   NA , NC                        ,     ALWAYS      )
 GMM_FORMAT( GENERIC_64BIT                ,  64,  1,  1, 1, x, x,   NA , NC                        ,     ALWAYS      )
@@ -421,59 +424,59 @@ GMM_FORMAT( GENERIC_192BIT               , 192,  1,  1, 1, x, x,   NA , NC
 GMM_FORMAT( GENERIC_256BIT               , 256,  1,  1, 1, x, x,   NA , NC                        ,     GEN(8)      )
 GMM_FORMAT( I420                         ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      ) // Same as IYUV.
 GMM_FORMAT( IYUV                         ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( IMC1                         ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     ALWAYS      )
-GMM_FORMAT( IMC2                         ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     ALWAYS      )
-GMM_FORMAT( IMC3                         ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     ALWAYS      )
-GMM_FORMAT( IMC4                         ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     ALWAYS      )
-GMM_FORMAT( L4A4                         ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     ALWAYS      ) // A4L4. No HW support.
-GMM_FORMAT( MFX_JPEG_YUV411              ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     GEN(7)      )
-GMM_FORMAT( MFX_JPEG_YUV411R             ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     GEN(7)      )
-GMM_FORMAT( MFX_JPEG_YUV420              ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     GEN(7)      ) // Same as IMC3.
-GMM_FORMAT( MFX_JPEG_YUV422H             ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     GEN(7)      )
-GMM_FORMAT( MFX_JPEG_YUV422V             ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     GEN(7)      )
-GMM_FORMAT( MFX_JPEG_YUV444              ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     GEN(7)      )
+GMM_FORMAT( IMC1                         ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     ALWAYS      )
+GMM_FORMAT( IMC2                         ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     ALWAYS      )
+GMM_FORMAT( IMC3                         ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     ALWAYS      )
+GMM_FORMAT( IMC4                         ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     ALWAYS      )
+GMM_FORMAT( L4A4                         ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     ALWAYS      ) // No HW support.
+GMM_FORMAT( MFX_JPEG_YUV411              ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     GEN(7)      )
+GMM_FORMAT( MFX_JPEG_YUV411R             ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     GEN(7)      )
+GMM_FORMAT( MFX_JPEG_YUV420              ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     GEN(7)      ) // Same as IMC3.
+GMM_FORMAT( MFX_JPEG_YUV422H             ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     GEN(7)      )
+GMM_FORMAT( MFX_JPEG_YUV422V             ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     GEN(7)      )
+GMM_FORMAT( MFX_JPEG_YUV444              ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     GEN(7)      )
 GMM_FORMAT( NV11                         ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( NV12                         ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     ALWAYS      )
-GMM_FORMAT( NV21                         ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     ALWAYS      )
+GMM_FORMAT( NV12                         ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     ALWAYS      )
+GMM_FORMAT( NV21                         ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     ALWAYS      )
 GMM_FORMAT( P8                           ,   8,  1,  1, 1, R, x,   NA,  NC                        ,     ALWAYS      )
-GMM_FORMAT( P010                         ,  16,  1,  1, 1, R, x,   NA , FC(2,  x,    P010,   ,   ),     ALWAYS      )
+GMM_FORMAT( P010                         ,  16,  1,  1, 1, R, x,   NA , FC(4,  x,    P010,   ,_L ),     ALWAYS      )
 GMM_FORMAT( P012                         ,  16,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( P016                         ,  16,  1,  1, 1, R, x,   NA , FC(2,  x,    P016,   ,   ),     ALWAYS      )
+GMM_FORMAT( P016                         ,  16,  1,  1, 1, R, x,   NA , FC(4,  x,    P016,   ,_L ),     ALWAYS      )
 GMM_FORMAT( P208                         ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( R10G10B10_XR_BIAS_A2_UNORM   ,  32,  1,  1, 1, x, x,   NA , FC(2,  x, RGB10A2,   ,   ),     ALWAYS      ) // DXGI_FORMAT_R10G10B10_XR_BIAS_A2_UNORM
-GMM_FORMAT( R24G8_TYPELESS               ,  32,  1,  1, 1, x, x,   NA , FC(2, 32,       R, 32,  U),     ALWAYS      ) // DXGI_FORMAT_R24G8_TYPELESS (To differentiate between GENERIC_32BIT.)
-GMM_FORMAT( R32G8X24_TYPELESS            ,  64,  1,  1, 1, x, x,   NA , FC(2, 32,       R, 32,  U),     ALWAYS      ) // DXGI_FORMAT_R32G8X24_TYPELESS (To differentiate between GENERIC_64BIT.)
+GMM_FORMAT( R10G10B10_XR_BIAS_A2_UNORM   ,  32,  1,  1, 1, x, x,   NA , FC(4,  x, RGB10A2,   ,   ),     ALWAYS      ) // DXGI_FORMAT_R10G10B10_XR_BIAS_A2_UNORM
+GMM_FORMAT( R24G8_TYPELESS               ,  32,  1,  1, 1, x, x,   NA , FC(4, 32,       R, 32,  U),     ALWAYS      ) // DXGI_FORMAT_R24G8_TYPELESS (To differentiate between GENERIC_32BIT.)
+GMM_FORMAT( R32G8X24_TYPELESS            ,  64,  1,  1, 1, x, x,   NA , FC(4, 32,       R, 32,  U),     ALWAYS      ) // DXGI_FORMAT_R32G8X24_TYPELESS (To differentiate between GENERIC_64BIT.)
 GMM_FORMAT( RENDER_8BIT                  ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( RGBP                         ,   8,  1,  1, 1, R, x,   NA , FC(2,  x,    NV12,   ,   ),     ALWAYS      ) // FOURCC:RGBP
+GMM_FORMAT( RGBP                         ,   8,  1,  1, 1, R, x,   NA , FC(4,  x,    NV12,   ,_L ),     ALWAYS      ) // FOURCC:RGBP
 GMM_FORMAT( Y1_UNORM                     ,   1,  1,  1, 1, x, x,   NA , NC                        ,     GEN(8)      )
-GMM_FORMAT( Y8_UNORM_VA                  ,   8,  1,  1, 1, x, x,   NA , FC(2,  x,    NV12,   ,   ),     GEN(8)      )
-GMM_FORMAT( Y16_SNORM                    ,  16,  1,  1, 1, x, x,   NA , FC(2,  x,    P010,   ,   ),     GEN(8)      )
-GMM_FORMAT( Y16_UNORM                    ,  16,  1,  1, 1, x, x,   NA , FC(2,  x,    P010,   ,   ),     GEN(8)      )
+GMM_FORMAT( Y8_UNORM_VA                  ,   8,  1,  1, 1, x, x,   NA , FC(4,  x,    NV12,   ,_L ),     GEN(8)      )
+GMM_FORMAT( Y16_SNORM                    ,  16,  1,  1, 1, x, x,   NA , FC(4,  x,    P010,   ,_L ),     GEN(8)      )
+GMM_FORMAT( Y16_UNORM                    ,  16,  1,  1, 1, x, x,   NA , FC(4,  x,    P010,   ,_L ),     GEN(8)      )
 #if (IGFX_GEN >= IGFX_GEN10)
 GMM_FORMAT( Y32_UNORM                    ,  32,  1,  1, 1, x, x,   NA , NC                        ,     GEN(10)     ) // Y32 removed from Gen9 but still referenced, only available Gen10+
 #endif
-GMM_FORMAT( Y210                         ,  64,  2,  1, 1, R, x,   NA , FC(2,  x,    Y210,   ,   ),     GEN(11)     ) // Packed 422 10/12/16 bit
-GMM_FORMAT( Y212                         ,  64,  2,  1, 1, R, x,   NA , FC(2,  x,    Y216,   ,   ),     GEN(11)     )
-GMM_FORMAT( Y410                         ,  32,  1,  1, 1, R, x,   NA , FC(2,  x,    Y410,   ,   ),     GEN(11)     )
-GMM_FORMAT( Y412                         ,  64,  1,  1, 1, R, x,   NA , FC(2,  x,    Y416,   ,   ),     GEN(11)     )
-GMM_FORMAT( Y216                         ,  64,  2,  1, 1, R, x,   NA,  FC(2,  x,    Y216,   ,   ),     ALWAYS      )
-GMM_FORMAT( Y416                         ,  64,  1,  1, 1, R, x,   NA , FC(2,  x,    Y416,   ,   ),     ALWAYS      ) // Packed 444 10/12/16 bit,
+GMM_FORMAT( Y210                         ,  64,  2,  1, 1, R, x,   NA , FC(4,  x,    Y210,   ,   ),     GEN(11)     ) // Packed 422 10/12/16 bit
+GMM_FORMAT( Y212                         ,  64,  2,  1, 1, R, x,   NA , FC(4,  x,    Y216,   ,   ),     GEN(11)     )
+GMM_FORMAT( Y410                         ,  32,  1,  1, 1, R, x,   NA , FC(4,  x,    Y410,   ,   ),     GEN(11)     )
+GMM_FORMAT( Y412                         ,  64,  1,  1, 1, R, x,   NA , FC(4,  x,    Y416,   ,   ),     GEN(11)     )
+GMM_FORMAT( Y216                         ,  64,  2,  1, 1, R, x,   NA,  FC(4,  x,    Y216,   ,   ),     ALWAYS      )
+GMM_FORMAT( Y416                         ,  64,  1,  1, 1, R, x,   NA , FC(4,  x,    Y416,   ,   ),     ALWAYS      ) // Packed 444 10/12/16 bit,
 GMM_FORMAT( YV12                         ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
 GMM_FORMAT( YVU9                         ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
 // Implement packed 4:2:2 YUV format (UYVY, VYUY, YUY2, YVYU) as compressed block format by suffixing _2x1.(i.e. 32bpe 2x1 pixel blocks instead of 16bpp 1x1 block)
 // All OS components(UMDs/KMD) can switch to *_2x1 style independent of legacy implementation.
 // Refer GmmCommonExt.h for legacy implemenation of UYVY, VYUY, YUY2, YVYU)
 // TODO : Unify them when all OS-components switch to compressed block format
-GMM_FORMAT( UYVY_2x1                     ,  32,  2,  1, 1, R, x,   NA , FC(2,  x,   SWAPY,   ,   ),     ALWAYS      )
-GMM_FORMAT( VYUY_2x1                     ,  32,  2,  1, 1, R, x,   NA , FC(2,  x, SWAPUVY,   ,   ),     ALWAYS      )
-GMM_FORMAT( YUY2_2x1                     ,  32,  2,  1, 1, R, x,   NA , FC(2,  x,    YUY2,   ,   ),     ALWAYS      )
-GMM_FORMAT( YVYU_2x1                     ,  32,  2,  1, 1, R, x,   NA , FC(2,  x,  SWAPUV,   ,   ),     ALWAYS      )
+GMM_FORMAT( UYVY_2x1                     ,  32,  2,  1, 1, R, x,   NA , FC(4,  x,   SWAPY,   ,   ),     ALWAYS      )
+GMM_FORMAT( VYUY_2x1                     ,  32,  2,  1, 1, R, x,   NA , FC(4,  x, SWAPUVY,   ,   ),     ALWAYS      )
+GMM_FORMAT( YUY2_2x1                     ,  32,  2,  1, 1, R, x,   NA , FC(4,  x,    YUY2,   ,   ),     ALWAYS      )
+GMM_FORMAT( YVYU_2x1                     ,  32,  2,  1, 1, R, x,   NA , FC(4,  x,  SWAPUV,   ,   ),     ALWAYS      )
 GMM_FORMAT( MEDIA_Y1_UNORM               ,   1,  1,  1, 1, x, x,   NA , NC                        ,     GEN(8)      )
-GMM_FORMAT( MEDIA_Y8_UNORM               ,   8,  1,  1, 1, x, x,   NA , FC(2,  x,    NV12,   ,   ),     GEN(8)      )
-GMM_FORMAT( MEDIA_Y16_SNORM              ,  16,  1,  1, 1, x, x,   NA , FC(2,  x,    P010,   ,   ),     GEN(8)      )
-GMM_FORMAT( MEDIA_Y16_UNORM              ,  16,  1,  1, 1, x, x,   NA , FC(2,  x,    P010,   ,   ),     GEN(8)      )
+GMM_FORMAT( MEDIA_Y8_UNORM               ,   8,  1,  1, 1, x, x,   NA , FC(4,  x,    NV12,   ,_L ),     GEN(8)      )
+GMM_FORMAT( MEDIA_Y16_SNORM              ,  16,  1,  1, 1, x, x,   NA , FC(4,  x,    P010,   ,_L ),     GEN(8)      )
+GMM_FORMAT( MEDIA_Y16_UNORM              ,  16,  1,  1, 1, x, x,   NA , FC(4,  x,    P010,   ,_L ),     GEN(8)      )
 GMM_FORMAT( MEDIA_Y32_UNORM              ,   1,  1,  1, 1, x, x,   NA , NC                        ,     GEN(8)      ) // Y32 is BDW name for SKL Y1, and is 1bpp with 32b granularity
-GMM_FORMAT( B16G16R16A16_UNORM           ,  64,  1,  1, 1, R, x,   NA , FC(3, 16,    RGBA, 16,  U),     ALWAYS      ) // Swapped ARGB16 for media-SFC output
+GMM_FORMAT( B16G16R16A16_UNORM           ,  64,  1,  1, 1, R, x,   NA , FC(4, 16,    RGBA, 16,  U),     ALWAYS      ) // Swapped ARGB16 for media-SFC output
 GMM_FORMAT( P216                         ,  16,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
 #if _WIN32
 GMM_FORMAT( WGBOX_YUV444                 ,  32,  1,  1, 1, x, x,   NA , NC                        ,     GEN(9)      ) // For testing purposes only.
diff --git a/Source/GmmLib/inc/External/Common/GmmInfo.h b/Source/GmmLib/inc/External/Common/GmmInfo.h
index 95e3aa9..55a26f8 100644
--- a/Source/GmmLib/inc/External/Common/GmmInfo.h
+++ b/Source/GmmLib/inc/External/Common/GmmInfo.h
@@ -657,7 +657,8 @@ typedef struct _GMM_ADAPTER_INFO_
                                                    const void *   pSkuTable,
                                                    const void *   pWaTable,
                                                    const void *   pGtSysInfo,
-                                                   ADAPTER_BDF    sBdf);
+                                                   ADAPTER_BDF    sBdf,
+						   const GMM_CLIENT ClientType);
 #endif
         GMM_STATUS GMM_STDCALL          RemoveContext(ADAPTER_BDF sBdf);
         Context* GMM_STDCALL            GetAdapterLibContext(ADAPTER_BDF sBdf);
diff --git a/Source/GmmLib/inc/External/Common/GmmPlatformExt.h b/Source/GmmLib/inc/External/Common/GmmPlatformExt.h
index fdc9f47..7482ffc 100644
--- a/Source/GmmLib/inc/External/Common/GmmPlatformExt.h
+++ b/Source/GmmLib/inc/External/Common/GmmPlatformExt.h
@@ -61,6 +61,7 @@ typedef enum GMM_FLATCCS_FORMAT_ENUM
     GMM_FLATCCS_FORMAT_R32F1,
     GMM_FLATCCS_FORMAT_R32S1 = GMM_FLATCCS_FORMAT_R32F1,
     GMM_FLATCCS_FORMAT_R32U1 = GMM_FLATCCS_FORMAT_R32F1,
+    GMM_FLATCCS_FORMAT_D32U  = GMM_FLATCCS_FORMAT_R32F1,
 
     GMM_FLATCCS_FORMAT_R16F1,
     GMM_FLATCCS_FORMAT_R16S1 = GMM_FLATCCS_FORMAT_R16F1,
@@ -79,7 +80,11 @@ typedef enum GMM_FLATCCS_FORMAT_ENUM
     GMM_FLATCCS_FORMAT_Y216,
     GMM_FLATCCS_FORMAT_Y416,
     GMM_FLATCCS_FORMAT_P010,
+    GMM_FLATCCS_FORMAT_P010_L = GMM_FLATCCS_FORMAT_P010,         //MC 7h
+    GMM_FLATCCS_FORMAT_P010_C = GMM_FLATCCS_FORMAT_P010,         //MC 7h
     GMM_FLATCCS_FORMAT_P016,
+    GMM_FLATCCS_FORMAT_P016_L = GMM_FLATCCS_FORMAT_P016,         //MC 8h
+    GMM_FLATCCS_FORMAT_P016_C = GMM_FLATCCS_FORMAT_P016,         //MC 8h
     GMM_FLATCCS_FORMAT_AYUV,
     GMM_FLATCCS_FORMAT_ARGB8b,
     GMM_FLATCCS_FORMAT_SWAPY,
@@ -87,6 +92,8 @@ typedef enum GMM_FLATCCS_FORMAT_ENUM
     GMM_FLATCCS_FORMAT_SWAPUVY,
     GMM_FLATCCS_FORMAT_RGB10b,
     GMM_FLATCCS_FORMAT_NV12,
+    GMM_FLATCCS_FORMAT_NV12_L = GMM_FLATCCS_FORMAT_NV12,
+    GMM_FLATCCS_FORMAT_NV12_C = GMM_FLATCCS_FORMAT_NV12,
 
     GMM_FLATCCS_FORMAT_YCRCB_SWAPUV = GMM_FLATCCS_FORMAT_SWAPUV,
     GMM_FLATCCS_FORMAT_YCRCB_SWAPUVY = GMM_FLATCCS_FORMAT_SWAPUVY,
@@ -97,6 +104,99 @@ typedef enum GMM_FLATCCS_FORMAT_ENUM
     GMM_FLATCCS_FORMAT_INVALID,                          //equal to last valid encoding plus one
 } GMM_FLATCCS_FORMAT;
 
+typedef enum GMM_XE2_UNIFIED_COMP_FORMAT_ENUM
+{
+    GMM_XE2_UNIFIED_COMP_FORMAT_R8     = 0, //0h – bpc8 ‘R’
+    GMM_XE2_UNIFIED_COMP_MIN_FORMAT    = GMM_XE2_UNIFIED_COMP_FORMAT_R8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_NV12_L = GMM_XE2_UNIFIED_COMP_FORMAT_R8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_D32U   = GMM_XE2_UNIFIED_COMP_FORMAT_R8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R8U    = GMM_XE2_UNIFIED_COMP_FORMAT_R8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R8S    = GMM_XE2_UNIFIED_COMP_FORMAT_R8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R8U1   = GMM_XE2_UNIFIED_COMP_FORMAT_R8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R8S1   = GMM_XE2_UNIFIED_COMP_FORMAT_R8,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG8, //1h – bpc8 ‘RG’
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGB5A1 = GMM_XE2_UNIFIED_COMP_FORMAT_RG8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA4  = GMM_XE2_UNIFIED_COMP_FORMAT_RG8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_B5G6R5 = GMM_XE2_UNIFIED_COMP_FORMAT_RG8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_NV12_C = GMM_XE2_UNIFIED_COMP_FORMAT_RG8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG8U   = GMM_XE2_UNIFIED_COMP_FORMAT_RG8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG8S   = GMM_XE2_UNIFIED_COMP_FORMAT_RG8,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA8, // 2h – bpc8 ‘RGBA’
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA8U        = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA8S        = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_YUY2          = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_AYUV          = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB         = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_SWAPY         = GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB,
+    GMM_XE2_UNIFIED_COMP_FORMAT_SWAPUV        = GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB,
+    GMM_XE2_UNIFIED_COMP_FORMAT_SWAPUVY       = GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB,
+    GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB_SWAPUV  = GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB,
+    GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB_SWAPUVY = GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB,
+    GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB_SWAPY   = GMM_XE2_UNIFIED_COMP_FORMAT_YCRCB,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGB10A2, // 3h – 3bpc10_1bpc2 ‘RGBA10A2’
+    GMM_XE2_UNIFIED_COMP_FORMAT_Y410 = GMM_XE2_UNIFIED_COMP_FORMAT_RGB10A2,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG11B10, // 4h - 2bpc11_1bpc10 ‘RG11B10’
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_R16, // 5h - bpc16 ‘R’
+    GMM_XE2_UNIFIED_COMP_FORMAT_R16U   = GMM_XE2_UNIFIED_COMP_FORMAT_R16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R16S   = GMM_XE2_UNIFIED_COMP_FORMAT_R16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R16F1  = GMM_XE2_UNIFIED_COMP_FORMAT_R16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R16U1  = GMM_XE2_UNIFIED_COMP_FORMAT_R16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R16S1  = GMM_XE2_UNIFIED_COMP_FORMAT_R16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_P010_L = GMM_XE2_UNIFIED_COMP_FORMAT_R16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_P016_L = GMM_XE2_UNIFIED_COMP_FORMAT_R16,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG16, // 6h – bpc16 ‘RG’
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG16U  = GMM_XE2_UNIFIED_COMP_FORMAT_RG16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG16F  = GMM_XE2_UNIFIED_COMP_FORMAT_RG16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG16S  = GMM_XE2_UNIFIED_COMP_FORMAT_RG16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_P010_C = GMM_XE2_UNIFIED_COMP_FORMAT_RG16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_P016_C = GMM_XE2_UNIFIED_COMP_FORMAT_RG16,
+
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA16, // 7h - bpc16 ‘RGBA’
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA16U = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA16F = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA16,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA16S = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA16,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_R32, // 8h - bpc32 ‘R’
+    GMM_XE2_UNIFIED_COMP_FORMAT_R32U  = GMM_XE2_UNIFIED_COMP_FORMAT_R32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R32F  = GMM_XE2_UNIFIED_COMP_FORMAT_R32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R32S  = GMM_XE2_UNIFIED_COMP_FORMAT_R32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R32U1 = GMM_XE2_UNIFIED_COMP_FORMAT_R32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R32F1 = GMM_XE2_UNIFIED_COMP_FORMAT_R32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_R32S1 = GMM_XE2_UNIFIED_COMP_FORMAT_R32,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG32, // 9h - bpc32 ‘RG’
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG32U = GMM_XE2_UNIFIED_COMP_FORMAT_RG32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG32F = GMM_XE2_UNIFIED_COMP_FORMAT_RG32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RG32S = GMM_XE2_UNIFIED_COMP_FORMAT_RG32,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA32, // 10h - bpc32 ‘RGBA’
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA32U = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA32F = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA32,
+    GMM_XE2_UNIFIED_COMP_FORMAT_RGBA32S = GMM_XE2_UNIFIED_COMP_FORMAT_RGBA32,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_Y210, // 11h – packed YUV (Y210, Y416, Y216)
+    GMM_XE2_UNIFIED_COMP_FORMAT_Y216 = GMM_XE2_UNIFIED_COMP_FORMAT_Y210,
+    GMM_XE2_UNIFIED_COMP_FORMAT_Y416 = GMM_XE2_UNIFIED_COMP_FORMAT_Y210,
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RSVD1, // 12h – Unused
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_HW_RSVD, // 13h – HW Stateless from MMIO or Uncompressed
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_RSVD2_, // 13h – Stateless MMIO CMF?
+
+    GMM_XE2_UNIFIED_COMP_FORMAT_ML8 = 0xF, // 15h – ML and Lossy-Compressed textures
+    GMM_XE2_UNIFIED_COMP_MAX_FORMAT = GMM_XE2_UNIFIED_COMP_FORMAT_ML8,
+    GMM_XE2_UNIFIED_COMP_FORMAT_INVALID, //equal to last valid encoding plus one
+} GMM_XE2_UNIFIED_COMP_FORMAT;
+
+
 typedef enum GMM_UNIFIED_COMP_FORMAT_ENUM
 {
     GMM_UNIFIED_COMP_FORMAT_RGBA32F = 0, //0h - bpc32 RGBA F/S
@@ -286,14 +386,16 @@ typedef enum GMM_TILE_MODE_ENUM
     DEFINE_TILE_BPEs( YS_2D_16X ),
     DEFINE_TILE_BPEs( YS_3D     ),
 
-    // XE-HP
+    // XE_HP/Xe2_LPG
     TILE4,
     DEFINE_TILE_BPEs( _64_1D ),
     DEFINE_TILE_BPEs( _64_2D ),
     DEFINE_TILE_BPEs( _64_2D_2X),
     DEFINE_TILE_BPEs( _64_2D_4X),
     DEFINE_TILE_BPEs( _64_3D),
-
+    // Xe2 above
+    DEFINE_TILE_BPEs(_64_2D_8X),
+    DEFINE_TILE_BPEs(_64_2D_16X),
     GMM_TILE_MODES
 }GMM_TILE_MODE;
 
diff --git a/Source/GmmLib/inc/External/Common/GmmResourceFlags.h b/Source/GmmLib/inc/External/Common/GmmResourceFlags.h
index d6e230e..8592cd2 100644
--- a/Source/GmmLib/inc/External/Common/GmmResourceFlags.h
+++ b/Source/GmmLib/inc/External/Common/GmmResourceFlags.h
@@ -134,6 +134,10 @@ typedef struct GMM_RESOURCE_FLAG_REC
         uint32_t __PreWddm2SVM             : 1; // Internal GMM flag--Clients don't set.
         uint32_t Tile4                     : 1; // 4KB tile
         uint32_t Tile64                    : 1; // 64KB tile
+        uint32_t NotCompressed           : 1; // UMD to set this for a resource, this will be a request to GMM which need not be honoured always
+        uint32_t __MapCompressible       : 1; // Internal GMM flag which marks a resource as compressed during map, used for tracking
+        uint32_t __MapUnCompressible     : 1; // Internal GMM flag which marks a resource as not compressed during map, used for tracking
+		
     } Info;
 
     // Wa: Any Surface specific Work Around will go in here
diff --git a/Source/GmmLib/inc/External/Common/GmmResourceInfoCommon.h b/Source/GmmLib/inc/External/Common/GmmResourceInfoCommon.h
index f9b244a..bfc5af9 100644
--- a/Source/GmmLib/inc/External/Common/GmmResourceInfoCommon.h
+++ b/Source/GmmLib/inc/External/Common/GmmResourceInfoCommon.h
@@ -208,6 +208,7 @@ namespace GmmLib
             GMM_VIRTUAL uint32_t                GMM_STDCALL GetFastClearHeight(uint32_t MipLevel);
 
 
+
             /* inline functions */
 
 #ifndef __GMM_KMD__
@@ -294,14 +295,14 @@ namespace GmmLib
             /////////////////////////////////////////////////////////////////////////////////////
             GMM_INLINE_VIRTUAL GMM_INLINE_EXPORTED void* GMM_STDCALL GetSystemMemPointer(uint8_t IsD3DDdiAllocation)
             {
-                if (IsD3DDdiAllocation)
-                {
-                    return (void *)GMM_GFX_ADDRESS_CANONIZE(ExistingSysMem.pGfxAlignedVirtAddress);
-                }
-                else
-                {
-                    return (void *)GMM_GFX_ADDRESS_CANONIZE(ExistingSysMem.pVirtAddress);
-                }
+	        if (IsD3DDdiAllocation)
+	        {
+		    return (void *)GMM_GFX_ADDRESS_CANONIZE(ExistingSysMem.pGfxAlignedVirtAddress);
+	        }
+	        else
+	        {
+		    return (void *)GMM_GFX_ADDRESS_CANONIZE(ExistingSysMem.pVirtAddress);
+		}
             }
 
             /////////////////////////////////////////////////////////////////////////////////////
@@ -514,12 +515,42 @@ namespace GmmLib
                         switch (Surf.MSAA.NumSamples)
                         {
                             case 2:
+			                    MSAASpecialFactorForDepthAndStencil = 2;
+			                    if (GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling && (Surf.BitsPerPixel == 128))
+			                    {
+			                        MSAASpecialFactorForDepthAndStencil = 1;
+			                    }
+			                    break;
                             case 4:
                                 MSAASpecialFactorForDepthAndStencil = 2;
                                 break;
                             case 8:
+			                    MSAASpecialFactorForDepthAndStencil = 4;
+			                    if (GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)
+			                    {
+			                        if (Surf.BitsPerPixel == 32 || Surf.BitsPerPixel == 8)
+			                        {
+			                            MSAASpecialFactorForDepthAndStencil = 2;
+			                        }
+			                    }
+			                    else if (!GetGmmLibContext()->GetSkuTable().FtrTileY && !GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)
+			                    {
+			                        MSAASpecialFactorForDepthAndStencil = 2; // same as 4X
+			                    }
+			                    break;
                             case 16:
                                 MSAASpecialFactorForDepthAndStencil = 4;
+			                    if (GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)
+			                    {
+			                        if (Surf.BitsPerPixel == 64)
+			                        {
+			                            MSAASpecialFactorForDepthAndStencil = 8;
+			                        }
+			                    }
+			                    else if (!GetGmmLibContext()->GetSkuTable().FtrTileY && !GetGmmLibContext()->GetSkuTable().FtrXe2PlusTiling)
+			                    {
+			                        MSAASpecialFactorForDepthAndStencil = 2; // same as 4X
+			                    }
                                 break;
                             default:
                                 break;
@@ -950,14 +981,14 @@ namespace GmmLib
             GMM_INLINE_VIRTUAL GMM_INLINE_EXPORTED GMM_GFX_ADDRESS GMM_STDCALL GetGfxAddress()
             {
                 // Support for Sparse/Tiled resources will be unified in later
-                if (SvmAddress)
-                {
+	        if (SvmAddress)
+	        {
                     return GMM_GFX_ADDRESS_CANONIZE(SvmAddress);
-                }
-                else
-                {
-                    return 0;
-                }
+		}
+	        else
+	        {
+	            return 0;
+	        }
             }
 
             /////////////////////////////////////////////////////////////////////////////////////
@@ -1129,6 +1160,13 @@ namespace GmmLib
                     else if ((GmmAuxType == GMM_AUX_CC) && (Surf.Flags.Gpu.IndirectClearColor || Surf.Flags.Gpu.ColorDiscard))
                     {
                         Offset = Surf.Size + AuxSurf.UnpaddedSize;
+	                if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+	                {
+	                    if (Surf.MSAA.NumSamples > 1)
+	                    {
+	                        Offset = Surf.Size; // Beginning of MCS which is first 4K of AuxSurf, Clear colour is stored only for MSAA surfaces
+	                    }
+	                }
                     }
                     else if (GmmAuxType == GMM_AUX_COMP_STATE)
                     {
@@ -1210,7 +1248,22 @@ namespace GmmLib
                     }
                     else
                     {
-                        return (AuxSurf.CCSize);
+                    
+                        if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+                        {
+                            if (Surf.MSAA.NumSamples > 1)
+                            {
+                                return (AuxSurf.UnpaddedSize); // CC is part of MCS
+                            }
+                            else
+                            {
+                                return 0; // fixed CC values used, not stored as part of Aux
+                            }
+                        }
+                        else
+                        {
+                            return (AuxSurf.CCSize);
+                        }										
                     }
                 }
                 else if (GmmAuxType == GMM_AUX_ZCS)
@@ -1414,10 +1467,17 @@ namespace GmmLib
                         {
                             switch (GetHAlign())
                             {
-                                case 4:  HAlign = 1; break;
-                                case 8:  HAlign = 2; break;
-                                case 16: HAlign = 3; break;
-                                default: HAlign = 1; // TODO(Benign): Change back to 0 + assert after packed YUV handling corrected.
+			                case 4:
+			                    HAlign = 1;
+			                    break;
+			                case 8:
+			                    HAlign = 2;
+			                    break;
+			                case 16:
+			                    HAlign = 3;
+			                    break;
+			                default:
+			                    HAlign = 1; // Change back to 0 + assert after packed YUV handling corrected.
                             }
                         }
                         else
@@ -1429,26 +1489,43 @@ namespace GmmLib
                                 Align = GetHAlign();
                             }
 
-                            switch (Align)
-                            {
-                                case  16:  HAlign = 0; break;
-                                case  32:  HAlign = 1; break;
-                                case  64:  HAlign = 2; break;
-                                case 128:  HAlign = 3; break;
-                                default:   HAlign = 0; __GMM_ASSERT(0);
+		                    switch (Align)
+		                    {
+		                    case 16:
+		                        HAlign = 0;
+		                        break;
+		                    case 32:
+		                        HAlign = 1;
+		                        break;
+		                    case 64:
+		                        HAlign = 2;
+		                        break;
+		                    case 128:
+                            case 256:
+		                        HAlign = 3;
+		                        break;
+		                    default:
+		                        HAlign = 0;
+		                        __GMM_ASSERT(0);
                             }
-                        }
-                    }
-                }
-                else
-                {
-                    switch (Surf.Alignment.HAlign)
-                    {
-                        case 4:  HAlign = 0; break;
-                        case 8:  HAlign = 1; break;
-                        default: HAlign = 0; __GMM_ASSERT(0);
-                    }
                 }
+            }
+        }
+        else
+        {
+            switch (Surf.Alignment.HAlign)
+            {
+            case 4:
+                HAlign = 0;
+                break;
+            case 8:
+                HAlign = 1;
+                break;
+            default:
+                HAlign = 0;
+                __GMM_ASSERT(0);
+            }
+        }
 
                 return HAlign;
             }
@@ -1474,10 +1551,17 @@ namespace GmmLib
                     {
                         switch (GetVAlign())
                         {
-                            case 4:  VAlign = 1; break;
-                            case 8:  VAlign = 2; break;
-                            case 16: VAlign = 3; break;
-                            default: VAlign = 1;
+		                case 4:
+		                    VAlign = 1;
+		                    break;
+		                case 8:
+		                    VAlign = 2;
+		                    break;
+		                case 16:
+		                    VAlign = 3;
+		                    break;
+		                default:
+		                    VAlign = 1;
                         }
                     }
                 }
@@ -1485,9 +1569,15 @@ namespace GmmLib
                 {
                     switch (Surf.Alignment.VAlign)
                     {
-                        case 2:  VAlign = 0; break;
-                        case 4:  VAlign = 1; break;
-                        default: VAlign = 0; __GMM_ASSERT(0);
+		            case 2:
+		                VAlign = 0;
+		                break;
+		            case 4:
+		                VAlign = 1;
+		                break;
+		            default:
+		                VAlign = 0;
+		                __GMM_ASSERT(0);
                     }
                 }
 
@@ -1832,23 +1922,25 @@ namespace GmmLib
             {
                 const GMM_CACHE_POLICY_ELEMENT *CachePolicy = GetGmmLibContext()->GetCachePolicyUsage();
 
-                __GMM_ASSERT(CachePolicy[GetCachePolicyUsage()].Initialized);
+            GMM_RESOURCE_USAGE_TYPE Usage = GetCachePolicyUsage();
+
+		        __GMM_ASSERT(CachePolicy[Usage].Initialized);
 
                 // Prevent wrong Usage for XAdapter resources. UMD does not call GetMemoryObject on shader resources but,
                 // when they add it someone could call it without knowing the restriction.
                 if(Surf.Flags.Info.XAdapter &&
-                   GetCachePolicyUsage() != GMM_RESOURCE_USAGE_XADAPTER_SHARED_RESOURCE)
+                   (Usage != GMM_RESOURCE_USAGE_XADAPTER_SHARED_RESOURCE))
                 {
                     __GMM_ASSERT(false);
                 }
 
-                if((CachePolicy[GetCachePolicyUsage()].Override & CachePolicy[GetCachePolicyUsage()].IDCode) ||
-                   (CachePolicy[GetCachePolicyUsage()].Override == ALWAYS_OVERRIDE))
+                if((CachePolicy[Usage].Override & CachePolicy[Usage].IDCode) ||
+                   (CachePolicy[Usage].Override == ALWAYS_OVERRIDE))
                 {
-                    return CachePolicy[GetCachePolicyUsage()].MemoryObjectOverride;
+                    return CachePolicy[Usage].MemoryObjectOverride;
                 }
 
-                return CachePolicy[GetCachePolicyUsage()].MemoryObjectNoOverride;
+                return CachePolicy[Usage].MemoryObjectNoOverride;
             }
 
             /////////////////////////////////////////////////////////////////////////////////////
@@ -1897,8 +1989,15 @@ namespace GmmLib
                         Surf.Flags.Info.ExistingSysMem ||
                         Surf.Flags.Info.NonLocalOnly))
                 {
-                    return GFX_CEIL_DIV(Surf.Size, 256);
-                }
+		    if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+		    {
+			return GFX_CEIL_DIV(Surf.Size, 512);
+		    }
+		    else
+		    {
+			return GFX_CEIL_DIV(Surf.Size, 256);
+		    }
+		}
                 return 0;
             }
 			/////////////////////////////////////////////////////////////////////////////////////
@@ -1998,16 +2097,82 @@ namespace GmmLib
             /////////////////////////////////////////////////////////////////////////////////////
             GMM_INLINE_VIRTUAL GMM_INLINE_EXPORTED uint32_t GMM_STDCALL Is1MBAlignedAuxTPlanarSurface()
             {
-		const GMM_PLATFORM_INFO *pPlatform = (GMM_PLATFORM_INFO *)GMM_OVERRIDE_EXPORTED_PLATFORM_INFO(&Surf, GetGmmLibContext());
+	        const GMM_PLATFORM_INFO *pPlatform = (GMM_PLATFORM_INFO *)GMM_OVERRIDE_EXPORTED_PLATFORM_INFO(&Surf, GetGmmLibContext());
 		
-		if(GMM_IS_1MB_AUX_TILEALIGNEDPLANES(pPlatform->Platform, Surf))
-		{
-		    return Surf.OffsetInfo.PlaneXe_LPG.Is1MBAuxTAlignedPlanes;
-		}
+	        if(GMM_IS_1MB_AUX_TILEALIGNEDPLANES(pPlatform->Platform, Surf))
+	        {
+	            return Surf.OffsetInfo.PlaneXe_LPG.Is1MBAuxTAlignedPlanes;
+	        }
 		
-		return 0;          
+	        return 0;          
             }
 
+            GMM_INLINE_VIRTUAL GMM_INLINE_EXPORTED uint32_t GMM_STDCALL IsResourceMappedCompressible()
+            {
+                uint32_t CompressedRes = 0;
+                if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+                {
+                    CompressedRes = !Surf.Flags.Info.NotCompressed;
+                }
+                else
+                {
+                    CompressedRes = Surf.Flags.Info.RenderCompressed || Surf.Flags.Info.MediaCompressed;
+                }
+
+                return CompressedRes;
+            }
+			
+	    /////////////////////////////////////////////////////////////////////////////////////
+	    /// Returns true for displayable resources
+	    /// @return
+	    /////////////////////////////////////////////////////////////////////////////////////
+	    GMM_INLINE_VIRTUAL GMM_INLINE_EXPORTED bool GMM_STDCALL IsDisplayable()
+	    {
+	        return ((Surf.Type == RESOURCE_PRIMARY) || (Surf.Type == RESOURCE_CURSOR) || Surf.Flags.Gpu.FlipChain || Surf.Flags.Gpu.Overlay);
+	    }
+						
+	    GMM_INLINE_VIRTUAL GMM_INLINE_EXPORTED uint64_t GMM_STDCALL GetDriverProtectionBits(GMM_OVERRIDE_VALUES OverrideData)
+	    {
+	        GMM_DRIVERPROTECTION     DriverProtection = {{0}};
+	        const GMM_PLATFORM_INFO *pPlatform;
+	        GMM_RESOURCE_USAGE_TYPE  Usage;
+
+	        pPlatform = (GMM_PLATFORM_INFO *)GMM_OVERRIDE_EXPORTED_PLATFORM_INFO(&Surf, GetGmmLibContext());
+	        if (GFX_GET_CURRENT_PRODUCT(pPlatform->Platform) < IGFX_PVC)
+	        {
+	            return 0;
+	        }
+	        Usage = Surf.CachePolicy.Usage;
+	        if ((OverrideData.Usage > GMM_RESOURCE_USAGE_UNKNOWN) && (OverrideData.Usage < GMM_RESOURCE_USAGE_MAX)) 
+	        {
+	            Usage = (GMM_RESOURCE_USAGE_TYPE)OverrideData.Usage;
+	        }
+	        if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
+	        {
+	            if (OverrideData.CompressionDis)
+	            {
+	                DriverProtection.CompressionEnReq = 0;
+	            }
+	            else
+	            {
+
+	                DriverProtection.CompressionEnReq = !Surf.Flags.Info.NotCompressed;
+	            }
+	        }
+
+	        bool IscompressionEn              = DriverProtection.CompressionEnReq ? true : false;
+	        DriverProtection.CacheableNoSnoop = false;
+
+	        DriverProtection.PATIndex = GetGmmLibContext()->GetCachePolicyObj()->CachePolicyGetPATIndex(NULL, Usage, &IscompressionEn, (bool)(Surf.Flags.Info.Cacheable));
+
+	        DriverProtection.CompressionEnReq = IscompressionEn ? true : false;
+
+	        return DriverProtection.Value;
+	    }
+	    
+	    GMM_VIRTUAL uint64_t GMM_STDCALL       Get2DFastClearSurfaceWidthFor3DSurface(uint32_t MipLevel);
+	    GMM_VIRTUAL uint64_t GMM_STDCALL       Get2DFastClearSurfaceHeightFor3DSurface(uint32_t MipLevel);
+		
     };
 
 } // namespace GmmLib
diff --git a/Source/GmmLib/inc/External/Common/GmmResourceInfoExt.h b/Source/GmmLib/inc/External/Common/GmmResourceInfoExt.h
index 0ffd558..5dd38ec 100644
--- a/Source/GmmLib/inc/External/Common/GmmResourceInfoExt.h
+++ b/Source/GmmLib/inc/External/Common/GmmResourceInfoExt.h
@@ -363,6 +363,19 @@ typedef struct GMM_RESCREATE_CUSTOM_PARAMS__REC
     uint32_t CpTag;
 }GMM_RESCREATE_CUSTOM_PARAMS;
 
+typedef union GMM_DRIVERPROTECTION_BITS
+{
+    struct
+    {
+        uint64_t PATIndex        : 5; // PATIndex
+        uint64_t Reserved        : 25;
+        uint64_t CacheableNoSnoop: 1;  // disregard OS's coherent request in UpdatePageTable
+        uint64_t CompressionEnReq: 1;  // C/NC request from UMD
+        uint64_t Reserved1       : 32; //DO NOT SET !! Reserved for OS Refer: D3DGPU_UNIQUE_DRIVER_PROTECTION
+    };
+    uint64_t Value;
+} GMM_DRIVERPROTECTION;
+
 #ifndef __GMM_KMD__
 typedef struct GMM_RESCREATE_CUSTOM_PARAMS_2_REC : public GMM_RESCREATE_CUSTOM_PARAMS
 {
@@ -383,6 +396,12 @@ typedef struct GMM_RESCREATE_CUSTOM_PARAMS_2_REC : public GMM_RESCREATE_CUSTOM_P
 }GMM_RESCREATE_CUSTOM_PARAMS_2;
 #endif
 
+typedef struct GMM_OVERRIDE_VALUES_REC
+{
+    uint32_t Usage; // GMM_RESOURCE_USAGE_TYPE
+    uint8_t  CompressionDis;
+} GMM_OVERRIDE_VALUES;
+
 //===========================================================================
 // enum :
 //        GMM_UNIFIED_AUX_TYPE
@@ -671,9 +690,10 @@ GMM_GFX_SIZE_T      GMM_STDCALL GmmResGetPlanarGetXOffset(GMM_RESOURCE_INFO *pGm
 GMM_GFX_SIZE_T      GMM_STDCALL GmmResGetPlanarGetYOffset(GMM_RESOURCE_INFO *pGmmResource, GMM_YUV_PLANE Plane);
 GMM_GFX_SIZE_T      GMM_STDCALL GmmResGetPlanarAuxOffset(GMM_RESOURCE_INFO *pGmmResource, uint32_t ArrayIndex, GMM_UNIFIED_AUX_TYPE Plane);
 void                GMM_STDCALL GmmResSetLibContext(GMM_RESOURCE_INFO *pGmmResource, void *pLibContext);
-
+uint32_t            GMM_STDCALL GmmResIsMappedCompressible(GMM_RESOURCE_INFO *pGmmResource);
 // Remove when client moves to new interface
 uint32_t            GMM_STDCALL GmmResGetRenderSize(GMM_RESOURCE_INFO *pResourceInfo);
+uint8_t GMM_STDCALL GmmGetCompressionFormat(GMM_RESOURCE_FORMAT Format, GMM_LIB_CONTEXT *pGmmLibContext);
 
 //=====================================================================================================
 //forward declarations
diff --git a/Source/GmmLib/inc/Internal/Common/GmmCommonInt.h b/Source/GmmLib/inc/Internal/Common/GmmCommonInt.h
index b11d4b3..a83c72c 100644
--- a/Source/GmmLib/inc/Internal/Common/GmmCommonInt.h
+++ b/Source/GmmLib/inc/Internal/Common/GmmCommonInt.h
@@ -20,3 +20,13 @@ ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 ============================================================================*/
 #pragma once
+
+// Helper Macros for CoherentPATIndex Value handling.
+#define CONCATENATE_COHERENT_PATINDEX(a, b) (((a & __BIT(0)) << 5) | b) // 'a' ->higher order bits 6th bit [5] MSB, 'b' -> Lower order 5 bits [4:0]
+
+#define GET_COHERENT_PATINDEX_VALUE(pGmmLibContext, usage) (CONCATENATE_COHERENT_PATINDEX(pGmmLibContext->GetCachePolicyElement(usage).CoherentPATIndexHigherBit, \
+                                                                                          pGmmLibContext->GetCachePolicyElement(usage).CoherentPATIndex))
+
+#define GET_COHERENT_PATINDEX_LOWER_BITS(value) (value & (~(~0 << 5)))
+
+#define GET_COHERENT_PATINDEX_HIGHER_BIT(value) ((value >> 5) & __BIT(0))
diff --git a/Source/GmmLib/inc/Internal/Common/GmmLibInc.h b/Source/GmmLib/inc/Internal/Common/GmmLibInc.h
index 4f17aa8..04581f5 100644
--- a/Source/GmmLib/inc/Internal/Common/GmmLibInc.h
+++ b/Source/GmmLib/inc/Internal/Common/GmmLibInc.h
@@ -40,6 +40,7 @@ OTHER DEALINGS IN THE SOFTWARE.
 #include "External/Common/CachePolicy/GmmCachePolicyGen11.h"
 #include "External/Common/CachePolicy/GmmCachePolicyGen12.h"
 #include "External/Common/CachePolicy/GmmCachePolicyXe_LPG.h"
+#include "External/Common/CachePolicy/GmmCachePolicyXe2_LPG.h"
 #include "External/Common/CachePolicy/GmmCachePolicyGen12dGPU.h"
 #include "External/Common/GmmResourceInfoExt.h"
 #include "../Platform/GmmPlatforms.h"
@@ -63,7 +64,7 @@ OTHER DEALINGS IN THE SOFTWARE.
 #include "External/Common/GmmInfo.h"
 #include "../Utility/GmmUtility.h"
 #include "External/Common/GmmPageTableMgr.h"
-
+#include "Internal/Common/GmmCommonInt.h"
 #include "External/Common/GmmDebug.h"                   // Unified Definitions of GMM_ASSERT and GMM_DEBUG Macros
 
 #ifndef DXGKDDI_INTERFACE_VERSION_WDDM1_3
diff --git a/Source/GmmLib/inc/Internal/Common/Platform/GmmGen12Platform.h b/Source/GmmLib/inc/Internal/Common/Platform/GmmGen12Platform.h
index 50df1f6..04a41af 100644
--- a/Source/GmmLib/inc/Internal/Common/Platform/GmmGen12Platform.h
+++ b/Source/GmmLib/inc/Internal/Common/Platform/GmmGen12Platform.h
@@ -47,6 +47,7 @@ typedef enum _FC_TileType
     FC_TILE_YS,
     FC_TILE_4,
     FC_TILE_64,
+    FC_TILE_64_3D,
     //max equals last supported plus one
     FC_TILE_MAX
 } FC_TILE_TYPE;
@@ -56,11 +57,12 @@ typedef enum _FC_TileType
                            (((x) >= TILE_YF_2D_8bpe && (x) <= TILE_YF_2D_128bpe) ? (FC_TILE_YF) : \
                            (((x) >= TILE_YS_2D_8bpe && (x) <= TILE_YS_2D_128bpe) ? (FC_TILE_YS) : \
                            (((x) >= TILE__64_2D_8bpe && (x) <= TILE__64_2D_128bpe) ? (FC_TILE_64) : \
-                           (FC_TILE_MAX))))))
-#define FCMaxBppModes      5
-#define FCMaxModes         FC_TILE_MAX * FCMaxBppModes
-#define FCBppMode(bpp)     __GmmLog2(bpp) - 3
-#define FCMode(TileMode, bpp)  (FCTilingType(TileMode) < FC_TILE_MAX) ? (FCTilingType(TileMode) * FCMaxBppModes + FCBppMode(bpp)) : FCMaxModes
+                           (((x) >= TILE__64_3D_8bpe && (x) <= TILE__64_3D_128bpe) ? (FC_TILE_64_3D) : \
+                           (FC_TILE_MAX)))))))
+#define FCMaxBppModes         5
+#define FCMaxModes            FC_TILE_MAX *FCMaxBppModes
+#define FCBppMode(bpp)        __GmmLog2(bpp) - 3
+#define FCMode(TileMode, bpp) (FCTilingType(TileMode) < FC_TILE_MAX) ? (FCTilingType(TileMode) * FCMaxBppModes + FCBppMode(bpp)) : FCMaxModes
 
 //===========================================================================
 // typedef:
diff --git a/Source/GmmLib/inc/Internal/Common/Texture/GmmGen12TextureCalc.h b/Source/GmmLib/inc/Internal/Common/Texture/GmmGen12TextureCalc.h
index 5b76bb2..b3dd9d2 100644
--- a/Source/GmmLib/inc/Internal/Common/Texture/GmmGen12TextureCalc.h
+++ b/Source/GmmLib/inc/Internal/Common/Texture/GmmGen12TextureCalc.h
@@ -108,6 +108,11 @@ namespace GmmLib
                 GMM_UNREFERENCED_PARAMETER(WidthBytesPhysical);
                 GMM_UNREFERENCED_PARAMETER(WidthBytesLock);
             }
+            virtual uint64_t GMM_STDCALL Get2DFCSurfaceWidthFor3DSurface(GMM_TEXTURE_INFO *pTexInfo,
+                                                                 uint64_t          Width);
+            virtual uint64_t GMM_STDCALL Get2DFCSurfaceHeightFor3DSurface(GMM_TEXTURE_INFO *pTexInfo,
+                                                                  uint32_t          Height,
+                                                                  uint32_t          Depth);
 
             /* inline functions */
     };
diff --git a/Source/GmmLib/inc/Internal/Common/Texture/GmmTextureCalc.h b/Source/GmmLib/inc/Internal/Common/Texture/GmmTextureCalc.h
index 1426c5e..8620200 100644
--- a/Source/GmmLib/inc/Internal/Common/Texture/GmmTextureCalc.h
+++ b/Source/GmmLib/inc/Internal/Common/Texture/GmmTextureCalc.h
@@ -346,6 +346,20 @@ namespace GmmLib
                                                                 GMM_GFX_SIZE_T &WidthBytesPhysical,
                                                                 GMM_GFX_SIZE_T &WidthBytesLock);
             GMM_STATUS MSAACompression(GMM_TEXTURE_INFO *pTexInfo);
+		virtual uint64_t GMM_STDCALL Get2DFCSurfaceWidthFor3DSurface(GMM_TEXTURE_INFO *pTexInfo,
+		                                                             uint64_t          Width)
+		{
+		    GMM_UNREFERENCED_PARAMETER(pTexInfo);
+		    return Width;
+		}
+		virtual uint64_t GMM_STDCALL Get2DFCSurfaceHeightFor3DSurface(GMM_TEXTURE_INFO *pTexInfo,
+		                                                              uint32_t          Height,
+		                                                              uint32_t          Depth)
+		{
+		    GMM_UNREFERENCED_PARAMETER(pTexInfo);
+		    GMM_UNREFERENCED_PARAMETER(Depth);
+		    return Height;
+		}
 
             uint32_t GMM_STDCALL GetDisplayFrameOffset(GMM_TEXTURE_INFO    *pTexInfo,
                                                        GMM_REQ_OFFSET_INFO *pReqInfo);	    
@@ -366,8 +380,6 @@ namespace GmmLib
             virtual void GMM_STDCALL GetBltInfoPerPlane(GMM_TEXTURE_INFO *pTexInfo,
                                                              GMM_RES_COPY_BLT *pBlt,
                                                              uint32_t PlaneId);
-
-
 	    /* inline functions */
     };
 
diff --git a/Source/GmmLib/inc/Internal/Common/Texture/GmmXe_LPGTextureCalc.h b/Source/GmmLib/inc/Internal/Common/Texture/GmmXe_LPGTextureCalc.h
index 856771e..869f3aa 100644
--- a/Source/GmmLib/inc/Internal/Common/Texture/GmmXe_LPGTextureCalc.h
+++ b/Source/GmmLib/inc/Internal/Common/Texture/GmmXe_LPGTextureCalc.h
@@ -81,8 +81,6 @@ namespace GmmLib
                                                              GMM_RES_COPY_BLT *pBlt,
                                                              uint32_t PlaneId);
 
-            
-
             /* inline functions */
     };
 }
diff --git a/Source/inc/common/gtsysinfo.h b/Source/inc/common/gtsysinfo.h
index 0289ff9..556ae55 100644
--- a/Source/inc/common/gtsysinfo.h
+++ b/Source/inc/common/gtsysinfo.h
@@ -283,7 +283,7 @@ typedef struct GT_SYSTEM_INFO
     GT_CACHE_TYPES  CacheTypes;                     // Types of caches available on system (L3/LLC/eDRAM).                     
     uint32_t        MaxVECS;                        // Max VECS instances.
     uint32_t        MemoryType;                     // GT_MEMORY_TYPES - type of memory supported in current platform
-
+    uint32_t        SLMSizeInKb;                    // SLM Size
 } GT_SYSTEM_INFO, *PGT_SYSTEM_INFO;
 
 #pragma pack(pop)
diff --git a/Source/inc/common/igfxfmid.h b/Source/inc/common/igfxfmid.h
index 5ef90f5..a9176de 100644
--- a/Source/inc/common/igfxfmid.h
+++ b/Source/inc/common/igfxfmid.h
@@ -77,7 +77,9 @@ typedef enum {
     IGFX_PVC = 1271,
     IGFX_METEORLAKE = 1272,
     IGFX_ARROWLAKE = 1273,
-
+    IGFX_BMG = 1274,
+    IGFX_LUNARLAKE = 1275,
+    
     IGFX_MAX_PRODUCT,
     IGFX_GENNEXT               = 0x7ffffffe,
     PRODUCT_FAMILY_FORCE_ULONG = 0x7fffffff
@@ -137,7 +139,9 @@ typedef enum {
     IGFX_XE_HP_CORE      = 0x0c05,  //XE_HP family
     IGFX_XE_HPG_CORE     = 0x0c07,  // XE_HPG Family
     IGFX_XE_HPC_CORE     = 0x0c08,  // XE_HPC Family
-                                
+    IGFX_XE2_LPG_CORE    = 0x0c09,  // XE2_LPG Family
+    IGFX_XE2_HPG_CORE    = IGFX_XE2_LPG_CORE,  //XE2_HPG Family
+
     //Please add new GENs BEFORE THIS !
     IGFX_MAX_CORE,
 
@@ -296,7 +300,8 @@ typedef enum __NATIVEGTTYPE
 // This macro returns true if the product family is discrete
 #define GFX_IS_DISCRETE_PRODUCT(pf)    ( ( pf == IGFX_DG1 )             ||   \
                                          ( pf == IGFX_DG2 )             ||   \
-                                         ( pf == IGFX_XE_HP_SDV ) )
+                                         ( pf == IGFX_XE_HP_SDV )       ||   \
+                                         ( pf == IGFX_BMG ) )
 
 #define GFX_IS_DISCRETE_FAMILY(p)      GFX_IS_DISCRETE_PRODUCT(GFX_GET_CURRENT_PRODUCT(p))
 
@@ -325,6 +330,7 @@ typedef enum __NATIVEGTTYPE
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||   \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||   \
+                                         ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE2_HPG_CORE ) ||   \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_5_OR_LATER(p)       ( ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN5_CORE )    ||   \
@@ -341,6 +347,7 @@ typedef enum __NATIVEGTTYPE
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||   \
+                                         ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE2_HPG_CORE ) ||   \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_5_75_OR_LATER(p)    ( ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN5_75_CORE ) ||   \
@@ -355,6 +362,7 @@ typedef enum __NATIVEGTTYPE
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||   \
+                                         ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE2_HPG_CORE ) ||   \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_6_OR_LATER(p)       ( ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN6_CORE )    ||   \
@@ -367,6 +375,7 @@ typedef enum __NATIVEGTTYPE
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||   \
+                                         ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE2_HPG_CORE ) ||   \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_7_OR_LATER(p)       ( ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN7_CORE )    ||   \
@@ -379,6 +388,7 @@ typedef enum __NATIVEGTTYPE
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||   \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||   \
+                                         ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE2_HPG_CORE ) ||  \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_7_5_OR_LATER(p)     ( ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN7_5_CORE )  ||  \
@@ -1886,6 +1896,7 @@ typedef enum __NATIVEGTTYPE
 #define DEV_ID_0BDB                            0x0BDB
 #define DEV_ID_0B69                            0x0B69
 #define DEV_ID_0B6E                            0x0B6E
+#define DEV_ID_0BD4                            0x0BD4
 
 // Macro to identify PVC device ID
 #define GFX_IS_XT_CONFIG(d) ((d == DEV_ID_0BD5)             ||  \
@@ -1896,7 +1907,8 @@ typedef enum __NATIVEGTTYPE
                              (d == DEV_ID_0BDA)             ||  \
                              (d == DEV_ID_0BDB)		    ||  \
                              (d == DEV_ID_0B69)             ||  \
-			     (d == DEV_ID_0B6E))
+			     (d == DEV_ID_0B6E)             ||  \
+			     (d == DEV_ID_0BD4))
 
 //DG2 Device IDs
 #define DEV_ID_4F80                             0x4F80
@@ -1932,8 +1944,11 @@ typedef enum __NATIVEGTTYPE
 #define DEV_ID_56BB                             0x56BB
 #define DEV_ID_56BC                             0x56BC
 #define DEV_ID_56BD                             0x56BD
+#define DEV_ID_56BE                             0x56BE
+#define DEV_ID_56BF                             0x56BF
 #define DEV_ID_56C0                             0x56C0
 #define DEV_ID_56C1                             0x56C1
+#define DEV_ID_56C2                             0x56C2
 
 // RPL-P/U
 #define DEV_ID_A7A0                             0xA7A0
@@ -1951,6 +1966,8 @@ typedef enum __NATIVEGTTYPE
 #define DEV_ID_46D0                             0x46D0
 #define DEV_ID_46D1                             0x46D1
 #define DEV_ID_46D2                             0x46D2
+#define DEV_ID_46D3                             0x46D3
+#define DEV_ID_46D4                             0x46D4
 
 // MTL
 #define DEV_ID_7D40                             0x7D40
@@ -1964,6 +1981,23 @@ typedef enum __NATIVEGTTYPE
 // ARL-S
 #define DEV_ID_7D67                             0x7D67
 
+// ARL-H
+#define DEV_ID_7D41                             0x7D41
+#define DEV_ID_7D51                             0x7D51
+#define DEV_ID_7DD1                             0x7DD1
+
+// LNL
+#define DEV_ID_64A0                             0x64A0
+#define DEV_ID_6420                             0x6420
+#define DEV_ID_64B0                             0x64B0
+
+//BMG
+#define DEV_ID_E202                             0xE202
+#define DEV_ID_E20B                             0xE20B
+#define DEV_ID_E20C                             0xE20C
+#define DEV_ID_E20D                             0xE20D
+#define DEV_ID_E212                             0xE212
+
 #define MGM_HAS     0
 
 //#define SDG_HAS      1              //Reserve place for Springdale-G HAS
@@ -1977,7 +2011,11 @@ typedef enum __NATIVEGTTYPE
                                  ( d == DEV_ID_5695 )             ||   \
                                  ( d == DEV_ID_56B0 )             ||   \
                                  ( d == DEV_ID_56B1 )             ||   \
-                                 ( d == DEV_ID_56C1 )             ||   \
+                                 ( d == DEV_ID_56BA )             ||   \
+                                 ( d == DEV_ID_56BB )             ||   \
+                                 ( d == DEV_ID_56BC )             ||   \
+                                 ( d == DEV_ID_56BD )             ||   \
+				 ( d == DEV_ID_56C1 )             ||   \
                                  ( d == DEV_ID_4F87 )             ||   \
                                  ( d == DEV_ID_4F88 ))
 
@@ -1987,7 +2025,10 @@ typedef enum __NATIVEGTTYPE
                                       ( d == DEV_ID_5690 )                              ||   \
                                       ( d == DEV_ID_5691 )                              ||   \
                                       ( d == DEV_ID_5692 )                              ||   \
-                                      ( d == DEV_ID_56C0 )                              ||   \
+                                      ( d == DEV_ID_56BE )                              ||   \
+                                      ( d == DEV_ID_56BF )                              ||   \
+				      ( d == DEV_ID_56C0 )                              ||   \
+	                              ( d == DEV_ID_56C2 )                              ||   \
                                       ( d == DEV_ID_4F80 )                              ||   \
                                       ( d == DEV_ID_4F81 )                              ||   \
                                       ( d == DEV_ID_4F82 )                              ||   \
@@ -2006,6 +2047,11 @@ typedef enum __NATIVEGTTYPE
 // Macro to identify ARL-S Device ID
 #define GFX_IS_ARL_S(d)  ( ( d == DEV_ID_7D67 ) )
 
+// Macro to identify ARL-H Device ID
+#define GFX_IS_ARL_H(d)  ( ( d == DEV_ID_7D41 )  ||   \
+                         ( d == DEV_ID_7D51 )    ||   \
+                         ( d == DEV_ID_7DD1 ))
+
 //we define the highest cap and lower cap of stepping IDs
 #define SI_REV_ID(lo,hi) (lo | hi<<16)
 
diff --git a/Source/inc/common/sku_wa.h b/Source/inc/common/sku_wa.h
index 80f57ba..9b7c117 100644
--- a/Source/inc/common/sku_wa.h
+++ b/Source/inc/common/sku_wa.h
@@ -70,6 +70,7 @@ typedef struct _SKU_FEATURE_TABLE
         unsigned int   FtrCCSNode : 1; // To indicate if CCS Node support is present.
         unsigned int   FtrTileY     : 1;  // Identifies Legacy tiles TileY/Yf/Ys on the platform
         unsigned int   FtrCCSMultiInstance : 1; // To indicate if driver supports MultiContext mode on RCS and more than 1 CCS.
+	unsigned int   FtrL3TransientDataFlush : 1;  // Transient data flush from L3 cache	
     };
 
 
@@ -109,6 +110,12 @@ typedef struct _SKU_FEATURE_TABLE
 	unsigned int   FtrUnified3DMediaCompressionFormats : 1; // DG2 has unified Render/media compression(versus TGLLP/XeHP_SDV 's multiple instances) and requires changes to RC format h/w encodings.
         unsigned int   FtrForceTile4                    : 1;  // Flag to force Tile4 usage as default in Tile64 supported platforms.
         unsigned int   FtrTile64Optimization            : 1;
+        unsigned int   FtrDiscrete                      : 1;  // Discrete-gfx
+        unsigned int   FtrXe2Compression                : 1;  // Xe2 Stateless Compression
+	unsigned int   FtrXe2PlusTiling                 : 1;  // Tile64 MSAA Layout
+        unsigned int   FtrL4Cache                       : 1;  // L4 cache support
+        unsigned int   FtrPml5Support                   : 1;  // xe2 page tables		
+		
     };
 
 
@@ -534,6 +541,36 @@ typedef struct _WA_TABLE
         WA_BUG_TYPE_UNKNOWN,
         WA_BUG_PERF_IMPACT_UNKNOWN, WA_COMPONENT_UNKNOWN)
 
+        WA_DECLARE(
+        Wa_14018443005,
+        "[Xe2] - Incorrect handling of compression when changing cached PA usage from compression OFF and another client does partial sector compression ON on W with UC",
+        WA_BUG_TYPE_UNKNOWN,
+        WA_BUG_PERF_IMPACT_UNKNOWN, WA_COMPONENT_GMM)
+
+        WA_DECLARE(
+        Wa_14018976079,
+        "[LNL] CPU-GPU False sharing broken for 1-way coherent pages",
+        WA_BUG_TYPE_UNKNOWN,
+        WA_BUG_PERF_IMPACT_UNKNOWN, WA_COMPONENT_GMM)
+
+        WA_DECLARE(
+        Wa_14018984349,
+        "[LNL] CPU-GPU False sharing broken for non-coherent pages",
+        WA_BUG_TYPE_UNKNOWN,
+        WA_BUG_PERF_IMPACT_UNKNOWN, WA_COMPONENT_GMM)
+		
+	WA_DECLARE(
+        Wa_14020040029,
+        "Misalignment on Depth buffer for Zplanes",
+        WA_BUG_TYPE_UNKNOWN,
+        WA_BUG_PERF_IMPACT_UNKNOWN, WA_COMPONENT_GMM)
+
+        WA_DECLARE(
+        Wa_EmuMufasaSupportOnBmg,
+        "WA for supporting failure seen in BMG with Mufasa",
+        WA_BUG_TYPE_FUNCTIONAL,
+        WA_BUG_PERF_IMPACT_UNKNOWN, WA_COMPONENT_UNKNOWN)	
+
 } WA_TABLE, *PWA_TABLE;
 
 //********************************** SKU/WA Macros *************************************
diff --git a/Source/inc/umKmInc/UmKmDmaPerfTimer.h b/Source/inc/umKmInc/UmKmDmaPerfTimer.h
index 069fc31..c11eeab 100644
--- a/Source/inc/umKmInc/UmKmDmaPerfTimer.h
+++ b/Source/inc/umKmInc/UmKmDmaPerfTimer.h
@@ -207,6 +207,9 @@ typedef enum _VPHAL_PERFTAG
     VPHAL_VEBOX_Y216,
     VPHAL_VEBOX_Y410,
     VPHAL_VEBOX_Y416,
+    VPHAL_VEBOX_AYUV,
+    VPHAL_VEBOX_RGB32,
+    VPHAL_VEBOX_RGB64,
 
     // PERFTAGs for AdvProc using Render
     VPHAL_ISTAB_PH1_PLY_PLY = 0x200,
```

