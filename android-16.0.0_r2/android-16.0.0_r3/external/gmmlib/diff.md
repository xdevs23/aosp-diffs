```diff
diff --git a/METADATA b/METADATA
index 3371cea..7510870 100644
--- a/METADATA
+++ b/METADATA
@@ -7,14 +7,14 @@ description: "The Intel(R) Graphics Memory Management Library provides device sp
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 10
-    day: 22
+    year: 2025
+    month: 3
+    day: 26
   }
   identifier {
     type: "Git"
     value: "https://github.com/intel/gmmlib"
-    version: "intel-gmmlib-22.5.2"
+    version: "intel-gmmlib-22.7.1"
     primary_source: true
   }
 }
diff --git a/README.rst b/README.rst
index ddad599..b538b94 100644
--- a/README.rst
+++ b/README.rst
@@ -92,6 +92,8 @@ Xe_LPG (MTL: Meteor Lake, ARL: Arrow Lake)
 
 Xe2_HPG (BMG: Battlemage, LNL: Lunar Lake)
 
+Xe3_LPG (Panther Lake)
+
 Release Tags
 ============
 
diff --git a/Source/GmmLib/CMakeLists.txt b/Source/GmmLib/CMakeLists.txt
index fcb4782..48d054c 100644
--- a/Source/GmmLib/CMakeLists.txt
+++ b/Source/GmmLib/CMakeLists.txt
@@ -25,14 +25,14 @@ project(igfx_gmmumd)
 
 # GmmLib Api Version used for so naming
 set(GMMLIB_API_MAJOR_VERSION 12)
-set(GMMLIB_API_MINOR_VERSION 5)
+set(GMMLIB_API_MINOR_VERSION 7)
 
 if(NOT DEFINED MAJOR_VERSION)
 	set(MAJOR_VERSION 12)
 endif()
 
 if(NOT DEFINED MINOR_VERSION)
-	set(MINOR_VERSION 5)
+	set(MINOR_VERSION 7)
 endif()
 
 if(NOT DEFINED PATCH_VERSION)
diff --git a/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.cpp
index 6552d22..f7f544e 100644
--- a/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.cpp
@@ -43,7 +43,8 @@ GMM_STATUS GmmLib::GmmXe2_LPGCachePolicy::InitCachePolicy()
 
     // Define index of cache element
     uint32_t Usage          = 0;
-    uint32_t ReservedPATIdx = 13; /* Rsvd PAT section 13-19 */
+    uint32_t ReservedPATIdx = 16; /* Rsvd PAT section 16-19 */
+    uint32_t ReservedPATIdxEnd = 20;
 
 #if (_WIN32 && (_DEBUG || _RELEASE_INTERNAL))
     void *pKmdGmmContext = NULL;
@@ -396,16 +397,13 @@ uint32_t GMM_STDCALL GmmLib::GmmXe2_LPGCachePolicy::CachePolicyGetPATIndex(GMM_R
         __GMM_ASSERT(false);
     }
 
-#if (defined __linux__ || defined(WDDM_LINUX))
-    IsCpuCacheable = false;
-#endif
     // requested compressed and coherent
     if (CompressionEnable && IsCpuCacheable)
     {
-        // return coherent uncompressed
-        ReturnPATIndex    = CoherentPATIndex;
-        CompressionEnable = false;
-        GMM_ASSERTDPF(false, "Coherent Compressed is not supported on Xe2. However, respecting the coherency and returning CoherentPATIndex");
+	// return coherent uncompressed
+	ReturnPATIndex    = CoherentPATIndex;
+	CompressionEnable = false;
+	GMM_ASSERTDPF(false, "Coherent Compressed is not supported on Xe2. However, respecting the coherency and returning CoherentPATIndex");
     }
     // requested compressed only
     else if (CompressionEnable)
diff --git a/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.h b/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.h
index 4b07a4a..b4244cf 100644
--- a/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.h
+++ b/Source/GmmLib/CachePolicy/GmmXe2_LPGCachePolicy.h
@@ -80,11 +80,11 @@ DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_CURSOR
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DISPLAY_STATIC_IMG_FOR_SMOOTH_ROTATION_BUFFER         ,  3,     0,     0,      0    ,  0			,  0     , 0,    NoP);
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_DUMMY_PAGE                                            ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GDI_SURFACE                                           ,  1,     0,     0,      0    ,  0			,  0     , 1,    NoP);
-DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GENERIC_KMD_RESOURCE                                  ,  1,		0,     0,      0    ,  0    		,  _WA_2W, 1,    NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GENERIC_KMD_RESOURCE                                  ,  _L3_P,	0,     0,      0    ,  0    		        ,  _WA_2W, 1,    NoP);
 // GMM_RESOURCE_USAGE_GFX_RING is only used if WaEnableRingHostMapping is enabled .
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GFX_RING                                              ,  0,     0,     0,      0    ,  0			,  0     , 1,	  NoP);
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_GTT_TRANSFER_REGION                                   ,  0,     0,     0,      0    ,  0			,  0     , 1,	  NoP);
-DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HW_CONTEXT                                            ,  1,		0,     0,	   0    ,  0			,  _WA_2W, 1,     NoP);
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_HW_CONTEXT                                            ,  _L3_P,	0,     0,      0    ,  0			,  _WA_2W, 1,     NoP);
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_STATE_MANAGER_KERNEL_STATE                            ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_KMD_STAGING_SURFACE                                   ,  1,     0,     0,      0    ,  0			,  0     , 1,    NoP);
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_MBM_BUFFER                                            ,  0,     0,     0,      0    ,  0			,  0     , 1,    NoP);
diff --git a/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp b/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp
index 2593a06..a1b3540 100644
--- a/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp
+++ b/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.cpp
@@ -386,7 +386,7 @@ void GmmLib::GmmXe_LPGCachePolicy::SetUpMOCSTable()
     }
     // Fixed MOCS Table
     //             Index      LookUp  Go      L3CC       L4CC   ignorePAT
-    GMM_DEFINE_MOCS( 0      , 1     , 0     , L3_WB    , L4_WB , 1)
+    GMM_DEFINE_MOCS( 0      , 1     , 0     , L3_WB    , L4_WB , 0)
     GMM_DEFINE_MOCS( 1      , 1     , 0     , L3_WB    , L4_WB , 1)
     GMM_DEFINE_MOCS( 2      , 1     , 0     , L3_UC    , L4_WB , 1)
     GMM_DEFINE_MOCS( 3      , 1     , 0     , L3_UC    , L4_UC , 1)
diff --git a/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.h b/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.h
index 8127826..7fc10d3 100644
--- a/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.h
+++ b/Source/GmmLib/CachePolicy/GmmXe_LPGCachePolicy.h
@@ -172,7 +172,7 @@ DEFINE_CACHE_ELEMENT(MHW_RESOURCE_USAGE_Sfc_IefLineBufferSurface,
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER                                            , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER_CONST                                      , 1 ,  0   ,       0,   1,         0,      0    , 1      ,  0     );
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER_CSR_UC                                     , 0 ,  0   ,       1,   1,         1,      0    , 0      ,  0     );
-DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER_CACHELINE_MISALIGNED                       , 0 ,  0   ,       1,   1,         1,      0    , 1      ,  0     ); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_BUFFER_CACHELINE_MISALIGNED                       , 0 ,  0   ,       0,   1,         1,      0    , 1      ,  0     ); 
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_IMAGE                                             , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_INLINE_CONST                                      , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_INLINE_CONST_HDC                                  , 1 ,  0   ,       0,   1,         0,      0    , 1      ,  0     );
@@ -181,7 +181,7 @@ DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_PRIVATE_MEM
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_PRINTF_BUFFER                                     , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_STATE_HEAP_BUFFER                                 , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_SYSTEM_MEMORY_BUFFER                              , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
-DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_SYSTEM_MEMORY_BUFFER_CACHELINE_MISALIGNED         , 0 ,  0   ,       1,   1,         1,      0    , 1      ,  0     ); 
+DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_SYSTEM_MEMORY_BUFFER_CACHELINE_MISALIGNED         , 0 ,  0   ,       0,   1,         1,      0    , 1      ,  0     ); 
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_ISH_HEAP_BUFFER                                   , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_TAG_MEMORY_BUFFER                                 , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
 DEFINE_CACHE_ELEMENT(GMM_RESOURCE_USAGE_OCL_TEXTURE_BUFFER                                    , 1 ,  0   ,       0,   1,         1,      0    , 1      ,  0     );
diff --git a/Source/GmmLib/GlobalInfo/GmmClientContext.cpp b/Source/GmmLib/GlobalInfo/GmmClientContext.cpp
index 8215295..e3f87d3 100644
--- a/Source/GmmLib/GlobalInfo/GmmClientContext.cpp
+++ b/Source/GmmLib/GlobalInfo/GmmClientContext.cpp
@@ -39,13 +39,22 @@ extern GMM_MA_LIB_CONTEXT *pGmmMALibContext;
 /////////////////////////////////////////////////////////////////////////////////////
 GmmLib::GmmClientContext::GmmClientContext(GMM_CLIENT ClientType, Context *pLibContext)
     : ClientType(),
-      pUmdAdapter(),
+      pClientContextAilFlags(),
       pGmmUmdContext(),
       DeviceCB(),
       IsDeviceCbReceived(0)
 {
     this->ClientType     = ClientType;
     this->pGmmLibContext = pLibContext;
+    
+    if (NULL != (pClientContextAilFlags = (GMM_AIL_STRUCT *)malloc(sizeof(GMM_AIL_STRUCT))))
+    {
+        memset(pClientContextAilFlags, 0, sizeof(GMM_AIL_STRUCT));
+    }
+    else
+    {
+        pClientContextAilFlags = NULL;
+    }
 }
 /////////////////////////////////////////////////////////////////////////////////////
 /// Destructor to free  GmmLib::GmmClientContext object memory
@@ -53,6 +62,11 @@ GmmLib::GmmClientContext::GmmClientContext(GMM_CLIENT ClientType, Context *pLibC
 GmmLib::GmmClientContext::~GmmClientContext()
 {
     pGmmLibContext = NULL;
+    if (pClientContextAilFlags)
+    {
+        free(pClientContextAilFlags);
+	pClientContextAilFlags = NULL;
+    }    
 }
 
 /////////////////////////////////////////////////////////////////////////////////////
@@ -128,6 +142,35 @@ uint8_t GMM_STDCALL GmmLib::GmmClientContext::GetSurfaceStateL1CachePolicy(GMM_R
     return pGmmLibContext->GetCachePolicyObj()->GetSurfaceStateL1CachePolicy(Usage);
 }
 
+////////////////////////////////////////////////////////////////////////////////////
+/// Member function to get the AIL flags associated with Client Context
+/// @param[in] None
+/// @return    GMM_AIL_STRUCT associated with the ClientContext
+
+const uint64_t* GMM_STDCALL GmmLib::GmmClientContext::GmmGetAIL()
+{
+    return (uint64_t*)(this->pClientContextAilFlags);
+}
+
+////////////////////////////////////////////////////////////////////////////////////
+/// Member function to Set the AIL flags associated with Client Context
+///
+/// @param[in] GMM_AIL_STRUCT: Pointer to AIL struct
+/// @return    void
+void GMM_STDCALL GmmLib::GmmClientContext::GmmSetAIL(GMM_AIL_STRUCT* pAilFlags)
+{
+    //Cache the AilXe2CompressionRequest value
+    bool IsClientAilXe2Compression = this->pClientContextAilFlags->AilDisableXe2CompressionRequest;
+
+    memcpy(this->pClientContextAilFlags, pAilFlags, sizeof(GMM_AIL_STRUCT));
+
+    // Update the Current ClientContext flags with whatever was cached earlier before copy
+    this->pClientContextAilFlags->AilDisableXe2CompressionRequest = IsClientAilXe2Compression;
+
+    return;
+}
+
+
 /////////////////////////////////////////////////////////////////////////////////////
 /// Member function of ClientContext class to return Swizzle Descriptor
 /// given Swizzle name , ResType and bpe
@@ -952,19 +995,34 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmClientContext::GmmSetDeviceInfo(GMM_DEVICE_INF
 /// @see        Class GmmLib::GmmClientContext
 ///
 /// @param[in]  ClientType : describles the UMD clients such as OCL, DX, OGL, Vulkan etc
-/// @param[in]  sBDF: Adapter's BDF info
+/// @param[in]  sBDF: Adapter's BDF info@param[in]  sBDF: Adapter's BDF info
+/// @param[in]  _pSkuTable: SkuTable Pointer
 ///
 /// @return     Pointer to GmmClientContext, if Context is created
 /////////////////////////////////////////////////////////////////////////////////////
-extern "C" GMM_CLIENT_CONTEXT *GMM_STDCALL GmmCreateClientContextForAdapter(GMM_CLIENT  ClientType,
-                                                                            ADAPTER_BDF sBdf)
+extern "C" GMM_CLIENT_CONTEXT *GMM_STDCALL GmmCreateClientContextForAdapter(GMM_CLIENT ClientType,
+                                                                            ADAPTER_BDF sBdf,
+                                                                            const void *_pSkuTable)
 {
     GMM_CLIENT_CONTEXT *pGmmClientContext = nullptr;
     GMM_LIB_CONTEXT *   pLibContext       = pGmmMALibContext->GetAdapterLibContext(sBdf);
+    SKU_FEATURE_TABLE *pSkuTable;
 
     if (pLibContext)
     {
         pGmmClientContext = new GMM_CLIENT_CONTEXT(ClientType, pLibContext);
+	
+	if (pGmmClientContext)
+	{
+	    pSkuTable = (SKU_FEATURE_TABLE *)_pSkuTable;
+            if (GFX_GET_CURRENT_RENDERCORE(pLibContext->GetPlatformInfo().Platform) >= IGFX_XE2_HPG_CORE && pLibContext->GetSkuTable().FtrXe2Compression && !pSkuTable->FtrXe2Compression)
+            {
+
+                GMM_AIL_STRUCT *pClientAilFlags = (GMM_AIL_STRUCT *)pGmmClientContext->GmmGetAIL();
+
+                pClientAilFlags->AilDisableXe2CompressionRequest = true;
+            }
+        }
 
     }
     return pGmmClientContext;
diff --git a/Source/GmmLib/GlobalInfo/GmmInfo.cpp b/Source/GmmLib/GlobalInfo/GmmInfo.cpp
index 8876890..4d553b5 100644
--- a/Source/GmmLib/GlobalInfo/GmmInfo.cpp
+++ b/Source/GmmLib/GlobalInfo/GmmInfo.cpp
@@ -1005,7 +1005,16 @@ GMM_CLIENT               ClientType)
     this->SkuTable  = *pSkuTable;
     this->WaTable   = *pWaTable;
     this->GtSysInfo = *pGtSysInfo;
-    
+   
+    if (GFX_GET_CURRENT_RENDERCORE(Platform) >= IGFX_XE2_HPG_CORE && (pSkuTable->FtrXe2Compression == false))
+    {
+        this->SkuTable.FtrXe2Compression = true;
+        if (!(this->GetSkuTable().FtrFlatPhysCCS) || !(this->GetSkuTable().FtrE2ECompression))
+        {
+            SkuTable.FtrXe2Compression = false;
+        }
+    }
+
     this->pPlatformInfo = CreatePlatformInfo(Platform, false);
     if(this->pPlatformInfo == NULL)
     {
@@ -1101,6 +1110,7 @@ GMM_CACHE_POLICY *GMM_STDCALL GmmLib::Context::CreateCachePolicyCommon()
         switch(GFX_GET_CURRENT_RENDERCORE(this->GetPlatformInfo().Platform))
         {
             case IGFX_XE2_HPG_CORE:
+            case IGFX_XE3_CORE:
                 pGmmCachePolicy = new GmmLib::GmmXe2_LPGCachePolicy(CachePolicy, this);
                 break;
             case IGFX_GEN12LP_CORE:
@@ -1181,6 +1191,7 @@ GMM_TEXTURE_CALC *GMM_STDCALL GmmLib::Context::CreateTextureCalc(PLATFORM Platfo
                  return new GmmGen12TextureCalc(this);
 				 break;
             case IGFX_XE2_HPG_CORE:
+	    case IGFX_XE3_CORE:
             default:
                 return new GmmXe_LPGTextureCalc(this);
                 break;
@@ -1216,6 +1227,7 @@ GMM_PLATFORM_INFO_CLASS *GMM_STDCALL GmmLib::Context::CreatePlatformInfo(PLATFOR
         case IGFX_XE_HPG_CORE:
         case IGFX_XE_HPC_CORE:
         case IGFX_XE2_HPG_CORE:
+	case IGFX_XE3_CORE:
             return new GmmLib::PlatformInfoGen12(Platform, (GMM_LIB_CONTEXT *)this);
             break;
         case IGFX_GEN11_CORE:
diff --git a/Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp b/Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp
index 11cb89a..ae78852 100755
--- a/Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp
+++ b/Source/GmmLib/GlobalInfo/GmmLibDllMain.cpp
@@ -59,8 +59,8 @@ extern "C" GMM_LIB_API GMM_STATUS GMM_STDCALL InitializeGmm(GMM_INIT_IN_ARGS *pI
 
         if(Status == GMM_SUCCESS)
         {
-            pOutArgs->pGmmClientContext = GmmCreateClientContextForAdapter(pInArgs->ClientType,
-			                                                          stAdapterBDF);
+            pOutArgs->pGmmClientContext = GmmCreateClientContextForAdapter(pInArgs->ClientType, 
+			                                      stAdapterBDF, pInArgs->pSkuTable);		
         }
 
 #endif
diff --git a/Source/GmmLib/Resource/GmmResourceInfoCommon.cpp b/Source/GmmLib/Resource/GmmResourceInfoCommon.cpp
index b1e428f..9428527 100644
--- a/Source/GmmLib/Resource/GmmResourceInfoCommon.cpp
+++ b/Source/GmmLib/Resource/GmmResourceInfoCommon.cpp
@@ -55,7 +55,7 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::Is64KBPageSuitable()
     if(GetGmmLibContext()->GetSkuTable().FtrLocalMemory)
      {
         Ignore64KBPadding |= (Surf.Flags.Info.Shared && !Surf.Flags.Info.NotLockable);
-        Ignore64KBPadding |= ((GetGmmLibContext()->GetSkuTable().FtrLocalMemoryAllows4KB) && Surf.Flags.Info.NoOptimizationPadding);
+	Ignore64KBPadding |= ((GetGmmLibContext()->GetSkuTable().FtrLocalMemoryAllows4KB) && (Surf.Flags.Info.NoOptimizationPadding && !GFX_IS_ALIGNED(Size, GMM_KBYTE(64))));	
         Ignore64KBPadding |= ((GetGmmLibContext()->GetSkuTable().FtrLocalMemoryAllows4KB || Surf.Flags.Info.NonLocalOnly) && (((Size * (100 + (GMM_GFX_SIZE_T)GetGmmLibContext()->GetAllowedPaddingFor64KbPagesPercentage())) / 100) < GFX_ALIGN(Size, GMM_KBYTE(64))));
     }
     else
@@ -500,7 +500,9 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmResourceInfoCommon::Create(Context &GmmLibCont
                 if(GetGmmLibContext()->GetSkuTable().FtrFlatPhysCCS && AuxSurf.Type == RESOURCE_INVALID)
                 {
                     //ie only AuxType is CCS, doesn't exist with FlatCCS, enable it for CC
-                    if (!GetGmmLibContext()->GetSkuTable().FtrXe2Compression || (GetGmmLibContext()->GetSkuTable().FtrXe2Compression && (Surf.MSAA.NumSamples > 1)))
+                    if (!GetGmmLibContext()->GetSkuTable().FtrXe2Compression || (GetGmmLibContext()->GetSkuTable().FtrXe2Compression &&
+			(!(((GMM_AIL_STRUCT *)(GetGmmClientContext()->GmmGetAIL()))->AilDisableXe2CompressionRequest)) &&
+                        (Surf.MSAA.NumSamples > 1)))
                     {
                         AuxSurf.Type = Surf.Type;
                     }
@@ -2362,7 +2364,7 @@ bool GMM_STDCALL GmmLib::GmmResourceInfoCommon::IsMipRCCAligned(uint8_t &MisAlig
     const uint8_t RCCCachelineWidth  = 32;
     const uint8_t RCCCachelineHeight = 4;
 
-    for(uint8_t lod = 0; lod <= GetMaxLod(); lod++)
+    for(uint8_t lod = 0; lod <= ((uint8_t)GetMaxLod()); lod++)
     {
         if(!(GFX_IS_ALIGNED(GetMipWidth(lod), RCCCachelineWidth) &&
              GFX_IS_ALIGNED(GetMipHeight(lod), RCCCachelineHeight)))
diff --git a/Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp b/Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp
index e22154d..3c2c829 100644
--- a/Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp
+++ b/Source/GmmLib/Resource/GmmResourceInfoCommonEx.cpp
@@ -45,7 +45,16 @@ bool GmmLib::GmmResourceInfoCommon::CopyClientParams(GMM_RESCREATE_PARAMS &Creat
         return false;
     }
     {
-        // Promote tiling options if caller does not provide any.
+        if ((GetGmmLibContext()->GetSkuTable().FtrXe2Compression) &&
+            (CreateParams.Type == RESOURCE_BUFFER) &&
+            (CreateParams.Flags.Info.Linear) &&
+            (CreateParams.Flags.Gpu.FlipChain))
+        {
+            CreateParams.Flags.Info.Linear = false;
+            CreateParams.Flags.Info.Tile4  = true;
+        }
+	
+	// Promote tiling options if caller does not provide any.
         // X/Y/W/L are tiling formats, and Yf/Ys are modifiers to the internal
         // ordering for Y and L macro-formats.
         if((CreateParams.Flags.Info.Linear +
@@ -59,7 +68,14 @@ bool GmmLib::GmmResourceInfoCommon::CopyClientParams(GMM_RESCREATE_PARAMS &Creat
                CreateParams.Flags.Info.ExistingSysMem)
             {
                 CreateParams.Flags.Info.Linear = true;
-            }
+
+                if ((GetGmmLibContext()->GetSkuTable().FtrXe2Compression) &&
+                    CreateParams.Flags.Gpu.FlipChain && (CreateParams.Type == RESOURCE_BUFFER))
+                {
+                    CreateParams.Flags.Info.Linear = false;
+                    CreateParams.Flags.Info.Tile4  = true;
+                }
+	    }
 
             if(GetGmmLibContext()->GetSkuTable().FtrTileY)
             {
@@ -164,6 +180,19 @@ bool GmmLib::GmmResourceInfoCommon::CopyClientParams(GMM_RESCREATE_PARAMS &Creat
 
                 // Displayable surfaces cannot be Tiled4/64.
                 __GMM_ASSERT(!GetGmmLibContext()->GetSkuTable().FtrDisplayYTiling);
+		
+		if (GFX_GET_CURRENT_RENDERCORE(GetGmmLibContext()->GetPlatformInfo().Platform) >= IGFX_XE3_CORE)
+                {
+                    if (CreateParams.Flags.Gpu.FlipChain || CreateParams.Flags.Gpu.Overlay ||
+                        CreateParams.Flags.Gpu.Presentable)
+                    {
+                        if (CreateParams.Flags.Info.TiledX == 1)
+                        {
+                            CreateParams.Flags.Info.TiledX = 0;
+                            CreateParams.Flags.Info.Tile4  = 1;
+                        }
+                    }
+                }
 
                 //override displayable surfaces to TileX
                 if(GetGmmLibContext()->GetSkuTable().FtrDisplayXTiling)
@@ -660,6 +689,18 @@ uint8_t GMM_STDCALL GmmLib::GmmResourceInfoCommon::ValidateParams()
         }
     }
 
+#ifndef __GMM_KMD__
+    if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression && (GetGmmClientContext() != NULL))
+    {
+        if (((GMM_AIL_STRUCT *)(GetGmmClientContext()->GmmGetAIL()))->AilDisableXe2CompressionRequest)
+        {
+            //Disable Compression at resource level only, However at adapter level FtrXe2Compression could be still enabled.
+            //AilDisableXe2CompressionRequest helps us to acheive this.
+            Surf.Flags.Info.NotCompressed = 1;
+        }
+    }
+#endif
+
     if((GFX_GET_CURRENT_RENDERCORE(pPlatformResource->Platform) < IGFX_GEN8_CORE) &&
        Surf.Flags.Info.TiledW)
     {
diff --git a/Source/GmmLib/Texture/GmmGen12Texture.cpp b/Source/GmmLib/Texture/GmmGen12Texture.cpp
index 20bdd2b..4bf1e3c 100644
--- a/Source/GmmLib/Texture/GmmGen12Texture.cpp
+++ b/Source/GmmLib/Texture/GmmGen12Texture.cpp
@@ -316,6 +316,11 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmGen12TextureCalc::FillTex2D(GMM_TEXTURE_INFO *
     Height = pTexInfo->BaseHeight;
     Width  = GFX_ULONG_CAST(pTexInfo->BaseWidth);
 
+    if((pTexInfo->Format == GMM_FORMAT_R8G8B8_UINT) && (pTexInfo->Flags.Info.Linear || pTexInfo->Flags.Info.TiledX))
+    {
+        Width += GFX_CEIL_DIV(Width, 63);
+    }
+
     pTexInfo->MSAA.NumSamples = GFX_MAX(pTexInfo->MSAA.NumSamples, 1);
 
     if(pTexInfo->Flags.Info.TiledYf || GMM_IS_64KB_TILE(pTexInfo->Flags))
diff --git a/Source/GmmLib/Texture/GmmGen9Texture.cpp b/Source/GmmLib/Texture/GmmGen9Texture.cpp
index f3b6012..f342163 100644
--- a/Source/GmmLib/Texture/GmmGen9Texture.cpp
+++ b/Source/GmmLib/Texture/GmmGen9Texture.cpp
@@ -153,8 +153,12 @@ GMM_STATUS GMM_STDCALL GmmLib::GmmGen9TextureCalc::FillTex1D(GMM_TEXTURE_INFO *
     /////////////////////////////
     // Calculate Surface QPitch
     /////////////////////////////
-
-    Width    = __GMM_EXPAND_WIDTH(this, GFX_ULONG_CAST(pTexInfo->BaseWidth), HAlign, pTexInfo);
+    Width = GFX_ULONG_CAST(pTexInfo->BaseWidth);
+    if((pTexInfo->Format == GMM_FORMAT_R8G8B8_UINT) && (pTexInfo->Flags.Info.Linear || pTexInfo->Flags.Info.TiledX))
+    {
+        Width += GFX_CEIL_DIV(Width, 63);
+    }
+    Width    = __GMM_EXPAND_WIDTH(this, Width, HAlign, pTexInfo);
     MipWidth = Width;
 
     if((pTexInfo->Flags.Info.TiledYf || GMM_IS_64KB_TILE(pTexInfo->Flags)) &&
diff --git a/Source/GmmLib/Texture/GmmTextureAlloc.cpp b/Source/GmmLib/Texture/GmmTextureAlloc.cpp
index b471cf8..e4437ac 100644
--- a/Source/GmmLib/Texture/GmmTextureAlloc.cpp
+++ b/Source/GmmLib/Texture/GmmTextureAlloc.cpp
@@ -1329,7 +1329,6 @@ GMM_STATUS GmmLib::GmmTextureCalc::FillTexBlockMem(GMM_TEXTURE_INFO * pTexInfo,
     __GMM_ASSERTPTR(pRestrictions, GMM_ERROR);
     __GMM_ASSERT(pTexInfo->BitsPerPixel == GMM_BITS(8) || (pTexInfo->Flags.Info.AllowVirtualPadding));
     __GMM_ASSERT(pTexInfo->BaseHeight == 1);
-    __GMM_ASSERT(pTexInfo->Flags.Info.Linear == 1);
     __GMM_ASSERT(pTexInfo->Flags.Info.TiledW == 0);
     __GMM_ASSERT(pTexInfo->Flags.Info.TiledX == 0);
     __GMM_ASSERT(pTexInfo->Flags.Info.TiledY == 0);
diff --git a/Source/GmmLib/Texture/GmmTextureOffset.cpp b/Source/GmmLib/Texture/GmmTextureOffset.cpp
index 95d4aaf..cd5ccc2 100644
--- a/Source/GmmLib/Texture/GmmTextureOffset.cpp
+++ b/Source/GmmLib/Texture/GmmTextureOffset.cpp
@@ -848,7 +848,7 @@ void GmmLib::GmmTextureCalc::SetPlanarOffsetInfo(GMM_TEXTURE_INFO *pTexInfo, GMM
     {
         pTexInfo->OffsetInfo.Plane.IsTileAlignedPlanes = true;
     }
-    for(uint8_t i = 1; i <= CreateParams.NoOfPlanes; i++)
+    for(uint32_t i = 1; i <= CreateParams.NoOfPlanes; i++)
     {
         pTexInfo->OffsetInfo.Plane.X[i] = CreateParams.PlaneOffset.X[i];
         pTexInfo->OffsetInfo.Plane.Y[i] = CreateParams.PlaneOffset.Y[i];
@@ -866,7 +866,7 @@ void GmmLib::GmmTextureCalc::SetPlanarOffsetInfo_2(GMM_TEXTURE_INFO *pTexInfo, G
     {
         pTexInfo->OffsetInfo.Plane.IsTileAlignedPlanes = true;
     }
-    for(uint8_t i = 1; i <= CreateParams.NoOfPlanes; i++)
+    for(uint32_t i = 1; i <= CreateParams.NoOfPlanes; i++)
     {
         pTexInfo->OffsetInfo.Plane.X[i] = CreateParams.PlaneOffset.X[i];
         pTexInfo->OffsetInfo.Plane.Y[i] = CreateParams.PlaneOffset.Y[i];
diff --git a/Source/GmmLib/Texture/GmmXe_LPGTexture.cpp b/Source/GmmLib/Texture/GmmXe_LPGTexture.cpp
index 4a83600..c65f0dc 100644
--- a/Source/GmmLib/Texture/GmmXe_LPGTexture.cpp
+++ b/Source/GmmLib/Texture/GmmXe_LPGTexture.cpp
@@ -1204,7 +1204,7 @@ void GmmLib::GmmXe_LPGTextureCalc::SetPlanarOffsetInfo(GMM_TEXTURE_INFO *pTexInf
     {
         pTexInfo->OffsetInfo.PlaneXe_LPG.IsTileAlignedPlanes = true;
     }
-    for(uint8_t i = 1; i <= CreateParams.NoOfPlanes; i++)
+    for(uint32_t i = 1; i <= CreateParams.NoOfPlanes; i++)
     {
         pTexInfo->OffsetInfo.PlaneXe_LPG.X[i] = CreateParams.PlaneOffset.X[i];
         pTexInfo->OffsetInfo.PlaneXe_LPG.Y[i] = CreateParams.PlaneOffset.Y[i];
@@ -1222,7 +1222,7 @@ void GmmLib::GmmXe_LPGTextureCalc::SetPlanarOffsetInfo_2(GMM_TEXTURE_INFO *pTexI
     {
         pTexInfo->OffsetInfo.PlaneXe_LPG.IsTileAlignedPlanes = true;
     }
-    for(uint8_t i = 1; i <= CreateParams.NoOfPlanes; i++)
+    for(uint32_t i = 1; i <= CreateParams.NoOfPlanes; i++)
     {
         pTexInfo->OffsetInfo.PlaneXe_LPG.X[i] = CreateParams.PlaneOffset.X[i];
         pTexInfo->OffsetInfo.PlaneXe_LPG.Y[i] = CreateParams.PlaneOffset.Y[i];
diff --git a/Source/GmmLib/inc/External/Common/GmmCachePolicyExt.h b/Source/GmmLib/inc/External/Common/GmmCachePolicyExt.h
index b20ff54..037b4e7 100644
--- a/Source/GmmLib/inc/External/Common/GmmCachePolicyExt.h
+++ b/Source/GmmLib/inc/External/Common/GmmCachePolicyExt.h
@@ -129,7 +129,7 @@ typedef union MEMORY_OBJECT_CONTROL_STATE_REC {
         uint32_t EncryptedData  : 1;
         uint32_t Index          : 6;
         uint32_t                : 25;
-    } Gen9, Gen10, Gen11, Gen12, XE_HP, XE_LPG;
+    } Gen9, Gen10, Gen11, Gen12, XE_HP, XE_LPG, XE2;
 
     uint32_t DwordValue;
 } MEMORY_OBJECT_CONTROL_STATE;
diff --git a/Source/GmmLib/inc/External/Common/GmmClientContext.h b/Source/GmmLib/inc/External/Common/GmmClientContext.h
index a00f7c4..9907b7d 100644
--- a/Source/GmmLib/inc/External/Common/GmmClientContext.h
+++ b/Source/GmmLib/inc/External/Common/GmmClientContext.h
@@ -81,8 +81,12 @@ namespace GmmLib
     protected:
         GMM_CLIENT                       ClientType;
         ///< Placeholders for storing UMD context. Actual UMD context that needs to be stored here is 
-        void                             *pUmdAdapter;
-        GMM_UMD_CONTEXT                  *pGmmUmdContext;
+        union
+        {
+            void *pUmdAdapter;
+            GMM_AIL_STRUCT *pClientContextAilFlags; //To store the UMD AIL flags. This is applicable for each client. Used to populate the corresponding LibContextAilFlags
+        };
+	GMM_UMD_CONTEXT                  *pGmmUmdContext;
         GMM_DEVICE_CALLBACKS_INT          DeviceCB;       //OS-specific defn: Will be used by Clients to send as input arguments.
         // Flag to indicate Device_callbacks received.
         uint8_t             IsDeviceCbReceived;
@@ -177,6 +181,9 @@ namespace GmmLib
 #endif
 	GMM_VIRTUAL uint32_t GMM_STDCALL CachePolicyGetPATIndex(GMM_RESOURCE_INFO *pResInfo, GMM_RESOURCE_USAGE_TYPE Usage, bool *pCompressionEnable, bool IsCpuCacheable);
         GMM_VIRTUAL const SWIZZLE_DESCRIPTOR *GMM_STDCALL GetSwizzleDesc(EXTERNAL_SWIZZLE_NAME ExternalSwizzleName, EXTERNAL_RES_TYPE ResType, uint8_t bpe, bool isStdSwizzle = false);
+	
+	GMM_VIRTUAL void GMM_STDCALL            GmmSetAIL(GMM_AIL_STRUCT *pAilFlags);
+	GMM_VIRTUAL const uint64_t *GMM_STDCALL GmmGetAIL();
     };
 }
 
@@ -188,14 +195,13 @@ typedef struct GmmClientContext GMM_CLIENT_CONTEXT;
 
 #endif
 
-
-
 #ifdef __cplusplus
 extern "C" {
 #endif
 
     /* ClientContext will be unique to each client */
-    GMM_CLIENT_CONTEXT* GMM_STDCALL GmmCreateClientContextForAdapter(GMM_CLIENT ClientType, ADAPTER_BDF sBdf);
+    GMM_CLIENT_CONTEXT *GMM_STDCALL GmmCreateClientContextForAdapter(GMM_CLIENT ClientType, 
+		                               ADAPTER_BDF sBdf, const void *_pSkuTable);
     void GMM_STDCALL GmmDeleteClientContext(GMM_CLIENT_CONTEXT *pGmmClientContext);
 
 #if GMM_LIB_DLL
diff --git a/Source/GmmLib/inc/External/Common/GmmCommonExt.h b/Source/GmmLib/inc/External/Common/GmmCommonExt.h
index a59a43c..1a8d7ad 100644
--- a/Source/GmmLib/inc/External/Common/GmmCommonExt.h
+++ b/Source/GmmLib/inc/External/Common/GmmCommonExt.h
@@ -681,3 +681,17 @@ typedef enum GMM_RESOURCE_TYPE_ENUM
     GMM_MAX_HW_RESOURCE_TYPE
 } GMM_RESOURCE_TYPE;
 
+typedef struct
+{
+    union
+    {
+        struct
+        {
+            uint64_t AilDisableXe2CompressionRequest: 1;
+	    uint64_t reserved: 63;
+
+        };
+
+        uint64_t Value;
+    };
+} GMM_AIL_STRUCT;
diff --git a/Source/GmmLib/inc/External/Common/GmmFormatTable.h b/Source/GmmLib/inc/External/Common/GmmFormatTable.h
index f56884e..f25da09 100644
--- a/Source/GmmLib/inc/External/Common/GmmFormatTable.h
+++ b/Source/GmmLib/inc/External/Common/GmmFormatTable.h
@@ -443,7 +443,7 @@ GMM_FORMAT( P010                         ,  16,  1,  1, 1, R, x,   NA , FC(4,  x
 GMM_FORMAT( P012                         ,  16,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
 GMM_FORMAT( P016                         ,  16,  1,  1, 1, R, x,   NA , FC(4,  x,    P016,   ,_L ),     ALWAYS      )
 GMM_FORMAT( P208                         ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
-GMM_FORMAT( R10G10B10_XR_BIAS_A2_UNORM   ,  32,  1,  1, 1, x, x,   NA , FC(4,  x, RGB10A2,   ,   ),     ALWAYS      ) // DXGI_FORMAT_R10G10B10_XR_BIAS_A2_UNORM
+GMM_FORMAT( R10G10B10_XR_BIAS_A2_UNORM   ,  32,  1,  1, 1, R, x,   NA , FC(4,  x, RGB10A2,   ,   ),     ALWAYS      ) // DXGI_FORMAT_R10G10B10_XR_BIAS_A2_UNORM
 GMM_FORMAT( R24G8_TYPELESS               ,  32,  1,  1, 1, x, x,   NA , FC(4, 32,       R, 32,  U),     ALWAYS      ) // DXGI_FORMAT_R24G8_TYPELESS (To differentiate between GENERIC_32BIT.)
 GMM_FORMAT( R32G8X24_TYPELESS            ,  64,  1,  1, 1, x, x,   NA , FC(4, 32,       R, 32,  U),     ALWAYS      ) // DXGI_FORMAT_R32G8X24_TYPELESS (To differentiate between GENERIC_64BIT.)
 GMM_FORMAT( RENDER_8BIT                  ,   8,  1,  1, 1, R, x,   NA , NC                        ,     ALWAYS      )
diff --git a/Source/GmmLib/inc/External/Common/GmmResourceInfoCommon.h b/Source/GmmLib/inc/External/Common/GmmResourceInfoCommon.h
index bfc5af9..abbde33 100644
--- a/Source/GmmLib/inc/External/Common/GmmResourceInfoCommon.h
+++ b/Source/GmmLib/inc/External/Common/GmmResourceInfoCommon.h
@@ -715,7 +715,7 @@ namespace GmmLib
             /////////////////////////////////////////////////////////////////////////////////////
             GMM_INLINE_VIRTUAL GMM_INLINE_EXPORTED void GMM_STDCALL SetMmcMode(GMM_RESOURCE_MMC_INFO Mode, uint32_t ArrayIndex)
             {
-                __GMM_ASSERT((Mode == GMM_MMC_DISABLED) || (Mode == GMM_MMC_HORIZONTAL) || (Mode == GMM_MMC_VERTICAL));
+                __GMM_ASSERT((Mode == GMM_MMC_DISABLED) || (Mode == GMM_MMC_HORIZONTAL) || (Mode == GMM_MMC_VERTICAL) || (Mode == GMM_MMC_MC) || (Mode == GMM_MMC_RC));
                 
                 __GMM_ASSERT(ArrayIndex < GMM_MAX_MMC_INDEX);
 
@@ -1160,8 +1160,13 @@ namespace GmmLib
                     else if ((GmmAuxType == GMM_AUX_CC) && (Surf.Flags.Gpu.IndirectClearColor || Surf.Flags.Gpu.ColorDiscard))
                     {
                         Offset = Surf.Size + AuxSurf.UnpaddedSize;
-	                if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
-	                {
+			
+			if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression
+#ifndef __GMM_KMD__
+                        && !(((GMM_AIL_STRUCT *)(GetGmmClientContext()->GmmGetAIL()))->AilDisableXe2CompressionRequest)
+#endif
+			)
+			{
 	                    if (Surf.MSAA.NumSamples > 1)
 	                    {
 	                        Offset = Surf.Size; // Beginning of MCS which is first 4K of AuxSurf, Clear colour is stored only for MSAA surfaces
@@ -1248,9 +1253,12 @@ namespace GmmLib
                     }
                     else
                     {
-                    
-                        if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression)
-                        {
+			if (GetGmmLibContext()->GetSkuTable().FtrXe2Compression
+#ifndef __GMM_KMD__
+                            && !(((GMM_AIL_STRUCT *)(GetGmmClientContext()->GmmGetAIL()))->AilDisableXe2CompressionRequest)
+#endif
+			    )
+			    {
                             if (Surf.MSAA.NumSamples > 1)
                             {
                                 return (AuxSurf.UnpaddedSize); // CC is part of MCS
diff --git a/Source/GmmLib/inc/External/Common/GmmResourceInfoExt.h b/Source/GmmLib/inc/External/Common/GmmResourceInfoExt.h
index 5dd38ec..faf325c 100644
--- a/Source/GmmLib/inc/External/Common/GmmResourceInfoExt.h
+++ b/Source/GmmLib/inc/External/Common/GmmResourceInfoExt.h
@@ -59,6 +59,8 @@ typedef enum GMM_RESOURCE_MMC_INFO_REC
     GMM_MMC_DISABLED = 0,
     GMM_MMC_HORIZONTAL,
     GMM_MMC_VERTICAL,
+    GMM_MMC_MC,
+    GMM_MMC_RC    
 }GMM_RESOURCE_MMC_INFO;
 
 //===========================================================================
diff --git a/Source/inc/common/igfxfmid.h b/Source/inc/common/igfxfmid.h
index a9176de..d28b399 100644
--- a/Source/inc/common/igfxfmid.h
+++ b/Source/inc/common/igfxfmid.h
@@ -79,6 +79,7 @@ typedef enum {
     IGFX_ARROWLAKE = 1273,
     IGFX_BMG = 1274,
     IGFX_LUNARLAKE = 1275,
+    IGFX_PTL = 1300,
     
     IGFX_MAX_PRODUCT,
     IGFX_GENNEXT               = 0x7ffffffe,
@@ -141,6 +142,7 @@ typedef enum {
     IGFX_XE_HPC_CORE     = 0x0c08,  // XE_HPC Family
     IGFX_XE2_LPG_CORE    = 0x0c09,  // XE2_LPG Family
     IGFX_XE2_HPG_CORE    = IGFX_XE2_LPG_CORE,  //XE2_HPG Family
+    IGFX_XE3_CORE        = 0x1e00,  // XE3 Family
 
     //Please add new GENs BEFORE THIS !
     IGFX_MAX_CORE,
@@ -399,7 +401,7 @@ typedef enum __NATIVEGTTYPE
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN12_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||  \
-					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||  \
+					 ( GFX_GET_CURRENT_RENDERCORE(p) >= IGFX_XE_HPC_CORE )  ||  \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_8_OR_LATER(p)       ( ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN8_CORE )    ||  \
@@ -409,7 +411,7 @@ typedef enum __NATIVEGTTYPE
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN12_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||  \
-					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||  \
+					 ( GFX_GET_CURRENT_RENDERCORE(p) >= IGFX_XE_HPC_CORE )  ||  \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_8_CHV_OR_LATER(p)   ( ( GFX_GET_CURRENT_PRODUCT(p) == IGFX_CHERRYVIEW )      ||  \
@@ -419,7 +421,7 @@ typedef enum __NATIVEGTTYPE
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN12_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||  \
-					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||  \
+					 ( GFX_GET_CURRENT_RENDERCORE(p) >= IGFX_XE_HPC_CORE )  ||  \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_9_OR_LATER(p)       ( ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN9_CORE )    ||  \
@@ -428,7 +430,7 @@ typedef enum __NATIVEGTTYPE
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN12_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||  \
-					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||  \
+					 ( GFX_GET_CURRENT_RENDERCORE(p) >= IGFX_XE_HPC_CORE )  ||  \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_10_OR_LATER(p)       (( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN10_CORE )   ||  \
@@ -436,15 +438,16 @@ typedef enum __NATIVEGTTYPE
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN12_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||  \
-					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||  \
+					 ( GFX_GET_CURRENT_RENDERCORE(p) >= IGFX_XE_HPC_CORE )  ||  \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
 
 #define GFX_IS_GEN_11_OR_LATER(p)       (( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN11_CORE )   ||  \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GEN12_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HP_CORE )   ||  \
 					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPG_CORE )  ||  \
-					 ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_XE_HPC_CORE )  ||  \
+					 ( GFX_GET_CURRENT_RENDERCORE(p) >= IGFX_XE_HPC_CORE )  ||  \
                                          ( GFX_GET_CURRENT_RENDERCORE(p) == IGFX_GENNEXT_CORE ) )
+
 #define GFX_IS_GEN_12_OR_LATER(p)       (( GFX_GET_CURRENT_RENDERCORE(p) >= IGFX_GEN12_CORE ))
 #define GFX_IS_ATOM_PRODUCT_FAMILY(p)  ( GFX_IS_PRODUCT(p, IGFX_VALLEYVIEW)   ||  \
                                          GFX_IS_PRODUCT(p, IGFX_CHERRYVIEW)   ||  \
@@ -1936,6 +1939,7 @@ typedef enum __NATIVEGTTYPE
 #define DEV_ID_56A4                             0x56A4
 #define DEV_ID_56A5                             0x56A5
 #define DEV_ID_56A6                             0x56A6
+#define DEV_ID_56AF                             0x56AF
 #define DEV_ID_56B0                             0x56B0
 #define DEV_ID_56B1                             0x56B1
 #define DEV_ID_56B2                             0x56B2
@@ -1998,6 +2002,16 @@ typedef enum __NATIVEGTTYPE
 #define DEV_ID_E20D                             0xE20D
 #define DEV_ID_E212                             0xE212
 
+// PTL
+#define DEV_ID_B080                             0xB080
+#define DEV_ID_B081                             0xB081
+#define DEV_ID_B082                             0xB082
+#define DEV_ID_B083                             0xB083
+#define DEV_ID_B08F                             0xB08F
+#define DEV_ID_B090                             0xB090
+#define DEV_ID_B0A0                             0xB0A0
+#define DEV_ID_B0B0                             0xB0B0
+
 #define MGM_HAS     0
 
 //#define SDG_HAS      1              //Reserve place for Springdale-G HAS
@@ -2033,7 +2047,8 @@ typedef enum __NATIVEGTTYPE
                                       ( d == DEV_ID_4F81 )                              ||   \
                                       ( d == DEV_ID_4F82 )                              ||   \
                                       ( d == DEV_ID_4F83 )                              ||   \
-                                      ( d == DEV_ID_4F84 ))
+                                      ( d == DEV_ID_4F84 )                              ||   \
+                                      ( d == DEV_ID_56AF ))
 
 #define GFX_IS_DG2_G12_CONFIG(d)   ( ( d == DEV_ID_4F85 )                              ||   \
                                       ( d == DEV_ID_4F86 )                              ||   \
diff --git a/Source/inc/common/sku_wa.h b/Source/inc/common/sku_wa.h
index 9b7c117..69a72a2 100644
--- a/Source/inc/common/sku_wa.h
+++ b/Source/inc/common/sku_wa.h
@@ -194,7 +194,6 @@ enum WA_COMPONENT
 typedef struct _WA_TABLE
 {
         // struct wa_3d
-        unsigned int : 0;
 
         WA_DECLARE(
         WaAlignIndexBuffer,
@@ -203,7 +202,7 @@ typedef struct _WA_TABLE
         WA_BUG_PERF_IMPACT_UNKNOWN, WA_COMPONENT_UNKNOWN)
 
         // struct _wa_Gmm
-        unsigned int : 0;
+        unsigned int Reserved0: 31; // Handle 4bytes alignment boundary to maintain ABI
 
         WA_DECLARE(
         WaValign2ForR8G8B8UINTFormat,
diff --git a/Source/inc/umKmInc/UmKmDmaPerfTimer.h b/Source/inc/umKmInc/UmKmDmaPerfTimer.h
index c11eeab..d40efcc 100644
--- a/Source/inc/umKmInc/UmKmDmaPerfTimer.h
+++ b/Source/inc/umKmInc/UmKmDmaPerfTimer.h
@@ -339,6 +339,48 @@ typedef enum _VPHAL_PERFTAG
     VPHAL_SR_SUBPIXEL_CONV_2X2,
     VPHAL_SR_CONV_5X5_Y8,
 
+    //Media Copy
+    VPHAL_MCP_VEBOX_COPY,
+    VPHAL_MCP_RENDER_COPY,
+    VPHAL_MCP_BLT_COPY,
+
+    //OCL FC
+    VPHAL_OCL_FC_0LAYER,
+    VPHAL_OCL_FC_1LAYER,
+    VPHAL_OCL_FC_2LAYER,
+    VPHAL_OCL_FC_3LAYER,
+    VPHAL_OCL_FC_4LAYER,
+    VPHAL_OCL_FC_5LAYER,
+    VPHAL_OCL_FC_6LAYER,
+    VPHAL_OCL_FC_7LAYER,
+    VPHAL_OCL_FC_8LAYER,
+
+    //OCL FC w/ Primary Layer
+    VPHAL_OCL_FC_PRI_1LAYER,
+    VPHAL_OCL_FC_PRI_2LAYER,
+    VPHAL_OCL_FC_PRI_3LAYER,
+    VPHAL_OCL_FC_PRI_4LAYER,
+    VPHAL_OCL_FC_PRI_5LAYER,
+    VPHAL_OCL_FC_PRI_6LAYER,
+    VPHAL_OCL_FC_PRI_7LAYER,
+    VPHAL_OCL_FC_PRI_8LAYER,
+
+    //OCL FC w/ Rotation
+    VPHAL_OCL_FC_ROT_1LAYER,
+    VPHAL_OCL_FC_ROT_2LAYER,
+    VPHAL_OCL_FC_ROT_3LAYER,
+    VPHAL_OCL_FC_ROT_4LAYER,
+    VPHAL_OCL_FC_ROT_5LAYER,
+    VPHAL_OCL_FC_ROT_6LAYER,
+    VPHAL_OCL_FC_ROT_7LAYER,
+    VPHAL_OCL_FC_ROT_8LAYER,
+
+    //OCL FC FastExpress
+    VPHAL_OCL_FC_FP,
+    VPHAL_OCL_FC_FP_ROT,
+
+    //OCL 3DLut
+    VPHAL_OCL_3DLUT,    
     // ADD TAGS FOR NEW ADVPROC KRNS HERE
 
     VPHAL_PERFTAG_MAX
```

