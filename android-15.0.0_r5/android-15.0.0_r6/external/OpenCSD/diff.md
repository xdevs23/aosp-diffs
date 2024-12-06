```diff
diff --git a/.gitignore b/.gitignore
index 4385ae2..e79271d 100644
--- a/.gitignore
+++ b/.gitignore
@@ -54,22 +54,9 @@ ipch/
 # ignore bin test directory
 bin/
 *.log
-ref_trace_decoder/build/win/rctdl_c_api_lib/Release/*
-ref_trace_decoder/build/win/rctdl_c_api_lib/x64/Release/*
-ref_trace_decoder/build/win/ref_trace_decode_lib/Release/*
-ref_trace_decoder/build/win/ref_trace_decode_lib/x64/Release/*
-ref_trace_decoder/tests/build/win/simple_pkt_print_c_api/Release/*
-ref_trace_decoder/tests/build/win/simple_pkt_print_c_api/x64/Release/*
 *.lastbuildstate
 *.manifest
 *.cache
-ref_trace_decoder/docs/html/*
-ref_trace_decoder/tests/build/win/simple_pkt_print_c_api/Debug-dll/*
-ref_trace_decoder/tests/build/win/simple_pkt_print_c_api/x64/Debug-dll/*
-ref_trace_decoder/tests/build/win/trc_pkt_lister/Debug-dll/*
-ref_trace_decoder/tests/build/win/trc_pkt_lister/Release-dll/*
-ref_trace_decoder/tests/build/win/trc_pkt_lister/x64/Debug-dll/*
-ref_trace_decoder/tests/build/win/trc_pkt_lister/x64/Release-dll/*
 *.bak
 *.orig
 decoder/docs/html/*
@@ -79,4 +66,6 @@ decoder/docs/html/*
 *.iobj
 *.ipdb
 decoder/tests/results*
-*.recipe
\ No newline at end of file
+*.recipe
+decoder/tests/ds-snapshots
+*.FileListAbsolute.txt
diff --git a/METADATA b/METADATA
index 9cc5b67..ca077cc 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2024
-    month: 5
-    day: 15
+    month: 7
+    day: 24
   }
   homepage: "https://github.com/Linaro/OpenCSD"
   identifier {
     type: "Git"
     value: "https://github.com/Linaro/OpenCSD.git"
-    version: "v1.5.2"
+    version: "v1.5.3"
   }
 }
diff --git a/README.md b/README.md
index 352e865..35b26dc 100644
--- a/README.md
+++ b/README.md
@@ -27,7 +27,7 @@ Releases will appear on the master branch in the git repository with an appropri
 CoreSight Trace Component Support.
 ----------------------------------
 
-_Current Version 1.5.2_
+_Current Version 1.5.3_
 
 ### Current support:
 
@@ -326,6 +326,14 @@ Version and Modification Information
     - __Bugfix__: build: fix warnings building library.
     - __Bugfix__: tests: Fix typo in trc_pkt_lister help output.
 
+- _Version 1.5.3_:
+    - __Update__: tests: Add timing information to trc_pkt_lister program.
+    - __Update__: memacc: Add external interface to set memacc cache parameters. Update test programs.
+    - __Bugfix__: etm4x: fix packet print typo.
+    - __Bugfix__: docs: Minor fixes to docs and man file.
+    - __Bugfix__: build: minor fix for clang compatibility.
+
+
 Licence Information
 ===================
 
diff --git a/decoder/build/win-vs2022/rctdl_c_api_lib/x64/Debug-dll/libopencsd_c_api.dll.recipe b/decoder/build/win-vs2022/rctdl_c_api_lib/x64/Debug-dll/libopencsd_c_api.dll.recipe
deleted file mode 100644
index 93a8437..0000000
--- a/decoder/build/win-vs2022/rctdl_c_api_lib/x64/Debug-dll/libopencsd_c_api.dll.recipe
+++ /dev/null
@@ -1,11 +0,0 @@
-﻿<?xml version="1.0" encoding="utf-8"?>
-<Project>
-  <ProjectOutputs>
-    <ProjectOutput>
-      <FullPath>C:\work\OpenCSD\ocsd-linaro\decoder\lib\win64\dbg\libopencsd_c_api.dll</FullPath>
-    </ProjectOutput>
-  </ProjectOutputs>
-  <ContentFiles />
-  <SatelliteDlls />
-  <NonRecipeFileRefs />
-</Project>
\ No newline at end of file
diff --git a/decoder/docs/build_libs.md b/decoder/docs/build_libs.md
index 550d1cc..a289516 100644
--- a/decoder/docs/build_libs.md
+++ b/decoder/docs/build_libs.md
@@ -118,7 +118,7 @@ e.g. `./lib/win64/rel` will contain the windows 64 bit release libraries.
 The solution contains four configurations:-
 - *Debug* : builds debug versions of static C++ main library and C-API libraries, test programs linked to the static library.
 - *Debug-dll* : builds debug versions of static main library and C-API DLL. C-API statically linked to the main library. 
-C-API test built as `simple_pkt_print_c_api-dl.exe` and linked against the DLL version of the C-API library.
+C-API test built as `c_api_pkt_print_test_dll.exe` and linked against the DLL version of the C-API library.
 - *Release* : builds release static library versions, test programs linked to static libraries.
 - *Release-dll* : builds release C-API DLL, static main library.
 
@@ -126,9 +126,10 @@ _Note_: Currently there is no Windows DLL version of the main C++ library. This
 the project is nearer completion with further decode protocols, and the classes requiring export are established..
 
 Libraries built are:-
-- `libcstraced.lib` : static main C++ decoder library.
-- `cstraced_c_api.dll` : C-API DLL library. Statically linked against `libcstraced.lib` at .DLL build time.
-- `libcstraced_c_api.lib` : C-API static library. 
+- `libopencsd.lib` : static main C++ decoder library.
+- `libopencsd_c_api.lib` : C-API static library. 
+- `libopencsd_c_api.dll` : C-API DLL library. Statically linked against `libcstraced.lib` at .DLL build time. Built using the release-dll or debug-dll solution configurations.
+
 
 There is also a project file to build an auxiliary library used `trc_pkt_lister` for test purposes only.
 This is the `snapshot_parser_lib.lib` library, delivered to the `./tests/lib/win<bitsize>/<dgb\rel>` directories.
diff --git a/decoder/docs/doxygen_config.dox b/decoder/docs/doxygen_config.dox
index 8aa6ea8..2a581a3 100644
--- a/decoder/docs/doxygen_config.dox
+++ b/decoder/docs/doxygen_config.dox
@@ -38,7 +38,7 @@ PROJECT_NAME           = "OpenCSD - CoreSight Trace Decode Library"
 # could be handy for archiving the generated documentation or if some version
 # control system is used.
 
-PROJECT_NUMBER         = 1.5.2
+PROJECT_NUMBER         = 1.5.3
 
 # Using the PROJECT_BRIEF tag one can provide an optional one line description
 # for a project that appears at the top of each page and should give viewer a
diff --git a/decoder/docs/man/trc_pkt_lister.1 b/decoder/docs/man/trc_pkt_lister.1
index b0c9bc3..16aee91 100644
--- a/decoder/docs/man/trc_pkt_lister.1
+++ b/decoder/docs/man/trc_pkt_lister.1
@@ -116,6 +116,7 @@ trc_pkt_lister -ss_dir ../../snapshots/TC2 -o_raw_unpacked
 .PP
 .B Output:
 .br
+.nf
 Frame Data; Index  17958; ID_DATA[0x11]; 16 04 c0 86 42 97 e1 c4 
 .br
 Idx:17945; ID:11;	I_SYNC : Instruction Packet synchronisation.; (Periodic); Addr=0xc00
@@ -131,11 +132,14 @@ Idx:17974; ID:11;	P_HDR : Atom P-header.; WW; Cycles=2
 .PP
 .B Juno :
 ETB_1 selected which contains STM source output, plus raw packet output
+.fi
 .PP
 .B Command line:
 trc_pkt_lister -ss_dir ../../snapshots/juno_r1_1 -o_raw_unpacked -src_name ETB_1
 .PP
 .B Output
+.br
+.nf
 Trace Packet Lister : STM Protocol on Trace ID 0x20
 .br
 Frame Data; Index      0; ID_DATA[0x20]; ff ff ff ff ff ff ff ff ff ff 0f 0f 30 41 
@@ -151,6 +155,7 @@ Idx:13; ID:20;	M8:Set current master.; Master=0x41
 Idx:17; ID:20;	D32M:32 bit data; with marker.; Data=0x10000000
 .br
 Idx:22; ID:20;	C8:Set current channel.; Chan=0x0001
+.fi
 .PP
 .B Juno : 
 ETMv4 full trace decode + packet monitor, source trace ID 0x10 only.
@@ -161,6 +166,7 @@ trc_pkt_lister -ss_dir ../../snapshots/juno_r1_1 -decode -id 0x10
 .PP
 .B Output
 .br
+.nf
 Idx:17204; ID:10; [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x80 ];	I_ASYNC : Alignment Synchronisation.
 .br
 Idx:17218; ID:10; [0x01 0x01 0x00 ];	I_TRACE_INFO : Trace Info.; INFO=0x0
@@ -178,3 +184,4 @@ Idx:17230; ID:10; OCSD_GEN_TRC_ELEM_TRACE_ON( [begin or filter])
 Idx:17232; ID:10; OCSD_GEN_TRC_ELEM_PE_CONTEXT((ISA=A64) EL1N; 64-bit; VMID=0x0; CTXTID=0x0; )
 .br
 Idx:17248; ID:10; OCSD_GEN_TRC_ELEM_INSTR_RANGE(exec range=0xffffffc000096a00:[0xffffffc000096a10] num_i(4) last_sz(4) (ISA=A64) E ISB )
+.fi
diff --git a/decoder/include/common/ocsd_dcd_tree.h b/decoder/include/common/ocsd_dcd_tree.h
index b1c3dc6..1a3fdf6 100644
--- a/decoder/include/common/ocsd_dcd_tree.h
+++ b/decoder/include/common/ocsd_dcd_tree.h
@@ -290,6 +290,14 @@ public:
 
     void logMappedRanges();     //!< Log the mapped memory ranges to the default message logger.
 
+    /*! Memory accessor cacheing
+     * 
+     *  Memory accessor uses caching to reduce the number of calls / callbacks for memory images
+     *  This allows controlling / disabling of cacheing mechanisms.
+     *  Error returned if cache limits exceeded (4096 byte page, 256 pages)
+     */
+    ocsd_err_t setMemAccCacheing(const bool enable, const uint16_t page_size, const int nr_pages);
+
 /** @}*/
 
 /** @name Memory Accessors
diff --git a/decoder/include/mem_acc/trc_mem_acc_cache.h b/decoder/include/mem_acc/trc_mem_acc_cache.h
index 351d424..c321fd0 100644
--- a/decoder/include/mem_acc/trc_mem_acc_cache.h
+++ b/decoder/include/mem_acc/trc_mem_acc_cache.h
@@ -83,7 +83,8 @@ public:
 
     /* cache enabling and usage */
     ocsd_err_t enableCaching(bool bEnable);
-    ocsd_err_t setCacheSizes(const uint16_t page_size, const int nr_pages);
+    // optionally error if outside limits - otherwise set to max / min automatically
+    ocsd_err_t setCacheSizes(const uint16_t page_size, const int nr_pages, const bool err_on_limit = false);
 
     const bool enabled() const { return m_bCacheEnabled; };
     const bool enabled_for_size(const uint32_t reqSize) const
@@ -109,7 +110,7 @@ private:
     bool blockInCache(const ocsd_vaddr_t address, const uint32_t reqBytes, const uint8_t trcID); // run through each page to look for data.
     bool blockInPage(const ocsd_vaddr_t address, const uint32_t reqBytes, const uint8_t trcID);    
 
-    void logMsg(const std::string &szMsg);
+    void logMsg(const std::string &szMsg, ocsd_err_t err = OCSD_OK);
     int findNewPage();
     void incSequence(); // increment sequence on current block
 
diff --git a/decoder/include/mem_acc/trc_mem_acc_mapper.h b/decoder/include/mem_acc/trc_mem_acc_mapper.h
index 4d906f2..e0de833 100644
--- a/decoder/include/mem_acc/trc_mem_acc_mapper.h
+++ b/decoder/include/mem_acc/trc_mem_acc_mapper.h
@@ -87,8 +87,9 @@ public:
     // control memory access caching at runtime
     ocsd_err_t enableCaching(bool bEnable);
 
-    // set cache page size and number of pages (max 16k size, 256 pages)
-    ocsd_err_t setCacheSizes(uint16_t page_size, int num_pages);
+    // set cache page size and number of pages (max 16k size, 256 pages) - 
+    // optionally error if outside limits - otherwise set to max / min automatically
+    ocsd_err_t setCacheSizes(uint16_t page_size, int num_pages, const bool err_on_limit = false);
 
 protected:
     virtual bool findAccessor(const ocsd_vaddr_t address, const ocsd_mem_space_acc_t mem_space, const uint8_t cs_trace_id) = 0;     // set m_acc_curr if found valid range, leave unchanged if not.
diff --git a/decoder/include/opencsd/c_api/opencsd_c_api.h b/decoder/include/opencsd/c_api/opencsd_c_api.h
index ebbba87..62f6031 100644
--- a/decoder/include/opencsd/c_api/opencsd_c_api.h
+++ b/decoder/include/opencsd/c_api/opencsd_c_api.h
@@ -347,6 +347,20 @@ OCSD_C_API ocsd_err_t ocsd_dt_remove_mem_acc(const dcd_tree_handle_t handle, con
  */
 OCSD_C_API void ocsd_tl_log_mapped_mem_ranges(const dcd_tree_handle_t handle);
 
+/*
+ * Set cacheing for memory accessors - reduce access / callbacks to read memory images.
+ * 
+ * System defaults to caching enabled.
+ * 
+ * @param handle    : Handle to decode tree.
+ * @param enable    : 0 to disable caching.
+ * @param page_size : Page size in bytes.
+ * @param nr_pages  : Number of pages to use.
+ * 
+ * @return ocsd_err_t  : Library error code -  OCSD_OK if successful.
+ */
+OCSD_C_API ocsd_err_t ocsd_dt_set_mem_acc_cacheing(const dcd_tree_handle_t handle, const int enable, const uint16_t page_size, const int nr_pages);
+
 /** @}*/  
 
 /** @name Library Default Error Log Object API
diff --git a/decoder/include/opencsd/ocsd_if_version.h b/decoder/include/opencsd/ocsd_if_version.h
index 284eec3..2bcdc8b 100644
--- a/decoder/include/opencsd/ocsd_if_version.h
+++ b/decoder/include/opencsd/ocsd_if_version.h
@@ -44,7 +44,7 @@
 @{*/
 #define OCSD_VER_MAJOR 0x1 /**< Library Major Version */
 #define OCSD_VER_MINOR 0x5 /**< Library Minor Version */
-#define OCSD_VER_PATCH 0x2 /**< Library Patch Version */
+#define OCSD_VER_PATCH 0x3 /**< Library Patch Version */
 
 /** Library version number - MMMMnnpp format.
     MMMM = major version, 
@@ -53,7 +53,7 @@
 */
 #define OCSD_VER_NUM ((OCSD_VER_MAJOR << 16) | (OCSD_VER_MINOR << 8) | OCSD_VER_PATCH) 
 
-#define OCSD_VER_STRING "1.5.2"    /**< Library Version string */
+#define OCSD_VER_STRING "1.5.3"    /**< Library Version string */
 #define OCSD_LIB_NAME "OpenCSD Library"  /**< Library name string */
 #define OCSD_LIB_SHORT_NAME "OCSD"    /**< Library Short name string */
 /** @}*/
diff --git a/decoder/source/c_api/ocsd_c_api.cpp b/decoder/source/c_api/ocsd_c_api.cpp
index 2cc2334..0398996 100644
--- a/decoder/source/c_api/ocsd_c_api.cpp
+++ b/decoder/source/c_api/ocsd_c_api.cpp
@@ -462,6 +462,21 @@ OCSD_C_API void ocsd_tl_log_mapped_mem_ranges(const dcd_tree_handle_t handle)
     }
 }
 
+OCSD_C_API ocsd_err_t ocsd_dt_set_mem_acc_cacheing(const dcd_tree_handle_t handle, const int enable, const uint16_t page_size, const int nr_pages)
+{
+    ocsd_err_t err = OCSD_OK;
+
+    if (handle != C_API_INVALID_TREE_HANDLE)
+    {
+        DecodeTree* pDT = static_cast<DecodeTree*>(handle);
+        err = pDT->setMemAccCacheing(enable == 0 ? false : true, page_size, nr_pages);
+    }
+    else
+        err = OCSD_ERR_INVALID_PARAM_VAL;
+
+    return err;
+}
+
 OCSD_C_API void ocsd_gen_elem_init(ocsd_generic_trace_elem *p_pkt, const ocsd_gen_trc_elem_t elem_type)
 {
     p_pkt->elem_type = elem_type;
diff --git a/decoder/source/etmv4/trc_pkt_elem_etmv4i.cpp b/decoder/source/etmv4/trc_pkt_elem_etmv4i.cpp
index 8475d7e..ad2b10d 100644
--- a/decoder/source/etmv4/trc_pkt_elem_etmv4i.cpp
+++ b/decoder/source/etmv4/trc_pkt_elem_etmv4i.cpp
@@ -497,7 +497,7 @@ const char *EtmV4ITrcPacket::packetTypeName(const ocsd_etmv4_i_pkt_type type, co
 
     case ETM4_PKT_I_ADDR_CTXT_L_32IS1:
         pName = "I_ADDR_CTXT_L_32IS1";
-        pDesc = "Address & Context, Long, 32 bit, IS0.";
+        pDesc = "Address & Context, Long, 32 bit, IS1.";
         break;
 
     case ETM4_PKT_I_ADDR_CTXT_L_64IS0:
diff --git a/decoder/source/mem_acc/trc_mem_acc_cache.cpp b/decoder/source/mem_acc/trc_mem_acc_cache.cpp
index 903ab73..b638304 100644
--- a/decoder/source/mem_acc/trc_mem_acc_cache.cpp
+++ b/decoder/source/mem_acc/trc_mem_acc_cache.cpp
@@ -38,6 +38,7 @@
 #include "mem_acc/trc_mem_acc_cache.h"
 #include "mem_acc/trc_mem_acc_base.h"
 #include "interfaces/trc_error_log_i.h"
+#include "common/ocsd_error.h"
 
 #ifdef LOG_CACHE_STATS
 #define INC_HITS_RL(idx) m_hits++; m_hit_rl[m_mru_idx]++;
@@ -60,6 +61,7 @@
 
 // uncomment to log cache ops
 // #define LOG_CACHE_OPS
+// #define LOG_CACHE_CREATION
 
 ocsd_err_t TrcMemAccCache::createCaches()
 {
@@ -84,7 +86,11 @@ ocsd_err_t TrcMemAccCache::createCaches()
         m_hit_rl_max[j] = 0;
     }
 #endif
-
+#ifdef LOG_CACHE_CREATION
+    std::ostringstream oss;
+    oss << "MemAcc Caches: Num Pages=" << m_mru_num_pages << "; Page size=" << m_mru_page_size << ";\n";
+    logMsg(oss.str());
+#endif
     return OCSD_OK;
 }
 
@@ -159,32 +165,76 @@ ocsd_err_t TrcMemAccCache::enableCaching(bool bEnable)
     ocsd_err_t err = OCSD_OK;
 
     if (bEnable)
-        err = createCaches();
+    {
+        // don't create caches if they are done already.
+        if (!m_mru)
+            err = createCaches();
+    }
     else
         destroyCaches();
     m_bCacheEnabled = bEnable;
 
+#ifdef LOG_CACHE_CREATION
+    std::ostringstream oss;
+    oss << "MemAcc Caches: " << (bEnable ? "Enabled" : "Disabled") << ";\n";
+    logMsg(oss.str());
+#endif
+
     return err;
 }
 
-ocsd_err_t TrcMemAccCache::setCacheSizes(const uint16_t page_size, const int nr_pages)
+ocsd_err_t TrcMemAccCache::setCacheSizes(const uint16_t page_size, const int nr_pages, const bool err_on_limit /*= false*/)
 {
+    // do't re-create what we already have.
+    if (m_mru &&
+        (m_mru_num_pages == nr_pages) &&
+        (m_mru_page_size == page_size))
+        return OCSD_OK;
+
     /* remove any caches with the existing sizes */
     destroyCaches();
 
     /* set page size within Max/Min range */
     if (page_size > MEM_ACC_CACHE_PAGE_SIZE_MAX)
+    {
+        if (err_on_limit)
+        {
+            logMsg("MemAcc Caching: page size too large", OCSD_ERR_INVALID_PARAM_VAL);
+            return OCSD_ERR_INVALID_PARAM_VAL;
+        }
         m_mru_page_size = MEM_ACC_CACHE_PAGE_SIZE_MAX;
+    }
     else if (page_size < MEM_ACC_CACHE_PAGE_SIZE_MIN)
+    {
+        if (err_on_limit)
+        {
+            logMsg("MemAcc Caching: page size too small", OCSD_ERR_INVALID_PARAM_VAL);
+            return OCSD_ERR_INVALID_PARAM_VAL;
+        }
         m_mru_page_size = MEM_ACC_CACHE_PAGE_SIZE_MIN;
+    }
     else
         m_mru_page_size = page_size;
 
     /* set num pages within max/min range */
     if (nr_pages > MEM_ACC_CACHE_MRU_SIZE_MAX)
+    {
+        if (err_on_limit)
+        {
+            logMsg("MemAcc Caching: number of pages too large", OCSD_ERR_INVALID_PARAM_VAL);
+            return OCSD_ERR_INVALID_PARAM_VAL;
+        }
         m_mru_num_pages = MEM_ACC_CACHE_MRU_SIZE_MAX;
+    }
     else if (nr_pages < MEM_ACC_CACHE_MRU_SIZE_MIN)
+    {
+        if (err_on_limit)
+        {
+            logMsg("MemAcc Caching: number of pages too small", OCSD_ERR_INVALID_PARAM_VAL);
+            return OCSD_ERR_INVALID_PARAM_VAL;
+        }
         m_mru_num_pages = MEM_ACC_CACHE_MRU_SIZE_MIN;
+    }
     else
         m_mru_num_pages = nr_pages;
 
@@ -372,10 +422,18 @@ void TrcMemAccCache::invalidateByTraceID(int8_t trcID)
     }
 }
 
-void TrcMemAccCache::logMsg(const std::string &szMsg)
+void TrcMemAccCache::logMsg(const std::string &szMsg, ocsd_err_t err /*= OCSD_OK */ )
 {
     if (m_err_log)
-        m_err_log->LogMessage(ITraceErrorLog::HANDLE_GEN_INFO, OCSD_ERR_SEV_INFO, szMsg);
+    {
+        if (err == OCSD_OK)
+            m_err_log->LogMessage(ITraceErrorLog::HANDLE_GEN_INFO, OCSD_ERR_SEV_INFO, szMsg);
+        else
+        {
+            ocsdError ocsd_err( OCSD_ERR_SEV_ERROR, err, szMsg);
+            m_err_log->LogError(ITraceErrorLog::HANDLE_GEN_INFO, &ocsd_err);
+        }
+    }
 }
 
 void TrcMemAccCache::setErrorLog(ITraceErrorLog *log)
diff --git a/decoder/source/mem_acc/trc_mem_acc_mapper.cpp b/decoder/source/mem_acc/trc_mem_acc_mapper.cpp
index 9327f56..7cd57fe 100644
--- a/decoder/source/mem_acc/trc_mem_acc_mapper.cpp
+++ b/decoder/source/mem_acc/trc_mem_acc_mapper.cpp
@@ -72,9 +72,9 @@ ocsd_err_t TrcMemAccMapper::enableCaching(bool bEnable)
 }
 
 // set cache page size and number of pages (max 4096 size, 256 pages)
-ocsd_err_t TrcMemAccMapper::setCacheSizes(uint16_t page_size, int num_pages)
+ocsd_err_t TrcMemAccMapper::setCacheSizes(uint16_t page_size, int num_pages, const bool err_on_limit /*= false*/)
 {
-    return m_cache.setCacheSizes(page_size, num_pages);
+    return m_cache.setCacheSizes(page_size, num_pages, err_on_limit);
 }
 
 // memory access interface
diff --git a/decoder/source/ocsd_dcd_tree.cpp b/decoder/source/ocsd_dcd_tree.cpp
index d2c5105..9b1cae5 100644
--- a/decoder/source/ocsd_dcd_tree.cpp
+++ b/decoder/source/ocsd_dcd_tree.cpp
@@ -235,6 +235,25 @@ void DecodeTree::logMappedRanges()
         m_default_mapper->logMappedRanges();
 }
 
+ocsd_err_t DecodeTree::setMemAccCacheing(const bool enable, const uint16_t page_size, const int nr_pages)
+{
+    ocsd_err_t err = OCSD_OK;
+
+    if (!m_default_mapper)
+        return OCSD_ERR_NOT_INIT;
+
+    if (enable)
+    {
+        // set cache sizes - error if params out of limits
+        err = m_default_mapper->setCacheSizes(page_size, nr_pages, true);
+        if (err == OCSD_OK)
+            err = m_default_mapper->enableCaching(true);
+    }
+    else
+        err = m_default_mapper->enableCaching(false);
+    return err;
+}
+
 /* Memory accessor creation - all on default mem accessor using the 0 CSID for global core space. */
 ocsd_err_t DecodeTree::addBufferMemAcc(const ocsd_vaddr_t address, const ocsd_mem_space_acc_t mem_space, const uint8_t *p_mem_buffer, const uint32_t mem_length)
 {
diff --git a/decoder/source/ocsd_error.cpp b/decoder/source/ocsd_error.cpp
index 3aee372..fc63c77 100644
--- a/decoder/source/ocsd_error.cpp
+++ b/decoder/source/ocsd_error.cpp
@@ -80,8 +80,8 @@ static const char *s_errorCodeDescs[][2] = {
     {"OCSD_ERR_MEM_ACC_OVERLAP","Attempted to set an overlapping range in memory access map."},
     {"OCSD_ERR_MEM_ACC_FILE_NOT_FOUND","Memory access file could not be opened."},
     {"OCSD_ERR_MEM_ACC_FILE_DIFF_RANGE","Attempt to re-use the same memory access file for a different address range."},
-    {"OCSD_ERR_MEM_ACC_BAD_LEN","Memory accessor returned a bad read length value (larger than requested."},
     {"OCSD_ERR_MEM_ACC_RANGE_INVALID","Address range in accessor set to invalid values."},
+    {"OCSD_ERR_MEM_ACC_BAD_LEN","Memory accessor returned a bad read length value (larger than requested."},
     /* test errors - errors generated only by the test code, not the library */
     {"OCSD_ERR_TEST_SNAPSHOT_PARSE", "Test snapshot file parse error"},
     {"OCSD_ERR_TEST_SNAPSHOT_PARSE_INFO", "Test snapshot file parse information"},
diff --git a/decoder/tests/build/linux/c_api_pkt_print_test/makefile b/decoder/tests/build/linux/c_api_pkt_print_test/makefile
index f1108e4..57fc9bb 100644
--- a/decoder/tests/build/linux/c_api_pkt_print_test/makefile
+++ b/decoder/tests/build/linux/c_api_pkt_print_test/makefile
@@ -58,7 +58,7 @@ test_app: 	$(BIN_TEST_TARGET_DIR)/$(PROG)
 
  $(BIN_TEST_TARGET_DIR)/$(PROG): $(OBJECTS) | build_dir
 			mkdir -p  $(BIN_TEST_TARGET_DIR)
-			$(LINKER) $(LDFLAGS) $(OBJECTS) -Wl,--start-group $(LIBS) -Wl,--end-group -o $(BIN_TEST_TARGET_DIR)/$(PROG)
+			$(LINKER) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(BIN_TEST_TARGET_DIR)/$(PROG)
 			cp $(LIB_TARGET_DIR)/*.so .
 
 build_dir:
diff --git a/decoder/tests/build/linux/frame_demux_test/makefile b/decoder/tests/build/linux/frame_demux_test/makefile
index 29c75a0..36980ca 100644
--- a/decoder/tests/build/linux/frame_demux_test/makefile
+++ b/decoder/tests/build/linux/frame_demux_test/makefile
@@ -56,7 +56,7 @@ test_app: $(BIN_TEST_TARGET_DIR)/$(PROG)
 
  $(BIN_TEST_TARGET_DIR)/$(PROG): $(OBJECTS) | build_dir
 			mkdir -p  $(BIN_TEST_TARGET_DIR)
-			$(LINKER) $(LDFLAGS) $(OBJECTS) -Wl,--start-group $(LIBS) -Wl,--end-group -o $(BIN_TEST_TARGET_DIR)/$(PROG)
+			$(LINKER) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(BIN_TEST_TARGET_DIR)/$(PROG)
 
 build_dir:
 	mkdir -p $(BUILD_DIR)
diff --git a/decoder/tests/build/linux/mem_acc_test/makefile b/decoder/tests/build/linux/mem_acc_test/makefile
index 10df021..3b968d9 100644
--- a/decoder/tests/build/linux/mem_acc_test/makefile
+++ b/decoder/tests/build/linux/mem_acc_test/makefile
@@ -56,7 +56,7 @@ test_app: $(BIN_TEST_TARGET_DIR)/$(PROG)
 
  $(BIN_TEST_TARGET_DIR)/$(PROG): $(OBJECTS) | build_dir
 			mkdir -p  $(BIN_TEST_TARGET_DIR)
-			$(LINKER) $(LDFLAGS) $(OBJECTS) -Wl,--start-group $(LIBS) -Wl,--end-group -o $(BIN_TEST_TARGET_DIR)/$(PROG)
+			$(LINKER) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(BIN_TEST_TARGET_DIR)/$(PROG)
 
 build_dir:
 	mkdir -p $(BUILD_DIR)
diff --git a/decoder/tests/build/linux/mem_buffer_eg/makefile b/decoder/tests/build/linux/mem_buffer_eg/makefile
index 7939521..81799b8 100644
--- a/decoder/tests/build/linux/mem_buffer_eg/makefile
+++ b/decoder/tests/build/linux/mem_buffer_eg/makefile
@@ -58,7 +58,7 @@ test_app: $(BIN_TEST_TARGET_DIR)/$(PROG)
 
  $(BIN_TEST_TARGET_DIR)/$(PROG): $(OBJECTS) | build_dir
 			mkdir -p  $(BIN_TEST_TARGET_DIR)
-			$(LINKER) $(LDFLAGS) $(OBJECTS) -Wl,--start-group $(LIBS) -Wl,--end-group -o $(BIN_TEST_TARGET_DIR)/$(PROG)
+			$(LINKER) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(BIN_TEST_TARGET_DIR)/$(PROG)
 
 build_dir:
 	mkdir -p $(BUILD_DIR)
diff --git a/decoder/tests/build/linux/perr/makefile b/decoder/tests/build/linux/perr/makefile
index de6cdf4..b2d3601 100644
--- a/decoder/tests/build/linux/perr/makefile
+++ b/decoder/tests/build/linux/perr/makefile
@@ -56,7 +56,7 @@ test_app: $(BIN_TEST_TARGET_DIR)/$(PROG)
 
  $(BIN_TEST_TARGET_DIR)/$(PROG): $(OBJECTS) | build_dir
 			mkdir -p  $(BIN_TEST_TARGET_DIR)
-			$(LINKER) $(LDFLAGS) $(OBJECTS) -Wl,--start-group $(LIBS) -Wl,--end-group -o $(BIN_TEST_TARGET_DIR)/$(PROG)
+			$(LINKER) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(BIN_TEST_TARGET_DIR)/$(PROG)
 
 build_dir:
 	mkdir -p $(BUILD_DIR)
diff --git a/decoder/tests/build/linux/trc_pkt_lister/makefile b/decoder/tests/build/linux/trc_pkt_lister/makefile
index df0af0a..236d263 100644
--- a/decoder/tests/build/linux/trc_pkt_lister/makefile
+++ b/decoder/tests/build/linux/trc_pkt_lister/makefile
@@ -59,11 +59,11 @@ test_app: $(BIN_TEST_TARGET_DIR)/$(PROG)
 
  $(BIN_TEST_TARGET_DIR)/$(PROG): $(OBJECTS) | build_dir
 			mkdir -p  $(BIN_TEST_TARGET_DIR)
-			$(LINKER) $(LDFLAGS) $(OBJECTS) -Wl,--start-group $(LIBS) -Wl,--end-group -o $(BIN_TEST_TARGET_DIR)/$(PROG)
+			$(LINKER) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(BIN_TEST_TARGET_DIR)/$(PROG)
 
 $(BIN_TEST_TARGET_DIR)/$(PROG_S): $(OBJECTS) | build_dir
 			mkdir -p  $(BIN_TEST_TARGET_DIR)
-			$(LINKER) -static $(LDFLAGS) $(OBJECTS) -Wl,--start-group $(LIBS) -Wl,--end-group -o $(BIN_TEST_TARGET_DIR)/$(PROG_S)
+			$(LINKER) -static $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(BIN_TEST_TARGET_DIR)/$(PROG_S)
 
 
 
diff --git a/decoder/tests/build/win-vs2022/c_api_pkt_print_test/x64/debug-dll/c_api_pkt_print_test_dll.exe.recipe b/decoder/tests/build/win-vs2022/c_api_pkt_print_test/x64/debug-dll/c_api_pkt_print_test_dll.exe.recipe
deleted file mode 100644
index 63d719b..0000000
--- a/decoder/tests/build/win-vs2022/c_api_pkt_print_test/x64/debug-dll/c_api_pkt_print_test_dll.exe.recipe
+++ /dev/null
@@ -1,11 +0,0 @@
-﻿<?xml version="1.0" encoding="utf-8"?>
-<Project>
-  <ProjectOutputs>
-    <ProjectOutput>
-      <FullPath>C:\work\OpenCSD\ocsd-linaro\decoder\tests\bin\win64\dbg\c_api_pkt_print_test_dll.exe</FullPath>
-    </ProjectOutput>
-  </ProjectOutputs>
-  <ContentFiles />
-  <SatelliteDlls />
-  <NonRecipeFileRefs />
-</Project>
\ No newline at end of file
diff --git a/decoder/tests/snapshot_parser_lib/include/ss_to_dcdtree.h b/decoder/tests/snapshot_parser_lib/include/ss_to_dcdtree.h
index 0120120..b26b6d6 100644
--- a/decoder/tests/snapshot_parser_lib/include/ss_to_dcdtree.h
+++ b/decoder/tests/snapshot_parser_lib/include/ss_to_dcdtree.h
@@ -91,7 +91,7 @@ private:
     void LogError(const ocsdError &err);
 
     ocsd_mem_space_acc_t getMemSpaceFromString(const std::string& memspace);
-    void processDumpfiles(std::vector<Parser::DumpDef> &dumps);
+    ocsd_err_t processDumpfiles(std::vector<Parser::DumpDef> &dumps);
 
 
     uint32_t m_add_create_flags;
diff --git a/decoder/tests/snapshot_parser_lib/source/ss_to_dcdtree.cpp b/decoder/tests/snapshot_parser_lib/source/ss_to_dcdtree.cpp
index dd14aff..f8b1990 100644
--- a/decoder/tests/snapshot_parser_lib/source/ss_to_dcdtree.cpp
+++ b/decoder/tests/snapshot_parser_lib/source/ss_to_dcdtree.cpp
@@ -78,7 +78,9 @@ std::string CreateDcdTreeFromSnapShot::getBufferFileNameFromBuffName(const std::
 
 
 bool CreateDcdTreeFromSnapShot::createDecodeTree(const std::string &SourceName, bool bPacketProcOnly, uint32_t add_create_flags)
-{    
+{   
+    ocsd_err_t err = OCSD_OK;
+
     m_add_create_flags = add_create_flags;
     if(m_bInit)
     {
@@ -142,7 +144,7 @@ bool CreateDcdTreeFromSnapShot::createDecodeTree(const std::string &SourceName,
                                 numDecodersCreated++;
                                 if(!bPacketProcOnly &&(core_dev->dumpDefs.size() > 0))
                                 {
-                                    processDumpfiles(core_dev->dumpDefs);
+                                    err = processDumpfiles(core_dev->dumpDefs);
                                 }
                             }
                             else
@@ -190,7 +192,7 @@ bool CreateDcdTreeFromSnapShot::createDecodeTree(const std::string &SourceName,
                     it++;
             }
 
-            if(numDecodersCreated == 0)
+            if((numDecodersCreated == 0) || (err != OCSD_OK))
             {
                 // nothing useful found 
                 destroyDecodeTree();
@@ -618,11 +620,12 @@ ocsd_mem_space_acc_t CreateDcdTreeFromSnapShot::getMemSpaceFromString(const std:
     return mem_space;
 }
 
-void CreateDcdTreeFromSnapShot::processDumpfiles(std::vector<Parser::DumpDef> &dumps)
+ocsd_err_t CreateDcdTreeFromSnapShot::processDumpfiles(std::vector<Parser::DumpDef> &dumps)
 {
     std::string dumpFilePathName;
     std::vector<Parser::DumpDef>::const_iterator it;
     ocsd_mem_space_acc_t mem_space;
+    ocsd_err_t err = OCSD_OK;
 
     it = dumps.begin();
     while(it != dumps.end())
@@ -650,6 +653,7 @@ void CreateDcdTreeFromSnapShot::processDumpfiles(std::vector<Parser::DumpDef> &d
         }
         it++;
     }
+    return err;
 }
 
 /* End of File ss_to_dcdtree.cpp */
diff --git a/decoder/tests/source/c_api_pkt_print_test.c b/decoder/tests/source/c_api_pkt_print_test.c
index b930e05..c508f42 100644
--- a/decoder/tests/source/c_api_pkt_print_test.c
+++ b/decoder/tests/source/c_api_pkt_print_test.c
@@ -933,6 +933,9 @@ int process_trace_data(FILE *pf)
 
         ret = create_decoder(dcdtree_handle);
         ocsd_tl_log_mapped_mem_ranges(dcdtree_handle);
+        // check the mem acc caching api - if we are decoding.
+        if (op > TEST_PKT_PRINT)
+            ocsd_dt_set_mem_acc_cacheing(dcdtree_handle, 1, 1024, 8);
 
         if (ret == OCSD_OK)
         {
diff --git a/decoder/tests/source/trc_pkt_lister.cpp b/decoder/tests/source/trc_pkt_lister.cpp
index a207605..f62ad8d 100644
--- a/decoder/tests/source/trc_pkt_lister.cpp
+++ b/decoder/tests/source/trc_pkt_lister.cpp
@@ -40,6 +40,8 @@
 #include <iostream>
 #include <sstream>
 #include <cstring>
+#include <chrono>
+#include <ctime>
 
 #include "opencsd.h"              // the library
 #include "trace_snapshots.h"    // the snapshot reading test library
@@ -644,9 +646,11 @@ bool ProcessInputFile(DecodeTree *dcd_tree, std::string &in_filename,
                       TrcGenericElementPrinter* genElemPrinter, ocsdDefaultErrorLogger& err_logger)
 {
     bool bOK = true;
-
+    std::chrono::time_point<std::chrono::steady_clock> start, end;   // measure decode time
+    
     // need to push the data through the decode tree.
     std::ifstream in;
+
     in.open(in_filename, std::ifstream::in | std::ifstream::binary);
     if (in.is_open())
     {
@@ -655,6 +659,8 @@ bool ProcessInputFile(DecodeTree *dcd_tree, std::string &in_filename,
         uint8_t trace_buffer[bufferSize];   // temporary buffer to load blocks of data from the file
         uint32_t trace_index = 0;           // index into the overall trace buffer (file).
 
+        start = std::chrono::steady_clock::now();
+
         // process the file, a buffer load at a time
         while (!in.eof() && !OCSD_DATA_RESP_IS_FATAL(dataPathResp))
         {
@@ -745,7 +751,10 @@ bool ProcessInputFile(DecodeTree *dcd_tree, std::string &in_filename,
         in.close();
 
         std::ostringstream oss;
-        oss << "Trace Packet Lister : Trace buffer done, processed " << trace_index << " bytes.\n";
+        end = std::chrono::steady_clock::now();
+        std::chrono::duration<double> sec_elapsed{end -start};
+
+        oss << "Trace Packet Lister : Trace buffer done, processed " << trace_index << " bytes in " << std::setprecision(8) << sec_elapsed.count() << " seconds.\n";
         logger.LogMsg(oss.str());
         if (stats)
             PrintDecodeStats(dcd_tree);
@@ -801,10 +810,8 @@ void ListTracePackets(ocsdDefaultErrorLogger &err_logger, SnapShotReader &reader
             }
             if (macc_cache_disable || macc_cache_page_size || macc_cache_page_num)
             {
-                TrcMemAccMapper* pMapper = dcd_tree->getMemAccMapper();
-
                 if (macc_cache_disable)
-                    pMapper->enableCaching(false);
+                    dcd_tree->setMemAccCacheing(false, 0, 0);
                 else 
                 {
                     // one value set - set the other to default
@@ -812,7 +819,7 @@ void ListTracePackets(ocsdDefaultErrorLogger &err_logger, SnapShotReader &reader
                         macc_cache_page_size = MEM_ACC_CACHE_DEFAULT_PAGE_SIZE;
                     if (!macc_cache_page_num)
                         macc_cache_page_num = MEM_ACC_CACHE_DEFAULT_MRU_SIZE;
-                    pMapper->setCacheSizes(macc_cache_page_size, macc_cache_page_num);
+                    dcd_tree->setMemAccCacheing(true, macc_cache_page_size, macc_cache_page_num);
                 }
             }
         }
```

