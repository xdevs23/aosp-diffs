```diff
diff --git a/Android.bp b/Android.bp
index ff46b45..b8e9c66 100644
--- a/Android.bp
+++ b/Android.bp
@@ -3,6 +3,7 @@
 // deqp_spirv_headers_unified1_extinst.debuginfo.grammar.json
 // deqp_spirv_headers_unified1_extinst.glsl.std.450.grammar.json
 // deqp_spirv_headers_unified1_extinst.nonsemantic.clspvreflection.grammar.json
+// deqp_spirv_headers_unified1_extinst.nonsemantic.vkspreflection.grammar.json
 // deqp_spirv_headers_unified1_extinst.nonsemantic.shader.debuginfo.100.grammar.json
 // deqp_spirv_headers_unified1_extinst.opencl.debuginfo.100.grammar.json
 // deqp_spirv_headers_unified1_extinst.opencl.std.100.grammar.json
@@ -60,6 +61,11 @@ filegroup {
     srcs: ["include/spirv/unified1/extinst.nonsemantic.clspvreflection.grammar.json"],
 }
 
+filegroup {
+    name: "deqp_spirv_headers_unified1_extinst.nonsemantic.vkspreflection.grammar.json",
+    srcs: ["include/spirv/unified1/extinst.nonsemantic.vkspreflection.grammar.json"],
+}
+
 filegroup {
     name: "deqp_spirv_headers_unified1_extinst.nonsemantic.shader.debuginfo.100.grammar.json",
     srcs: ["include/spirv/unified1/extinst.nonsemantic.shader.debuginfo.100.grammar.json"],
diff --git a/BUILD.bazel b/BUILD.bazel
index 25634d9..36e83fa 100644
--- a/BUILD.bazel
+++ b/BUILD.bazel
@@ -133,6 +133,7 @@ cc_library(
         "include/spirv/unified1/GLSL.std.450.h",
         "include/spirv/unified1/NonSemanticClspvReflection.h",
         "include/spirv/unified1/NonSemanticDebugPrintf.h",
+        "include/spirv/unified1/NonSemanticShaderDebugInfo100.h",
         "include/spirv/unified1/NonSemanticVkspReflection.h",
         "include/spirv/unified1/OpenCL.std.h",
     ],
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 8cd4037..957b922 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -24,7 +24,7 @@
 # TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # MATERIALS OR THE USE OR OTHER DEALINGS IN THE MATERIALS.
 cmake_minimum_required(VERSION 3.14)
-project(SPIRV-Headers LANGUAGES CXX VERSION 1.5.5)
+project(SPIRV-Headers LANGUAGES C CXX VERSION 1.5.5)
 
 if (CMAKE_VERSION VERSION_LESS "3.21")
     # https://cmake.org/cmake/help/latest/variable/PROJECT_IS_TOP_LEVEL.html
@@ -35,12 +35,14 @@ add_library(SPIRV-Headers INTERFACE)
 add_library(SPIRV-Headers::SPIRV-Headers ALIAS SPIRV-Headers)
 target_include_directories(SPIRV-Headers INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
 
-if (PROJECT_IS_TOP_LEVEL)
-    option(BUILD_TESTS "Build the tests")
-    if (BUILD_TESTS)
-        add_subdirectory(tests)
-    endif()
+option(SPIRV_HEADERS_ENABLE_TESTS "Test SPIRV-Headers" ${PROJECT_IS_TOP_LEVEL})
+option(SPIRV_HEADERS_ENABLE_INSTALL "Install SPIRV-Headers" ${PROJECT_IS_TOP_LEVEL})
+
+if(SPIRV_HEADERS_ENABLE_TESTS)
+    add_subdirectory(tests)
+endif()
 
+if(SPIRV_HEADERS_ENABLE_INSTALL)
     include(GNUInstallDirs)
     include(CMakePackageConfigHelpers)
 
diff --git a/OWNERS b/OWNERS
index ca2b824..a973c04 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/external/deqp:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/include/spirv/spir-v.xml b/include/spirv/spir-v.xml
index 4a2de83..243b720 100644
--- a/include/spirv/spir-v.xml
+++ b/include/spirv/spir-v.xml
@@ -64,7 +64,7 @@
         <id value="11"  vendor="Intel"      comment="Contact Alexey, alexey.bader@intel.com"/>
         <id value="12"  vendor="Imagination" comment="Contact Stephen Clarke, stephen.clarke@imgtec.com"/>
         <id value="13"  vendor="Google" tool="Shaderc over Glslang" comment="Contact David Neto, dneto@google.com"/>
-        <id value="14"  vendor="Google" tool="spiregg" comment="Contact Lei Zhang, antiagainst@google.com"/>
+        <id value="14"  vendor="Google" tool="spiregg" comment="Contact Steven Perron, stevenperron@google.com"/>
         <id value="15"  vendor="Google" tool="rspirv" comment="Contact Lei Zhang, antiagainst@gmail.com"/>
         <id value="16"  vendor="X-LEGEND"   tool="Mesa-IR/SPIR-V Translator" comment="Contact Metora Wang, github:metora/MesaGLSLCompiler"/>
         <id value="17"  vendor="Khronos" tool="SPIR-V Tools Linker" comment="Contact David Neto, dneto@google.com"/>
@@ -72,7 +72,7 @@
         <id value="19"  vendor="Tellusim" tool="Clay Shader Compiler" comment="Contact info@tellusim.com"/>
         <id value="20"  vendor="W3C WebGPU Group" tool="WHLSL Shader Translator" comment="https://github.com/gpuweb/WHLSL"/>
         <id value="21"  vendor="Google" tool="Clspv" comment="Contact David Neto, dneto@google.com"/>
-        <id value="22"  vendor="Google" tool="MLIR SPIR-V Serializer" comment="Contact Lei Zhang, antiagainst@google.com"/>
+        <id value="22"  vendor="LLVM" tool="MLIR SPIR-V Serializer" comment="Contact Jakub Kuderski, jakub.kuderski@amd.com, https://mlir.llvm.org/docs/Dialects/SPIR-V/"/>
         <id value="23"  vendor="Google" tool="Tint Compiler" comment="Contact David Neto, dneto@google.com"/>
         <id value="24"  vendor="Google" tool="ANGLE Shader Compiler" comment="Contact Shahbaz Youssefi, syoussefi@google.com"/>
         <id value="25"  vendor="Netease Games" tool="Messiah Shader Compiler" comment="Contact Yuwen Wu, atyuwen@gmail.com"/>
@@ -92,7 +92,11 @@
         <id value="39"  vendor="SirLynix" tool="Nazara ShaderLang Compiler" comment="Contact Jérôme Leclercq, https://github.com/NazaraEngine/ShaderLang"/>
         <id value="40"  vendor="NVIDIA" tool="Slang Compiler" comment="Contact Theresa Foley, tfoley@nvidia.com, https://github.com/shader-slang/slang/"/>
         <id value="41"  vendor="Zig Software Foundation" tool="Zig Compiler" comment="Contact Robin Voetter, https://github.com/Snektron"/>
-        <unused start="42" end="0xFFFF" comment="Tool ID range reservable for future use by vendors"/>
+        <id value="42"  vendor="Rendong Liang" tool="spq" comment="Contact Rendong Liang, admin@penguinliong.moe, https://github.com/PENGUINLIONG/spq-rs"/>
+        <id value="43"  vendor="LLVM" tool="LLVM SPIR-V Backend" comment="Contact Michal Paszkowski, michal.paszkowski@intel.com, https://github.com/llvm/llvm-project/tree/main/llvm/lib/Target/SPIRV"/>
+        <id value="44"  vendor="Robert Konrad" tool="Kongruent" comment="Contact Robert Konrad, https://github.com/Kode/Kongruent"/>
+        <id value="45"  vendor="Kitsunebi Games" tool="Nuvk SPIR-V Emitter and DLSL compiler" comment="Contact Luna Nielsen, luna@foxgirls.gay, https://github.com/Inochi2D/nuvk"/>
+        <unused start="46" end="0xFFFF" comment="Tool ID range reservable for future use by vendors"/>
     </ids>
 
     <!-- SECTION: SPIR-V Opcodes and Enumerants -->
@@ -149,13 +153,14 @@
     <ids type="opcode" start="6528" end="6591" vendor="Codeplay" comment="Contact duncan.brawley@codeplay.com"/>
     <ids type="opcode" start="6592" end="6655" vendor="Saarland University" comment="Contact devillers@cg.uni-saarland.de"/>
     <ids type="opcode" start="6656" end="6719" vendor="Meta" comment="Contact dunfanlu@meta.com"/>
+    <ids type="opcode" start="6720" end="6783" vendor="MediaTek" comment="Contact samuel.huang@mediatek.com"/>
     <!-- Opcode enumerants to reserve for future use. To get a block, allocate
          multiples of 64 starting at the lowest available point in this
          block and add a corresponding <ids> tag immediately above. Make
          sure to fill in the vendor attribute, and preferably add a contact
          person/address in a comment attribute. -->
     <!-- Example new block: <ids type="opcode" start="XXXX" end="XXXX+64n-1" vendor="Add vendor" comment="Contact TBD"/> -->
-    <ids type="opcode" start="6656" end="65535" comment="Opcode range reservable for future use by vendors"/>
+    <ids type="opcode" start="6784" end="65535" comment="Opcode range reservable for future use by vendors"/>
     <!-- End reservations of opcodes -->
 
 
@@ -182,13 +187,14 @@
     <ids type="enumerant" start="6528" end="6591" vendor="Codeplay" comment="Contact duncan.brawley@codeplay.com"/>
     <ids type="enumerant" start="6592" end="6655" vendor="Saarland University" comment="Contact devillers@cg.uni-saarland.de"/>
     <ids type="enumerant" start="6656" end="6719" vendor="Meta" comment="Contact dunfanlu@meta.com"/>
+    <ids type="enumerant" start="6720" end="6783" vendor="MediaTek" comment="Contact samuel.huang@mediatek.com"/>
     <!-- Enumerants to reserve for future use. To get a block, allocate
          multiples of 64 starting at the lowest available point in this
          block and add a corresponding <ids> tag immediately above. Make
          sure to fill in the vendor attribute, and preferably add a contact
          person/address in a comment attribute. -->
     <!-- Example new block: <ids type="enumerant" start="XXXX" end="XXXX+64n-1" vendor="Add vendor" comment="Contact TBD"/> -->
-    <ids type="enumerant" start="6656" end="4294967295" comment="Enumerant range reservable for future use by vendors"/>
+    <ids type="enumerant" start="6784" end="4294967295" comment="Enumerant range reservable for future use by vendors"/>
     <!-- End reservations of enumerants -->
 
 
@@ -208,8 +214,8 @@
 
     <!-- Reserved loop control bits -->
     <ids type="LoopControl" start="0" end="15" vendor="Khronos" comment="Reserved LoopControl bits, not available to vendors - see the SPIR-V Specification"/>
-    <ids type="LoopControl" start="16" end="25" vendor="Intel" comment="Contact michael.kinsner@intel.com"/>
-    <ids type="LoopControl" start="26" end="30" comment="Unreserved bits reservable for use by vendors"/>
+    <ids type="LoopControl" start="16" end="27" vendor="Intel" comment="Contact michael.kinsner@intel.com"/>
+    <ids type="LoopControl" start="28" end="30" comment="Unreserved bits reservable for use by vendors"/>
     <ids type="LoopControl" start="31" end="31" vendor="Khronos" comment="Reserved LoopControl bit, not available to vendors"/>
 
 
@@ -269,8 +275,9 @@
 
     <!-- Reserved memory operand bits -->
     <ids type="MemoryOperand" start="0" end="15" vendor="Khronos" comment="Reserved MemoryOperand bits, not available to vendors - see the SPIR-V Specification"/>
-    <ids type="MemoryOperand" start="16" end="17" vendor="Intel" comment="Contact michael.kinsner@intel.com"/>
-    <ids type="MemoryOperand" start="18" end="30" comment="Unreserved bits reservable for use by vendors"/>
+    <ids type="MemoryOperand" start="16" end="18" vendor="Intel" comment="Contact michael.kinsner@intel.com"/>
+    <ids type="MemoryOperand" start="19" end="22" vendor="Arm" comment="Contact kevin.petit@arm.com"/>
+    <ids type="MemoryOperand" start="23" end="30" comment="Unreserved bits reservable for use by vendors"/>
     <ids type="MemoryOperand" start="31" end="31" vendor="Khronos" comment="Reserved MemoryOperand bit, not available to vendors"/>
 
     <!-- SECTION: SPIR-V Image Operand Bit Reservations -->
diff --git a/include/spirv/unified1/NonSemanticVkspReflection.h b/include/spirv/unified1/NonSemanticVkspReflection.h
index 0ef478a..af4a556 100644
--- a/include/spirv/unified1/NonSemanticVkspReflection.h
+++ b/include/spirv/unified1/NonSemanticVkspReflection.h
@@ -33,7 +33,7 @@ extern "C" {
 #endif
 
 enum {
-    NonSemanticVkspReflectionRevision = 1,
+    NonSemanticVkspReflectionRevision = 4,
     NonSemanticVkspReflectionRevision_BitWidthPadding = 0x7fffffff
 };
 
diff --git a/include/spirv/unified1/extinst.nonsemantic.vkspreflection.grammar.json b/include/spirv/unified1/extinst.nonsemantic.vkspreflection.grammar.json
index bee1bea..0bc12d6 100644
--- a/include/spirv/unified1/extinst.nonsemantic.vkspreflection.grammar.json
+++ b/include/spirv/unified1/extinst.nonsemantic.vkspreflection.grammar.json
@@ -1,25 +1,26 @@
 {
-  "revision" : 1,
+  "revision" : 4,
   "instructions" : [
     {
       "opname" : "Configuration",
       "opcode" : 1,
       "operands" : [
-        {"kind" : "LiteralString", "name" : "enabledExtensionNames" },
-        {"kind" : "LiteralInteger", "name" : "specializationInfoDataSize" },
-        {"kind" : "LiteralString", "name" : "specializationInfoData" },
-        {"kind" : "LiteralString", "name" : "shaderName" },
-        {"kind" : "LiteralString", "name" : "EntryPoint" },
-        {"kind" : "LiteralInteger", "name" : "groupCountX" },
-        {"kind" : "LiteralInteger", "name" : "groupCountY" },
-        {"kind" : "LiteralInteger", "name" : "groupCountZ" }
+        {"kind" : "IdRef", "name" : "enabledExtensionNames" },
+        {"kind" : "IdRef", "name" : "specializationInfoDataSize" },
+        {"kind" : "IdRef", "name" : "specializationInfoData" },
+        {"kind" : "IdRef", "name" : "shaderName" },
+        {"kind" : "IdRef", "name" : "EntryPoint" },
+        {"kind" : "IdRef", "name" : "groupCountX" },
+        {"kind" : "IdRef", "name" : "groupCountY" },
+        {"kind" : "IdRef", "name" : "groupCountZ" },
+        {"kind" : "IdRef", "name" : "dispatchId" }
       ]
     },
     {
       "opname" : "StartCounter",
       "opcode" : 2,
       "operands" : [
-        {"kind" : "LiteralString", "name" : "name" }
+        {"kind" : "IdRef", "name" : "name" }
       ]
     },
     {
@@ -33,102 +34,104 @@
       "opname" : "PushConstants",
       "opcode" : 4,
       "operands" : [
-        { "kind" : "LiteralInteger", "name" : "offset" },
-        { "kind" : "LiteralInteger", "name" : "size" },
-        { "kind" : "LiteralString", "name" : "pValues" },
-        { "kind" : "LiteralInteger", "name" : "stageFlags" }
+        { "kind" : "IdRef", "name" : "offset" },
+        { "kind" : "IdRef", "name" : "size" },
+        { "kind" : "IdRef", "name" : "pValues" },
+        { "kind" : "IdRef", "name" : "stageFlags" }
       ]
     },
     {
       "opname" : "SpecializationMapEntry",
       "opcode" : 5,
       "operands" : [
-        {"kind" : "LiteralInteger", "name" : "constantID" },
-        {"kind" : "LiteralInteger", "name" : "offset" },
-        {"kind" : "LiteralInteger", "name" : "size" }
+        {"kind" : "IdRef", "name" : "constantID" },
+        {"kind" : "IdRef", "name" : "offset" },
+        {"kind" : "IdRef", "name" : "size" }
       ]
     },
     {
       "opname" : "DescriptorSetBuffer",
       "opcode" : 6,
       "operands" : [
-        { "kind" : "LiteralInteger", "name" : "ds" },
-        { "kind" : "LiteralInteger", "name" : "binding" },
-        { "kind" : "LiteralInteger", "name" : "type" },
-        { "kind" : "LiteralInteger", "name" : "flags" },
-        { "kind" : "LiteralInteger", "name" : "queueFamilyIndexCount" },
-        { "kind" : "LiteralInteger", "name" : "sharingMode" },
-        { "kind" : "LiteralInteger", "name" : "size" },
-        { "kind" : "LiteralInteger", "name" : "usage" },
-        { "kind" : "LiteralInteger", "name" : "range" },
-        { "kind" : "LiteralInteger", "name" : "offset" },
-        { "kind" : "LiteralInteger", "name" : "memorySize" },
-        { "kind" : "LiteralInteger", "name" : "memoryType" },
-        { "kind" : "LiteralInteger", "name" : "bindOffset" }
+        { "kind" : "IdRef", "name" : "ds" },
+        { "kind" : "IdRef", "name" : "binding" },
+        { "kind" : "IdRef", "name" : "type" },
+        { "kind" : "IdRef", "name" : "flags" },
+        { "kind" : "IdRef", "name" : "queueFamilyIndexCount" },
+        { "kind" : "IdRef", "name" : "sharingMode" },
+        { "kind" : "IdRef", "name" : "size" },
+        { "kind" : "IdRef", "name" : "usage" },
+        { "kind" : "IdRef", "name" : "range" },
+        { "kind" : "IdRef", "name" : "offset" },
+        { "kind" : "IdRef", "name" : "memorySize" },
+        { "kind" : "IdRef", "name" : "memoryType" },
+        { "kind" : "IdRef", "name" : "bindOffset" },
+        { "kind" : "IdRef", "name" : "viewFlags" },
+        { "kind" : "IdRef", "name" : "viewFormat" }
       ]
     },
     {
       "opname" : "DescriptorSetImage",
       "opcode" : 7,
       "operands" : [
-        { "kind" : "LiteralInteger", "name" : "ds" },
-        { "kind" : "LiteralInteger", "name" : "binding" },
-        { "kind" : "LiteralInteger", "name" : "type" },
-        { "kind" : "LiteralInteger", "name" : "imageLayout"},
-        { "kind" : "LiteralInteger", "name" : "imageFlags"},
-        { "kind" : "LiteralInteger", "name" : "imageType"},
-        { "kind" : "LiteralInteger", "name" : "imageformat"},
-        { "kind" : "LiteralInteger", "name" : "width"},
-        { "kind" : "LiteralInteger", "name" : "height"},
-        { "kind" : "LiteralInteger", "name" : "depth"},
-        { "kind" : "LiteralInteger", "name" : "mipLevels"},
-        { "kind" : "LiteralInteger", "name" : "arrayLayers"},
-        { "kind" : "LiteralInteger", "name" : "samples"},
-        { "kind" : "LiteralInteger", "name" : "tiling"},
-        { "kind" : "LiteralInteger", "name" : "usage"},
-        { "kind" : "LiteralInteger", "name" : "sharingMode"},
-        { "kind" : "LiteralInteger", "name" : "queueFamilyIndexCount"},
-        { "kind" : "LiteralInteger", "name" : "initialLayout"},
-        { "kind" : "LiteralInteger", "name" : "aspectMask"},
-        { "kind" : "LiteralInteger", "name" : "baseMipLevel"},
-        { "kind" : "LiteralInteger", "name" : "levelCount"},
-        { "kind" : "LiteralInteger", "name" : "baseArrayLayer"},
-        { "kind" : "LiteralInteger", "name" : "layerCount"},
-        { "kind" : "LiteralInteger", "name" : "viewFlags"},
-        { "kind" : "LiteralInteger", "name" : "viewType"},
-        { "kind" : "LiteralInteger", "name" : "viewFormat"},
-        { "kind" : "LiteralInteger", "name" : "component_a"},
-        { "kind" : "LiteralInteger", "name" : "component_b"},
-        { "kind" : "LiteralInteger", "name" : "component_g"},
-        { "kind" : "LiteralInteger", "name" : "component_r"},
-        { "kind" : "LiteralInteger", "name" : "memorySize" },
-        { "kind" : "LiteralInteger", "name" : "memoryType" },
-        { "kind" : "LiteralInteger", "name" : "bindOffset"}
+        { "kind" : "IdRef", "name" : "ds" },
+        { "kind" : "IdRef", "name" : "binding" },
+        { "kind" : "IdRef", "name" : "type" },
+        { "kind" : "IdRef", "name" : "imageLayout"},
+        { "kind" : "IdRef", "name" : "imageFlags"},
+        { "kind" : "IdRef", "name" : "imageType"},
+        { "kind" : "IdRef", "name" : "imageformat"},
+        { "kind" : "IdRef", "name" : "width"},
+        { "kind" : "IdRef", "name" : "height"},
+        { "kind" : "IdRef", "name" : "depth"},
+        { "kind" : "IdRef", "name" : "mipLevels"},
+        { "kind" : "IdRef", "name" : "arrayLayers"},
+        { "kind" : "IdRef", "name" : "samples"},
+        { "kind" : "IdRef", "name" : "tiling"},
+        { "kind" : "IdRef", "name" : "usage"},
+        { "kind" : "IdRef", "name" : "sharingMode"},
+        { "kind" : "IdRef", "name" : "queueFamilyIndexCount"},
+        { "kind" : "IdRef", "name" : "initialLayout"},
+        { "kind" : "IdRef", "name" : "aspectMask"},
+        { "kind" : "IdRef", "name" : "baseMipLevel"},
+        { "kind" : "IdRef", "name" : "levelCount"},
+        { "kind" : "IdRef", "name" : "baseArrayLayer"},
+        { "kind" : "IdRef", "name" : "layerCount"},
+        { "kind" : "IdRef", "name" : "viewFlags"},
+        { "kind" : "IdRef", "name" : "viewType"},
+        { "kind" : "IdRef", "name" : "viewFormat"},
+        { "kind" : "IdRef", "name" : "component_a"},
+        { "kind" : "IdRef", "name" : "component_b"},
+        { "kind" : "IdRef", "name" : "component_g"},
+        { "kind" : "IdRef", "name" : "component_r"},
+        { "kind" : "IdRef", "name" : "memorySize" },
+        { "kind" : "IdRef", "name" : "memoryType" },
+        { "kind" : "IdRef", "name" : "bindOffset"}
       ]
     },
     {
       "opname" : "DescriptorSetSampler",
       "opcode" : 8,
       "operands" : [
-        { "kind" : "LiteralInteger", "name" : "ds" },
-        { "kind" : "LiteralInteger", "name" : "binding" },
-        { "kind" : "LiteralInteger", "name" : "type" },
-        { "kind" : "LiteralInteger", "name" : "flags"},
-        { "kind" : "LiteralInteger", "name" : "magFilter"},
-        { "kind" : "LiteralInteger", "name" : "minFilter"},
-        { "kind" : "LiteralInteger", "name" : "mipmapMode"},
-        { "kind" : "LiteralInteger", "name" : "addressModeU"},
-        { "kind" : "LiteralInteger", "name" : "addressModeV"},
-        { "kind" : "LiteralInteger", "name" : "addressModeW"},
-        { "kind" : "LiteralFloat", "name" : "mipLodBias"},
-        { "kind" : "LiteralInteger", "name" : "anisotropyEnable"},
-        { "kind" : "LiteralFloat", "name" : "maxAnisotropy"},
-        { "kind" : "LiteralInteger", "name" : "compareEnable"},
-        { "kind" : "LiteralInteger", "name" : "compareOp"},
-        { "kind" : "LiteralFloat", "name" : "minLod"},
-        { "kind" : "LiteralFloat", "name" : "maxLod"},
-        { "kind" : "LiteralInteger", "name" : "borderColor"},
-        { "kind" : "LiteralInteger", "name" : "unnormalizedCoordinates"}
+        { "kind" : "IdRef", "name" : "ds" },
+        { "kind" : "IdRef", "name" : "binding" },
+        { "kind" : "IdRef", "name" : "type" },
+        { "kind" : "IdRef", "name" : "flags"},
+        { "kind" : "IdRef", "name" : "magFilter"},
+        { "kind" : "IdRef", "name" : "minFilter"},
+        { "kind" : "IdRef", "name" : "mipmapMode"},
+        { "kind" : "IdRef", "name" : "addressModeU"},
+        { "kind" : "IdRef", "name" : "addressModeV"},
+        { "kind" : "IdRef", "name" : "addressModeW"},
+        { "kind" : "IdRef", "name" : "mipLodBias"},
+        { "kind" : "IdRef", "name" : "anisotropyEnable"},
+        { "kind" : "IdRef", "name" : "maxAnisotropy"},
+        { "kind" : "IdRef", "name" : "compareEnable"},
+        { "kind" : "IdRef", "name" : "compareOp"},
+        { "kind" : "IdRef", "name" : "minLod"},
+        { "kind" : "IdRef", "name" : "maxLod"},
+        { "kind" : "IdRef", "name" : "borderColor"},
+        { "kind" : "IdRef", "name" : "unnormalizedCoordinates"}
       ]
     }
   ]
diff --git a/include/spirv/unified1/spirv.bf b/include/spirv/unified1/spirv.bf
index 4231b33..4f067dd 100644
--- a/include/spirv/unified1/spirv.bf
+++ b/include/spirv/unified1/spirv.bf
@@ -12,7 +12,7 @@
 // 
 // MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 // STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
 // 
 // THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -71,6 +71,7 @@ namespace Spv
             WGSL = 10,
             Slang = 11,
             Zig = 12,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum ExecutionModel
@@ -98,6 +99,7 @@ namespace Spv
             CallableNV = 5318,
             TaskEXT = 5364,
             MeshEXT = 5365,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum AddressingModel
@@ -107,6 +109,7 @@ namespace Spv
             Physical64 = 2,
             PhysicalStorageBuffer64 = 5348,
             PhysicalStorageBuffer64EXT = 5348,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum MemoryModel
@@ -116,6 +119,7 @@ namespace Spv
             OpenCL = 2,
             Vulkan = 3,
             VulkanKHR = 3,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum ExecutionMode
@@ -171,6 +175,7 @@ namespace Spv
             EarlyAndLateFragmentTestsAMD = 5017,
             StencilRefReplacingEXT = 5027,
             CoalescingAMDX = 5069,
+            IsApiEntryAMDX = 5070,
             MaxNodeRecursionAMDX = 5071,
             StaticNumWorkgroupsAMDX = 5072,
             ShaderIndexAMDX = 5073,
@@ -183,11 +188,14 @@ namespace Spv
             StencilRefLessBackAMD = 5084,
             QuadDerivativesKHR = 5088,
             RequireFullQuadsKHR = 5089,
+            SharesInputWithAMDX = 5102,
             OutputLinesEXT = 5269,
             OutputLinesNV = 5269,
             OutputPrimitivesEXT = 5270,
             OutputPrimitivesNV = 5270,
+            DerivativeGroupQuadsKHR = 5289,
             DerivativeGroupQuadsNV = 5289,
+            DerivativeGroupLinearKHR = 5290,
             DerivativeGroupLinearNV = 5290,
             OutputTrianglesEXT = 5298,
             OutputTrianglesNV = 5298,
@@ -212,6 +220,10 @@ namespace Spv
             StreamingInterfaceINTEL = 6154,
             RegisterMapInterfaceINTEL = 6160,
             NamedBarrierCountINTEL = 6417,
+            MaximumRegistersINTEL = 6461,
+            MaximumRegistersIdINTEL = 6462,
+            NamedMaximumRegistersINTEL = 6463,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum StorageClass
@@ -231,7 +243,6 @@ namespace Spv
             StorageBuffer = 12,
             TileImageEXT = 4172,
             NodePayloadAMDX = 5068,
-            NodeOutputPayloadAMDX = 5076,
             CallableDataKHR = 5328,
             CallableDataNV = 5328,
             IncomingCallableDataKHR = 5329,
@@ -251,6 +262,7 @@ namespace Spv
             CodeSectionINTEL = 5605,
             DeviceOnlyINTEL = 5936,
             HostOnlyINTEL = 5937,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum Dim
@@ -263,6 +275,7 @@ namespace Spv
             Buffer = 5,
             SubpassData = 6,
             TileImageDataEXT = 4173,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum SamplerAddressingMode
@@ -272,12 +285,14 @@ namespace Spv
             Clamp = 2,
             Repeat = 3,
             RepeatMirrored = 4,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum SamplerFilterMode
         {
             Nearest = 0,
             Linear = 1,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum ImageFormat
@@ -324,6 +339,7 @@ namespace Spv
             R8ui = 39,
             R64ui = 40,
             R64i = 41,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum ImageChannelOrder
@@ -348,6 +364,7 @@ namespace Spv
             sRGBA = 17,
             sBGRA = 18,
             ABGR = 19,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum ImageChannelDataType
@@ -371,6 +388,8 @@ namespace Spv
             UnormInt101010_2 = 16,
             UnsignedIntRaw10EXT = 19,
             UnsignedIntRaw12EXT = 20,
+            UnormInt2_101010EXT = 21,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum ImageOperandsShift
@@ -395,6 +414,7 @@ namespace Spv
             ZeroExtend = 13,
             Nontemporal = 14,
             Offsets = 16,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum ImageOperandsMask
@@ -434,6 +454,7 @@ namespace Spv
             AllowReassoc = 17,
             AllowReassocINTEL = 17,
             AllowTransform = 18,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum FPFastMathModeMask
@@ -457,6 +478,7 @@ namespace Spv
             RTZ = 1,
             RTP = 2,
             RTN = 3,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum LinkageType
@@ -464,6 +486,7 @@ namespace Spv
             Export = 0,
             Import = 1,
             LinkOnceODR = 2,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum AccessQualifier
@@ -471,6 +494,7 @@ namespace Spv
             ReadOnly = 0,
             WriteOnly = 1,
             ReadWrite = 2,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum FunctionParameterAttribute
@@ -484,6 +508,7 @@ namespace Spv
             NoWrite = 6,
             NoReadWrite = 7,
             RuntimeAlignedINTEL = 5940,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum Decoration
@@ -539,11 +564,16 @@ namespace Spv
             NoUnsignedWrap = 4470,
             WeightTextureQCOM = 4487,
             BlockMatchTextureQCOM = 4488,
+            BlockMatchSamplerQCOM = 4499,
             ExplicitInterpAMD = 4999,
             NodeSharesPayloadLimitsWithAMDX = 5019,
             NodeMaxPayloadsAMDX = 5020,
             TrackFinishWritingAMDX = 5078,
             PayloadNodeNameAMDX = 5091,
+            PayloadNodeBaseIndexAMDX = 5098,
+            PayloadNodeSparseArrayAMDX = 5099,
+            PayloadNodeArraySizeAMDX = 5100,
+            PayloadDispatchIndirectAMDX = 5105,
             OverrideCoverageNV = 5248,
             PassthroughNV = 5250,
             ViewportRelativeNV = 5252,
@@ -632,6 +662,7 @@ namespace Spv
             ImplementInRegisterMapINTEL = 6191,
             CacheControlLoadINTEL = 6442,
             CacheControlStoreINTEL = 6443,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum BuiltIn
@@ -707,7 +738,7 @@ namespace Spv
             BaryCoordSmoothSampleAMD = 4997,
             BaryCoordPullModelAMD = 4998,
             FragStencilRefEXT = 5014,
-            CoalescedInputCountAMDX = 5021,
+            RemainingRecursionLevelsAMDX = 5021,
             ShaderIndexAMDX = 5073,
             ViewportMaskNV = 5253,
             SecondaryPositionNV = 5257,
@@ -774,12 +805,14 @@ namespace Spv
             HitKindFrontFacingMicroTriangleNV = 5405,
             HitKindBackFacingMicroTriangleNV = 5406,
             CullMaskKHR = 6021,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum SelectionControlShift
         {
             Flatten = 0,
             DontFlatten = 1,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum SelectionControlMask
@@ -810,6 +843,7 @@ namespace Spv
             NoFusionINTEL = 23,
             LoopCountINTEL = 24,
             MaxReinvocationDelayINTEL = 25,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum LoopControlMask
@@ -842,7 +876,9 @@ namespace Spv
             DontInline = 1,
             Pure = 2,
             Const = 3,
+            OptNoneEXT = 16,
             OptNoneINTEL = 16,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum FunctionControlMask
@@ -852,6 +888,7 @@ namespace Spv
             DontInline = 0x00000002,
             Pure = 0x00000004,
             Const = 0x00000008,
+            OptNoneEXT = 0x00010000,
             OptNoneINTEL = 0x00010000,
         }
 
@@ -874,6 +911,7 @@ namespace Spv
             MakeVisible = 14,
             MakeVisibleKHR = 14,
             Volatile = 15,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum MemorySemanticsMask
@@ -911,6 +949,7 @@ namespace Spv
             NonPrivatePointerKHR = 5,
             AliasScopeINTELMask = 16,
             NoAliasINTELMask = 17,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum MemoryAccessMask
@@ -939,6 +978,7 @@ namespace Spv
             QueueFamily = 5,
             QueueFamilyKHR = 5,
             ShaderCallKHR = 6,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum GroupOperation
@@ -950,6 +990,7 @@ namespace Spv
             PartitionedReduceNV = 6,
             PartitionedInclusiveScanNV = 7,
             PartitionedExclusiveScanNV = 8,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum KernelEnqueueFlags
@@ -957,11 +998,13 @@ namespace Spv
             NoWait = 0,
             WaitKernel = 1,
             WaitWorkGroup = 2,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum KernelProfilingInfoShift
         {
             CmdExecTime = 0,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum KernelProfilingInfoMask
@@ -1046,6 +1089,7 @@ namespace Spv
             TileImageColorReadAccessEXT = 4166,
             TileImageDepthReadAccessEXT = 4167,
             TileImageStencilReadAccessEXT = 4168,
+            CooperativeMatrixLayoutsARM = 4201,
             FragmentShadingRateKHR = 4422,
             SubgroupBallotKHR = 4423,
             DrawParameters = 4427,
@@ -1075,11 +1119,13 @@ namespace Spv
             RoundingModeRTZ = 4468,
             RayQueryProvisionalKHR = 4471,
             RayQueryKHR = 4472,
+            UntypedPointersKHR = 4473,
             RayTraversalPrimitiveCullingKHR = 4478,
             RayTracingKHR = 4479,
             TextureSampleWeightedQCOM = 4484,
             TextureBoxFilterQCOM = 4485,
             TextureBlockMatchQCOM = 4486,
+            TextureBlockMatch2QCOM = 4498,
             Float16ImageAMD = 5008,
             ImageGatherBiasLodAMD = 5009,
             FragmentMaskAMD = 5010,
@@ -1102,6 +1148,7 @@ namespace Spv
             MeshShadingEXT = 5283,
             FragmentBarycentricKHR = 5284,
             FragmentBarycentricNV = 5284,
+            ComputeDerivativeGroupQuadsKHR = 5288,
             ComputeDerivativeGroupQuadsNV = 5288,
             FragmentDensityEXT = 5291,
             ShadingRateNV = 5291,
@@ -1139,6 +1186,7 @@ namespace Spv
             VulkanMemoryModelDeviceScopeKHR = 5346,
             PhysicalStorageBufferAddresses = 5347,
             PhysicalStorageBufferAddressesEXT = 5347,
+            ComputeDerivativeGroupLinearKHR = 5350,
             ComputeDerivativeGroupLinearNV = 5350,
             RayTracingProvisionalKHR = 5353,
             CooperativeMatrixNV = 5357,
@@ -1153,7 +1201,15 @@ namespace Spv
             ShaderInvocationReorderNV = 5383,
             BindlessTextureNV = 5390,
             RayQueryPositionFetchKHR = 5391,
+            AtomicFloat16VectorNV = 5404,
             RayTracingDisplacementMicromapNV = 5409,
+            RawAccessChainsNV = 5414,
+            CooperativeMatrixReductionsNV = 5430,
+            CooperativeMatrixConversionsNV = 5431,
+            CooperativeMatrixPerElementOperationsNV = 5432,
+            CooperativeMatrixTensorAddressingNV = 5433,
+            CooperativeMatrixBlockLoadsNV = 5434,
+            TensorAddressingNV = 5439,
             SubgroupShuffleINTEL = 5568,
             SubgroupBufferBlockIOINTEL = 5569,
             SubgroupImageBlockIOINTEL = 5570,
@@ -1206,17 +1262,20 @@ namespace Spv
             DotProductKHR = 6019,
             RayCullMaskKHR = 6020,
             CooperativeMatrixKHR = 6022,
+            ReplicatedCompositesEXT = 6024,
             BitInstructions = 6025,
             GroupNonUniformRotateKHR = 6026,
             FloatControls2 = 6029,
             AtomicFloat32AddEXT = 6033,
             AtomicFloat64AddEXT = 6034,
             LongCompositesINTEL = 6089,
+            OptNoneEXT = 6094,
             OptNoneINTEL = 6094,
             AtomicFloat16AddEXT = 6095,
             DebugInfoModuleINTEL = 6114,
             BFloat16ConversionINTEL = 6115,
             SplitBarrierINTEL = 6141,
+            ArithmeticFenceEXT = 6144,
             FPGAClusterAttributesV2INTEL = 6150,
             FPGAKernelAttributesv2INTEL = 6161,
             FPMaxErrorINTEL = 6169,
@@ -1224,9 +1283,12 @@ namespace Spv
             FPGAArgumentInterfacesINTEL = 6174,
             GlobalVariableHostAccessINTEL = 6187,
             GlobalVariableFPGADecorationsINTEL = 6189,
+            SubgroupBufferPrefetchINTEL = 6220,
             GroupUniformArithmeticKHR = 6400,
             MaskedGatherScatterINTEL = 6427,
             CacheControlsINTEL = 6441,
+            RegisterLimitsINTEL = 6460,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum RayFlagsShift
@@ -1242,6 +1304,7 @@ namespace Spv
             SkipTrianglesKHR = 8,
             SkipAABBsKHR = 9,
             ForceOpacityMicromap2StateEXT = 10,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum RayFlagsMask
@@ -1264,6 +1327,7 @@ namespace Spv
         {
             RayQueryCandidateIntersectionKHR = 0,
             RayQueryCommittedIntersectionKHR = 1,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum RayQueryCommittedIntersectionType
@@ -1271,12 +1335,14 @@ namespace Spv
             RayQueryCommittedIntersectionNoneKHR = 0,
             RayQueryCommittedIntersectionTriangleKHR = 1,
             RayQueryCommittedIntersectionGeneratedKHR = 2,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum RayQueryCandidateIntersectionType
         {
             RayQueryCandidateIntersectionTriangleKHR = 0,
             RayQueryCandidateIntersectionAABBKHR = 1,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum FragmentShadingRateShift
@@ -1285,6 +1351,7 @@ namespace Spv
             Vertical4Pixels = 1,
             Horizontal2Pixels = 2,
             Horizontal4Pixels = 3,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum FragmentShadingRateMask
@@ -1300,12 +1367,14 @@ namespace Spv
         {
             Preserve = 0,
             FlushToZero = 1,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum FPOperationMode
         {
             IEEE = 0,
             ALT = 1,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum QuantizationModes
@@ -1318,6 +1387,7 @@ namespace Spv
             RND_MIN_INF = 5,
             RND_CONV = 6,
             RND_CONV_ODD = 7,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum OverflowModes
@@ -1326,12 +1396,14 @@ namespace Spv
             SAT = 1,
             SAT_ZERO = 2,
             SAT_SYM = 3,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum PackedVectorFormat
         {
             PackedVectorFormat4x8Bit = 0,
             PackedVectorFormat4x8BitKHR = 0,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum CooperativeMatrixOperandsShift
@@ -1341,6 +1413,7 @@ namespace Spv
             MatrixCSignedComponentsKHR = 2,
             MatrixResultSignedComponentsKHR = 3,
             SaturatingAccumulationKHR = 4,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum CooperativeMatrixOperandsMask
@@ -1357,6 +1430,9 @@ namespace Spv
         {
             RowMajorKHR = 0,
             ColumnMajorKHR = 1,
+            RowBlockedInterleavedARM = 4202,
+            ColumnBlockedInterleavedARM = 4203,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum CooperativeMatrixUse
@@ -1364,12 +1440,54 @@ namespace Spv
             MatrixAKHR = 0,
             MatrixBKHR = 1,
             MatrixAccumulatorKHR = 2,
+            Max = 0x7fffffff,
+        }
+
+        [AllowDuplicates, CRepr] public enum CooperativeMatrixReduceShift
+        {
+            Row = 0,
+            Column = 1,
+            CooperativeMatrixReduce2x2 = 2,
+            Max = 0x7fffffff,
+        }
+
+        [AllowDuplicates, CRepr] public enum CooperativeMatrixReduceMask
+        {
+            MaskNone = 0,
+            Row = 0x00000001,
+            Column = 0x00000002,
+            CooperativeMatrixReduce2x2 = 0x00000004,
+        }
+
+        [AllowDuplicates, CRepr] public enum TensorClampMode
+        {
+            Undefined = 0,
+            Constant = 1,
+            ClampToEdge = 2,
+            Repeat = 3,
+            RepeatMirrored = 4,
+            Max = 0x7fffffff,
+        }
+
+        [AllowDuplicates, CRepr] public enum TensorAddressingOperandsShift
+        {
+            TensorView = 0,
+            DecodeFunc = 1,
+            Max = 0x7fffffff,
+        }
+
+        [AllowDuplicates, CRepr] public enum TensorAddressingOperandsMask
+        {
+            MaskNone = 0,
+            TensorView = 0x00000001,
+            DecodeFunc = 0x00000002,
         }
 
         [AllowDuplicates, CRepr] public enum InitializationModeQualifier
         {
             InitOnDeviceReprogramINTEL = 0,
             InitOnDeviceResetINTEL = 1,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum HostAccessQualifier
@@ -1378,6 +1496,7 @@ namespace Spv
             ReadINTEL = 1,
             WriteINTEL = 2,
             ReadWriteINTEL = 3,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum LoadCacheControl
@@ -1387,6 +1506,7 @@ namespace Spv
             StreamingINTEL = 2,
             InvalidateAfterReadINTEL = 3,
             ConstCachedINTEL = 4,
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum StoreCacheControl
@@ -1395,6 +1515,32 @@ namespace Spv
             WriteThroughINTEL = 1,
             WriteBackINTEL = 2,
             StreamingINTEL = 3,
+            Max = 0x7fffffff,
+        }
+
+        [AllowDuplicates, CRepr] public enum NamedMaximumNumberOfRegisters
+        {
+            AutoINTEL = 0,
+            Max = 0x7fffffff,
+        }
+
+        [AllowDuplicates, CRepr] public enum RawAccessChainOperandsShift
+        {
+            RobustnessPerComponentNV = 0,
+            RobustnessPerElementNV = 1,
+            Max = 0x7fffffff,
+        }
+
+        [AllowDuplicates, CRepr] public enum RawAccessChainOperandsMask
+        {
+            MaskNone = 0,
+            RobustnessPerComponentNV = 0x00000001,
+            RobustnessPerElementNV = 0x00000002,
+        }
+
+        [AllowDuplicates, CRepr] public enum FPEncoding
+        {
+            Max = 0x7fffffff,
         }
 
         [AllowDuplicates, CRepr] public enum Op
@@ -1747,13 +1893,22 @@ namespace Spv
             OpDepthAttachmentReadEXT = 4161,
             OpStencilAttachmentReadEXT = 4162,
             OpTerminateInvocation = 4416,
+            OpTypeUntypedPointerKHR = 4417,
+            OpUntypedVariableKHR = 4418,
+            OpUntypedAccessChainKHR = 4419,
+            OpUntypedInBoundsAccessChainKHR = 4420,
             OpSubgroupBallotKHR = 4421,
             OpSubgroupFirstInvocationKHR = 4422,
+            OpUntypedPtrAccessChainKHR = 4423,
+            OpUntypedInBoundsPtrAccessChainKHR = 4424,
+            OpUntypedArrayLengthKHR = 4425,
+            OpUntypedPrefetchKHR = 4426,
             OpSubgroupAllKHR = 4428,
             OpSubgroupAnyKHR = 4429,
             OpSubgroupAllEqualKHR = 4430,
             OpGroupNonUniformRotateKHR = 4431,
             OpSubgroupReadInvocationKHR = 4432,
+            OpExtInstWithForwardRefsKHR = 4433,
             OpTraceRayKHR = 4445,
             OpExecuteCallableKHR = 4446,
             OpConvertUToAccelerationStructureKHR = 4447,
@@ -1776,6 +1931,9 @@ namespace Spv
             OpCooperativeMatrixStoreKHR = 4458,
             OpCooperativeMatrixMulAddKHR = 4459,
             OpCooperativeMatrixLengthKHR = 4460,
+            OpConstantCompositeReplicateEXT = 4461,
+            OpSpecConstantCompositeReplicateEXT = 4462,
+            OpCompositeConstructReplicateEXT = 4463,
             OpTypeRayQueryKHR = 4472,
             OpRayQueryInitializeKHR = 4473,
             OpRayQueryTerminateKHR = 4474,
@@ -1787,6 +1945,10 @@ namespace Spv
             OpImageBoxFilterQCOM = 4481,
             OpImageBlockMatchSSDQCOM = 4482,
             OpImageBlockMatchSADQCOM = 4483,
+            OpImageBlockMatchWindowSSDQCOM = 4500,
+            OpImageBlockMatchWindowSADQCOM = 4501,
+            OpImageBlockMatchGatherSSDQCOM = 4502,
+            OpImageBlockMatchGatherSADQCOM = 4503,
             OpGroupIAddNonUniformAMD = 5000,
             OpGroupFAddNonUniformAMD = 5001,
             OpGroupFMinNonUniformAMD = 5002,
@@ -1798,9 +1960,14 @@ namespace Spv
             OpFragmentMaskFetchAMD = 5011,
             OpFragmentFetchAMD = 5012,
             OpReadClockKHR = 5056,
-            OpFinalizeNodePayloadsAMDX = 5075,
+            OpAllocateNodePayloadsAMDX = 5074,
+            OpEnqueueNodePayloadsAMDX = 5075,
+            OpTypeNodePayloadArrayAMDX = 5076,
             OpFinishWritingNodePayloadAMDX = 5078,
-            OpInitializeNodePayloadsAMDX = 5090,
+            OpNodePayloadArrayLengthAMDX = 5090,
+            OpIsNodePayloadValidAMDX = 5101,
+            OpConstantStringAMDX = 5103,
+            OpSpecConstantStringAMDX = 5104,
             OpGroupNonUniformQuadAllKHR = 5110,
             OpGroupNonUniformQuadAnyKHR = 5111,
             OpHitObjectRecordHitMotionNV = 5249,
@@ -1837,6 +2004,7 @@ namespace Spv
             OpReorderThreadWithHintNV = 5280,
             OpTypeHitObjectNV = 5281,
             OpImageSampleFootprintNV = 5283,
+            OpCooperativeMatrixConvertNV = 5293,
             OpEmitMeshTasksEXT = 5294,
             OpSetMeshOutputsEXT = 5295,
             OpGroupNonUniformPartitionNV = 5296,
@@ -1861,9 +2029,26 @@ namespace Spv
             OpCooperativeMatrixLengthNV = 5362,
             OpBeginInvocationInterlockEXT = 5364,
             OpEndInvocationInterlockEXT = 5365,
+            OpCooperativeMatrixReduceNV = 5366,
+            OpCooperativeMatrixLoadTensorNV = 5367,
+            OpCooperativeMatrixStoreTensorNV = 5368,
+            OpCooperativeMatrixPerElementOpNV = 5369,
+            OpTypeTensorLayoutNV = 5370,
+            OpTypeTensorViewNV = 5371,
+            OpCreateTensorLayoutNV = 5372,
+            OpTensorLayoutSetDimensionNV = 5373,
+            OpTensorLayoutSetStrideNV = 5374,
+            OpTensorLayoutSliceNV = 5375,
+            OpTensorLayoutSetClampValueNV = 5376,
+            OpCreateTensorViewNV = 5377,
+            OpTensorViewSetDimensionNV = 5378,
+            OpTensorViewSetStrideNV = 5379,
             OpDemoteToHelperInvocation = 5380,
             OpDemoteToHelperInvocationEXT = 5380,
             OpIsHelperInvocationEXT = 5381,
+            OpTensorViewSetClipNV = 5382,
+            OpTensorLayoutSetBlockSizeNV = 5384,
+            OpCooperativeMatrixTransposeNV = 5390,
             OpConvertUToImageNV = 5391,
             OpConvertUToSamplerNV = 5392,
             OpConvertImageToUNV = 5393,
@@ -1871,6 +2056,7 @@ namespace Spv
             OpConvertUToSampledImageNV = 5395,
             OpConvertSampledImageToUNV = 5396,
             OpSamplerImageAddressingModeNV = 5397,
+            OpRawAccessChainNV = 5398,
             OpSubgroupShuffleINTEL = 5571,
             OpSubgroupShuffleDownINTEL = 5572,
             OpSubgroupShuffleUpINTEL = 5573,
@@ -2117,6 +2303,8 @@ namespace Spv
             OpConvertBF16ToFINTEL = 6117,
             OpControlBarrierArriveINTEL = 6142,
             OpControlBarrierWaitINTEL = 6143,
+            OpArithmeticFenceEXT = 6145,
+            OpSubgroupBlockPrefetchINTEL = 6221,
             OpGroupIMulKHR = 6401,
             OpGroupFMulKHR = 6402,
             OpGroupBitwiseAndKHR = 6403,
@@ -2127,6 +2315,7 @@ namespace Spv
             OpGroupLogicalXorKHR = 6408,
             OpMaskedGatherINTEL = 6428,
             OpMaskedScatterINTEL = 6429,
+            Max = 0x7fffffff,
         }
     }
 }
diff --git a/include/spirv/unified1/spirv.core.grammar.json b/include/spirv/unified1/spirv.core.grammar.json
index a57d351..dde0114 100644
--- a/include/spirv/unified1/spirv.core.grammar.json
+++ b/include/spirv/unified1/spirv.core.grammar.json
@@ -27,7 +27,7 @@
   "magic_number" : "0x07230203",
   "major_version" : 1,
   "minor_version" : 6,
-  "revision" : 1,
+  "revision" : 4,
   "instruction_printing_class" : [
     {
       "tag"     : "@exclude"
@@ -330,7 +330,8 @@
       "opcode" : 22,
       "operands" : [
         { "kind" : "IdResult" },
-        { "kind" : "LiteralInteger", "name" : "'Width'" }
+        { "kind" : "LiteralInteger", "name" : "'Width'" },
+        { "kind" : "FPEncoding", "quantifier" : "?", "name" : "'Floating Point Encoding'" }
       ],
       "version": "1.0"
     },
@@ -753,7 +754,10 @@
         { "kind" : "MemoryAccess", "quantifier" : "?" },
         { "kind" : "MemoryAccess", "quantifier" : "?" }
       ],
-      "capabilities" : [ "Addresses" ],
+      "capabilities" : [
+        "Addresses",
+        "UntypedPointersKHR"
+      ],
       "version": "1.0"
     },
     {
@@ -4439,6 +4443,65 @@
       "capabilities" : [ "Shader" ],
       "version" : "1.6"
     },
+    {
+      "opname" : "OpTypeUntypedPointerKHR",
+      "class" : "Type-Declaration",
+      "opcode" : 4417,
+      "capabilities" : [
+        "UntypedPointersKHR"
+      ],
+      "provisional" : true,
+      "version" : "None",
+      "operands" : [
+        { "kind" : "IdResult" },
+        { "kind" : "StorageClass" }
+      ]
+    },
+    {
+      "opname" : "OpUntypedVariableKHR",
+      "class" : "Memory",
+      "opcode" : 4418,
+      "capabilities" : [ "UntypedPointersKHR" ],
+      "provisional" : true,
+      "version" : "None",
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "StorageClass" },
+        { "kind" : "IdRef", "quantifier" : "?",  "name" : "'Data Type'" },
+        { "kind" : "IdRef", "quantifier" : "?", "name" : "'Initializer'" }
+      ]
+    },
+    {
+      "opname" : "OpUntypedAccessChainKHR",
+      "class" : "Memory",
+      "opcode" : 4419,
+      "capabilities" : [ "UntypedPointersKHR" ],
+      "provisional" : true,
+      "version" : "None",
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                            "name" : "'Base Type'" },
+        { "kind" : "IdRef",                            "name" : "'Base'" },
+        { "kind" : "IdRef",        "quantifier" : "*", "name" : "'Indexes'" }
+      ]
+    },
+    {
+      "opname" : "OpUntypedInBoundsAccessChainKHR",
+      "class" : "Memory",
+      "opcode" : 4420,
+      "capabilities" : [ "UntypedPointersKHR" ],
+      "provisional" : true,
+      "version" : "None",
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                            "name" : "'Base Type'" },
+        { "kind" : "IdRef",                            "name" : "'Base'" },
+        { "kind" : "IdRef",        "quantifier" : "*", "name" : "'Indexes'" }
+      ]
+    },
     {
       "opname" : "OpSubgroupBallotKHR",
       "class"  : "Group",
@@ -4465,6 +4528,68 @@
       "extensions" : [ "SPV_KHR_shader_ballot" ],
       "version" : "None"
     },
+    {
+      "opname" : "OpUntypedPtrAccessChainKHR",
+      "class"  : "Memory",
+      "opcode" : 4423,
+      "capabilities" : [ "UntypedPointersKHR" ],
+      "provisional" : true,
+      "version" : "None",
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                            "name" : "'Base Type'" },
+        { "kind" : "IdRef",                            "name" : "'Base'" },
+        { "kind" : "IdRef",                            "name" : "'Element'" },
+        { "kind" : "IdRef",        "quantifier" : "*", "name" : "'Indexes'" }
+      ]
+    },
+    {
+      "opname" : "OpUntypedInBoundsPtrAccessChainKHR",
+      "class"  : "Memory",
+      "opcode" : 4424,
+      "capabilities" : [ "UntypedPointersKHR" ],
+      "provisional" : true,
+      "version" : "None",
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                            "name" : "'Base Type'" },
+        { "kind" : "IdRef",                            "name" : "'Base'" },
+        { "kind" : "IdRef",                            "name" : "'Element'" },
+        { "kind" : "IdRef",        "quantifier" : "*", "name" : "'Indexes'" }
+      ]
+    },
+    {
+      "opname" : "OpUntypedArrayLengthKHR",
+      "class"  : "Memory",
+      "opcode" : 4425,
+      "capabilities" : [ "UntypedPointersKHR" ],
+      "provisional" : true,
+      "version" : "None",
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                            "name" : "'Structure'" },
+        { "kind" : "IdRef",                            "name" : "'Pointer'" },
+        { "kind" : "LiteralInteger",                   "name" : "'Array member'" }
+      ]
+    },
+    {
+      "opname" : "OpUntypedPrefetchKHR",
+      "class"  : "Memory",
+      "opcode" : 4426,
+      "capabilities" : [ "UntypedPointersKHR" ],
+      "provisional" : true,
+      "version" : "None",
+      "operands" : [
+        { "kind" : "IdRef",                            "name" : "'Pointer Type'" },
+        { "kind" : "IdRef",                            "name" : "'Num Bytes'" },
+        { "kind" : "IdRef",        "quantifier" : "?", "name" : "'RW'" },
+        { "kind" : "IdRef",        "quantifier" : "?", "name" : "'Locality'" },
+        { "kind" : "IdRef",        "quantifier" : "?", "name" : "'Cache Type'" }
+      ]
+    },
     {
       "opname" : "OpSubgroupAllKHR",
       "class"  : "Group",
@@ -4539,6 +4664,20 @@
       "extensions" : [ "SPV_KHR_shader_ballot" ],
       "version" : "None"
     },
+    {
+      "opname" : "OpExtInstWithForwardRefsKHR",
+      "class"  : "Extension",
+      "opcode" : 4433,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                                     "name" : "'Set'" },
+        { "kind" : "LiteralExtInstInteger",                     "name" : "'Instruction'" },
+        { "kind" : "IdRef",                 "quantifier" : "*", "name" : "'Operand 1', +\n'Operand 2', +\n..." }
+      ],
+      "extensions" : [ "SPV_KHR_relaxed_extended_instruction" ],
+      "version": "None"
+    },
     {
       "opname" : "OpTraceRayKHR",
       "class"  : "Reserved",
@@ -4606,6 +4745,7 @@
     {
       "opname" : "OpSDot",
       "class"  : "Arithmetic",
+      "aliases" : ["OpSDotKHR"],
       "opcode" : 4450,
       "operands" : [
         { "kind" : "IdResultType" },
@@ -4615,26 +4755,13 @@
         { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
       ],
       "capabilities" : [ "DotProduct" ],
-      "version" : "1.6"
-    },
-    {
-      "opname" : "OpSDotKHR",
-      "class"  : "Arithmetic",
-      "opcode" : 4450,
-      "operands" : [
-        { "kind" : "IdResultType" },
-        { "kind" : "IdResult" },
-        { "kind" : "IdRef", "name" : "'Vector 1'" },
-        { "kind" : "IdRef", "name" : "'Vector 2'" },
-        { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
-      ],
-      "capabilities" : [ "DotProductKHR" ],
       "extensions" : [ "SPV_KHR_integer_dot_product" ],
       "version" : "1.6"
     },
     {
       "opname" : "OpUDot",
       "class"  : "Arithmetic",
+      "aliases" : ["OpUDotKHR"],
       "opcode" : 4451,
       "operands" : [
         { "kind" : "IdResultType" },
@@ -4644,26 +4771,13 @@
         { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
       ],
       "capabilities" : [ "DotProduct" ],
-      "version" : "1.6"
-    },
-    {
-      "opname" : "OpUDotKHR",
-      "class"  : "Arithmetic",
-      "opcode" : 4451,
-      "operands" : [
-        { "kind" : "IdResultType" },
-        { "kind" : "IdResult" },
-        { "kind" : "IdRef", "name" : "'Vector 1'" },
-        { "kind" : "IdRef", "name" : "'Vector 2'" },
-        { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
-      ],
-      "capabilities" : [ "DotProductKHR" ],
       "extensions" : [ "SPV_KHR_integer_dot_product" ],
       "version" : "1.6"
     },
     {
       "opname" : "OpSUDot",
       "class"  : "Arithmetic",
+      "aliases" : ["OpSUDotKHR"],
       "opcode" : 4452,
       "operands" : [
         { "kind" : "IdResultType" },
@@ -4673,26 +4787,13 @@
         { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
       ],
       "capabilities" : [ "DotProduct" ],
-      "version" : "1.6"
-    },
-    {
-      "opname" : "OpSUDotKHR",
-      "class"  : "Arithmetic",
-      "opcode" : 4452,
-      "operands" : [
-        { "kind" : "IdResultType" },
-        { "kind" : "IdResult" },
-        { "kind" : "IdRef", "name" : "'Vector 1'" },
-        { "kind" : "IdRef", "name" : "'Vector 2'" },
-        { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
-      ],
-      "capabilities" : [ "DotProductKHR" ],
       "extensions" : [ "SPV_KHR_integer_dot_product" ],
       "version" : "1.6"
     },
     {
       "opname" : "OpSDotAccSat",
       "class"  : "Arithmetic",
+      "aliases" : ["OpSDotAccSatKHR"],
       "opcode" : 4453,
       "operands" : [
         { "kind" : "IdResultType" },
@@ -4703,27 +4804,13 @@
         { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
       ],
       "capabilities" : [ "DotProduct" ],
-      "version" : "1.6"
-    },
-    {
-      "opname" : "OpSDotAccSatKHR",
-      "class"  : "Arithmetic",
-      "opcode" : 4453,
-      "operands" : [
-        { "kind" : "IdResultType" },
-        { "kind" : "IdResult" },
-        { "kind" : "IdRef", "name" : "'Vector 1'" },
-        { "kind" : "IdRef", "name" : "'Vector 2'" },
-        { "kind" : "IdRef", "name" : "'Accumulator'" },
-        { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
-      ],
-      "capabilities" : [ "DotProductKHR" ],
       "extensions" : [ "SPV_KHR_integer_dot_product" ],
       "version" : "1.6"
     },
     {
       "opname" : "OpUDotAccSat",
       "class"  : "Arithmetic",
+      "aliases" : ["OpUDotAccSatKHR"],
       "opcode" : 4454,
       "operands" : [
         { "kind" : "IdResultType" },
@@ -4734,27 +4821,13 @@
         { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
       ],
       "capabilities" : [ "DotProduct" ],
-      "version" : "1.6"
-    },
-    {
-      "opname" : "OpUDotAccSatKHR",
-      "class"  : "Arithmetic",
-      "opcode" : 4454,
-      "operands" : [
-        { "kind" : "IdResultType" },
-        { "kind" : "IdResult" },
-        { "kind" : "IdRef", "name" : "'Vector 1'" },
-        { "kind" : "IdRef", "name" : "'Vector 2'" },
-        { "kind" : "IdRef", "name" : "'Accumulator'" },
-        { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
-      ],
-      "capabilities" : [ "DotProductKHR" ],
       "extensions" : [ "SPV_KHR_integer_dot_product" ],
       "version" : "1.6"
     },
     {
       "opname" : "OpSUDotAccSat",
       "class"  : "Arithmetic",
+      "aliases" : ["OpSUDotAccSatKHR"],
       "opcode" : 4455,
       "operands" : [
         { "kind" : "IdResultType" },
@@ -4765,21 +4838,6 @@
         { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
       ],
       "capabilities" : [ "DotProduct" ],
-      "version" : "1.6"
-    },
-    {
-      "opname" : "OpSUDotAccSatKHR",
-      "class"  : "Arithmetic",
-      "opcode" : 4455,
-      "operands" : [
-        { "kind" : "IdResultType" },
-        { "kind" : "IdResult" },
-        { "kind" : "IdRef", "name" : "'Vector 1'" },
-        { "kind" : "IdRef", "name" : "'Vector 2'" },
-        { "kind" : "IdRef", "name" : "'Accumulator'" },
-        { "kind" : "PackedVectorFormat", "name" : "'Packed Vector Format'", "quantifier" : "?" }
-      ],
-      "capabilities" : [ "DotProductKHR" ],
       "extensions" : [ "SPV_KHR_integer_dot_product" ],
       "version" : "1.6"
     },
@@ -4854,6 +4912,42 @@
       "capabilities" : [ "CooperativeMatrixKHR" ],
       "version" : "None"
     },
+    {
+      "opname" : "OpConstantCompositeReplicateEXT",
+      "class"  : "Constant-Creation",
+      "opcode" : 4461,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",        "name" : "'Value'" }
+      ],
+      "capabilities" : [ "ReplicatedCompositesEXT" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpSpecConstantCompositeReplicateEXT",
+      "class"  : "Constant-Creation",
+      "opcode" : 4462,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",        "name" : "'Value'" }
+      ],
+      "capabilities" : [ "ReplicatedCompositesEXT" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpCompositeConstructReplicateEXT",
+      "class"  : "Composite",
+      "opcode" : 4463,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",        "name" : "'Value'" }
+      ],
+      "capabilities" : [ "ReplicatedCompositesEXT" ],
+      "version" : "None"
+    },
     {
         "opname" : "OpTypeRayQueryKHR",
         "class" : "Type-Declaration",
@@ -5050,6 +5144,70 @@
       "capabilities" : [ "TextureBlockMatchQCOM" ],
       "version" : "None"
     },
+    {
+      "opname" : "OpImageBlockMatchWindowSSDQCOM",
+      "class"  : "Image",
+      "opcode" : 4500,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name" : "'Target Sampled Image'" },
+        { "kind" : "IdRef", "name" : "'Target Coordinates'" },
+        { "kind" : "IdRef", "name" : "'Reference Sampled Image'" },
+        { "kind" : "IdRef", "name" : "'Reference Coordinates'" },
+        { "kind" : "IdRef", "name" : "'Block Size'" }
+      ],
+      "capabilities" : [ "TextureBlockMatch2QCOM" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpImageBlockMatchWindowSADQCOM",
+      "class"  : "Image",
+      "opcode" : 4501,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name" : "'Target Sampled Image'" },
+        { "kind" : "IdRef", "name" : "'Target Coordinates'" },
+        { "kind" : "IdRef", "name" : "'Reference Sampled Image'" },
+        { "kind" : "IdRef", "name" : "'Reference Coordinates'" },
+        { "kind" : "IdRef", "name" : "'Block Size'" }
+      ],
+      "capabilities" : [ "TextureBlockMatch2QCOM" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpImageBlockMatchGatherSSDQCOM",
+      "class"  : "Image",
+      "opcode" : 4502,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name" : "'Target Sampled Image'" },
+        { "kind" : "IdRef", "name" : "'Target Coordinates'" },
+        { "kind" : "IdRef", "name" : "'Reference Sampled Image'" },
+        { "kind" : "IdRef", "name" : "'Reference Coordinates'" },
+        { "kind" : "IdRef", "name" : "'Block Size'" }
+      ],
+      "capabilities" : [ "TextureBlockMatch2QCOM" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpImageBlockMatchGatherSADQCOM",
+      "class"  : "Image",
+      "opcode" : 4503,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name" : "'Target Sampled Image'" },
+        { "kind" : "IdRef", "name" : "'Target Coordinates'" },
+        { "kind" : "IdRef", "name" : "'Reference Sampled Image'" },
+        { "kind" : "IdRef", "name" : "'Reference Coordinates'" },
+        { "kind" : "IdRef", "name" : "'Block Size'" }
+      ],
+      "capabilities" : [ "TextureBlockMatch2QCOM" ],
+      "version" : "None"
+    },
     {
       "opname" : "OpGroupIAddNonUniformAMD",
       "class"  : "Group",
@@ -5212,13 +5370,41 @@
       "version" : "None"
     },
     {
-      "opname" : "OpFinalizeNodePayloadsAMDX",
+      "opname" : "OpAllocateNodePayloadsAMDX",
+      "class"  : "Reserved",
+      "opcode" : 5074,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdScope", "name" : "'Visibility'" },
+        { "kind" : "IdRef", "name": "'Payload Count'" },
+        { "kind" : "IdRef", "name": "'Node Index'" }
+      ],
+      "capabilities" : [ "ShaderEnqueueAMDX" ],
+      "provisional" : true,
+      "version" : "None"
+    },
+    {
+      "opname" : "OpEnqueueNodePayloadsAMDX",
       "class"  : "Reserved",
       "opcode" : 5075,
       "operands" : [
         { "kind" : "IdRef", "name": "'Payload Array'" }
       ],
       "capabilities" : [ "ShaderEnqueueAMDX" ],
+      "provisional" : true,
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTypeNodePayloadArrayAMDX",
+      "class"  : "Reserved",
+      "opcode" : 5076,
+      "operands" : [
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name": "'Payload Type'" }
+      ],
+      "capabilities" : [ "ShaderEnqueueAMDX" ],
+      "provisional" : true,
       "version" : "None"
     },
     {
@@ -5231,31 +5417,70 @@
         { "kind" : "IdRef", "name": "'Payload'" }
       ],
       "capabilities" : [ "ShaderEnqueueAMDX" ],
+      "provisional" : true,
       "version" : "None"
     },
     {
-      "opname" : "OpInitializeNodePayloadsAMDX",
+      "opname" : "OpNodePayloadArrayLengthAMDX",
       "class"  : "Reserved",
       "opcode" : 5090,
       "operands" : [
-        { "kind" : "IdRef", "name": "'Payload Array'" },
-        { "kind" : "IdScope", "name": "'Visibility'" },
-        { "kind" : "IdRef", "name": "'Payload Count'" },
-        { "kind" : "IdRef", "name": "'Node Index'" }
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name": "'Payload Array'" }
       ],
       "capabilities" : [ "ShaderEnqueueAMDX" ],
+      "provisional" : true,
       "version" : "None"
     },
     {
-      "opname" : "OpGroupNonUniformQuadAllKHR",
-      "class"  : "Non-Uniform",
-      "opcode" : 5110,
+      "opname" : "OpIsNodePayloadValidAMDX",
+      "class"  : "Reserved",
+      "opcode" : 5101,
       "operands" : [
         { "kind" : "IdResultType" },
         { "kind" : "IdResult" },
-        { "kind" : "IdRef", "name" : "'Predicate'" }
+        { "kind" : "IdRef", "name": "'Payload Type'" },
+        { "kind" : "IdRef", "name": "'Node Index'" }
       ],
-      "capabilities" : [ "QuadControlKHR" ],
+      "capabilities" : [ "ShaderEnqueueAMDX" ],
+      "provisional" : true,
+      "version": "None"
+    },
+    {
+      "opname" : "OpConstantStringAMDX",
+      "class"  : "Reserved",
+      "opcode" : 5103,
+      "operands" : [
+        { "kind" : "IdResult" },
+        { "kind" : "LiteralString", "name": "'Literal String'" }
+      ],
+      "capabilities" : [ "ShaderEnqueueAMDX" ],
+      "provisional" : true,
+      "version": "None"
+    },
+    {
+      "opname" : "OpSpecConstantStringAMDX",
+      "class"  : "Reserved",
+      "opcode" : 5104,
+      "operands" : [
+        { "kind" : "IdResult" },
+        { "kind" : "LiteralString", "name": "'Literal String'" }
+      ],
+      "capabilities" : [ "ShaderEnqueueAMDX" ],
+      "provisional" : true,
+      "version": "None"
+    },
+    {
+      "opname" : "OpGroupNonUniformQuadAllKHR",
+      "class"  : "Non-Uniform",
+      "opcode" : 5110,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name" : "'Predicate'" }
+      ],
+      "capabilities" : [ "QuadControlKHR" ],
       "version" : "None"
     },
     {
@@ -5742,6 +5967,18 @@
       "extensions" : [ "SPV_NV_shader_image_footprint" ],
       "version" : "None"
     },
+    {
+      "opname" : "OpCooperativeMatrixConvertNV",
+      "class"  : "Conversion",
+      "opcode" : 5293,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",             "name" : "'Matrix'" }
+      ],
+      "capabilities" : [ "CooperativeMatrixConversionsNV" ],
+      "version" : "None"
+    },
     {
       "opname" : "OpEmitMeshTasksEXT",
       "class"  : "Reserved",
@@ -5823,23 +6060,10 @@
       "capabilities" : [ "DisplacementMicromapNV" ],
       "version" : "None"
     },
-    {
-      "opname" : "OpReportIntersectionNV",
-      "class"  : "Reserved",
-      "opcode" : 5334,
-      "operands" : [
-        { "kind" : "IdResultType" },
-        { "kind" : "IdResult" },
-        { "kind" : "IdRef", "name" : "'Hit'" },
-        { "kind" : "IdRef", "name" : "'HitKind'" }
-      ],
-      "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-      "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-      "version" : "None"
-    },
     {
       "opname" : "OpReportIntersectionKHR",
       "class"  : "Reserved",
+      "aliases" : ["OpReportIntersectionNV"],
       "opcode" : 5334,
       "operands" : [
         { "kind" : "IdResultType" },
@@ -5954,20 +6178,10 @@
       "capabilities" : [ "RayQueryPositionFetchKHR" ],
       "version" : "None"
     },
-    {
-      "opname" : "OpTypeAccelerationStructureNV",
-      "class"  : "Type-Declaration",
-      "opcode" : 5341,
-      "operands" : [
-        { "kind" : "IdResult" }
-      ],
-      "capabilities" : [ "RayTracingNV" , "RayTracingKHR", "RayQueryKHR" ],
-      "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing", "SPV_KHR_ray_query" ],
-      "version" : "None"
-    },
     {
       "opname" : "OpTypeAccelerationStructureKHR",
       "class"  : "Type-Declaration",
+      "aliases" : ["OpTypeAccelerationStructureNV"],
       "opcode" : 5341,
       "operands" : [
         { "kind" : "IdResult" }
@@ -6080,17 +6294,200 @@
       "version" : "None"
     },
     {
-      "opname" : "OpDemoteToHelperInvocation",
-      "class"  : "Control-Flow",
-      "opcode" : 5380,
-      "capabilities" : [ "DemoteToHelperInvocation" ],
-      "version" : "1.6"
+      "opname" : "OpCooperativeMatrixReduceNV",
+      "class"  : "Arithmetic",
+      "opcode" : 5366,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name" : "'Matrix'" },
+        { "kind" : "CooperativeMatrixReduce",      "name" : "'Reduce'" },
+        { "kind" : "IdRef", "name" : "'CombineFunc'" }
+      ],
+      "capabilities" : [ "CooperativeMatrixReductionsNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpCooperativeMatrixLoadTensorNV",
+      "class"  : "Memory",
+      "opcode" : 5367,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",             "name" : "'Pointer'" },
+        { "kind" : "IdRef",             "name" : "'Object'" },
+        { "kind" : "IdRef",             "name" : "'TensorLayout'" },
+        { "kind" : "MemoryAccess",      "name" : "'Memory Operand'"},
+        { "kind" : "TensorAddressingOperands", "name" : "'Tensor Addressing Operands'"}
+      ],
+      "capabilities" : [ "CooperativeMatrixTensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpCooperativeMatrixStoreTensorNV",
+      "class"  : "Memory",
+      "opcode" : 5368,
+      "operands" : [
+        { "kind" : "IdRef",             "name" : "'Pointer'" },
+        { "kind" : "IdRef",             "name" : "'Object'" },
+        { "kind" : "IdRef",             "name" : "'TensorLayout'" },
+        { "kind" : "MemoryAccess",      "name" : "'Memory Operand'"},
+        { "kind" : "TensorAddressingOperands", "name" : "'Tensor Addressing Operands'"}
+      ],
+      "capabilities" : [ "CooperativeMatrixTensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpCooperativeMatrixPerElementOpNV",
+      "class"  : "Function",
+      "opcode" : 5369,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name" : "'Matrix'" },
+        { "kind" : "IdRef", "name" : "'Func'" },
+        { "kind" : "IdRef",        "quantifier" : "*", "name" : "'Operands'" }
+      ],
+      "capabilities" : [ "CooperativeMatrixPerElementOperationsNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTypeTensorLayoutNV",
+      "class"  : "Type-Declaration",
+      "opcode" : 5370,
+      "operands" : [
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",             "name" : "'Dim'" },
+        { "kind" : "IdRef",             "name" : "'ClampMode'" }
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTypeTensorViewNV",
+      "class"  : "Type-Declaration",
+      "opcode" : 5371,
+      "operands" : [
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",             "name" : "'Dim'" },
+        { "kind" : "IdRef",             "name" : "'HasDimensions'" },
+        { "kind" : "IdRef", "quantifier" : "*", "name" : "'p'" }
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpCreateTensorLayoutNV",
+      "class"  : "Reserved",
+      "opcode" : 5372,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" }
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTensorLayoutSetDimensionNV",
+      "class"  : "Reserved",
+      "opcode" : 5373,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                     "name" : "'TensorLayout'" },
+        { "kind" : "IdRef", "quantifier" : "*", "name" : "'Dim'" }
+
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
     },
     {
-      "opname" : "OpDemoteToHelperInvocationEXT",
+      "opname" : "OpTensorLayoutSetStrideNV",
+      "class"  : "Reserved",
+      "opcode" : 5374,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                     "name" : "'TensorLayout'" },
+        { "kind" : "IdRef", "quantifier" : "*", "name" : "'Stride'" }
+
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTensorLayoutSliceNV",
+      "class"  : "Reserved",
+      "opcode" : 5375,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                     "name" : "'TensorLayout'" },
+        { "kind" : "IdRef", "quantifier" : "*", "name" : "'Operands'" }
+
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTensorLayoutSetClampValueNV",
+      "class"  : "Reserved",
+      "opcode" : 5376,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                     "name" : "'TensorLayout'" },
+        { "kind" : "IdRef",                     "name" : "'Value'" }
+
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpCreateTensorViewNV",
+      "class"  : "Reserved",
+      "opcode" : 5377,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" }
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTensorViewSetDimensionNV",
+      "class"  : "Reserved",
+      "opcode" : 5378,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                     "name" : "'TensorView'" },
+        { "kind" : "IdRef", "quantifier" : "*", "name" : "'Dim'" }
+
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTensorViewSetStrideNV",
+      "class"  : "Reserved",
+      "opcode" : 5379,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                     "name" : "'TensorView'" },
+        { "kind" : "IdRef", "quantifier" : "*", "name" : "'Stride'" }
+
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpDemoteToHelperInvocation",
       "class"  : "Control-Flow",
+      "aliases" : ["OpDemoteToHelperInvocationEXT"],
       "opcode" : 5380,
-      "capabilities" : [ "DemoteToHelperInvocationEXT" ],
+      "capabilities" : [ "DemoteToHelperInvocation" ],
       "version" : "1.6"
     },
     {
@@ -6101,10 +6498,52 @@
         { "kind" : "IdResultType" },
         { "kind" : "IdResult" }
       ],
-      "capabilities" : [ "DemoteToHelperInvocationEXT" ],
+      "capabilities" : [ "DemoteToHelperInvocation" ],
       "extensions" : [ "SPV_EXT_demote_to_helper_invocation" ],
       "version" : "None"
     },
+    {
+      "opname" : "OpTensorViewSetClipNV",
+      "class"  : "Reserved",
+      "opcode" : 5382,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                     "name" : "'TensorView'" },
+        { "kind" : "IdRef",                     "name" : "'ClipRowOffset'" },
+        { "kind" : "IdRef",                     "name" : "'ClipRowSpan'" },
+        { "kind" : "IdRef",                     "name" : "'ClipColOffset'" },
+        { "kind" : "IdRef",                     "name" : "'ClipColSpan'" }
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpTensorLayoutSetBlockSizeNV",
+      "class"  : "Reserved",
+      "opcode" : 5384,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",                     "name" : "'TensorLayout'" },
+        { "kind" : "IdRef", "quantifier" : "*", "name" : "'BlockSize'" }
+
+      ],
+      "capabilities" : [ "TensorAddressingNV" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpCooperativeMatrixTransposeNV",
+      "class"  : "Conversion",
+      "opcode" : 5390,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef", "name" : "'Matrix'" }
+      ],
+      "capabilities" : [ "CooperativeMatrixConversionsNV" ],
+      "version" : "None"
+    },
     {
       "opname" : "OpConvertUToImageNV",
       "class"  : "Reserved",
@@ -6187,6 +6626,24 @@
       "capabilities" : [ "BindlessTextureNV" ],
       "version" : "None"
     },
+    {
+      "opname" : "OpRawAccessChainNV",
+      "class"  : "Memory",
+      "opcode" : 5398,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",          "name" : "'Base'" },
+        { "kind" : "IdRef",          "name" : "'Byte stride'" },
+        { "kind" : "IdRef",          "name" : "'Element index'" },
+        { "kind" : "IdRef",          "name" : "'Byte offset'" },
+        { "kind" : "RawAccessChainOperands", "quantifier" : "?" }
+      ],
+      "capabilities" : [
+        "RawAccessChainsNV"
+      ],
+      "version" : "None"
+    },
     {
       "opname" : "OpSubgroupShuffleINTEL",
       "class"  : "Group",
@@ -6576,7 +7033,7 @@
         { "kind" : "IdMemorySemantics", "name" : "'Semantics'" },
         { "kind" : "IdRef",             "name" : "'Value'" }
       ],
-      "capabilities" : [ "AtomicFloat16MinMaxEXT", "AtomicFloat32MinMaxEXT", "AtomicFloat64MinMaxEXT" ],
+      "capabilities" : [ "AtomicFloat16MinMaxEXT", "AtomicFloat32MinMaxEXT", "AtomicFloat64MinMaxEXT", "AtomicFloat16VectorNV" ],
       "version" : "None"
     },
     {
@@ -6591,7 +7048,7 @@
         { "kind" : "IdMemorySemantics", "name" : "'Semantics'" },
         { "kind" : "IdRef",             "name" : "'Value'" }
       ],
-      "capabilities" : [ "AtomicFloat16MinMaxEXT", "AtomicFloat32MinMaxEXT", "AtomicFloat64MinMaxEXT" ],
+      "capabilities" : [ "AtomicFloat16MinMaxEXT", "AtomicFloat32MinMaxEXT", "AtomicFloat64MinMaxEXT", "AtomicFloat16VectorNV" ],
       "version" : "None"
     },
     {
@@ -6622,17 +7079,7 @@
     {
       "opname" : "OpDecorateString",
       "class"  : "Annotation",
-      "opcode" : 5632,
-      "operands" : [
-        { "kind" : "IdRef",         "name" : "'Target'" },
-        { "kind" : "Decoration" }
-      ],
-      "extensions" : [ "SPV_GOOGLE_decorate_string", "SPV_GOOGLE_hlsl_functionality1" ],
-      "version" : "1.4"
-    },
-    {
-      "opname" : "OpDecorateStringGOOGLE",
-      "class"  : "Annotation",
+      "aliases" : ["OpDecorateStringGOOGLE"],
       "opcode" : 5632,
       "operands" : [
         { "kind" : "IdRef",         "name" : "'Target'" },
@@ -6644,18 +7091,7 @@
     {
       "opname" : "OpMemberDecorateString",
       "class"  : "Annotation",
-      "opcode" : 5633,
-      "operands" : [
-        { "kind" : "IdRef",          "name" : "'Struct Type'" },
-        { "kind" : "LiteralInteger", "name" : "'Member'" },
-        { "kind" : "Decoration" }
-      ],
-      "extensions" : [ "SPV_GOOGLE_decorate_string", "SPV_GOOGLE_hlsl_functionality1" ],
-      "version" : "1.4"
-    },
-    {
-      "opname" : "OpMemberDecorateStringGOOGLE",
-      "class"  : "Annotation",
+      "aliases" : ["OpMemberDecorateStringGOOGLE"],
       "opcode" : 5633,
       "operands" : [
         { "kind" : "IdRef",          "name" : "'Struct Type'" },
@@ -9563,7 +9999,7 @@
         { "kind" : "IdMemorySemantics", "name" : "'Semantics'" },
         { "kind" : "IdRef",             "name" : "'Value'" }
       ],
-      "capabilities" : [ "AtomicFloat16AddEXT", "AtomicFloat32AddEXT", "AtomicFloat64AddEXT" ],
+      "capabilities" : [ "AtomicFloat16AddEXT", "AtomicFloat32AddEXT", "AtomicFloat64AddEXT", "AtomicFloat16VectorNV" ],
       "extensions" : [ "SPV_EXT_shader_atomic_float_add" ],
       "version" : "None"
     },
@@ -9671,6 +10107,30 @@
       "capabilities" : [ "SplitBarrierINTEL" ],
       "version" : "None"
     },
+    {
+      "opname" : "OpArithmeticFenceEXT",
+      "class"  : "Miscellaneous",
+      "opcode" : 6145,
+      "operands" : [
+        { "kind" : "IdResultType" },
+        { "kind" : "IdResult" },
+        { "kind" : "IdRef",          "name" : "'Target '" }
+      ],
+      "capabilities" : [ "ArithmeticFenceEXT" ],
+      "version" : "None"
+    },
+    {
+      "opname" : "OpSubgroupBlockPrefetchINTEL",
+      "class"  : "Group",
+      "opcode" : 6221,
+      "operands" : [
+        { "kind" : "IdRef", "name" : "'Ptr'" },
+        { "kind" : "IdRef", "name" : "'NumBytes'" },
+        { "kind" : "MemoryAccess", "quantifier" : "?" }
+      ],
+      "capabilities" : [ "SubgroupBufferPrefetchINTEL" ],
+      "version" : "None"
+    },
     {
       "opname" : "OpGroupIMulKHR",
       "class"  : "Group",
@@ -9892,15 +10352,7 @@
         },
         {
           "enumerant" : "MakeTexelAvailable",
-          "value" : "0x0100",
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "parameters" : [
-            { "kind" : "IdScope" }
-          ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "MakeTexelAvailableKHR",
+          "aliases" : [ "MakeTexelAvailableKHR" ],
           "value" : "0x0100",
           "capabilities" : [ "VulkanMemoryModel" ],
           "parameters" : [
@@ -9911,15 +10363,7 @@
         },
         {
           "enumerant" : "MakeTexelVisible",
-          "value" : "0x0200",
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "parameters" : [
-            { "kind" : "IdScope" }
-          ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "MakeTexelVisibleKHR",
+          "aliases" : [ "MakeTexelVisibleKHR" ],
           "value" : "0x0200",
           "capabilities" : [ "VulkanMemoryModel" ],
           "parameters" : [
@@ -9930,12 +10374,7 @@
         },
         {
           "enumerant" : "NonPrivateTexel",
-          "value" : "0x0400",
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "NonPrivateTexelKHR",
+          "aliases" : [ "NonPrivateTexelKHR" ],
           "value" : "0x0400",
           "capabilities" : [ "VulkanMemoryModel" ],
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
@@ -9943,12 +10382,7 @@
         },
         {
           "enumerant" : "VolatileTexel",
-          "value" : "0x0800",
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "VolatileTexelKHR",
+          "aliases" : [ "VolatileTexelKHR" ],
           "value" : "0x0800",
           "capabilities" : [ "VulkanMemoryModel" ],
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
@@ -10015,24 +10449,14 @@
         },
         {
           "enumerant" : "AllowContract",
-          "value" : "0x10000",
-          "capabilities" : [ "FloatControls2", "FPFastMathModeINTEL" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "AllowContractFastINTEL",
+          "aliases" : ["AllowContractFastINTEL"],
           "value" : "0x10000",
           "capabilities" : [ "FloatControls2", "FPFastMathModeINTEL" ],
           "version" : "None"
         },
         {
           "enumerant" : "AllowReassoc",
-          "value" : "0x20000",
-          "capabilities" : [ "FloatControls2", "FPFastMathModeINTEL" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "AllowReassocINTEL",
+          "aliases" : ["AllowReassocINTEL"],
           "value" : "0x20000",
           "capabilities" : [ "FloatControls2", "FPFastMathModeINTEL" ],
           "version" : "None"
@@ -10257,9 +10681,10 @@
           "version" : "1.0"
         },
         {
-          "enumerant" : "OptNoneINTEL",
+          "enumerant" : "OptNoneEXT",
+          "aliases" : ["OptNoneINTEL"],
           "value" : "0x10000",
-          "capabilities" : [  "OptNoneINTEL" ],
+          "capabilities" : [  "OptNoneEXT" ],
           "version" : "None"
         }
       ]
@@ -10270,11 +10695,7 @@
       "enumerants" : [
         {
           "enumerant" : "Relaxed",
-          "value" : "0x0000",
-          "version" : "1.0"
-        },
-        {
-          "enumerant" : "None",
+          "aliases" : ["None"],
           "value" : "0x0000",
           "version" : "1.0"
         },
@@ -10332,12 +10753,7 @@
         },
         {
           "enumerant" : "OutputMemory",
-          "value" : "0x1000",
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "OutputMemoryKHR",
+          "aliases" : ["OutputMemoryKHR"],
           "value" : "0x1000",
           "capabilities" : [ "VulkanMemoryModel" ],
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
@@ -10345,12 +10761,7 @@
         },
         {
           "enumerant" : "MakeAvailable",
-          "value" : "0x2000",
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "MakeAvailableKHR",
+          "aliases" : ["MakeAvailableKHR"],
           "value" : "0x2000",
           "capabilities" : [ "VulkanMemoryModel" ],
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
@@ -10358,12 +10769,7 @@
         },
         {
           "enumerant" : "MakeVisible",
-          "value" : "0x4000",
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "MakeVisibleKHR",
+          "aliases" : ["MakeVisibleKHR"],
           "value" : "0x4000",
           "capabilities" : [ "VulkanMemoryModel" ],
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
@@ -10407,15 +10813,7 @@
         },
         {
           "enumerant" : "MakePointerAvailable",
-          "value" : "0x0008",
-          "parameters" : [
-            { "kind" : "IdScope" }
-          ],
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "MakePointerAvailableKHR",
+          "aliases" : ["MakePointerAvailableKHR"],
           "value" : "0x0008",
           "parameters" : [
             { "kind" : "IdScope" }
@@ -10426,15 +10824,7 @@
         },
         {
           "enumerant" : "MakePointerVisible",
-          "value" : "0x0010",
-          "parameters" : [
-            { "kind" : "IdScope" }
-          ],
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "MakePointerVisibleKHR",
+          "aliases" : ["MakePointerVisibleKHR"],
           "value" : "0x0010",
           "parameters" : [
             { "kind" : "IdScope" }
@@ -10445,12 +10835,7 @@
         },
         {
           "enumerant" : "NonPrivatePointer",
-          "value" : "0x0020",
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "NonPrivatePointerKHR",
+          "aliases" : ["NonPrivatePointerKHR"],
           "value" : "0x0020",
           "capabilities" : [ "VulkanMemoryModel" ],
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
@@ -10603,6 +10988,28 @@
         }
       ]
     },
+    {
+      "category" : "BitEnum",
+      "kind" : "RawAccessChainOperands",
+      "enumerants" : [
+        {
+          "enumerant" : "None",
+          "value" : "0x0000"
+        },
+        {
+          "enumerant" : "RobustnessPerComponentNV",
+          "value" : "0x0001",
+          "capabilities" : [ "RawAccessChainsNV" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "RobustnessPerElementNV",
+          "value" : "0x0002",
+          "capabilities" : [ "RawAccessChainsNV" ],
+          "version" : "None"
+        }
+      ]
+    },
     {
       "category" : "ValueEnum",
       "kind" : "SourceLanguage",
@@ -10732,74 +11139,44 @@
           "capabilities" : [ "MeshShadingNV" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "RayGenerationNV",
-          "value" : 5313,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "RayGenerationKHR",
+          "aliases" : ["RayGenerationNV"],
           "value" : 5313,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "IntersectionNV",
-          "value" : 5314,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "IntersectionKHR",
+          "aliases" : ["IntersectionNV"],
           "value" : 5314,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "AnyHitNV",
-          "value" : 5315,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "AnyHitKHR",
+          "aliases" : ["AnyHitNV"],
           "value" : 5315,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "ClosestHitNV",
-          "value" : 5316,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "ClosestHitKHR",
+          "aliases" : ["ClosestHitNV"],
           "value" : 5316,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "MissNV",
-          "value" : 5317,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "MissKHR",
+          "aliases" : ["MissNV"],
           "value" : 5317,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "CallableNV",
-          "value" : 5318,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "CallableKHR",
+          "aliases" : ["CallableNV"],
           "value" : 5318,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
@@ -10841,17 +11218,11 @@
         },
         {
           "enumerant" : "PhysicalStorageBuffer64",
+          "aliases" : ["PhysicalStorageBuffer64EXT"],
           "value" : 5348,
           "extensions" : [ "SPV_EXT_physical_storage_buffer", "SPV_KHR_physical_storage_buffer" ],
           "capabilities" : [ "PhysicalStorageBufferAddresses" ],
           "version" : "1.5"
-        },
-        {
-          "enumerant" : "PhysicalStorageBuffer64EXT",
-          "value" : 5348,
-          "extensions" : [ "SPV_EXT_physical_storage_buffer" ],
-          "capabilities" : [ "PhysicalStorageBufferAddresses" ],
-          "version" : "1.5"
         }
       ]
     },
@@ -10879,12 +11250,7 @@
         },
         {
           "enumerant" : "Vulkan",
-          "value" : 3,
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "VulkanKHR",
+          "aliases" : ["VulkanKHR"],
           "value" : 3,
           "capabilities" : [ "VulkanMemoryModel" ],
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
@@ -11260,6 +11626,17 @@
           "enumerant" : "CoalescingAMDX",
           "value" : 5069,
           "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "provisional" : true,
+          "version" : "None"
+        },
+        {
+          "enumerant" : "IsApiEntryAMDX",
+          "value" : 5070,
+          "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "parameters" : [
+            { "kind" : "IdRef", "name" : "'Is Entry'" }
+          ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -11269,6 +11646,7 @@
           "parameters" : [
             { "kind" : "IdRef", "name" : "'Number of recursions'" }
           ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -11280,6 +11658,7 @@
             { "kind" : "IdRef", "name" : "'y size'" },
             { "kind" : "IdRef", "name" : "'z size'" }
           ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -11289,6 +11668,7 @@
           "parameters" : [
             { "kind" : "IdRef", "name" : "'Shader Index'" }
           ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -11300,6 +11680,7 @@
             { "kind" : "IdRef", "name" : "'y size'" },
             { "kind" : "IdRef", "name" : "'z size'" }
           ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -11357,31 +11738,27 @@
           "version" : "None"
         },
         {
-          "enumerant" : "OutputLinesNV",
-          "value" : 5269,
-          "capabilities" : [ "MeshShadingNV", "MeshShadingEXT" ],
-          "extensions" : [ "SPV_NV_mesh_shader", "SPV_EXT_mesh_shader" ],
+          "enumerant" : "SharesInputWithAMDX",
+          "value" : 5102,
+          "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "parameters" : [
+            { "kind" : "IdRef", "name" : "'Node Name'" },
+            { "kind" : "IdRef", "name" : "'Shader Index'" }
+          ],
+          "provisional" : true,
           "version" : "None"
         },
         {
           "enumerant" : "OutputLinesEXT",
+          "aliases" : ["OutputLinesNV"],
           "value" : 5269,
           "capabilities" : [ "MeshShadingNV", "MeshShadingEXT" ],
           "extensions" : [ "SPV_NV_mesh_shader", "SPV_EXT_mesh_shader" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "OutputPrimitivesNV",
-          "value" : 5270,
-          "capabilities" : [ "MeshShadingNV", "MeshShadingEXT" ],
-          "parameters" : [
-            { "kind" : "LiteralInteger", "name" : "'Primitive count'" }
-          ],
-          "extensions" : [ "SPV_NV_mesh_shader", "SPV_EXT_mesh_shader" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "OutputPrimitivesEXT",
+          "aliases" : ["OutputPrimitivesNV"],
           "value" : 5270,
           "capabilities" : [ "MeshShadingNV", "MeshShadingEXT" ],
           "parameters" : [
@@ -11391,28 +11768,24 @@
           "version" : "None"
         },
         {
-          "enumerant" : "DerivativeGroupQuadsNV",
+          "enumerant" : "DerivativeGroupQuadsKHR",
+          "aliases" : ["DerivativeGroupQuadsNV"],
           "value" : 5289,
-          "capabilities" : [ "ComputeDerivativeGroupQuadsNV" ],
-          "extensions" : [ "SPV_NV_compute_shader_derivatives" ],
+          "capabilities" : [ "ComputeDerivativeGroupQuadsNV", "ComputeDerivativeGroupQuadsKHR" ],
+          "extensions" : [ "SPV_NV_compute_shader_derivatives", "SPV_KHR_compute_shader_derivatives" ],
           "version" : "None"
         },
         {
-          "enumerant" : "DerivativeGroupLinearNV",
+          "enumerant" : "DerivativeGroupLinearKHR",
+          "aliases" : ["DerivativeGroupLinearNV"],
           "value" : 5290,
-          "capabilities" : [ "ComputeDerivativeGroupLinearNV" ],
-          "extensions" : [ "SPV_NV_compute_shader_derivatives" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "OutputTrianglesNV",
-          "value" : 5298,
-          "capabilities" : [ "MeshShadingNV", "MeshShadingEXT" ],
-          "extensions" : [ "SPV_NV_mesh_shader", "SPV_EXT_mesh_shader" ],
+          "capabilities" : [ "ComputeDerivativeGroupLinearNV", "ComputeDerivativeGroupLinearKHR" ],
+          "extensions" : [ "SPV_NV_compute_shader_derivatives", "SPV_KHR_compute_shader_derivatives" ],
           "version" : "None"
         },
         {
           "enumerant" : "OutputTrianglesEXT",
+          "aliases" : ["OutputTrianglesNV"],
           "value" : 5298,
           "capabilities" : [ "MeshShadingNV", "MeshShadingEXT" ],
           "extensions" : [ "SPV_NV_mesh_shader", "SPV_EXT_mesh_shader" ],
@@ -11596,6 +11969,33 @@
           ],
           "capabilities" : [ "VectorComputeINTEL" ],
           "version" : "None"
+        },
+        {
+          "enumerant" : "MaximumRegistersINTEL",
+          "value" : 6461,
+          "parameters" : [
+            { "kind" : "LiteralInteger", "name" : "'Number of Registers'" }
+          ],
+          "capabilities" : [ "RegisterLimitsINTEL" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "MaximumRegistersIdINTEL",
+          "value" : 6462,
+          "parameters" : [
+            { "kind" : "IdRef", "name" : "'Number of Registers'" }
+          ],
+          "capabilities" : [ "RegisterLimitsINTEL" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "NamedMaximumRegistersINTEL",
+          "value" : 6463,
+          "parameters" : [
+            { "kind" : "NamedMaximumNumberOfRegisters", "name" : "'Named Maximum Number of Registers'" }
+          ],
+          "capabilities" : [ "RegisterLimitsINTEL" ],
+          "version" : "None"
         }
       ]
     },
@@ -11689,93 +12089,52 @@
           "enumerant" : "NodePayloadAMDX",
           "value" : 5068,
           "capabilities" : [ "ShaderEnqueueAMDX" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "NodeOutputPayloadAMDX",
-          "value" : 5076,
-          "capabilities" : [ "ShaderEnqueueAMDX" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "CallableDataNV",
-          "value" : 5328,
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
+          "provisional" : true,
           "version" : "None"
         },
         {
           "enumerant" : "CallableDataKHR",
+          "aliases" : ["CallableDataNV"],
           "value" : 5328,
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "IncomingCallableDataNV",
-          "value" : 5329,
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "IncomingCallableDataKHR",
+          "aliases" : ["IncomingCallableDataNV"],
           "value" : 5329,
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "RayPayloadNV",
-          "value" : 5338,
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "RayPayloadKHR",
+          "aliases" : ["RayPayloadNV"],
           "value" : 5338,
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "HitAttributeNV",
-          "value" : 5339,
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "HitAttributeKHR",
+          "aliases" : ["HitAttributeNV"],
           "value" : 5339,
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "IncomingRayPayloadNV",
-          "value" : 5342,
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "IncomingRayPayloadKHR",
+          "aliases" : ["IncomingRayPayloadNV"],
           "value" : 5342,
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "ShaderRecordBufferNV",
-          "value" : 5343,
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "ShaderRecordBufferKHR",
+          "aliases" : ["ShaderRecordBufferNV"],
           "value" : 5343,
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
@@ -11783,18 +12142,12 @@
         },
         {
           "enumerant" : "PhysicalStorageBuffer",
+          "aliases" : ["PhysicalStorageBufferEXT"],
           "value" : 5349,
           "extensions" : [ "SPV_EXT_physical_storage_buffer", "SPV_KHR_physical_storage_buffer" ],
           "capabilities" : [ "PhysicalStorageBufferAddresses" ],
           "version" : "1.5"
         },
-        {
-          "enumerant" : "PhysicalStorageBufferEXT",
-          "value" : 5349,
-          "extensions" : [ "SPV_EXT_physical_storage_buffer" ],
-          "capabilities" : [ "PhysicalStorageBufferAddresses" ],
-          "version" : "1.5"
-        },
         {
           "enumerant" : "HitObjectAttributeNV",
           "value" : 5385,
@@ -12395,6 +12748,11 @@
           "enumerant" : "UnsignedIntRaw12EXT",
           "value" : 20,
           "version": "1.0"
+        },
+        {
+          "enumerant" : "UnormInt2_101010EXT",
+          "value" : 21,
+          "version": "1.0"
         }
       ]
     },
@@ -13056,6 +13414,12 @@
           "extensions" : [ "SPV_QCOM_image_processing" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "BlockMatchSamplerQCOM",
+          "value" : 4499,
+          "extensions" : [ "SPV_QCOM_image_processing2" ],
+          "version" : "None"
+        },
         {
           "enumerant" : "ExplicitInterpAMD",
           "value" : 4999,
@@ -13067,8 +13431,9 @@
           "value" : 5019,
           "capabilities" : [ "ShaderEnqueueAMDX" ],
           "parameters" : [
-            { "kind" : "IdRef", "name" : "'Payload Array'" }
+            { "kind" : "IdRef", "name" : "'Payload Type'" }
           ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -13078,12 +13443,14 @@
           "parameters" : [
             { "kind" : "IdRef", "name" : "'Max number of payloads'" }
           ],
+          "provisional" : true,
           "version" : "None"
         },
         {
           "enumerant" : "TrackFinishWritingAMDX",
           "value" : 5078,
           "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -13091,8 +13458,43 @@
           "value" : 5091,
           "capabilities" : [ "ShaderEnqueueAMDX" ],
           "parameters" : [
-            { "kind" : "LiteralString", "name" : "'Node Name'" }
+            { "kind" : "IdRef", "name" : "'Node Name'" }
+          ],
+          "provisional" : true,
+          "version" : "None"
+        },
+        {
+          "enumerant" : "PayloadNodeBaseIndexAMDX",
+          "value" : 5098,
+          "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "parameters" : [
+            { "kind" : "IdRef", "name" : "'Base Index'" }
+          ],
+          "provisional" : true,
+          "version" : "None"
+        },
+        {
+          "enumerant" : "PayloadNodeSparseArrayAMDX",
+          "value" : 5099,
+          "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "provisional" : true,
+          "version" : "None"
+        },
+        {
+          "enumerant" : "PayloadNodeArraySizeAMDX",
+          "value" : 5100,
+          "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "parameters" : [
+            { "kind" : "IdRef", "name" : "'Array Size'" }
           ],
+          "provisional" : true,
+          "version" : "None"
+        },
+        {
+          "enumerant" : "PayloadDispatchIndirectAMDX",
+          "value" : 5105,
+          "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -13125,15 +13527,9 @@
             { "kind" : "LiteralInteger", "name" : "'Offset'" }
           ]
         },
-        {
-          "enumerant" : "PerPrimitiveNV",
-          "value" : 5271,
-          "capabilities" : [ "MeshShadingNV", "MeshShadingEXT" ],
-          "extensions" : [ "SPV_NV_mesh_shader", "SPV_EXT_mesh_shader" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "PerPrimitiveEXT",
+          "aliases" : ["PerPrimitiveNV"],
           "value" : 5271,
           "capabilities" : [ "MeshShadingNV", "MeshShadingEXT" ],
           "extensions" : [ "SPV_NV_mesh_shader", "SPV_EXT_mesh_shader" ],
@@ -13155,26 +13551,15 @@
         },
         {
           "enumerant" : "PerVertexKHR",
+          "aliases" : ["PerVertexNV"],
           "value" : 5285,
-          "capabilities" : [ "FragmentBarycentricNV", "FragmentBarycentricKHR" ],
-          "extensions" : [ "SPV_NV_fragment_shader_barycentric", "SPV_KHR_fragment_shader_barycentric" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "PerVertexNV",
-          "value" : 5285,
-          "capabilities" : [ "FragmentBarycentricNV", "FragmentBarycentricKHR" ],
+          "capabilities" : [ "FragmentBarycentricKHR" ],
           "extensions" : [ "SPV_NV_fragment_shader_barycentric", "SPV_KHR_fragment_shader_barycentric" ],
           "version" : "None"
         },
         {
           "enumerant" : "NonUniform",
-          "value" : 5300,
-          "capabilities" : [ "ShaderNonUniform" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "NonUniformEXT",
+          "aliases" : ["NonUniformEXT"],
           "value" : 5300,
           "capabilities" : [ "ShaderNonUniform" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -13182,32 +13567,20 @@
         },
         {
           "enumerant" : "RestrictPointer",
+          "aliases" : ["RestrictPointerEXT"],
           "value" : 5355,
           "capabilities" : [ "PhysicalStorageBufferAddresses" ],
           "extensions" : [ "SPV_EXT_physical_storage_buffer", "SPV_KHR_physical_storage_buffer" ],
           "version" : "1.5"
         },
-        {
-          "enumerant" : "RestrictPointerEXT",
-          "value" : 5355,
-          "capabilities" : [ "PhysicalStorageBufferAddresses" ],
-          "extensions" : [ "SPV_EXT_physical_storage_buffer" ],
-          "version" : "1.5"
-        },
         {
           "enumerant" : "AliasedPointer",
+          "aliases" : ["AliasedPointerEXT"],
           "value" : 5356,
           "capabilities" : [ "PhysicalStorageBufferAddresses" ],
           "extensions" : [ "SPV_EXT_physical_storage_buffer", "SPV_KHR_physical_storage_buffer" ],
           "version" : "1.5"
         },
-        {
-          "enumerant" : "AliasedPointerEXT",
-          "value" : 5356,
-          "capabilities" : [ "PhysicalStorageBufferAddresses" ],
-          "extensions" : [ "SPV_EXT_physical_storage_buffer" ],
-          "version" : "1.5"
-        },
         {
           "enumerant" : "HitObjectShaderRecordBufferNV",
           "value" : 5386,
@@ -13307,37 +13680,23 @@
         },
         {
           "enumerant" : "CounterBuffer",
-          "value" : 5634,
-          "parameters" : [
-            { "kind" : "IdRef", "name" : "'Counter Buffer'" }
-          ],
-          "version" : "1.4"
-        },
-        {
-          "enumerant" : "HlslCounterBufferGOOGLE",
+          "aliases" : ["HlslCounterBufferGOOGLE"],
           "value" : 5634,
           "parameters" : [
             { "kind" : "IdRef", "name" : "'Counter Buffer'" }
           ],
           "extensions" : [ "SPV_GOOGLE_hlsl_functionality1" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "UserSemantic",
-          "value" : 5635,
-          "parameters" : [
-            { "kind" : "LiteralString", "name" : "'Semantic'" }
-          ],
           "version" : "1.4"
         },
         {
-          "enumerant" : "HlslSemanticGOOGLE",
+          "enumerant" : "UserSemantic",
+          "aliases" : ["HlslSemanticGOOGLE"],
           "value" : 5635,
           "parameters" : [
             { "kind" : "LiteralString", "name" : "'Semantic'" }
           ],
           "extensions" : [ "SPV_GOOGLE_hlsl_functionality1" ],
-          "version" : "None"
+          "version" : "1.4"
         },
         {
           "enumerant" : "UserTypeGOOGLE",
@@ -14077,12 +14436,7 @@
         },
         {
           "enumerant" : "SubgroupEqMask",
-          "value" : 4416,
-          "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
-          "version" : "1.3"
-        },
-        {
-          "enumerant" : "SubgroupEqMaskKHR",
+          "aliases" : ["SubgroupEqMaskKHR"],
           "value" : 4416,
           "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
           "extensions" : [ "SPV_KHR_shader_ballot" ],
@@ -14090,12 +14444,7 @@
         },
         {
           "enumerant" : "SubgroupGeMask",
-          "value" : 4417,
-          "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
-          "version" : "1.3"
-        },
-        {
-          "enumerant" : "SubgroupGeMaskKHR",
+          "aliases" : ["SubgroupGeMaskKHR"],
           "value" : 4417,
           "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
           "extensions" : [ "SPV_KHR_shader_ballot" ],
@@ -14103,12 +14452,7 @@
         },
         {
           "enumerant" : "SubgroupGtMask",
-          "value" : 4418,
-          "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
-          "version" : "1.3"
-        },
-        {
-          "enumerant" : "SubgroupGtMaskKHR",
+          "aliases" : ["SubgroupGtMaskKHR"],
           "value" : 4418,
           "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
           "extensions" : [ "SPV_KHR_shader_ballot" ],
@@ -14116,12 +14460,7 @@
         },
         {
           "enumerant" : "SubgroupLeMask",
-          "value" : 4419,
-          "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
-          "version" : "1.3"
-        },
-        {
-          "enumerant" : "SubgroupLeMaskKHR",
+          "aliases" : ["SubgroupLeMaskKHR"],
           "value" : 4419,
           "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
           "extensions" : [ "SPV_KHR_shader_ballot" ],
@@ -14129,12 +14468,7 @@
         },
         {
           "enumerant" : "SubgroupLtMask",
-          "value" : 4420,
-          "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
-          "version" : "1.3"
-        },
-        {
-          "enumerant" : "SubgroupLtMaskKHR",
+          "aliases" : ["SubgroupLtMaskKHR"],
           "value" : 4420,
           "capabilities" : [ "SubgroupBallotKHR", "GroupNonUniformBallot" ],
           "extensions" : [ "SPV_KHR_shader_ballot" ],
@@ -14239,15 +14573,17 @@
           "version" : "None"
         },
         {
-          "enumerant" : "CoalescedInputCountAMDX",
+          "enumerant" : "RemainingRecursionLevelsAMDX",
           "value" : 5021,
           "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "provisional" : true,
           "version" : "None"
         },
         {
           "enumerant" : "ShaderIndexAMDX",
           "value" : 5073,
           "capabilities" : [ "ShaderEnqueueAMDX" ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -14350,60 +14686,36 @@
         },
         {
           "enumerant" : "BaryCoordKHR",
+          "aliases" : ["BaryCoordNV"],
           "value" : 5286,
-          "capabilities" : [ "FragmentBarycentricNV", "FragmentBarycentricKHR" ],
-          "extensions" : [ "SPV_NV_fragment_shader_barycentric", "SPV_KHR_fragment_shader_barycentric" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "BaryCoordNV",
-          "value" : 5286,
-          "capabilities" : [ "FragmentBarycentricNV", "FragmentBarycentricKHR" ],
+          "capabilities" : [ "FragmentBarycentricKHR" ],
           "extensions" : [ "SPV_NV_fragment_shader_barycentric", "SPV_KHR_fragment_shader_barycentric" ],
           "version" : "None"
         },
         {
           "enumerant" : "BaryCoordNoPerspKHR",
+          "aliases" : ["BaryCoordNoPerspNV"],
           "value" : 5287,
-          "capabilities" : [ "FragmentBarycentricNV", "FragmentBarycentricKHR" ],
-          "extensions" : [ "SPV_NV_fragment_shader_barycentric", "SPV_KHR_fragment_shader_barycentric" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "BaryCoordNoPerspNV",
-          "value" : 5287,
-          "capabilities" : [ "FragmentBarycentricNV", "FragmentBarycentricKHR" ],
+          "capabilities" : [ "FragmentBarycentricKHR" ],
           "extensions" : [ "SPV_NV_fragment_shader_barycentric", "SPV_KHR_fragment_shader_barycentric" ],
           "version" : "None"
         },
         {
           "enumerant" : "FragSizeEXT",
+          "aliases" : ["FragmentSizeNV"],
           "value" : 5292 ,
-          "capabilities" : [ "FragmentDensityEXT", "ShadingRateNV" ],
+          "capabilities" : [ "FragmentDensityEXT" ],
           "extensions" : [ "SPV_EXT_fragment_invocation_density", "SPV_NV_shading_rate" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "FragmentSizeNV",
-          "value" : 5292 ,
-          "capabilities" : [ "ShadingRateNV", "FragmentDensityEXT" ],
-          "extensions" : [ "SPV_NV_shading_rate", "SPV_EXT_fragment_invocation_density" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "FragInvocationCountEXT",
+          "aliases" : ["InvocationsPerPixelNV"],
           "value" : 5293,
-          "capabilities" : [ "FragmentDensityEXT", "ShadingRateNV" ],
+          "capabilities" : [ "FragmentDensityEXT" ],
           "extensions" : [ "SPV_EXT_fragment_invocation_density", "SPV_NV_shading_rate" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "InvocationsPerPixelNV",
-          "value" : 5293,
-          "capabilities" : [ "ShadingRateNV", "FragmentDensityEXT" ],
-          "extensions" : [ "SPV_NV_shading_rate", "SPV_EXT_fragment_invocation_density" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "PrimitivePointIndicesEXT",
           "value" : 5294,
@@ -14432,155 +14744,89 @@
           "extensions" : [ "SPV_EXT_mesh_shader" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "LaunchIdNV",
-          "value" : 5319,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "LaunchIdKHR",
+          "aliases" : ["LaunchIdNV"],
           "value" : 5319,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "LaunchSizeNV",
-          "value" : 5320,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "LaunchSizeKHR",
+          "aliases" : ["LaunchSizeNV"],
           "value" : 5320,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "WorldRayOriginNV",
-          "value" : 5321,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "WorldRayOriginKHR",
+          "aliases" : ["WorldRayOriginNV"],
           "value" : 5321,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "WorldRayDirectionNV",
-          "value" : 5322,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "WorldRayDirectionKHR",
+          "aliases" : ["WorldRayDirectionNV"],
           "value" : 5322,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "ObjectRayOriginNV",
-          "value" : 5323,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "ObjectRayOriginKHR",
+          "aliases" : ["ObjectRayOriginNV"],
           "value" : 5323,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "ObjectRayDirectionNV",
-          "value" : 5324,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "ObjectRayDirectionKHR",
+          "aliases" : ["ObjectRayDirectionNV"],
           "value" : 5324,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "RayTminNV",
-          "value" : 5325,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "RayTminKHR",
+          "aliases" : ["RayTminNV"],
           "value" : 5325,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "RayTmaxNV",
-          "value" : 5326,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "RayTmaxKHR",
+          "aliases" : ["RayTmaxNV"],
           "value" : 5326,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "InstanceCustomIndexNV",
-          "value" : 5327,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "InstanceCustomIndexKHR",
+          "aliases" : ["InstanceCustomIndexNV"],
           "value" : 5327,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "ObjectToWorldNV",
-          "value" : 5330,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "ObjectToWorldKHR",
+          "aliases" : ["ObjectToWorldNV"],
           "value" : 5330,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "WorldToObjectNV",
-          "value" : 5331,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "WorldToObjectKHR",
+          "aliases" : ["WorldToObjectNV"],
           "value" : 5331,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
@@ -14593,15 +14839,9 @@
           "extensions" : [ "SPV_NV_ray_tracing" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "HitKindNV",
-          "value" : 5333,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "HitKindKHR",
+          "aliases" : ["HitKindNV"],
           "value" : 5333,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
@@ -14632,15 +14872,9 @@
           "capabilities" : [ "RayTracingDisplacementMicromapNV" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "IncomingRayFlagsNV",
-          "value" : 5351,
-          "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
-          "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "IncomingRayFlagsKHR",
+          "aliases" : ["IncomingRayFlagsNV"],
           "value" : 5351,
           "capabilities" : [ "RayTracingNV" , "RayTracingKHR" ],
           "extensions" : [ "SPV_NV_ray_tracing" , "SPV_KHR_ray_tracing" ],
@@ -14733,12 +14967,7 @@
         },
         {
           "enumerant" : "QueueFamily",
-          "value" : 5,
-          "capabilities" : [ "VulkanMemoryModel" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "QueueFamilyKHR",
+          "aliases" : ["QueueFamilyKHR"],
           "value" : 5,
           "capabilities" : [ "VulkanMemoryModel" ],
           "version" : "1.5"
@@ -15259,6 +15488,12 @@
           "extensions" : [ "SPV_EXT_shader_tile_image" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "CooperativeMatrixLayoutsARM",
+          "value" : 4201,
+          "extensions" : [ "SPV_ARM_cooperative_matrix_layouts" ],
+          "version" : "None"
+        },
         {
           "enumerant" : "FragmentShadingRateKHR",
           "value" : 4422,
@@ -15308,33 +15543,16 @@
         },
         {
           "enumerant" : "StorageBuffer16BitAccess",
-          "value" : 4433,
-          "extensions" : [ "SPV_KHR_16bit_storage" ],
-          "version" : "1.3"
-        },
-        {
-          "enumerant" : "StorageUniformBufferBlock16",
+          "aliases" : ["StorageUniformBufferBlock16"],
           "value" : 4433,
           "extensions" : [ "SPV_KHR_16bit_storage" ],
           "version" : "1.3"
         },
         {
           "enumerant" : "UniformAndStorageBuffer16BitAccess",
+          "aliases" : ["StorageUniform16"],
           "value" : 4434,
-          "capabilities" : [
-            "StorageBuffer16BitAccess",
-            "StorageUniformBufferBlock16"
-          ],
-          "extensions" : [ "SPV_KHR_16bit_storage" ],
-          "version" : "1.3"
-        },
-        {
-          "enumerant" : "StorageUniform16",
-          "value" : 4434,
-          "capabilities" : [
-            "StorageBuffer16BitAccess",
-            "StorageUniformBufferBlock16"
-          ],
+          "capabilities" : [ "StorageBuffer16BitAccess" ],
           "extensions" : [ "SPV_KHR_16bit_storage" ],
           "version" : "1.3"
         },
@@ -15452,6 +15670,13 @@
           "extensions" : [ "SPV_KHR_ray_query" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "UntypedPointersKHR",
+          "value" : 4473,
+          "extensions" : [ "SPV_KHR_untyped_pointers" ],
+          "provisional" : true,
+          "version" : "None"
+        },
         {
           "enumerant" : "RayTraversalPrimitiveCullingKHR",
           "value" : 4478,
@@ -15484,6 +15709,12 @@
           "extensions" : [ "SPV_QCOM_image_processing" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "TextureBlockMatch2QCOM",
+          "value" : 4498,
+          "extensions" : [ "SPV_QCOM_image_processing2" ],
+          "version" : "None"
+        },
         {
           "enumerant" : "Float16ImageAMD",
           "value" : 5008,
@@ -15537,6 +15768,7 @@
           "value" : 5067,
           "capabilities" : [ "Shader" ],
           "extensions" : [ "SPV_AMDX_shader_enqueue" ],
+          "provisional" : true,
           "version" : "None"
         },
         {
@@ -15544,7 +15776,7 @@
           "value" : 5087,
           "extensions" : [ "SPV_KHR_quad_control" ],
           "version" : "None"
-        },		
+        },
         {
           "enumerant" : "SampleMaskOverrideCoverageNV",
           "value" : 5249,
@@ -15561,22 +15793,16 @@
         },
         {
           "enumerant" : "ShaderViewportIndexLayerEXT",
+          "aliases" : ["ShaderViewportIndexLayerNV"],
           "value" : 5254,
           "capabilities" : [ "MultiViewport" ],
-          "extensions" : [ "SPV_EXT_shader_viewport_index_layer" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "ShaderViewportIndexLayerNV",
-          "value" : 5254,
-          "capabilities" : [ "MultiViewport" ],
-          "extensions" : [ "SPV_NV_viewport_array2" ],
+          "extensions" : [ "SPV_EXT_shader_viewport_index_layer", "SPV_NV_viewport_array2" ],
           "version" : "None"
         },
         {
           "enumerant" : "ShaderViewportMaskNV",
           "value" : 5255,
-          "capabilities" : [ "ShaderViewportIndexLayerNV" ],
+          "capabilities" : [ "ShaderViewportIndexLayerEXT" ],
           "extensions" : [ "SPV_NV_viewport_array2" ],
           "version" : "None"
         },
@@ -15623,36 +15849,27 @@
         },
         {
           "enumerant" : "FragmentBarycentricKHR",
+          "aliases" : ["FragmentBarycentricNV"],
           "value" : 5284,
           "extensions" : [ "SPV_NV_fragment_shader_barycentric", "SPV_KHR_fragment_shader_barycentric" ],
           "version" : "None"
         },
         {
-          "enumerant" : "FragmentBarycentricNV",
-          "value" : 5284,
-          "extensions" : [ "SPV_NV_fragment_shader_barycentric", "SPV_KHR_fragment_shader_barycentric" ],
-          "version" : "None"
-        },
-        {
-          "enumerant" : "ComputeDerivativeGroupQuadsNV",
+          "enumerant" : "ComputeDerivativeGroupQuadsKHR",
+          "aliases" : ["ComputeDerivativeGroupQuadsNV"],
           "value" : 5288,
-          "extensions" : [ "SPV_NV_compute_shader_derivatives" ],
+          "capabilities" : [ "Shader" ],
+          "extensions" : [ "SPV_NV_compute_shader_derivatives", "SPV_KHR_compute_shader_derivatives" ],
           "version" : "None"
         },
         {
           "enumerant" : "FragmentDensityEXT",
+          "aliases" : ["ShadingRateNV"],
           "value" : 5291,
           "capabilities" : [ "Shader" ],
           "extensions" : [ "SPV_EXT_fragment_invocation_density", "SPV_NV_shading_rate" ],
           "version" : "None"
         },
-        {
-          "enumerant" : "ShadingRateNV",
-          "value" : 5291,
-          "capabilities" : [ "Shader" ],
-          "extensions" : [ "SPV_NV_shading_rate", "SPV_EXT_fragment_invocation_density" ],
-          "version" : "None"
-        },
         {
           "enumerant" : "GroupNonUniformPartitionedNV",
           "value" : 5297,
@@ -15661,12 +15878,7 @@
         },
         {
           "enumerant" : "ShaderNonUniform",
-          "value" : 5301,
-          "capabilities" : [ "Shader" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "ShaderNonUniformEXT",
+          "aliases" : ["ShaderNonUniformEXT"],
           "value" : 5301,
           "capabilities" : [ "Shader" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15674,12 +15886,7 @@
         },
         {
           "enumerant" : "RuntimeDescriptorArray",
-          "value" : 5302,
-          "capabilities" : [ "Shader" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "RuntimeDescriptorArrayEXT",
+          "aliases" : ["RuntimeDescriptorArrayEXT"],
           "value" : 5302,
           "capabilities" : [ "Shader" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15687,12 +15894,7 @@
         },
         {
           "enumerant" : "InputAttachmentArrayDynamicIndexing",
-          "value" : 5303,
-          "capabilities" : [ "InputAttachment" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "InputAttachmentArrayDynamicIndexingEXT",
+          "aliases" : ["InputAttachmentArrayDynamicIndexingEXT"],
           "value" : 5303,
           "capabilities" : [ "InputAttachment" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15700,12 +15902,7 @@
         },
         {
           "enumerant" : "UniformTexelBufferArrayDynamicIndexing",
-          "value" : 5304,
-          "capabilities" : [ "SampledBuffer" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "UniformTexelBufferArrayDynamicIndexingEXT",
+          "aliases" : ["UniformTexelBufferArrayDynamicIndexingEXT"],
           "value" : 5304,
           "capabilities" : [ "SampledBuffer" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15713,12 +15910,7 @@
         },
         {
           "enumerant" : "StorageTexelBufferArrayDynamicIndexing",
-          "value" : 5305,
-          "capabilities" : [ "ImageBuffer" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "StorageTexelBufferArrayDynamicIndexingEXT",
+          "aliases" : ["StorageTexelBufferArrayDynamicIndexingEXT"],
           "value" : 5305,
           "capabilities" : [ "ImageBuffer" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15726,12 +15918,7 @@
         },
         {
           "enumerant" : "UniformBufferArrayNonUniformIndexing",
-          "value" : 5306,
-          "capabilities" : [ "ShaderNonUniform" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "UniformBufferArrayNonUniformIndexingEXT",
+          "aliases" : ["UniformBufferArrayNonUniformIndexingEXT"],
           "value" : 5306,
           "capabilities" : [ "ShaderNonUniform" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15739,12 +15926,7 @@
         },
         {
           "enumerant" : "SampledImageArrayNonUniformIndexing",
-          "value" : 5307,
-          "capabilities" : [ "ShaderNonUniform" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "SampledImageArrayNonUniformIndexingEXT",
+          "aliases" : ["SampledImageArrayNonUniformIndexingEXT"],
           "value" : 5307,
           "capabilities" : [ "ShaderNonUniform" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15752,12 +15934,7 @@
         },
         {
           "enumerant" : "StorageBufferArrayNonUniformIndexing",
-          "value" : 5308,
-          "capabilities" : [ "ShaderNonUniform" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "StorageBufferArrayNonUniformIndexingEXT",
+          "aliases" : ["StorageBufferArrayNonUniformIndexingEXT"],
           "value" : 5308,
           "capabilities" : [ "ShaderNonUniform" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15765,12 +15942,7 @@
         },
         {
           "enumerant" : "StorageImageArrayNonUniformIndexing",
-          "value" : 5309,
-          "capabilities" : [ "ShaderNonUniform" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "StorageImageArrayNonUniformIndexingEXT",
+          "aliases" : ["StorageImageArrayNonUniformIndexingEXT"],
           "value" : 5309,
           "capabilities" : [ "ShaderNonUniform" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15778,12 +15950,7 @@
         },
         {
           "enumerant" : "InputAttachmentArrayNonUniformIndexing",
-          "value" : 5310,
-          "capabilities" : [ "InputAttachment", "ShaderNonUniform" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "InputAttachmentArrayNonUniformIndexingEXT",
+          "aliases" : ["InputAttachmentArrayNonUniformIndexingEXT"],
           "value" : 5310,
           "capabilities" : [ "InputAttachment", "ShaderNonUniform" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15791,12 +15958,7 @@
         },
         {
           "enumerant" : "UniformTexelBufferArrayNonUniformIndexing",
-          "value" : 5311,
-          "capabilities" : [ "SampledBuffer", "ShaderNonUniform" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "UniformTexelBufferArrayNonUniformIndexingEXT",
+          "aliases" : ["UniformTexelBufferArrayNonUniformIndexingEXT"],
           "value" : 5311,
           "capabilities" : [ "SampledBuffer", "ShaderNonUniform" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15804,12 +15966,7 @@
         },
         {
           "enumerant" : "StorageTexelBufferArrayNonUniformIndexing",
-          "value" : 5312,
-          "capabilities" : [ "ImageBuffer", "ShaderNonUniform" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "StorageTexelBufferArrayNonUniformIndexingEXT",
+          "aliases" : ["StorageTexelBufferArrayNonUniformIndexingEXT"],
           "value" : 5312,
           "capabilities" : [ "ImageBuffer", "ShaderNonUniform" ],
           "extensions" : [ "SPV_EXT_descriptor_indexing" ],
@@ -15838,44 +15995,32 @@
         },
         {
           "enumerant" : "VulkanMemoryModel",
-          "value" : 5345,
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "VulkanMemoryModelKHR",
+          "aliases" : ["VulkanMemoryModelKHR"],
           "value" : 5345,
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
           "version" : "1.5"
         },
         {
           "enumerant" : "VulkanMemoryModelDeviceScope",
-          "value" : 5346,
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "VulkanMemoryModelDeviceScopeKHR",
+          "aliases" : ["VulkanMemoryModelDeviceScopeKHR"],
           "value" : 5346,
           "extensions" : [ "SPV_KHR_vulkan_memory_model" ],
           "version" : "1.5"
         },
         {
           "enumerant" : "PhysicalStorageBufferAddresses",
+          "aliases" : ["PhysicalStorageBufferAddressesEXT"],
           "value" : 5347,
           "capabilities" : [ "Shader" ],
           "extensions" : [ "SPV_EXT_physical_storage_buffer", "SPV_KHR_physical_storage_buffer" ],
           "version" : "1.5"
         },
         {
-          "enumerant" : "PhysicalStorageBufferAddressesEXT",
-          "value" : 5347,
-          "capabilities" : [ "Shader" ],
-          "extensions" : [ "SPV_EXT_physical_storage_buffer" ],
-          "version" : "1.5"
-        },
-        {
-          "enumerant" : "ComputeDerivativeGroupLinearNV",
+          "enumerant" : "ComputeDerivativeGroupLinearKHR",
+          "aliases" : ["ComputeDerivativeGroupLinearNV"],
           "value" : 5350,
-          "extensions" : [ "SPV_NV_compute_shader_derivatives" ],
+          "capabilities" : [ "Shader" ],
+          "extensions" : [ "SPV_NV_compute_shader_derivatives", "SPV_KHR_compute_shader_derivatives" ],
           "version" : "None"
         },
         {
@@ -15922,12 +16067,7 @@
         },
         {
           "enumerant" : "DemoteToHelperInvocation",
-          "value" : 5379,
-          "capabilities" : [ "Shader" ],
-          "version" : "1.6"
-        },
-        {
-          "enumerant" : "DemoteToHelperInvocationEXT",
+          "aliases" : ["DemoteToHelperInvocationEXT"],
           "value" : 5379,
           "capabilities" : [ "Shader" ],
           "extensions" : [ "SPV_EXT_demote_to_helper_invocation" ],
@@ -15967,6 +16107,12 @@
           "extensions" : [ "SPV_KHR_ray_tracing_position_fetch" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "AtomicFloat16VectorNV",
+          "value" : 5404,
+          "extensions" : [ "SPV_NV_shader_atomic_fp16_vector" ],
+          "version" : "None"
+        },
         {
           "enumerant" : "RayTracingDisplacementMicromapNV",
           "value" : 5409,
@@ -15974,6 +16120,48 @@
           "extensions" : [ "SPV_NV_displacement_micromap" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "RawAccessChainsNV",
+          "value" : 5414,
+          "extensions" : [ "SPV_NV_raw_access_chains" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "CooperativeMatrixReductionsNV",
+          "value" : 5430,
+          "extensions" : [ "SPV_NV_cooperative_matrix2" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "CooperativeMatrixConversionsNV",
+          "value" : 5431,
+          "extensions" : [ "SPV_NV_cooperative_matrix2" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "CooperativeMatrixPerElementOperationsNV",
+          "value" : 5432,
+          "extensions" : [ "SPV_NV_cooperative_matrix2" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "CooperativeMatrixTensorAddressingNV",
+          "value" : 5433,
+          "extensions" : [ "SPV_NV_cooperative_matrix2" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "CooperativeMatrixBlockLoadsNV",
+          "value" : 5434,
+          "extensions" : [ "SPV_NV_cooperative_matrix2" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "TensorAddressingNV",
+          "value" : 5439,
+          "extensions" : [ "SPV_NV_tensor_addressing" ],
+          "version" : "None"
+        },
         {
           "enumerant" : "SubgroupShuffleINTEL",
           "value" : 5568,
@@ -16231,23 +16419,14 @@
         },
         {
           "enumerant" : "DotProductInputAll",
-          "value" : 6016,
-          "version" : "1.6"
-        },
-        {
-          "enumerant" : "DotProductInputAllKHR",
+          "aliases" : ["DotProductInputAllKHR"],
           "value" : 6016,
           "extensions" : [ "SPV_KHR_integer_dot_product" ],
           "version" : "1.6"
         },
         {
           "enumerant" : "DotProductInput4x8Bit",
-          "value" : 6017,
-          "capabilities" : [ "Int8" ],
-          "version" : "1.6"
-        },
-        {
-          "enumerant" : "DotProductInput4x8BitKHR",
+          "aliases" : ["DotProductInput4x8BitKHR"],
           "value" : 6017,
           "capabilities" : [ "Int8" ],
           "extensions" : [ "SPV_KHR_integer_dot_product" ],
@@ -16255,22 +16434,14 @@
         },
         {
           "enumerant" : "DotProductInput4x8BitPacked",
-          "value" : 6018,
-          "version" : "1.6"
-        },
-        {
-          "enumerant" : "DotProductInput4x8BitPackedKHR",
+          "aliases" : ["DotProductInput4x8BitPackedKHR"],
           "value" : 6018,
           "extensions" : [ "SPV_KHR_integer_dot_product" ],
           "version" : "1.6"
         },
         {
           "enumerant" : "DotProduct",
-          "value" : 6019,
-          "version" : "1.6"
-        },
-        {
-          "enumerant" : "DotProductKHR",
+          "aliases" : ["DotProductKHR"],
           "value" : 6019,
           "extensions" : [ "SPV_KHR_integer_dot_product" ],
           "version" : "1.6"
@@ -16287,6 +16458,12 @@
           "extensions" : [ "SPV_KHR_cooperative_matrix" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "ReplicatedCompositesEXT",
+          "value" : 6024,
+          "extensions" : [ "SPV_EXT_replicated_composites" ],
+          "version" : "None"
+        },
         {
           "enumerant" : "BitInstructions",
           "value" : 6025,
@@ -16325,9 +16502,10 @@
           "version" : "None"
         },
         {
-          "enumerant" : "OptNoneINTEL",
+          "enumerant" : "OptNoneEXT",
+          "aliases" : ["OptNoneINTEL"],
           "value" : 6094,
-          "extensions" : [ "SPV_INTEL_optnone" ],
+          "extensions" : [ "SPV_EXT_optnone", "SPV_INTEL_optnone" ],
           "version" : "None"
         },
         {
@@ -16354,6 +16532,12 @@
           "extensions" : [ "SPV_INTEL_split_barrier" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "ArithmeticFenceEXT",
+          "value" : 6144,
+          "extensions" : [ "SPV_EXT_arithmetic_fence" ],
+          "version" : "None"
+        },
         {
           "enumerant" : "FPGAClusterAttributesV2INTEL",
           "value" : 6150,
@@ -16398,6 +16582,12 @@
           "extensions": [ "SPV_INTEL_global_variable_fpga_decorations" ],
           "version" : "None"
         },
+        {
+          "enumerant" : "SubgroupBufferPrefetchINTEL",
+          "value" : 6220,
+          "extensions": [ "SPV_INTEL_subgroup_buffer_prefetch" ],
+          "version" : "None"
+        },
         {
           "enumerant" : "GroupUniformArithmeticKHR",
           "value" : 6400,
@@ -16415,6 +16605,12 @@
           "value" : 6441,
           "extensions" : [ "SPV_INTEL_cache_controls" ],
           "version" : "None"
+        },
+        {
+          "enumerant" : "RegisterLimitsINTEL",
+          "value" : 6460,
+          "extensions" : [ "SPV_INTEL_maximum_registers" ],
+          "version" : "None"
         }
       ]
     },
@@ -16484,11 +16680,7 @@
       "enumerants" : [
         {
           "enumerant" : "PackedVectorFormat4x8Bit",
-          "value" : 0,
-          "version" : "1.6"
-        },
-        {
-          "enumerant" : "PackedVectorFormat4x8BitKHR",
+          "aliases" : ["PackedVectorFormat4x8BitKHR"],
           "value" : 0,
           "extensions" : [ "SPV_KHR_integer_dot_product" ],
           "version" : "1.6"
@@ -16544,6 +16736,16 @@
           "enumerant" : "ColumnMajorKHR",
           "value" : 1,
           "version" : "None"
+        },
+        {
+          "enumerant" : "RowBlockedInterleavedARM",
+          "value" : 4202,
+          "version" : "None"
+        },
+        {
+          "enumerant" : "ColumnBlockedInterleavedARM",
+          "value" : 4203,
+          "version" : "None"
         }
       ]
     },
@@ -16568,6 +16770,87 @@
         }
       ]
     },
+    {
+      "category" : "BitEnum",
+      "kind" : "CooperativeMatrixReduce",
+      "enumerants" : [
+        {
+          "enumerant" : "Row",
+          "value" : "0x0001",
+          "version" : "None"
+        },
+        {
+          "enumerant" : "Column",
+          "value" : "0x0002",
+          "version" : "None"
+        },
+        {
+          "enumerant" : "2x2",
+          "value" : "0x0004",
+          "version" : "None"
+        }
+      ]
+    },
+    {
+      "category" : "ValueEnum",
+      "kind" : "TensorClampMode",
+      "enumerants" : [
+        {
+          "enumerant" : "Undefined",
+          "value" : 0,
+          "version": "None"
+        },
+        {
+          "enumerant" : "Constant",
+          "value" : 1,
+          "version": "None"
+        },
+        {
+          "enumerant" : "ClampToEdge",
+          "value" : 2,
+          "version": "None"
+        },
+        {
+          "enumerant" : "Repeat",
+          "value" : 3,
+          "version": "None"
+        },
+        {
+          "enumerant" : "RepeatMirrored",
+          "value" : 4,
+          "version": "None"
+        }
+      ]
+    },
+    {
+      "category" : "BitEnum",
+      "kind" : "TensorAddressingOperands",
+      "enumerants" : [
+        {
+          "enumerant" : "None",
+          "value" : "0x0000",
+          "version" : "None"
+        },
+        {
+          "enumerant" : "TensorView",
+          "value" : "0x0001",
+          "parameters" : [
+            { "kind" : "IdRef" }
+          ],
+          "capabilities" : [ "CooperativeMatrixTensorAddressingNV" ],
+          "version" : "None"
+        },
+        {
+          "enumerant" : "DecodeFunc",
+          "value" : "0x0002",
+          "parameters" : [
+            { "kind" : "IdRef" }
+          ],
+          "capabilities" : [ "CooperativeMatrixBlockLoadsNV" ],
+          "version" : "None"
+        }
+      ]
+    },
     {
       "category" : "ValueEnum",
       "kind" : "InitializationModeQualifier",
@@ -16652,6 +16935,24 @@
         }
       ]
     },
+    {
+      "category" : "ValueEnum",
+      "kind" : "NamedMaximumNumberOfRegisters",
+      "enumerants" : [
+        {
+          "enumerant" : "AutoINTEL",
+          "value" : 0,
+          "capabilities" : [ "RegisterLimitsINTEL" ],
+          "version" : "None"
+        }
+      ]
+    },
+    {
+      "category" : "ValueEnum",
+      "kind" : "FPEncoding",
+      "enumerants" : [
+      ]
+    },
     {
       "category" : "Id",
       "kind" : "IdResultType",
diff --git a/include/spirv/unified1/spirv.cs b/include/spirv/unified1/spirv.cs
index 41bbbf1..c01cf94 100644
--- a/include/spirv/unified1/spirv.cs
+++ b/include/spirv/unified1/spirv.cs
@@ -12,7 +12,7 @@
 // 
 // MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 // STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
 // 
 // THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -70,6 +70,7 @@ namespace Spv
             WGSL = 10,
             Slang = 11,
             Zig = 12,
+            Max = 0x7fffffff,
         }
 
         public enum ExecutionModel
@@ -97,6 +98,7 @@ namespace Spv
             CallableNV = 5318,
             TaskEXT = 5364,
             MeshEXT = 5365,
+            Max = 0x7fffffff,
         }
 
         public enum AddressingModel
@@ -106,6 +108,7 @@ namespace Spv
             Physical64 = 2,
             PhysicalStorageBuffer64 = 5348,
             PhysicalStorageBuffer64EXT = 5348,
+            Max = 0x7fffffff,
         }
 
         public enum MemoryModel
@@ -115,6 +118,7 @@ namespace Spv
             OpenCL = 2,
             Vulkan = 3,
             VulkanKHR = 3,
+            Max = 0x7fffffff,
         }
 
         public enum ExecutionMode
@@ -170,6 +174,7 @@ namespace Spv
             EarlyAndLateFragmentTestsAMD = 5017,
             StencilRefReplacingEXT = 5027,
             CoalescingAMDX = 5069,
+            IsApiEntryAMDX = 5070,
             MaxNodeRecursionAMDX = 5071,
             StaticNumWorkgroupsAMDX = 5072,
             ShaderIndexAMDX = 5073,
@@ -182,11 +187,14 @@ namespace Spv
             StencilRefLessBackAMD = 5084,
             QuadDerivativesKHR = 5088,
             RequireFullQuadsKHR = 5089,
+            SharesInputWithAMDX = 5102,
             OutputLinesEXT = 5269,
             OutputLinesNV = 5269,
             OutputPrimitivesEXT = 5270,
             OutputPrimitivesNV = 5270,
+            DerivativeGroupQuadsKHR = 5289,
             DerivativeGroupQuadsNV = 5289,
+            DerivativeGroupLinearKHR = 5290,
             DerivativeGroupLinearNV = 5290,
             OutputTrianglesEXT = 5298,
             OutputTrianglesNV = 5298,
@@ -211,6 +219,10 @@ namespace Spv
             StreamingInterfaceINTEL = 6154,
             RegisterMapInterfaceINTEL = 6160,
             NamedBarrierCountINTEL = 6417,
+            MaximumRegistersINTEL = 6461,
+            MaximumRegistersIdINTEL = 6462,
+            NamedMaximumRegistersINTEL = 6463,
+            Max = 0x7fffffff,
         }
 
         public enum StorageClass
@@ -230,7 +242,6 @@ namespace Spv
             StorageBuffer = 12,
             TileImageEXT = 4172,
             NodePayloadAMDX = 5068,
-            NodeOutputPayloadAMDX = 5076,
             CallableDataKHR = 5328,
             CallableDataNV = 5328,
             IncomingCallableDataKHR = 5329,
@@ -250,6 +261,7 @@ namespace Spv
             CodeSectionINTEL = 5605,
             DeviceOnlyINTEL = 5936,
             HostOnlyINTEL = 5937,
+            Max = 0x7fffffff,
         }
 
         public enum Dim
@@ -262,6 +274,7 @@ namespace Spv
             Buffer = 5,
             SubpassData = 6,
             TileImageDataEXT = 4173,
+            Max = 0x7fffffff,
         }
 
         public enum SamplerAddressingMode
@@ -271,12 +284,14 @@ namespace Spv
             Clamp = 2,
             Repeat = 3,
             RepeatMirrored = 4,
+            Max = 0x7fffffff,
         }
 
         public enum SamplerFilterMode
         {
             Nearest = 0,
             Linear = 1,
+            Max = 0x7fffffff,
         }
 
         public enum ImageFormat
@@ -323,6 +338,7 @@ namespace Spv
             R8ui = 39,
             R64ui = 40,
             R64i = 41,
+            Max = 0x7fffffff,
         }
 
         public enum ImageChannelOrder
@@ -347,6 +363,7 @@ namespace Spv
             sRGBA = 17,
             sBGRA = 18,
             ABGR = 19,
+            Max = 0x7fffffff,
         }
 
         public enum ImageChannelDataType
@@ -370,6 +387,8 @@ namespace Spv
             UnormInt101010_2 = 16,
             UnsignedIntRaw10EXT = 19,
             UnsignedIntRaw12EXT = 20,
+            UnormInt2_101010EXT = 21,
+            Max = 0x7fffffff,
         }
 
         public enum ImageOperandsShift
@@ -394,6 +413,7 @@ namespace Spv
             ZeroExtend = 13,
             Nontemporal = 14,
             Offsets = 16,
+            Max = 0x7fffffff,
         }
 
         public enum ImageOperandsMask
@@ -433,6 +453,7 @@ namespace Spv
             AllowReassoc = 17,
             AllowReassocINTEL = 17,
             AllowTransform = 18,
+            Max = 0x7fffffff,
         }
 
         public enum FPFastMathModeMask
@@ -456,6 +477,7 @@ namespace Spv
             RTZ = 1,
             RTP = 2,
             RTN = 3,
+            Max = 0x7fffffff,
         }
 
         public enum LinkageType
@@ -463,6 +485,7 @@ namespace Spv
             Export = 0,
             Import = 1,
             LinkOnceODR = 2,
+            Max = 0x7fffffff,
         }
 
         public enum AccessQualifier
@@ -470,6 +493,7 @@ namespace Spv
             ReadOnly = 0,
             WriteOnly = 1,
             ReadWrite = 2,
+            Max = 0x7fffffff,
         }
 
         public enum FunctionParameterAttribute
@@ -483,6 +507,7 @@ namespace Spv
             NoWrite = 6,
             NoReadWrite = 7,
             RuntimeAlignedINTEL = 5940,
+            Max = 0x7fffffff,
         }
 
         public enum Decoration
@@ -538,11 +563,16 @@ namespace Spv
             NoUnsignedWrap = 4470,
             WeightTextureQCOM = 4487,
             BlockMatchTextureQCOM = 4488,
+            BlockMatchSamplerQCOM = 4499,
             ExplicitInterpAMD = 4999,
             NodeSharesPayloadLimitsWithAMDX = 5019,
             NodeMaxPayloadsAMDX = 5020,
             TrackFinishWritingAMDX = 5078,
             PayloadNodeNameAMDX = 5091,
+            PayloadNodeBaseIndexAMDX = 5098,
+            PayloadNodeSparseArrayAMDX = 5099,
+            PayloadNodeArraySizeAMDX = 5100,
+            PayloadDispatchIndirectAMDX = 5105,
             OverrideCoverageNV = 5248,
             PassthroughNV = 5250,
             ViewportRelativeNV = 5252,
@@ -631,6 +661,7 @@ namespace Spv
             ImplementInRegisterMapINTEL = 6191,
             CacheControlLoadINTEL = 6442,
             CacheControlStoreINTEL = 6443,
+            Max = 0x7fffffff,
         }
 
         public enum BuiltIn
@@ -706,7 +737,7 @@ namespace Spv
             BaryCoordSmoothSampleAMD = 4997,
             BaryCoordPullModelAMD = 4998,
             FragStencilRefEXT = 5014,
-            CoalescedInputCountAMDX = 5021,
+            RemainingRecursionLevelsAMDX = 5021,
             ShaderIndexAMDX = 5073,
             ViewportMaskNV = 5253,
             SecondaryPositionNV = 5257,
@@ -773,12 +804,14 @@ namespace Spv
             HitKindFrontFacingMicroTriangleNV = 5405,
             HitKindBackFacingMicroTriangleNV = 5406,
             CullMaskKHR = 6021,
+            Max = 0x7fffffff,
         }
 
         public enum SelectionControlShift
         {
             Flatten = 0,
             DontFlatten = 1,
+            Max = 0x7fffffff,
         }
 
         public enum SelectionControlMask
@@ -809,6 +842,7 @@ namespace Spv
             NoFusionINTEL = 23,
             LoopCountINTEL = 24,
             MaxReinvocationDelayINTEL = 25,
+            Max = 0x7fffffff,
         }
 
         public enum LoopControlMask
@@ -841,7 +875,9 @@ namespace Spv
             DontInline = 1,
             Pure = 2,
             Const = 3,
+            OptNoneEXT = 16,
             OptNoneINTEL = 16,
+            Max = 0x7fffffff,
         }
 
         public enum FunctionControlMask
@@ -851,6 +887,7 @@ namespace Spv
             DontInline = 0x00000002,
             Pure = 0x00000004,
             Const = 0x00000008,
+            OptNoneEXT = 0x00010000,
             OptNoneINTEL = 0x00010000,
         }
 
@@ -873,6 +910,7 @@ namespace Spv
             MakeVisible = 14,
             MakeVisibleKHR = 14,
             Volatile = 15,
+            Max = 0x7fffffff,
         }
 
         public enum MemorySemanticsMask
@@ -910,6 +948,7 @@ namespace Spv
             NonPrivatePointerKHR = 5,
             AliasScopeINTELMask = 16,
             NoAliasINTELMask = 17,
+            Max = 0x7fffffff,
         }
 
         public enum MemoryAccessMask
@@ -938,6 +977,7 @@ namespace Spv
             QueueFamily = 5,
             QueueFamilyKHR = 5,
             ShaderCallKHR = 6,
+            Max = 0x7fffffff,
         }
 
         public enum GroupOperation
@@ -949,6 +989,7 @@ namespace Spv
             PartitionedReduceNV = 6,
             PartitionedInclusiveScanNV = 7,
             PartitionedExclusiveScanNV = 8,
+            Max = 0x7fffffff,
         }
 
         public enum KernelEnqueueFlags
@@ -956,11 +997,13 @@ namespace Spv
             NoWait = 0,
             WaitKernel = 1,
             WaitWorkGroup = 2,
+            Max = 0x7fffffff,
         }
 
         public enum KernelProfilingInfoShift
         {
             CmdExecTime = 0,
+            Max = 0x7fffffff,
         }
 
         public enum KernelProfilingInfoMask
@@ -1045,6 +1088,7 @@ namespace Spv
             TileImageColorReadAccessEXT = 4166,
             TileImageDepthReadAccessEXT = 4167,
             TileImageStencilReadAccessEXT = 4168,
+            CooperativeMatrixLayoutsARM = 4201,
             FragmentShadingRateKHR = 4422,
             SubgroupBallotKHR = 4423,
             DrawParameters = 4427,
@@ -1074,11 +1118,13 @@ namespace Spv
             RoundingModeRTZ = 4468,
             RayQueryProvisionalKHR = 4471,
             RayQueryKHR = 4472,
+            UntypedPointersKHR = 4473,
             RayTraversalPrimitiveCullingKHR = 4478,
             RayTracingKHR = 4479,
             TextureSampleWeightedQCOM = 4484,
             TextureBoxFilterQCOM = 4485,
             TextureBlockMatchQCOM = 4486,
+            TextureBlockMatch2QCOM = 4498,
             Float16ImageAMD = 5008,
             ImageGatherBiasLodAMD = 5009,
             FragmentMaskAMD = 5010,
@@ -1101,6 +1147,7 @@ namespace Spv
             MeshShadingEXT = 5283,
             FragmentBarycentricKHR = 5284,
             FragmentBarycentricNV = 5284,
+            ComputeDerivativeGroupQuadsKHR = 5288,
             ComputeDerivativeGroupQuadsNV = 5288,
             FragmentDensityEXT = 5291,
             ShadingRateNV = 5291,
@@ -1138,6 +1185,7 @@ namespace Spv
             VulkanMemoryModelDeviceScopeKHR = 5346,
             PhysicalStorageBufferAddresses = 5347,
             PhysicalStorageBufferAddressesEXT = 5347,
+            ComputeDerivativeGroupLinearKHR = 5350,
             ComputeDerivativeGroupLinearNV = 5350,
             RayTracingProvisionalKHR = 5353,
             CooperativeMatrixNV = 5357,
@@ -1152,7 +1200,15 @@ namespace Spv
             ShaderInvocationReorderNV = 5383,
             BindlessTextureNV = 5390,
             RayQueryPositionFetchKHR = 5391,
+            AtomicFloat16VectorNV = 5404,
             RayTracingDisplacementMicromapNV = 5409,
+            RawAccessChainsNV = 5414,
+            CooperativeMatrixReductionsNV = 5430,
+            CooperativeMatrixConversionsNV = 5431,
+            CooperativeMatrixPerElementOperationsNV = 5432,
+            CooperativeMatrixTensorAddressingNV = 5433,
+            CooperativeMatrixBlockLoadsNV = 5434,
+            TensorAddressingNV = 5439,
             SubgroupShuffleINTEL = 5568,
             SubgroupBufferBlockIOINTEL = 5569,
             SubgroupImageBlockIOINTEL = 5570,
@@ -1205,17 +1261,20 @@ namespace Spv
             DotProductKHR = 6019,
             RayCullMaskKHR = 6020,
             CooperativeMatrixKHR = 6022,
+            ReplicatedCompositesEXT = 6024,
             BitInstructions = 6025,
             GroupNonUniformRotateKHR = 6026,
             FloatControls2 = 6029,
             AtomicFloat32AddEXT = 6033,
             AtomicFloat64AddEXT = 6034,
             LongCompositesINTEL = 6089,
+            OptNoneEXT = 6094,
             OptNoneINTEL = 6094,
             AtomicFloat16AddEXT = 6095,
             DebugInfoModuleINTEL = 6114,
             BFloat16ConversionINTEL = 6115,
             SplitBarrierINTEL = 6141,
+            ArithmeticFenceEXT = 6144,
             FPGAClusterAttributesV2INTEL = 6150,
             FPGAKernelAttributesv2INTEL = 6161,
             FPMaxErrorINTEL = 6169,
@@ -1223,9 +1282,12 @@ namespace Spv
             FPGAArgumentInterfacesINTEL = 6174,
             GlobalVariableHostAccessINTEL = 6187,
             GlobalVariableFPGADecorationsINTEL = 6189,
+            SubgroupBufferPrefetchINTEL = 6220,
             GroupUniformArithmeticKHR = 6400,
             MaskedGatherScatterINTEL = 6427,
             CacheControlsINTEL = 6441,
+            RegisterLimitsINTEL = 6460,
+            Max = 0x7fffffff,
         }
 
         public enum RayFlagsShift
@@ -1241,6 +1303,7 @@ namespace Spv
             SkipTrianglesKHR = 8,
             SkipAABBsKHR = 9,
             ForceOpacityMicromap2StateEXT = 10,
+            Max = 0x7fffffff,
         }
 
         public enum RayFlagsMask
@@ -1263,6 +1326,7 @@ namespace Spv
         {
             RayQueryCandidateIntersectionKHR = 0,
             RayQueryCommittedIntersectionKHR = 1,
+            Max = 0x7fffffff,
         }
 
         public enum RayQueryCommittedIntersectionType
@@ -1270,12 +1334,14 @@ namespace Spv
             RayQueryCommittedIntersectionNoneKHR = 0,
             RayQueryCommittedIntersectionTriangleKHR = 1,
             RayQueryCommittedIntersectionGeneratedKHR = 2,
+            Max = 0x7fffffff,
         }
 
         public enum RayQueryCandidateIntersectionType
         {
             RayQueryCandidateIntersectionTriangleKHR = 0,
             RayQueryCandidateIntersectionAABBKHR = 1,
+            Max = 0x7fffffff,
         }
 
         public enum FragmentShadingRateShift
@@ -1284,6 +1350,7 @@ namespace Spv
             Vertical4Pixels = 1,
             Horizontal2Pixels = 2,
             Horizontal4Pixels = 3,
+            Max = 0x7fffffff,
         }
 
         public enum FragmentShadingRateMask
@@ -1299,12 +1366,14 @@ namespace Spv
         {
             Preserve = 0,
             FlushToZero = 1,
+            Max = 0x7fffffff,
         }
 
         public enum FPOperationMode
         {
             IEEE = 0,
             ALT = 1,
+            Max = 0x7fffffff,
         }
 
         public enum QuantizationModes
@@ -1317,6 +1386,7 @@ namespace Spv
             RND_MIN_INF = 5,
             RND_CONV = 6,
             RND_CONV_ODD = 7,
+            Max = 0x7fffffff,
         }
 
         public enum OverflowModes
@@ -1325,12 +1395,14 @@ namespace Spv
             SAT = 1,
             SAT_ZERO = 2,
             SAT_SYM = 3,
+            Max = 0x7fffffff,
         }
 
         public enum PackedVectorFormat
         {
             PackedVectorFormat4x8Bit = 0,
             PackedVectorFormat4x8BitKHR = 0,
+            Max = 0x7fffffff,
         }
 
         public enum CooperativeMatrixOperandsShift
@@ -1340,6 +1412,7 @@ namespace Spv
             MatrixCSignedComponentsKHR = 2,
             MatrixResultSignedComponentsKHR = 3,
             SaturatingAccumulationKHR = 4,
+            Max = 0x7fffffff,
         }
 
         public enum CooperativeMatrixOperandsMask
@@ -1356,6 +1429,9 @@ namespace Spv
         {
             RowMajorKHR = 0,
             ColumnMajorKHR = 1,
+            RowBlockedInterleavedARM = 4202,
+            ColumnBlockedInterleavedARM = 4203,
+            Max = 0x7fffffff,
         }
 
         public enum CooperativeMatrixUse
@@ -1363,12 +1439,54 @@ namespace Spv
             MatrixAKHR = 0,
             MatrixBKHR = 1,
             MatrixAccumulatorKHR = 2,
+            Max = 0x7fffffff,
+        }
+
+        public enum CooperativeMatrixReduceShift
+        {
+            Row = 0,
+            Column = 1,
+            CooperativeMatrixReduce2x2 = 2,
+            Max = 0x7fffffff,
+        }
+
+        public enum CooperativeMatrixReduceMask
+        {
+            MaskNone = 0,
+            Row = 0x00000001,
+            Column = 0x00000002,
+            CooperativeMatrixReduce2x2 = 0x00000004,
+        }
+
+        public enum TensorClampMode
+        {
+            Undefined = 0,
+            Constant = 1,
+            ClampToEdge = 2,
+            Repeat = 3,
+            RepeatMirrored = 4,
+            Max = 0x7fffffff,
+        }
+
+        public enum TensorAddressingOperandsShift
+        {
+            TensorView = 0,
+            DecodeFunc = 1,
+            Max = 0x7fffffff,
+        }
+
+        public enum TensorAddressingOperandsMask
+        {
+            MaskNone = 0,
+            TensorView = 0x00000001,
+            DecodeFunc = 0x00000002,
         }
 
         public enum InitializationModeQualifier
         {
             InitOnDeviceReprogramINTEL = 0,
             InitOnDeviceResetINTEL = 1,
+            Max = 0x7fffffff,
         }
 
         public enum HostAccessQualifier
@@ -1377,6 +1495,7 @@ namespace Spv
             ReadINTEL = 1,
             WriteINTEL = 2,
             ReadWriteINTEL = 3,
+            Max = 0x7fffffff,
         }
 
         public enum LoadCacheControl
@@ -1386,6 +1505,7 @@ namespace Spv
             StreamingINTEL = 2,
             InvalidateAfterReadINTEL = 3,
             ConstCachedINTEL = 4,
+            Max = 0x7fffffff,
         }
 
         public enum StoreCacheControl
@@ -1394,6 +1514,32 @@ namespace Spv
             WriteThroughINTEL = 1,
             WriteBackINTEL = 2,
             StreamingINTEL = 3,
+            Max = 0x7fffffff,
+        }
+
+        public enum NamedMaximumNumberOfRegisters
+        {
+            AutoINTEL = 0,
+            Max = 0x7fffffff,
+        }
+
+        public enum RawAccessChainOperandsShift
+        {
+            RobustnessPerComponentNV = 0,
+            RobustnessPerElementNV = 1,
+            Max = 0x7fffffff,
+        }
+
+        public enum RawAccessChainOperandsMask
+        {
+            MaskNone = 0,
+            RobustnessPerComponentNV = 0x00000001,
+            RobustnessPerElementNV = 0x00000002,
+        }
+
+        public enum FPEncoding
+        {
+            Max = 0x7fffffff,
         }
 
         public enum Op
@@ -1746,13 +1892,22 @@ namespace Spv
             OpDepthAttachmentReadEXT = 4161,
             OpStencilAttachmentReadEXT = 4162,
             OpTerminateInvocation = 4416,
+            OpTypeUntypedPointerKHR = 4417,
+            OpUntypedVariableKHR = 4418,
+            OpUntypedAccessChainKHR = 4419,
+            OpUntypedInBoundsAccessChainKHR = 4420,
             OpSubgroupBallotKHR = 4421,
             OpSubgroupFirstInvocationKHR = 4422,
+            OpUntypedPtrAccessChainKHR = 4423,
+            OpUntypedInBoundsPtrAccessChainKHR = 4424,
+            OpUntypedArrayLengthKHR = 4425,
+            OpUntypedPrefetchKHR = 4426,
             OpSubgroupAllKHR = 4428,
             OpSubgroupAnyKHR = 4429,
             OpSubgroupAllEqualKHR = 4430,
             OpGroupNonUniformRotateKHR = 4431,
             OpSubgroupReadInvocationKHR = 4432,
+            OpExtInstWithForwardRefsKHR = 4433,
             OpTraceRayKHR = 4445,
             OpExecuteCallableKHR = 4446,
             OpConvertUToAccelerationStructureKHR = 4447,
@@ -1775,6 +1930,9 @@ namespace Spv
             OpCooperativeMatrixStoreKHR = 4458,
             OpCooperativeMatrixMulAddKHR = 4459,
             OpCooperativeMatrixLengthKHR = 4460,
+            OpConstantCompositeReplicateEXT = 4461,
+            OpSpecConstantCompositeReplicateEXT = 4462,
+            OpCompositeConstructReplicateEXT = 4463,
             OpTypeRayQueryKHR = 4472,
             OpRayQueryInitializeKHR = 4473,
             OpRayQueryTerminateKHR = 4474,
@@ -1786,6 +1944,10 @@ namespace Spv
             OpImageBoxFilterQCOM = 4481,
             OpImageBlockMatchSSDQCOM = 4482,
             OpImageBlockMatchSADQCOM = 4483,
+            OpImageBlockMatchWindowSSDQCOM = 4500,
+            OpImageBlockMatchWindowSADQCOM = 4501,
+            OpImageBlockMatchGatherSSDQCOM = 4502,
+            OpImageBlockMatchGatherSADQCOM = 4503,
             OpGroupIAddNonUniformAMD = 5000,
             OpGroupFAddNonUniformAMD = 5001,
             OpGroupFMinNonUniformAMD = 5002,
@@ -1797,9 +1959,14 @@ namespace Spv
             OpFragmentMaskFetchAMD = 5011,
             OpFragmentFetchAMD = 5012,
             OpReadClockKHR = 5056,
-            OpFinalizeNodePayloadsAMDX = 5075,
+            OpAllocateNodePayloadsAMDX = 5074,
+            OpEnqueueNodePayloadsAMDX = 5075,
+            OpTypeNodePayloadArrayAMDX = 5076,
             OpFinishWritingNodePayloadAMDX = 5078,
-            OpInitializeNodePayloadsAMDX = 5090,
+            OpNodePayloadArrayLengthAMDX = 5090,
+            OpIsNodePayloadValidAMDX = 5101,
+            OpConstantStringAMDX = 5103,
+            OpSpecConstantStringAMDX = 5104,
             OpGroupNonUniformQuadAllKHR = 5110,
             OpGroupNonUniformQuadAnyKHR = 5111,
             OpHitObjectRecordHitMotionNV = 5249,
@@ -1836,6 +2003,7 @@ namespace Spv
             OpReorderThreadWithHintNV = 5280,
             OpTypeHitObjectNV = 5281,
             OpImageSampleFootprintNV = 5283,
+            OpCooperativeMatrixConvertNV = 5293,
             OpEmitMeshTasksEXT = 5294,
             OpSetMeshOutputsEXT = 5295,
             OpGroupNonUniformPartitionNV = 5296,
@@ -1860,9 +2028,26 @@ namespace Spv
             OpCooperativeMatrixLengthNV = 5362,
             OpBeginInvocationInterlockEXT = 5364,
             OpEndInvocationInterlockEXT = 5365,
+            OpCooperativeMatrixReduceNV = 5366,
+            OpCooperativeMatrixLoadTensorNV = 5367,
+            OpCooperativeMatrixStoreTensorNV = 5368,
+            OpCooperativeMatrixPerElementOpNV = 5369,
+            OpTypeTensorLayoutNV = 5370,
+            OpTypeTensorViewNV = 5371,
+            OpCreateTensorLayoutNV = 5372,
+            OpTensorLayoutSetDimensionNV = 5373,
+            OpTensorLayoutSetStrideNV = 5374,
+            OpTensorLayoutSliceNV = 5375,
+            OpTensorLayoutSetClampValueNV = 5376,
+            OpCreateTensorViewNV = 5377,
+            OpTensorViewSetDimensionNV = 5378,
+            OpTensorViewSetStrideNV = 5379,
             OpDemoteToHelperInvocation = 5380,
             OpDemoteToHelperInvocationEXT = 5380,
             OpIsHelperInvocationEXT = 5381,
+            OpTensorViewSetClipNV = 5382,
+            OpTensorLayoutSetBlockSizeNV = 5384,
+            OpCooperativeMatrixTransposeNV = 5390,
             OpConvertUToImageNV = 5391,
             OpConvertUToSamplerNV = 5392,
             OpConvertImageToUNV = 5393,
@@ -1870,6 +2055,7 @@ namespace Spv
             OpConvertUToSampledImageNV = 5395,
             OpConvertSampledImageToUNV = 5396,
             OpSamplerImageAddressingModeNV = 5397,
+            OpRawAccessChainNV = 5398,
             OpSubgroupShuffleINTEL = 5571,
             OpSubgroupShuffleDownINTEL = 5572,
             OpSubgroupShuffleUpINTEL = 5573,
@@ -2116,6 +2302,8 @@ namespace Spv
             OpConvertBF16ToFINTEL = 6117,
             OpControlBarrierArriveINTEL = 6142,
             OpControlBarrierWaitINTEL = 6143,
+            OpArithmeticFenceEXT = 6145,
+            OpSubgroupBlockPrefetchINTEL = 6221,
             OpGroupIMulKHR = 6401,
             OpGroupFMulKHR = 6402,
             OpGroupBitwiseAndKHR = 6403,
@@ -2126,6 +2314,7 @@ namespace Spv
             OpGroupLogicalXorKHR = 6408,
             OpMaskedGatherINTEL = 6428,
             OpMaskedScatterINTEL = 6429,
+            Max = 0x7fffffff,
         }
     }
 }
diff --git a/include/spirv/unified1/spirv.h b/include/spirv/unified1/spirv.h
index a68b7a1..9b1793c 100644
--- a/include/spirv/unified1/spirv.h
+++ b/include/spirv/unified1/spirv.h
@@ -13,7 +13,7 @@
 ** 
 ** MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 ** STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-** HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+** HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
 ** 
 ** THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 ** OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -178,6 +178,7 @@ typedef enum SpvExecutionMode_ {
     SpvExecutionModeEarlyAndLateFragmentTestsAMD = 5017,
     SpvExecutionModeStencilRefReplacingEXT = 5027,
     SpvExecutionModeCoalescingAMDX = 5069,
+    SpvExecutionModeIsApiEntryAMDX = 5070,
     SpvExecutionModeMaxNodeRecursionAMDX = 5071,
     SpvExecutionModeStaticNumWorkgroupsAMDX = 5072,
     SpvExecutionModeShaderIndexAMDX = 5073,
@@ -190,11 +191,14 @@ typedef enum SpvExecutionMode_ {
     SpvExecutionModeStencilRefLessBackAMD = 5084,
     SpvExecutionModeQuadDerivativesKHR = 5088,
     SpvExecutionModeRequireFullQuadsKHR = 5089,
+    SpvExecutionModeSharesInputWithAMDX = 5102,
     SpvExecutionModeOutputLinesEXT = 5269,
     SpvExecutionModeOutputLinesNV = 5269,
     SpvExecutionModeOutputPrimitivesEXT = 5270,
     SpvExecutionModeOutputPrimitivesNV = 5270,
+    SpvExecutionModeDerivativeGroupQuadsKHR = 5289,
     SpvExecutionModeDerivativeGroupQuadsNV = 5289,
+    SpvExecutionModeDerivativeGroupLinearKHR = 5290,
     SpvExecutionModeDerivativeGroupLinearNV = 5290,
     SpvExecutionModeOutputTrianglesEXT = 5298,
     SpvExecutionModeOutputTrianglesNV = 5298,
@@ -219,6 +223,9 @@ typedef enum SpvExecutionMode_ {
     SpvExecutionModeStreamingInterfaceINTEL = 6154,
     SpvExecutionModeRegisterMapInterfaceINTEL = 6160,
     SpvExecutionModeNamedBarrierCountINTEL = 6417,
+    SpvExecutionModeMaximumRegistersINTEL = 6461,
+    SpvExecutionModeMaximumRegistersIdINTEL = 6462,
+    SpvExecutionModeNamedMaximumRegistersINTEL = 6463,
     SpvExecutionModeMax = 0x7fffffff,
 } SpvExecutionMode;
 
@@ -238,7 +245,6 @@ typedef enum SpvStorageClass_ {
     SpvStorageClassStorageBuffer = 12,
     SpvStorageClassTileImageEXT = 4172,
     SpvStorageClassNodePayloadAMDX = 5068,
-    SpvStorageClassNodeOutputPayloadAMDX = 5076,
     SpvStorageClassCallableDataKHR = 5328,
     SpvStorageClassCallableDataNV = 5328,
     SpvStorageClassIncomingCallableDataKHR = 5329,
@@ -378,6 +384,7 @@ typedef enum SpvImageChannelDataType_ {
     SpvImageChannelDataTypeUnormInt101010_2 = 16,
     SpvImageChannelDataTypeUnsignedIntRaw10EXT = 19,
     SpvImageChannelDataTypeUnsignedIntRaw12EXT = 20,
+    SpvImageChannelDataTypeUnormInt2_101010EXT = 21,
     SpvImageChannelDataTypeMax = 0x7fffffff,
 } SpvImageChannelDataType;
 
@@ -544,11 +551,16 @@ typedef enum SpvDecoration_ {
     SpvDecorationNoUnsignedWrap = 4470,
     SpvDecorationWeightTextureQCOM = 4487,
     SpvDecorationBlockMatchTextureQCOM = 4488,
+    SpvDecorationBlockMatchSamplerQCOM = 4499,
     SpvDecorationExplicitInterpAMD = 4999,
     SpvDecorationNodeSharesPayloadLimitsWithAMDX = 5019,
     SpvDecorationNodeMaxPayloadsAMDX = 5020,
     SpvDecorationTrackFinishWritingAMDX = 5078,
     SpvDecorationPayloadNodeNameAMDX = 5091,
+    SpvDecorationPayloadNodeBaseIndexAMDX = 5098,
+    SpvDecorationPayloadNodeSparseArrayAMDX = 5099,
+    SpvDecorationPayloadNodeArraySizeAMDX = 5100,
+    SpvDecorationPayloadDispatchIndirectAMDX = 5105,
     SpvDecorationOverrideCoverageNV = 5248,
     SpvDecorationPassthroughNV = 5250,
     SpvDecorationViewportRelativeNV = 5252,
@@ -712,7 +724,7 @@ typedef enum SpvBuiltIn_ {
     SpvBuiltInBaryCoordSmoothSampleAMD = 4997,
     SpvBuiltInBaryCoordPullModelAMD = 4998,
     SpvBuiltInFragStencilRefEXT = 5014,
-    SpvBuiltInCoalescedInputCountAMDX = 5021,
+    SpvBuiltInRemainingRecursionLevelsAMDX = 5021,
     SpvBuiltInShaderIndexAMDX = 5073,
     SpvBuiltInViewportMaskNV = 5253,
     SpvBuiltInSecondaryPositionNV = 5257,
@@ -845,6 +857,7 @@ typedef enum SpvFunctionControlShift_ {
     SpvFunctionControlDontInlineShift = 1,
     SpvFunctionControlPureShift = 2,
     SpvFunctionControlConstShift = 3,
+    SpvFunctionControlOptNoneEXTShift = 16,
     SpvFunctionControlOptNoneINTELShift = 16,
     SpvFunctionControlMax = 0x7fffffff,
 } SpvFunctionControlShift;
@@ -855,6 +868,7 @@ typedef enum SpvFunctionControlMask_ {
     SpvFunctionControlDontInlineMask = 0x00000002,
     SpvFunctionControlPureMask = 0x00000004,
     SpvFunctionControlConstMask = 0x00000008,
+    SpvFunctionControlOptNoneEXTMask = 0x00010000,
     SpvFunctionControlOptNoneINTELMask = 0x00010000,
 } SpvFunctionControlMask;
 
@@ -1045,6 +1059,7 @@ typedef enum SpvCapability_ {
     SpvCapabilityTileImageColorReadAccessEXT = 4166,
     SpvCapabilityTileImageDepthReadAccessEXT = 4167,
     SpvCapabilityTileImageStencilReadAccessEXT = 4168,
+    SpvCapabilityCooperativeMatrixLayoutsARM = 4201,
     SpvCapabilityFragmentShadingRateKHR = 4422,
     SpvCapabilitySubgroupBallotKHR = 4423,
     SpvCapabilityDrawParameters = 4427,
@@ -1074,11 +1089,13 @@ typedef enum SpvCapability_ {
     SpvCapabilityRoundingModeRTZ = 4468,
     SpvCapabilityRayQueryProvisionalKHR = 4471,
     SpvCapabilityRayQueryKHR = 4472,
+    SpvCapabilityUntypedPointersKHR = 4473,
     SpvCapabilityRayTraversalPrimitiveCullingKHR = 4478,
     SpvCapabilityRayTracingKHR = 4479,
     SpvCapabilityTextureSampleWeightedQCOM = 4484,
     SpvCapabilityTextureBoxFilterQCOM = 4485,
     SpvCapabilityTextureBlockMatchQCOM = 4486,
+    SpvCapabilityTextureBlockMatch2QCOM = 4498,
     SpvCapabilityFloat16ImageAMD = 5008,
     SpvCapabilityImageGatherBiasLodAMD = 5009,
     SpvCapabilityFragmentMaskAMD = 5010,
@@ -1101,6 +1118,7 @@ typedef enum SpvCapability_ {
     SpvCapabilityMeshShadingEXT = 5283,
     SpvCapabilityFragmentBarycentricKHR = 5284,
     SpvCapabilityFragmentBarycentricNV = 5284,
+    SpvCapabilityComputeDerivativeGroupQuadsKHR = 5288,
     SpvCapabilityComputeDerivativeGroupQuadsNV = 5288,
     SpvCapabilityFragmentDensityEXT = 5291,
     SpvCapabilityShadingRateNV = 5291,
@@ -1138,6 +1156,7 @@ typedef enum SpvCapability_ {
     SpvCapabilityVulkanMemoryModelDeviceScopeKHR = 5346,
     SpvCapabilityPhysicalStorageBufferAddresses = 5347,
     SpvCapabilityPhysicalStorageBufferAddressesEXT = 5347,
+    SpvCapabilityComputeDerivativeGroupLinearKHR = 5350,
     SpvCapabilityComputeDerivativeGroupLinearNV = 5350,
     SpvCapabilityRayTracingProvisionalKHR = 5353,
     SpvCapabilityCooperativeMatrixNV = 5357,
@@ -1152,7 +1171,15 @@ typedef enum SpvCapability_ {
     SpvCapabilityShaderInvocationReorderNV = 5383,
     SpvCapabilityBindlessTextureNV = 5390,
     SpvCapabilityRayQueryPositionFetchKHR = 5391,
+    SpvCapabilityAtomicFloat16VectorNV = 5404,
     SpvCapabilityRayTracingDisplacementMicromapNV = 5409,
+    SpvCapabilityRawAccessChainsNV = 5414,
+    SpvCapabilityCooperativeMatrixReductionsNV = 5430,
+    SpvCapabilityCooperativeMatrixConversionsNV = 5431,
+    SpvCapabilityCooperativeMatrixPerElementOperationsNV = 5432,
+    SpvCapabilityCooperativeMatrixTensorAddressingNV = 5433,
+    SpvCapabilityCooperativeMatrixBlockLoadsNV = 5434,
+    SpvCapabilityTensorAddressingNV = 5439,
     SpvCapabilitySubgroupShuffleINTEL = 5568,
     SpvCapabilitySubgroupBufferBlockIOINTEL = 5569,
     SpvCapabilitySubgroupImageBlockIOINTEL = 5570,
@@ -1205,17 +1232,20 @@ typedef enum SpvCapability_ {
     SpvCapabilityDotProductKHR = 6019,
     SpvCapabilityRayCullMaskKHR = 6020,
     SpvCapabilityCooperativeMatrixKHR = 6022,
+    SpvCapabilityReplicatedCompositesEXT = 6024,
     SpvCapabilityBitInstructions = 6025,
     SpvCapabilityGroupNonUniformRotateKHR = 6026,
     SpvCapabilityFloatControls2 = 6029,
     SpvCapabilityAtomicFloat32AddEXT = 6033,
     SpvCapabilityAtomicFloat64AddEXT = 6034,
     SpvCapabilityLongCompositesINTEL = 6089,
+    SpvCapabilityOptNoneEXT = 6094,
     SpvCapabilityOptNoneINTEL = 6094,
     SpvCapabilityAtomicFloat16AddEXT = 6095,
     SpvCapabilityDebugInfoModuleINTEL = 6114,
     SpvCapabilityBFloat16ConversionINTEL = 6115,
     SpvCapabilitySplitBarrierINTEL = 6141,
+    SpvCapabilityArithmeticFenceEXT = 6144,
     SpvCapabilityFPGAClusterAttributesV2INTEL = 6150,
     SpvCapabilityFPGAKernelAttributesv2INTEL = 6161,
     SpvCapabilityFPMaxErrorINTEL = 6169,
@@ -1223,9 +1253,11 @@ typedef enum SpvCapability_ {
     SpvCapabilityFPGAArgumentInterfacesINTEL = 6174,
     SpvCapabilityGlobalVariableHostAccessINTEL = 6187,
     SpvCapabilityGlobalVariableFPGADecorationsINTEL = 6189,
+    SpvCapabilitySubgroupBufferPrefetchINTEL = 6220,
     SpvCapabilityGroupUniformArithmeticKHR = 6400,
     SpvCapabilityMaskedGatherScatterINTEL = 6427,
     SpvCapabilityCacheControlsINTEL = 6441,
+    SpvCapabilityRegisterLimitsINTEL = 6460,
     SpvCapabilityMax = 0x7fffffff,
 } SpvCapability;
 
@@ -1353,6 +1385,8 @@ typedef enum SpvCooperativeMatrixOperandsMask_ {
 typedef enum SpvCooperativeMatrixLayout_ {
     SpvCooperativeMatrixLayoutRowMajorKHR = 0,
     SpvCooperativeMatrixLayoutColumnMajorKHR = 1,
+    SpvCooperativeMatrixLayoutRowBlockedInterleavedARM = 4202,
+    SpvCooperativeMatrixLayoutColumnBlockedInterleavedARM = 4203,
     SpvCooperativeMatrixLayoutMax = 0x7fffffff,
 } SpvCooperativeMatrixLayout;
 
@@ -1363,6 +1397,41 @@ typedef enum SpvCooperativeMatrixUse_ {
     SpvCooperativeMatrixUseMax = 0x7fffffff,
 } SpvCooperativeMatrixUse;
 
+typedef enum SpvCooperativeMatrixReduceShift_ {
+    SpvCooperativeMatrixReduceRowShift = 0,
+    SpvCooperativeMatrixReduceColumnShift = 1,
+    SpvCooperativeMatrixReduce2x2Shift = 2,
+    SpvCooperativeMatrixReduceMax = 0x7fffffff,
+} SpvCooperativeMatrixReduceShift;
+
+typedef enum SpvCooperativeMatrixReduceMask_ {
+    SpvCooperativeMatrixReduceMaskNone = 0,
+    SpvCooperativeMatrixReduceRowMask = 0x00000001,
+    SpvCooperativeMatrixReduceColumnMask = 0x00000002,
+    SpvCooperativeMatrixReduce2x2Mask = 0x00000004,
+} SpvCooperativeMatrixReduceMask;
+
+typedef enum SpvTensorClampMode_ {
+    SpvTensorClampModeUndefined = 0,
+    SpvTensorClampModeConstant = 1,
+    SpvTensorClampModeClampToEdge = 2,
+    SpvTensorClampModeRepeat = 3,
+    SpvTensorClampModeRepeatMirrored = 4,
+    SpvTensorClampModeMax = 0x7fffffff,
+} SpvTensorClampMode;
+
+typedef enum SpvTensorAddressingOperandsShift_ {
+    SpvTensorAddressingOperandsTensorViewShift = 0,
+    SpvTensorAddressingOperandsDecodeFuncShift = 1,
+    SpvTensorAddressingOperandsMax = 0x7fffffff,
+} SpvTensorAddressingOperandsShift;
+
+typedef enum SpvTensorAddressingOperandsMask_ {
+    SpvTensorAddressingOperandsMaskNone = 0,
+    SpvTensorAddressingOperandsTensorViewMask = 0x00000001,
+    SpvTensorAddressingOperandsDecodeFuncMask = 0x00000002,
+} SpvTensorAddressingOperandsMask;
+
 typedef enum SpvInitializationModeQualifier_ {
     SpvInitializationModeQualifierInitOnDeviceReprogramINTEL = 0,
     SpvInitializationModeQualifierInitOnDeviceResetINTEL = 1,
@@ -1394,6 +1463,27 @@ typedef enum SpvStoreCacheControl_ {
     SpvStoreCacheControlMax = 0x7fffffff,
 } SpvStoreCacheControl;
 
+typedef enum SpvNamedMaximumNumberOfRegisters_ {
+    SpvNamedMaximumNumberOfRegistersAutoINTEL = 0,
+    SpvNamedMaximumNumberOfRegistersMax = 0x7fffffff,
+} SpvNamedMaximumNumberOfRegisters;
+
+typedef enum SpvRawAccessChainOperandsShift_ {
+    SpvRawAccessChainOperandsRobustnessPerComponentNVShift = 0,
+    SpvRawAccessChainOperandsRobustnessPerElementNVShift = 1,
+    SpvRawAccessChainOperandsMax = 0x7fffffff,
+} SpvRawAccessChainOperandsShift;
+
+typedef enum SpvRawAccessChainOperandsMask_ {
+    SpvRawAccessChainOperandsMaskNone = 0,
+    SpvRawAccessChainOperandsRobustnessPerComponentNVMask = 0x00000001,
+    SpvRawAccessChainOperandsRobustnessPerElementNVMask = 0x00000002,
+} SpvRawAccessChainOperandsMask;
+
+typedef enum SpvFPEncoding_ {
+    SpvFPEncodingMax = 0x7fffffff,
+} SpvFPEncoding;
+
 typedef enum SpvOp_ {
     SpvOpNop = 0,
     SpvOpUndef = 1,
@@ -1743,13 +1833,22 @@ typedef enum SpvOp_ {
     SpvOpDepthAttachmentReadEXT = 4161,
     SpvOpStencilAttachmentReadEXT = 4162,
     SpvOpTerminateInvocation = 4416,
+    SpvOpTypeUntypedPointerKHR = 4417,
+    SpvOpUntypedVariableKHR = 4418,
+    SpvOpUntypedAccessChainKHR = 4419,
+    SpvOpUntypedInBoundsAccessChainKHR = 4420,
     SpvOpSubgroupBallotKHR = 4421,
     SpvOpSubgroupFirstInvocationKHR = 4422,
+    SpvOpUntypedPtrAccessChainKHR = 4423,
+    SpvOpUntypedInBoundsPtrAccessChainKHR = 4424,
+    SpvOpUntypedArrayLengthKHR = 4425,
+    SpvOpUntypedPrefetchKHR = 4426,
     SpvOpSubgroupAllKHR = 4428,
     SpvOpSubgroupAnyKHR = 4429,
     SpvOpSubgroupAllEqualKHR = 4430,
     SpvOpGroupNonUniformRotateKHR = 4431,
     SpvOpSubgroupReadInvocationKHR = 4432,
+    SpvOpExtInstWithForwardRefsKHR = 4433,
     SpvOpTraceRayKHR = 4445,
     SpvOpExecuteCallableKHR = 4446,
     SpvOpConvertUToAccelerationStructureKHR = 4447,
@@ -1772,6 +1871,9 @@ typedef enum SpvOp_ {
     SpvOpCooperativeMatrixStoreKHR = 4458,
     SpvOpCooperativeMatrixMulAddKHR = 4459,
     SpvOpCooperativeMatrixLengthKHR = 4460,
+    SpvOpConstantCompositeReplicateEXT = 4461,
+    SpvOpSpecConstantCompositeReplicateEXT = 4462,
+    SpvOpCompositeConstructReplicateEXT = 4463,
     SpvOpTypeRayQueryKHR = 4472,
     SpvOpRayQueryInitializeKHR = 4473,
     SpvOpRayQueryTerminateKHR = 4474,
@@ -1783,6 +1885,10 @@ typedef enum SpvOp_ {
     SpvOpImageBoxFilterQCOM = 4481,
     SpvOpImageBlockMatchSSDQCOM = 4482,
     SpvOpImageBlockMatchSADQCOM = 4483,
+    SpvOpImageBlockMatchWindowSSDQCOM = 4500,
+    SpvOpImageBlockMatchWindowSADQCOM = 4501,
+    SpvOpImageBlockMatchGatherSSDQCOM = 4502,
+    SpvOpImageBlockMatchGatherSADQCOM = 4503,
     SpvOpGroupIAddNonUniformAMD = 5000,
     SpvOpGroupFAddNonUniformAMD = 5001,
     SpvOpGroupFMinNonUniformAMD = 5002,
@@ -1794,9 +1900,14 @@ typedef enum SpvOp_ {
     SpvOpFragmentMaskFetchAMD = 5011,
     SpvOpFragmentFetchAMD = 5012,
     SpvOpReadClockKHR = 5056,
-    SpvOpFinalizeNodePayloadsAMDX = 5075,
+    SpvOpAllocateNodePayloadsAMDX = 5074,
+    SpvOpEnqueueNodePayloadsAMDX = 5075,
+    SpvOpTypeNodePayloadArrayAMDX = 5076,
     SpvOpFinishWritingNodePayloadAMDX = 5078,
-    SpvOpInitializeNodePayloadsAMDX = 5090,
+    SpvOpNodePayloadArrayLengthAMDX = 5090,
+    SpvOpIsNodePayloadValidAMDX = 5101,
+    SpvOpConstantStringAMDX = 5103,
+    SpvOpSpecConstantStringAMDX = 5104,
     SpvOpGroupNonUniformQuadAllKHR = 5110,
     SpvOpGroupNonUniformQuadAnyKHR = 5111,
     SpvOpHitObjectRecordHitMotionNV = 5249,
@@ -1833,6 +1944,7 @@ typedef enum SpvOp_ {
     SpvOpReorderThreadWithHintNV = 5280,
     SpvOpTypeHitObjectNV = 5281,
     SpvOpImageSampleFootprintNV = 5283,
+    SpvOpCooperativeMatrixConvertNV = 5293,
     SpvOpEmitMeshTasksEXT = 5294,
     SpvOpSetMeshOutputsEXT = 5295,
     SpvOpGroupNonUniformPartitionNV = 5296,
@@ -1857,9 +1969,26 @@ typedef enum SpvOp_ {
     SpvOpCooperativeMatrixLengthNV = 5362,
     SpvOpBeginInvocationInterlockEXT = 5364,
     SpvOpEndInvocationInterlockEXT = 5365,
+    SpvOpCooperativeMatrixReduceNV = 5366,
+    SpvOpCooperativeMatrixLoadTensorNV = 5367,
+    SpvOpCooperativeMatrixStoreTensorNV = 5368,
+    SpvOpCooperativeMatrixPerElementOpNV = 5369,
+    SpvOpTypeTensorLayoutNV = 5370,
+    SpvOpTypeTensorViewNV = 5371,
+    SpvOpCreateTensorLayoutNV = 5372,
+    SpvOpTensorLayoutSetDimensionNV = 5373,
+    SpvOpTensorLayoutSetStrideNV = 5374,
+    SpvOpTensorLayoutSliceNV = 5375,
+    SpvOpTensorLayoutSetClampValueNV = 5376,
+    SpvOpCreateTensorViewNV = 5377,
+    SpvOpTensorViewSetDimensionNV = 5378,
+    SpvOpTensorViewSetStrideNV = 5379,
     SpvOpDemoteToHelperInvocation = 5380,
     SpvOpDemoteToHelperInvocationEXT = 5380,
     SpvOpIsHelperInvocationEXT = 5381,
+    SpvOpTensorViewSetClipNV = 5382,
+    SpvOpTensorLayoutSetBlockSizeNV = 5384,
+    SpvOpCooperativeMatrixTransposeNV = 5390,
     SpvOpConvertUToImageNV = 5391,
     SpvOpConvertUToSamplerNV = 5392,
     SpvOpConvertImageToUNV = 5393,
@@ -1867,6 +1996,7 @@ typedef enum SpvOp_ {
     SpvOpConvertUToSampledImageNV = 5395,
     SpvOpConvertSampledImageToUNV = 5396,
     SpvOpSamplerImageAddressingModeNV = 5397,
+    SpvOpRawAccessChainNV = 5398,
     SpvOpSubgroupShuffleINTEL = 5571,
     SpvOpSubgroupShuffleDownINTEL = 5572,
     SpvOpSubgroupShuffleUpINTEL = 5573,
@@ -2113,6 +2243,8 @@ typedef enum SpvOp_ {
     SpvOpConvertBF16ToFINTEL = 6117,
     SpvOpControlBarrierArriveINTEL = 6142,
     SpvOpControlBarrierWaitINTEL = 6143,
+    SpvOpArithmeticFenceEXT = 6145,
+    SpvOpSubgroupBlockPrefetchINTEL = 6221,
     SpvOpGroupIMulKHR = 6401,
     SpvOpGroupFMulKHR = 6402,
     SpvOpGroupBitwiseAndKHR = 6403,
@@ -2482,13 +2614,22 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpDepthAttachmentReadEXT: *hasResult = true; *hasResultType = true; break;
     case SpvOpStencilAttachmentReadEXT: *hasResult = true; *hasResultType = true; break;
     case SpvOpTerminateInvocation: *hasResult = false; *hasResultType = false; break;
+    case SpvOpTypeUntypedPointerKHR: *hasResult = true; *hasResultType = false; break;
+    case SpvOpUntypedVariableKHR: *hasResult = true; *hasResultType = true; break;
+    case SpvOpUntypedAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case SpvOpUntypedInBoundsAccessChainKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpSubgroupBallotKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpSubgroupFirstInvocationKHR: *hasResult = true; *hasResultType = true; break;
+    case SpvOpUntypedPtrAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case SpvOpUntypedInBoundsPtrAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case SpvOpUntypedArrayLengthKHR: *hasResult = true; *hasResultType = true; break;
+    case SpvOpUntypedPrefetchKHR: *hasResult = false; *hasResultType = false; break;
     case SpvOpSubgroupAllKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpSubgroupAnyKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpSubgroupAllEqualKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpGroupNonUniformRotateKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpSubgroupReadInvocationKHR: *hasResult = true; *hasResultType = true; break;
+    case SpvOpExtInstWithForwardRefsKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpTraceRayKHR: *hasResult = false; *hasResultType = false; break;
     case SpvOpExecuteCallableKHR: *hasResult = false; *hasResultType = false; break;
     case SpvOpConvertUToAccelerationStructureKHR: *hasResult = true; *hasResultType = true; break;
@@ -2505,6 +2646,9 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpCooperativeMatrixStoreKHR: *hasResult = false; *hasResultType = false; break;
     case SpvOpCooperativeMatrixMulAddKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpCooperativeMatrixLengthKHR: *hasResult = true; *hasResultType = true; break;
+    case SpvOpConstantCompositeReplicateEXT: *hasResult = true; *hasResultType = true; break;
+    case SpvOpSpecConstantCompositeReplicateEXT: *hasResult = true; *hasResultType = true; break;
+    case SpvOpCompositeConstructReplicateEXT: *hasResult = true; *hasResultType = true; break;
     case SpvOpTypeRayQueryKHR: *hasResult = true; *hasResultType = false; break;
     case SpvOpRayQueryInitializeKHR: *hasResult = false; *hasResultType = false; break;
     case SpvOpRayQueryTerminateKHR: *hasResult = false; *hasResultType = false; break;
@@ -2516,6 +2660,10 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpImageBoxFilterQCOM: *hasResult = true; *hasResultType = true; break;
     case SpvOpImageBlockMatchSSDQCOM: *hasResult = true; *hasResultType = true; break;
     case SpvOpImageBlockMatchSADQCOM: *hasResult = true; *hasResultType = true; break;
+    case SpvOpImageBlockMatchWindowSSDQCOM: *hasResult = true; *hasResultType = true; break;
+    case SpvOpImageBlockMatchWindowSADQCOM: *hasResult = true; *hasResultType = true; break;
+    case SpvOpImageBlockMatchGatherSSDQCOM: *hasResult = true; *hasResultType = true; break;
+    case SpvOpImageBlockMatchGatherSADQCOM: *hasResult = true; *hasResultType = true; break;
     case SpvOpGroupIAddNonUniformAMD: *hasResult = true; *hasResultType = true; break;
     case SpvOpGroupFAddNonUniformAMD: *hasResult = true; *hasResultType = true; break;
     case SpvOpGroupFMinNonUniformAMD: *hasResult = true; *hasResultType = true; break;
@@ -2527,9 +2675,14 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpFragmentMaskFetchAMD: *hasResult = true; *hasResultType = true; break;
     case SpvOpFragmentFetchAMD: *hasResult = true; *hasResultType = true; break;
     case SpvOpReadClockKHR: *hasResult = true; *hasResultType = true; break;
-    case SpvOpFinalizeNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case SpvOpAllocateNodePayloadsAMDX: *hasResult = true; *hasResultType = true; break;
+    case SpvOpEnqueueNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case SpvOpTypeNodePayloadArrayAMDX: *hasResult = true; *hasResultType = false; break;
     case SpvOpFinishWritingNodePayloadAMDX: *hasResult = true; *hasResultType = true; break;
-    case SpvOpInitializeNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case SpvOpNodePayloadArrayLengthAMDX: *hasResult = true; *hasResultType = true; break;
+    case SpvOpIsNodePayloadValidAMDX: *hasResult = true; *hasResultType = true; break;
+    case SpvOpConstantStringAMDX: *hasResult = true; *hasResultType = false; break;
+    case SpvOpSpecConstantStringAMDX: *hasResult = true; *hasResultType = false; break;
     case SpvOpGroupNonUniformQuadAllKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpGroupNonUniformQuadAnyKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpHitObjectRecordHitMotionNV: *hasResult = false; *hasResultType = false; break;
@@ -2566,20 +2719,21 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpReorderThreadWithHintNV: *hasResult = false; *hasResultType = false; break;
     case SpvOpTypeHitObjectNV: *hasResult = true; *hasResultType = false; break;
     case SpvOpImageSampleFootprintNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpCooperativeMatrixConvertNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpEmitMeshTasksEXT: *hasResult = false; *hasResultType = false; break;
     case SpvOpSetMeshOutputsEXT: *hasResult = false; *hasResultType = false; break;
     case SpvOpGroupNonUniformPartitionNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpWritePackedPrimitiveIndices4x8NV: *hasResult = false; *hasResultType = false; break;
     case SpvOpFetchMicroTriangleVertexPositionNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpFetchMicroTriangleVertexBarycentricNV: *hasResult = true; *hasResultType = true; break;
-    case SpvOpReportIntersectionNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpReportIntersectionKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpIgnoreIntersectionNV: *hasResult = false; *hasResultType = false; break;
     case SpvOpTerminateRayNV: *hasResult = false; *hasResultType = false; break;
     case SpvOpTraceNV: *hasResult = false; *hasResultType = false; break;
     case SpvOpTraceMotionNV: *hasResult = false; *hasResultType = false; break;
     case SpvOpTraceRayMotionNV: *hasResult = false; *hasResultType = false; break;
     case SpvOpRayQueryGetIntersectionTriangleVertexPositionsKHR: *hasResult = true; *hasResultType = true; break;
-    case SpvOpTypeAccelerationStructureNV: *hasResult = true; *hasResultType = false; break;
+    case SpvOpTypeAccelerationStructureKHR: *hasResult = true; *hasResultType = false; break;
     case SpvOpExecuteCallableNV: *hasResult = false; *hasResultType = false; break;
     case SpvOpTypeCooperativeMatrixNV: *hasResult = true; *hasResultType = false; break;
     case SpvOpCooperativeMatrixLoadNV: *hasResult = true; *hasResultType = true; break;
@@ -2588,8 +2742,25 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpCooperativeMatrixLengthNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpBeginInvocationInterlockEXT: *hasResult = false; *hasResultType = false; break;
     case SpvOpEndInvocationInterlockEXT: *hasResult = false; *hasResultType = false; break;
+    case SpvOpCooperativeMatrixReduceNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpCooperativeMatrixLoadTensorNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpCooperativeMatrixStoreTensorNV: *hasResult = false; *hasResultType = false; break;
+    case SpvOpCooperativeMatrixPerElementOpNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTypeTensorLayoutNV: *hasResult = true; *hasResultType = false; break;
+    case SpvOpTypeTensorViewNV: *hasResult = true; *hasResultType = false; break;
+    case SpvOpCreateTensorLayoutNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTensorLayoutSetDimensionNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTensorLayoutSetStrideNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTensorLayoutSliceNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTensorLayoutSetClampValueNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpCreateTensorViewNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTensorViewSetDimensionNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTensorViewSetStrideNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpDemoteToHelperInvocation: *hasResult = false; *hasResultType = false; break;
     case SpvOpIsHelperInvocationEXT: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTensorViewSetClipNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpTensorLayoutSetBlockSizeNV: *hasResult = true; *hasResultType = true; break;
+    case SpvOpCooperativeMatrixTransposeNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpConvertUToImageNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpConvertUToSamplerNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpConvertImageToUNV: *hasResult = true; *hasResultType = true; break;
@@ -2597,6 +2768,7 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpConvertUToSampledImageNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpConvertSampledImageToUNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpSamplerImageAddressingModeNV: *hasResult = false; *hasResultType = false; break;
+    case SpvOpRawAccessChainNV: *hasResult = true; *hasResultType = true; break;
     case SpvOpSubgroupShuffleINTEL: *hasResult = true; *hasResultType = true; break;
     case SpvOpSubgroupShuffleDownINTEL: *hasResult = true; *hasResultType = true; break;
     case SpvOpSubgroupShuffleUpINTEL: *hasResult = true; *hasResultType = true; break;
@@ -2841,6 +3013,8 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpConvertBF16ToFINTEL: *hasResult = true; *hasResultType = true; break;
     case SpvOpControlBarrierArriveINTEL: *hasResult = false; *hasResultType = false; break;
     case SpvOpControlBarrierWaitINTEL: *hasResult = false; *hasResultType = false; break;
+    case SpvOpArithmeticFenceEXT: *hasResult = true; *hasResultType = true; break;
+    case SpvOpSubgroupBlockPrefetchINTEL: *hasResult = false; *hasResultType = false; break;
     case SpvOpGroupIMulKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpGroupFMulKHR: *hasResult = true; *hasResultType = true; break;
     case SpvOpGroupBitwiseAndKHR: *hasResult = true; *hasResultType = true; break;
@@ -2853,6 +3027,1852 @@ inline void SpvHasResultAndType(SpvOp opcode, bool *hasResult, bool *hasResultTy
     case SpvOpMaskedScatterINTEL: *hasResult = false; *hasResultType = false; break;
     }
 }
+inline const char* SpvSourceLanguageToString(SpvSourceLanguage value) {
+    switch (value) {
+    case SpvSourceLanguageUnknown: return "Unknown";
+    case SpvSourceLanguageESSL: return "ESSL";
+    case SpvSourceLanguageGLSL: return "GLSL";
+    case SpvSourceLanguageOpenCL_C: return "OpenCL_C";
+    case SpvSourceLanguageOpenCL_CPP: return "OpenCL_CPP";
+    case SpvSourceLanguageHLSL: return "HLSL";
+    case SpvSourceLanguageCPP_for_OpenCL: return "CPP_for_OpenCL";
+    case SpvSourceLanguageSYCL: return "SYCL";
+    case SpvSourceLanguageHERO_C: return "HERO_C";
+    case SpvSourceLanguageNZSL: return "NZSL";
+    case SpvSourceLanguageWGSL: return "WGSL";
+    case SpvSourceLanguageSlang: return "Slang";
+    case SpvSourceLanguageZig: return "Zig";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvExecutionModelToString(SpvExecutionModel value) {
+    switch (value) {
+    case SpvExecutionModelVertex: return "Vertex";
+    case SpvExecutionModelTessellationControl: return "TessellationControl";
+    case SpvExecutionModelTessellationEvaluation: return "TessellationEvaluation";
+    case SpvExecutionModelGeometry: return "Geometry";
+    case SpvExecutionModelFragment: return "Fragment";
+    case SpvExecutionModelGLCompute: return "GLCompute";
+    case SpvExecutionModelKernel: return "Kernel";
+    case SpvExecutionModelTaskNV: return "TaskNV";
+    case SpvExecutionModelMeshNV: return "MeshNV";
+    case SpvExecutionModelRayGenerationKHR: return "RayGenerationKHR";
+    case SpvExecutionModelIntersectionKHR: return "IntersectionKHR";
+    case SpvExecutionModelAnyHitKHR: return "AnyHitKHR";
+    case SpvExecutionModelClosestHitKHR: return "ClosestHitKHR";
+    case SpvExecutionModelMissKHR: return "MissKHR";
+    case SpvExecutionModelCallableKHR: return "CallableKHR";
+    case SpvExecutionModelTaskEXT: return "TaskEXT";
+    case SpvExecutionModelMeshEXT: return "MeshEXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvAddressingModelToString(SpvAddressingModel value) {
+    switch (value) {
+    case SpvAddressingModelLogical: return "Logical";
+    case SpvAddressingModelPhysical32: return "Physical32";
+    case SpvAddressingModelPhysical64: return "Physical64";
+    case SpvAddressingModelPhysicalStorageBuffer64: return "PhysicalStorageBuffer64";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvMemoryModelToString(SpvMemoryModel value) {
+    switch (value) {
+    case SpvMemoryModelSimple: return "Simple";
+    case SpvMemoryModelGLSL450: return "GLSL450";
+    case SpvMemoryModelOpenCL: return "OpenCL";
+    case SpvMemoryModelVulkan: return "Vulkan";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvExecutionModeToString(SpvExecutionMode value) {
+    switch (value) {
+    case SpvExecutionModeInvocations: return "Invocations";
+    case SpvExecutionModeSpacingEqual: return "SpacingEqual";
+    case SpvExecutionModeSpacingFractionalEven: return "SpacingFractionalEven";
+    case SpvExecutionModeSpacingFractionalOdd: return "SpacingFractionalOdd";
+    case SpvExecutionModeVertexOrderCw: return "VertexOrderCw";
+    case SpvExecutionModeVertexOrderCcw: return "VertexOrderCcw";
+    case SpvExecutionModePixelCenterInteger: return "PixelCenterInteger";
+    case SpvExecutionModeOriginUpperLeft: return "OriginUpperLeft";
+    case SpvExecutionModeOriginLowerLeft: return "OriginLowerLeft";
+    case SpvExecutionModeEarlyFragmentTests: return "EarlyFragmentTests";
+    case SpvExecutionModePointMode: return "PointMode";
+    case SpvExecutionModeXfb: return "Xfb";
+    case SpvExecutionModeDepthReplacing: return "DepthReplacing";
+    case SpvExecutionModeDepthGreater: return "DepthGreater";
+    case SpvExecutionModeDepthLess: return "DepthLess";
+    case SpvExecutionModeDepthUnchanged: return "DepthUnchanged";
+    case SpvExecutionModeLocalSize: return "LocalSize";
+    case SpvExecutionModeLocalSizeHint: return "LocalSizeHint";
+    case SpvExecutionModeInputPoints: return "InputPoints";
+    case SpvExecutionModeInputLines: return "InputLines";
+    case SpvExecutionModeInputLinesAdjacency: return "InputLinesAdjacency";
+    case SpvExecutionModeTriangles: return "Triangles";
+    case SpvExecutionModeInputTrianglesAdjacency: return "InputTrianglesAdjacency";
+    case SpvExecutionModeQuads: return "Quads";
+    case SpvExecutionModeIsolines: return "Isolines";
+    case SpvExecutionModeOutputVertices: return "OutputVertices";
+    case SpvExecutionModeOutputPoints: return "OutputPoints";
+    case SpvExecutionModeOutputLineStrip: return "OutputLineStrip";
+    case SpvExecutionModeOutputTriangleStrip: return "OutputTriangleStrip";
+    case SpvExecutionModeVecTypeHint: return "VecTypeHint";
+    case SpvExecutionModeContractionOff: return "ContractionOff";
+    case SpvExecutionModeInitializer: return "Initializer";
+    case SpvExecutionModeFinalizer: return "Finalizer";
+    case SpvExecutionModeSubgroupSize: return "SubgroupSize";
+    case SpvExecutionModeSubgroupsPerWorkgroup: return "SubgroupsPerWorkgroup";
+    case SpvExecutionModeSubgroupsPerWorkgroupId: return "SubgroupsPerWorkgroupId";
+    case SpvExecutionModeLocalSizeId: return "LocalSizeId";
+    case SpvExecutionModeLocalSizeHintId: return "LocalSizeHintId";
+    case SpvExecutionModeNonCoherentColorAttachmentReadEXT: return "NonCoherentColorAttachmentReadEXT";
+    case SpvExecutionModeNonCoherentDepthAttachmentReadEXT: return "NonCoherentDepthAttachmentReadEXT";
+    case SpvExecutionModeNonCoherentStencilAttachmentReadEXT: return "NonCoherentStencilAttachmentReadEXT";
+    case SpvExecutionModeSubgroupUniformControlFlowKHR: return "SubgroupUniformControlFlowKHR";
+    case SpvExecutionModePostDepthCoverage: return "PostDepthCoverage";
+    case SpvExecutionModeDenormPreserve: return "DenormPreserve";
+    case SpvExecutionModeDenormFlushToZero: return "DenormFlushToZero";
+    case SpvExecutionModeSignedZeroInfNanPreserve: return "SignedZeroInfNanPreserve";
+    case SpvExecutionModeRoundingModeRTE: return "RoundingModeRTE";
+    case SpvExecutionModeRoundingModeRTZ: return "RoundingModeRTZ";
+    case SpvExecutionModeEarlyAndLateFragmentTestsAMD: return "EarlyAndLateFragmentTestsAMD";
+    case SpvExecutionModeStencilRefReplacingEXT: return "StencilRefReplacingEXT";
+    case SpvExecutionModeCoalescingAMDX: return "CoalescingAMDX";
+    case SpvExecutionModeIsApiEntryAMDX: return "IsApiEntryAMDX";
+    case SpvExecutionModeMaxNodeRecursionAMDX: return "MaxNodeRecursionAMDX";
+    case SpvExecutionModeStaticNumWorkgroupsAMDX: return "StaticNumWorkgroupsAMDX";
+    case SpvExecutionModeShaderIndexAMDX: return "ShaderIndexAMDX";
+    case SpvExecutionModeMaxNumWorkgroupsAMDX: return "MaxNumWorkgroupsAMDX";
+    case SpvExecutionModeStencilRefUnchangedFrontAMD: return "StencilRefUnchangedFrontAMD";
+    case SpvExecutionModeStencilRefGreaterFrontAMD: return "StencilRefGreaterFrontAMD";
+    case SpvExecutionModeStencilRefLessFrontAMD: return "StencilRefLessFrontAMD";
+    case SpvExecutionModeStencilRefUnchangedBackAMD: return "StencilRefUnchangedBackAMD";
+    case SpvExecutionModeStencilRefGreaterBackAMD: return "StencilRefGreaterBackAMD";
+    case SpvExecutionModeStencilRefLessBackAMD: return "StencilRefLessBackAMD";
+    case SpvExecutionModeQuadDerivativesKHR: return "QuadDerivativesKHR";
+    case SpvExecutionModeRequireFullQuadsKHR: return "RequireFullQuadsKHR";
+    case SpvExecutionModeSharesInputWithAMDX: return "SharesInputWithAMDX";
+    case SpvExecutionModeOutputLinesEXT: return "OutputLinesEXT";
+    case SpvExecutionModeOutputPrimitivesEXT: return "OutputPrimitivesEXT";
+    case SpvExecutionModeDerivativeGroupQuadsKHR: return "DerivativeGroupQuadsKHR";
+    case SpvExecutionModeDerivativeGroupLinearKHR: return "DerivativeGroupLinearKHR";
+    case SpvExecutionModeOutputTrianglesEXT: return "OutputTrianglesEXT";
+    case SpvExecutionModePixelInterlockOrderedEXT: return "PixelInterlockOrderedEXT";
+    case SpvExecutionModePixelInterlockUnorderedEXT: return "PixelInterlockUnorderedEXT";
+    case SpvExecutionModeSampleInterlockOrderedEXT: return "SampleInterlockOrderedEXT";
+    case SpvExecutionModeSampleInterlockUnorderedEXT: return "SampleInterlockUnorderedEXT";
+    case SpvExecutionModeShadingRateInterlockOrderedEXT: return "ShadingRateInterlockOrderedEXT";
+    case SpvExecutionModeShadingRateInterlockUnorderedEXT: return "ShadingRateInterlockUnorderedEXT";
+    case SpvExecutionModeSharedLocalMemorySizeINTEL: return "SharedLocalMemorySizeINTEL";
+    case SpvExecutionModeRoundingModeRTPINTEL: return "RoundingModeRTPINTEL";
+    case SpvExecutionModeRoundingModeRTNINTEL: return "RoundingModeRTNINTEL";
+    case SpvExecutionModeFloatingPointModeALTINTEL: return "FloatingPointModeALTINTEL";
+    case SpvExecutionModeFloatingPointModeIEEEINTEL: return "FloatingPointModeIEEEINTEL";
+    case SpvExecutionModeMaxWorkgroupSizeINTEL: return "MaxWorkgroupSizeINTEL";
+    case SpvExecutionModeMaxWorkDimINTEL: return "MaxWorkDimINTEL";
+    case SpvExecutionModeNoGlobalOffsetINTEL: return "NoGlobalOffsetINTEL";
+    case SpvExecutionModeNumSIMDWorkitemsINTEL: return "NumSIMDWorkitemsINTEL";
+    case SpvExecutionModeSchedulerTargetFmaxMhzINTEL: return "SchedulerTargetFmaxMhzINTEL";
+    case SpvExecutionModeMaximallyReconvergesKHR: return "MaximallyReconvergesKHR";
+    case SpvExecutionModeFPFastMathDefault: return "FPFastMathDefault";
+    case SpvExecutionModeStreamingInterfaceINTEL: return "StreamingInterfaceINTEL";
+    case SpvExecutionModeRegisterMapInterfaceINTEL: return "RegisterMapInterfaceINTEL";
+    case SpvExecutionModeNamedBarrierCountINTEL: return "NamedBarrierCountINTEL";
+    case SpvExecutionModeMaximumRegistersINTEL: return "MaximumRegistersINTEL";
+    case SpvExecutionModeMaximumRegistersIdINTEL: return "MaximumRegistersIdINTEL";
+    case SpvExecutionModeNamedMaximumRegistersINTEL: return "NamedMaximumRegistersINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvStorageClassToString(SpvStorageClass value) {
+    switch (value) {
+    case SpvStorageClassUniformConstant: return "UniformConstant";
+    case SpvStorageClassInput: return "Input";
+    case SpvStorageClassUniform: return "Uniform";
+    case SpvStorageClassOutput: return "Output";
+    case SpvStorageClassWorkgroup: return "Workgroup";
+    case SpvStorageClassCrossWorkgroup: return "CrossWorkgroup";
+    case SpvStorageClassPrivate: return "Private";
+    case SpvStorageClassFunction: return "Function";
+    case SpvStorageClassGeneric: return "Generic";
+    case SpvStorageClassPushConstant: return "PushConstant";
+    case SpvStorageClassAtomicCounter: return "AtomicCounter";
+    case SpvStorageClassImage: return "Image";
+    case SpvStorageClassStorageBuffer: return "StorageBuffer";
+    case SpvStorageClassTileImageEXT: return "TileImageEXT";
+    case SpvStorageClassNodePayloadAMDX: return "NodePayloadAMDX";
+    case SpvStorageClassCallableDataKHR: return "CallableDataKHR";
+    case SpvStorageClassIncomingCallableDataKHR: return "IncomingCallableDataKHR";
+    case SpvStorageClassRayPayloadKHR: return "RayPayloadKHR";
+    case SpvStorageClassHitAttributeKHR: return "HitAttributeKHR";
+    case SpvStorageClassIncomingRayPayloadKHR: return "IncomingRayPayloadKHR";
+    case SpvStorageClassShaderRecordBufferKHR: return "ShaderRecordBufferKHR";
+    case SpvStorageClassPhysicalStorageBuffer: return "PhysicalStorageBuffer";
+    case SpvStorageClassHitObjectAttributeNV: return "HitObjectAttributeNV";
+    case SpvStorageClassTaskPayloadWorkgroupEXT: return "TaskPayloadWorkgroupEXT";
+    case SpvStorageClassCodeSectionINTEL: return "CodeSectionINTEL";
+    case SpvStorageClassDeviceOnlyINTEL: return "DeviceOnlyINTEL";
+    case SpvStorageClassHostOnlyINTEL: return "HostOnlyINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvDimToString(SpvDim value) {
+    switch (value) {
+    case SpvDim1D: return "1D";
+    case SpvDim2D: return "2D";
+    case SpvDim3D: return "3D";
+    case SpvDimCube: return "Cube";
+    case SpvDimRect: return "Rect";
+    case SpvDimBuffer: return "Buffer";
+    case SpvDimSubpassData: return "SubpassData";
+    case SpvDimTileImageDataEXT: return "TileImageDataEXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvSamplerAddressingModeToString(SpvSamplerAddressingMode value) {
+    switch (value) {
+    case SpvSamplerAddressingModeNone: return "None";
+    case SpvSamplerAddressingModeClampToEdge: return "ClampToEdge";
+    case SpvSamplerAddressingModeClamp: return "Clamp";
+    case SpvSamplerAddressingModeRepeat: return "Repeat";
+    case SpvSamplerAddressingModeRepeatMirrored: return "RepeatMirrored";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvSamplerFilterModeToString(SpvSamplerFilterMode value) {
+    switch (value) {
+    case SpvSamplerFilterModeNearest: return "Nearest";
+    case SpvSamplerFilterModeLinear: return "Linear";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvImageFormatToString(SpvImageFormat value) {
+    switch (value) {
+    case SpvImageFormatUnknown: return "Unknown";
+    case SpvImageFormatRgba32f: return "Rgba32f";
+    case SpvImageFormatRgba16f: return "Rgba16f";
+    case SpvImageFormatR32f: return "R32f";
+    case SpvImageFormatRgba8: return "Rgba8";
+    case SpvImageFormatRgba8Snorm: return "Rgba8Snorm";
+    case SpvImageFormatRg32f: return "Rg32f";
+    case SpvImageFormatRg16f: return "Rg16f";
+    case SpvImageFormatR11fG11fB10f: return "R11fG11fB10f";
+    case SpvImageFormatR16f: return "R16f";
+    case SpvImageFormatRgba16: return "Rgba16";
+    case SpvImageFormatRgb10A2: return "Rgb10A2";
+    case SpvImageFormatRg16: return "Rg16";
+    case SpvImageFormatRg8: return "Rg8";
+    case SpvImageFormatR16: return "R16";
+    case SpvImageFormatR8: return "R8";
+    case SpvImageFormatRgba16Snorm: return "Rgba16Snorm";
+    case SpvImageFormatRg16Snorm: return "Rg16Snorm";
+    case SpvImageFormatRg8Snorm: return "Rg8Snorm";
+    case SpvImageFormatR16Snorm: return "R16Snorm";
+    case SpvImageFormatR8Snorm: return "R8Snorm";
+    case SpvImageFormatRgba32i: return "Rgba32i";
+    case SpvImageFormatRgba16i: return "Rgba16i";
+    case SpvImageFormatRgba8i: return "Rgba8i";
+    case SpvImageFormatR32i: return "R32i";
+    case SpvImageFormatRg32i: return "Rg32i";
+    case SpvImageFormatRg16i: return "Rg16i";
+    case SpvImageFormatRg8i: return "Rg8i";
+    case SpvImageFormatR16i: return "R16i";
+    case SpvImageFormatR8i: return "R8i";
+    case SpvImageFormatRgba32ui: return "Rgba32ui";
+    case SpvImageFormatRgba16ui: return "Rgba16ui";
+    case SpvImageFormatRgba8ui: return "Rgba8ui";
+    case SpvImageFormatR32ui: return "R32ui";
+    case SpvImageFormatRgb10a2ui: return "Rgb10a2ui";
+    case SpvImageFormatRg32ui: return "Rg32ui";
+    case SpvImageFormatRg16ui: return "Rg16ui";
+    case SpvImageFormatRg8ui: return "Rg8ui";
+    case SpvImageFormatR16ui: return "R16ui";
+    case SpvImageFormatR8ui: return "R8ui";
+    case SpvImageFormatR64ui: return "R64ui";
+    case SpvImageFormatR64i: return "R64i";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvImageChannelOrderToString(SpvImageChannelOrder value) {
+    switch (value) {
+    case SpvImageChannelOrderR: return "R";
+    case SpvImageChannelOrderA: return "A";
+    case SpvImageChannelOrderRG: return "RG";
+    case SpvImageChannelOrderRA: return "RA";
+    case SpvImageChannelOrderRGB: return "RGB";
+    case SpvImageChannelOrderRGBA: return "RGBA";
+    case SpvImageChannelOrderBGRA: return "BGRA";
+    case SpvImageChannelOrderARGB: return "ARGB";
+    case SpvImageChannelOrderIntensity: return "Intensity";
+    case SpvImageChannelOrderLuminance: return "Luminance";
+    case SpvImageChannelOrderRx: return "Rx";
+    case SpvImageChannelOrderRGx: return "RGx";
+    case SpvImageChannelOrderRGBx: return "RGBx";
+    case SpvImageChannelOrderDepth: return "Depth";
+    case SpvImageChannelOrderDepthStencil: return "DepthStencil";
+    case SpvImageChannelOrdersRGB: return "sRGB";
+    case SpvImageChannelOrdersRGBx: return "sRGBx";
+    case SpvImageChannelOrdersRGBA: return "sRGBA";
+    case SpvImageChannelOrdersBGRA: return "sBGRA";
+    case SpvImageChannelOrderABGR: return "ABGR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvImageChannelDataTypeToString(SpvImageChannelDataType value) {
+    switch (value) {
+    case SpvImageChannelDataTypeSnormInt8: return "SnormInt8";
+    case SpvImageChannelDataTypeSnormInt16: return "SnormInt16";
+    case SpvImageChannelDataTypeUnormInt8: return "UnormInt8";
+    case SpvImageChannelDataTypeUnormInt16: return "UnormInt16";
+    case SpvImageChannelDataTypeUnormShort565: return "UnormShort565";
+    case SpvImageChannelDataTypeUnormShort555: return "UnormShort555";
+    case SpvImageChannelDataTypeUnormInt101010: return "UnormInt101010";
+    case SpvImageChannelDataTypeSignedInt8: return "SignedInt8";
+    case SpvImageChannelDataTypeSignedInt16: return "SignedInt16";
+    case SpvImageChannelDataTypeSignedInt32: return "SignedInt32";
+    case SpvImageChannelDataTypeUnsignedInt8: return "UnsignedInt8";
+    case SpvImageChannelDataTypeUnsignedInt16: return "UnsignedInt16";
+    case SpvImageChannelDataTypeUnsignedInt32: return "UnsignedInt32";
+    case SpvImageChannelDataTypeHalfFloat: return "HalfFloat";
+    case SpvImageChannelDataTypeFloat: return "Float";
+    case SpvImageChannelDataTypeUnormInt24: return "UnormInt24";
+    case SpvImageChannelDataTypeUnormInt101010_2: return "UnormInt101010_2";
+    case SpvImageChannelDataTypeUnsignedIntRaw10EXT: return "UnsignedIntRaw10EXT";
+    case SpvImageChannelDataTypeUnsignedIntRaw12EXT: return "UnsignedIntRaw12EXT";
+    case SpvImageChannelDataTypeUnormInt2_101010EXT: return "UnormInt2_101010EXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvFPRoundingModeToString(SpvFPRoundingMode value) {
+    switch (value) {
+    case SpvFPRoundingModeRTE: return "RTE";
+    case SpvFPRoundingModeRTZ: return "RTZ";
+    case SpvFPRoundingModeRTP: return "RTP";
+    case SpvFPRoundingModeRTN: return "RTN";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvLinkageTypeToString(SpvLinkageType value) {
+    switch (value) {
+    case SpvLinkageTypeExport: return "Export";
+    case SpvLinkageTypeImport: return "Import";
+    case SpvLinkageTypeLinkOnceODR: return "LinkOnceODR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvAccessQualifierToString(SpvAccessQualifier value) {
+    switch (value) {
+    case SpvAccessQualifierReadOnly: return "ReadOnly";
+    case SpvAccessQualifierWriteOnly: return "WriteOnly";
+    case SpvAccessQualifierReadWrite: return "ReadWrite";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvFunctionParameterAttributeToString(SpvFunctionParameterAttribute value) {
+    switch (value) {
+    case SpvFunctionParameterAttributeZext: return "Zext";
+    case SpvFunctionParameterAttributeSext: return "Sext";
+    case SpvFunctionParameterAttributeByVal: return "ByVal";
+    case SpvFunctionParameterAttributeSret: return "Sret";
+    case SpvFunctionParameterAttributeNoAlias: return "NoAlias";
+    case SpvFunctionParameterAttributeNoCapture: return "NoCapture";
+    case SpvFunctionParameterAttributeNoWrite: return "NoWrite";
+    case SpvFunctionParameterAttributeNoReadWrite: return "NoReadWrite";
+    case SpvFunctionParameterAttributeRuntimeAlignedINTEL: return "RuntimeAlignedINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvDecorationToString(SpvDecoration value) {
+    switch (value) {
+    case SpvDecorationRelaxedPrecision: return "RelaxedPrecision";
+    case SpvDecorationSpecId: return "SpecId";
+    case SpvDecorationBlock: return "Block";
+    case SpvDecorationBufferBlock: return "BufferBlock";
+    case SpvDecorationRowMajor: return "RowMajor";
+    case SpvDecorationColMajor: return "ColMajor";
+    case SpvDecorationArrayStride: return "ArrayStride";
+    case SpvDecorationMatrixStride: return "MatrixStride";
+    case SpvDecorationGLSLShared: return "GLSLShared";
+    case SpvDecorationGLSLPacked: return "GLSLPacked";
+    case SpvDecorationCPacked: return "CPacked";
+    case SpvDecorationBuiltIn: return "BuiltIn";
+    case SpvDecorationNoPerspective: return "NoPerspective";
+    case SpvDecorationFlat: return "Flat";
+    case SpvDecorationPatch: return "Patch";
+    case SpvDecorationCentroid: return "Centroid";
+    case SpvDecorationSample: return "Sample";
+    case SpvDecorationInvariant: return "Invariant";
+    case SpvDecorationRestrict: return "Restrict";
+    case SpvDecorationAliased: return "Aliased";
+    case SpvDecorationVolatile: return "Volatile";
+    case SpvDecorationConstant: return "Constant";
+    case SpvDecorationCoherent: return "Coherent";
+    case SpvDecorationNonWritable: return "NonWritable";
+    case SpvDecorationNonReadable: return "NonReadable";
+    case SpvDecorationUniform: return "Uniform";
+    case SpvDecorationUniformId: return "UniformId";
+    case SpvDecorationSaturatedConversion: return "SaturatedConversion";
+    case SpvDecorationStream: return "Stream";
+    case SpvDecorationLocation: return "Location";
+    case SpvDecorationComponent: return "Component";
+    case SpvDecorationIndex: return "Index";
+    case SpvDecorationBinding: return "Binding";
+    case SpvDecorationDescriptorSet: return "DescriptorSet";
+    case SpvDecorationOffset: return "Offset";
+    case SpvDecorationXfbBuffer: return "XfbBuffer";
+    case SpvDecorationXfbStride: return "XfbStride";
+    case SpvDecorationFuncParamAttr: return "FuncParamAttr";
+    case SpvDecorationFPRoundingMode: return "FPRoundingMode";
+    case SpvDecorationFPFastMathMode: return "FPFastMathMode";
+    case SpvDecorationLinkageAttributes: return "LinkageAttributes";
+    case SpvDecorationNoContraction: return "NoContraction";
+    case SpvDecorationInputAttachmentIndex: return "InputAttachmentIndex";
+    case SpvDecorationAlignment: return "Alignment";
+    case SpvDecorationMaxByteOffset: return "MaxByteOffset";
+    case SpvDecorationAlignmentId: return "AlignmentId";
+    case SpvDecorationMaxByteOffsetId: return "MaxByteOffsetId";
+    case SpvDecorationNoSignedWrap: return "NoSignedWrap";
+    case SpvDecorationNoUnsignedWrap: return "NoUnsignedWrap";
+    case SpvDecorationWeightTextureQCOM: return "WeightTextureQCOM";
+    case SpvDecorationBlockMatchTextureQCOM: return "BlockMatchTextureQCOM";
+    case SpvDecorationBlockMatchSamplerQCOM: return "BlockMatchSamplerQCOM";
+    case SpvDecorationExplicitInterpAMD: return "ExplicitInterpAMD";
+    case SpvDecorationNodeSharesPayloadLimitsWithAMDX: return "NodeSharesPayloadLimitsWithAMDX";
+    case SpvDecorationNodeMaxPayloadsAMDX: return "NodeMaxPayloadsAMDX";
+    case SpvDecorationTrackFinishWritingAMDX: return "TrackFinishWritingAMDX";
+    case SpvDecorationPayloadNodeNameAMDX: return "PayloadNodeNameAMDX";
+    case SpvDecorationPayloadNodeBaseIndexAMDX: return "PayloadNodeBaseIndexAMDX";
+    case SpvDecorationPayloadNodeSparseArrayAMDX: return "PayloadNodeSparseArrayAMDX";
+    case SpvDecorationPayloadNodeArraySizeAMDX: return "PayloadNodeArraySizeAMDX";
+    case SpvDecorationPayloadDispatchIndirectAMDX: return "PayloadDispatchIndirectAMDX";
+    case SpvDecorationOverrideCoverageNV: return "OverrideCoverageNV";
+    case SpvDecorationPassthroughNV: return "PassthroughNV";
+    case SpvDecorationViewportRelativeNV: return "ViewportRelativeNV";
+    case SpvDecorationSecondaryViewportRelativeNV: return "SecondaryViewportRelativeNV";
+    case SpvDecorationPerPrimitiveEXT: return "PerPrimitiveEXT";
+    case SpvDecorationPerViewNV: return "PerViewNV";
+    case SpvDecorationPerTaskNV: return "PerTaskNV";
+    case SpvDecorationPerVertexKHR: return "PerVertexKHR";
+    case SpvDecorationNonUniform: return "NonUniform";
+    case SpvDecorationRestrictPointer: return "RestrictPointer";
+    case SpvDecorationAliasedPointer: return "AliasedPointer";
+    case SpvDecorationHitObjectShaderRecordBufferNV: return "HitObjectShaderRecordBufferNV";
+    case SpvDecorationBindlessSamplerNV: return "BindlessSamplerNV";
+    case SpvDecorationBindlessImageNV: return "BindlessImageNV";
+    case SpvDecorationBoundSamplerNV: return "BoundSamplerNV";
+    case SpvDecorationBoundImageNV: return "BoundImageNV";
+    case SpvDecorationSIMTCallINTEL: return "SIMTCallINTEL";
+    case SpvDecorationReferencedIndirectlyINTEL: return "ReferencedIndirectlyINTEL";
+    case SpvDecorationClobberINTEL: return "ClobberINTEL";
+    case SpvDecorationSideEffectsINTEL: return "SideEffectsINTEL";
+    case SpvDecorationVectorComputeVariableINTEL: return "VectorComputeVariableINTEL";
+    case SpvDecorationFuncParamIOKindINTEL: return "FuncParamIOKindINTEL";
+    case SpvDecorationVectorComputeFunctionINTEL: return "VectorComputeFunctionINTEL";
+    case SpvDecorationStackCallINTEL: return "StackCallINTEL";
+    case SpvDecorationGlobalVariableOffsetINTEL: return "GlobalVariableOffsetINTEL";
+    case SpvDecorationCounterBuffer: return "CounterBuffer";
+    case SpvDecorationHlslSemanticGOOGLE: return "HlslSemanticGOOGLE";
+    case SpvDecorationUserTypeGOOGLE: return "UserTypeGOOGLE";
+    case SpvDecorationFunctionRoundingModeINTEL: return "FunctionRoundingModeINTEL";
+    case SpvDecorationFunctionDenormModeINTEL: return "FunctionDenormModeINTEL";
+    case SpvDecorationRegisterINTEL: return "RegisterINTEL";
+    case SpvDecorationMemoryINTEL: return "MemoryINTEL";
+    case SpvDecorationNumbanksINTEL: return "NumbanksINTEL";
+    case SpvDecorationBankwidthINTEL: return "BankwidthINTEL";
+    case SpvDecorationMaxPrivateCopiesINTEL: return "MaxPrivateCopiesINTEL";
+    case SpvDecorationSinglepumpINTEL: return "SinglepumpINTEL";
+    case SpvDecorationDoublepumpINTEL: return "DoublepumpINTEL";
+    case SpvDecorationMaxReplicatesINTEL: return "MaxReplicatesINTEL";
+    case SpvDecorationSimpleDualPortINTEL: return "SimpleDualPortINTEL";
+    case SpvDecorationMergeINTEL: return "MergeINTEL";
+    case SpvDecorationBankBitsINTEL: return "BankBitsINTEL";
+    case SpvDecorationForcePow2DepthINTEL: return "ForcePow2DepthINTEL";
+    case SpvDecorationStridesizeINTEL: return "StridesizeINTEL";
+    case SpvDecorationWordsizeINTEL: return "WordsizeINTEL";
+    case SpvDecorationTrueDualPortINTEL: return "TrueDualPortINTEL";
+    case SpvDecorationBurstCoalesceINTEL: return "BurstCoalesceINTEL";
+    case SpvDecorationCacheSizeINTEL: return "CacheSizeINTEL";
+    case SpvDecorationDontStaticallyCoalesceINTEL: return "DontStaticallyCoalesceINTEL";
+    case SpvDecorationPrefetchINTEL: return "PrefetchINTEL";
+    case SpvDecorationStallEnableINTEL: return "StallEnableINTEL";
+    case SpvDecorationFuseLoopsInFunctionINTEL: return "FuseLoopsInFunctionINTEL";
+    case SpvDecorationMathOpDSPModeINTEL: return "MathOpDSPModeINTEL";
+    case SpvDecorationAliasScopeINTEL: return "AliasScopeINTEL";
+    case SpvDecorationNoAliasINTEL: return "NoAliasINTEL";
+    case SpvDecorationInitiationIntervalINTEL: return "InitiationIntervalINTEL";
+    case SpvDecorationMaxConcurrencyINTEL: return "MaxConcurrencyINTEL";
+    case SpvDecorationPipelineEnableINTEL: return "PipelineEnableINTEL";
+    case SpvDecorationBufferLocationINTEL: return "BufferLocationINTEL";
+    case SpvDecorationIOPipeStorageINTEL: return "IOPipeStorageINTEL";
+    case SpvDecorationFunctionFloatingPointModeINTEL: return "FunctionFloatingPointModeINTEL";
+    case SpvDecorationSingleElementVectorINTEL: return "SingleElementVectorINTEL";
+    case SpvDecorationVectorComputeCallableFunctionINTEL: return "VectorComputeCallableFunctionINTEL";
+    case SpvDecorationMediaBlockIOINTEL: return "MediaBlockIOINTEL";
+    case SpvDecorationStallFreeINTEL: return "StallFreeINTEL";
+    case SpvDecorationFPMaxErrorDecorationINTEL: return "FPMaxErrorDecorationINTEL";
+    case SpvDecorationLatencyControlLabelINTEL: return "LatencyControlLabelINTEL";
+    case SpvDecorationLatencyControlConstraintINTEL: return "LatencyControlConstraintINTEL";
+    case SpvDecorationConduitKernelArgumentINTEL: return "ConduitKernelArgumentINTEL";
+    case SpvDecorationRegisterMapKernelArgumentINTEL: return "RegisterMapKernelArgumentINTEL";
+    case SpvDecorationMMHostInterfaceAddressWidthINTEL: return "MMHostInterfaceAddressWidthINTEL";
+    case SpvDecorationMMHostInterfaceDataWidthINTEL: return "MMHostInterfaceDataWidthINTEL";
+    case SpvDecorationMMHostInterfaceLatencyINTEL: return "MMHostInterfaceLatencyINTEL";
+    case SpvDecorationMMHostInterfaceReadWriteModeINTEL: return "MMHostInterfaceReadWriteModeINTEL";
+    case SpvDecorationMMHostInterfaceMaxBurstINTEL: return "MMHostInterfaceMaxBurstINTEL";
+    case SpvDecorationMMHostInterfaceWaitRequestINTEL: return "MMHostInterfaceWaitRequestINTEL";
+    case SpvDecorationStableKernelArgumentINTEL: return "StableKernelArgumentINTEL";
+    case SpvDecorationHostAccessINTEL: return "HostAccessINTEL";
+    case SpvDecorationInitModeINTEL: return "InitModeINTEL";
+    case SpvDecorationImplementInRegisterMapINTEL: return "ImplementInRegisterMapINTEL";
+    case SpvDecorationCacheControlLoadINTEL: return "CacheControlLoadINTEL";
+    case SpvDecorationCacheControlStoreINTEL: return "CacheControlStoreINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvBuiltInToString(SpvBuiltIn value) {
+    switch (value) {
+    case SpvBuiltInPosition: return "Position";
+    case SpvBuiltInPointSize: return "PointSize";
+    case SpvBuiltInClipDistance: return "ClipDistance";
+    case SpvBuiltInCullDistance: return "CullDistance";
+    case SpvBuiltInVertexId: return "VertexId";
+    case SpvBuiltInInstanceId: return "InstanceId";
+    case SpvBuiltInPrimitiveId: return "PrimitiveId";
+    case SpvBuiltInInvocationId: return "InvocationId";
+    case SpvBuiltInLayer: return "Layer";
+    case SpvBuiltInViewportIndex: return "ViewportIndex";
+    case SpvBuiltInTessLevelOuter: return "TessLevelOuter";
+    case SpvBuiltInTessLevelInner: return "TessLevelInner";
+    case SpvBuiltInTessCoord: return "TessCoord";
+    case SpvBuiltInPatchVertices: return "PatchVertices";
+    case SpvBuiltInFragCoord: return "FragCoord";
+    case SpvBuiltInPointCoord: return "PointCoord";
+    case SpvBuiltInFrontFacing: return "FrontFacing";
+    case SpvBuiltInSampleId: return "SampleId";
+    case SpvBuiltInSamplePosition: return "SamplePosition";
+    case SpvBuiltInSampleMask: return "SampleMask";
+    case SpvBuiltInFragDepth: return "FragDepth";
+    case SpvBuiltInHelperInvocation: return "HelperInvocation";
+    case SpvBuiltInNumWorkgroups: return "NumWorkgroups";
+    case SpvBuiltInWorkgroupSize: return "WorkgroupSize";
+    case SpvBuiltInWorkgroupId: return "WorkgroupId";
+    case SpvBuiltInLocalInvocationId: return "LocalInvocationId";
+    case SpvBuiltInGlobalInvocationId: return "GlobalInvocationId";
+    case SpvBuiltInLocalInvocationIndex: return "LocalInvocationIndex";
+    case SpvBuiltInWorkDim: return "WorkDim";
+    case SpvBuiltInGlobalSize: return "GlobalSize";
+    case SpvBuiltInEnqueuedWorkgroupSize: return "EnqueuedWorkgroupSize";
+    case SpvBuiltInGlobalOffset: return "GlobalOffset";
+    case SpvBuiltInGlobalLinearId: return "GlobalLinearId";
+    case SpvBuiltInSubgroupSize: return "SubgroupSize";
+    case SpvBuiltInSubgroupMaxSize: return "SubgroupMaxSize";
+    case SpvBuiltInNumSubgroups: return "NumSubgroups";
+    case SpvBuiltInNumEnqueuedSubgroups: return "NumEnqueuedSubgroups";
+    case SpvBuiltInSubgroupId: return "SubgroupId";
+    case SpvBuiltInSubgroupLocalInvocationId: return "SubgroupLocalInvocationId";
+    case SpvBuiltInVertexIndex: return "VertexIndex";
+    case SpvBuiltInInstanceIndex: return "InstanceIndex";
+    case SpvBuiltInCoreIDARM: return "CoreIDARM";
+    case SpvBuiltInCoreCountARM: return "CoreCountARM";
+    case SpvBuiltInCoreMaxIDARM: return "CoreMaxIDARM";
+    case SpvBuiltInWarpIDARM: return "WarpIDARM";
+    case SpvBuiltInWarpMaxIDARM: return "WarpMaxIDARM";
+    case SpvBuiltInSubgroupEqMask: return "SubgroupEqMask";
+    case SpvBuiltInSubgroupGeMask: return "SubgroupGeMask";
+    case SpvBuiltInSubgroupGtMask: return "SubgroupGtMask";
+    case SpvBuiltInSubgroupLeMask: return "SubgroupLeMask";
+    case SpvBuiltInSubgroupLtMask: return "SubgroupLtMask";
+    case SpvBuiltInBaseVertex: return "BaseVertex";
+    case SpvBuiltInBaseInstance: return "BaseInstance";
+    case SpvBuiltInDrawIndex: return "DrawIndex";
+    case SpvBuiltInPrimitiveShadingRateKHR: return "PrimitiveShadingRateKHR";
+    case SpvBuiltInDeviceIndex: return "DeviceIndex";
+    case SpvBuiltInViewIndex: return "ViewIndex";
+    case SpvBuiltInShadingRateKHR: return "ShadingRateKHR";
+    case SpvBuiltInBaryCoordNoPerspAMD: return "BaryCoordNoPerspAMD";
+    case SpvBuiltInBaryCoordNoPerspCentroidAMD: return "BaryCoordNoPerspCentroidAMD";
+    case SpvBuiltInBaryCoordNoPerspSampleAMD: return "BaryCoordNoPerspSampleAMD";
+    case SpvBuiltInBaryCoordSmoothAMD: return "BaryCoordSmoothAMD";
+    case SpvBuiltInBaryCoordSmoothCentroidAMD: return "BaryCoordSmoothCentroidAMD";
+    case SpvBuiltInBaryCoordSmoothSampleAMD: return "BaryCoordSmoothSampleAMD";
+    case SpvBuiltInBaryCoordPullModelAMD: return "BaryCoordPullModelAMD";
+    case SpvBuiltInFragStencilRefEXT: return "FragStencilRefEXT";
+    case SpvBuiltInRemainingRecursionLevelsAMDX: return "RemainingRecursionLevelsAMDX";
+    case SpvBuiltInShaderIndexAMDX: return "ShaderIndexAMDX";
+    case SpvBuiltInViewportMaskNV: return "ViewportMaskNV";
+    case SpvBuiltInSecondaryPositionNV: return "SecondaryPositionNV";
+    case SpvBuiltInSecondaryViewportMaskNV: return "SecondaryViewportMaskNV";
+    case SpvBuiltInPositionPerViewNV: return "PositionPerViewNV";
+    case SpvBuiltInViewportMaskPerViewNV: return "ViewportMaskPerViewNV";
+    case SpvBuiltInFullyCoveredEXT: return "FullyCoveredEXT";
+    case SpvBuiltInTaskCountNV: return "TaskCountNV";
+    case SpvBuiltInPrimitiveCountNV: return "PrimitiveCountNV";
+    case SpvBuiltInPrimitiveIndicesNV: return "PrimitiveIndicesNV";
+    case SpvBuiltInClipDistancePerViewNV: return "ClipDistancePerViewNV";
+    case SpvBuiltInCullDistancePerViewNV: return "CullDistancePerViewNV";
+    case SpvBuiltInLayerPerViewNV: return "LayerPerViewNV";
+    case SpvBuiltInMeshViewCountNV: return "MeshViewCountNV";
+    case SpvBuiltInMeshViewIndicesNV: return "MeshViewIndicesNV";
+    case SpvBuiltInBaryCoordKHR: return "BaryCoordKHR";
+    case SpvBuiltInBaryCoordNoPerspKHR: return "BaryCoordNoPerspKHR";
+    case SpvBuiltInFragSizeEXT: return "FragSizeEXT";
+    case SpvBuiltInFragInvocationCountEXT: return "FragInvocationCountEXT";
+    case SpvBuiltInPrimitivePointIndicesEXT: return "PrimitivePointIndicesEXT";
+    case SpvBuiltInPrimitiveLineIndicesEXT: return "PrimitiveLineIndicesEXT";
+    case SpvBuiltInPrimitiveTriangleIndicesEXT: return "PrimitiveTriangleIndicesEXT";
+    case SpvBuiltInCullPrimitiveEXT: return "CullPrimitiveEXT";
+    case SpvBuiltInLaunchIdKHR: return "LaunchIdKHR";
+    case SpvBuiltInLaunchSizeKHR: return "LaunchSizeKHR";
+    case SpvBuiltInWorldRayOriginKHR: return "WorldRayOriginKHR";
+    case SpvBuiltInWorldRayDirectionKHR: return "WorldRayDirectionKHR";
+    case SpvBuiltInObjectRayOriginKHR: return "ObjectRayOriginKHR";
+    case SpvBuiltInObjectRayDirectionKHR: return "ObjectRayDirectionKHR";
+    case SpvBuiltInRayTminKHR: return "RayTminKHR";
+    case SpvBuiltInRayTmaxKHR: return "RayTmaxKHR";
+    case SpvBuiltInInstanceCustomIndexKHR: return "InstanceCustomIndexKHR";
+    case SpvBuiltInObjectToWorldKHR: return "ObjectToWorldKHR";
+    case SpvBuiltInWorldToObjectKHR: return "WorldToObjectKHR";
+    case SpvBuiltInHitTNV: return "HitTNV";
+    case SpvBuiltInHitKindKHR: return "HitKindKHR";
+    case SpvBuiltInCurrentRayTimeNV: return "CurrentRayTimeNV";
+    case SpvBuiltInHitTriangleVertexPositionsKHR: return "HitTriangleVertexPositionsKHR";
+    case SpvBuiltInHitMicroTriangleVertexPositionsNV: return "HitMicroTriangleVertexPositionsNV";
+    case SpvBuiltInHitMicroTriangleVertexBarycentricsNV: return "HitMicroTriangleVertexBarycentricsNV";
+    case SpvBuiltInIncomingRayFlagsKHR: return "IncomingRayFlagsKHR";
+    case SpvBuiltInRayGeometryIndexKHR: return "RayGeometryIndexKHR";
+    case SpvBuiltInWarpsPerSMNV: return "WarpsPerSMNV";
+    case SpvBuiltInSMCountNV: return "SMCountNV";
+    case SpvBuiltInWarpIDNV: return "WarpIDNV";
+    case SpvBuiltInSMIDNV: return "SMIDNV";
+    case SpvBuiltInHitKindFrontFacingMicroTriangleNV: return "HitKindFrontFacingMicroTriangleNV";
+    case SpvBuiltInHitKindBackFacingMicroTriangleNV: return "HitKindBackFacingMicroTriangleNV";
+    case SpvBuiltInCullMaskKHR: return "CullMaskKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvScopeToString(SpvScope value) {
+    switch (value) {
+    case SpvScopeCrossDevice: return "CrossDevice";
+    case SpvScopeDevice: return "Device";
+    case SpvScopeWorkgroup: return "Workgroup";
+    case SpvScopeSubgroup: return "Subgroup";
+    case SpvScopeInvocation: return "Invocation";
+    case SpvScopeQueueFamily: return "QueueFamily";
+    case SpvScopeShaderCallKHR: return "ShaderCallKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvGroupOperationToString(SpvGroupOperation value) {
+    switch (value) {
+    case SpvGroupOperationReduce: return "Reduce";
+    case SpvGroupOperationInclusiveScan: return "InclusiveScan";
+    case SpvGroupOperationExclusiveScan: return "ExclusiveScan";
+    case SpvGroupOperationClusteredReduce: return "ClusteredReduce";
+    case SpvGroupOperationPartitionedReduceNV: return "PartitionedReduceNV";
+    case SpvGroupOperationPartitionedInclusiveScanNV: return "PartitionedInclusiveScanNV";
+    case SpvGroupOperationPartitionedExclusiveScanNV: return "PartitionedExclusiveScanNV";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvKernelEnqueueFlagsToString(SpvKernelEnqueueFlags value) {
+    switch (value) {
+    case SpvKernelEnqueueFlagsNoWait: return "NoWait";
+    case SpvKernelEnqueueFlagsWaitKernel: return "WaitKernel";
+    case SpvKernelEnqueueFlagsWaitWorkGroup: return "WaitWorkGroup";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvCapabilityToString(SpvCapability value) {
+    switch (value) {
+    case SpvCapabilityMatrix: return "Matrix";
+    case SpvCapabilityShader: return "Shader";
+    case SpvCapabilityGeometry: return "Geometry";
+    case SpvCapabilityTessellation: return "Tessellation";
+    case SpvCapabilityAddresses: return "Addresses";
+    case SpvCapabilityLinkage: return "Linkage";
+    case SpvCapabilityKernel: return "Kernel";
+    case SpvCapabilityVector16: return "Vector16";
+    case SpvCapabilityFloat16Buffer: return "Float16Buffer";
+    case SpvCapabilityFloat16: return "Float16";
+    case SpvCapabilityFloat64: return "Float64";
+    case SpvCapabilityInt64: return "Int64";
+    case SpvCapabilityInt64Atomics: return "Int64Atomics";
+    case SpvCapabilityImageBasic: return "ImageBasic";
+    case SpvCapabilityImageReadWrite: return "ImageReadWrite";
+    case SpvCapabilityImageMipmap: return "ImageMipmap";
+    case SpvCapabilityPipes: return "Pipes";
+    case SpvCapabilityGroups: return "Groups";
+    case SpvCapabilityDeviceEnqueue: return "DeviceEnqueue";
+    case SpvCapabilityLiteralSampler: return "LiteralSampler";
+    case SpvCapabilityAtomicStorage: return "AtomicStorage";
+    case SpvCapabilityInt16: return "Int16";
+    case SpvCapabilityTessellationPointSize: return "TessellationPointSize";
+    case SpvCapabilityGeometryPointSize: return "GeometryPointSize";
+    case SpvCapabilityImageGatherExtended: return "ImageGatherExtended";
+    case SpvCapabilityStorageImageMultisample: return "StorageImageMultisample";
+    case SpvCapabilityUniformBufferArrayDynamicIndexing: return "UniformBufferArrayDynamicIndexing";
+    case SpvCapabilitySampledImageArrayDynamicIndexing: return "SampledImageArrayDynamicIndexing";
+    case SpvCapabilityStorageBufferArrayDynamicIndexing: return "StorageBufferArrayDynamicIndexing";
+    case SpvCapabilityStorageImageArrayDynamicIndexing: return "StorageImageArrayDynamicIndexing";
+    case SpvCapabilityClipDistance: return "ClipDistance";
+    case SpvCapabilityCullDistance: return "CullDistance";
+    case SpvCapabilityImageCubeArray: return "ImageCubeArray";
+    case SpvCapabilitySampleRateShading: return "SampleRateShading";
+    case SpvCapabilityImageRect: return "ImageRect";
+    case SpvCapabilitySampledRect: return "SampledRect";
+    case SpvCapabilityGenericPointer: return "GenericPointer";
+    case SpvCapabilityInt8: return "Int8";
+    case SpvCapabilityInputAttachment: return "InputAttachment";
+    case SpvCapabilitySparseResidency: return "SparseResidency";
+    case SpvCapabilityMinLod: return "MinLod";
+    case SpvCapabilitySampled1D: return "Sampled1D";
+    case SpvCapabilityImage1D: return "Image1D";
+    case SpvCapabilitySampledCubeArray: return "SampledCubeArray";
+    case SpvCapabilitySampledBuffer: return "SampledBuffer";
+    case SpvCapabilityImageBuffer: return "ImageBuffer";
+    case SpvCapabilityImageMSArray: return "ImageMSArray";
+    case SpvCapabilityStorageImageExtendedFormats: return "StorageImageExtendedFormats";
+    case SpvCapabilityImageQuery: return "ImageQuery";
+    case SpvCapabilityDerivativeControl: return "DerivativeControl";
+    case SpvCapabilityInterpolationFunction: return "InterpolationFunction";
+    case SpvCapabilityTransformFeedback: return "TransformFeedback";
+    case SpvCapabilityGeometryStreams: return "GeometryStreams";
+    case SpvCapabilityStorageImageReadWithoutFormat: return "StorageImageReadWithoutFormat";
+    case SpvCapabilityStorageImageWriteWithoutFormat: return "StorageImageWriteWithoutFormat";
+    case SpvCapabilityMultiViewport: return "MultiViewport";
+    case SpvCapabilitySubgroupDispatch: return "SubgroupDispatch";
+    case SpvCapabilityNamedBarrier: return "NamedBarrier";
+    case SpvCapabilityPipeStorage: return "PipeStorage";
+    case SpvCapabilityGroupNonUniform: return "GroupNonUniform";
+    case SpvCapabilityGroupNonUniformVote: return "GroupNonUniformVote";
+    case SpvCapabilityGroupNonUniformArithmetic: return "GroupNonUniformArithmetic";
+    case SpvCapabilityGroupNonUniformBallot: return "GroupNonUniformBallot";
+    case SpvCapabilityGroupNonUniformShuffle: return "GroupNonUniformShuffle";
+    case SpvCapabilityGroupNonUniformShuffleRelative: return "GroupNonUniformShuffleRelative";
+    case SpvCapabilityGroupNonUniformClustered: return "GroupNonUniformClustered";
+    case SpvCapabilityGroupNonUniformQuad: return "GroupNonUniformQuad";
+    case SpvCapabilityShaderLayer: return "ShaderLayer";
+    case SpvCapabilityShaderViewportIndex: return "ShaderViewportIndex";
+    case SpvCapabilityUniformDecoration: return "UniformDecoration";
+    case SpvCapabilityCoreBuiltinsARM: return "CoreBuiltinsARM";
+    case SpvCapabilityTileImageColorReadAccessEXT: return "TileImageColorReadAccessEXT";
+    case SpvCapabilityTileImageDepthReadAccessEXT: return "TileImageDepthReadAccessEXT";
+    case SpvCapabilityTileImageStencilReadAccessEXT: return "TileImageStencilReadAccessEXT";
+    case SpvCapabilityCooperativeMatrixLayoutsARM: return "CooperativeMatrixLayoutsARM";
+    case SpvCapabilityFragmentShadingRateKHR: return "FragmentShadingRateKHR";
+    case SpvCapabilitySubgroupBallotKHR: return "SubgroupBallotKHR";
+    case SpvCapabilityDrawParameters: return "DrawParameters";
+    case SpvCapabilityWorkgroupMemoryExplicitLayoutKHR: return "WorkgroupMemoryExplicitLayoutKHR";
+    case SpvCapabilityWorkgroupMemoryExplicitLayout8BitAccessKHR: return "WorkgroupMemoryExplicitLayout8BitAccessKHR";
+    case SpvCapabilityWorkgroupMemoryExplicitLayout16BitAccessKHR: return "WorkgroupMemoryExplicitLayout16BitAccessKHR";
+    case SpvCapabilitySubgroupVoteKHR: return "SubgroupVoteKHR";
+    case SpvCapabilityStorageBuffer16BitAccess: return "StorageBuffer16BitAccess";
+    case SpvCapabilityStorageUniform16: return "StorageUniform16";
+    case SpvCapabilityStoragePushConstant16: return "StoragePushConstant16";
+    case SpvCapabilityStorageInputOutput16: return "StorageInputOutput16";
+    case SpvCapabilityDeviceGroup: return "DeviceGroup";
+    case SpvCapabilityMultiView: return "MultiView";
+    case SpvCapabilityVariablePointersStorageBuffer: return "VariablePointersStorageBuffer";
+    case SpvCapabilityVariablePointers: return "VariablePointers";
+    case SpvCapabilityAtomicStorageOps: return "AtomicStorageOps";
+    case SpvCapabilitySampleMaskPostDepthCoverage: return "SampleMaskPostDepthCoverage";
+    case SpvCapabilityStorageBuffer8BitAccess: return "StorageBuffer8BitAccess";
+    case SpvCapabilityUniformAndStorageBuffer8BitAccess: return "UniformAndStorageBuffer8BitAccess";
+    case SpvCapabilityStoragePushConstant8: return "StoragePushConstant8";
+    case SpvCapabilityDenormPreserve: return "DenormPreserve";
+    case SpvCapabilityDenormFlushToZero: return "DenormFlushToZero";
+    case SpvCapabilitySignedZeroInfNanPreserve: return "SignedZeroInfNanPreserve";
+    case SpvCapabilityRoundingModeRTE: return "RoundingModeRTE";
+    case SpvCapabilityRoundingModeRTZ: return "RoundingModeRTZ";
+    case SpvCapabilityRayQueryProvisionalKHR: return "RayQueryProvisionalKHR";
+    case SpvCapabilityRayQueryKHR: return "RayQueryKHR";
+    case SpvCapabilityUntypedPointersKHR: return "UntypedPointersKHR";
+    case SpvCapabilityRayTraversalPrimitiveCullingKHR: return "RayTraversalPrimitiveCullingKHR";
+    case SpvCapabilityRayTracingKHR: return "RayTracingKHR";
+    case SpvCapabilityTextureSampleWeightedQCOM: return "TextureSampleWeightedQCOM";
+    case SpvCapabilityTextureBoxFilterQCOM: return "TextureBoxFilterQCOM";
+    case SpvCapabilityTextureBlockMatchQCOM: return "TextureBlockMatchQCOM";
+    case SpvCapabilityTextureBlockMatch2QCOM: return "TextureBlockMatch2QCOM";
+    case SpvCapabilityFloat16ImageAMD: return "Float16ImageAMD";
+    case SpvCapabilityImageGatherBiasLodAMD: return "ImageGatherBiasLodAMD";
+    case SpvCapabilityFragmentMaskAMD: return "FragmentMaskAMD";
+    case SpvCapabilityStencilExportEXT: return "StencilExportEXT";
+    case SpvCapabilityImageReadWriteLodAMD: return "ImageReadWriteLodAMD";
+    case SpvCapabilityInt64ImageEXT: return "Int64ImageEXT";
+    case SpvCapabilityShaderClockKHR: return "ShaderClockKHR";
+    case SpvCapabilityShaderEnqueueAMDX: return "ShaderEnqueueAMDX";
+    case SpvCapabilityQuadControlKHR: return "QuadControlKHR";
+    case SpvCapabilitySampleMaskOverrideCoverageNV: return "SampleMaskOverrideCoverageNV";
+    case SpvCapabilityGeometryShaderPassthroughNV: return "GeometryShaderPassthroughNV";
+    case SpvCapabilityShaderViewportIndexLayerEXT: return "ShaderViewportIndexLayerEXT";
+    case SpvCapabilityShaderViewportMaskNV: return "ShaderViewportMaskNV";
+    case SpvCapabilityShaderStereoViewNV: return "ShaderStereoViewNV";
+    case SpvCapabilityPerViewAttributesNV: return "PerViewAttributesNV";
+    case SpvCapabilityFragmentFullyCoveredEXT: return "FragmentFullyCoveredEXT";
+    case SpvCapabilityMeshShadingNV: return "MeshShadingNV";
+    case SpvCapabilityImageFootprintNV: return "ImageFootprintNV";
+    case SpvCapabilityMeshShadingEXT: return "MeshShadingEXT";
+    case SpvCapabilityFragmentBarycentricKHR: return "FragmentBarycentricKHR";
+    case SpvCapabilityComputeDerivativeGroupQuadsKHR: return "ComputeDerivativeGroupQuadsKHR";
+    case SpvCapabilityFragmentDensityEXT: return "FragmentDensityEXT";
+    case SpvCapabilityGroupNonUniformPartitionedNV: return "GroupNonUniformPartitionedNV";
+    case SpvCapabilityShaderNonUniform: return "ShaderNonUniform";
+    case SpvCapabilityRuntimeDescriptorArray: return "RuntimeDescriptorArray";
+    case SpvCapabilityInputAttachmentArrayDynamicIndexing: return "InputAttachmentArrayDynamicIndexing";
+    case SpvCapabilityUniformTexelBufferArrayDynamicIndexing: return "UniformTexelBufferArrayDynamicIndexing";
+    case SpvCapabilityStorageTexelBufferArrayDynamicIndexing: return "StorageTexelBufferArrayDynamicIndexing";
+    case SpvCapabilityUniformBufferArrayNonUniformIndexing: return "UniformBufferArrayNonUniformIndexing";
+    case SpvCapabilitySampledImageArrayNonUniformIndexing: return "SampledImageArrayNonUniformIndexing";
+    case SpvCapabilityStorageBufferArrayNonUniformIndexing: return "StorageBufferArrayNonUniformIndexing";
+    case SpvCapabilityStorageImageArrayNonUniformIndexing: return "StorageImageArrayNonUniformIndexing";
+    case SpvCapabilityInputAttachmentArrayNonUniformIndexing: return "InputAttachmentArrayNonUniformIndexing";
+    case SpvCapabilityUniformTexelBufferArrayNonUniformIndexing: return "UniformTexelBufferArrayNonUniformIndexing";
+    case SpvCapabilityStorageTexelBufferArrayNonUniformIndexing: return "StorageTexelBufferArrayNonUniformIndexing";
+    case SpvCapabilityRayTracingPositionFetchKHR: return "RayTracingPositionFetchKHR";
+    case SpvCapabilityRayTracingNV: return "RayTracingNV";
+    case SpvCapabilityRayTracingMotionBlurNV: return "RayTracingMotionBlurNV";
+    case SpvCapabilityVulkanMemoryModel: return "VulkanMemoryModel";
+    case SpvCapabilityVulkanMemoryModelDeviceScope: return "VulkanMemoryModelDeviceScope";
+    case SpvCapabilityPhysicalStorageBufferAddresses: return "PhysicalStorageBufferAddresses";
+    case SpvCapabilityComputeDerivativeGroupLinearKHR: return "ComputeDerivativeGroupLinearKHR";
+    case SpvCapabilityRayTracingProvisionalKHR: return "RayTracingProvisionalKHR";
+    case SpvCapabilityCooperativeMatrixNV: return "CooperativeMatrixNV";
+    case SpvCapabilityFragmentShaderSampleInterlockEXT: return "FragmentShaderSampleInterlockEXT";
+    case SpvCapabilityFragmentShaderShadingRateInterlockEXT: return "FragmentShaderShadingRateInterlockEXT";
+    case SpvCapabilityShaderSMBuiltinsNV: return "ShaderSMBuiltinsNV";
+    case SpvCapabilityFragmentShaderPixelInterlockEXT: return "FragmentShaderPixelInterlockEXT";
+    case SpvCapabilityDemoteToHelperInvocation: return "DemoteToHelperInvocation";
+    case SpvCapabilityDisplacementMicromapNV: return "DisplacementMicromapNV";
+    case SpvCapabilityRayTracingOpacityMicromapEXT: return "RayTracingOpacityMicromapEXT";
+    case SpvCapabilityShaderInvocationReorderNV: return "ShaderInvocationReorderNV";
+    case SpvCapabilityBindlessTextureNV: return "BindlessTextureNV";
+    case SpvCapabilityRayQueryPositionFetchKHR: return "RayQueryPositionFetchKHR";
+    case SpvCapabilityAtomicFloat16VectorNV: return "AtomicFloat16VectorNV";
+    case SpvCapabilityRayTracingDisplacementMicromapNV: return "RayTracingDisplacementMicromapNV";
+    case SpvCapabilityRawAccessChainsNV: return "RawAccessChainsNV";
+    case SpvCapabilityCooperativeMatrixReductionsNV: return "CooperativeMatrixReductionsNV";
+    case SpvCapabilityCooperativeMatrixConversionsNV: return "CooperativeMatrixConversionsNV";
+    case SpvCapabilityCooperativeMatrixPerElementOperationsNV: return "CooperativeMatrixPerElementOperationsNV";
+    case SpvCapabilityCooperativeMatrixTensorAddressingNV: return "CooperativeMatrixTensorAddressingNV";
+    case SpvCapabilityCooperativeMatrixBlockLoadsNV: return "CooperativeMatrixBlockLoadsNV";
+    case SpvCapabilityTensorAddressingNV: return "TensorAddressingNV";
+    case SpvCapabilitySubgroupShuffleINTEL: return "SubgroupShuffleINTEL";
+    case SpvCapabilitySubgroupBufferBlockIOINTEL: return "SubgroupBufferBlockIOINTEL";
+    case SpvCapabilitySubgroupImageBlockIOINTEL: return "SubgroupImageBlockIOINTEL";
+    case SpvCapabilitySubgroupImageMediaBlockIOINTEL: return "SubgroupImageMediaBlockIOINTEL";
+    case SpvCapabilityRoundToInfinityINTEL: return "RoundToInfinityINTEL";
+    case SpvCapabilityFloatingPointModeINTEL: return "FloatingPointModeINTEL";
+    case SpvCapabilityIntegerFunctions2INTEL: return "IntegerFunctions2INTEL";
+    case SpvCapabilityFunctionPointersINTEL: return "FunctionPointersINTEL";
+    case SpvCapabilityIndirectReferencesINTEL: return "IndirectReferencesINTEL";
+    case SpvCapabilityAsmINTEL: return "AsmINTEL";
+    case SpvCapabilityAtomicFloat32MinMaxEXT: return "AtomicFloat32MinMaxEXT";
+    case SpvCapabilityAtomicFloat64MinMaxEXT: return "AtomicFloat64MinMaxEXT";
+    case SpvCapabilityAtomicFloat16MinMaxEXT: return "AtomicFloat16MinMaxEXT";
+    case SpvCapabilityVectorComputeINTEL: return "VectorComputeINTEL";
+    case SpvCapabilityVectorAnyINTEL: return "VectorAnyINTEL";
+    case SpvCapabilityExpectAssumeKHR: return "ExpectAssumeKHR";
+    case SpvCapabilitySubgroupAvcMotionEstimationINTEL: return "SubgroupAvcMotionEstimationINTEL";
+    case SpvCapabilitySubgroupAvcMotionEstimationIntraINTEL: return "SubgroupAvcMotionEstimationIntraINTEL";
+    case SpvCapabilitySubgroupAvcMotionEstimationChromaINTEL: return "SubgroupAvcMotionEstimationChromaINTEL";
+    case SpvCapabilityVariableLengthArrayINTEL: return "VariableLengthArrayINTEL";
+    case SpvCapabilityFunctionFloatControlINTEL: return "FunctionFloatControlINTEL";
+    case SpvCapabilityFPGAMemoryAttributesINTEL: return "FPGAMemoryAttributesINTEL";
+    case SpvCapabilityFPFastMathModeINTEL: return "FPFastMathModeINTEL";
+    case SpvCapabilityArbitraryPrecisionIntegersINTEL: return "ArbitraryPrecisionIntegersINTEL";
+    case SpvCapabilityArbitraryPrecisionFloatingPointINTEL: return "ArbitraryPrecisionFloatingPointINTEL";
+    case SpvCapabilityUnstructuredLoopControlsINTEL: return "UnstructuredLoopControlsINTEL";
+    case SpvCapabilityFPGALoopControlsINTEL: return "FPGALoopControlsINTEL";
+    case SpvCapabilityKernelAttributesINTEL: return "KernelAttributesINTEL";
+    case SpvCapabilityFPGAKernelAttributesINTEL: return "FPGAKernelAttributesINTEL";
+    case SpvCapabilityFPGAMemoryAccessesINTEL: return "FPGAMemoryAccessesINTEL";
+    case SpvCapabilityFPGAClusterAttributesINTEL: return "FPGAClusterAttributesINTEL";
+    case SpvCapabilityLoopFuseINTEL: return "LoopFuseINTEL";
+    case SpvCapabilityFPGADSPControlINTEL: return "FPGADSPControlINTEL";
+    case SpvCapabilityMemoryAccessAliasingINTEL: return "MemoryAccessAliasingINTEL";
+    case SpvCapabilityFPGAInvocationPipeliningAttributesINTEL: return "FPGAInvocationPipeliningAttributesINTEL";
+    case SpvCapabilityFPGABufferLocationINTEL: return "FPGABufferLocationINTEL";
+    case SpvCapabilityArbitraryPrecisionFixedPointINTEL: return "ArbitraryPrecisionFixedPointINTEL";
+    case SpvCapabilityUSMStorageClassesINTEL: return "USMStorageClassesINTEL";
+    case SpvCapabilityRuntimeAlignedAttributeINTEL: return "RuntimeAlignedAttributeINTEL";
+    case SpvCapabilityIOPipesINTEL: return "IOPipesINTEL";
+    case SpvCapabilityBlockingPipesINTEL: return "BlockingPipesINTEL";
+    case SpvCapabilityFPGARegINTEL: return "FPGARegINTEL";
+    case SpvCapabilityDotProductInputAll: return "DotProductInputAll";
+    case SpvCapabilityDotProductInput4x8Bit: return "DotProductInput4x8Bit";
+    case SpvCapabilityDotProductInput4x8BitPacked: return "DotProductInput4x8BitPacked";
+    case SpvCapabilityDotProduct: return "DotProduct";
+    case SpvCapabilityRayCullMaskKHR: return "RayCullMaskKHR";
+    case SpvCapabilityCooperativeMatrixKHR: return "CooperativeMatrixKHR";
+    case SpvCapabilityReplicatedCompositesEXT: return "ReplicatedCompositesEXT";
+    case SpvCapabilityBitInstructions: return "BitInstructions";
+    case SpvCapabilityGroupNonUniformRotateKHR: return "GroupNonUniformRotateKHR";
+    case SpvCapabilityFloatControls2: return "FloatControls2";
+    case SpvCapabilityAtomicFloat32AddEXT: return "AtomicFloat32AddEXT";
+    case SpvCapabilityAtomicFloat64AddEXT: return "AtomicFloat64AddEXT";
+    case SpvCapabilityLongCompositesINTEL: return "LongCompositesINTEL";
+    case SpvCapabilityOptNoneEXT: return "OptNoneEXT";
+    case SpvCapabilityAtomicFloat16AddEXT: return "AtomicFloat16AddEXT";
+    case SpvCapabilityDebugInfoModuleINTEL: return "DebugInfoModuleINTEL";
+    case SpvCapabilityBFloat16ConversionINTEL: return "BFloat16ConversionINTEL";
+    case SpvCapabilitySplitBarrierINTEL: return "SplitBarrierINTEL";
+    case SpvCapabilityArithmeticFenceEXT: return "ArithmeticFenceEXT";
+    case SpvCapabilityFPGAClusterAttributesV2INTEL: return "FPGAClusterAttributesV2INTEL";
+    case SpvCapabilityFPGAKernelAttributesv2INTEL: return "FPGAKernelAttributesv2INTEL";
+    case SpvCapabilityFPMaxErrorINTEL: return "FPMaxErrorINTEL";
+    case SpvCapabilityFPGALatencyControlINTEL: return "FPGALatencyControlINTEL";
+    case SpvCapabilityFPGAArgumentInterfacesINTEL: return "FPGAArgumentInterfacesINTEL";
+    case SpvCapabilityGlobalVariableHostAccessINTEL: return "GlobalVariableHostAccessINTEL";
+    case SpvCapabilityGlobalVariableFPGADecorationsINTEL: return "GlobalVariableFPGADecorationsINTEL";
+    case SpvCapabilitySubgroupBufferPrefetchINTEL: return "SubgroupBufferPrefetchINTEL";
+    case SpvCapabilityGroupUniformArithmeticKHR: return "GroupUniformArithmeticKHR";
+    case SpvCapabilityMaskedGatherScatterINTEL: return "MaskedGatherScatterINTEL";
+    case SpvCapabilityCacheControlsINTEL: return "CacheControlsINTEL";
+    case SpvCapabilityRegisterLimitsINTEL: return "RegisterLimitsINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvRayQueryIntersectionToString(SpvRayQueryIntersection value) {
+    switch (value) {
+    case SpvRayQueryIntersectionRayQueryCandidateIntersectionKHR: return "RayQueryCandidateIntersectionKHR";
+    case SpvRayQueryIntersectionRayQueryCommittedIntersectionKHR: return "RayQueryCommittedIntersectionKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvRayQueryCommittedIntersectionTypeToString(SpvRayQueryCommittedIntersectionType value) {
+    switch (value) {
+    case SpvRayQueryCommittedIntersectionTypeRayQueryCommittedIntersectionNoneKHR: return "RayQueryCommittedIntersectionNoneKHR";
+    case SpvRayQueryCommittedIntersectionTypeRayQueryCommittedIntersectionTriangleKHR: return "RayQueryCommittedIntersectionTriangleKHR";
+    case SpvRayQueryCommittedIntersectionTypeRayQueryCommittedIntersectionGeneratedKHR: return "RayQueryCommittedIntersectionGeneratedKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvRayQueryCandidateIntersectionTypeToString(SpvRayQueryCandidateIntersectionType value) {
+    switch (value) {
+    case SpvRayQueryCandidateIntersectionTypeRayQueryCandidateIntersectionTriangleKHR: return "RayQueryCandidateIntersectionTriangleKHR";
+    case SpvRayQueryCandidateIntersectionTypeRayQueryCandidateIntersectionAABBKHR: return "RayQueryCandidateIntersectionAABBKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvFPDenormModeToString(SpvFPDenormMode value) {
+    switch (value) {
+    case SpvFPDenormModePreserve: return "Preserve";
+    case SpvFPDenormModeFlushToZero: return "FlushToZero";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvFPOperationModeToString(SpvFPOperationMode value) {
+    switch (value) {
+    case SpvFPOperationModeIEEE: return "IEEE";
+    case SpvFPOperationModeALT: return "ALT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvQuantizationModesToString(SpvQuantizationModes value) {
+    switch (value) {
+    case SpvQuantizationModesTRN: return "TRN";
+    case SpvQuantizationModesTRN_ZERO: return "TRN_ZERO";
+    case SpvQuantizationModesRND: return "RND";
+    case SpvQuantizationModesRND_ZERO: return "RND_ZERO";
+    case SpvQuantizationModesRND_INF: return "RND_INF";
+    case SpvQuantizationModesRND_MIN_INF: return "RND_MIN_INF";
+    case SpvQuantizationModesRND_CONV: return "RND_CONV";
+    case SpvQuantizationModesRND_CONV_ODD: return "RND_CONV_ODD";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvOverflowModesToString(SpvOverflowModes value) {
+    switch (value) {
+    case SpvOverflowModesWRAP: return "WRAP";
+    case SpvOverflowModesSAT: return "SAT";
+    case SpvOverflowModesSAT_ZERO: return "SAT_ZERO";
+    case SpvOverflowModesSAT_SYM: return "SAT_SYM";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvPackedVectorFormatToString(SpvPackedVectorFormat value) {
+    switch (value) {
+    case SpvPackedVectorFormatPackedVectorFormat4x8Bit: return "PackedVectorFormat4x8Bit";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvCooperativeMatrixLayoutToString(SpvCooperativeMatrixLayout value) {
+    switch (value) {
+    case SpvCooperativeMatrixLayoutRowMajorKHR: return "RowMajorKHR";
+    case SpvCooperativeMatrixLayoutColumnMajorKHR: return "ColumnMajorKHR";
+    case SpvCooperativeMatrixLayoutRowBlockedInterleavedARM: return "RowBlockedInterleavedARM";
+    case SpvCooperativeMatrixLayoutColumnBlockedInterleavedARM: return "ColumnBlockedInterleavedARM";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvCooperativeMatrixUseToString(SpvCooperativeMatrixUse value) {
+    switch (value) {
+    case SpvCooperativeMatrixUseMatrixAKHR: return "MatrixAKHR";
+    case SpvCooperativeMatrixUseMatrixBKHR: return "MatrixBKHR";
+    case SpvCooperativeMatrixUseMatrixAccumulatorKHR: return "MatrixAccumulatorKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvTensorClampModeToString(SpvTensorClampMode value) {
+    switch (value) {
+    case SpvTensorClampModeUndefined: return "Undefined";
+    case SpvTensorClampModeConstant: return "Constant";
+    case SpvTensorClampModeClampToEdge: return "ClampToEdge";
+    case SpvTensorClampModeRepeat: return "Repeat";
+    case SpvTensorClampModeRepeatMirrored: return "RepeatMirrored";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvInitializationModeQualifierToString(SpvInitializationModeQualifier value) {
+    switch (value) {
+    case SpvInitializationModeQualifierInitOnDeviceReprogramINTEL: return "InitOnDeviceReprogramINTEL";
+    case SpvInitializationModeQualifierInitOnDeviceResetINTEL: return "InitOnDeviceResetINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvHostAccessQualifierToString(SpvHostAccessQualifier value) {
+    switch (value) {
+    case SpvHostAccessQualifierNoneINTEL: return "NoneINTEL";
+    case SpvHostAccessQualifierReadINTEL: return "ReadINTEL";
+    case SpvHostAccessQualifierWriteINTEL: return "WriteINTEL";
+    case SpvHostAccessQualifierReadWriteINTEL: return "ReadWriteINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvLoadCacheControlToString(SpvLoadCacheControl value) {
+    switch (value) {
+    case SpvLoadCacheControlUncachedINTEL: return "UncachedINTEL";
+    case SpvLoadCacheControlCachedINTEL: return "CachedINTEL";
+    case SpvLoadCacheControlStreamingINTEL: return "StreamingINTEL";
+    case SpvLoadCacheControlInvalidateAfterReadINTEL: return "InvalidateAfterReadINTEL";
+    case SpvLoadCacheControlConstCachedINTEL: return "ConstCachedINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvStoreCacheControlToString(SpvStoreCacheControl value) {
+    switch (value) {
+    case SpvStoreCacheControlUncachedINTEL: return "UncachedINTEL";
+    case SpvStoreCacheControlWriteThroughINTEL: return "WriteThroughINTEL";
+    case SpvStoreCacheControlWriteBackINTEL: return "WriteBackINTEL";
+    case SpvStoreCacheControlStreamingINTEL: return "StreamingINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvNamedMaximumNumberOfRegistersToString(SpvNamedMaximumNumberOfRegisters value) {
+    switch (value) {
+    case SpvNamedMaximumNumberOfRegistersAutoINTEL: return "AutoINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvFPEncodingToString(SpvFPEncoding value) {
+    switch (value) {
+    default: return "Unknown";
+    }
+}
+
+inline const char* SpvOpToString(SpvOp value) {
+    switch (value) {
+    case SpvOpNop: return "OpNop";
+    case SpvOpUndef: return "OpUndef";
+    case SpvOpSourceContinued: return "OpSourceContinued";
+    case SpvOpSource: return "OpSource";
+    case SpvOpSourceExtension: return "OpSourceExtension";
+    case SpvOpName: return "OpName";
+    case SpvOpMemberName: return "OpMemberName";
+    case SpvOpString: return "OpString";
+    case SpvOpLine: return "OpLine";
+    case SpvOpExtension: return "OpExtension";
+    case SpvOpExtInstImport: return "OpExtInstImport";
+    case SpvOpExtInst: return "OpExtInst";
+    case SpvOpMemoryModel: return "OpMemoryModel";
+    case SpvOpEntryPoint: return "OpEntryPoint";
+    case SpvOpExecutionMode: return "OpExecutionMode";
+    case SpvOpCapability: return "OpCapability";
+    case SpvOpTypeVoid: return "OpTypeVoid";
+    case SpvOpTypeBool: return "OpTypeBool";
+    case SpvOpTypeInt: return "OpTypeInt";
+    case SpvOpTypeFloat: return "OpTypeFloat";
+    case SpvOpTypeVector: return "OpTypeVector";
+    case SpvOpTypeMatrix: return "OpTypeMatrix";
+    case SpvOpTypeImage: return "OpTypeImage";
+    case SpvOpTypeSampler: return "OpTypeSampler";
+    case SpvOpTypeSampledImage: return "OpTypeSampledImage";
+    case SpvOpTypeArray: return "OpTypeArray";
+    case SpvOpTypeRuntimeArray: return "OpTypeRuntimeArray";
+    case SpvOpTypeStruct: return "OpTypeStruct";
+    case SpvOpTypeOpaque: return "OpTypeOpaque";
+    case SpvOpTypePointer: return "OpTypePointer";
+    case SpvOpTypeFunction: return "OpTypeFunction";
+    case SpvOpTypeEvent: return "OpTypeEvent";
+    case SpvOpTypeDeviceEvent: return "OpTypeDeviceEvent";
+    case SpvOpTypeReserveId: return "OpTypeReserveId";
+    case SpvOpTypeQueue: return "OpTypeQueue";
+    case SpvOpTypePipe: return "OpTypePipe";
+    case SpvOpTypeForwardPointer: return "OpTypeForwardPointer";
+    case SpvOpConstantTrue: return "OpConstantTrue";
+    case SpvOpConstantFalse: return "OpConstantFalse";
+    case SpvOpConstant: return "OpConstant";
+    case SpvOpConstantComposite: return "OpConstantComposite";
+    case SpvOpConstantSampler: return "OpConstantSampler";
+    case SpvOpConstantNull: return "OpConstantNull";
+    case SpvOpSpecConstantTrue: return "OpSpecConstantTrue";
+    case SpvOpSpecConstantFalse: return "OpSpecConstantFalse";
+    case SpvOpSpecConstant: return "OpSpecConstant";
+    case SpvOpSpecConstantComposite: return "OpSpecConstantComposite";
+    case SpvOpSpecConstantOp: return "OpSpecConstantOp";
+    case SpvOpFunction: return "OpFunction";
+    case SpvOpFunctionParameter: return "OpFunctionParameter";
+    case SpvOpFunctionEnd: return "OpFunctionEnd";
+    case SpvOpFunctionCall: return "OpFunctionCall";
+    case SpvOpVariable: return "OpVariable";
+    case SpvOpImageTexelPointer: return "OpImageTexelPointer";
+    case SpvOpLoad: return "OpLoad";
+    case SpvOpStore: return "OpStore";
+    case SpvOpCopyMemory: return "OpCopyMemory";
+    case SpvOpCopyMemorySized: return "OpCopyMemorySized";
+    case SpvOpAccessChain: return "OpAccessChain";
+    case SpvOpInBoundsAccessChain: return "OpInBoundsAccessChain";
+    case SpvOpPtrAccessChain: return "OpPtrAccessChain";
+    case SpvOpArrayLength: return "OpArrayLength";
+    case SpvOpGenericPtrMemSemantics: return "OpGenericPtrMemSemantics";
+    case SpvOpInBoundsPtrAccessChain: return "OpInBoundsPtrAccessChain";
+    case SpvOpDecorate: return "OpDecorate";
+    case SpvOpMemberDecorate: return "OpMemberDecorate";
+    case SpvOpDecorationGroup: return "OpDecorationGroup";
+    case SpvOpGroupDecorate: return "OpGroupDecorate";
+    case SpvOpGroupMemberDecorate: return "OpGroupMemberDecorate";
+    case SpvOpVectorExtractDynamic: return "OpVectorExtractDynamic";
+    case SpvOpVectorInsertDynamic: return "OpVectorInsertDynamic";
+    case SpvOpVectorShuffle: return "OpVectorShuffle";
+    case SpvOpCompositeConstruct: return "OpCompositeConstruct";
+    case SpvOpCompositeExtract: return "OpCompositeExtract";
+    case SpvOpCompositeInsert: return "OpCompositeInsert";
+    case SpvOpCopyObject: return "OpCopyObject";
+    case SpvOpTranspose: return "OpTranspose";
+    case SpvOpSampledImage: return "OpSampledImage";
+    case SpvOpImageSampleImplicitLod: return "OpImageSampleImplicitLod";
+    case SpvOpImageSampleExplicitLod: return "OpImageSampleExplicitLod";
+    case SpvOpImageSampleDrefImplicitLod: return "OpImageSampleDrefImplicitLod";
+    case SpvOpImageSampleDrefExplicitLod: return "OpImageSampleDrefExplicitLod";
+    case SpvOpImageSampleProjImplicitLod: return "OpImageSampleProjImplicitLod";
+    case SpvOpImageSampleProjExplicitLod: return "OpImageSampleProjExplicitLod";
+    case SpvOpImageSampleProjDrefImplicitLod: return "OpImageSampleProjDrefImplicitLod";
+    case SpvOpImageSampleProjDrefExplicitLod: return "OpImageSampleProjDrefExplicitLod";
+    case SpvOpImageFetch: return "OpImageFetch";
+    case SpvOpImageGather: return "OpImageGather";
+    case SpvOpImageDrefGather: return "OpImageDrefGather";
+    case SpvOpImageRead: return "OpImageRead";
+    case SpvOpImageWrite: return "OpImageWrite";
+    case SpvOpImage: return "OpImage";
+    case SpvOpImageQueryFormat: return "OpImageQueryFormat";
+    case SpvOpImageQueryOrder: return "OpImageQueryOrder";
+    case SpvOpImageQuerySizeLod: return "OpImageQuerySizeLod";
+    case SpvOpImageQuerySize: return "OpImageQuerySize";
+    case SpvOpImageQueryLod: return "OpImageQueryLod";
+    case SpvOpImageQueryLevels: return "OpImageQueryLevels";
+    case SpvOpImageQuerySamples: return "OpImageQuerySamples";
+    case SpvOpConvertFToU: return "OpConvertFToU";
+    case SpvOpConvertFToS: return "OpConvertFToS";
+    case SpvOpConvertSToF: return "OpConvertSToF";
+    case SpvOpConvertUToF: return "OpConvertUToF";
+    case SpvOpUConvert: return "OpUConvert";
+    case SpvOpSConvert: return "OpSConvert";
+    case SpvOpFConvert: return "OpFConvert";
+    case SpvOpQuantizeToF16: return "OpQuantizeToF16";
+    case SpvOpConvertPtrToU: return "OpConvertPtrToU";
+    case SpvOpSatConvertSToU: return "OpSatConvertSToU";
+    case SpvOpSatConvertUToS: return "OpSatConvertUToS";
+    case SpvOpConvertUToPtr: return "OpConvertUToPtr";
+    case SpvOpPtrCastToGeneric: return "OpPtrCastToGeneric";
+    case SpvOpGenericCastToPtr: return "OpGenericCastToPtr";
+    case SpvOpGenericCastToPtrExplicit: return "OpGenericCastToPtrExplicit";
+    case SpvOpBitcast: return "OpBitcast";
+    case SpvOpSNegate: return "OpSNegate";
+    case SpvOpFNegate: return "OpFNegate";
+    case SpvOpIAdd: return "OpIAdd";
+    case SpvOpFAdd: return "OpFAdd";
+    case SpvOpISub: return "OpISub";
+    case SpvOpFSub: return "OpFSub";
+    case SpvOpIMul: return "OpIMul";
+    case SpvOpFMul: return "OpFMul";
+    case SpvOpUDiv: return "OpUDiv";
+    case SpvOpSDiv: return "OpSDiv";
+    case SpvOpFDiv: return "OpFDiv";
+    case SpvOpUMod: return "OpUMod";
+    case SpvOpSRem: return "OpSRem";
+    case SpvOpSMod: return "OpSMod";
+    case SpvOpFRem: return "OpFRem";
+    case SpvOpFMod: return "OpFMod";
+    case SpvOpVectorTimesScalar: return "OpVectorTimesScalar";
+    case SpvOpMatrixTimesScalar: return "OpMatrixTimesScalar";
+    case SpvOpVectorTimesMatrix: return "OpVectorTimesMatrix";
+    case SpvOpMatrixTimesVector: return "OpMatrixTimesVector";
+    case SpvOpMatrixTimesMatrix: return "OpMatrixTimesMatrix";
+    case SpvOpOuterProduct: return "OpOuterProduct";
+    case SpvOpDot: return "OpDot";
+    case SpvOpIAddCarry: return "OpIAddCarry";
+    case SpvOpISubBorrow: return "OpISubBorrow";
+    case SpvOpUMulExtended: return "OpUMulExtended";
+    case SpvOpSMulExtended: return "OpSMulExtended";
+    case SpvOpAny: return "OpAny";
+    case SpvOpAll: return "OpAll";
+    case SpvOpIsNan: return "OpIsNan";
+    case SpvOpIsInf: return "OpIsInf";
+    case SpvOpIsFinite: return "OpIsFinite";
+    case SpvOpIsNormal: return "OpIsNormal";
+    case SpvOpSignBitSet: return "OpSignBitSet";
+    case SpvOpLessOrGreater: return "OpLessOrGreater";
+    case SpvOpOrdered: return "OpOrdered";
+    case SpvOpUnordered: return "OpUnordered";
+    case SpvOpLogicalEqual: return "OpLogicalEqual";
+    case SpvOpLogicalNotEqual: return "OpLogicalNotEqual";
+    case SpvOpLogicalOr: return "OpLogicalOr";
+    case SpvOpLogicalAnd: return "OpLogicalAnd";
+    case SpvOpLogicalNot: return "OpLogicalNot";
+    case SpvOpSelect: return "OpSelect";
+    case SpvOpIEqual: return "OpIEqual";
+    case SpvOpINotEqual: return "OpINotEqual";
+    case SpvOpUGreaterThan: return "OpUGreaterThan";
+    case SpvOpSGreaterThan: return "OpSGreaterThan";
+    case SpvOpUGreaterThanEqual: return "OpUGreaterThanEqual";
+    case SpvOpSGreaterThanEqual: return "OpSGreaterThanEqual";
+    case SpvOpULessThan: return "OpULessThan";
+    case SpvOpSLessThan: return "OpSLessThan";
+    case SpvOpULessThanEqual: return "OpULessThanEqual";
+    case SpvOpSLessThanEqual: return "OpSLessThanEqual";
+    case SpvOpFOrdEqual: return "OpFOrdEqual";
+    case SpvOpFUnordEqual: return "OpFUnordEqual";
+    case SpvOpFOrdNotEqual: return "OpFOrdNotEqual";
+    case SpvOpFUnordNotEqual: return "OpFUnordNotEqual";
+    case SpvOpFOrdLessThan: return "OpFOrdLessThan";
+    case SpvOpFUnordLessThan: return "OpFUnordLessThan";
+    case SpvOpFOrdGreaterThan: return "OpFOrdGreaterThan";
+    case SpvOpFUnordGreaterThan: return "OpFUnordGreaterThan";
+    case SpvOpFOrdLessThanEqual: return "OpFOrdLessThanEqual";
+    case SpvOpFUnordLessThanEqual: return "OpFUnordLessThanEqual";
+    case SpvOpFOrdGreaterThanEqual: return "OpFOrdGreaterThanEqual";
+    case SpvOpFUnordGreaterThanEqual: return "OpFUnordGreaterThanEqual";
+    case SpvOpShiftRightLogical: return "OpShiftRightLogical";
+    case SpvOpShiftRightArithmetic: return "OpShiftRightArithmetic";
+    case SpvOpShiftLeftLogical: return "OpShiftLeftLogical";
+    case SpvOpBitwiseOr: return "OpBitwiseOr";
+    case SpvOpBitwiseXor: return "OpBitwiseXor";
+    case SpvOpBitwiseAnd: return "OpBitwiseAnd";
+    case SpvOpNot: return "OpNot";
+    case SpvOpBitFieldInsert: return "OpBitFieldInsert";
+    case SpvOpBitFieldSExtract: return "OpBitFieldSExtract";
+    case SpvOpBitFieldUExtract: return "OpBitFieldUExtract";
+    case SpvOpBitReverse: return "OpBitReverse";
+    case SpvOpBitCount: return "OpBitCount";
+    case SpvOpDPdx: return "OpDPdx";
+    case SpvOpDPdy: return "OpDPdy";
+    case SpvOpFwidth: return "OpFwidth";
+    case SpvOpDPdxFine: return "OpDPdxFine";
+    case SpvOpDPdyFine: return "OpDPdyFine";
+    case SpvOpFwidthFine: return "OpFwidthFine";
+    case SpvOpDPdxCoarse: return "OpDPdxCoarse";
+    case SpvOpDPdyCoarse: return "OpDPdyCoarse";
+    case SpvOpFwidthCoarse: return "OpFwidthCoarse";
+    case SpvOpEmitVertex: return "OpEmitVertex";
+    case SpvOpEndPrimitive: return "OpEndPrimitive";
+    case SpvOpEmitStreamVertex: return "OpEmitStreamVertex";
+    case SpvOpEndStreamPrimitive: return "OpEndStreamPrimitive";
+    case SpvOpControlBarrier: return "OpControlBarrier";
+    case SpvOpMemoryBarrier: return "OpMemoryBarrier";
+    case SpvOpAtomicLoad: return "OpAtomicLoad";
+    case SpvOpAtomicStore: return "OpAtomicStore";
+    case SpvOpAtomicExchange: return "OpAtomicExchange";
+    case SpvOpAtomicCompareExchange: return "OpAtomicCompareExchange";
+    case SpvOpAtomicCompareExchangeWeak: return "OpAtomicCompareExchangeWeak";
+    case SpvOpAtomicIIncrement: return "OpAtomicIIncrement";
+    case SpvOpAtomicIDecrement: return "OpAtomicIDecrement";
+    case SpvOpAtomicIAdd: return "OpAtomicIAdd";
+    case SpvOpAtomicISub: return "OpAtomicISub";
+    case SpvOpAtomicSMin: return "OpAtomicSMin";
+    case SpvOpAtomicUMin: return "OpAtomicUMin";
+    case SpvOpAtomicSMax: return "OpAtomicSMax";
+    case SpvOpAtomicUMax: return "OpAtomicUMax";
+    case SpvOpAtomicAnd: return "OpAtomicAnd";
+    case SpvOpAtomicOr: return "OpAtomicOr";
+    case SpvOpAtomicXor: return "OpAtomicXor";
+    case SpvOpPhi: return "OpPhi";
+    case SpvOpLoopMerge: return "OpLoopMerge";
+    case SpvOpSelectionMerge: return "OpSelectionMerge";
+    case SpvOpLabel: return "OpLabel";
+    case SpvOpBranch: return "OpBranch";
+    case SpvOpBranchConditional: return "OpBranchConditional";
+    case SpvOpSwitch: return "OpSwitch";
+    case SpvOpKill: return "OpKill";
+    case SpvOpReturn: return "OpReturn";
+    case SpvOpReturnValue: return "OpReturnValue";
+    case SpvOpUnreachable: return "OpUnreachable";
+    case SpvOpLifetimeStart: return "OpLifetimeStart";
+    case SpvOpLifetimeStop: return "OpLifetimeStop";
+    case SpvOpGroupAsyncCopy: return "OpGroupAsyncCopy";
+    case SpvOpGroupWaitEvents: return "OpGroupWaitEvents";
+    case SpvOpGroupAll: return "OpGroupAll";
+    case SpvOpGroupAny: return "OpGroupAny";
+    case SpvOpGroupBroadcast: return "OpGroupBroadcast";
+    case SpvOpGroupIAdd: return "OpGroupIAdd";
+    case SpvOpGroupFAdd: return "OpGroupFAdd";
+    case SpvOpGroupFMin: return "OpGroupFMin";
+    case SpvOpGroupUMin: return "OpGroupUMin";
+    case SpvOpGroupSMin: return "OpGroupSMin";
+    case SpvOpGroupFMax: return "OpGroupFMax";
+    case SpvOpGroupUMax: return "OpGroupUMax";
+    case SpvOpGroupSMax: return "OpGroupSMax";
+    case SpvOpReadPipe: return "OpReadPipe";
+    case SpvOpWritePipe: return "OpWritePipe";
+    case SpvOpReservedReadPipe: return "OpReservedReadPipe";
+    case SpvOpReservedWritePipe: return "OpReservedWritePipe";
+    case SpvOpReserveReadPipePackets: return "OpReserveReadPipePackets";
+    case SpvOpReserveWritePipePackets: return "OpReserveWritePipePackets";
+    case SpvOpCommitReadPipe: return "OpCommitReadPipe";
+    case SpvOpCommitWritePipe: return "OpCommitWritePipe";
+    case SpvOpIsValidReserveId: return "OpIsValidReserveId";
+    case SpvOpGetNumPipePackets: return "OpGetNumPipePackets";
+    case SpvOpGetMaxPipePackets: return "OpGetMaxPipePackets";
+    case SpvOpGroupReserveReadPipePackets: return "OpGroupReserveReadPipePackets";
+    case SpvOpGroupReserveWritePipePackets: return "OpGroupReserveWritePipePackets";
+    case SpvOpGroupCommitReadPipe: return "OpGroupCommitReadPipe";
+    case SpvOpGroupCommitWritePipe: return "OpGroupCommitWritePipe";
+    case SpvOpEnqueueMarker: return "OpEnqueueMarker";
+    case SpvOpEnqueueKernel: return "OpEnqueueKernel";
+    case SpvOpGetKernelNDrangeSubGroupCount: return "OpGetKernelNDrangeSubGroupCount";
+    case SpvOpGetKernelNDrangeMaxSubGroupSize: return "OpGetKernelNDrangeMaxSubGroupSize";
+    case SpvOpGetKernelWorkGroupSize: return "OpGetKernelWorkGroupSize";
+    case SpvOpGetKernelPreferredWorkGroupSizeMultiple: return "OpGetKernelPreferredWorkGroupSizeMultiple";
+    case SpvOpRetainEvent: return "OpRetainEvent";
+    case SpvOpReleaseEvent: return "OpReleaseEvent";
+    case SpvOpCreateUserEvent: return "OpCreateUserEvent";
+    case SpvOpIsValidEvent: return "OpIsValidEvent";
+    case SpvOpSetUserEventStatus: return "OpSetUserEventStatus";
+    case SpvOpCaptureEventProfilingInfo: return "OpCaptureEventProfilingInfo";
+    case SpvOpGetDefaultQueue: return "OpGetDefaultQueue";
+    case SpvOpBuildNDRange: return "OpBuildNDRange";
+    case SpvOpImageSparseSampleImplicitLod: return "OpImageSparseSampleImplicitLod";
+    case SpvOpImageSparseSampleExplicitLod: return "OpImageSparseSampleExplicitLod";
+    case SpvOpImageSparseSampleDrefImplicitLod: return "OpImageSparseSampleDrefImplicitLod";
+    case SpvOpImageSparseSampleDrefExplicitLod: return "OpImageSparseSampleDrefExplicitLod";
+    case SpvOpImageSparseSampleProjImplicitLod: return "OpImageSparseSampleProjImplicitLod";
+    case SpvOpImageSparseSampleProjExplicitLod: return "OpImageSparseSampleProjExplicitLod";
+    case SpvOpImageSparseSampleProjDrefImplicitLod: return "OpImageSparseSampleProjDrefImplicitLod";
+    case SpvOpImageSparseSampleProjDrefExplicitLod: return "OpImageSparseSampleProjDrefExplicitLod";
+    case SpvOpImageSparseFetch: return "OpImageSparseFetch";
+    case SpvOpImageSparseGather: return "OpImageSparseGather";
+    case SpvOpImageSparseDrefGather: return "OpImageSparseDrefGather";
+    case SpvOpImageSparseTexelsResident: return "OpImageSparseTexelsResident";
+    case SpvOpNoLine: return "OpNoLine";
+    case SpvOpAtomicFlagTestAndSet: return "OpAtomicFlagTestAndSet";
+    case SpvOpAtomicFlagClear: return "OpAtomicFlagClear";
+    case SpvOpImageSparseRead: return "OpImageSparseRead";
+    case SpvOpSizeOf: return "OpSizeOf";
+    case SpvOpTypePipeStorage: return "OpTypePipeStorage";
+    case SpvOpConstantPipeStorage: return "OpConstantPipeStorage";
+    case SpvOpCreatePipeFromPipeStorage: return "OpCreatePipeFromPipeStorage";
+    case SpvOpGetKernelLocalSizeForSubgroupCount: return "OpGetKernelLocalSizeForSubgroupCount";
+    case SpvOpGetKernelMaxNumSubgroups: return "OpGetKernelMaxNumSubgroups";
+    case SpvOpTypeNamedBarrier: return "OpTypeNamedBarrier";
+    case SpvOpNamedBarrierInitialize: return "OpNamedBarrierInitialize";
+    case SpvOpMemoryNamedBarrier: return "OpMemoryNamedBarrier";
+    case SpvOpModuleProcessed: return "OpModuleProcessed";
+    case SpvOpExecutionModeId: return "OpExecutionModeId";
+    case SpvOpDecorateId: return "OpDecorateId";
+    case SpvOpGroupNonUniformElect: return "OpGroupNonUniformElect";
+    case SpvOpGroupNonUniformAll: return "OpGroupNonUniformAll";
+    case SpvOpGroupNonUniformAny: return "OpGroupNonUniformAny";
+    case SpvOpGroupNonUniformAllEqual: return "OpGroupNonUniformAllEqual";
+    case SpvOpGroupNonUniformBroadcast: return "OpGroupNonUniformBroadcast";
+    case SpvOpGroupNonUniformBroadcastFirst: return "OpGroupNonUniformBroadcastFirst";
+    case SpvOpGroupNonUniformBallot: return "OpGroupNonUniformBallot";
+    case SpvOpGroupNonUniformInverseBallot: return "OpGroupNonUniformInverseBallot";
+    case SpvOpGroupNonUniformBallotBitExtract: return "OpGroupNonUniformBallotBitExtract";
+    case SpvOpGroupNonUniformBallotBitCount: return "OpGroupNonUniformBallotBitCount";
+    case SpvOpGroupNonUniformBallotFindLSB: return "OpGroupNonUniformBallotFindLSB";
+    case SpvOpGroupNonUniformBallotFindMSB: return "OpGroupNonUniformBallotFindMSB";
+    case SpvOpGroupNonUniformShuffle: return "OpGroupNonUniformShuffle";
+    case SpvOpGroupNonUniformShuffleXor: return "OpGroupNonUniformShuffleXor";
+    case SpvOpGroupNonUniformShuffleUp: return "OpGroupNonUniformShuffleUp";
+    case SpvOpGroupNonUniformShuffleDown: return "OpGroupNonUniformShuffleDown";
+    case SpvOpGroupNonUniformIAdd: return "OpGroupNonUniformIAdd";
+    case SpvOpGroupNonUniformFAdd: return "OpGroupNonUniformFAdd";
+    case SpvOpGroupNonUniformIMul: return "OpGroupNonUniformIMul";
+    case SpvOpGroupNonUniformFMul: return "OpGroupNonUniformFMul";
+    case SpvOpGroupNonUniformSMin: return "OpGroupNonUniformSMin";
+    case SpvOpGroupNonUniformUMin: return "OpGroupNonUniformUMin";
+    case SpvOpGroupNonUniformFMin: return "OpGroupNonUniformFMin";
+    case SpvOpGroupNonUniformSMax: return "OpGroupNonUniformSMax";
+    case SpvOpGroupNonUniformUMax: return "OpGroupNonUniformUMax";
+    case SpvOpGroupNonUniformFMax: return "OpGroupNonUniformFMax";
+    case SpvOpGroupNonUniformBitwiseAnd: return "OpGroupNonUniformBitwiseAnd";
+    case SpvOpGroupNonUniformBitwiseOr: return "OpGroupNonUniformBitwiseOr";
+    case SpvOpGroupNonUniformBitwiseXor: return "OpGroupNonUniformBitwiseXor";
+    case SpvOpGroupNonUniformLogicalAnd: return "OpGroupNonUniformLogicalAnd";
+    case SpvOpGroupNonUniformLogicalOr: return "OpGroupNonUniformLogicalOr";
+    case SpvOpGroupNonUniformLogicalXor: return "OpGroupNonUniformLogicalXor";
+    case SpvOpGroupNonUniformQuadBroadcast: return "OpGroupNonUniformQuadBroadcast";
+    case SpvOpGroupNonUniformQuadSwap: return "OpGroupNonUniformQuadSwap";
+    case SpvOpCopyLogical: return "OpCopyLogical";
+    case SpvOpPtrEqual: return "OpPtrEqual";
+    case SpvOpPtrNotEqual: return "OpPtrNotEqual";
+    case SpvOpPtrDiff: return "OpPtrDiff";
+    case SpvOpColorAttachmentReadEXT: return "OpColorAttachmentReadEXT";
+    case SpvOpDepthAttachmentReadEXT: return "OpDepthAttachmentReadEXT";
+    case SpvOpStencilAttachmentReadEXT: return "OpStencilAttachmentReadEXT";
+    case SpvOpTerminateInvocation: return "OpTerminateInvocation";
+    case SpvOpTypeUntypedPointerKHR: return "OpTypeUntypedPointerKHR";
+    case SpvOpUntypedVariableKHR: return "OpUntypedVariableKHR";
+    case SpvOpUntypedAccessChainKHR: return "OpUntypedAccessChainKHR";
+    case SpvOpUntypedInBoundsAccessChainKHR: return "OpUntypedInBoundsAccessChainKHR";
+    case SpvOpSubgroupBallotKHR: return "OpSubgroupBallotKHR";
+    case SpvOpSubgroupFirstInvocationKHR: return "OpSubgroupFirstInvocationKHR";
+    case SpvOpUntypedPtrAccessChainKHR: return "OpUntypedPtrAccessChainKHR";
+    case SpvOpUntypedInBoundsPtrAccessChainKHR: return "OpUntypedInBoundsPtrAccessChainKHR";
+    case SpvOpUntypedArrayLengthKHR: return "OpUntypedArrayLengthKHR";
+    case SpvOpUntypedPrefetchKHR: return "OpUntypedPrefetchKHR";
+    case SpvOpSubgroupAllKHR: return "OpSubgroupAllKHR";
+    case SpvOpSubgroupAnyKHR: return "OpSubgroupAnyKHR";
+    case SpvOpSubgroupAllEqualKHR: return "OpSubgroupAllEqualKHR";
+    case SpvOpGroupNonUniformRotateKHR: return "OpGroupNonUniformRotateKHR";
+    case SpvOpSubgroupReadInvocationKHR: return "OpSubgroupReadInvocationKHR";
+    case SpvOpExtInstWithForwardRefsKHR: return "OpExtInstWithForwardRefsKHR";
+    case SpvOpTraceRayKHR: return "OpTraceRayKHR";
+    case SpvOpExecuteCallableKHR: return "OpExecuteCallableKHR";
+    case SpvOpConvertUToAccelerationStructureKHR: return "OpConvertUToAccelerationStructureKHR";
+    case SpvOpIgnoreIntersectionKHR: return "OpIgnoreIntersectionKHR";
+    case SpvOpTerminateRayKHR: return "OpTerminateRayKHR";
+    case SpvOpSDot: return "OpSDot";
+    case SpvOpUDot: return "OpUDot";
+    case SpvOpSUDot: return "OpSUDot";
+    case SpvOpSDotAccSat: return "OpSDotAccSat";
+    case SpvOpUDotAccSat: return "OpUDotAccSat";
+    case SpvOpSUDotAccSat: return "OpSUDotAccSat";
+    case SpvOpTypeCooperativeMatrixKHR: return "OpTypeCooperativeMatrixKHR";
+    case SpvOpCooperativeMatrixLoadKHR: return "OpCooperativeMatrixLoadKHR";
+    case SpvOpCooperativeMatrixStoreKHR: return "OpCooperativeMatrixStoreKHR";
+    case SpvOpCooperativeMatrixMulAddKHR: return "OpCooperativeMatrixMulAddKHR";
+    case SpvOpCooperativeMatrixLengthKHR: return "OpCooperativeMatrixLengthKHR";
+    case SpvOpConstantCompositeReplicateEXT: return "OpConstantCompositeReplicateEXT";
+    case SpvOpSpecConstantCompositeReplicateEXT: return "OpSpecConstantCompositeReplicateEXT";
+    case SpvOpCompositeConstructReplicateEXT: return "OpCompositeConstructReplicateEXT";
+    case SpvOpTypeRayQueryKHR: return "OpTypeRayQueryKHR";
+    case SpvOpRayQueryInitializeKHR: return "OpRayQueryInitializeKHR";
+    case SpvOpRayQueryTerminateKHR: return "OpRayQueryTerminateKHR";
+    case SpvOpRayQueryGenerateIntersectionKHR: return "OpRayQueryGenerateIntersectionKHR";
+    case SpvOpRayQueryConfirmIntersectionKHR: return "OpRayQueryConfirmIntersectionKHR";
+    case SpvOpRayQueryProceedKHR: return "OpRayQueryProceedKHR";
+    case SpvOpRayQueryGetIntersectionTypeKHR: return "OpRayQueryGetIntersectionTypeKHR";
+    case SpvOpImageSampleWeightedQCOM: return "OpImageSampleWeightedQCOM";
+    case SpvOpImageBoxFilterQCOM: return "OpImageBoxFilterQCOM";
+    case SpvOpImageBlockMatchSSDQCOM: return "OpImageBlockMatchSSDQCOM";
+    case SpvOpImageBlockMatchSADQCOM: return "OpImageBlockMatchSADQCOM";
+    case SpvOpImageBlockMatchWindowSSDQCOM: return "OpImageBlockMatchWindowSSDQCOM";
+    case SpvOpImageBlockMatchWindowSADQCOM: return "OpImageBlockMatchWindowSADQCOM";
+    case SpvOpImageBlockMatchGatherSSDQCOM: return "OpImageBlockMatchGatherSSDQCOM";
+    case SpvOpImageBlockMatchGatherSADQCOM: return "OpImageBlockMatchGatherSADQCOM";
+    case SpvOpGroupIAddNonUniformAMD: return "OpGroupIAddNonUniformAMD";
+    case SpvOpGroupFAddNonUniformAMD: return "OpGroupFAddNonUniformAMD";
+    case SpvOpGroupFMinNonUniformAMD: return "OpGroupFMinNonUniformAMD";
+    case SpvOpGroupUMinNonUniformAMD: return "OpGroupUMinNonUniformAMD";
+    case SpvOpGroupSMinNonUniformAMD: return "OpGroupSMinNonUniformAMD";
+    case SpvOpGroupFMaxNonUniformAMD: return "OpGroupFMaxNonUniformAMD";
+    case SpvOpGroupUMaxNonUniformAMD: return "OpGroupUMaxNonUniformAMD";
+    case SpvOpGroupSMaxNonUniformAMD: return "OpGroupSMaxNonUniformAMD";
+    case SpvOpFragmentMaskFetchAMD: return "OpFragmentMaskFetchAMD";
+    case SpvOpFragmentFetchAMD: return "OpFragmentFetchAMD";
+    case SpvOpReadClockKHR: return "OpReadClockKHR";
+    case SpvOpAllocateNodePayloadsAMDX: return "OpAllocateNodePayloadsAMDX";
+    case SpvOpEnqueueNodePayloadsAMDX: return "OpEnqueueNodePayloadsAMDX";
+    case SpvOpTypeNodePayloadArrayAMDX: return "OpTypeNodePayloadArrayAMDX";
+    case SpvOpFinishWritingNodePayloadAMDX: return "OpFinishWritingNodePayloadAMDX";
+    case SpvOpNodePayloadArrayLengthAMDX: return "OpNodePayloadArrayLengthAMDX";
+    case SpvOpIsNodePayloadValidAMDX: return "OpIsNodePayloadValidAMDX";
+    case SpvOpConstantStringAMDX: return "OpConstantStringAMDX";
+    case SpvOpSpecConstantStringAMDX: return "OpSpecConstantStringAMDX";
+    case SpvOpGroupNonUniformQuadAllKHR: return "OpGroupNonUniformQuadAllKHR";
+    case SpvOpGroupNonUniformQuadAnyKHR: return "OpGroupNonUniformQuadAnyKHR";
+    case SpvOpHitObjectRecordHitMotionNV: return "OpHitObjectRecordHitMotionNV";
+    case SpvOpHitObjectRecordHitWithIndexMotionNV: return "OpHitObjectRecordHitWithIndexMotionNV";
+    case SpvOpHitObjectRecordMissMotionNV: return "OpHitObjectRecordMissMotionNV";
+    case SpvOpHitObjectGetWorldToObjectNV: return "OpHitObjectGetWorldToObjectNV";
+    case SpvOpHitObjectGetObjectToWorldNV: return "OpHitObjectGetObjectToWorldNV";
+    case SpvOpHitObjectGetObjectRayDirectionNV: return "OpHitObjectGetObjectRayDirectionNV";
+    case SpvOpHitObjectGetObjectRayOriginNV: return "OpHitObjectGetObjectRayOriginNV";
+    case SpvOpHitObjectTraceRayMotionNV: return "OpHitObjectTraceRayMotionNV";
+    case SpvOpHitObjectGetShaderRecordBufferHandleNV: return "OpHitObjectGetShaderRecordBufferHandleNV";
+    case SpvOpHitObjectGetShaderBindingTableRecordIndexNV: return "OpHitObjectGetShaderBindingTableRecordIndexNV";
+    case SpvOpHitObjectRecordEmptyNV: return "OpHitObjectRecordEmptyNV";
+    case SpvOpHitObjectTraceRayNV: return "OpHitObjectTraceRayNV";
+    case SpvOpHitObjectRecordHitNV: return "OpHitObjectRecordHitNV";
+    case SpvOpHitObjectRecordHitWithIndexNV: return "OpHitObjectRecordHitWithIndexNV";
+    case SpvOpHitObjectRecordMissNV: return "OpHitObjectRecordMissNV";
+    case SpvOpHitObjectExecuteShaderNV: return "OpHitObjectExecuteShaderNV";
+    case SpvOpHitObjectGetCurrentTimeNV: return "OpHitObjectGetCurrentTimeNV";
+    case SpvOpHitObjectGetAttributesNV: return "OpHitObjectGetAttributesNV";
+    case SpvOpHitObjectGetHitKindNV: return "OpHitObjectGetHitKindNV";
+    case SpvOpHitObjectGetPrimitiveIndexNV: return "OpHitObjectGetPrimitiveIndexNV";
+    case SpvOpHitObjectGetGeometryIndexNV: return "OpHitObjectGetGeometryIndexNV";
+    case SpvOpHitObjectGetInstanceIdNV: return "OpHitObjectGetInstanceIdNV";
+    case SpvOpHitObjectGetInstanceCustomIndexNV: return "OpHitObjectGetInstanceCustomIndexNV";
+    case SpvOpHitObjectGetWorldRayDirectionNV: return "OpHitObjectGetWorldRayDirectionNV";
+    case SpvOpHitObjectGetWorldRayOriginNV: return "OpHitObjectGetWorldRayOriginNV";
+    case SpvOpHitObjectGetRayTMaxNV: return "OpHitObjectGetRayTMaxNV";
+    case SpvOpHitObjectGetRayTMinNV: return "OpHitObjectGetRayTMinNV";
+    case SpvOpHitObjectIsEmptyNV: return "OpHitObjectIsEmptyNV";
+    case SpvOpHitObjectIsHitNV: return "OpHitObjectIsHitNV";
+    case SpvOpHitObjectIsMissNV: return "OpHitObjectIsMissNV";
+    case SpvOpReorderThreadWithHitObjectNV: return "OpReorderThreadWithHitObjectNV";
+    case SpvOpReorderThreadWithHintNV: return "OpReorderThreadWithHintNV";
+    case SpvOpTypeHitObjectNV: return "OpTypeHitObjectNV";
+    case SpvOpImageSampleFootprintNV: return "OpImageSampleFootprintNV";
+    case SpvOpCooperativeMatrixConvertNV: return "OpCooperativeMatrixConvertNV";
+    case SpvOpEmitMeshTasksEXT: return "OpEmitMeshTasksEXT";
+    case SpvOpSetMeshOutputsEXT: return "OpSetMeshOutputsEXT";
+    case SpvOpGroupNonUniformPartitionNV: return "OpGroupNonUniformPartitionNV";
+    case SpvOpWritePackedPrimitiveIndices4x8NV: return "OpWritePackedPrimitiveIndices4x8NV";
+    case SpvOpFetchMicroTriangleVertexPositionNV: return "OpFetchMicroTriangleVertexPositionNV";
+    case SpvOpFetchMicroTriangleVertexBarycentricNV: return "OpFetchMicroTriangleVertexBarycentricNV";
+    case SpvOpReportIntersectionKHR: return "OpReportIntersectionKHR";
+    case SpvOpIgnoreIntersectionNV: return "OpIgnoreIntersectionNV";
+    case SpvOpTerminateRayNV: return "OpTerminateRayNV";
+    case SpvOpTraceNV: return "OpTraceNV";
+    case SpvOpTraceMotionNV: return "OpTraceMotionNV";
+    case SpvOpTraceRayMotionNV: return "OpTraceRayMotionNV";
+    case SpvOpRayQueryGetIntersectionTriangleVertexPositionsKHR: return "OpRayQueryGetIntersectionTriangleVertexPositionsKHR";
+    case SpvOpTypeAccelerationStructureKHR: return "OpTypeAccelerationStructureKHR";
+    case SpvOpExecuteCallableNV: return "OpExecuteCallableNV";
+    case SpvOpTypeCooperativeMatrixNV: return "OpTypeCooperativeMatrixNV";
+    case SpvOpCooperativeMatrixLoadNV: return "OpCooperativeMatrixLoadNV";
+    case SpvOpCooperativeMatrixStoreNV: return "OpCooperativeMatrixStoreNV";
+    case SpvOpCooperativeMatrixMulAddNV: return "OpCooperativeMatrixMulAddNV";
+    case SpvOpCooperativeMatrixLengthNV: return "OpCooperativeMatrixLengthNV";
+    case SpvOpBeginInvocationInterlockEXT: return "OpBeginInvocationInterlockEXT";
+    case SpvOpEndInvocationInterlockEXT: return "OpEndInvocationInterlockEXT";
+    case SpvOpCooperativeMatrixReduceNV: return "OpCooperativeMatrixReduceNV";
+    case SpvOpCooperativeMatrixLoadTensorNV: return "OpCooperativeMatrixLoadTensorNV";
+    case SpvOpCooperativeMatrixStoreTensorNV: return "OpCooperativeMatrixStoreTensorNV";
+    case SpvOpCooperativeMatrixPerElementOpNV: return "OpCooperativeMatrixPerElementOpNV";
+    case SpvOpTypeTensorLayoutNV: return "OpTypeTensorLayoutNV";
+    case SpvOpTypeTensorViewNV: return "OpTypeTensorViewNV";
+    case SpvOpCreateTensorLayoutNV: return "OpCreateTensorLayoutNV";
+    case SpvOpTensorLayoutSetDimensionNV: return "OpTensorLayoutSetDimensionNV";
+    case SpvOpTensorLayoutSetStrideNV: return "OpTensorLayoutSetStrideNV";
+    case SpvOpTensorLayoutSliceNV: return "OpTensorLayoutSliceNV";
+    case SpvOpTensorLayoutSetClampValueNV: return "OpTensorLayoutSetClampValueNV";
+    case SpvOpCreateTensorViewNV: return "OpCreateTensorViewNV";
+    case SpvOpTensorViewSetDimensionNV: return "OpTensorViewSetDimensionNV";
+    case SpvOpTensorViewSetStrideNV: return "OpTensorViewSetStrideNV";
+    case SpvOpDemoteToHelperInvocation: return "OpDemoteToHelperInvocation";
+    case SpvOpIsHelperInvocationEXT: return "OpIsHelperInvocationEXT";
+    case SpvOpTensorViewSetClipNV: return "OpTensorViewSetClipNV";
+    case SpvOpTensorLayoutSetBlockSizeNV: return "OpTensorLayoutSetBlockSizeNV";
+    case SpvOpCooperativeMatrixTransposeNV: return "OpCooperativeMatrixTransposeNV";
+    case SpvOpConvertUToImageNV: return "OpConvertUToImageNV";
+    case SpvOpConvertUToSamplerNV: return "OpConvertUToSamplerNV";
+    case SpvOpConvertImageToUNV: return "OpConvertImageToUNV";
+    case SpvOpConvertSamplerToUNV: return "OpConvertSamplerToUNV";
+    case SpvOpConvertUToSampledImageNV: return "OpConvertUToSampledImageNV";
+    case SpvOpConvertSampledImageToUNV: return "OpConvertSampledImageToUNV";
+    case SpvOpSamplerImageAddressingModeNV: return "OpSamplerImageAddressingModeNV";
+    case SpvOpRawAccessChainNV: return "OpRawAccessChainNV";
+    case SpvOpSubgroupShuffleINTEL: return "OpSubgroupShuffleINTEL";
+    case SpvOpSubgroupShuffleDownINTEL: return "OpSubgroupShuffleDownINTEL";
+    case SpvOpSubgroupShuffleUpINTEL: return "OpSubgroupShuffleUpINTEL";
+    case SpvOpSubgroupShuffleXorINTEL: return "OpSubgroupShuffleXorINTEL";
+    case SpvOpSubgroupBlockReadINTEL: return "OpSubgroupBlockReadINTEL";
+    case SpvOpSubgroupBlockWriteINTEL: return "OpSubgroupBlockWriteINTEL";
+    case SpvOpSubgroupImageBlockReadINTEL: return "OpSubgroupImageBlockReadINTEL";
+    case SpvOpSubgroupImageBlockWriteINTEL: return "OpSubgroupImageBlockWriteINTEL";
+    case SpvOpSubgroupImageMediaBlockReadINTEL: return "OpSubgroupImageMediaBlockReadINTEL";
+    case SpvOpSubgroupImageMediaBlockWriteINTEL: return "OpSubgroupImageMediaBlockWriteINTEL";
+    case SpvOpUCountLeadingZerosINTEL: return "OpUCountLeadingZerosINTEL";
+    case SpvOpUCountTrailingZerosINTEL: return "OpUCountTrailingZerosINTEL";
+    case SpvOpAbsISubINTEL: return "OpAbsISubINTEL";
+    case SpvOpAbsUSubINTEL: return "OpAbsUSubINTEL";
+    case SpvOpIAddSatINTEL: return "OpIAddSatINTEL";
+    case SpvOpUAddSatINTEL: return "OpUAddSatINTEL";
+    case SpvOpIAverageINTEL: return "OpIAverageINTEL";
+    case SpvOpUAverageINTEL: return "OpUAverageINTEL";
+    case SpvOpIAverageRoundedINTEL: return "OpIAverageRoundedINTEL";
+    case SpvOpUAverageRoundedINTEL: return "OpUAverageRoundedINTEL";
+    case SpvOpISubSatINTEL: return "OpISubSatINTEL";
+    case SpvOpUSubSatINTEL: return "OpUSubSatINTEL";
+    case SpvOpIMul32x16INTEL: return "OpIMul32x16INTEL";
+    case SpvOpUMul32x16INTEL: return "OpUMul32x16INTEL";
+    case SpvOpConstantFunctionPointerINTEL: return "OpConstantFunctionPointerINTEL";
+    case SpvOpFunctionPointerCallINTEL: return "OpFunctionPointerCallINTEL";
+    case SpvOpAsmTargetINTEL: return "OpAsmTargetINTEL";
+    case SpvOpAsmINTEL: return "OpAsmINTEL";
+    case SpvOpAsmCallINTEL: return "OpAsmCallINTEL";
+    case SpvOpAtomicFMinEXT: return "OpAtomicFMinEXT";
+    case SpvOpAtomicFMaxEXT: return "OpAtomicFMaxEXT";
+    case SpvOpAssumeTrueKHR: return "OpAssumeTrueKHR";
+    case SpvOpExpectKHR: return "OpExpectKHR";
+    case SpvOpDecorateString: return "OpDecorateString";
+    case SpvOpMemberDecorateString: return "OpMemberDecorateString";
+    case SpvOpVmeImageINTEL: return "OpVmeImageINTEL";
+    case SpvOpTypeVmeImageINTEL: return "OpTypeVmeImageINTEL";
+    case SpvOpTypeAvcImePayloadINTEL: return "OpTypeAvcImePayloadINTEL";
+    case SpvOpTypeAvcRefPayloadINTEL: return "OpTypeAvcRefPayloadINTEL";
+    case SpvOpTypeAvcSicPayloadINTEL: return "OpTypeAvcSicPayloadINTEL";
+    case SpvOpTypeAvcMcePayloadINTEL: return "OpTypeAvcMcePayloadINTEL";
+    case SpvOpTypeAvcMceResultINTEL: return "OpTypeAvcMceResultINTEL";
+    case SpvOpTypeAvcImeResultINTEL: return "OpTypeAvcImeResultINTEL";
+    case SpvOpTypeAvcImeResultSingleReferenceStreamoutINTEL: return "OpTypeAvcImeResultSingleReferenceStreamoutINTEL";
+    case SpvOpTypeAvcImeResultDualReferenceStreamoutINTEL: return "OpTypeAvcImeResultDualReferenceStreamoutINTEL";
+    case SpvOpTypeAvcImeSingleReferenceStreaminINTEL: return "OpTypeAvcImeSingleReferenceStreaminINTEL";
+    case SpvOpTypeAvcImeDualReferenceStreaminINTEL: return "OpTypeAvcImeDualReferenceStreaminINTEL";
+    case SpvOpTypeAvcRefResultINTEL: return "OpTypeAvcRefResultINTEL";
+    case SpvOpTypeAvcSicResultINTEL: return "OpTypeAvcSicResultINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultInterBaseMultiReferencePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterBaseMultiReferencePenaltyINTEL";
+    case SpvOpSubgroupAvcMceSetInterBaseMultiReferencePenaltyINTEL: return "OpSubgroupAvcMceSetInterBaseMultiReferencePenaltyINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultInterShapePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterShapePenaltyINTEL";
+    case SpvOpSubgroupAvcMceSetInterShapePenaltyINTEL: return "OpSubgroupAvcMceSetInterShapePenaltyINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultInterDirectionPenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterDirectionPenaltyINTEL";
+    case SpvOpSubgroupAvcMceSetInterDirectionPenaltyINTEL: return "OpSubgroupAvcMceSetInterDirectionPenaltyINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultIntraLumaShapePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraLumaShapePenaltyINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultInterMotionVectorCostTableINTEL: return "OpSubgroupAvcMceGetDefaultInterMotionVectorCostTableINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultHighPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultHighPenaltyCostTableINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultMediumPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultMediumPenaltyCostTableINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultLowPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultLowPenaltyCostTableINTEL";
+    case SpvOpSubgroupAvcMceSetMotionVectorCostFunctionINTEL: return "OpSubgroupAvcMceSetMotionVectorCostFunctionINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultIntraLumaModePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraLumaModePenaltyINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultNonDcLumaIntraPenaltyINTEL: return "OpSubgroupAvcMceGetDefaultNonDcLumaIntraPenaltyINTEL";
+    case SpvOpSubgroupAvcMceGetDefaultIntraChromaModeBasePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraChromaModeBasePenaltyINTEL";
+    case SpvOpSubgroupAvcMceSetAcOnlyHaarINTEL: return "OpSubgroupAvcMceSetAcOnlyHaarINTEL";
+    case SpvOpSubgroupAvcMceSetSourceInterlacedFieldPolarityINTEL: return "OpSubgroupAvcMceSetSourceInterlacedFieldPolarityINTEL";
+    case SpvOpSubgroupAvcMceSetSingleReferenceInterlacedFieldPolarityINTEL: return "OpSubgroupAvcMceSetSingleReferenceInterlacedFieldPolarityINTEL";
+    case SpvOpSubgroupAvcMceSetDualReferenceInterlacedFieldPolaritiesINTEL: return "OpSubgroupAvcMceSetDualReferenceInterlacedFieldPolaritiesINTEL";
+    case SpvOpSubgroupAvcMceConvertToImePayloadINTEL: return "OpSubgroupAvcMceConvertToImePayloadINTEL";
+    case SpvOpSubgroupAvcMceConvertToImeResultINTEL: return "OpSubgroupAvcMceConvertToImeResultINTEL";
+    case SpvOpSubgroupAvcMceConvertToRefPayloadINTEL: return "OpSubgroupAvcMceConvertToRefPayloadINTEL";
+    case SpvOpSubgroupAvcMceConvertToRefResultINTEL: return "OpSubgroupAvcMceConvertToRefResultINTEL";
+    case SpvOpSubgroupAvcMceConvertToSicPayloadINTEL: return "OpSubgroupAvcMceConvertToSicPayloadINTEL";
+    case SpvOpSubgroupAvcMceConvertToSicResultINTEL: return "OpSubgroupAvcMceConvertToSicResultINTEL";
+    case SpvOpSubgroupAvcMceGetMotionVectorsINTEL: return "OpSubgroupAvcMceGetMotionVectorsINTEL";
+    case SpvOpSubgroupAvcMceGetInterDistortionsINTEL: return "OpSubgroupAvcMceGetInterDistortionsINTEL";
+    case SpvOpSubgroupAvcMceGetBestInterDistortionsINTEL: return "OpSubgroupAvcMceGetBestInterDistortionsINTEL";
+    case SpvOpSubgroupAvcMceGetInterMajorShapeINTEL: return "OpSubgroupAvcMceGetInterMajorShapeINTEL";
+    case SpvOpSubgroupAvcMceGetInterMinorShapeINTEL: return "OpSubgroupAvcMceGetInterMinorShapeINTEL";
+    case SpvOpSubgroupAvcMceGetInterDirectionsINTEL: return "OpSubgroupAvcMceGetInterDirectionsINTEL";
+    case SpvOpSubgroupAvcMceGetInterMotionVectorCountINTEL: return "OpSubgroupAvcMceGetInterMotionVectorCountINTEL";
+    case SpvOpSubgroupAvcMceGetInterReferenceIdsINTEL: return "OpSubgroupAvcMceGetInterReferenceIdsINTEL";
+    case SpvOpSubgroupAvcMceGetInterReferenceInterlacedFieldPolaritiesINTEL: return "OpSubgroupAvcMceGetInterReferenceInterlacedFieldPolaritiesINTEL";
+    case SpvOpSubgroupAvcImeInitializeINTEL: return "OpSubgroupAvcImeInitializeINTEL";
+    case SpvOpSubgroupAvcImeSetSingleReferenceINTEL: return "OpSubgroupAvcImeSetSingleReferenceINTEL";
+    case SpvOpSubgroupAvcImeSetDualReferenceINTEL: return "OpSubgroupAvcImeSetDualReferenceINTEL";
+    case SpvOpSubgroupAvcImeRefWindowSizeINTEL: return "OpSubgroupAvcImeRefWindowSizeINTEL";
+    case SpvOpSubgroupAvcImeAdjustRefOffsetINTEL: return "OpSubgroupAvcImeAdjustRefOffsetINTEL";
+    case SpvOpSubgroupAvcImeConvertToMcePayloadINTEL: return "OpSubgroupAvcImeConvertToMcePayloadINTEL";
+    case SpvOpSubgroupAvcImeSetMaxMotionVectorCountINTEL: return "OpSubgroupAvcImeSetMaxMotionVectorCountINTEL";
+    case SpvOpSubgroupAvcImeSetUnidirectionalMixDisableINTEL: return "OpSubgroupAvcImeSetUnidirectionalMixDisableINTEL";
+    case SpvOpSubgroupAvcImeSetEarlySearchTerminationThresholdINTEL: return "OpSubgroupAvcImeSetEarlySearchTerminationThresholdINTEL";
+    case SpvOpSubgroupAvcImeSetWeightedSadINTEL: return "OpSubgroupAvcImeSetWeightedSadINTEL";
+    case SpvOpSubgroupAvcImeEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceINTEL";
+    case SpvOpSubgroupAvcImeEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceINTEL";
+    case SpvOpSubgroupAvcImeEvaluateWithSingleReferenceStreaminINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminINTEL";
+    case SpvOpSubgroupAvcImeEvaluateWithDualReferenceStreaminINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreaminINTEL";
+    case SpvOpSubgroupAvcImeEvaluateWithSingleReferenceStreamoutINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreamoutINTEL";
+    case SpvOpSubgroupAvcImeEvaluateWithDualReferenceStreamoutINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreamoutINTEL";
+    case SpvOpSubgroupAvcImeEvaluateWithSingleReferenceStreaminoutINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminoutINTEL";
+    case SpvOpSubgroupAvcImeEvaluateWithDualReferenceStreaminoutINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreaminoutINTEL";
+    case SpvOpSubgroupAvcImeConvertToMceResultINTEL: return "OpSubgroupAvcImeConvertToMceResultINTEL";
+    case SpvOpSubgroupAvcImeGetSingleReferenceStreaminINTEL: return "OpSubgroupAvcImeGetSingleReferenceStreaminINTEL";
+    case SpvOpSubgroupAvcImeGetDualReferenceStreaminINTEL: return "OpSubgroupAvcImeGetDualReferenceStreaminINTEL";
+    case SpvOpSubgroupAvcImeStripSingleReferenceStreamoutINTEL: return "OpSubgroupAvcImeStripSingleReferenceStreamoutINTEL";
+    case SpvOpSubgroupAvcImeStripDualReferenceStreamoutINTEL: return "OpSubgroupAvcImeStripDualReferenceStreamoutINTEL";
+    case SpvOpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeMotionVectorsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeMotionVectorsINTEL";
+    case SpvOpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeDistortionsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeDistortionsINTEL";
+    case SpvOpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeReferenceIdsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeReferenceIdsINTEL";
+    case SpvOpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeMotionVectorsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeMotionVectorsINTEL";
+    case SpvOpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeDistortionsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeDistortionsINTEL";
+    case SpvOpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeReferenceIdsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeReferenceIdsINTEL";
+    case SpvOpSubgroupAvcImeGetBorderReachedINTEL: return "OpSubgroupAvcImeGetBorderReachedINTEL";
+    case SpvOpSubgroupAvcImeGetTruncatedSearchIndicationINTEL: return "OpSubgroupAvcImeGetTruncatedSearchIndicationINTEL";
+    case SpvOpSubgroupAvcImeGetUnidirectionalEarlySearchTerminationINTEL: return "OpSubgroupAvcImeGetUnidirectionalEarlySearchTerminationINTEL";
+    case SpvOpSubgroupAvcImeGetWeightingPatternMinimumMotionVectorINTEL: return "OpSubgroupAvcImeGetWeightingPatternMinimumMotionVectorINTEL";
+    case SpvOpSubgroupAvcImeGetWeightingPatternMinimumDistortionINTEL: return "OpSubgroupAvcImeGetWeightingPatternMinimumDistortionINTEL";
+    case SpvOpSubgroupAvcFmeInitializeINTEL: return "OpSubgroupAvcFmeInitializeINTEL";
+    case SpvOpSubgroupAvcBmeInitializeINTEL: return "OpSubgroupAvcBmeInitializeINTEL";
+    case SpvOpSubgroupAvcRefConvertToMcePayloadINTEL: return "OpSubgroupAvcRefConvertToMcePayloadINTEL";
+    case SpvOpSubgroupAvcRefSetBidirectionalMixDisableINTEL: return "OpSubgroupAvcRefSetBidirectionalMixDisableINTEL";
+    case SpvOpSubgroupAvcRefSetBilinearFilterEnableINTEL: return "OpSubgroupAvcRefSetBilinearFilterEnableINTEL";
+    case SpvOpSubgroupAvcRefEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithSingleReferenceINTEL";
+    case SpvOpSubgroupAvcRefEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithDualReferenceINTEL";
+    case SpvOpSubgroupAvcRefEvaluateWithMultiReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithMultiReferenceINTEL";
+    case SpvOpSubgroupAvcRefEvaluateWithMultiReferenceInterlacedINTEL: return "OpSubgroupAvcRefEvaluateWithMultiReferenceInterlacedINTEL";
+    case SpvOpSubgroupAvcRefConvertToMceResultINTEL: return "OpSubgroupAvcRefConvertToMceResultINTEL";
+    case SpvOpSubgroupAvcSicInitializeINTEL: return "OpSubgroupAvcSicInitializeINTEL";
+    case SpvOpSubgroupAvcSicConfigureSkcINTEL: return "OpSubgroupAvcSicConfigureSkcINTEL";
+    case SpvOpSubgroupAvcSicConfigureIpeLumaINTEL: return "OpSubgroupAvcSicConfigureIpeLumaINTEL";
+    case SpvOpSubgroupAvcSicConfigureIpeLumaChromaINTEL: return "OpSubgroupAvcSicConfigureIpeLumaChromaINTEL";
+    case SpvOpSubgroupAvcSicGetMotionVectorMaskINTEL: return "OpSubgroupAvcSicGetMotionVectorMaskINTEL";
+    case SpvOpSubgroupAvcSicConvertToMcePayloadINTEL: return "OpSubgroupAvcSicConvertToMcePayloadINTEL";
+    case SpvOpSubgroupAvcSicSetIntraLumaShapePenaltyINTEL: return "OpSubgroupAvcSicSetIntraLumaShapePenaltyINTEL";
+    case SpvOpSubgroupAvcSicSetIntraLumaModeCostFunctionINTEL: return "OpSubgroupAvcSicSetIntraLumaModeCostFunctionINTEL";
+    case SpvOpSubgroupAvcSicSetIntraChromaModeCostFunctionINTEL: return "OpSubgroupAvcSicSetIntraChromaModeCostFunctionINTEL";
+    case SpvOpSubgroupAvcSicSetBilinearFilterEnableINTEL: return "OpSubgroupAvcSicSetBilinearFilterEnableINTEL";
+    case SpvOpSubgroupAvcSicSetSkcForwardTransformEnableINTEL: return "OpSubgroupAvcSicSetSkcForwardTransformEnableINTEL";
+    case SpvOpSubgroupAvcSicSetBlockBasedRawSkipSadINTEL: return "OpSubgroupAvcSicSetBlockBasedRawSkipSadINTEL";
+    case SpvOpSubgroupAvcSicEvaluateIpeINTEL: return "OpSubgroupAvcSicEvaluateIpeINTEL";
+    case SpvOpSubgroupAvcSicEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithSingleReferenceINTEL";
+    case SpvOpSubgroupAvcSicEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithDualReferenceINTEL";
+    case SpvOpSubgroupAvcSicEvaluateWithMultiReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithMultiReferenceINTEL";
+    case SpvOpSubgroupAvcSicEvaluateWithMultiReferenceInterlacedINTEL: return "OpSubgroupAvcSicEvaluateWithMultiReferenceInterlacedINTEL";
+    case SpvOpSubgroupAvcSicConvertToMceResultINTEL: return "OpSubgroupAvcSicConvertToMceResultINTEL";
+    case SpvOpSubgroupAvcSicGetIpeLumaShapeINTEL: return "OpSubgroupAvcSicGetIpeLumaShapeINTEL";
+    case SpvOpSubgroupAvcSicGetBestIpeLumaDistortionINTEL: return "OpSubgroupAvcSicGetBestIpeLumaDistortionINTEL";
+    case SpvOpSubgroupAvcSicGetBestIpeChromaDistortionINTEL: return "OpSubgroupAvcSicGetBestIpeChromaDistortionINTEL";
+    case SpvOpSubgroupAvcSicGetPackedIpeLumaModesINTEL: return "OpSubgroupAvcSicGetPackedIpeLumaModesINTEL";
+    case SpvOpSubgroupAvcSicGetIpeChromaModeINTEL: return "OpSubgroupAvcSicGetIpeChromaModeINTEL";
+    case SpvOpSubgroupAvcSicGetPackedSkcLumaCountThresholdINTEL: return "OpSubgroupAvcSicGetPackedSkcLumaCountThresholdINTEL";
+    case SpvOpSubgroupAvcSicGetPackedSkcLumaSumThresholdINTEL: return "OpSubgroupAvcSicGetPackedSkcLumaSumThresholdINTEL";
+    case SpvOpSubgroupAvcSicGetInterRawSadsINTEL: return "OpSubgroupAvcSicGetInterRawSadsINTEL";
+    case SpvOpVariableLengthArrayINTEL: return "OpVariableLengthArrayINTEL";
+    case SpvOpSaveMemoryINTEL: return "OpSaveMemoryINTEL";
+    case SpvOpRestoreMemoryINTEL: return "OpRestoreMemoryINTEL";
+    case SpvOpArbitraryFloatSinCosPiINTEL: return "OpArbitraryFloatSinCosPiINTEL";
+    case SpvOpArbitraryFloatCastINTEL: return "OpArbitraryFloatCastINTEL";
+    case SpvOpArbitraryFloatCastFromIntINTEL: return "OpArbitraryFloatCastFromIntINTEL";
+    case SpvOpArbitraryFloatCastToIntINTEL: return "OpArbitraryFloatCastToIntINTEL";
+    case SpvOpArbitraryFloatAddINTEL: return "OpArbitraryFloatAddINTEL";
+    case SpvOpArbitraryFloatSubINTEL: return "OpArbitraryFloatSubINTEL";
+    case SpvOpArbitraryFloatMulINTEL: return "OpArbitraryFloatMulINTEL";
+    case SpvOpArbitraryFloatDivINTEL: return "OpArbitraryFloatDivINTEL";
+    case SpvOpArbitraryFloatGTINTEL: return "OpArbitraryFloatGTINTEL";
+    case SpvOpArbitraryFloatGEINTEL: return "OpArbitraryFloatGEINTEL";
+    case SpvOpArbitraryFloatLTINTEL: return "OpArbitraryFloatLTINTEL";
+    case SpvOpArbitraryFloatLEINTEL: return "OpArbitraryFloatLEINTEL";
+    case SpvOpArbitraryFloatEQINTEL: return "OpArbitraryFloatEQINTEL";
+    case SpvOpArbitraryFloatRecipINTEL: return "OpArbitraryFloatRecipINTEL";
+    case SpvOpArbitraryFloatRSqrtINTEL: return "OpArbitraryFloatRSqrtINTEL";
+    case SpvOpArbitraryFloatCbrtINTEL: return "OpArbitraryFloatCbrtINTEL";
+    case SpvOpArbitraryFloatHypotINTEL: return "OpArbitraryFloatHypotINTEL";
+    case SpvOpArbitraryFloatSqrtINTEL: return "OpArbitraryFloatSqrtINTEL";
+    case SpvOpArbitraryFloatLogINTEL: return "OpArbitraryFloatLogINTEL";
+    case SpvOpArbitraryFloatLog2INTEL: return "OpArbitraryFloatLog2INTEL";
+    case SpvOpArbitraryFloatLog10INTEL: return "OpArbitraryFloatLog10INTEL";
+    case SpvOpArbitraryFloatLog1pINTEL: return "OpArbitraryFloatLog1pINTEL";
+    case SpvOpArbitraryFloatExpINTEL: return "OpArbitraryFloatExpINTEL";
+    case SpvOpArbitraryFloatExp2INTEL: return "OpArbitraryFloatExp2INTEL";
+    case SpvOpArbitraryFloatExp10INTEL: return "OpArbitraryFloatExp10INTEL";
+    case SpvOpArbitraryFloatExpm1INTEL: return "OpArbitraryFloatExpm1INTEL";
+    case SpvOpArbitraryFloatSinINTEL: return "OpArbitraryFloatSinINTEL";
+    case SpvOpArbitraryFloatCosINTEL: return "OpArbitraryFloatCosINTEL";
+    case SpvOpArbitraryFloatSinCosINTEL: return "OpArbitraryFloatSinCosINTEL";
+    case SpvOpArbitraryFloatSinPiINTEL: return "OpArbitraryFloatSinPiINTEL";
+    case SpvOpArbitraryFloatCosPiINTEL: return "OpArbitraryFloatCosPiINTEL";
+    case SpvOpArbitraryFloatASinINTEL: return "OpArbitraryFloatASinINTEL";
+    case SpvOpArbitraryFloatASinPiINTEL: return "OpArbitraryFloatASinPiINTEL";
+    case SpvOpArbitraryFloatACosINTEL: return "OpArbitraryFloatACosINTEL";
+    case SpvOpArbitraryFloatACosPiINTEL: return "OpArbitraryFloatACosPiINTEL";
+    case SpvOpArbitraryFloatATanINTEL: return "OpArbitraryFloatATanINTEL";
+    case SpvOpArbitraryFloatATanPiINTEL: return "OpArbitraryFloatATanPiINTEL";
+    case SpvOpArbitraryFloatATan2INTEL: return "OpArbitraryFloatATan2INTEL";
+    case SpvOpArbitraryFloatPowINTEL: return "OpArbitraryFloatPowINTEL";
+    case SpvOpArbitraryFloatPowRINTEL: return "OpArbitraryFloatPowRINTEL";
+    case SpvOpArbitraryFloatPowNINTEL: return "OpArbitraryFloatPowNINTEL";
+    case SpvOpLoopControlINTEL: return "OpLoopControlINTEL";
+    case SpvOpAliasDomainDeclINTEL: return "OpAliasDomainDeclINTEL";
+    case SpvOpAliasScopeDeclINTEL: return "OpAliasScopeDeclINTEL";
+    case SpvOpAliasScopeListDeclINTEL: return "OpAliasScopeListDeclINTEL";
+    case SpvOpFixedSqrtINTEL: return "OpFixedSqrtINTEL";
+    case SpvOpFixedRecipINTEL: return "OpFixedRecipINTEL";
+    case SpvOpFixedRsqrtINTEL: return "OpFixedRsqrtINTEL";
+    case SpvOpFixedSinINTEL: return "OpFixedSinINTEL";
+    case SpvOpFixedCosINTEL: return "OpFixedCosINTEL";
+    case SpvOpFixedSinCosINTEL: return "OpFixedSinCosINTEL";
+    case SpvOpFixedSinPiINTEL: return "OpFixedSinPiINTEL";
+    case SpvOpFixedCosPiINTEL: return "OpFixedCosPiINTEL";
+    case SpvOpFixedSinCosPiINTEL: return "OpFixedSinCosPiINTEL";
+    case SpvOpFixedLogINTEL: return "OpFixedLogINTEL";
+    case SpvOpFixedExpINTEL: return "OpFixedExpINTEL";
+    case SpvOpPtrCastToCrossWorkgroupINTEL: return "OpPtrCastToCrossWorkgroupINTEL";
+    case SpvOpCrossWorkgroupCastToPtrINTEL: return "OpCrossWorkgroupCastToPtrINTEL";
+    case SpvOpReadPipeBlockingINTEL: return "OpReadPipeBlockingINTEL";
+    case SpvOpWritePipeBlockingINTEL: return "OpWritePipeBlockingINTEL";
+    case SpvOpFPGARegINTEL: return "OpFPGARegINTEL";
+    case SpvOpRayQueryGetRayTMinKHR: return "OpRayQueryGetRayTMinKHR";
+    case SpvOpRayQueryGetRayFlagsKHR: return "OpRayQueryGetRayFlagsKHR";
+    case SpvOpRayQueryGetIntersectionTKHR: return "OpRayQueryGetIntersectionTKHR";
+    case SpvOpRayQueryGetIntersectionInstanceCustomIndexKHR: return "OpRayQueryGetIntersectionInstanceCustomIndexKHR";
+    case SpvOpRayQueryGetIntersectionInstanceIdKHR: return "OpRayQueryGetIntersectionInstanceIdKHR";
+    case SpvOpRayQueryGetIntersectionInstanceShaderBindingTableRecordOffsetKHR: return "OpRayQueryGetIntersectionInstanceShaderBindingTableRecordOffsetKHR";
+    case SpvOpRayQueryGetIntersectionGeometryIndexKHR: return "OpRayQueryGetIntersectionGeometryIndexKHR";
+    case SpvOpRayQueryGetIntersectionPrimitiveIndexKHR: return "OpRayQueryGetIntersectionPrimitiveIndexKHR";
+    case SpvOpRayQueryGetIntersectionBarycentricsKHR: return "OpRayQueryGetIntersectionBarycentricsKHR";
+    case SpvOpRayQueryGetIntersectionFrontFaceKHR: return "OpRayQueryGetIntersectionFrontFaceKHR";
+    case SpvOpRayQueryGetIntersectionCandidateAABBOpaqueKHR: return "OpRayQueryGetIntersectionCandidateAABBOpaqueKHR";
+    case SpvOpRayQueryGetIntersectionObjectRayDirectionKHR: return "OpRayQueryGetIntersectionObjectRayDirectionKHR";
+    case SpvOpRayQueryGetIntersectionObjectRayOriginKHR: return "OpRayQueryGetIntersectionObjectRayOriginKHR";
+    case SpvOpRayQueryGetWorldRayDirectionKHR: return "OpRayQueryGetWorldRayDirectionKHR";
+    case SpvOpRayQueryGetWorldRayOriginKHR: return "OpRayQueryGetWorldRayOriginKHR";
+    case SpvOpRayQueryGetIntersectionObjectToWorldKHR: return "OpRayQueryGetIntersectionObjectToWorldKHR";
+    case SpvOpRayQueryGetIntersectionWorldToObjectKHR: return "OpRayQueryGetIntersectionWorldToObjectKHR";
+    case SpvOpAtomicFAddEXT: return "OpAtomicFAddEXT";
+    case SpvOpTypeBufferSurfaceINTEL: return "OpTypeBufferSurfaceINTEL";
+    case SpvOpTypeStructContinuedINTEL: return "OpTypeStructContinuedINTEL";
+    case SpvOpConstantCompositeContinuedINTEL: return "OpConstantCompositeContinuedINTEL";
+    case SpvOpSpecConstantCompositeContinuedINTEL: return "OpSpecConstantCompositeContinuedINTEL";
+    case SpvOpCompositeConstructContinuedINTEL: return "OpCompositeConstructContinuedINTEL";
+    case SpvOpConvertFToBF16INTEL: return "OpConvertFToBF16INTEL";
+    case SpvOpConvertBF16ToFINTEL: return "OpConvertBF16ToFINTEL";
+    case SpvOpControlBarrierArriveINTEL: return "OpControlBarrierArriveINTEL";
+    case SpvOpControlBarrierWaitINTEL: return "OpControlBarrierWaitINTEL";
+    case SpvOpArithmeticFenceEXT: return "OpArithmeticFenceEXT";
+    case SpvOpSubgroupBlockPrefetchINTEL: return "OpSubgroupBlockPrefetchINTEL";
+    case SpvOpGroupIMulKHR: return "OpGroupIMulKHR";
+    case SpvOpGroupFMulKHR: return "OpGroupFMulKHR";
+    case SpvOpGroupBitwiseAndKHR: return "OpGroupBitwiseAndKHR";
+    case SpvOpGroupBitwiseOrKHR: return "OpGroupBitwiseOrKHR";
+    case SpvOpGroupBitwiseXorKHR: return "OpGroupBitwiseXorKHR";
+    case SpvOpGroupLogicalAndKHR: return "OpGroupLogicalAndKHR";
+    case SpvOpGroupLogicalOrKHR: return "OpGroupLogicalOrKHR";
+    case SpvOpGroupLogicalXorKHR: return "OpGroupLogicalXorKHR";
+    case SpvOpMaskedGatherINTEL: return "OpMaskedGatherINTEL";
+    case SpvOpMaskedScatterINTEL: return "OpMaskedScatterINTEL";
+    default: return "Unknown";
+    }
+}
+
 #endif /* SPV_ENABLE_UTILITY_CODE */
 
 #endif
diff --git a/include/spirv/unified1/spirv.hpp b/include/spirv/unified1/spirv.hpp
index b9c8743..0c30b76 100644
--- a/include/spirv/unified1/spirv.hpp
+++ b/include/spirv/unified1/spirv.hpp
@@ -12,7 +12,7 @@
 // 
 // MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 // STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
 // 
 // THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -174,6 +174,7 @@ enum ExecutionMode {
     ExecutionModeEarlyAndLateFragmentTestsAMD = 5017,
     ExecutionModeStencilRefReplacingEXT = 5027,
     ExecutionModeCoalescingAMDX = 5069,
+    ExecutionModeIsApiEntryAMDX = 5070,
     ExecutionModeMaxNodeRecursionAMDX = 5071,
     ExecutionModeStaticNumWorkgroupsAMDX = 5072,
     ExecutionModeShaderIndexAMDX = 5073,
@@ -186,11 +187,14 @@ enum ExecutionMode {
     ExecutionModeStencilRefLessBackAMD = 5084,
     ExecutionModeQuadDerivativesKHR = 5088,
     ExecutionModeRequireFullQuadsKHR = 5089,
+    ExecutionModeSharesInputWithAMDX = 5102,
     ExecutionModeOutputLinesEXT = 5269,
     ExecutionModeOutputLinesNV = 5269,
     ExecutionModeOutputPrimitivesEXT = 5270,
     ExecutionModeOutputPrimitivesNV = 5270,
+    ExecutionModeDerivativeGroupQuadsKHR = 5289,
     ExecutionModeDerivativeGroupQuadsNV = 5289,
+    ExecutionModeDerivativeGroupLinearKHR = 5290,
     ExecutionModeDerivativeGroupLinearNV = 5290,
     ExecutionModeOutputTrianglesEXT = 5298,
     ExecutionModeOutputTrianglesNV = 5298,
@@ -215,6 +219,9 @@ enum ExecutionMode {
     ExecutionModeStreamingInterfaceINTEL = 6154,
     ExecutionModeRegisterMapInterfaceINTEL = 6160,
     ExecutionModeNamedBarrierCountINTEL = 6417,
+    ExecutionModeMaximumRegistersINTEL = 6461,
+    ExecutionModeMaximumRegistersIdINTEL = 6462,
+    ExecutionModeNamedMaximumRegistersINTEL = 6463,
     ExecutionModeMax = 0x7fffffff,
 };
 
@@ -234,7 +241,6 @@ enum StorageClass {
     StorageClassStorageBuffer = 12,
     StorageClassTileImageEXT = 4172,
     StorageClassNodePayloadAMDX = 5068,
-    StorageClassNodeOutputPayloadAMDX = 5076,
     StorageClassCallableDataKHR = 5328,
     StorageClassCallableDataNV = 5328,
     StorageClassIncomingCallableDataKHR = 5329,
@@ -374,6 +380,7 @@ enum ImageChannelDataType {
     ImageChannelDataTypeUnormInt101010_2 = 16,
     ImageChannelDataTypeUnsignedIntRaw10EXT = 19,
     ImageChannelDataTypeUnsignedIntRaw12EXT = 20,
+    ImageChannelDataTypeUnormInt2_101010EXT = 21,
     ImageChannelDataTypeMax = 0x7fffffff,
 };
 
@@ -540,11 +547,16 @@ enum Decoration {
     DecorationNoUnsignedWrap = 4470,
     DecorationWeightTextureQCOM = 4487,
     DecorationBlockMatchTextureQCOM = 4488,
+    DecorationBlockMatchSamplerQCOM = 4499,
     DecorationExplicitInterpAMD = 4999,
     DecorationNodeSharesPayloadLimitsWithAMDX = 5019,
     DecorationNodeMaxPayloadsAMDX = 5020,
     DecorationTrackFinishWritingAMDX = 5078,
     DecorationPayloadNodeNameAMDX = 5091,
+    DecorationPayloadNodeBaseIndexAMDX = 5098,
+    DecorationPayloadNodeSparseArrayAMDX = 5099,
+    DecorationPayloadNodeArraySizeAMDX = 5100,
+    DecorationPayloadDispatchIndirectAMDX = 5105,
     DecorationOverrideCoverageNV = 5248,
     DecorationPassthroughNV = 5250,
     DecorationViewportRelativeNV = 5252,
@@ -708,7 +720,7 @@ enum BuiltIn {
     BuiltInBaryCoordSmoothSampleAMD = 4997,
     BuiltInBaryCoordPullModelAMD = 4998,
     BuiltInFragStencilRefEXT = 5014,
-    BuiltInCoalescedInputCountAMDX = 5021,
+    BuiltInRemainingRecursionLevelsAMDX = 5021,
     BuiltInShaderIndexAMDX = 5073,
     BuiltInViewportMaskNV = 5253,
     BuiltInSecondaryPositionNV = 5257,
@@ -841,6 +853,7 @@ enum FunctionControlShift {
     FunctionControlDontInlineShift = 1,
     FunctionControlPureShift = 2,
     FunctionControlConstShift = 3,
+    FunctionControlOptNoneEXTShift = 16,
     FunctionControlOptNoneINTELShift = 16,
     FunctionControlMax = 0x7fffffff,
 };
@@ -851,6 +864,7 @@ enum FunctionControlMask {
     FunctionControlDontInlineMask = 0x00000002,
     FunctionControlPureMask = 0x00000004,
     FunctionControlConstMask = 0x00000008,
+    FunctionControlOptNoneEXTMask = 0x00010000,
     FunctionControlOptNoneINTELMask = 0x00010000,
 };
 
@@ -1041,6 +1055,7 @@ enum Capability {
     CapabilityTileImageColorReadAccessEXT = 4166,
     CapabilityTileImageDepthReadAccessEXT = 4167,
     CapabilityTileImageStencilReadAccessEXT = 4168,
+    CapabilityCooperativeMatrixLayoutsARM = 4201,
     CapabilityFragmentShadingRateKHR = 4422,
     CapabilitySubgroupBallotKHR = 4423,
     CapabilityDrawParameters = 4427,
@@ -1070,11 +1085,13 @@ enum Capability {
     CapabilityRoundingModeRTZ = 4468,
     CapabilityRayQueryProvisionalKHR = 4471,
     CapabilityRayQueryKHR = 4472,
+    CapabilityUntypedPointersKHR = 4473,
     CapabilityRayTraversalPrimitiveCullingKHR = 4478,
     CapabilityRayTracingKHR = 4479,
     CapabilityTextureSampleWeightedQCOM = 4484,
     CapabilityTextureBoxFilterQCOM = 4485,
     CapabilityTextureBlockMatchQCOM = 4486,
+    CapabilityTextureBlockMatch2QCOM = 4498,
     CapabilityFloat16ImageAMD = 5008,
     CapabilityImageGatherBiasLodAMD = 5009,
     CapabilityFragmentMaskAMD = 5010,
@@ -1097,6 +1114,7 @@ enum Capability {
     CapabilityMeshShadingEXT = 5283,
     CapabilityFragmentBarycentricKHR = 5284,
     CapabilityFragmentBarycentricNV = 5284,
+    CapabilityComputeDerivativeGroupQuadsKHR = 5288,
     CapabilityComputeDerivativeGroupQuadsNV = 5288,
     CapabilityFragmentDensityEXT = 5291,
     CapabilityShadingRateNV = 5291,
@@ -1134,6 +1152,7 @@ enum Capability {
     CapabilityVulkanMemoryModelDeviceScopeKHR = 5346,
     CapabilityPhysicalStorageBufferAddresses = 5347,
     CapabilityPhysicalStorageBufferAddressesEXT = 5347,
+    CapabilityComputeDerivativeGroupLinearKHR = 5350,
     CapabilityComputeDerivativeGroupLinearNV = 5350,
     CapabilityRayTracingProvisionalKHR = 5353,
     CapabilityCooperativeMatrixNV = 5357,
@@ -1148,7 +1167,15 @@ enum Capability {
     CapabilityShaderInvocationReorderNV = 5383,
     CapabilityBindlessTextureNV = 5390,
     CapabilityRayQueryPositionFetchKHR = 5391,
+    CapabilityAtomicFloat16VectorNV = 5404,
     CapabilityRayTracingDisplacementMicromapNV = 5409,
+    CapabilityRawAccessChainsNV = 5414,
+    CapabilityCooperativeMatrixReductionsNV = 5430,
+    CapabilityCooperativeMatrixConversionsNV = 5431,
+    CapabilityCooperativeMatrixPerElementOperationsNV = 5432,
+    CapabilityCooperativeMatrixTensorAddressingNV = 5433,
+    CapabilityCooperativeMatrixBlockLoadsNV = 5434,
+    CapabilityTensorAddressingNV = 5439,
     CapabilitySubgroupShuffleINTEL = 5568,
     CapabilitySubgroupBufferBlockIOINTEL = 5569,
     CapabilitySubgroupImageBlockIOINTEL = 5570,
@@ -1201,17 +1228,20 @@ enum Capability {
     CapabilityDotProductKHR = 6019,
     CapabilityRayCullMaskKHR = 6020,
     CapabilityCooperativeMatrixKHR = 6022,
+    CapabilityReplicatedCompositesEXT = 6024,
     CapabilityBitInstructions = 6025,
     CapabilityGroupNonUniformRotateKHR = 6026,
     CapabilityFloatControls2 = 6029,
     CapabilityAtomicFloat32AddEXT = 6033,
     CapabilityAtomicFloat64AddEXT = 6034,
     CapabilityLongCompositesINTEL = 6089,
+    CapabilityOptNoneEXT = 6094,
     CapabilityOptNoneINTEL = 6094,
     CapabilityAtomicFloat16AddEXT = 6095,
     CapabilityDebugInfoModuleINTEL = 6114,
     CapabilityBFloat16ConversionINTEL = 6115,
     CapabilitySplitBarrierINTEL = 6141,
+    CapabilityArithmeticFenceEXT = 6144,
     CapabilityFPGAClusterAttributesV2INTEL = 6150,
     CapabilityFPGAKernelAttributesv2INTEL = 6161,
     CapabilityFPMaxErrorINTEL = 6169,
@@ -1219,9 +1249,11 @@ enum Capability {
     CapabilityFPGAArgumentInterfacesINTEL = 6174,
     CapabilityGlobalVariableHostAccessINTEL = 6187,
     CapabilityGlobalVariableFPGADecorationsINTEL = 6189,
+    CapabilitySubgroupBufferPrefetchINTEL = 6220,
     CapabilityGroupUniformArithmeticKHR = 6400,
     CapabilityMaskedGatherScatterINTEL = 6427,
     CapabilityCacheControlsINTEL = 6441,
+    CapabilityRegisterLimitsINTEL = 6460,
     CapabilityMax = 0x7fffffff,
 };
 
@@ -1349,6 +1381,8 @@ enum CooperativeMatrixOperandsMask {
 enum CooperativeMatrixLayout {
     CooperativeMatrixLayoutRowMajorKHR = 0,
     CooperativeMatrixLayoutColumnMajorKHR = 1,
+    CooperativeMatrixLayoutRowBlockedInterleavedARM = 4202,
+    CooperativeMatrixLayoutColumnBlockedInterleavedARM = 4203,
     CooperativeMatrixLayoutMax = 0x7fffffff,
 };
 
@@ -1359,6 +1393,41 @@ enum CooperativeMatrixUse {
     CooperativeMatrixUseMax = 0x7fffffff,
 };
 
+enum CooperativeMatrixReduceShift {
+    CooperativeMatrixReduceRowShift = 0,
+    CooperativeMatrixReduceColumnShift = 1,
+    CooperativeMatrixReduce2x2Shift = 2,
+    CooperativeMatrixReduceMax = 0x7fffffff,
+};
+
+enum CooperativeMatrixReduceMask {
+    CooperativeMatrixReduceMaskNone = 0,
+    CooperativeMatrixReduceRowMask = 0x00000001,
+    CooperativeMatrixReduceColumnMask = 0x00000002,
+    CooperativeMatrixReduce2x2Mask = 0x00000004,
+};
+
+enum TensorClampMode {
+    TensorClampModeUndefined = 0,
+    TensorClampModeConstant = 1,
+    TensorClampModeClampToEdge = 2,
+    TensorClampModeRepeat = 3,
+    TensorClampModeRepeatMirrored = 4,
+    TensorClampModeMax = 0x7fffffff,
+};
+
+enum TensorAddressingOperandsShift {
+    TensorAddressingOperandsTensorViewShift = 0,
+    TensorAddressingOperandsDecodeFuncShift = 1,
+    TensorAddressingOperandsMax = 0x7fffffff,
+};
+
+enum TensorAddressingOperandsMask {
+    TensorAddressingOperandsMaskNone = 0,
+    TensorAddressingOperandsTensorViewMask = 0x00000001,
+    TensorAddressingOperandsDecodeFuncMask = 0x00000002,
+};
+
 enum InitializationModeQualifier {
     InitializationModeQualifierInitOnDeviceReprogramINTEL = 0,
     InitializationModeQualifierInitOnDeviceResetINTEL = 1,
@@ -1390,6 +1459,27 @@ enum StoreCacheControl {
     StoreCacheControlMax = 0x7fffffff,
 };
 
+enum NamedMaximumNumberOfRegisters {
+    NamedMaximumNumberOfRegistersAutoINTEL = 0,
+    NamedMaximumNumberOfRegistersMax = 0x7fffffff,
+};
+
+enum RawAccessChainOperandsShift {
+    RawAccessChainOperandsRobustnessPerComponentNVShift = 0,
+    RawAccessChainOperandsRobustnessPerElementNVShift = 1,
+    RawAccessChainOperandsMax = 0x7fffffff,
+};
+
+enum RawAccessChainOperandsMask {
+    RawAccessChainOperandsMaskNone = 0,
+    RawAccessChainOperandsRobustnessPerComponentNVMask = 0x00000001,
+    RawAccessChainOperandsRobustnessPerElementNVMask = 0x00000002,
+};
+
+enum FPEncoding {
+    FPEncodingMax = 0x7fffffff,
+};
+
 enum Op {
     OpNop = 0,
     OpUndef = 1,
@@ -1739,13 +1829,22 @@ enum Op {
     OpDepthAttachmentReadEXT = 4161,
     OpStencilAttachmentReadEXT = 4162,
     OpTerminateInvocation = 4416,
+    OpTypeUntypedPointerKHR = 4417,
+    OpUntypedVariableKHR = 4418,
+    OpUntypedAccessChainKHR = 4419,
+    OpUntypedInBoundsAccessChainKHR = 4420,
     OpSubgroupBallotKHR = 4421,
     OpSubgroupFirstInvocationKHR = 4422,
+    OpUntypedPtrAccessChainKHR = 4423,
+    OpUntypedInBoundsPtrAccessChainKHR = 4424,
+    OpUntypedArrayLengthKHR = 4425,
+    OpUntypedPrefetchKHR = 4426,
     OpSubgroupAllKHR = 4428,
     OpSubgroupAnyKHR = 4429,
     OpSubgroupAllEqualKHR = 4430,
     OpGroupNonUniformRotateKHR = 4431,
     OpSubgroupReadInvocationKHR = 4432,
+    OpExtInstWithForwardRefsKHR = 4433,
     OpTraceRayKHR = 4445,
     OpExecuteCallableKHR = 4446,
     OpConvertUToAccelerationStructureKHR = 4447,
@@ -1768,6 +1867,9 @@ enum Op {
     OpCooperativeMatrixStoreKHR = 4458,
     OpCooperativeMatrixMulAddKHR = 4459,
     OpCooperativeMatrixLengthKHR = 4460,
+    OpConstantCompositeReplicateEXT = 4461,
+    OpSpecConstantCompositeReplicateEXT = 4462,
+    OpCompositeConstructReplicateEXT = 4463,
     OpTypeRayQueryKHR = 4472,
     OpRayQueryInitializeKHR = 4473,
     OpRayQueryTerminateKHR = 4474,
@@ -1779,6 +1881,10 @@ enum Op {
     OpImageBoxFilterQCOM = 4481,
     OpImageBlockMatchSSDQCOM = 4482,
     OpImageBlockMatchSADQCOM = 4483,
+    OpImageBlockMatchWindowSSDQCOM = 4500,
+    OpImageBlockMatchWindowSADQCOM = 4501,
+    OpImageBlockMatchGatherSSDQCOM = 4502,
+    OpImageBlockMatchGatherSADQCOM = 4503,
     OpGroupIAddNonUniformAMD = 5000,
     OpGroupFAddNonUniformAMD = 5001,
     OpGroupFMinNonUniformAMD = 5002,
@@ -1790,9 +1896,14 @@ enum Op {
     OpFragmentMaskFetchAMD = 5011,
     OpFragmentFetchAMD = 5012,
     OpReadClockKHR = 5056,
-    OpFinalizeNodePayloadsAMDX = 5075,
+    OpAllocateNodePayloadsAMDX = 5074,
+    OpEnqueueNodePayloadsAMDX = 5075,
+    OpTypeNodePayloadArrayAMDX = 5076,
     OpFinishWritingNodePayloadAMDX = 5078,
-    OpInitializeNodePayloadsAMDX = 5090,
+    OpNodePayloadArrayLengthAMDX = 5090,
+    OpIsNodePayloadValidAMDX = 5101,
+    OpConstantStringAMDX = 5103,
+    OpSpecConstantStringAMDX = 5104,
     OpGroupNonUniformQuadAllKHR = 5110,
     OpGroupNonUniformQuadAnyKHR = 5111,
     OpHitObjectRecordHitMotionNV = 5249,
@@ -1829,6 +1940,7 @@ enum Op {
     OpReorderThreadWithHintNV = 5280,
     OpTypeHitObjectNV = 5281,
     OpImageSampleFootprintNV = 5283,
+    OpCooperativeMatrixConvertNV = 5293,
     OpEmitMeshTasksEXT = 5294,
     OpSetMeshOutputsEXT = 5295,
     OpGroupNonUniformPartitionNV = 5296,
@@ -1853,9 +1965,26 @@ enum Op {
     OpCooperativeMatrixLengthNV = 5362,
     OpBeginInvocationInterlockEXT = 5364,
     OpEndInvocationInterlockEXT = 5365,
+    OpCooperativeMatrixReduceNV = 5366,
+    OpCooperativeMatrixLoadTensorNV = 5367,
+    OpCooperativeMatrixStoreTensorNV = 5368,
+    OpCooperativeMatrixPerElementOpNV = 5369,
+    OpTypeTensorLayoutNV = 5370,
+    OpTypeTensorViewNV = 5371,
+    OpCreateTensorLayoutNV = 5372,
+    OpTensorLayoutSetDimensionNV = 5373,
+    OpTensorLayoutSetStrideNV = 5374,
+    OpTensorLayoutSliceNV = 5375,
+    OpTensorLayoutSetClampValueNV = 5376,
+    OpCreateTensorViewNV = 5377,
+    OpTensorViewSetDimensionNV = 5378,
+    OpTensorViewSetStrideNV = 5379,
     OpDemoteToHelperInvocation = 5380,
     OpDemoteToHelperInvocationEXT = 5380,
     OpIsHelperInvocationEXT = 5381,
+    OpTensorViewSetClipNV = 5382,
+    OpTensorLayoutSetBlockSizeNV = 5384,
+    OpCooperativeMatrixTransposeNV = 5390,
     OpConvertUToImageNV = 5391,
     OpConvertUToSamplerNV = 5392,
     OpConvertImageToUNV = 5393,
@@ -1863,6 +1992,7 @@ enum Op {
     OpConvertUToSampledImageNV = 5395,
     OpConvertSampledImageToUNV = 5396,
     OpSamplerImageAddressingModeNV = 5397,
+    OpRawAccessChainNV = 5398,
     OpSubgroupShuffleINTEL = 5571,
     OpSubgroupShuffleDownINTEL = 5572,
     OpSubgroupShuffleUpINTEL = 5573,
@@ -2109,6 +2239,8 @@ enum Op {
     OpConvertBF16ToFINTEL = 6117,
     OpControlBarrierArriveINTEL = 6142,
     OpControlBarrierWaitINTEL = 6143,
+    OpArithmeticFenceEXT = 6145,
+    OpSubgroupBlockPrefetchINTEL = 6221,
     OpGroupIMulKHR = 6401,
     OpGroupFMulKHR = 6402,
     OpGroupBitwiseAndKHR = 6403,
@@ -2478,13 +2610,22 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpDepthAttachmentReadEXT: *hasResult = true; *hasResultType = true; break;
     case OpStencilAttachmentReadEXT: *hasResult = true; *hasResultType = true; break;
     case OpTerminateInvocation: *hasResult = false; *hasResultType = false; break;
+    case OpTypeUntypedPointerKHR: *hasResult = true; *hasResultType = false; break;
+    case OpUntypedVariableKHR: *hasResult = true; *hasResultType = true; break;
+    case OpUntypedAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case OpUntypedInBoundsAccessChainKHR: *hasResult = true; *hasResultType = true; break;
     case OpSubgroupBallotKHR: *hasResult = true; *hasResultType = true; break;
     case OpSubgroupFirstInvocationKHR: *hasResult = true; *hasResultType = true; break;
+    case OpUntypedPtrAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case OpUntypedInBoundsPtrAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case OpUntypedArrayLengthKHR: *hasResult = true; *hasResultType = true; break;
+    case OpUntypedPrefetchKHR: *hasResult = false; *hasResultType = false; break;
     case OpSubgroupAllKHR: *hasResult = true; *hasResultType = true; break;
     case OpSubgroupAnyKHR: *hasResult = true; *hasResultType = true; break;
     case OpSubgroupAllEqualKHR: *hasResult = true; *hasResultType = true; break;
     case OpGroupNonUniformRotateKHR: *hasResult = true; *hasResultType = true; break;
     case OpSubgroupReadInvocationKHR: *hasResult = true; *hasResultType = true; break;
+    case OpExtInstWithForwardRefsKHR: *hasResult = true; *hasResultType = true; break;
     case OpTraceRayKHR: *hasResult = false; *hasResultType = false; break;
     case OpExecuteCallableKHR: *hasResult = false; *hasResultType = false; break;
     case OpConvertUToAccelerationStructureKHR: *hasResult = true; *hasResultType = true; break;
@@ -2501,6 +2642,9 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpCooperativeMatrixStoreKHR: *hasResult = false; *hasResultType = false; break;
     case OpCooperativeMatrixMulAddKHR: *hasResult = true; *hasResultType = true; break;
     case OpCooperativeMatrixLengthKHR: *hasResult = true; *hasResultType = true; break;
+    case OpConstantCompositeReplicateEXT: *hasResult = true; *hasResultType = true; break;
+    case OpSpecConstantCompositeReplicateEXT: *hasResult = true; *hasResultType = true; break;
+    case OpCompositeConstructReplicateEXT: *hasResult = true; *hasResultType = true; break;
     case OpTypeRayQueryKHR: *hasResult = true; *hasResultType = false; break;
     case OpRayQueryInitializeKHR: *hasResult = false; *hasResultType = false; break;
     case OpRayQueryTerminateKHR: *hasResult = false; *hasResultType = false; break;
@@ -2512,6 +2656,10 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpImageBoxFilterQCOM: *hasResult = true; *hasResultType = true; break;
     case OpImageBlockMatchSSDQCOM: *hasResult = true; *hasResultType = true; break;
     case OpImageBlockMatchSADQCOM: *hasResult = true; *hasResultType = true; break;
+    case OpImageBlockMatchWindowSSDQCOM: *hasResult = true; *hasResultType = true; break;
+    case OpImageBlockMatchWindowSADQCOM: *hasResult = true; *hasResultType = true; break;
+    case OpImageBlockMatchGatherSSDQCOM: *hasResult = true; *hasResultType = true; break;
+    case OpImageBlockMatchGatherSADQCOM: *hasResult = true; *hasResultType = true; break;
     case OpGroupIAddNonUniformAMD: *hasResult = true; *hasResultType = true; break;
     case OpGroupFAddNonUniformAMD: *hasResult = true; *hasResultType = true; break;
     case OpGroupFMinNonUniformAMD: *hasResult = true; *hasResultType = true; break;
@@ -2523,9 +2671,14 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpFragmentMaskFetchAMD: *hasResult = true; *hasResultType = true; break;
     case OpFragmentFetchAMD: *hasResult = true; *hasResultType = true; break;
     case OpReadClockKHR: *hasResult = true; *hasResultType = true; break;
-    case OpFinalizeNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case OpAllocateNodePayloadsAMDX: *hasResult = true; *hasResultType = true; break;
+    case OpEnqueueNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case OpTypeNodePayloadArrayAMDX: *hasResult = true; *hasResultType = false; break;
     case OpFinishWritingNodePayloadAMDX: *hasResult = true; *hasResultType = true; break;
-    case OpInitializeNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case OpNodePayloadArrayLengthAMDX: *hasResult = true; *hasResultType = true; break;
+    case OpIsNodePayloadValidAMDX: *hasResult = true; *hasResultType = true; break;
+    case OpConstantStringAMDX: *hasResult = true; *hasResultType = false; break;
+    case OpSpecConstantStringAMDX: *hasResult = true; *hasResultType = false; break;
     case OpGroupNonUniformQuadAllKHR: *hasResult = true; *hasResultType = true; break;
     case OpGroupNonUniformQuadAnyKHR: *hasResult = true; *hasResultType = true; break;
     case OpHitObjectRecordHitMotionNV: *hasResult = false; *hasResultType = false; break;
@@ -2562,20 +2715,21 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpReorderThreadWithHintNV: *hasResult = false; *hasResultType = false; break;
     case OpTypeHitObjectNV: *hasResult = true; *hasResultType = false; break;
     case OpImageSampleFootprintNV: *hasResult = true; *hasResultType = true; break;
+    case OpCooperativeMatrixConvertNV: *hasResult = true; *hasResultType = true; break;
     case OpEmitMeshTasksEXT: *hasResult = false; *hasResultType = false; break;
     case OpSetMeshOutputsEXT: *hasResult = false; *hasResultType = false; break;
     case OpGroupNonUniformPartitionNV: *hasResult = true; *hasResultType = true; break;
     case OpWritePackedPrimitiveIndices4x8NV: *hasResult = false; *hasResultType = false; break;
     case OpFetchMicroTriangleVertexPositionNV: *hasResult = true; *hasResultType = true; break;
     case OpFetchMicroTriangleVertexBarycentricNV: *hasResult = true; *hasResultType = true; break;
-    case OpReportIntersectionNV: *hasResult = true; *hasResultType = true; break;
+    case OpReportIntersectionKHR: *hasResult = true; *hasResultType = true; break;
     case OpIgnoreIntersectionNV: *hasResult = false; *hasResultType = false; break;
     case OpTerminateRayNV: *hasResult = false; *hasResultType = false; break;
     case OpTraceNV: *hasResult = false; *hasResultType = false; break;
     case OpTraceMotionNV: *hasResult = false; *hasResultType = false; break;
     case OpTraceRayMotionNV: *hasResult = false; *hasResultType = false; break;
     case OpRayQueryGetIntersectionTriangleVertexPositionsKHR: *hasResult = true; *hasResultType = true; break;
-    case OpTypeAccelerationStructureNV: *hasResult = true; *hasResultType = false; break;
+    case OpTypeAccelerationStructureKHR: *hasResult = true; *hasResultType = false; break;
     case OpExecuteCallableNV: *hasResult = false; *hasResultType = false; break;
     case OpTypeCooperativeMatrixNV: *hasResult = true; *hasResultType = false; break;
     case OpCooperativeMatrixLoadNV: *hasResult = true; *hasResultType = true; break;
@@ -2584,8 +2738,25 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpCooperativeMatrixLengthNV: *hasResult = true; *hasResultType = true; break;
     case OpBeginInvocationInterlockEXT: *hasResult = false; *hasResultType = false; break;
     case OpEndInvocationInterlockEXT: *hasResult = false; *hasResultType = false; break;
+    case OpCooperativeMatrixReduceNV: *hasResult = true; *hasResultType = true; break;
+    case OpCooperativeMatrixLoadTensorNV: *hasResult = true; *hasResultType = true; break;
+    case OpCooperativeMatrixStoreTensorNV: *hasResult = false; *hasResultType = false; break;
+    case OpCooperativeMatrixPerElementOpNV: *hasResult = true; *hasResultType = true; break;
+    case OpTypeTensorLayoutNV: *hasResult = true; *hasResultType = false; break;
+    case OpTypeTensorViewNV: *hasResult = true; *hasResultType = false; break;
+    case OpCreateTensorLayoutNV: *hasResult = true; *hasResultType = true; break;
+    case OpTensorLayoutSetDimensionNV: *hasResult = true; *hasResultType = true; break;
+    case OpTensorLayoutSetStrideNV: *hasResult = true; *hasResultType = true; break;
+    case OpTensorLayoutSliceNV: *hasResult = true; *hasResultType = true; break;
+    case OpTensorLayoutSetClampValueNV: *hasResult = true; *hasResultType = true; break;
+    case OpCreateTensorViewNV: *hasResult = true; *hasResultType = true; break;
+    case OpTensorViewSetDimensionNV: *hasResult = true; *hasResultType = true; break;
+    case OpTensorViewSetStrideNV: *hasResult = true; *hasResultType = true; break;
     case OpDemoteToHelperInvocation: *hasResult = false; *hasResultType = false; break;
     case OpIsHelperInvocationEXT: *hasResult = true; *hasResultType = true; break;
+    case OpTensorViewSetClipNV: *hasResult = true; *hasResultType = true; break;
+    case OpTensorLayoutSetBlockSizeNV: *hasResult = true; *hasResultType = true; break;
+    case OpCooperativeMatrixTransposeNV: *hasResult = true; *hasResultType = true; break;
     case OpConvertUToImageNV: *hasResult = true; *hasResultType = true; break;
     case OpConvertUToSamplerNV: *hasResult = true; *hasResultType = true; break;
     case OpConvertImageToUNV: *hasResult = true; *hasResultType = true; break;
@@ -2593,6 +2764,7 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpConvertUToSampledImageNV: *hasResult = true; *hasResultType = true; break;
     case OpConvertSampledImageToUNV: *hasResult = true; *hasResultType = true; break;
     case OpSamplerImageAddressingModeNV: *hasResult = false; *hasResultType = false; break;
+    case OpRawAccessChainNV: *hasResult = true; *hasResultType = true; break;
     case OpSubgroupShuffleINTEL: *hasResult = true; *hasResultType = true; break;
     case OpSubgroupShuffleDownINTEL: *hasResult = true; *hasResultType = true; break;
     case OpSubgroupShuffleUpINTEL: *hasResult = true; *hasResultType = true; break;
@@ -2837,6 +3009,8 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpConvertBF16ToFINTEL: *hasResult = true; *hasResultType = true; break;
     case OpControlBarrierArriveINTEL: *hasResult = false; *hasResultType = false; break;
     case OpControlBarrierWaitINTEL: *hasResult = false; *hasResultType = false; break;
+    case OpArithmeticFenceEXT: *hasResult = true; *hasResultType = true; break;
+    case OpSubgroupBlockPrefetchINTEL: *hasResult = false; *hasResultType = false; break;
     case OpGroupIMulKHR: *hasResult = true; *hasResultType = true; break;
     case OpGroupFMulKHR: *hasResult = true; *hasResultType = true; break;
     case OpGroupBitwiseAndKHR: *hasResult = true; *hasResultType = true; break;
@@ -2849,6 +3023,1852 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case OpMaskedScatterINTEL: *hasResult = false; *hasResultType = false; break;
     }
 }
+inline const char* SourceLanguageToString(SourceLanguage value) {
+    switch (value) {
+    case SourceLanguageUnknown: return "Unknown";
+    case SourceLanguageESSL: return "ESSL";
+    case SourceLanguageGLSL: return "GLSL";
+    case SourceLanguageOpenCL_C: return "OpenCL_C";
+    case SourceLanguageOpenCL_CPP: return "OpenCL_CPP";
+    case SourceLanguageHLSL: return "HLSL";
+    case SourceLanguageCPP_for_OpenCL: return "CPP_for_OpenCL";
+    case SourceLanguageSYCL: return "SYCL";
+    case SourceLanguageHERO_C: return "HERO_C";
+    case SourceLanguageNZSL: return "NZSL";
+    case SourceLanguageWGSL: return "WGSL";
+    case SourceLanguageSlang: return "Slang";
+    case SourceLanguageZig: return "Zig";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ExecutionModelToString(ExecutionModel value) {
+    switch (value) {
+    case ExecutionModelVertex: return "Vertex";
+    case ExecutionModelTessellationControl: return "TessellationControl";
+    case ExecutionModelTessellationEvaluation: return "TessellationEvaluation";
+    case ExecutionModelGeometry: return "Geometry";
+    case ExecutionModelFragment: return "Fragment";
+    case ExecutionModelGLCompute: return "GLCompute";
+    case ExecutionModelKernel: return "Kernel";
+    case ExecutionModelTaskNV: return "TaskNV";
+    case ExecutionModelMeshNV: return "MeshNV";
+    case ExecutionModelRayGenerationKHR: return "RayGenerationKHR";
+    case ExecutionModelIntersectionKHR: return "IntersectionKHR";
+    case ExecutionModelAnyHitKHR: return "AnyHitKHR";
+    case ExecutionModelClosestHitKHR: return "ClosestHitKHR";
+    case ExecutionModelMissKHR: return "MissKHR";
+    case ExecutionModelCallableKHR: return "CallableKHR";
+    case ExecutionModelTaskEXT: return "TaskEXT";
+    case ExecutionModelMeshEXT: return "MeshEXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* AddressingModelToString(AddressingModel value) {
+    switch (value) {
+    case AddressingModelLogical: return "Logical";
+    case AddressingModelPhysical32: return "Physical32";
+    case AddressingModelPhysical64: return "Physical64";
+    case AddressingModelPhysicalStorageBuffer64: return "PhysicalStorageBuffer64";
+    default: return "Unknown";
+    }
+}
+
+inline const char* MemoryModelToString(MemoryModel value) {
+    switch (value) {
+    case MemoryModelSimple: return "Simple";
+    case MemoryModelGLSL450: return "GLSL450";
+    case MemoryModelOpenCL: return "OpenCL";
+    case MemoryModelVulkan: return "Vulkan";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ExecutionModeToString(ExecutionMode value) {
+    switch (value) {
+    case ExecutionModeInvocations: return "Invocations";
+    case ExecutionModeSpacingEqual: return "SpacingEqual";
+    case ExecutionModeSpacingFractionalEven: return "SpacingFractionalEven";
+    case ExecutionModeSpacingFractionalOdd: return "SpacingFractionalOdd";
+    case ExecutionModeVertexOrderCw: return "VertexOrderCw";
+    case ExecutionModeVertexOrderCcw: return "VertexOrderCcw";
+    case ExecutionModePixelCenterInteger: return "PixelCenterInteger";
+    case ExecutionModeOriginUpperLeft: return "OriginUpperLeft";
+    case ExecutionModeOriginLowerLeft: return "OriginLowerLeft";
+    case ExecutionModeEarlyFragmentTests: return "EarlyFragmentTests";
+    case ExecutionModePointMode: return "PointMode";
+    case ExecutionModeXfb: return "Xfb";
+    case ExecutionModeDepthReplacing: return "DepthReplacing";
+    case ExecutionModeDepthGreater: return "DepthGreater";
+    case ExecutionModeDepthLess: return "DepthLess";
+    case ExecutionModeDepthUnchanged: return "DepthUnchanged";
+    case ExecutionModeLocalSize: return "LocalSize";
+    case ExecutionModeLocalSizeHint: return "LocalSizeHint";
+    case ExecutionModeInputPoints: return "InputPoints";
+    case ExecutionModeInputLines: return "InputLines";
+    case ExecutionModeInputLinesAdjacency: return "InputLinesAdjacency";
+    case ExecutionModeTriangles: return "Triangles";
+    case ExecutionModeInputTrianglesAdjacency: return "InputTrianglesAdjacency";
+    case ExecutionModeQuads: return "Quads";
+    case ExecutionModeIsolines: return "Isolines";
+    case ExecutionModeOutputVertices: return "OutputVertices";
+    case ExecutionModeOutputPoints: return "OutputPoints";
+    case ExecutionModeOutputLineStrip: return "OutputLineStrip";
+    case ExecutionModeOutputTriangleStrip: return "OutputTriangleStrip";
+    case ExecutionModeVecTypeHint: return "VecTypeHint";
+    case ExecutionModeContractionOff: return "ContractionOff";
+    case ExecutionModeInitializer: return "Initializer";
+    case ExecutionModeFinalizer: return "Finalizer";
+    case ExecutionModeSubgroupSize: return "SubgroupSize";
+    case ExecutionModeSubgroupsPerWorkgroup: return "SubgroupsPerWorkgroup";
+    case ExecutionModeSubgroupsPerWorkgroupId: return "SubgroupsPerWorkgroupId";
+    case ExecutionModeLocalSizeId: return "LocalSizeId";
+    case ExecutionModeLocalSizeHintId: return "LocalSizeHintId";
+    case ExecutionModeNonCoherentColorAttachmentReadEXT: return "NonCoherentColorAttachmentReadEXT";
+    case ExecutionModeNonCoherentDepthAttachmentReadEXT: return "NonCoherentDepthAttachmentReadEXT";
+    case ExecutionModeNonCoherentStencilAttachmentReadEXT: return "NonCoherentStencilAttachmentReadEXT";
+    case ExecutionModeSubgroupUniformControlFlowKHR: return "SubgroupUniformControlFlowKHR";
+    case ExecutionModePostDepthCoverage: return "PostDepthCoverage";
+    case ExecutionModeDenormPreserve: return "DenormPreserve";
+    case ExecutionModeDenormFlushToZero: return "DenormFlushToZero";
+    case ExecutionModeSignedZeroInfNanPreserve: return "SignedZeroInfNanPreserve";
+    case ExecutionModeRoundingModeRTE: return "RoundingModeRTE";
+    case ExecutionModeRoundingModeRTZ: return "RoundingModeRTZ";
+    case ExecutionModeEarlyAndLateFragmentTestsAMD: return "EarlyAndLateFragmentTestsAMD";
+    case ExecutionModeStencilRefReplacingEXT: return "StencilRefReplacingEXT";
+    case ExecutionModeCoalescingAMDX: return "CoalescingAMDX";
+    case ExecutionModeIsApiEntryAMDX: return "IsApiEntryAMDX";
+    case ExecutionModeMaxNodeRecursionAMDX: return "MaxNodeRecursionAMDX";
+    case ExecutionModeStaticNumWorkgroupsAMDX: return "StaticNumWorkgroupsAMDX";
+    case ExecutionModeShaderIndexAMDX: return "ShaderIndexAMDX";
+    case ExecutionModeMaxNumWorkgroupsAMDX: return "MaxNumWorkgroupsAMDX";
+    case ExecutionModeStencilRefUnchangedFrontAMD: return "StencilRefUnchangedFrontAMD";
+    case ExecutionModeStencilRefGreaterFrontAMD: return "StencilRefGreaterFrontAMD";
+    case ExecutionModeStencilRefLessFrontAMD: return "StencilRefLessFrontAMD";
+    case ExecutionModeStencilRefUnchangedBackAMD: return "StencilRefUnchangedBackAMD";
+    case ExecutionModeStencilRefGreaterBackAMD: return "StencilRefGreaterBackAMD";
+    case ExecutionModeStencilRefLessBackAMD: return "StencilRefLessBackAMD";
+    case ExecutionModeQuadDerivativesKHR: return "QuadDerivativesKHR";
+    case ExecutionModeRequireFullQuadsKHR: return "RequireFullQuadsKHR";
+    case ExecutionModeSharesInputWithAMDX: return "SharesInputWithAMDX";
+    case ExecutionModeOutputLinesEXT: return "OutputLinesEXT";
+    case ExecutionModeOutputPrimitivesEXT: return "OutputPrimitivesEXT";
+    case ExecutionModeDerivativeGroupQuadsKHR: return "DerivativeGroupQuadsKHR";
+    case ExecutionModeDerivativeGroupLinearKHR: return "DerivativeGroupLinearKHR";
+    case ExecutionModeOutputTrianglesEXT: return "OutputTrianglesEXT";
+    case ExecutionModePixelInterlockOrderedEXT: return "PixelInterlockOrderedEXT";
+    case ExecutionModePixelInterlockUnorderedEXT: return "PixelInterlockUnorderedEXT";
+    case ExecutionModeSampleInterlockOrderedEXT: return "SampleInterlockOrderedEXT";
+    case ExecutionModeSampleInterlockUnorderedEXT: return "SampleInterlockUnorderedEXT";
+    case ExecutionModeShadingRateInterlockOrderedEXT: return "ShadingRateInterlockOrderedEXT";
+    case ExecutionModeShadingRateInterlockUnorderedEXT: return "ShadingRateInterlockUnorderedEXT";
+    case ExecutionModeSharedLocalMemorySizeINTEL: return "SharedLocalMemorySizeINTEL";
+    case ExecutionModeRoundingModeRTPINTEL: return "RoundingModeRTPINTEL";
+    case ExecutionModeRoundingModeRTNINTEL: return "RoundingModeRTNINTEL";
+    case ExecutionModeFloatingPointModeALTINTEL: return "FloatingPointModeALTINTEL";
+    case ExecutionModeFloatingPointModeIEEEINTEL: return "FloatingPointModeIEEEINTEL";
+    case ExecutionModeMaxWorkgroupSizeINTEL: return "MaxWorkgroupSizeINTEL";
+    case ExecutionModeMaxWorkDimINTEL: return "MaxWorkDimINTEL";
+    case ExecutionModeNoGlobalOffsetINTEL: return "NoGlobalOffsetINTEL";
+    case ExecutionModeNumSIMDWorkitemsINTEL: return "NumSIMDWorkitemsINTEL";
+    case ExecutionModeSchedulerTargetFmaxMhzINTEL: return "SchedulerTargetFmaxMhzINTEL";
+    case ExecutionModeMaximallyReconvergesKHR: return "MaximallyReconvergesKHR";
+    case ExecutionModeFPFastMathDefault: return "FPFastMathDefault";
+    case ExecutionModeStreamingInterfaceINTEL: return "StreamingInterfaceINTEL";
+    case ExecutionModeRegisterMapInterfaceINTEL: return "RegisterMapInterfaceINTEL";
+    case ExecutionModeNamedBarrierCountINTEL: return "NamedBarrierCountINTEL";
+    case ExecutionModeMaximumRegistersINTEL: return "MaximumRegistersINTEL";
+    case ExecutionModeMaximumRegistersIdINTEL: return "MaximumRegistersIdINTEL";
+    case ExecutionModeNamedMaximumRegistersINTEL: return "NamedMaximumRegistersINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* StorageClassToString(StorageClass value) {
+    switch (value) {
+    case StorageClassUniformConstant: return "UniformConstant";
+    case StorageClassInput: return "Input";
+    case StorageClassUniform: return "Uniform";
+    case StorageClassOutput: return "Output";
+    case StorageClassWorkgroup: return "Workgroup";
+    case StorageClassCrossWorkgroup: return "CrossWorkgroup";
+    case StorageClassPrivate: return "Private";
+    case StorageClassFunction: return "Function";
+    case StorageClassGeneric: return "Generic";
+    case StorageClassPushConstant: return "PushConstant";
+    case StorageClassAtomicCounter: return "AtomicCounter";
+    case StorageClassImage: return "Image";
+    case StorageClassStorageBuffer: return "StorageBuffer";
+    case StorageClassTileImageEXT: return "TileImageEXT";
+    case StorageClassNodePayloadAMDX: return "NodePayloadAMDX";
+    case StorageClassCallableDataKHR: return "CallableDataKHR";
+    case StorageClassIncomingCallableDataKHR: return "IncomingCallableDataKHR";
+    case StorageClassRayPayloadKHR: return "RayPayloadKHR";
+    case StorageClassHitAttributeKHR: return "HitAttributeKHR";
+    case StorageClassIncomingRayPayloadKHR: return "IncomingRayPayloadKHR";
+    case StorageClassShaderRecordBufferKHR: return "ShaderRecordBufferKHR";
+    case StorageClassPhysicalStorageBuffer: return "PhysicalStorageBuffer";
+    case StorageClassHitObjectAttributeNV: return "HitObjectAttributeNV";
+    case StorageClassTaskPayloadWorkgroupEXT: return "TaskPayloadWorkgroupEXT";
+    case StorageClassCodeSectionINTEL: return "CodeSectionINTEL";
+    case StorageClassDeviceOnlyINTEL: return "DeviceOnlyINTEL";
+    case StorageClassHostOnlyINTEL: return "HostOnlyINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* DimToString(Dim value) {
+    switch (value) {
+    case Dim1D: return "1D";
+    case Dim2D: return "2D";
+    case Dim3D: return "3D";
+    case DimCube: return "Cube";
+    case DimRect: return "Rect";
+    case DimBuffer: return "Buffer";
+    case DimSubpassData: return "SubpassData";
+    case DimTileImageDataEXT: return "TileImageDataEXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SamplerAddressingModeToString(SamplerAddressingMode value) {
+    switch (value) {
+    case SamplerAddressingModeNone: return "None";
+    case SamplerAddressingModeClampToEdge: return "ClampToEdge";
+    case SamplerAddressingModeClamp: return "Clamp";
+    case SamplerAddressingModeRepeat: return "Repeat";
+    case SamplerAddressingModeRepeatMirrored: return "RepeatMirrored";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SamplerFilterModeToString(SamplerFilterMode value) {
+    switch (value) {
+    case SamplerFilterModeNearest: return "Nearest";
+    case SamplerFilterModeLinear: return "Linear";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ImageFormatToString(ImageFormat value) {
+    switch (value) {
+    case ImageFormatUnknown: return "Unknown";
+    case ImageFormatRgba32f: return "Rgba32f";
+    case ImageFormatRgba16f: return "Rgba16f";
+    case ImageFormatR32f: return "R32f";
+    case ImageFormatRgba8: return "Rgba8";
+    case ImageFormatRgba8Snorm: return "Rgba8Snorm";
+    case ImageFormatRg32f: return "Rg32f";
+    case ImageFormatRg16f: return "Rg16f";
+    case ImageFormatR11fG11fB10f: return "R11fG11fB10f";
+    case ImageFormatR16f: return "R16f";
+    case ImageFormatRgba16: return "Rgba16";
+    case ImageFormatRgb10A2: return "Rgb10A2";
+    case ImageFormatRg16: return "Rg16";
+    case ImageFormatRg8: return "Rg8";
+    case ImageFormatR16: return "R16";
+    case ImageFormatR8: return "R8";
+    case ImageFormatRgba16Snorm: return "Rgba16Snorm";
+    case ImageFormatRg16Snorm: return "Rg16Snorm";
+    case ImageFormatRg8Snorm: return "Rg8Snorm";
+    case ImageFormatR16Snorm: return "R16Snorm";
+    case ImageFormatR8Snorm: return "R8Snorm";
+    case ImageFormatRgba32i: return "Rgba32i";
+    case ImageFormatRgba16i: return "Rgba16i";
+    case ImageFormatRgba8i: return "Rgba8i";
+    case ImageFormatR32i: return "R32i";
+    case ImageFormatRg32i: return "Rg32i";
+    case ImageFormatRg16i: return "Rg16i";
+    case ImageFormatRg8i: return "Rg8i";
+    case ImageFormatR16i: return "R16i";
+    case ImageFormatR8i: return "R8i";
+    case ImageFormatRgba32ui: return "Rgba32ui";
+    case ImageFormatRgba16ui: return "Rgba16ui";
+    case ImageFormatRgba8ui: return "Rgba8ui";
+    case ImageFormatR32ui: return "R32ui";
+    case ImageFormatRgb10a2ui: return "Rgb10a2ui";
+    case ImageFormatRg32ui: return "Rg32ui";
+    case ImageFormatRg16ui: return "Rg16ui";
+    case ImageFormatRg8ui: return "Rg8ui";
+    case ImageFormatR16ui: return "R16ui";
+    case ImageFormatR8ui: return "R8ui";
+    case ImageFormatR64ui: return "R64ui";
+    case ImageFormatR64i: return "R64i";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ImageChannelOrderToString(ImageChannelOrder value) {
+    switch (value) {
+    case ImageChannelOrderR: return "R";
+    case ImageChannelOrderA: return "A";
+    case ImageChannelOrderRG: return "RG";
+    case ImageChannelOrderRA: return "RA";
+    case ImageChannelOrderRGB: return "RGB";
+    case ImageChannelOrderRGBA: return "RGBA";
+    case ImageChannelOrderBGRA: return "BGRA";
+    case ImageChannelOrderARGB: return "ARGB";
+    case ImageChannelOrderIntensity: return "Intensity";
+    case ImageChannelOrderLuminance: return "Luminance";
+    case ImageChannelOrderRx: return "Rx";
+    case ImageChannelOrderRGx: return "RGx";
+    case ImageChannelOrderRGBx: return "RGBx";
+    case ImageChannelOrderDepth: return "Depth";
+    case ImageChannelOrderDepthStencil: return "DepthStencil";
+    case ImageChannelOrdersRGB: return "sRGB";
+    case ImageChannelOrdersRGBx: return "sRGBx";
+    case ImageChannelOrdersRGBA: return "sRGBA";
+    case ImageChannelOrdersBGRA: return "sBGRA";
+    case ImageChannelOrderABGR: return "ABGR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ImageChannelDataTypeToString(ImageChannelDataType value) {
+    switch (value) {
+    case ImageChannelDataTypeSnormInt8: return "SnormInt8";
+    case ImageChannelDataTypeSnormInt16: return "SnormInt16";
+    case ImageChannelDataTypeUnormInt8: return "UnormInt8";
+    case ImageChannelDataTypeUnormInt16: return "UnormInt16";
+    case ImageChannelDataTypeUnormShort565: return "UnormShort565";
+    case ImageChannelDataTypeUnormShort555: return "UnormShort555";
+    case ImageChannelDataTypeUnormInt101010: return "UnormInt101010";
+    case ImageChannelDataTypeSignedInt8: return "SignedInt8";
+    case ImageChannelDataTypeSignedInt16: return "SignedInt16";
+    case ImageChannelDataTypeSignedInt32: return "SignedInt32";
+    case ImageChannelDataTypeUnsignedInt8: return "UnsignedInt8";
+    case ImageChannelDataTypeUnsignedInt16: return "UnsignedInt16";
+    case ImageChannelDataTypeUnsignedInt32: return "UnsignedInt32";
+    case ImageChannelDataTypeHalfFloat: return "HalfFloat";
+    case ImageChannelDataTypeFloat: return "Float";
+    case ImageChannelDataTypeUnormInt24: return "UnormInt24";
+    case ImageChannelDataTypeUnormInt101010_2: return "UnormInt101010_2";
+    case ImageChannelDataTypeUnsignedIntRaw10EXT: return "UnsignedIntRaw10EXT";
+    case ImageChannelDataTypeUnsignedIntRaw12EXT: return "UnsignedIntRaw12EXT";
+    case ImageChannelDataTypeUnormInt2_101010EXT: return "UnormInt2_101010EXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FPRoundingModeToString(FPRoundingMode value) {
+    switch (value) {
+    case FPRoundingModeRTE: return "RTE";
+    case FPRoundingModeRTZ: return "RTZ";
+    case FPRoundingModeRTP: return "RTP";
+    case FPRoundingModeRTN: return "RTN";
+    default: return "Unknown";
+    }
+}
+
+inline const char* LinkageTypeToString(LinkageType value) {
+    switch (value) {
+    case LinkageTypeExport: return "Export";
+    case LinkageTypeImport: return "Import";
+    case LinkageTypeLinkOnceODR: return "LinkOnceODR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* AccessQualifierToString(AccessQualifier value) {
+    switch (value) {
+    case AccessQualifierReadOnly: return "ReadOnly";
+    case AccessQualifierWriteOnly: return "WriteOnly";
+    case AccessQualifierReadWrite: return "ReadWrite";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FunctionParameterAttributeToString(FunctionParameterAttribute value) {
+    switch (value) {
+    case FunctionParameterAttributeZext: return "Zext";
+    case FunctionParameterAttributeSext: return "Sext";
+    case FunctionParameterAttributeByVal: return "ByVal";
+    case FunctionParameterAttributeSret: return "Sret";
+    case FunctionParameterAttributeNoAlias: return "NoAlias";
+    case FunctionParameterAttributeNoCapture: return "NoCapture";
+    case FunctionParameterAttributeNoWrite: return "NoWrite";
+    case FunctionParameterAttributeNoReadWrite: return "NoReadWrite";
+    case FunctionParameterAttributeRuntimeAlignedINTEL: return "RuntimeAlignedINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* DecorationToString(Decoration value) {
+    switch (value) {
+    case DecorationRelaxedPrecision: return "RelaxedPrecision";
+    case DecorationSpecId: return "SpecId";
+    case DecorationBlock: return "Block";
+    case DecorationBufferBlock: return "BufferBlock";
+    case DecorationRowMajor: return "RowMajor";
+    case DecorationColMajor: return "ColMajor";
+    case DecorationArrayStride: return "ArrayStride";
+    case DecorationMatrixStride: return "MatrixStride";
+    case DecorationGLSLShared: return "GLSLShared";
+    case DecorationGLSLPacked: return "GLSLPacked";
+    case DecorationCPacked: return "CPacked";
+    case DecorationBuiltIn: return "BuiltIn";
+    case DecorationNoPerspective: return "NoPerspective";
+    case DecorationFlat: return "Flat";
+    case DecorationPatch: return "Patch";
+    case DecorationCentroid: return "Centroid";
+    case DecorationSample: return "Sample";
+    case DecorationInvariant: return "Invariant";
+    case DecorationRestrict: return "Restrict";
+    case DecorationAliased: return "Aliased";
+    case DecorationVolatile: return "Volatile";
+    case DecorationConstant: return "Constant";
+    case DecorationCoherent: return "Coherent";
+    case DecorationNonWritable: return "NonWritable";
+    case DecorationNonReadable: return "NonReadable";
+    case DecorationUniform: return "Uniform";
+    case DecorationUniformId: return "UniformId";
+    case DecorationSaturatedConversion: return "SaturatedConversion";
+    case DecorationStream: return "Stream";
+    case DecorationLocation: return "Location";
+    case DecorationComponent: return "Component";
+    case DecorationIndex: return "Index";
+    case DecorationBinding: return "Binding";
+    case DecorationDescriptorSet: return "DescriptorSet";
+    case DecorationOffset: return "Offset";
+    case DecorationXfbBuffer: return "XfbBuffer";
+    case DecorationXfbStride: return "XfbStride";
+    case DecorationFuncParamAttr: return "FuncParamAttr";
+    case DecorationFPRoundingMode: return "FPRoundingMode";
+    case DecorationFPFastMathMode: return "FPFastMathMode";
+    case DecorationLinkageAttributes: return "LinkageAttributes";
+    case DecorationNoContraction: return "NoContraction";
+    case DecorationInputAttachmentIndex: return "InputAttachmentIndex";
+    case DecorationAlignment: return "Alignment";
+    case DecorationMaxByteOffset: return "MaxByteOffset";
+    case DecorationAlignmentId: return "AlignmentId";
+    case DecorationMaxByteOffsetId: return "MaxByteOffsetId";
+    case DecorationNoSignedWrap: return "NoSignedWrap";
+    case DecorationNoUnsignedWrap: return "NoUnsignedWrap";
+    case DecorationWeightTextureQCOM: return "WeightTextureQCOM";
+    case DecorationBlockMatchTextureQCOM: return "BlockMatchTextureQCOM";
+    case DecorationBlockMatchSamplerQCOM: return "BlockMatchSamplerQCOM";
+    case DecorationExplicitInterpAMD: return "ExplicitInterpAMD";
+    case DecorationNodeSharesPayloadLimitsWithAMDX: return "NodeSharesPayloadLimitsWithAMDX";
+    case DecorationNodeMaxPayloadsAMDX: return "NodeMaxPayloadsAMDX";
+    case DecorationTrackFinishWritingAMDX: return "TrackFinishWritingAMDX";
+    case DecorationPayloadNodeNameAMDX: return "PayloadNodeNameAMDX";
+    case DecorationPayloadNodeBaseIndexAMDX: return "PayloadNodeBaseIndexAMDX";
+    case DecorationPayloadNodeSparseArrayAMDX: return "PayloadNodeSparseArrayAMDX";
+    case DecorationPayloadNodeArraySizeAMDX: return "PayloadNodeArraySizeAMDX";
+    case DecorationPayloadDispatchIndirectAMDX: return "PayloadDispatchIndirectAMDX";
+    case DecorationOverrideCoverageNV: return "OverrideCoverageNV";
+    case DecorationPassthroughNV: return "PassthroughNV";
+    case DecorationViewportRelativeNV: return "ViewportRelativeNV";
+    case DecorationSecondaryViewportRelativeNV: return "SecondaryViewportRelativeNV";
+    case DecorationPerPrimitiveEXT: return "PerPrimitiveEXT";
+    case DecorationPerViewNV: return "PerViewNV";
+    case DecorationPerTaskNV: return "PerTaskNV";
+    case DecorationPerVertexKHR: return "PerVertexKHR";
+    case DecorationNonUniform: return "NonUniform";
+    case DecorationRestrictPointer: return "RestrictPointer";
+    case DecorationAliasedPointer: return "AliasedPointer";
+    case DecorationHitObjectShaderRecordBufferNV: return "HitObjectShaderRecordBufferNV";
+    case DecorationBindlessSamplerNV: return "BindlessSamplerNV";
+    case DecorationBindlessImageNV: return "BindlessImageNV";
+    case DecorationBoundSamplerNV: return "BoundSamplerNV";
+    case DecorationBoundImageNV: return "BoundImageNV";
+    case DecorationSIMTCallINTEL: return "SIMTCallINTEL";
+    case DecorationReferencedIndirectlyINTEL: return "ReferencedIndirectlyINTEL";
+    case DecorationClobberINTEL: return "ClobberINTEL";
+    case DecorationSideEffectsINTEL: return "SideEffectsINTEL";
+    case DecorationVectorComputeVariableINTEL: return "VectorComputeVariableINTEL";
+    case DecorationFuncParamIOKindINTEL: return "FuncParamIOKindINTEL";
+    case DecorationVectorComputeFunctionINTEL: return "VectorComputeFunctionINTEL";
+    case DecorationStackCallINTEL: return "StackCallINTEL";
+    case DecorationGlobalVariableOffsetINTEL: return "GlobalVariableOffsetINTEL";
+    case DecorationCounterBuffer: return "CounterBuffer";
+    case DecorationHlslSemanticGOOGLE: return "HlslSemanticGOOGLE";
+    case DecorationUserTypeGOOGLE: return "UserTypeGOOGLE";
+    case DecorationFunctionRoundingModeINTEL: return "FunctionRoundingModeINTEL";
+    case DecorationFunctionDenormModeINTEL: return "FunctionDenormModeINTEL";
+    case DecorationRegisterINTEL: return "RegisterINTEL";
+    case DecorationMemoryINTEL: return "MemoryINTEL";
+    case DecorationNumbanksINTEL: return "NumbanksINTEL";
+    case DecorationBankwidthINTEL: return "BankwidthINTEL";
+    case DecorationMaxPrivateCopiesINTEL: return "MaxPrivateCopiesINTEL";
+    case DecorationSinglepumpINTEL: return "SinglepumpINTEL";
+    case DecorationDoublepumpINTEL: return "DoublepumpINTEL";
+    case DecorationMaxReplicatesINTEL: return "MaxReplicatesINTEL";
+    case DecorationSimpleDualPortINTEL: return "SimpleDualPortINTEL";
+    case DecorationMergeINTEL: return "MergeINTEL";
+    case DecorationBankBitsINTEL: return "BankBitsINTEL";
+    case DecorationForcePow2DepthINTEL: return "ForcePow2DepthINTEL";
+    case DecorationStridesizeINTEL: return "StridesizeINTEL";
+    case DecorationWordsizeINTEL: return "WordsizeINTEL";
+    case DecorationTrueDualPortINTEL: return "TrueDualPortINTEL";
+    case DecorationBurstCoalesceINTEL: return "BurstCoalesceINTEL";
+    case DecorationCacheSizeINTEL: return "CacheSizeINTEL";
+    case DecorationDontStaticallyCoalesceINTEL: return "DontStaticallyCoalesceINTEL";
+    case DecorationPrefetchINTEL: return "PrefetchINTEL";
+    case DecorationStallEnableINTEL: return "StallEnableINTEL";
+    case DecorationFuseLoopsInFunctionINTEL: return "FuseLoopsInFunctionINTEL";
+    case DecorationMathOpDSPModeINTEL: return "MathOpDSPModeINTEL";
+    case DecorationAliasScopeINTEL: return "AliasScopeINTEL";
+    case DecorationNoAliasINTEL: return "NoAliasINTEL";
+    case DecorationInitiationIntervalINTEL: return "InitiationIntervalINTEL";
+    case DecorationMaxConcurrencyINTEL: return "MaxConcurrencyINTEL";
+    case DecorationPipelineEnableINTEL: return "PipelineEnableINTEL";
+    case DecorationBufferLocationINTEL: return "BufferLocationINTEL";
+    case DecorationIOPipeStorageINTEL: return "IOPipeStorageINTEL";
+    case DecorationFunctionFloatingPointModeINTEL: return "FunctionFloatingPointModeINTEL";
+    case DecorationSingleElementVectorINTEL: return "SingleElementVectorINTEL";
+    case DecorationVectorComputeCallableFunctionINTEL: return "VectorComputeCallableFunctionINTEL";
+    case DecorationMediaBlockIOINTEL: return "MediaBlockIOINTEL";
+    case DecorationStallFreeINTEL: return "StallFreeINTEL";
+    case DecorationFPMaxErrorDecorationINTEL: return "FPMaxErrorDecorationINTEL";
+    case DecorationLatencyControlLabelINTEL: return "LatencyControlLabelINTEL";
+    case DecorationLatencyControlConstraintINTEL: return "LatencyControlConstraintINTEL";
+    case DecorationConduitKernelArgumentINTEL: return "ConduitKernelArgumentINTEL";
+    case DecorationRegisterMapKernelArgumentINTEL: return "RegisterMapKernelArgumentINTEL";
+    case DecorationMMHostInterfaceAddressWidthINTEL: return "MMHostInterfaceAddressWidthINTEL";
+    case DecorationMMHostInterfaceDataWidthINTEL: return "MMHostInterfaceDataWidthINTEL";
+    case DecorationMMHostInterfaceLatencyINTEL: return "MMHostInterfaceLatencyINTEL";
+    case DecorationMMHostInterfaceReadWriteModeINTEL: return "MMHostInterfaceReadWriteModeINTEL";
+    case DecorationMMHostInterfaceMaxBurstINTEL: return "MMHostInterfaceMaxBurstINTEL";
+    case DecorationMMHostInterfaceWaitRequestINTEL: return "MMHostInterfaceWaitRequestINTEL";
+    case DecorationStableKernelArgumentINTEL: return "StableKernelArgumentINTEL";
+    case DecorationHostAccessINTEL: return "HostAccessINTEL";
+    case DecorationInitModeINTEL: return "InitModeINTEL";
+    case DecorationImplementInRegisterMapINTEL: return "ImplementInRegisterMapINTEL";
+    case DecorationCacheControlLoadINTEL: return "CacheControlLoadINTEL";
+    case DecorationCacheControlStoreINTEL: return "CacheControlStoreINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* BuiltInToString(BuiltIn value) {
+    switch (value) {
+    case BuiltInPosition: return "Position";
+    case BuiltInPointSize: return "PointSize";
+    case BuiltInClipDistance: return "ClipDistance";
+    case BuiltInCullDistance: return "CullDistance";
+    case BuiltInVertexId: return "VertexId";
+    case BuiltInInstanceId: return "InstanceId";
+    case BuiltInPrimitiveId: return "PrimitiveId";
+    case BuiltInInvocationId: return "InvocationId";
+    case BuiltInLayer: return "Layer";
+    case BuiltInViewportIndex: return "ViewportIndex";
+    case BuiltInTessLevelOuter: return "TessLevelOuter";
+    case BuiltInTessLevelInner: return "TessLevelInner";
+    case BuiltInTessCoord: return "TessCoord";
+    case BuiltInPatchVertices: return "PatchVertices";
+    case BuiltInFragCoord: return "FragCoord";
+    case BuiltInPointCoord: return "PointCoord";
+    case BuiltInFrontFacing: return "FrontFacing";
+    case BuiltInSampleId: return "SampleId";
+    case BuiltInSamplePosition: return "SamplePosition";
+    case BuiltInSampleMask: return "SampleMask";
+    case BuiltInFragDepth: return "FragDepth";
+    case BuiltInHelperInvocation: return "HelperInvocation";
+    case BuiltInNumWorkgroups: return "NumWorkgroups";
+    case BuiltInWorkgroupSize: return "WorkgroupSize";
+    case BuiltInWorkgroupId: return "WorkgroupId";
+    case BuiltInLocalInvocationId: return "LocalInvocationId";
+    case BuiltInGlobalInvocationId: return "GlobalInvocationId";
+    case BuiltInLocalInvocationIndex: return "LocalInvocationIndex";
+    case BuiltInWorkDim: return "WorkDim";
+    case BuiltInGlobalSize: return "GlobalSize";
+    case BuiltInEnqueuedWorkgroupSize: return "EnqueuedWorkgroupSize";
+    case BuiltInGlobalOffset: return "GlobalOffset";
+    case BuiltInGlobalLinearId: return "GlobalLinearId";
+    case BuiltInSubgroupSize: return "SubgroupSize";
+    case BuiltInSubgroupMaxSize: return "SubgroupMaxSize";
+    case BuiltInNumSubgroups: return "NumSubgroups";
+    case BuiltInNumEnqueuedSubgroups: return "NumEnqueuedSubgroups";
+    case BuiltInSubgroupId: return "SubgroupId";
+    case BuiltInSubgroupLocalInvocationId: return "SubgroupLocalInvocationId";
+    case BuiltInVertexIndex: return "VertexIndex";
+    case BuiltInInstanceIndex: return "InstanceIndex";
+    case BuiltInCoreIDARM: return "CoreIDARM";
+    case BuiltInCoreCountARM: return "CoreCountARM";
+    case BuiltInCoreMaxIDARM: return "CoreMaxIDARM";
+    case BuiltInWarpIDARM: return "WarpIDARM";
+    case BuiltInWarpMaxIDARM: return "WarpMaxIDARM";
+    case BuiltInSubgroupEqMask: return "SubgroupEqMask";
+    case BuiltInSubgroupGeMask: return "SubgroupGeMask";
+    case BuiltInSubgroupGtMask: return "SubgroupGtMask";
+    case BuiltInSubgroupLeMask: return "SubgroupLeMask";
+    case BuiltInSubgroupLtMask: return "SubgroupLtMask";
+    case BuiltInBaseVertex: return "BaseVertex";
+    case BuiltInBaseInstance: return "BaseInstance";
+    case BuiltInDrawIndex: return "DrawIndex";
+    case BuiltInPrimitiveShadingRateKHR: return "PrimitiveShadingRateKHR";
+    case BuiltInDeviceIndex: return "DeviceIndex";
+    case BuiltInViewIndex: return "ViewIndex";
+    case BuiltInShadingRateKHR: return "ShadingRateKHR";
+    case BuiltInBaryCoordNoPerspAMD: return "BaryCoordNoPerspAMD";
+    case BuiltInBaryCoordNoPerspCentroidAMD: return "BaryCoordNoPerspCentroidAMD";
+    case BuiltInBaryCoordNoPerspSampleAMD: return "BaryCoordNoPerspSampleAMD";
+    case BuiltInBaryCoordSmoothAMD: return "BaryCoordSmoothAMD";
+    case BuiltInBaryCoordSmoothCentroidAMD: return "BaryCoordSmoothCentroidAMD";
+    case BuiltInBaryCoordSmoothSampleAMD: return "BaryCoordSmoothSampleAMD";
+    case BuiltInBaryCoordPullModelAMD: return "BaryCoordPullModelAMD";
+    case BuiltInFragStencilRefEXT: return "FragStencilRefEXT";
+    case BuiltInRemainingRecursionLevelsAMDX: return "RemainingRecursionLevelsAMDX";
+    case BuiltInShaderIndexAMDX: return "ShaderIndexAMDX";
+    case BuiltInViewportMaskNV: return "ViewportMaskNV";
+    case BuiltInSecondaryPositionNV: return "SecondaryPositionNV";
+    case BuiltInSecondaryViewportMaskNV: return "SecondaryViewportMaskNV";
+    case BuiltInPositionPerViewNV: return "PositionPerViewNV";
+    case BuiltInViewportMaskPerViewNV: return "ViewportMaskPerViewNV";
+    case BuiltInFullyCoveredEXT: return "FullyCoveredEXT";
+    case BuiltInTaskCountNV: return "TaskCountNV";
+    case BuiltInPrimitiveCountNV: return "PrimitiveCountNV";
+    case BuiltInPrimitiveIndicesNV: return "PrimitiveIndicesNV";
+    case BuiltInClipDistancePerViewNV: return "ClipDistancePerViewNV";
+    case BuiltInCullDistancePerViewNV: return "CullDistancePerViewNV";
+    case BuiltInLayerPerViewNV: return "LayerPerViewNV";
+    case BuiltInMeshViewCountNV: return "MeshViewCountNV";
+    case BuiltInMeshViewIndicesNV: return "MeshViewIndicesNV";
+    case BuiltInBaryCoordKHR: return "BaryCoordKHR";
+    case BuiltInBaryCoordNoPerspKHR: return "BaryCoordNoPerspKHR";
+    case BuiltInFragSizeEXT: return "FragSizeEXT";
+    case BuiltInFragInvocationCountEXT: return "FragInvocationCountEXT";
+    case BuiltInPrimitivePointIndicesEXT: return "PrimitivePointIndicesEXT";
+    case BuiltInPrimitiveLineIndicesEXT: return "PrimitiveLineIndicesEXT";
+    case BuiltInPrimitiveTriangleIndicesEXT: return "PrimitiveTriangleIndicesEXT";
+    case BuiltInCullPrimitiveEXT: return "CullPrimitiveEXT";
+    case BuiltInLaunchIdKHR: return "LaunchIdKHR";
+    case BuiltInLaunchSizeKHR: return "LaunchSizeKHR";
+    case BuiltInWorldRayOriginKHR: return "WorldRayOriginKHR";
+    case BuiltInWorldRayDirectionKHR: return "WorldRayDirectionKHR";
+    case BuiltInObjectRayOriginKHR: return "ObjectRayOriginKHR";
+    case BuiltInObjectRayDirectionKHR: return "ObjectRayDirectionKHR";
+    case BuiltInRayTminKHR: return "RayTminKHR";
+    case BuiltInRayTmaxKHR: return "RayTmaxKHR";
+    case BuiltInInstanceCustomIndexKHR: return "InstanceCustomIndexKHR";
+    case BuiltInObjectToWorldKHR: return "ObjectToWorldKHR";
+    case BuiltInWorldToObjectKHR: return "WorldToObjectKHR";
+    case BuiltInHitTNV: return "HitTNV";
+    case BuiltInHitKindKHR: return "HitKindKHR";
+    case BuiltInCurrentRayTimeNV: return "CurrentRayTimeNV";
+    case BuiltInHitTriangleVertexPositionsKHR: return "HitTriangleVertexPositionsKHR";
+    case BuiltInHitMicroTriangleVertexPositionsNV: return "HitMicroTriangleVertexPositionsNV";
+    case BuiltInHitMicroTriangleVertexBarycentricsNV: return "HitMicroTriangleVertexBarycentricsNV";
+    case BuiltInIncomingRayFlagsKHR: return "IncomingRayFlagsKHR";
+    case BuiltInRayGeometryIndexKHR: return "RayGeometryIndexKHR";
+    case BuiltInWarpsPerSMNV: return "WarpsPerSMNV";
+    case BuiltInSMCountNV: return "SMCountNV";
+    case BuiltInWarpIDNV: return "WarpIDNV";
+    case BuiltInSMIDNV: return "SMIDNV";
+    case BuiltInHitKindFrontFacingMicroTriangleNV: return "HitKindFrontFacingMicroTriangleNV";
+    case BuiltInHitKindBackFacingMicroTriangleNV: return "HitKindBackFacingMicroTriangleNV";
+    case BuiltInCullMaskKHR: return "CullMaskKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ScopeToString(Scope value) {
+    switch (value) {
+    case ScopeCrossDevice: return "CrossDevice";
+    case ScopeDevice: return "Device";
+    case ScopeWorkgroup: return "Workgroup";
+    case ScopeSubgroup: return "Subgroup";
+    case ScopeInvocation: return "Invocation";
+    case ScopeQueueFamily: return "QueueFamily";
+    case ScopeShaderCallKHR: return "ShaderCallKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* GroupOperationToString(GroupOperation value) {
+    switch (value) {
+    case GroupOperationReduce: return "Reduce";
+    case GroupOperationInclusiveScan: return "InclusiveScan";
+    case GroupOperationExclusiveScan: return "ExclusiveScan";
+    case GroupOperationClusteredReduce: return "ClusteredReduce";
+    case GroupOperationPartitionedReduceNV: return "PartitionedReduceNV";
+    case GroupOperationPartitionedInclusiveScanNV: return "PartitionedInclusiveScanNV";
+    case GroupOperationPartitionedExclusiveScanNV: return "PartitionedExclusiveScanNV";
+    default: return "Unknown";
+    }
+}
+
+inline const char* KernelEnqueueFlagsToString(KernelEnqueueFlags value) {
+    switch (value) {
+    case KernelEnqueueFlagsNoWait: return "NoWait";
+    case KernelEnqueueFlagsWaitKernel: return "WaitKernel";
+    case KernelEnqueueFlagsWaitWorkGroup: return "WaitWorkGroup";
+    default: return "Unknown";
+    }
+}
+
+inline const char* CapabilityToString(Capability value) {
+    switch (value) {
+    case CapabilityMatrix: return "Matrix";
+    case CapabilityShader: return "Shader";
+    case CapabilityGeometry: return "Geometry";
+    case CapabilityTessellation: return "Tessellation";
+    case CapabilityAddresses: return "Addresses";
+    case CapabilityLinkage: return "Linkage";
+    case CapabilityKernel: return "Kernel";
+    case CapabilityVector16: return "Vector16";
+    case CapabilityFloat16Buffer: return "Float16Buffer";
+    case CapabilityFloat16: return "Float16";
+    case CapabilityFloat64: return "Float64";
+    case CapabilityInt64: return "Int64";
+    case CapabilityInt64Atomics: return "Int64Atomics";
+    case CapabilityImageBasic: return "ImageBasic";
+    case CapabilityImageReadWrite: return "ImageReadWrite";
+    case CapabilityImageMipmap: return "ImageMipmap";
+    case CapabilityPipes: return "Pipes";
+    case CapabilityGroups: return "Groups";
+    case CapabilityDeviceEnqueue: return "DeviceEnqueue";
+    case CapabilityLiteralSampler: return "LiteralSampler";
+    case CapabilityAtomicStorage: return "AtomicStorage";
+    case CapabilityInt16: return "Int16";
+    case CapabilityTessellationPointSize: return "TessellationPointSize";
+    case CapabilityGeometryPointSize: return "GeometryPointSize";
+    case CapabilityImageGatherExtended: return "ImageGatherExtended";
+    case CapabilityStorageImageMultisample: return "StorageImageMultisample";
+    case CapabilityUniformBufferArrayDynamicIndexing: return "UniformBufferArrayDynamicIndexing";
+    case CapabilitySampledImageArrayDynamicIndexing: return "SampledImageArrayDynamicIndexing";
+    case CapabilityStorageBufferArrayDynamicIndexing: return "StorageBufferArrayDynamicIndexing";
+    case CapabilityStorageImageArrayDynamicIndexing: return "StorageImageArrayDynamicIndexing";
+    case CapabilityClipDistance: return "ClipDistance";
+    case CapabilityCullDistance: return "CullDistance";
+    case CapabilityImageCubeArray: return "ImageCubeArray";
+    case CapabilitySampleRateShading: return "SampleRateShading";
+    case CapabilityImageRect: return "ImageRect";
+    case CapabilitySampledRect: return "SampledRect";
+    case CapabilityGenericPointer: return "GenericPointer";
+    case CapabilityInt8: return "Int8";
+    case CapabilityInputAttachment: return "InputAttachment";
+    case CapabilitySparseResidency: return "SparseResidency";
+    case CapabilityMinLod: return "MinLod";
+    case CapabilitySampled1D: return "Sampled1D";
+    case CapabilityImage1D: return "Image1D";
+    case CapabilitySampledCubeArray: return "SampledCubeArray";
+    case CapabilitySampledBuffer: return "SampledBuffer";
+    case CapabilityImageBuffer: return "ImageBuffer";
+    case CapabilityImageMSArray: return "ImageMSArray";
+    case CapabilityStorageImageExtendedFormats: return "StorageImageExtendedFormats";
+    case CapabilityImageQuery: return "ImageQuery";
+    case CapabilityDerivativeControl: return "DerivativeControl";
+    case CapabilityInterpolationFunction: return "InterpolationFunction";
+    case CapabilityTransformFeedback: return "TransformFeedback";
+    case CapabilityGeometryStreams: return "GeometryStreams";
+    case CapabilityStorageImageReadWithoutFormat: return "StorageImageReadWithoutFormat";
+    case CapabilityStorageImageWriteWithoutFormat: return "StorageImageWriteWithoutFormat";
+    case CapabilityMultiViewport: return "MultiViewport";
+    case CapabilitySubgroupDispatch: return "SubgroupDispatch";
+    case CapabilityNamedBarrier: return "NamedBarrier";
+    case CapabilityPipeStorage: return "PipeStorage";
+    case CapabilityGroupNonUniform: return "GroupNonUniform";
+    case CapabilityGroupNonUniformVote: return "GroupNonUniformVote";
+    case CapabilityGroupNonUniformArithmetic: return "GroupNonUniformArithmetic";
+    case CapabilityGroupNonUniformBallot: return "GroupNonUniformBallot";
+    case CapabilityGroupNonUniformShuffle: return "GroupNonUniformShuffle";
+    case CapabilityGroupNonUniformShuffleRelative: return "GroupNonUniformShuffleRelative";
+    case CapabilityGroupNonUniformClustered: return "GroupNonUniformClustered";
+    case CapabilityGroupNonUniformQuad: return "GroupNonUniformQuad";
+    case CapabilityShaderLayer: return "ShaderLayer";
+    case CapabilityShaderViewportIndex: return "ShaderViewportIndex";
+    case CapabilityUniformDecoration: return "UniformDecoration";
+    case CapabilityCoreBuiltinsARM: return "CoreBuiltinsARM";
+    case CapabilityTileImageColorReadAccessEXT: return "TileImageColorReadAccessEXT";
+    case CapabilityTileImageDepthReadAccessEXT: return "TileImageDepthReadAccessEXT";
+    case CapabilityTileImageStencilReadAccessEXT: return "TileImageStencilReadAccessEXT";
+    case CapabilityCooperativeMatrixLayoutsARM: return "CooperativeMatrixLayoutsARM";
+    case CapabilityFragmentShadingRateKHR: return "FragmentShadingRateKHR";
+    case CapabilitySubgroupBallotKHR: return "SubgroupBallotKHR";
+    case CapabilityDrawParameters: return "DrawParameters";
+    case CapabilityWorkgroupMemoryExplicitLayoutKHR: return "WorkgroupMemoryExplicitLayoutKHR";
+    case CapabilityWorkgroupMemoryExplicitLayout8BitAccessKHR: return "WorkgroupMemoryExplicitLayout8BitAccessKHR";
+    case CapabilityWorkgroupMemoryExplicitLayout16BitAccessKHR: return "WorkgroupMemoryExplicitLayout16BitAccessKHR";
+    case CapabilitySubgroupVoteKHR: return "SubgroupVoteKHR";
+    case CapabilityStorageBuffer16BitAccess: return "StorageBuffer16BitAccess";
+    case CapabilityStorageUniform16: return "StorageUniform16";
+    case CapabilityStoragePushConstant16: return "StoragePushConstant16";
+    case CapabilityStorageInputOutput16: return "StorageInputOutput16";
+    case CapabilityDeviceGroup: return "DeviceGroup";
+    case CapabilityMultiView: return "MultiView";
+    case CapabilityVariablePointersStorageBuffer: return "VariablePointersStorageBuffer";
+    case CapabilityVariablePointers: return "VariablePointers";
+    case CapabilityAtomicStorageOps: return "AtomicStorageOps";
+    case CapabilitySampleMaskPostDepthCoverage: return "SampleMaskPostDepthCoverage";
+    case CapabilityStorageBuffer8BitAccess: return "StorageBuffer8BitAccess";
+    case CapabilityUniformAndStorageBuffer8BitAccess: return "UniformAndStorageBuffer8BitAccess";
+    case CapabilityStoragePushConstant8: return "StoragePushConstant8";
+    case CapabilityDenormPreserve: return "DenormPreserve";
+    case CapabilityDenormFlushToZero: return "DenormFlushToZero";
+    case CapabilitySignedZeroInfNanPreserve: return "SignedZeroInfNanPreserve";
+    case CapabilityRoundingModeRTE: return "RoundingModeRTE";
+    case CapabilityRoundingModeRTZ: return "RoundingModeRTZ";
+    case CapabilityRayQueryProvisionalKHR: return "RayQueryProvisionalKHR";
+    case CapabilityRayQueryKHR: return "RayQueryKHR";
+    case CapabilityUntypedPointersKHR: return "UntypedPointersKHR";
+    case CapabilityRayTraversalPrimitiveCullingKHR: return "RayTraversalPrimitiveCullingKHR";
+    case CapabilityRayTracingKHR: return "RayTracingKHR";
+    case CapabilityTextureSampleWeightedQCOM: return "TextureSampleWeightedQCOM";
+    case CapabilityTextureBoxFilterQCOM: return "TextureBoxFilterQCOM";
+    case CapabilityTextureBlockMatchQCOM: return "TextureBlockMatchQCOM";
+    case CapabilityTextureBlockMatch2QCOM: return "TextureBlockMatch2QCOM";
+    case CapabilityFloat16ImageAMD: return "Float16ImageAMD";
+    case CapabilityImageGatherBiasLodAMD: return "ImageGatherBiasLodAMD";
+    case CapabilityFragmentMaskAMD: return "FragmentMaskAMD";
+    case CapabilityStencilExportEXT: return "StencilExportEXT";
+    case CapabilityImageReadWriteLodAMD: return "ImageReadWriteLodAMD";
+    case CapabilityInt64ImageEXT: return "Int64ImageEXT";
+    case CapabilityShaderClockKHR: return "ShaderClockKHR";
+    case CapabilityShaderEnqueueAMDX: return "ShaderEnqueueAMDX";
+    case CapabilityQuadControlKHR: return "QuadControlKHR";
+    case CapabilitySampleMaskOverrideCoverageNV: return "SampleMaskOverrideCoverageNV";
+    case CapabilityGeometryShaderPassthroughNV: return "GeometryShaderPassthroughNV";
+    case CapabilityShaderViewportIndexLayerEXT: return "ShaderViewportIndexLayerEXT";
+    case CapabilityShaderViewportMaskNV: return "ShaderViewportMaskNV";
+    case CapabilityShaderStereoViewNV: return "ShaderStereoViewNV";
+    case CapabilityPerViewAttributesNV: return "PerViewAttributesNV";
+    case CapabilityFragmentFullyCoveredEXT: return "FragmentFullyCoveredEXT";
+    case CapabilityMeshShadingNV: return "MeshShadingNV";
+    case CapabilityImageFootprintNV: return "ImageFootprintNV";
+    case CapabilityMeshShadingEXT: return "MeshShadingEXT";
+    case CapabilityFragmentBarycentricKHR: return "FragmentBarycentricKHR";
+    case CapabilityComputeDerivativeGroupQuadsKHR: return "ComputeDerivativeGroupQuadsKHR";
+    case CapabilityFragmentDensityEXT: return "FragmentDensityEXT";
+    case CapabilityGroupNonUniformPartitionedNV: return "GroupNonUniformPartitionedNV";
+    case CapabilityShaderNonUniform: return "ShaderNonUniform";
+    case CapabilityRuntimeDescriptorArray: return "RuntimeDescriptorArray";
+    case CapabilityInputAttachmentArrayDynamicIndexing: return "InputAttachmentArrayDynamicIndexing";
+    case CapabilityUniformTexelBufferArrayDynamicIndexing: return "UniformTexelBufferArrayDynamicIndexing";
+    case CapabilityStorageTexelBufferArrayDynamicIndexing: return "StorageTexelBufferArrayDynamicIndexing";
+    case CapabilityUniformBufferArrayNonUniformIndexing: return "UniformBufferArrayNonUniformIndexing";
+    case CapabilitySampledImageArrayNonUniformIndexing: return "SampledImageArrayNonUniformIndexing";
+    case CapabilityStorageBufferArrayNonUniformIndexing: return "StorageBufferArrayNonUniformIndexing";
+    case CapabilityStorageImageArrayNonUniformIndexing: return "StorageImageArrayNonUniformIndexing";
+    case CapabilityInputAttachmentArrayNonUniformIndexing: return "InputAttachmentArrayNonUniformIndexing";
+    case CapabilityUniformTexelBufferArrayNonUniformIndexing: return "UniformTexelBufferArrayNonUniformIndexing";
+    case CapabilityStorageTexelBufferArrayNonUniformIndexing: return "StorageTexelBufferArrayNonUniformIndexing";
+    case CapabilityRayTracingPositionFetchKHR: return "RayTracingPositionFetchKHR";
+    case CapabilityRayTracingNV: return "RayTracingNV";
+    case CapabilityRayTracingMotionBlurNV: return "RayTracingMotionBlurNV";
+    case CapabilityVulkanMemoryModel: return "VulkanMemoryModel";
+    case CapabilityVulkanMemoryModelDeviceScope: return "VulkanMemoryModelDeviceScope";
+    case CapabilityPhysicalStorageBufferAddresses: return "PhysicalStorageBufferAddresses";
+    case CapabilityComputeDerivativeGroupLinearKHR: return "ComputeDerivativeGroupLinearKHR";
+    case CapabilityRayTracingProvisionalKHR: return "RayTracingProvisionalKHR";
+    case CapabilityCooperativeMatrixNV: return "CooperativeMatrixNV";
+    case CapabilityFragmentShaderSampleInterlockEXT: return "FragmentShaderSampleInterlockEXT";
+    case CapabilityFragmentShaderShadingRateInterlockEXT: return "FragmentShaderShadingRateInterlockEXT";
+    case CapabilityShaderSMBuiltinsNV: return "ShaderSMBuiltinsNV";
+    case CapabilityFragmentShaderPixelInterlockEXT: return "FragmentShaderPixelInterlockEXT";
+    case CapabilityDemoteToHelperInvocation: return "DemoteToHelperInvocation";
+    case CapabilityDisplacementMicromapNV: return "DisplacementMicromapNV";
+    case CapabilityRayTracingOpacityMicromapEXT: return "RayTracingOpacityMicromapEXT";
+    case CapabilityShaderInvocationReorderNV: return "ShaderInvocationReorderNV";
+    case CapabilityBindlessTextureNV: return "BindlessTextureNV";
+    case CapabilityRayQueryPositionFetchKHR: return "RayQueryPositionFetchKHR";
+    case CapabilityAtomicFloat16VectorNV: return "AtomicFloat16VectorNV";
+    case CapabilityRayTracingDisplacementMicromapNV: return "RayTracingDisplacementMicromapNV";
+    case CapabilityRawAccessChainsNV: return "RawAccessChainsNV";
+    case CapabilityCooperativeMatrixReductionsNV: return "CooperativeMatrixReductionsNV";
+    case CapabilityCooperativeMatrixConversionsNV: return "CooperativeMatrixConversionsNV";
+    case CapabilityCooperativeMatrixPerElementOperationsNV: return "CooperativeMatrixPerElementOperationsNV";
+    case CapabilityCooperativeMatrixTensorAddressingNV: return "CooperativeMatrixTensorAddressingNV";
+    case CapabilityCooperativeMatrixBlockLoadsNV: return "CooperativeMatrixBlockLoadsNV";
+    case CapabilityTensorAddressingNV: return "TensorAddressingNV";
+    case CapabilitySubgroupShuffleINTEL: return "SubgroupShuffleINTEL";
+    case CapabilitySubgroupBufferBlockIOINTEL: return "SubgroupBufferBlockIOINTEL";
+    case CapabilitySubgroupImageBlockIOINTEL: return "SubgroupImageBlockIOINTEL";
+    case CapabilitySubgroupImageMediaBlockIOINTEL: return "SubgroupImageMediaBlockIOINTEL";
+    case CapabilityRoundToInfinityINTEL: return "RoundToInfinityINTEL";
+    case CapabilityFloatingPointModeINTEL: return "FloatingPointModeINTEL";
+    case CapabilityIntegerFunctions2INTEL: return "IntegerFunctions2INTEL";
+    case CapabilityFunctionPointersINTEL: return "FunctionPointersINTEL";
+    case CapabilityIndirectReferencesINTEL: return "IndirectReferencesINTEL";
+    case CapabilityAsmINTEL: return "AsmINTEL";
+    case CapabilityAtomicFloat32MinMaxEXT: return "AtomicFloat32MinMaxEXT";
+    case CapabilityAtomicFloat64MinMaxEXT: return "AtomicFloat64MinMaxEXT";
+    case CapabilityAtomicFloat16MinMaxEXT: return "AtomicFloat16MinMaxEXT";
+    case CapabilityVectorComputeINTEL: return "VectorComputeINTEL";
+    case CapabilityVectorAnyINTEL: return "VectorAnyINTEL";
+    case CapabilityExpectAssumeKHR: return "ExpectAssumeKHR";
+    case CapabilitySubgroupAvcMotionEstimationINTEL: return "SubgroupAvcMotionEstimationINTEL";
+    case CapabilitySubgroupAvcMotionEstimationIntraINTEL: return "SubgroupAvcMotionEstimationIntraINTEL";
+    case CapabilitySubgroupAvcMotionEstimationChromaINTEL: return "SubgroupAvcMotionEstimationChromaINTEL";
+    case CapabilityVariableLengthArrayINTEL: return "VariableLengthArrayINTEL";
+    case CapabilityFunctionFloatControlINTEL: return "FunctionFloatControlINTEL";
+    case CapabilityFPGAMemoryAttributesINTEL: return "FPGAMemoryAttributesINTEL";
+    case CapabilityFPFastMathModeINTEL: return "FPFastMathModeINTEL";
+    case CapabilityArbitraryPrecisionIntegersINTEL: return "ArbitraryPrecisionIntegersINTEL";
+    case CapabilityArbitraryPrecisionFloatingPointINTEL: return "ArbitraryPrecisionFloatingPointINTEL";
+    case CapabilityUnstructuredLoopControlsINTEL: return "UnstructuredLoopControlsINTEL";
+    case CapabilityFPGALoopControlsINTEL: return "FPGALoopControlsINTEL";
+    case CapabilityKernelAttributesINTEL: return "KernelAttributesINTEL";
+    case CapabilityFPGAKernelAttributesINTEL: return "FPGAKernelAttributesINTEL";
+    case CapabilityFPGAMemoryAccessesINTEL: return "FPGAMemoryAccessesINTEL";
+    case CapabilityFPGAClusterAttributesINTEL: return "FPGAClusterAttributesINTEL";
+    case CapabilityLoopFuseINTEL: return "LoopFuseINTEL";
+    case CapabilityFPGADSPControlINTEL: return "FPGADSPControlINTEL";
+    case CapabilityMemoryAccessAliasingINTEL: return "MemoryAccessAliasingINTEL";
+    case CapabilityFPGAInvocationPipeliningAttributesINTEL: return "FPGAInvocationPipeliningAttributesINTEL";
+    case CapabilityFPGABufferLocationINTEL: return "FPGABufferLocationINTEL";
+    case CapabilityArbitraryPrecisionFixedPointINTEL: return "ArbitraryPrecisionFixedPointINTEL";
+    case CapabilityUSMStorageClassesINTEL: return "USMStorageClassesINTEL";
+    case CapabilityRuntimeAlignedAttributeINTEL: return "RuntimeAlignedAttributeINTEL";
+    case CapabilityIOPipesINTEL: return "IOPipesINTEL";
+    case CapabilityBlockingPipesINTEL: return "BlockingPipesINTEL";
+    case CapabilityFPGARegINTEL: return "FPGARegINTEL";
+    case CapabilityDotProductInputAll: return "DotProductInputAll";
+    case CapabilityDotProductInput4x8Bit: return "DotProductInput4x8Bit";
+    case CapabilityDotProductInput4x8BitPacked: return "DotProductInput4x8BitPacked";
+    case CapabilityDotProduct: return "DotProduct";
+    case CapabilityRayCullMaskKHR: return "RayCullMaskKHR";
+    case CapabilityCooperativeMatrixKHR: return "CooperativeMatrixKHR";
+    case CapabilityReplicatedCompositesEXT: return "ReplicatedCompositesEXT";
+    case CapabilityBitInstructions: return "BitInstructions";
+    case CapabilityGroupNonUniformRotateKHR: return "GroupNonUniformRotateKHR";
+    case CapabilityFloatControls2: return "FloatControls2";
+    case CapabilityAtomicFloat32AddEXT: return "AtomicFloat32AddEXT";
+    case CapabilityAtomicFloat64AddEXT: return "AtomicFloat64AddEXT";
+    case CapabilityLongCompositesINTEL: return "LongCompositesINTEL";
+    case CapabilityOptNoneEXT: return "OptNoneEXT";
+    case CapabilityAtomicFloat16AddEXT: return "AtomicFloat16AddEXT";
+    case CapabilityDebugInfoModuleINTEL: return "DebugInfoModuleINTEL";
+    case CapabilityBFloat16ConversionINTEL: return "BFloat16ConversionINTEL";
+    case CapabilitySplitBarrierINTEL: return "SplitBarrierINTEL";
+    case CapabilityArithmeticFenceEXT: return "ArithmeticFenceEXT";
+    case CapabilityFPGAClusterAttributesV2INTEL: return "FPGAClusterAttributesV2INTEL";
+    case CapabilityFPGAKernelAttributesv2INTEL: return "FPGAKernelAttributesv2INTEL";
+    case CapabilityFPMaxErrorINTEL: return "FPMaxErrorINTEL";
+    case CapabilityFPGALatencyControlINTEL: return "FPGALatencyControlINTEL";
+    case CapabilityFPGAArgumentInterfacesINTEL: return "FPGAArgumentInterfacesINTEL";
+    case CapabilityGlobalVariableHostAccessINTEL: return "GlobalVariableHostAccessINTEL";
+    case CapabilityGlobalVariableFPGADecorationsINTEL: return "GlobalVariableFPGADecorationsINTEL";
+    case CapabilitySubgroupBufferPrefetchINTEL: return "SubgroupBufferPrefetchINTEL";
+    case CapabilityGroupUniformArithmeticKHR: return "GroupUniformArithmeticKHR";
+    case CapabilityMaskedGatherScatterINTEL: return "MaskedGatherScatterINTEL";
+    case CapabilityCacheControlsINTEL: return "CacheControlsINTEL";
+    case CapabilityRegisterLimitsINTEL: return "RegisterLimitsINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* RayQueryIntersectionToString(RayQueryIntersection value) {
+    switch (value) {
+    case RayQueryIntersectionRayQueryCandidateIntersectionKHR: return "RayQueryCandidateIntersectionKHR";
+    case RayQueryIntersectionRayQueryCommittedIntersectionKHR: return "RayQueryCommittedIntersectionKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* RayQueryCommittedIntersectionTypeToString(RayQueryCommittedIntersectionType value) {
+    switch (value) {
+    case RayQueryCommittedIntersectionTypeRayQueryCommittedIntersectionNoneKHR: return "RayQueryCommittedIntersectionNoneKHR";
+    case RayQueryCommittedIntersectionTypeRayQueryCommittedIntersectionTriangleKHR: return "RayQueryCommittedIntersectionTriangleKHR";
+    case RayQueryCommittedIntersectionTypeRayQueryCommittedIntersectionGeneratedKHR: return "RayQueryCommittedIntersectionGeneratedKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* RayQueryCandidateIntersectionTypeToString(RayQueryCandidateIntersectionType value) {
+    switch (value) {
+    case RayQueryCandidateIntersectionTypeRayQueryCandidateIntersectionTriangleKHR: return "RayQueryCandidateIntersectionTriangleKHR";
+    case RayQueryCandidateIntersectionTypeRayQueryCandidateIntersectionAABBKHR: return "RayQueryCandidateIntersectionAABBKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FPDenormModeToString(FPDenormMode value) {
+    switch (value) {
+    case FPDenormModePreserve: return "Preserve";
+    case FPDenormModeFlushToZero: return "FlushToZero";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FPOperationModeToString(FPOperationMode value) {
+    switch (value) {
+    case FPOperationModeIEEE: return "IEEE";
+    case FPOperationModeALT: return "ALT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* QuantizationModesToString(QuantizationModes value) {
+    switch (value) {
+    case QuantizationModesTRN: return "TRN";
+    case QuantizationModesTRN_ZERO: return "TRN_ZERO";
+    case QuantizationModesRND: return "RND";
+    case QuantizationModesRND_ZERO: return "RND_ZERO";
+    case QuantizationModesRND_INF: return "RND_INF";
+    case QuantizationModesRND_MIN_INF: return "RND_MIN_INF";
+    case QuantizationModesRND_CONV: return "RND_CONV";
+    case QuantizationModesRND_CONV_ODD: return "RND_CONV_ODD";
+    default: return "Unknown";
+    }
+}
+
+inline const char* OverflowModesToString(OverflowModes value) {
+    switch (value) {
+    case OverflowModesWRAP: return "WRAP";
+    case OverflowModesSAT: return "SAT";
+    case OverflowModesSAT_ZERO: return "SAT_ZERO";
+    case OverflowModesSAT_SYM: return "SAT_SYM";
+    default: return "Unknown";
+    }
+}
+
+inline const char* PackedVectorFormatToString(PackedVectorFormat value) {
+    switch (value) {
+    case PackedVectorFormatPackedVectorFormat4x8Bit: return "PackedVectorFormat4x8Bit";
+    default: return "Unknown";
+    }
+}
+
+inline const char* CooperativeMatrixLayoutToString(CooperativeMatrixLayout value) {
+    switch (value) {
+    case CooperativeMatrixLayoutRowMajorKHR: return "RowMajorKHR";
+    case CooperativeMatrixLayoutColumnMajorKHR: return "ColumnMajorKHR";
+    case CooperativeMatrixLayoutRowBlockedInterleavedARM: return "RowBlockedInterleavedARM";
+    case CooperativeMatrixLayoutColumnBlockedInterleavedARM: return "ColumnBlockedInterleavedARM";
+    default: return "Unknown";
+    }
+}
+
+inline const char* CooperativeMatrixUseToString(CooperativeMatrixUse value) {
+    switch (value) {
+    case CooperativeMatrixUseMatrixAKHR: return "MatrixAKHR";
+    case CooperativeMatrixUseMatrixBKHR: return "MatrixBKHR";
+    case CooperativeMatrixUseMatrixAccumulatorKHR: return "MatrixAccumulatorKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* TensorClampModeToString(TensorClampMode value) {
+    switch (value) {
+    case TensorClampModeUndefined: return "Undefined";
+    case TensorClampModeConstant: return "Constant";
+    case TensorClampModeClampToEdge: return "ClampToEdge";
+    case TensorClampModeRepeat: return "Repeat";
+    case TensorClampModeRepeatMirrored: return "RepeatMirrored";
+    default: return "Unknown";
+    }
+}
+
+inline const char* InitializationModeQualifierToString(InitializationModeQualifier value) {
+    switch (value) {
+    case InitializationModeQualifierInitOnDeviceReprogramINTEL: return "InitOnDeviceReprogramINTEL";
+    case InitializationModeQualifierInitOnDeviceResetINTEL: return "InitOnDeviceResetINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* HostAccessQualifierToString(HostAccessQualifier value) {
+    switch (value) {
+    case HostAccessQualifierNoneINTEL: return "NoneINTEL";
+    case HostAccessQualifierReadINTEL: return "ReadINTEL";
+    case HostAccessQualifierWriteINTEL: return "WriteINTEL";
+    case HostAccessQualifierReadWriteINTEL: return "ReadWriteINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* LoadCacheControlToString(LoadCacheControl value) {
+    switch (value) {
+    case LoadCacheControlUncachedINTEL: return "UncachedINTEL";
+    case LoadCacheControlCachedINTEL: return "CachedINTEL";
+    case LoadCacheControlStreamingINTEL: return "StreamingINTEL";
+    case LoadCacheControlInvalidateAfterReadINTEL: return "InvalidateAfterReadINTEL";
+    case LoadCacheControlConstCachedINTEL: return "ConstCachedINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* StoreCacheControlToString(StoreCacheControl value) {
+    switch (value) {
+    case StoreCacheControlUncachedINTEL: return "UncachedINTEL";
+    case StoreCacheControlWriteThroughINTEL: return "WriteThroughINTEL";
+    case StoreCacheControlWriteBackINTEL: return "WriteBackINTEL";
+    case StoreCacheControlStreamingINTEL: return "StreamingINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* NamedMaximumNumberOfRegistersToString(NamedMaximumNumberOfRegisters value) {
+    switch (value) {
+    case NamedMaximumNumberOfRegistersAutoINTEL: return "AutoINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FPEncodingToString(FPEncoding value) {
+    switch (value) {
+    default: return "Unknown";
+    }
+}
+
+inline const char* OpToString(Op value) {
+    switch (value) {
+    case OpNop: return "OpNop";
+    case OpUndef: return "OpUndef";
+    case OpSourceContinued: return "OpSourceContinued";
+    case OpSource: return "OpSource";
+    case OpSourceExtension: return "OpSourceExtension";
+    case OpName: return "OpName";
+    case OpMemberName: return "OpMemberName";
+    case OpString: return "OpString";
+    case OpLine: return "OpLine";
+    case OpExtension: return "OpExtension";
+    case OpExtInstImport: return "OpExtInstImport";
+    case OpExtInst: return "OpExtInst";
+    case OpMemoryModel: return "OpMemoryModel";
+    case OpEntryPoint: return "OpEntryPoint";
+    case OpExecutionMode: return "OpExecutionMode";
+    case OpCapability: return "OpCapability";
+    case OpTypeVoid: return "OpTypeVoid";
+    case OpTypeBool: return "OpTypeBool";
+    case OpTypeInt: return "OpTypeInt";
+    case OpTypeFloat: return "OpTypeFloat";
+    case OpTypeVector: return "OpTypeVector";
+    case OpTypeMatrix: return "OpTypeMatrix";
+    case OpTypeImage: return "OpTypeImage";
+    case OpTypeSampler: return "OpTypeSampler";
+    case OpTypeSampledImage: return "OpTypeSampledImage";
+    case OpTypeArray: return "OpTypeArray";
+    case OpTypeRuntimeArray: return "OpTypeRuntimeArray";
+    case OpTypeStruct: return "OpTypeStruct";
+    case OpTypeOpaque: return "OpTypeOpaque";
+    case OpTypePointer: return "OpTypePointer";
+    case OpTypeFunction: return "OpTypeFunction";
+    case OpTypeEvent: return "OpTypeEvent";
+    case OpTypeDeviceEvent: return "OpTypeDeviceEvent";
+    case OpTypeReserveId: return "OpTypeReserveId";
+    case OpTypeQueue: return "OpTypeQueue";
+    case OpTypePipe: return "OpTypePipe";
+    case OpTypeForwardPointer: return "OpTypeForwardPointer";
+    case OpConstantTrue: return "OpConstantTrue";
+    case OpConstantFalse: return "OpConstantFalse";
+    case OpConstant: return "OpConstant";
+    case OpConstantComposite: return "OpConstantComposite";
+    case OpConstantSampler: return "OpConstantSampler";
+    case OpConstantNull: return "OpConstantNull";
+    case OpSpecConstantTrue: return "OpSpecConstantTrue";
+    case OpSpecConstantFalse: return "OpSpecConstantFalse";
+    case OpSpecConstant: return "OpSpecConstant";
+    case OpSpecConstantComposite: return "OpSpecConstantComposite";
+    case OpSpecConstantOp: return "OpSpecConstantOp";
+    case OpFunction: return "OpFunction";
+    case OpFunctionParameter: return "OpFunctionParameter";
+    case OpFunctionEnd: return "OpFunctionEnd";
+    case OpFunctionCall: return "OpFunctionCall";
+    case OpVariable: return "OpVariable";
+    case OpImageTexelPointer: return "OpImageTexelPointer";
+    case OpLoad: return "OpLoad";
+    case OpStore: return "OpStore";
+    case OpCopyMemory: return "OpCopyMemory";
+    case OpCopyMemorySized: return "OpCopyMemorySized";
+    case OpAccessChain: return "OpAccessChain";
+    case OpInBoundsAccessChain: return "OpInBoundsAccessChain";
+    case OpPtrAccessChain: return "OpPtrAccessChain";
+    case OpArrayLength: return "OpArrayLength";
+    case OpGenericPtrMemSemantics: return "OpGenericPtrMemSemantics";
+    case OpInBoundsPtrAccessChain: return "OpInBoundsPtrAccessChain";
+    case OpDecorate: return "OpDecorate";
+    case OpMemberDecorate: return "OpMemberDecorate";
+    case OpDecorationGroup: return "OpDecorationGroup";
+    case OpGroupDecorate: return "OpGroupDecorate";
+    case OpGroupMemberDecorate: return "OpGroupMemberDecorate";
+    case OpVectorExtractDynamic: return "OpVectorExtractDynamic";
+    case OpVectorInsertDynamic: return "OpVectorInsertDynamic";
+    case OpVectorShuffle: return "OpVectorShuffle";
+    case OpCompositeConstruct: return "OpCompositeConstruct";
+    case OpCompositeExtract: return "OpCompositeExtract";
+    case OpCompositeInsert: return "OpCompositeInsert";
+    case OpCopyObject: return "OpCopyObject";
+    case OpTranspose: return "OpTranspose";
+    case OpSampledImage: return "OpSampledImage";
+    case OpImageSampleImplicitLod: return "OpImageSampleImplicitLod";
+    case OpImageSampleExplicitLod: return "OpImageSampleExplicitLod";
+    case OpImageSampleDrefImplicitLod: return "OpImageSampleDrefImplicitLod";
+    case OpImageSampleDrefExplicitLod: return "OpImageSampleDrefExplicitLod";
+    case OpImageSampleProjImplicitLod: return "OpImageSampleProjImplicitLod";
+    case OpImageSampleProjExplicitLod: return "OpImageSampleProjExplicitLod";
+    case OpImageSampleProjDrefImplicitLod: return "OpImageSampleProjDrefImplicitLod";
+    case OpImageSampleProjDrefExplicitLod: return "OpImageSampleProjDrefExplicitLod";
+    case OpImageFetch: return "OpImageFetch";
+    case OpImageGather: return "OpImageGather";
+    case OpImageDrefGather: return "OpImageDrefGather";
+    case OpImageRead: return "OpImageRead";
+    case OpImageWrite: return "OpImageWrite";
+    case OpImage: return "OpImage";
+    case OpImageQueryFormat: return "OpImageQueryFormat";
+    case OpImageQueryOrder: return "OpImageQueryOrder";
+    case OpImageQuerySizeLod: return "OpImageQuerySizeLod";
+    case OpImageQuerySize: return "OpImageQuerySize";
+    case OpImageQueryLod: return "OpImageQueryLod";
+    case OpImageQueryLevels: return "OpImageQueryLevels";
+    case OpImageQuerySamples: return "OpImageQuerySamples";
+    case OpConvertFToU: return "OpConvertFToU";
+    case OpConvertFToS: return "OpConvertFToS";
+    case OpConvertSToF: return "OpConvertSToF";
+    case OpConvertUToF: return "OpConvertUToF";
+    case OpUConvert: return "OpUConvert";
+    case OpSConvert: return "OpSConvert";
+    case OpFConvert: return "OpFConvert";
+    case OpQuantizeToF16: return "OpQuantizeToF16";
+    case OpConvertPtrToU: return "OpConvertPtrToU";
+    case OpSatConvertSToU: return "OpSatConvertSToU";
+    case OpSatConvertUToS: return "OpSatConvertUToS";
+    case OpConvertUToPtr: return "OpConvertUToPtr";
+    case OpPtrCastToGeneric: return "OpPtrCastToGeneric";
+    case OpGenericCastToPtr: return "OpGenericCastToPtr";
+    case OpGenericCastToPtrExplicit: return "OpGenericCastToPtrExplicit";
+    case OpBitcast: return "OpBitcast";
+    case OpSNegate: return "OpSNegate";
+    case OpFNegate: return "OpFNegate";
+    case OpIAdd: return "OpIAdd";
+    case OpFAdd: return "OpFAdd";
+    case OpISub: return "OpISub";
+    case OpFSub: return "OpFSub";
+    case OpIMul: return "OpIMul";
+    case OpFMul: return "OpFMul";
+    case OpUDiv: return "OpUDiv";
+    case OpSDiv: return "OpSDiv";
+    case OpFDiv: return "OpFDiv";
+    case OpUMod: return "OpUMod";
+    case OpSRem: return "OpSRem";
+    case OpSMod: return "OpSMod";
+    case OpFRem: return "OpFRem";
+    case OpFMod: return "OpFMod";
+    case OpVectorTimesScalar: return "OpVectorTimesScalar";
+    case OpMatrixTimesScalar: return "OpMatrixTimesScalar";
+    case OpVectorTimesMatrix: return "OpVectorTimesMatrix";
+    case OpMatrixTimesVector: return "OpMatrixTimesVector";
+    case OpMatrixTimesMatrix: return "OpMatrixTimesMatrix";
+    case OpOuterProduct: return "OpOuterProduct";
+    case OpDot: return "OpDot";
+    case OpIAddCarry: return "OpIAddCarry";
+    case OpISubBorrow: return "OpISubBorrow";
+    case OpUMulExtended: return "OpUMulExtended";
+    case OpSMulExtended: return "OpSMulExtended";
+    case OpAny: return "OpAny";
+    case OpAll: return "OpAll";
+    case OpIsNan: return "OpIsNan";
+    case OpIsInf: return "OpIsInf";
+    case OpIsFinite: return "OpIsFinite";
+    case OpIsNormal: return "OpIsNormal";
+    case OpSignBitSet: return "OpSignBitSet";
+    case OpLessOrGreater: return "OpLessOrGreater";
+    case OpOrdered: return "OpOrdered";
+    case OpUnordered: return "OpUnordered";
+    case OpLogicalEqual: return "OpLogicalEqual";
+    case OpLogicalNotEqual: return "OpLogicalNotEqual";
+    case OpLogicalOr: return "OpLogicalOr";
+    case OpLogicalAnd: return "OpLogicalAnd";
+    case OpLogicalNot: return "OpLogicalNot";
+    case OpSelect: return "OpSelect";
+    case OpIEqual: return "OpIEqual";
+    case OpINotEqual: return "OpINotEqual";
+    case OpUGreaterThan: return "OpUGreaterThan";
+    case OpSGreaterThan: return "OpSGreaterThan";
+    case OpUGreaterThanEqual: return "OpUGreaterThanEqual";
+    case OpSGreaterThanEqual: return "OpSGreaterThanEqual";
+    case OpULessThan: return "OpULessThan";
+    case OpSLessThan: return "OpSLessThan";
+    case OpULessThanEqual: return "OpULessThanEqual";
+    case OpSLessThanEqual: return "OpSLessThanEqual";
+    case OpFOrdEqual: return "OpFOrdEqual";
+    case OpFUnordEqual: return "OpFUnordEqual";
+    case OpFOrdNotEqual: return "OpFOrdNotEqual";
+    case OpFUnordNotEqual: return "OpFUnordNotEqual";
+    case OpFOrdLessThan: return "OpFOrdLessThan";
+    case OpFUnordLessThan: return "OpFUnordLessThan";
+    case OpFOrdGreaterThan: return "OpFOrdGreaterThan";
+    case OpFUnordGreaterThan: return "OpFUnordGreaterThan";
+    case OpFOrdLessThanEqual: return "OpFOrdLessThanEqual";
+    case OpFUnordLessThanEqual: return "OpFUnordLessThanEqual";
+    case OpFOrdGreaterThanEqual: return "OpFOrdGreaterThanEqual";
+    case OpFUnordGreaterThanEqual: return "OpFUnordGreaterThanEqual";
+    case OpShiftRightLogical: return "OpShiftRightLogical";
+    case OpShiftRightArithmetic: return "OpShiftRightArithmetic";
+    case OpShiftLeftLogical: return "OpShiftLeftLogical";
+    case OpBitwiseOr: return "OpBitwiseOr";
+    case OpBitwiseXor: return "OpBitwiseXor";
+    case OpBitwiseAnd: return "OpBitwiseAnd";
+    case OpNot: return "OpNot";
+    case OpBitFieldInsert: return "OpBitFieldInsert";
+    case OpBitFieldSExtract: return "OpBitFieldSExtract";
+    case OpBitFieldUExtract: return "OpBitFieldUExtract";
+    case OpBitReverse: return "OpBitReverse";
+    case OpBitCount: return "OpBitCount";
+    case OpDPdx: return "OpDPdx";
+    case OpDPdy: return "OpDPdy";
+    case OpFwidth: return "OpFwidth";
+    case OpDPdxFine: return "OpDPdxFine";
+    case OpDPdyFine: return "OpDPdyFine";
+    case OpFwidthFine: return "OpFwidthFine";
+    case OpDPdxCoarse: return "OpDPdxCoarse";
+    case OpDPdyCoarse: return "OpDPdyCoarse";
+    case OpFwidthCoarse: return "OpFwidthCoarse";
+    case OpEmitVertex: return "OpEmitVertex";
+    case OpEndPrimitive: return "OpEndPrimitive";
+    case OpEmitStreamVertex: return "OpEmitStreamVertex";
+    case OpEndStreamPrimitive: return "OpEndStreamPrimitive";
+    case OpControlBarrier: return "OpControlBarrier";
+    case OpMemoryBarrier: return "OpMemoryBarrier";
+    case OpAtomicLoad: return "OpAtomicLoad";
+    case OpAtomicStore: return "OpAtomicStore";
+    case OpAtomicExchange: return "OpAtomicExchange";
+    case OpAtomicCompareExchange: return "OpAtomicCompareExchange";
+    case OpAtomicCompareExchangeWeak: return "OpAtomicCompareExchangeWeak";
+    case OpAtomicIIncrement: return "OpAtomicIIncrement";
+    case OpAtomicIDecrement: return "OpAtomicIDecrement";
+    case OpAtomicIAdd: return "OpAtomicIAdd";
+    case OpAtomicISub: return "OpAtomicISub";
+    case OpAtomicSMin: return "OpAtomicSMin";
+    case OpAtomicUMin: return "OpAtomicUMin";
+    case OpAtomicSMax: return "OpAtomicSMax";
+    case OpAtomicUMax: return "OpAtomicUMax";
+    case OpAtomicAnd: return "OpAtomicAnd";
+    case OpAtomicOr: return "OpAtomicOr";
+    case OpAtomicXor: return "OpAtomicXor";
+    case OpPhi: return "OpPhi";
+    case OpLoopMerge: return "OpLoopMerge";
+    case OpSelectionMerge: return "OpSelectionMerge";
+    case OpLabel: return "OpLabel";
+    case OpBranch: return "OpBranch";
+    case OpBranchConditional: return "OpBranchConditional";
+    case OpSwitch: return "OpSwitch";
+    case OpKill: return "OpKill";
+    case OpReturn: return "OpReturn";
+    case OpReturnValue: return "OpReturnValue";
+    case OpUnreachable: return "OpUnreachable";
+    case OpLifetimeStart: return "OpLifetimeStart";
+    case OpLifetimeStop: return "OpLifetimeStop";
+    case OpGroupAsyncCopy: return "OpGroupAsyncCopy";
+    case OpGroupWaitEvents: return "OpGroupWaitEvents";
+    case OpGroupAll: return "OpGroupAll";
+    case OpGroupAny: return "OpGroupAny";
+    case OpGroupBroadcast: return "OpGroupBroadcast";
+    case OpGroupIAdd: return "OpGroupIAdd";
+    case OpGroupFAdd: return "OpGroupFAdd";
+    case OpGroupFMin: return "OpGroupFMin";
+    case OpGroupUMin: return "OpGroupUMin";
+    case OpGroupSMin: return "OpGroupSMin";
+    case OpGroupFMax: return "OpGroupFMax";
+    case OpGroupUMax: return "OpGroupUMax";
+    case OpGroupSMax: return "OpGroupSMax";
+    case OpReadPipe: return "OpReadPipe";
+    case OpWritePipe: return "OpWritePipe";
+    case OpReservedReadPipe: return "OpReservedReadPipe";
+    case OpReservedWritePipe: return "OpReservedWritePipe";
+    case OpReserveReadPipePackets: return "OpReserveReadPipePackets";
+    case OpReserveWritePipePackets: return "OpReserveWritePipePackets";
+    case OpCommitReadPipe: return "OpCommitReadPipe";
+    case OpCommitWritePipe: return "OpCommitWritePipe";
+    case OpIsValidReserveId: return "OpIsValidReserveId";
+    case OpGetNumPipePackets: return "OpGetNumPipePackets";
+    case OpGetMaxPipePackets: return "OpGetMaxPipePackets";
+    case OpGroupReserveReadPipePackets: return "OpGroupReserveReadPipePackets";
+    case OpGroupReserveWritePipePackets: return "OpGroupReserveWritePipePackets";
+    case OpGroupCommitReadPipe: return "OpGroupCommitReadPipe";
+    case OpGroupCommitWritePipe: return "OpGroupCommitWritePipe";
+    case OpEnqueueMarker: return "OpEnqueueMarker";
+    case OpEnqueueKernel: return "OpEnqueueKernel";
+    case OpGetKernelNDrangeSubGroupCount: return "OpGetKernelNDrangeSubGroupCount";
+    case OpGetKernelNDrangeMaxSubGroupSize: return "OpGetKernelNDrangeMaxSubGroupSize";
+    case OpGetKernelWorkGroupSize: return "OpGetKernelWorkGroupSize";
+    case OpGetKernelPreferredWorkGroupSizeMultiple: return "OpGetKernelPreferredWorkGroupSizeMultiple";
+    case OpRetainEvent: return "OpRetainEvent";
+    case OpReleaseEvent: return "OpReleaseEvent";
+    case OpCreateUserEvent: return "OpCreateUserEvent";
+    case OpIsValidEvent: return "OpIsValidEvent";
+    case OpSetUserEventStatus: return "OpSetUserEventStatus";
+    case OpCaptureEventProfilingInfo: return "OpCaptureEventProfilingInfo";
+    case OpGetDefaultQueue: return "OpGetDefaultQueue";
+    case OpBuildNDRange: return "OpBuildNDRange";
+    case OpImageSparseSampleImplicitLod: return "OpImageSparseSampleImplicitLod";
+    case OpImageSparseSampleExplicitLod: return "OpImageSparseSampleExplicitLod";
+    case OpImageSparseSampleDrefImplicitLod: return "OpImageSparseSampleDrefImplicitLod";
+    case OpImageSparseSampleDrefExplicitLod: return "OpImageSparseSampleDrefExplicitLod";
+    case OpImageSparseSampleProjImplicitLod: return "OpImageSparseSampleProjImplicitLod";
+    case OpImageSparseSampleProjExplicitLod: return "OpImageSparseSampleProjExplicitLod";
+    case OpImageSparseSampleProjDrefImplicitLod: return "OpImageSparseSampleProjDrefImplicitLod";
+    case OpImageSparseSampleProjDrefExplicitLod: return "OpImageSparseSampleProjDrefExplicitLod";
+    case OpImageSparseFetch: return "OpImageSparseFetch";
+    case OpImageSparseGather: return "OpImageSparseGather";
+    case OpImageSparseDrefGather: return "OpImageSparseDrefGather";
+    case OpImageSparseTexelsResident: return "OpImageSparseTexelsResident";
+    case OpNoLine: return "OpNoLine";
+    case OpAtomicFlagTestAndSet: return "OpAtomicFlagTestAndSet";
+    case OpAtomicFlagClear: return "OpAtomicFlagClear";
+    case OpImageSparseRead: return "OpImageSparseRead";
+    case OpSizeOf: return "OpSizeOf";
+    case OpTypePipeStorage: return "OpTypePipeStorage";
+    case OpConstantPipeStorage: return "OpConstantPipeStorage";
+    case OpCreatePipeFromPipeStorage: return "OpCreatePipeFromPipeStorage";
+    case OpGetKernelLocalSizeForSubgroupCount: return "OpGetKernelLocalSizeForSubgroupCount";
+    case OpGetKernelMaxNumSubgroups: return "OpGetKernelMaxNumSubgroups";
+    case OpTypeNamedBarrier: return "OpTypeNamedBarrier";
+    case OpNamedBarrierInitialize: return "OpNamedBarrierInitialize";
+    case OpMemoryNamedBarrier: return "OpMemoryNamedBarrier";
+    case OpModuleProcessed: return "OpModuleProcessed";
+    case OpExecutionModeId: return "OpExecutionModeId";
+    case OpDecorateId: return "OpDecorateId";
+    case OpGroupNonUniformElect: return "OpGroupNonUniformElect";
+    case OpGroupNonUniformAll: return "OpGroupNonUniformAll";
+    case OpGroupNonUniformAny: return "OpGroupNonUniformAny";
+    case OpGroupNonUniformAllEqual: return "OpGroupNonUniformAllEqual";
+    case OpGroupNonUniformBroadcast: return "OpGroupNonUniformBroadcast";
+    case OpGroupNonUniformBroadcastFirst: return "OpGroupNonUniformBroadcastFirst";
+    case OpGroupNonUniformBallot: return "OpGroupNonUniformBallot";
+    case OpGroupNonUniformInverseBallot: return "OpGroupNonUniformInverseBallot";
+    case OpGroupNonUniformBallotBitExtract: return "OpGroupNonUniformBallotBitExtract";
+    case OpGroupNonUniformBallotBitCount: return "OpGroupNonUniformBallotBitCount";
+    case OpGroupNonUniformBallotFindLSB: return "OpGroupNonUniformBallotFindLSB";
+    case OpGroupNonUniformBallotFindMSB: return "OpGroupNonUniformBallotFindMSB";
+    case OpGroupNonUniformShuffle: return "OpGroupNonUniformShuffle";
+    case OpGroupNonUniformShuffleXor: return "OpGroupNonUniformShuffleXor";
+    case OpGroupNonUniformShuffleUp: return "OpGroupNonUniformShuffleUp";
+    case OpGroupNonUniformShuffleDown: return "OpGroupNonUniformShuffleDown";
+    case OpGroupNonUniformIAdd: return "OpGroupNonUniformIAdd";
+    case OpGroupNonUniformFAdd: return "OpGroupNonUniformFAdd";
+    case OpGroupNonUniformIMul: return "OpGroupNonUniformIMul";
+    case OpGroupNonUniformFMul: return "OpGroupNonUniformFMul";
+    case OpGroupNonUniformSMin: return "OpGroupNonUniformSMin";
+    case OpGroupNonUniformUMin: return "OpGroupNonUniformUMin";
+    case OpGroupNonUniformFMin: return "OpGroupNonUniformFMin";
+    case OpGroupNonUniformSMax: return "OpGroupNonUniformSMax";
+    case OpGroupNonUniformUMax: return "OpGroupNonUniformUMax";
+    case OpGroupNonUniformFMax: return "OpGroupNonUniformFMax";
+    case OpGroupNonUniformBitwiseAnd: return "OpGroupNonUniformBitwiseAnd";
+    case OpGroupNonUniformBitwiseOr: return "OpGroupNonUniformBitwiseOr";
+    case OpGroupNonUniformBitwiseXor: return "OpGroupNonUniformBitwiseXor";
+    case OpGroupNonUniformLogicalAnd: return "OpGroupNonUniformLogicalAnd";
+    case OpGroupNonUniformLogicalOr: return "OpGroupNonUniformLogicalOr";
+    case OpGroupNonUniformLogicalXor: return "OpGroupNonUniformLogicalXor";
+    case OpGroupNonUniformQuadBroadcast: return "OpGroupNonUniformQuadBroadcast";
+    case OpGroupNonUniformQuadSwap: return "OpGroupNonUniformQuadSwap";
+    case OpCopyLogical: return "OpCopyLogical";
+    case OpPtrEqual: return "OpPtrEqual";
+    case OpPtrNotEqual: return "OpPtrNotEqual";
+    case OpPtrDiff: return "OpPtrDiff";
+    case OpColorAttachmentReadEXT: return "OpColorAttachmentReadEXT";
+    case OpDepthAttachmentReadEXT: return "OpDepthAttachmentReadEXT";
+    case OpStencilAttachmentReadEXT: return "OpStencilAttachmentReadEXT";
+    case OpTerminateInvocation: return "OpTerminateInvocation";
+    case OpTypeUntypedPointerKHR: return "OpTypeUntypedPointerKHR";
+    case OpUntypedVariableKHR: return "OpUntypedVariableKHR";
+    case OpUntypedAccessChainKHR: return "OpUntypedAccessChainKHR";
+    case OpUntypedInBoundsAccessChainKHR: return "OpUntypedInBoundsAccessChainKHR";
+    case OpSubgroupBallotKHR: return "OpSubgroupBallotKHR";
+    case OpSubgroupFirstInvocationKHR: return "OpSubgroupFirstInvocationKHR";
+    case OpUntypedPtrAccessChainKHR: return "OpUntypedPtrAccessChainKHR";
+    case OpUntypedInBoundsPtrAccessChainKHR: return "OpUntypedInBoundsPtrAccessChainKHR";
+    case OpUntypedArrayLengthKHR: return "OpUntypedArrayLengthKHR";
+    case OpUntypedPrefetchKHR: return "OpUntypedPrefetchKHR";
+    case OpSubgroupAllKHR: return "OpSubgroupAllKHR";
+    case OpSubgroupAnyKHR: return "OpSubgroupAnyKHR";
+    case OpSubgroupAllEqualKHR: return "OpSubgroupAllEqualKHR";
+    case OpGroupNonUniformRotateKHR: return "OpGroupNonUniformRotateKHR";
+    case OpSubgroupReadInvocationKHR: return "OpSubgroupReadInvocationKHR";
+    case OpExtInstWithForwardRefsKHR: return "OpExtInstWithForwardRefsKHR";
+    case OpTraceRayKHR: return "OpTraceRayKHR";
+    case OpExecuteCallableKHR: return "OpExecuteCallableKHR";
+    case OpConvertUToAccelerationStructureKHR: return "OpConvertUToAccelerationStructureKHR";
+    case OpIgnoreIntersectionKHR: return "OpIgnoreIntersectionKHR";
+    case OpTerminateRayKHR: return "OpTerminateRayKHR";
+    case OpSDot: return "OpSDot";
+    case OpUDot: return "OpUDot";
+    case OpSUDot: return "OpSUDot";
+    case OpSDotAccSat: return "OpSDotAccSat";
+    case OpUDotAccSat: return "OpUDotAccSat";
+    case OpSUDotAccSat: return "OpSUDotAccSat";
+    case OpTypeCooperativeMatrixKHR: return "OpTypeCooperativeMatrixKHR";
+    case OpCooperativeMatrixLoadKHR: return "OpCooperativeMatrixLoadKHR";
+    case OpCooperativeMatrixStoreKHR: return "OpCooperativeMatrixStoreKHR";
+    case OpCooperativeMatrixMulAddKHR: return "OpCooperativeMatrixMulAddKHR";
+    case OpCooperativeMatrixLengthKHR: return "OpCooperativeMatrixLengthKHR";
+    case OpConstantCompositeReplicateEXT: return "OpConstantCompositeReplicateEXT";
+    case OpSpecConstantCompositeReplicateEXT: return "OpSpecConstantCompositeReplicateEXT";
+    case OpCompositeConstructReplicateEXT: return "OpCompositeConstructReplicateEXT";
+    case OpTypeRayQueryKHR: return "OpTypeRayQueryKHR";
+    case OpRayQueryInitializeKHR: return "OpRayQueryInitializeKHR";
+    case OpRayQueryTerminateKHR: return "OpRayQueryTerminateKHR";
+    case OpRayQueryGenerateIntersectionKHR: return "OpRayQueryGenerateIntersectionKHR";
+    case OpRayQueryConfirmIntersectionKHR: return "OpRayQueryConfirmIntersectionKHR";
+    case OpRayQueryProceedKHR: return "OpRayQueryProceedKHR";
+    case OpRayQueryGetIntersectionTypeKHR: return "OpRayQueryGetIntersectionTypeKHR";
+    case OpImageSampleWeightedQCOM: return "OpImageSampleWeightedQCOM";
+    case OpImageBoxFilterQCOM: return "OpImageBoxFilterQCOM";
+    case OpImageBlockMatchSSDQCOM: return "OpImageBlockMatchSSDQCOM";
+    case OpImageBlockMatchSADQCOM: return "OpImageBlockMatchSADQCOM";
+    case OpImageBlockMatchWindowSSDQCOM: return "OpImageBlockMatchWindowSSDQCOM";
+    case OpImageBlockMatchWindowSADQCOM: return "OpImageBlockMatchWindowSADQCOM";
+    case OpImageBlockMatchGatherSSDQCOM: return "OpImageBlockMatchGatherSSDQCOM";
+    case OpImageBlockMatchGatherSADQCOM: return "OpImageBlockMatchGatherSADQCOM";
+    case OpGroupIAddNonUniformAMD: return "OpGroupIAddNonUniformAMD";
+    case OpGroupFAddNonUniformAMD: return "OpGroupFAddNonUniformAMD";
+    case OpGroupFMinNonUniformAMD: return "OpGroupFMinNonUniformAMD";
+    case OpGroupUMinNonUniformAMD: return "OpGroupUMinNonUniformAMD";
+    case OpGroupSMinNonUniformAMD: return "OpGroupSMinNonUniformAMD";
+    case OpGroupFMaxNonUniformAMD: return "OpGroupFMaxNonUniformAMD";
+    case OpGroupUMaxNonUniformAMD: return "OpGroupUMaxNonUniformAMD";
+    case OpGroupSMaxNonUniformAMD: return "OpGroupSMaxNonUniformAMD";
+    case OpFragmentMaskFetchAMD: return "OpFragmentMaskFetchAMD";
+    case OpFragmentFetchAMD: return "OpFragmentFetchAMD";
+    case OpReadClockKHR: return "OpReadClockKHR";
+    case OpAllocateNodePayloadsAMDX: return "OpAllocateNodePayloadsAMDX";
+    case OpEnqueueNodePayloadsAMDX: return "OpEnqueueNodePayloadsAMDX";
+    case OpTypeNodePayloadArrayAMDX: return "OpTypeNodePayloadArrayAMDX";
+    case OpFinishWritingNodePayloadAMDX: return "OpFinishWritingNodePayloadAMDX";
+    case OpNodePayloadArrayLengthAMDX: return "OpNodePayloadArrayLengthAMDX";
+    case OpIsNodePayloadValidAMDX: return "OpIsNodePayloadValidAMDX";
+    case OpConstantStringAMDX: return "OpConstantStringAMDX";
+    case OpSpecConstantStringAMDX: return "OpSpecConstantStringAMDX";
+    case OpGroupNonUniformQuadAllKHR: return "OpGroupNonUniformQuadAllKHR";
+    case OpGroupNonUniformQuadAnyKHR: return "OpGroupNonUniformQuadAnyKHR";
+    case OpHitObjectRecordHitMotionNV: return "OpHitObjectRecordHitMotionNV";
+    case OpHitObjectRecordHitWithIndexMotionNV: return "OpHitObjectRecordHitWithIndexMotionNV";
+    case OpHitObjectRecordMissMotionNV: return "OpHitObjectRecordMissMotionNV";
+    case OpHitObjectGetWorldToObjectNV: return "OpHitObjectGetWorldToObjectNV";
+    case OpHitObjectGetObjectToWorldNV: return "OpHitObjectGetObjectToWorldNV";
+    case OpHitObjectGetObjectRayDirectionNV: return "OpHitObjectGetObjectRayDirectionNV";
+    case OpHitObjectGetObjectRayOriginNV: return "OpHitObjectGetObjectRayOriginNV";
+    case OpHitObjectTraceRayMotionNV: return "OpHitObjectTraceRayMotionNV";
+    case OpHitObjectGetShaderRecordBufferHandleNV: return "OpHitObjectGetShaderRecordBufferHandleNV";
+    case OpHitObjectGetShaderBindingTableRecordIndexNV: return "OpHitObjectGetShaderBindingTableRecordIndexNV";
+    case OpHitObjectRecordEmptyNV: return "OpHitObjectRecordEmptyNV";
+    case OpHitObjectTraceRayNV: return "OpHitObjectTraceRayNV";
+    case OpHitObjectRecordHitNV: return "OpHitObjectRecordHitNV";
+    case OpHitObjectRecordHitWithIndexNV: return "OpHitObjectRecordHitWithIndexNV";
+    case OpHitObjectRecordMissNV: return "OpHitObjectRecordMissNV";
+    case OpHitObjectExecuteShaderNV: return "OpHitObjectExecuteShaderNV";
+    case OpHitObjectGetCurrentTimeNV: return "OpHitObjectGetCurrentTimeNV";
+    case OpHitObjectGetAttributesNV: return "OpHitObjectGetAttributesNV";
+    case OpHitObjectGetHitKindNV: return "OpHitObjectGetHitKindNV";
+    case OpHitObjectGetPrimitiveIndexNV: return "OpHitObjectGetPrimitiveIndexNV";
+    case OpHitObjectGetGeometryIndexNV: return "OpHitObjectGetGeometryIndexNV";
+    case OpHitObjectGetInstanceIdNV: return "OpHitObjectGetInstanceIdNV";
+    case OpHitObjectGetInstanceCustomIndexNV: return "OpHitObjectGetInstanceCustomIndexNV";
+    case OpHitObjectGetWorldRayDirectionNV: return "OpHitObjectGetWorldRayDirectionNV";
+    case OpHitObjectGetWorldRayOriginNV: return "OpHitObjectGetWorldRayOriginNV";
+    case OpHitObjectGetRayTMaxNV: return "OpHitObjectGetRayTMaxNV";
+    case OpHitObjectGetRayTMinNV: return "OpHitObjectGetRayTMinNV";
+    case OpHitObjectIsEmptyNV: return "OpHitObjectIsEmptyNV";
+    case OpHitObjectIsHitNV: return "OpHitObjectIsHitNV";
+    case OpHitObjectIsMissNV: return "OpHitObjectIsMissNV";
+    case OpReorderThreadWithHitObjectNV: return "OpReorderThreadWithHitObjectNV";
+    case OpReorderThreadWithHintNV: return "OpReorderThreadWithHintNV";
+    case OpTypeHitObjectNV: return "OpTypeHitObjectNV";
+    case OpImageSampleFootprintNV: return "OpImageSampleFootprintNV";
+    case OpCooperativeMatrixConvertNV: return "OpCooperativeMatrixConvertNV";
+    case OpEmitMeshTasksEXT: return "OpEmitMeshTasksEXT";
+    case OpSetMeshOutputsEXT: return "OpSetMeshOutputsEXT";
+    case OpGroupNonUniformPartitionNV: return "OpGroupNonUniformPartitionNV";
+    case OpWritePackedPrimitiveIndices4x8NV: return "OpWritePackedPrimitiveIndices4x8NV";
+    case OpFetchMicroTriangleVertexPositionNV: return "OpFetchMicroTriangleVertexPositionNV";
+    case OpFetchMicroTriangleVertexBarycentricNV: return "OpFetchMicroTriangleVertexBarycentricNV";
+    case OpReportIntersectionKHR: return "OpReportIntersectionKHR";
+    case OpIgnoreIntersectionNV: return "OpIgnoreIntersectionNV";
+    case OpTerminateRayNV: return "OpTerminateRayNV";
+    case OpTraceNV: return "OpTraceNV";
+    case OpTraceMotionNV: return "OpTraceMotionNV";
+    case OpTraceRayMotionNV: return "OpTraceRayMotionNV";
+    case OpRayQueryGetIntersectionTriangleVertexPositionsKHR: return "OpRayQueryGetIntersectionTriangleVertexPositionsKHR";
+    case OpTypeAccelerationStructureKHR: return "OpTypeAccelerationStructureKHR";
+    case OpExecuteCallableNV: return "OpExecuteCallableNV";
+    case OpTypeCooperativeMatrixNV: return "OpTypeCooperativeMatrixNV";
+    case OpCooperativeMatrixLoadNV: return "OpCooperativeMatrixLoadNV";
+    case OpCooperativeMatrixStoreNV: return "OpCooperativeMatrixStoreNV";
+    case OpCooperativeMatrixMulAddNV: return "OpCooperativeMatrixMulAddNV";
+    case OpCooperativeMatrixLengthNV: return "OpCooperativeMatrixLengthNV";
+    case OpBeginInvocationInterlockEXT: return "OpBeginInvocationInterlockEXT";
+    case OpEndInvocationInterlockEXT: return "OpEndInvocationInterlockEXT";
+    case OpCooperativeMatrixReduceNV: return "OpCooperativeMatrixReduceNV";
+    case OpCooperativeMatrixLoadTensorNV: return "OpCooperativeMatrixLoadTensorNV";
+    case OpCooperativeMatrixStoreTensorNV: return "OpCooperativeMatrixStoreTensorNV";
+    case OpCooperativeMatrixPerElementOpNV: return "OpCooperativeMatrixPerElementOpNV";
+    case OpTypeTensorLayoutNV: return "OpTypeTensorLayoutNV";
+    case OpTypeTensorViewNV: return "OpTypeTensorViewNV";
+    case OpCreateTensorLayoutNV: return "OpCreateTensorLayoutNV";
+    case OpTensorLayoutSetDimensionNV: return "OpTensorLayoutSetDimensionNV";
+    case OpTensorLayoutSetStrideNV: return "OpTensorLayoutSetStrideNV";
+    case OpTensorLayoutSliceNV: return "OpTensorLayoutSliceNV";
+    case OpTensorLayoutSetClampValueNV: return "OpTensorLayoutSetClampValueNV";
+    case OpCreateTensorViewNV: return "OpCreateTensorViewNV";
+    case OpTensorViewSetDimensionNV: return "OpTensorViewSetDimensionNV";
+    case OpTensorViewSetStrideNV: return "OpTensorViewSetStrideNV";
+    case OpDemoteToHelperInvocation: return "OpDemoteToHelperInvocation";
+    case OpIsHelperInvocationEXT: return "OpIsHelperInvocationEXT";
+    case OpTensorViewSetClipNV: return "OpTensorViewSetClipNV";
+    case OpTensorLayoutSetBlockSizeNV: return "OpTensorLayoutSetBlockSizeNV";
+    case OpCooperativeMatrixTransposeNV: return "OpCooperativeMatrixTransposeNV";
+    case OpConvertUToImageNV: return "OpConvertUToImageNV";
+    case OpConvertUToSamplerNV: return "OpConvertUToSamplerNV";
+    case OpConvertImageToUNV: return "OpConvertImageToUNV";
+    case OpConvertSamplerToUNV: return "OpConvertSamplerToUNV";
+    case OpConvertUToSampledImageNV: return "OpConvertUToSampledImageNV";
+    case OpConvertSampledImageToUNV: return "OpConvertSampledImageToUNV";
+    case OpSamplerImageAddressingModeNV: return "OpSamplerImageAddressingModeNV";
+    case OpRawAccessChainNV: return "OpRawAccessChainNV";
+    case OpSubgroupShuffleINTEL: return "OpSubgroupShuffleINTEL";
+    case OpSubgroupShuffleDownINTEL: return "OpSubgroupShuffleDownINTEL";
+    case OpSubgroupShuffleUpINTEL: return "OpSubgroupShuffleUpINTEL";
+    case OpSubgroupShuffleXorINTEL: return "OpSubgroupShuffleXorINTEL";
+    case OpSubgroupBlockReadINTEL: return "OpSubgroupBlockReadINTEL";
+    case OpSubgroupBlockWriteINTEL: return "OpSubgroupBlockWriteINTEL";
+    case OpSubgroupImageBlockReadINTEL: return "OpSubgroupImageBlockReadINTEL";
+    case OpSubgroupImageBlockWriteINTEL: return "OpSubgroupImageBlockWriteINTEL";
+    case OpSubgroupImageMediaBlockReadINTEL: return "OpSubgroupImageMediaBlockReadINTEL";
+    case OpSubgroupImageMediaBlockWriteINTEL: return "OpSubgroupImageMediaBlockWriteINTEL";
+    case OpUCountLeadingZerosINTEL: return "OpUCountLeadingZerosINTEL";
+    case OpUCountTrailingZerosINTEL: return "OpUCountTrailingZerosINTEL";
+    case OpAbsISubINTEL: return "OpAbsISubINTEL";
+    case OpAbsUSubINTEL: return "OpAbsUSubINTEL";
+    case OpIAddSatINTEL: return "OpIAddSatINTEL";
+    case OpUAddSatINTEL: return "OpUAddSatINTEL";
+    case OpIAverageINTEL: return "OpIAverageINTEL";
+    case OpUAverageINTEL: return "OpUAverageINTEL";
+    case OpIAverageRoundedINTEL: return "OpIAverageRoundedINTEL";
+    case OpUAverageRoundedINTEL: return "OpUAverageRoundedINTEL";
+    case OpISubSatINTEL: return "OpISubSatINTEL";
+    case OpUSubSatINTEL: return "OpUSubSatINTEL";
+    case OpIMul32x16INTEL: return "OpIMul32x16INTEL";
+    case OpUMul32x16INTEL: return "OpUMul32x16INTEL";
+    case OpConstantFunctionPointerINTEL: return "OpConstantFunctionPointerINTEL";
+    case OpFunctionPointerCallINTEL: return "OpFunctionPointerCallINTEL";
+    case OpAsmTargetINTEL: return "OpAsmTargetINTEL";
+    case OpAsmINTEL: return "OpAsmINTEL";
+    case OpAsmCallINTEL: return "OpAsmCallINTEL";
+    case OpAtomicFMinEXT: return "OpAtomicFMinEXT";
+    case OpAtomicFMaxEXT: return "OpAtomicFMaxEXT";
+    case OpAssumeTrueKHR: return "OpAssumeTrueKHR";
+    case OpExpectKHR: return "OpExpectKHR";
+    case OpDecorateString: return "OpDecorateString";
+    case OpMemberDecorateString: return "OpMemberDecorateString";
+    case OpVmeImageINTEL: return "OpVmeImageINTEL";
+    case OpTypeVmeImageINTEL: return "OpTypeVmeImageINTEL";
+    case OpTypeAvcImePayloadINTEL: return "OpTypeAvcImePayloadINTEL";
+    case OpTypeAvcRefPayloadINTEL: return "OpTypeAvcRefPayloadINTEL";
+    case OpTypeAvcSicPayloadINTEL: return "OpTypeAvcSicPayloadINTEL";
+    case OpTypeAvcMcePayloadINTEL: return "OpTypeAvcMcePayloadINTEL";
+    case OpTypeAvcMceResultINTEL: return "OpTypeAvcMceResultINTEL";
+    case OpTypeAvcImeResultINTEL: return "OpTypeAvcImeResultINTEL";
+    case OpTypeAvcImeResultSingleReferenceStreamoutINTEL: return "OpTypeAvcImeResultSingleReferenceStreamoutINTEL";
+    case OpTypeAvcImeResultDualReferenceStreamoutINTEL: return "OpTypeAvcImeResultDualReferenceStreamoutINTEL";
+    case OpTypeAvcImeSingleReferenceStreaminINTEL: return "OpTypeAvcImeSingleReferenceStreaminINTEL";
+    case OpTypeAvcImeDualReferenceStreaminINTEL: return "OpTypeAvcImeDualReferenceStreaminINTEL";
+    case OpTypeAvcRefResultINTEL: return "OpTypeAvcRefResultINTEL";
+    case OpTypeAvcSicResultINTEL: return "OpTypeAvcSicResultINTEL";
+    case OpSubgroupAvcMceGetDefaultInterBaseMultiReferencePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterBaseMultiReferencePenaltyINTEL";
+    case OpSubgroupAvcMceSetInterBaseMultiReferencePenaltyINTEL: return "OpSubgroupAvcMceSetInterBaseMultiReferencePenaltyINTEL";
+    case OpSubgroupAvcMceGetDefaultInterShapePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterShapePenaltyINTEL";
+    case OpSubgroupAvcMceSetInterShapePenaltyINTEL: return "OpSubgroupAvcMceSetInterShapePenaltyINTEL";
+    case OpSubgroupAvcMceGetDefaultInterDirectionPenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterDirectionPenaltyINTEL";
+    case OpSubgroupAvcMceSetInterDirectionPenaltyINTEL: return "OpSubgroupAvcMceSetInterDirectionPenaltyINTEL";
+    case OpSubgroupAvcMceGetDefaultIntraLumaShapePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraLumaShapePenaltyINTEL";
+    case OpSubgroupAvcMceGetDefaultInterMotionVectorCostTableINTEL: return "OpSubgroupAvcMceGetDefaultInterMotionVectorCostTableINTEL";
+    case OpSubgroupAvcMceGetDefaultHighPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultHighPenaltyCostTableINTEL";
+    case OpSubgroupAvcMceGetDefaultMediumPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultMediumPenaltyCostTableINTEL";
+    case OpSubgroupAvcMceGetDefaultLowPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultLowPenaltyCostTableINTEL";
+    case OpSubgroupAvcMceSetMotionVectorCostFunctionINTEL: return "OpSubgroupAvcMceSetMotionVectorCostFunctionINTEL";
+    case OpSubgroupAvcMceGetDefaultIntraLumaModePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraLumaModePenaltyINTEL";
+    case OpSubgroupAvcMceGetDefaultNonDcLumaIntraPenaltyINTEL: return "OpSubgroupAvcMceGetDefaultNonDcLumaIntraPenaltyINTEL";
+    case OpSubgroupAvcMceGetDefaultIntraChromaModeBasePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraChromaModeBasePenaltyINTEL";
+    case OpSubgroupAvcMceSetAcOnlyHaarINTEL: return "OpSubgroupAvcMceSetAcOnlyHaarINTEL";
+    case OpSubgroupAvcMceSetSourceInterlacedFieldPolarityINTEL: return "OpSubgroupAvcMceSetSourceInterlacedFieldPolarityINTEL";
+    case OpSubgroupAvcMceSetSingleReferenceInterlacedFieldPolarityINTEL: return "OpSubgroupAvcMceSetSingleReferenceInterlacedFieldPolarityINTEL";
+    case OpSubgroupAvcMceSetDualReferenceInterlacedFieldPolaritiesINTEL: return "OpSubgroupAvcMceSetDualReferenceInterlacedFieldPolaritiesINTEL";
+    case OpSubgroupAvcMceConvertToImePayloadINTEL: return "OpSubgroupAvcMceConvertToImePayloadINTEL";
+    case OpSubgroupAvcMceConvertToImeResultINTEL: return "OpSubgroupAvcMceConvertToImeResultINTEL";
+    case OpSubgroupAvcMceConvertToRefPayloadINTEL: return "OpSubgroupAvcMceConvertToRefPayloadINTEL";
+    case OpSubgroupAvcMceConvertToRefResultINTEL: return "OpSubgroupAvcMceConvertToRefResultINTEL";
+    case OpSubgroupAvcMceConvertToSicPayloadINTEL: return "OpSubgroupAvcMceConvertToSicPayloadINTEL";
+    case OpSubgroupAvcMceConvertToSicResultINTEL: return "OpSubgroupAvcMceConvertToSicResultINTEL";
+    case OpSubgroupAvcMceGetMotionVectorsINTEL: return "OpSubgroupAvcMceGetMotionVectorsINTEL";
+    case OpSubgroupAvcMceGetInterDistortionsINTEL: return "OpSubgroupAvcMceGetInterDistortionsINTEL";
+    case OpSubgroupAvcMceGetBestInterDistortionsINTEL: return "OpSubgroupAvcMceGetBestInterDistortionsINTEL";
+    case OpSubgroupAvcMceGetInterMajorShapeINTEL: return "OpSubgroupAvcMceGetInterMajorShapeINTEL";
+    case OpSubgroupAvcMceGetInterMinorShapeINTEL: return "OpSubgroupAvcMceGetInterMinorShapeINTEL";
+    case OpSubgroupAvcMceGetInterDirectionsINTEL: return "OpSubgroupAvcMceGetInterDirectionsINTEL";
+    case OpSubgroupAvcMceGetInterMotionVectorCountINTEL: return "OpSubgroupAvcMceGetInterMotionVectorCountINTEL";
+    case OpSubgroupAvcMceGetInterReferenceIdsINTEL: return "OpSubgroupAvcMceGetInterReferenceIdsINTEL";
+    case OpSubgroupAvcMceGetInterReferenceInterlacedFieldPolaritiesINTEL: return "OpSubgroupAvcMceGetInterReferenceInterlacedFieldPolaritiesINTEL";
+    case OpSubgroupAvcImeInitializeINTEL: return "OpSubgroupAvcImeInitializeINTEL";
+    case OpSubgroupAvcImeSetSingleReferenceINTEL: return "OpSubgroupAvcImeSetSingleReferenceINTEL";
+    case OpSubgroupAvcImeSetDualReferenceINTEL: return "OpSubgroupAvcImeSetDualReferenceINTEL";
+    case OpSubgroupAvcImeRefWindowSizeINTEL: return "OpSubgroupAvcImeRefWindowSizeINTEL";
+    case OpSubgroupAvcImeAdjustRefOffsetINTEL: return "OpSubgroupAvcImeAdjustRefOffsetINTEL";
+    case OpSubgroupAvcImeConvertToMcePayloadINTEL: return "OpSubgroupAvcImeConvertToMcePayloadINTEL";
+    case OpSubgroupAvcImeSetMaxMotionVectorCountINTEL: return "OpSubgroupAvcImeSetMaxMotionVectorCountINTEL";
+    case OpSubgroupAvcImeSetUnidirectionalMixDisableINTEL: return "OpSubgroupAvcImeSetUnidirectionalMixDisableINTEL";
+    case OpSubgroupAvcImeSetEarlySearchTerminationThresholdINTEL: return "OpSubgroupAvcImeSetEarlySearchTerminationThresholdINTEL";
+    case OpSubgroupAvcImeSetWeightedSadINTEL: return "OpSubgroupAvcImeSetWeightedSadINTEL";
+    case OpSubgroupAvcImeEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceINTEL";
+    case OpSubgroupAvcImeEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceINTEL";
+    case OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminINTEL";
+    case OpSubgroupAvcImeEvaluateWithDualReferenceStreaminINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreaminINTEL";
+    case OpSubgroupAvcImeEvaluateWithSingleReferenceStreamoutINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreamoutINTEL";
+    case OpSubgroupAvcImeEvaluateWithDualReferenceStreamoutINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreamoutINTEL";
+    case OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminoutINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminoutINTEL";
+    case OpSubgroupAvcImeEvaluateWithDualReferenceStreaminoutINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreaminoutINTEL";
+    case OpSubgroupAvcImeConvertToMceResultINTEL: return "OpSubgroupAvcImeConvertToMceResultINTEL";
+    case OpSubgroupAvcImeGetSingleReferenceStreaminINTEL: return "OpSubgroupAvcImeGetSingleReferenceStreaminINTEL";
+    case OpSubgroupAvcImeGetDualReferenceStreaminINTEL: return "OpSubgroupAvcImeGetDualReferenceStreaminINTEL";
+    case OpSubgroupAvcImeStripSingleReferenceStreamoutINTEL: return "OpSubgroupAvcImeStripSingleReferenceStreamoutINTEL";
+    case OpSubgroupAvcImeStripDualReferenceStreamoutINTEL: return "OpSubgroupAvcImeStripDualReferenceStreamoutINTEL";
+    case OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeMotionVectorsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeMotionVectorsINTEL";
+    case OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeDistortionsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeDistortionsINTEL";
+    case OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeReferenceIdsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeReferenceIdsINTEL";
+    case OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeMotionVectorsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeMotionVectorsINTEL";
+    case OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeDistortionsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeDistortionsINTEL";
+    case OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeReferenceIdsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeReferenceIdsINTEL";
+    case OpSubgroupAvcImeGetBorderReachedINTEL: return "OpSubgroupAvcImeGetBorderReachedINTEL";
+    case OpSubgroupAvcImeGetTruncatedSearchIndicationINTEL: return "OpSubgroupAvcImeGetTruncatedSearchIndicationINTEL";
+    case OpSubgroupAvcImeGetUnidirectionalEarlySearchTerminationINTEL: return "OpSubgroupAvcImeGetUnidirectionalEarlySearchTerminationINTEL";
+    case OpSubgroupAvcImeGetWeightingPatternMinimumMotionVectorINTEL: return "OpSubgroupAvcImeGetWeightingPatternMinimumMotionVectorINTEL";
+    case OpSubgroupAvcImeGetWeightingPatternMinimumDistortionINTEL: return "OpSubgroupAvcImeGetWeightingPatternMinimumDistortionINTEL";
+    case OpSubgroupAvcFmeInitializeINTEL: return "OpSubgroupAvcFmeInitializeINTEL";
+    case OpSubgroupAvcBmeInitializeINTEL: return "OpSubgroupAvcBmeInitializeINTEL";
+    case OpSubgroupAvcRefConvertToMcePayloadINTEL: return "OpSubgroupAvcRefConvertToMcePayloadINTEL";
+    case OpSubgroupAvcRefSetBidirectionalMixDisableINTEL: return "OpSubgroupAvcRefSetBidirectionalMixDisableINTEL";
+    case OpSubgroupAvcRefSetBilinearFilterEnableINTEL: return "OpSubgroupAvcRefSetBilinearFilterEnableINTEL";
+    case OpSubgroupAvcRefEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithSingleReferenceINTEL";
+    case OpSubgroupAvcRefEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithDualReferenceINTEL";
+    case OpSubgroupAvcRefEvaluateWithMultiReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithMultiReferenceINTEL";
+    case OpSubgroupAvcRefEvaluateWithMultiReferenceInterlacedINTEL: return "OpSubgroupAvcRefEvaluateWithMultiReferenceInterlacedINTEL";
+    case OpSubgroupAvcRefConvertToMceResultINTEL: return "OpSubgroupAvcRefConvertToMceResultINTEL";
+    case OpSubgroupAvcSicInitializeINTEL: return "OpSubgroupAvcSicInitializeINTEL";
+    case OpSubgroupAvcSicConfigureSkcINTEL: return "OpSubgroupAvcSicConfigureSkcINTEL";
+    case OpSubgroupAvcSicConfigureIpeLumaINTEL: return "OpSubgroupAvcSicConfigureIpeLumaINTEL";
+    case OpSubgroupAvcSicConfigureIpeLumaChromaINTEL: return "OpSubgroupAvcSicConfigureIpeLumaChromaINTEL";
+    case OpSubgroupAvcSicGetMotionVectorMaskINTEL: return "OpSubgroupAvcSicGetMotionVectorMaskINTEL";
+    case OpSubgroupAvcSicConvertToMcePayloadINTEL: return "OpSubgroupAvcSicConvertToMcePayloadINTEL";
+    case OpSubgroupAvcSicSetIntraLumaShapePenaltyINTEL: return "OpSubgroupAvcSicSetIntraLumaShapePenaltyINTEL";
+    case OpSubgroupAvcSicSetIntraLumaModeCostFunctionINTEL: return "OpSubgroupAvcSicSetIntraLumaModeCostFunctionINTEL";
+    case OpSubgroupAvcSicSetIntraChromaModeCostFunctionINTEL: return "OpSubgroupAvcSicSetIntraChromaModeCostFunctionINTEL";
+    case OpSubgroupAvcSicSetBilinearFilterEnableINTEL: return "OpSubgroupAvcSicSetBilinearFilterEnableINTEL";
+    case OpSubgroupAvcSicSetSkcForwardTransformEnableINTEL: return "OpSubgroupAvcSicSetSkcForwardTransformEnableINTEL";
+    case OpSubgroupAvcSicSetBlockBasedRawSkipSadINTEL: return "OpSubgroupAvcSicSetBlockBasedRawSkipSadINTEL";
+    case OpSubgroupAvcSicEvaluateIpeINTEL: return "OpSubgroupAvcSicEvaluateIpeINTEL";
+    case OpSubgroupAvcSicEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithSingleReferenceINTEL";
+    case OpSubgroupAvcSicEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithDualReferenceINTEL";
+    case OpSubgroupAvcSicEvaluateWithMultiReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithMultiReferenceINTEL";
+    case OpSubgroupAvcSicEvaluateWithMultiReferenceInterlacedINTEL: return "OpSubgroupAvcSicEvaluateWithMultiReferenceInterlacedINTEL";
+    case OpSubgroupAvcSicConvertToMceResultINTEL: return "OpSubgroupAvcSicConvertToMceResultINTEL";
+    case OpSubgroupAvcSicGetIpeLumaShapeINTEL: return "OpSubgroupAvcSicGetIpeLumaShapeINTEL";
+    case OpSubgroupAvcSicGetBestIpeLumaDistortionINTEL: return "OpSubgroupAvcSicGetBestIpeLumaDistortionINTEL";
+    case OpSubgroupAvcSicGetBestIpeChromaDistortionINTEL: return "OpSubgroupAvcSicGetBestIpeChromaDistortionINTEL";
+    case OpSubgroupAvcSicGetPackedIpeLumaModesINTEL: return "OpSubgroupAvcSicGetPackedIpeLumaModesINTEL";
+    case OpSubgroupAvcSicGetIpeChromaModeINTEL: return "OpSubgroupAvcSicGetIpeChromaModeINTEL";
+    case OpSubgroupAvcSicGetPackedSkcLumaCountThresholdINTEL: return "OpSubgroupAvcSicGetPackedSkcLumaCountThresholdINTEL";
+    case OpSubgroupAvcSicGetPackedSkcLumaSumThresholdINTEL: return "OpSubgroupAvcSicGetPackedSkcLumaSumThresholdINTEL";
+    case OpSubgroupAvcSicGetInterRawSadsINTEL: return "OpSubgroupAvcSicGetInterRawSadsINTEL";
+    case OpVariableLengthArrayINTEL: return "OpVariableLengthArrayINTEL";
+    case OpSaveMemoryINTEL: return "OpSaveMemoryINTEL";
+    case OpRestoreMemoryINTEL: return "OpRestoreMemoryINTEL";
+    case OpArbitraryFloatSinCosPiINTEL: return "OpArbitraryFloatSinCosPiINTEL";
+    case OpArbitraryFloatCastINTEL: return "OpArbitraryFloatCastINTEL";
+    case OpArbitraryFloatCastFromIntINTEL: return "OpArbitraryFloatCastFromIntINTEL";
+    case OpArbitraryFloatCastToIntINTEL: return "OpArbitraryFloatCastToIntINTEL";
+    case OpArbitraryFloatAddINTEL: return "OpArbitraryFloatAddINTEL";
+    case OpArbitraryFloatSubINTEL: return "OpArbitraryFloatSubINTEL";
+    case OpArbitraryFloatMulINTEL: return "OpArbitraryFloatMulINTEL";
+    case OpArbitraryFloatDivINTEL: return "OpArbitraryFloatDivINTEL";
+    case OpArbitraryFloatGTINTEL: return "OpArbitraryFloatGTINTEL";
+    case OpArbitraryFloatGEINTEL: return "OpArbitraryFloatGEINTEL";
+    case OpArbitraryFloatLTINTEL: return "OpArbitraryFloatLTINTEL";
+    case OpArbitraryFloatLEINTEL: return "OpArbitraryFloatLEINTEL";
+    case OpArbitraryFloatEQINTEL: return "OpArbitraryFloatEQINTEL";
+    case OpArbitraryFloatRecipINTEL: return "OpArbitraryFloatRecipINTEL";
+    case OpArbitraryFloatRSqrtINTEL: return "OpArbitraryFloatRSqrtINTEL";
+    case OpArbitraryFloatCbrtINTEL: return "OpArbitraryFloatCbrtINTEL";
+    case OpArbitraryFloatHypotINTEL: return "OpArbitraryFloatHypotINTEL";
+    case OpArbitraryFloatSqrtINTEL: return "OpArbitraryFloatSqrtINTEL";
+    case OpArbitraryFloatLogINTEL: return "OpArbitraryFloatLogINTEL";
+    case OpArbitraryFloatLog2INTEL: return "OpArbitraryFloatLog2INTEL";
+    case OpArbitraryFloatLog10INTEL: return "OpArbitraryFloatLog10INTEL";
+    case OpArbitraryFloatLog1pINTEL: return "OpArbitraryFloatLog1pINTEL";
+    case OpArbitraryFloatExpINTEL: return "OpArbitraryFloatExpINTEL";
+    case OpArbitraryFloatExp2INTEL: return "OpArbitraryFloatExp2INTEL";
+    case OpArbitraryFloatExp10INTEL: return "OpArbitraryFloatExp10INTEL";
+    case OpArbitraryFloatExpm1INTEL: return "OpArbitraryFloatExpm1INTEL";
+    case OpArbitraryFloatSinINTEL: return "OpArbitraryFloatSinINTEL";
+    case OpArbitraryFloatCosINTEL: return "OpArbitraryFloatCosINTEL";
+    case OpArbitraryFloatSinCosINTEL: return "OpArbitraryFloatSinCosINTEL";
+    case OpArbitraryFloatSinPiINTEL: return "OpArbitraryFloatSinPiINTEL";
+    case OpArbitraryFloatCosPiINTEL: return "OpArbitraryFloatCosPiINTEL";
+    case OpArbitraryFloatASinINTEL: return "OpArbitraryFloatASinINTEL";
+    case OpArbitraryFloatASinPiINTEL: return "OpArbitraryFloatASinPiINTEL";
+    case OpArbitraryFloatACosINTEL: return "OpArbitraryFloatACosINTEL";
+    case OpArbitraryFloatACosPiINTEL: return "OpArbitraryFloatACosPiINTEL";
+    case OpArbitraryFloatATanINTEL: return "OpArbitraryFloatATanINTEL";
+    case OpArbitraryFloatATanPiINTEL: return "OpArbitraryFloatATanPiINTEL";
+    case OpArbitraryFloatATan2INTEL: return "OpArbitraryFloatATan2INTEL";
+    case OpArbitraryFloatPowINTEL: return "OpArbitraryFloatPowINTEL";
+    case OpArbitraryFloatPowRINTEL: return "OpArbitraryFloatPowRINTEL";
+    case OpArbitraryFloatPowNINTEL: return "OpArbitraryFloatPowNINTEL";
+    case OpLoopControlINTEL: return "OpLoopControlINTEL";
+    case OpAliasDomainDeclINTEL: return "OpAliasDomainDeclINTEL";
+    case OpAliasScopeDeclINTEL: return "OpAliasScopeDeclINTEL";
+    case OpAliasScopeListDeclINTEL: return "OpAliasScopeListDeclINTEL";
+    case OpFixedSqrtINTEL: return "OpFixedSqrtINTEL";
+    case OpFixedRecipINTEL: return "OpFixedRecipINTEL";
+    case OpFixedRsqrtINTEL: return "OpFixedRsqrtINTEL";
+    case OpFixedSinINTEL: return "OpFixedSinINTEL";
+    case OpFixedCosINTEL: return "OpFixedCosINTEL";
+    case OpFixedSinCosINTEL: return "OpFixedSinCosINTEL";
+    case OpFixedSinPiINTEL: return "OpFixedSinPiINTEL";
+    case OpFixedCosPiINTEL: return "OpFixedCosPiINTEL";
+    case OpFixedSinCosPiINTEL: return "OpFixedSinCosPiINTEL";
+    case OpFixedLogINTEL: return "OpFixedLogINTEL";
+    case OpFixedExpINTEL: return "OpFixedExpINTEL";
+    case OpPtrCastToCrossWorkgroupINTEL: return "OpPtrCastToCrossWorkgroupINTEL";
+    case OpCrossWorkgroupCastToPtrINTEL: return "OpCrossWorkgroupCastToPtrINTEL";
+    case OpReadPipeBlockingINTEL: return "OpReadPipeBlockingINTEL";
+    case OpWritePipeBlockingINTEL: return "OpWritePipeBlockingINTEL";
+    case OpFPGARegINTEL: return "OpFPGARegINTEL";
+    case OpRayQueryGetRayTMinKHR: return "OpRayQueryGetRayTMinKHR";
+    case OpRayQueryGetRayFlagsKHR: return "OpRayQueryGetRayFlagsKHR";
+    case OpRayQueryGetIntersectionTKHR: return "OpRayQueryGetIntersectionTKHR";
+    case OpRayQueryGetIntersectionInstanceCustomIndexKHR: return "OpRayQueryGetIntersectionInstanceCustomIndexKHR";
+    case OpRayQueryGetIntersectionInstanceIdKHR: return "OpRayQueryGetIntersectionInstanceIdKHR";
+    case OpRayQueryGetIntersectionInstanceShaderBindingTableRecordOffsetKHR: return "OpRayQueryGetIntersectionInstanceShaderBindingTableRecordOffsetKHR";
+    case OpRayQueryGetIntersectionGeometryIndexKHR: return "OpRayQueryGetIntersectionGeometryIndexKHR";
+    case OpRayQueryGetIntersectionPrimitiveIndexKHR: return "OpRayQueryGetIntersectionPrimitiveIndexKHR";
+    case OpRayQueryGetIntersectionBarycentricsKHR: return "OpRayQueryGetIntersectionBarycentricsKHR";
+    case OpRayQueryGetIntersectionFrontFaceKHR: return "OpRayQueryGetIntersectionFrontFaceKHR";
+    case OpRayQueryGetIntersectionCandidateAABBOpaqueKHR: return "OpRayQueryGetIntersectionCandidateAABBOpaqueKHR";
+    case OpRayQueryGetIntersectionObjectRayDirectionKHR: return "OpRayQueryGetIntersectionObjectRayDirectionKHR";
+    case OpRayQueryGetIntersectionObjectRayOriginKHR: return "OpRayQueryGetIntersectionObjectRayOriginKHR";
+    case OpRayQueryGetWorldRayDirectionKHR: return "OpRayQueryGetWorldRayDirectionKHR";
+    case OpRayQueryGetWorldRayOriginKHR: return "OpRayQueryGetWorldRayOriginKHR";
+    case OpRayQueryGetIntersectionObjectToWorldKHR: return "OpRayQueryGetIntersectionObjectToWorldKHR";
+    case OpRayQueryGetIntersectionWorldToObjectKHR: return "OpRayQueryGetIntersectionWorldToObjectKHR";
+    case OpAtomicFAddEXT: return "OpAtomicFAddEXT";
+    case OpTypeBufferSurfaceINTEL: return "OpTypeBufferSurfaceINTEL";
+    case OpTypeStructContinuedINTEL: return "OpTypeStructContinuedINTEL";
+    case OpConstantCompositeContinuedINTEL: return "OpConstantCompositeContinuedINTEL";
+    case OpSpecConstantCompositeContinuedINTEL: return "OpSpecConstantCompositeContinuedINTEL";
+    case OpCompositeConstructContinuedINTEL: return "OpCompositeConstructContinuedINTEL";
+    case OpConvertFToBF16INTEL: return "OpConvertFToBF16INTEL";
+    case OpConvertBF16ToFINTEL: return "OpConvertBF16ToFINTEL";
+    case OpControlBarrierArriveINTEL: return "OpControlBarrierArriveINTEL";
+    case OpControlBarrierWaitINTEL: return "OpControlBarrierWaitINTEL";
+    case OpArithmeticFenceEXT: return "OpArithmeticFenceEXT";
+    case OpSubgroupBlockPrefetchINTEL: return "OpSubgroupBlockPrefetchINTEL";
+    case OpGroupIMulKHR: return "OpGroupIMulKHR";
+    case OpGroupFMulKHR: return "OpGroupFMulKHR";
+    case OpGroupBitwiseAndKHR: return "OpGroupBitwiseAndKHR";
+    case OpGroupBitwiseOrKHR: return "OpGroupBitwiseOrKHR";
+    case OpGroupBitwiseXorKHR: return "OpGroupBitwiseXorKHR";
+    case OpGroupLogicalAndKHR: return "OpGroupLogicalAndKHR";
+    case OpGroupLogicalOrKHR: return "OpGroupLogicalOrKHR";
+    case OpGroupLogicalXorKHR: return "OpGroupLogicalXorKHR";
+    case OpMaskedGatherINTEL: return "OpMaskedGatherINTEL";
+    case OpMaskedScatterINTEL: return "OpMaskedScatterINTEL";
+    default: return "Unknown";
+    }
+}
+
 #endif /* SPV_ENABLE_UTILITY_CODE */
 
 // Overload bitwise operators for mask bit combining
@@ -2897,6 +4917,18 @@ inline CooperativeMatrixOperandsMask operator|(CooperativeMatrixOperandsMask a,
 inline CooperativeMatrixOperandsMask operator&(CooperativeMatrixOperandsMask a, CooperativeMatrixOperandsMask b) { return CooperativeMatrixOperandsMask(unsigned(a) & unsigned(b)); }
 inline CooperativeMatrixOperandsMask operator^(CooperativeMatrixOperandsMask a, CooperativeMatrixOperandsMask b) { return CooperativeMatrixOperandsMask(unsigned(a) ^ unsigned(b)); }
 inline CooperativeMatrixOperandsMask operator~(CooperativeMatrixOperandsMask a) { return CooperativeMatrixOperandsMask(~unsigned(a)); }
+inline CooperativeMatrixReduceMask operator|(CooperativeMatrixReduceMask a, CooperativeMatrixReduceMask b) { return CooperativeMatrixReduceMask(unsigned(a) | unsigned(b)); }
+inline CooperativeMatrixReduceMask operator&(CooperativeMatrixReduceMask a, CooperativeMatrixReduceMask b) { return CooperativeMatrixReduceMask(unsigned(a) & unsigned(b)); }
+inline CooperativeMatrixReduceMask operator^(CooperativeMatrixReduceMask a, CooperativeMatrixReduceMask b) { return CooperativeMatrixReduceMask(unsigned(a) ^ unsigned(b)); }
+inline CooperativeMatrixReduceMask operator~(CooperativeMatrixReduceMask a) { return CooperativeMatrixReduceMask(~unsigned(a)); }
+inline TensorAddressingOperandsMask operator|(TensorAddressingOperandsMask a, TensorAddressingOperandsMask b) { return TensorAddressingOperandsMask(unsigned(a) | unsigned(b)); }
+inline TensorAddressingOperandsMask operator&(TensorAddressingOperandsMask a, TensorAddressingOperandsMask b) { return TensorAddressingOperandsMask(unsigned(a) & unsigned(b)); }
+inline TensorAddressingOperandsMask operator^(TensorAddressingOperandsMask a, TensorAddressingOperandsMask b) { return TensorAddressingOperandsMask(unsigned(a) ^ unsigned(b)); }
+inline TensorAddressingOperandsMask operator~(TensorAddressingOperandsMask a) { return TensorAddressingOperandsMask(~unsigned(a)); }
+inline RawAccessChainOperandsMask operator|(RawAccessChainOperandsMask a, RawAccessChainOperandsMask b) { return RawAccessChainOperandsMask(unsigned(a) | unsigned(b)); }
+inline RawAccessChainOperandsMask operator&(RawAccessChainOperandsMask a, RawAccessChainOperandsMask b) { return RawAccessChainOperandsMask(unsigned(a) & unsigned(b)); }
+inline RawAccessChainOperandsMask operator^(RawAccessChainOperandsMask a, RawAccessChainOperandsMask b) { return RawAccessChainOperandsMask(unsigned(a) ^ unsigned(b)); }
+inline RawAccessChainOperandsMask operator~(RawAccessChainOperandsMask a) { return RawAccessChainOperandsMask(~unsigned(a)); }
 
 }  // end namespace spv
 
diff --git a/include/spirv/unified1/spirv.hpp11 b/include/spirv/unified1/spirv.hpp11
index e32ff7a..a549d03 100644
--- a/include/spirv/unified1/spirv.hpp11
+++ b/include/spirv/unified1/spirv.hpp11
@@ -12,7 +12,7 @@
 // 
 // MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 // STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
 // 
 // THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -174,6 +174,7 @@ enum class ExecutionMode : unsigned {
     EarlyAndLateFragmentTestsAMD = 5017,
     StencilRefReplacingEXT = 5027,
     CoalescingAMDX = 5069,
+    IsApiEntryAMDX = 5070,
     MaxNodeRecursionAMDX = 5071,
     StaticNumWorkgroupsAMDX = 5072,
     ShaderIndexAMDX = 5073,
@@ -186,11 +187,14 @@ enum class ExecutionMode : unsigned {
     StencilRefLessBackAMD = 5084,
     QuadDerivativesKHR = 5088,
     RequireFullQuadsKHR = 5089,
+    SharesInputWithAMDX = 5102,
     OutputLinesEXT = 5269,
     OutputLinesNV = 5269,
     OutputPrimitivesEXT = 5270,
     OutputPrimitivesNV = 5270,
+    DerivativeGroupQuadsKHR = 5289,
     DerivativeGroupQuadsNV = 5289,
+    DerivativeGroupLinearKHR = 5290,
     DerivativeGroupLinearNV = 5290,
     OutputTrianglesEXT = 5298,
     OutputTrianglesNV = 5298,
@@ -215,6 +219,9 @@ enum class ExecutionMode : unsigned {
     StreamingInterfaceINTEL = 6154,
     RegisterMapInterfaceINTEL = 6160,
     NamedBarrierCountINTEL = 6417,
+    MaximumRegistersINTEL = 6461,
+    MaximumRegistersIdINTEL = 6462,
+    NamedMaximumRegistersINTEL = 6463,
     Max = 0x7fffffff,
 };
 
@@ -234,7 +241,6 @@ enum class StorageClass : unsigned {
     StorageBuffer = 12,
     TileImageEXT = 4172,
     NodePayloadAMDX = 5068,
-    NodeOutputPayloadAMDX = 5076,
     CallableDataKHR = 5328,
     CallableDataNV = 5328,
     IncomingCallableDataKHR = 5329,
@@ -374,6 +380,7 @@ enum class ImageChannelDataType : unsigned {
     UnormInt101010_2 = 16,
     UnsignedIntRaw10EXT = 19,
     UnsignedIntRaw12EXT = 20,
+    UnormInt2_101010EXT = 21,
     Max = 0x7fffffff,
 };
 
@@ -540,11 +547,16 @@ enum class Decoration : unsigned {
     NoUnsignedWrap = 4470,
     WeightTextureQCOM = 4487,
     BlockMatchTextureQCOM = 4488,
+    BlockMatchSamplerQCOM = 4499,
     ExplicitInterpAMD = 4999,
     NodeSharesPayloadLimitsWithAMDX = 5019,
     NodeMaxPayloadsAMDX = 5020,
     TrackFinishWritingAMDX = 5078,
     PayloadNodeNameAMDX = 5091,
+    PayloadNodeBaseIndexAMDX = 5098,
+    PayloadNodeSparseArrayAMDX = 5099,
+    PayloadNodeArraySizeAMDX = 5100,
+    PayloadDispatchIndirectAMDX = 5105,
     OverrideCoverageNV = 5248,
     PassthroughNV = 5250,
     ViewportRelativeNV = 5252,
@@ -708,7 +720,7 @@ enum class BuiltIn : unsigned {
     BaryCoordSmoothSampleAMD = 4997,
     BaryCoordPullModelAMD = 4998,
     FragStencilRefEXT = 5014,
-    CoalescedInputCountAMDX = 5021,
+    RemainingRecursionLevelsAMDX = 5021,
     ShaderIndexAMDX = 5073,
     ViewportMaskNV = 5253,
     SecondaryPositionNV = 5257,
@@ -841,6 +853,7 @@ enum class FunctionControlShift : unsigned {
     DontInline = 1,
     Pure = 2,
     Const = 3,
+    OptNoneEXT = 16,
     OptNoneINTEL = 16,
     Max = 0x7fffffff,
 };
@@ -851,6 +864,7 @@ enum class FunctionControlMask : unsigned {
     DontInline = 0x00000002,
     Pure = 0x00000004,
     Const = 0x00000008,
+    OptNoneEXT = 0x00010000,
     OptNoneINTEL = 0x00010000,
 };
 
@@ -1041,6 +1055,7 @@ enum class Capability : unsigned {
     TileImageColorReadAccessEXT = 4166,
     TileImageDepthReadAccessEXT = 4167,
     TileImageStencilReadAccessEXT = 4168,
+    CooperativeMatrixLayoutsARM = 4201,
     FragmentShadingRateKHR = 4422,
     SubgroupBallotKHR = 4423,
     DrawParameters = 4427,
@@ -1070,11 +1085,13 @@ enum class Capability : unsigned {
     RoundingModeRTZ = 4468,
     RayQueryProvisionalKHR = 4471,
     RayQueryKHR = 4472,
+    UntypedPointersKHR = 4473,
     RayTraversalPrimitiveCullingKHR = 4478,
     RayTracingKHR = 4479,
     TextureSampleWeightedQCOM = 4484,
     TextureBoxFilterQCOM = 4485,
     TextureBlockMatchQCOM = 4486,
+    TextureBlockMatch2QCOM = 4498,
     Float16ImageAMD = 5008,
     ImageGatherBiasLodAMD = 5009,
     FragmentMaskAMD = 5010,
@@ -1097,6 +1114,7 @@ enum class Capability : unsigned {
     MeshShadingEXT = 5283,
     FragmentBarycentricKHR = 5284,
     FragmentBarycentricNV = 5284,
+    ComputeDerivativeGroupQuadsKHR = 5288,
     ComputeDerivativeGroupQuadsNV = 5288,
     FragmentDensityEXT = 5291,
     ShadingRateNV = 5291,
@@ -1134,6 +1152,7 @@ enum class Capability : unsigned {
     VulkanMemoryModelDeviceScopeKHR = 5346,
     PhysicalStorageBufferAddresses = 5347,
     PhysicalStorageBufferAddressesEXT = 5347,
+    ComputeDerivativeGroupLinearKHR = 5350,
     ComputeDerivativeGroupLinearNV = 5350,
     RayTracingProvisionalKHR = 5353,
     CooperativeMatrixNV = 5357,
@@ -1148,7 +1167,15 @@ enum class Capability : unsigned {
     ShaderInvocationReorderNV = 5383,
     BindlessTextureNV = 5390,
     RayQueryPositionFetchKHR = 5391,
+    AtomicFloat16VectorNV = 5404,
     RayTracingDisplacementMicromapNV = 5409,
+    RawAccessChainsNV = 5414,
+    CooperativeMatrixReductionsNV = 5430,
+    CooperativeMatrixConversionsNV = 5431,
+    CooperativeMatrixPerElementOperationsNV = 5432,
+    CooperativeMatrixTensorAddressingNV = 5433,
+    CooperativeMatrixBlockLoadsNV = 5434,
+    TensorAddressingNV = 5439,
     SubgroupShuffleINTEL = 5568,
     SubgroupBufferBlockIOINTEL = 5569,
     SubgroupImageBlockIOINTEL = 5570,
@@ -1201,17 +1228,20 @@ enum class Capability : unsigned {
     DotProductKHR = 6019,
     RayCullMaskKHR = 6020,
     CooperativeMatrixKHR = 6022,
+    ReplicatedCompositesEXT = 6024,
     BitInstructions = 6025,
     GroupNonUniformRotateKHR = 6026,
     FloatControls2 = 6029,
     AtomicFloat32AddEXT = 6033,
     AtomicFloat64AddEXT = 6034,
     LongCompositesINTEL = 6089,
+    OptNoneEXT = 6094,
     OptNoneINTEL = 6094,
     AtomicFloat16AddEXT = 6095,
     DebugInfoModuleINTEL = 6114,
     BFloat16ConversionINTEL = 6115,
     SplitBarrierINTEL = 6141,
+    ArithmeticFenceEXT = 6144,
     FPGAClusterAttributesV2INTEL = 6150,
     FPGAKernelAttributesv2INTEL = 6161,
     FPMaxErrorINTEL = 6169,
@@ -1219,9 +1249,11 @@ enum class Capability : unsigned {
     FPGAArgumentInterfacesINTEL = 6174,
     GlobalVariableHostAccessINTEL = 6187,
     GlobalVariableFPGADecorationsINTEL = 6189,
+    SubgroupBufferPrefetchINTEL = 6220,
     GroupUniformArithmeticKHR = 6400,
     MaskedGatherScatterINTEL = 6427,
     CacheControlsINTEL = 6441,
+    RegisterLimitsINTEL = 6460,
     Max = 0x7fffffff,
 };
 
@@ -1349,6 +1381,8 @@ enum class CooperativeMatrixOperandsMask : unsigned {
 enum class CooperativeMatrixLayout : unsigned {
     RowMajorKHR = 0,
     ColumnMajorKHR = 1,
+    RowBlockedInterleavedARM = 4202,
+    ColumnBlockedInterleavedARM = 4203,
     Max = 0x7fffffff,
 };
 
@@ -1359,6 +1393,41 @@ enum class CooperativeMatrixUse : unsigned {
     Max = 0x7fffffff,
 };
 
+enum class CooperativeMatrixReduceShift : unsigned {
+    Row = 0,
+    Column = 1,
+    CooperativeMatrixReduce2x2 = 2,
+    Max = 0x7fffffff,
+};
+
+enum class CooperativeMatrixReduceMask : unsigned {
+    MaskNone = 0,
+    Row = 0x00000001,
+    Column = 0x00000002,
+    CooperativeMatrixReduce2x2 = 0x00000004,
+};
+
+enum class TensorClampMode : unsigned {
+    Undefined = 0,
+    Constant = 1,
+    ClampToEdge = 2,
+    Repeat = 3,
+    RepeatMirrored = 4,
+    Max = 0x7fffffff,
+};
+
+enum class TensorAddressingOperandsShift : unsigned {
+    TensorView = 0,
+    DecodeFunc = 1,
+    Max = 0x7fffffff,
+};
+
+enum class TensorAddressingOperandsMask : unsigned {
+    MaskNone = 0,
+    TensorView = 0x00000001,
+    DecodeFunc = 0x00000002,
+};
+
 enum class InitializationModeQualifier : unsigned {
     InitOnDeviceReprogramINTEL = 0,
     InitOnDeviceResetINTEL = 1,
@@ -1390,6 +1459,27 @@ enum class StoreCacheControl : unsigned {
     Max = 0x7fffffff,
 };
 
+enum class NamedMaximumNumberOfRegisters : unsigned {
+    AutoINTEL = 0,
+    Max = 0x7fffffff,
+};
+
+enum class RawAccessChainOperandsShift : unsigned {
+    RobustnessPerComponentNV = 0,
+    RobustnessPerElementNV = 1,
+    Max = 0x7fffffff,
+};
+
+enum class RawAccessChainOperandsMask : unsigned {
+    MaskNone = 0,
+    RobustnessPerComponentNV = 0x00000001,
+    RobustnessPerElementNV = 0x00000002,
+};
+
+enum class FPEncoding : unsigned {
+    Max = 0x7fffffff,
+};
+
 enum class Op : unsigned {
     OpNop = 0,
     OpUndef = 1,
@@ -1739,13 +1829,22 @@ enum class Op : unsigned {
     OpDepthAttachmentReadEXT = 4161,
     OpStencilAttachmentReadEXT = 4162,
     OpTerminateInvocation = 4416,
+    OpTypeUntypedPointerKHR = 4417,
+    OpUntypedVariableKHR = 4418,
+    OpUntypedAccessChainKHR = 4419,
+    OpUntypedInBoundsAccessChainKHR = 4420,
     OpSubgroupBallotKHR = 4421,
     OpSubgroupFirstInvocationKHR = 4422,
+    OpUntypedPtrAccessChainKHR = 4423,
+    OpUntypedInBoundsPtrAccessChainKHR = 4424,
+    OpUntypedArrayLengthKHR = 4425,
+    OpUntypedPrefetchKHR = 4426,
     OpSubgroupAllKHR = 4428,
     OpSubgroupAnyKHR = 4429,
     OpSubgroupAllEqualKHR = 4430,
     OpGroupNonUniformRotateKHR = 4431,
     OpSubgroupReadInvocationKHR = 4432,
+    OpExtInstWithForwardRefsKHR = 4433,
     OpTraceRayKHR = 4445,
     OpExecuteCallableKHR = 4446,
     OpConvertUToAccelerationStructureKHR = 4447,
@@ -1768,6 +1867,9 @@ enum class Op : unsigned {
     OpCooperativeMatrixStoreKHR = 4458,
     OpCooperativeMatrixMulAddKHR = 4459,
     OpCooperativeMatrixLengthKHR = 4460,
+    OpConstantCompositeReplicateEXT = 4461,
+    OpSpecConstantCompositeReplicateEXT = 4462,
+    OpCompositeConstructReplicateEXT = 4463,
     OpTypeRayQueryKHR = 4472,
     OpRayQueryInitializeKHR = 4473,
     OpRayQueryTerminateKHR = 4474,
@@ -1779,6 +1881,10 @@ enum class Op : unsigned {
     OpImageBoxFilterQCOM = 4481,
     OpImageBlockMatchSSDQCOM = 4482,
     OpImageBlockMatchSADQCOM = 4483,
+    OpImageBlockMatchWindowSSDQCOM = 4500,
+    OpImageBlockMatchWindowSADQCOM = 4501,
+    OpImageBlockMatchGatherSSDQCOM = 4502,
+    OpImageBlockMatchGatherSADQCOM = 4503,
     OpGroupIAddNonUniformAMD = 5000,
     OpGroupFAddNonUniformAMD = 5001,
     OpGroupFMinNonUniformAMD = 5002,
@@ -1790,9 +1896,14 @@ enum class Op : unsigned {
     OpFragmentMaskFetchAMD = 5011,
     OpFragmentFetchAMD = 5012,
     OpReadClockKHR = 5056,
-    OpFinalizeNodePayloadsAMDX = 5075,
+    OpAllocateNodePayloadsAMDX = 5074,
+    OpEnqueueNodePayloadsAMDX = 5075,
+    OpTypeNodePayloadArrayAMDX = 5076,
     OpFinishWritingNodePayloadAMDX = 5078,
-    OpInitializeNodePayloadsAMDX = 5090,
+    OpNodePayloadArrayLengthAMDX = 5090,
+    OpIsNodePayloadValidAMDX = 5101,
+    OpConstantStringAMDX = 5103,
+    OpSpecConstantStringAMDX = 5104,
     OpGroupNonUniformQuadAllKHR = 5110,
     OpGroupNonUniformQuadAnyKHR = 5111,
     OpHitObjectRecordHitMotionNV = 5249,
@@ -1829,6 +1940,7 @@ enum class Op : unsigned {
     OpReorderThreadWithHintNV = 5280,
     OpTypeHitObjectNV = 5281,
     OpImageSampleFootprintNV = 5283,
+    OpCooperativeMatrixConvertNV = 5293,
     OpEmitMeshTasksEXT = 5294,
     OpSetMeshOutputsEXT = 5295,
     OpGroupNonUniformPartitionNV = 5296,
@@ -1853,9 +1965,26 @@ enum class Op : unsigned {
     OpCooperativeMatrixLengthNV = 5362,
     OpBeginInvocationInterlockEXT = 5364,
     OpEndInvocationInterlockEXT = 5365,
+    OpCooperativeMatrixReduceNV = 5366,
+    OpCooperativeMatrixLoadTensorNV = 5367,
+    OpCooperativeMatrixStoreTensorNV = 5368,
+    OpCooperativeMatrixPerElementOpNV = 5369,
+    OpTypeTensorLayoutNV = 5370,
+    OpTypeTensorViewNV = 5371,
+    OpCreateTensorLayoutNV = 5372,
+    OpTensorLayoutSetDimensionNV = 5373,
+    OpTensorLayoutSetStrideNV = 5374,
+    OpTensorLayoutSliceNV = 5375,
+    OpTensorLayoutSetClampValueNV = 5376,
+    OpCreateTensorViewNV = 5377,
+    OpTensorViewSetDimensionNV = 5378,
+    OpTensorViewSetStrideNV = 5379,
     OpDemoteToHelperInvocation = 5380,
     OpDemoteToHelperInvocationEXT = 5380,
     OpIsHelperInvocationEXT = 5381,
+    OpTensorViewSetClipNV = 5382,
+    OpTensorLayoutSetBlockSizeNV = 5384,
+    OpCooperativeMatrixTransposeNV = 5390,
     OpConvertUToImageNV = 5391,
     OpConvertUToSamplerNV = 5392,
     OpConvertImageToUNV = 5393,
@@ -1863,6 +1992,7 @@ enum class Op : unsigned {
     OpConvertUToSampledImageNV = 5395,
     OpConvertSampledImageToUNV = 5396,
     OpSamplerImageAddressingModeNV = 5397,
+    OpRawAccessChainNV = 5398,
     OpSubgroupShuffleINTEL = 5571,
     OpSubgroupShuffleDownINTEL = 5572,
     OpSubgroupShuffleUpINTEL = 5573,
@@ -2109,6 +2239,8 @@ enum class Op : unsigned {
     OpConvertBF16ToFINTEL = 6117,
     OpControlBarrierArriveINTEL = 6142,
     OpControlBarrierWaitINTEL = 6143,
+    OpArithmeticFenceEXT = 6145,
+    OpSubgroupBlockPrefetchINTEL = 6221,
     OpGroupIMulKHR = 6401,
     OpGroupFMulKHR = 6402,
     OpGroupBitwiseAndKHR = 6403,
@@ -2478,13 +2610,22 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpDepthAttachmentReadEXT: *hasResult = true; *hasResultType = true; break;
     case Op::OpStencilAttachmentReadEXT: *hasResult = true; *hasResultType = true; break;
     case Op::OpTerminateInvocation: *hasResult = false; *hasResultType = false; break;
+    case Op::OpTypeUntypedPointerKHR: *hasResult = true; *hasResultType = false; break;
+    case Op::OpUntypedVariableKHR: *hasResult = true; *hasResultType = true; break;
+    case Op::OpUntypedAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case Op::OpUntypedInBoundsAccessChainKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpSubgroupBallotKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpSubgroupFirstInvocationKHR: *hasResult = true; *hasResultType = true; break;
+    case Op::OpUntypedPtrAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case Op::OpUntypedInBoundsPtrAccessChainKHR: *hasResult = true; *hasResultType = true; break;
+    case Op::OpUntypedArrayLengthKHR: *hasResult = true; *hasResultType = true; break;
+    case Op::OpUntypedPrefetchKHR: *hasResult = false; *hasResultType = false; break;
     case Op::OpSubgroupAllKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpSubgroupAnyKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpSubgroupAllEqualKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpGroupNonUniformRotateKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpSubgroupReadInvocationKHR: *hasResult = true; *hasResultType = true; break;
+    case Op::OpExtInstWithForwardRefsKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpTraceRayKHR: *hasResult = false; *hasResultType = false; break;
     case Op::OpExecuteCallableKHR: *hasResult = false; *hasResultType = false; break;
     case Op::OpConvertUToAccelerationStructureKHR: *hasResult = true; *hasResultType = true; break;
@@ -2501,6 +2642,9 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpCooperativeMatrixStoreKHR: *hasResult = false; *hasResultType = false; break;
     case Op::OpCooperativeMatrixMulAddKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpCooperativeMatrixLengthKHR: *hasResult = true; *hasResultType = true; break;
+    case Op::OpConstantCompositeReplicateEXT: *hasResult = true; *hasResultType = true; break;
+    case Op::OpSpecConstantCompositeReplicateEXT: *hasResult = true; *hasResultType = true; break;
+    case Op::OpCompositeConstructReplicateEXT: *hasResult = true; *hasResultType = true; break;
     case Op::OpTypeRayQueryKHR: *hasResult = true; *hasResultType = false; break;
     case Op::OpRayQueryInitializeKHR: *hasResult = false; *hasResultType = false; break;
     case Op::OpRayQueryTerminateKHR: *hasResult = false; *hasResultType = false; break;
@@ -2512,6 +2656,10 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpImageBoxFilterQCOM: *hasResult = true; *hasResultType = true; break;
     case Op::OpImageBlockMatchSSDQCOM: *hasResult = true; *hasResultType = true; break;
     case Op::OpImageBlockMatchSADQCOM: *hasResult = true; *hasResultType = true; break;
+    case Op::OpImageBlockMatchWindowSSDQCOM: *hasResult = true; *hasResultType = true; break;
+    case Op::OpImageBlockMatchWindowSADQCOM: *hasResult = true; *hasResultType = true; break;
+    case Op::OpImageBlockMatchGatherSSDQCOM: *hasResult = true; *hasResultType = true; break;
+    case Op::OpImageBlockMatchGatherSADQCOM: *hasResult = true; *hasResultType = true; break;
     case Op::OpGroupIAddNonUniformAMD: *hasResult = true; *hasResultType = true; break;
     case Op::OpGroupFAddNonUniformAMD: *hasResult = true; *hasResultType = true; break;
     case Op::OpGroupFMinNonUniformAMD: *hasResult = true; *hasResultType = true; break;
@@ -2523,9 +2671,14 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpFragmentMaskFetchAMD: *hasResult = true; *hasResultType = true; break;
     case Op::OpFragmentFetchAMD: *hasResult = true; *hasResultType = true; break;
     case Op::OpReadClockKHR: *hasResult = true; *hasResultType = true; break;
-    case Op::OpFinalizeNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case Op::OpAllocateNodePayloadsAMDX: *hasResult = true; *hasResultType = true; break;
+    case Op::OpEnqueueNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case Op::OpTypeNodePayloadArrayAMDX: *hasResult = true; *hasResultType = false; break;
     case Op::OpFinishWritingNodePayloadAMDX: *hasResult = true; *hasResultType = true; break;
-    case Op::OpInitializeNodePayloadsAMDX: *hasResult = false; *hasResultType = false; break;
+    case Op::OpNodePayloadArrayLengthAMDX: *hasResult = true; *hasResultType = true; break;
+    case Op::OpIsNodePayloadValidAMDX: *hasResult = true; *hasResultType = true; break;
+    case Op::OpConstantStringAMDX: *hasResult = true; *hasResultType = false; break;
+    case Op::OpSpecConstantStringAMDX: *hasResult = true; *hasResultType = false; break;
     case Op::OpGroupNonUniformQuadAllKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpGroupNonUniformQuadAnyKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpHitObjectRecordHitMotionNV: *hasResult = false; *hasResultType = false; break;
@@ -2562,20 +2715,21 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpReorderThreadWithHintNV: *hasResult = false; *hasResultType = false; break;
     case Op::OpTypeHitObjectNV: *hasResult = true; *hasResultType = false; break;
     case Op::OpImageSampleFootprintNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpCooperativeMatrixConvertNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpEmitMeshTasksEXT: *hasResult = false; *hasResultType = false; break;
     case Op::OpSetMeshOutputsEXT: *hasResult = false; *hasResultType = false; break;
     case Op::OpGroupNonUniformPartitionNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpWritePackedPrimitiveIndices4x8NV: *hasResult = false; *hasResultType = false; break;
     case Op::OpFetchMicroTriangleVertexPositionNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpFetchMicroTriangleVertexBarycentricNV: *hasResult = true; *hasResultType = true; break;
-    case Op::OpReportIntersectionNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpReportIntersectionKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpIgnoreIntersectionNV: *hasResult = false; *hasResultType = false; break;
     case Op::OpTerminateRayNV: *hasResult = false; *hasResultType = false; break;
     case Op::OpTraceNV: *hasResult = false; *hasResultType = false; break;
     case Op::OpTraceMotionNV: *hasResult = false; *hasResultType = false; break;
     case Op::OpTraceRayMotionNV: *hasResult = false; *hasResultType = false; break;
     case Op::OpRayQueryGetIntersectionTriangleVertexPositionsKHR: *hasResult = true; *hasResultType = true; break;
-    case Op::OpTypeAccelerationStructureNV: *hasResult = true; *hasResultType = false; break;
+    case Op::OpTypeAccelerationStructureKHR: *hasResult = true; *hasResultType = false; break;
     case Op::OpExecuteCallableNV: *hasResult = false; *hasResultType = false; break;
     case Op::OpTypeCooperativeMatrixNV: *hasResult = true; *hasResultType = false; break;
     case Op::OpCooperativeMatrixLoadNV: *hasResult = true; *hasResultType = true; break;
@@ -2584,8 +2738,25 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpCooperativeMatrixLengthNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpBeginInvocationInterlockEXT: *hasResult = false; *hasResultType = false; break;
     case Op::OpEndInvocationInterlockEXT: *hasResult = false; *hasResultType = false; break;
+    case Op::OpCooperativeMatrixReduceNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpCooperativeMatrixLoadTensorNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpCooperativeMatrixStoreTensorNV: *hasResult = false; *hasResultType = false; break;
+    case Op::OpCooperativeMatrixPerElementOpNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTypeTensorLayoutNV: *hasResult = true; *hasResultType = false; break;
+    case Op::OpTypeTensorViewNV: *hasResult = true; *hasResultType = false; break;
+    case Op::OpCreateTensorLayoutNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTensorLayoutSetDimensionNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTensorLayoutSetStrideNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTensorLayoutSliceNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTensorLayoutSetClampValueNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpCreateTensorViewNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTensorViewSetDimensionNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTensorViewSetStrideNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpDemoteToHelperInvocation: *hasResult = false; *hasResultType = false; break;
     case Op::OpIsHelperInvocationEXT: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTensorViewSetClipNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpTensorLayoutSetBlockSizeNV: *hasResult = true; *hasResultType = true; break;
+    case Op::OpCooperativeMatrixTransposeNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpConvertUToImageNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpConvertUToSamplerNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpConvertImageToUNV: *hasResult = true; *hasResultType = true; break;
@@ -2593,6 +2764,7 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpConvertUToSampledImageNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpConvertSampledImageToUNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpSamplerImageAddressingModeNV: *hasResult = false; *hasResultType = false; break;
+    case Op::OpRawAccessChainNV: *hasResult = true; *hasResultType = true; break;
     case Op::OpSubgroupShuffleINTEL: *hasResult = true; *hasResultType = true; break;
     case Op::OpSubgroupShuffleDownINTEL: *hasResult = true; *hasResultType = true; break;
     case Op::OpSubgroupShuffleUpINTEL: *hasResult = true; *hasResultType = true; break;
@@ -2837,6 +3009,8 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpConvertBF16ToFINTEL: *hasResult = true; *hasResultType = true; break;
     case Op::OpControlBarrierArriveINTEL: *hasResult = false; *hasResultType = false; break;
     case Op::OpControlBarrierWaitINTEL: *hasResult = false; *hasResultType = false; break;
+    case Op::OpArithmeticFenceEXT: *hasResult = true; *hasResultType = true; break;
+    case Op::OpSubgroupBlockPrefetchINTEL: *hasResult = false; *hasResultType = false; break;
     case Op::OpGroupIMulKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpGroupFMulKHR: *hasResult = true; *hasResultType = true; break;
     case Op::OpGroupBitwiseAndKHR: *hasResult = true; *hasResultType = true; break;
@@ -2849,6 +3023,1852 @@ inline void HasResultAndType(Op opcode, bool *hasResult, bool *hasResultType) {
     case Op::OpMaskedScatterINTEL: *hasResult = false; *hasResultType = false; break;
     }
 }
+inline const char* SourceLanguageToString(SourceLanguage value) {
+    switch (value) {
+    case SourceLanguage::Unknown: return "Unknown";
+    case SourceLanguage::ESSL: return "ESSL";
+    case SourceLanguage::GLSL: return "GLSL";
+    case SourceLanguage::OpenCL_C: return "OpenCL_C";
+    case SourceLanguage::OpenCL_CPP: return "OpenCL_CPP";
+    case SourceLanguage::HLSL: return "HLSL";
+    case SourceLanguage::CPP_for_OpenCL: return "CPP_for_OpenCL";
+    case SourceLanguage::SYCL: return "SYCL";
+    case SourceLanguage::HERO_C: return "HERO_C";
+    case SourceLanguage::NZSL: return "NZSL";
+    case SourceLanguage::WGSL: return "WGSL";
+    case SourceLanguage::Slang: return "Slang";
+    case SourceLanguage::Zig: return "Zig";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ExecutionModelToString(ExecutionModel value) {
+    switch (value) {
+    case ExecutionModel::Vertex: return "Vertex";
+    case ExecutionModel::TessellationControl: return "TessellationControl";
+    case ExecutionModel::TessellationEvaluation: return "TessellationEvaluation";
+    case ExecutionModel::Geometry: return "Geometry";
+    case ExecutionModel::Fragment: return "Fragment";
+    case ExecutionModel::GLCompute: return "GLCompute";
+    case ExecutionModel::Kernel: return "Kernel";
+    case ExecutionModel::TaskNV: return "TaskNV";
+    case ExecutionModel::MeshNV: return "MeshNV";
+    case ExecutionModel::RayGenerationKHR: return "RayGenerationKHR";
+    case ExecutionModel::IntersectionKHR: return "IntersectionKHR";
+    case ExecutionModel::AnyHitKHR: return "AnyHitKHR";
+    case ExecutionModel::ClosestHitKHR: return "ClosestHitKHR";
+    case ExecutionModel::MissKHR: return "MissKHR";
+    case ExecutionModel::CallableKHR: return "CallableKHR";
+    case ExecutionModel::TaskEXT: return "TaskEXT";
+    case ExecutionModel::MeshEXT: return "MeshEXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* AddressingModelToString(AddressingModel value) {
+    switch (value) {
+    case AddressingModel::Logical: return "Logical";
+    case AddressingModel::Physical32: return "Physical32";
+    case AddressingModel::Physical64: return "Physical64";
+    case AddressingModel::PhysicalStorageBuffer64: return "PhysicalStorageBuffer64";
+    default: return "Unknown";
+    }
+}
+
+inline const char* MemoryModelToString(MemoryModel value) {
+    switch (value) {
+    case MemoryModel::Simple: return "Simple";
+    case MemoryModel::GLSL450: return "GLSL450";
+    case MemoryModel::OpenCL: return "OpenCL";
+    case MemoryModel::Vulkan: return "Vulkan";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ExecutionModeToString(ExecutionMode value) {
+    switch (value) {
+    case ExecutionMode::Invocations: return "Invocations";
+    case ExecutionMode::SpacingEqual: return "SpacingEqual";
+    case ExecutionMode::SpacingFractionalEven: return "SpacingFractionalEven";
+    case ExecutionMode::SpacingFractionalOdd: return "SpacingFractionalOdd";
+    case ExecutionMode::VertexOrderCw: return "VertexOrderCw";
+    case ExecutionMode::VertexOrderCcw: return "VertexOrderCcw";
+    case ExecutionMode::PixelCenterInteger: return "PixelCenterInteger";
+    case ExecutionMode::OriginUpperLeft: return "OriginUpperLeft";
+    case ExecutionMode::OriginLowerLeft: return "OriginLowerLeft";
+    case ExecutionMode::EarlyFragmentTests: return "EarlyFragmentTests";
+    case ExecutionMode::PointMode: return "PointMode";
+    case ExecutionMode::Xfb: return "Xfb";
+    case ExecutionMode::DepthReplacing: return "DepthReplacing";
+    case ExecutionMode::DepthGreater: return "DepthGreater";
+    case ExecutionMode::DepthLess: return "DepthLess";
+    case ExecutionMode::DepthUnchanged: return "DepthUnchanged";
+    case ExecutionMode::LocalSize: return "LocalSize";
+    case ExecutionMode::LocalSizeHint: return "LocalSizeHint";
+    case ExecutionMode::InputPoints: return "InputPoints";
+    case ExecutionMode::InputLines: return "InputLines";
+    case ExecutionMode::InputLinesAdjacency: return "InputLinesAdjacency";
+    case ExecutionMode::Triangles: return "Triangles";
+    case ExecutionMode::InputTrianglesAdjacency: return "InputTrianglesAdjacency";
+    case ExecutionMode::Quads: return "Quads";
+    case ExecutionMode::Isolines: return "Isolines";
+    case ExecutionMode::OutputVertices: return "OutputVertices";
+    case ExecutionMode::OutputPoints: return "OutputPoints";
+    case ExecutionMode::OutputLineStrip: return "OutputLineStrip";
+    case ExecutionMode::OutputTriangleStrip: return "OutputTriangleStrip";
+    case ExecutionMode::VecTypeHint: return "VecTypeHint";
+    case ExecutionMode::ContractionOff: return "ContractionOff";
+    case ExecutionMode::Initializer: return "Initializer";
+    case ExecutionMode::Finalizer: return "Finalizer";
+    case ExecutionMode::SubgroupSize: return "SubgroupSize";
+    case ExecutionMode::SubgroupsPerWorkgroup: return "SubgroupsPerWorkgroup";
+    case ExecutionMode::SubgroupsPerWorkgroupId: return "SubgroupsPerWorkgroupId";
+    case ExecutionMode::LocalSizeId: return "LocalSizeId";
+    case ExecutionMode::LocalSizeHintId: return "LocalSizeHintId";
+    case ExecutionMode::NonCoherentColorAttachmentReadEXT: return "NonCoherentColorAttachmentReadEXT";
+    case ExecutionMode::NonCoherentDepthAttachmentReadEXT: return "NonCoherentDepthAttachmentReadEXT";
+    case ExecutionMode::NonCoherentStencilAttachmentReadEXT: return "NonCoherentStencilAttachmentReadEXT";
+    case ExecutionMode::SubgroupUniformControlFlowKHR: return "SubgroupUniformControlFlowKHR";
+    case ExecutionMode::PostDepthCoverage: return "PostDepthCoverage";
+    case ExecutionMode::DenormPreserve: return "DenormPreserve";
+    case ExecutionMode::DenormFlushToZero: return "DenormFlushToZero";
+    case ExecutionMode::SignedZeroInfNanPreserve: return "SignedZeroInfNanPreserve";
+    case ExecutionMode::RoundingModeRTE: return "RoundingModeRTE";
+    case ExecutionMode::RoundingModeRTZ: return "RoundingModeRTZ";
+    case ExecutionMode::EarlyAndLateFragmentTestsAMD: return "EarlyAndLateFragmentTestsAMD";
+    case ExecutionMode::StencilRefReplacingEXT: return "StencilRefReplacingEXT";
+    case ExecutionMode::CoalescingAMDX: return "CoalescingAMDX";
+    case ExecutionMode::IsApiEntryAMDX: return "IsApiEntryAMDX";
+    case ExecutionMode::MaxNodeRecursionAMDX: return "MaxNodeRecursionAMDX";
+    case ExecutionMode::StaticNumWorkgroupsAMDX: return "StaticNumWorkgroupsAMDX";
+    case ExecutionMode::ShaderIndexAMDX: return "ShaderIndexAMDX";
+    case ExecutionMode::MaxNumWorkgroupsAMDX: return "MaxNumWorkgroupsAMDX";
+    case ExecutionMode::StencilRefUnchangedFrontAMD: return "StencilRefUnchangedFrontAMD";
+    case ExecutionMode::StencilRefGreaterFrontAMD: return "StencilRefGreaterFrontAMD";
+    case ExecutionMode::StencilRefLessFrontAMD: return "StencilRefLessFrontAMD";
+    case ExecutionMode::StencilRefUnchangedBackAMD: return "StencilRefUnchangedBackAMD";
+    case ExecutionMode::StencilRefGreaterBackAMD: return "StencilRefGreaterBackAMD";
+    case ExecutionMode::StencilRefLessBackAMD: return "StencilRefLessBackAMD";
+    case ExecutionMode::QuadDerivativesKHR: return "QuadDerivativesKHR";
+    case ExecutionMode::RequireFullQuadsKHR: return "RequireFullQuadsKHR";
+    case ExecutionMode::SharesInputWithAMDX: return "SharesInputWithAMDX";
+    case ExecutionMode::OutputLinesEXT: return "OutputLinesEXT";
+    case ExecutionMode::OutputPrimitivesEXT: return "OutputPrimitivesEXT";
+    case ExecutionMode::DerivativeGroupQuadsKHR: return "DerivativeGroupQuadsKHR";
+    case ExecutionMode::DerivativeGroupLinearKHR: return "DerivativeGroupLinearKHR";
+    case ExecutionMode::OutputTrianglesEXT: return "OutputTrianglesEXT";
+    case ExecutionMode::PixelInterlockOrderedEXT: return "PixelInterlockOrderedEXT";
+    case ExecutionMode::PixelInterlockUnorderedEXT: return "PixelInterlockUnorderedEXT";
+    case ExecutionMode::SampleInterlockOrderedEXT: return "SampleInterlockOrderedEXT";
+    case ExecutionMode::SampleInterlockUnorderedEXT: return "SampleInterlockUnorderedEXT";
+    case ExecutionMode::ShadingRateInterlockOrderedEXT: return "ShadingRateInterlockOrderedEXT";
+    case ExecutionMode::ShadingRateInterlockUnorderedEXT: return "ShadingRateInterlockUnorderedEXT";
+    case ExecutionMode::SharedLocalMemorySizeINTEL: return "SharedLocalMemorySizeINTEL";
+    case ExecutionMode::RoundingModeRTPINTEL: return "RoundingModeRTPINTEL";
+    case ExecutionMode::RoundingModeRTNINTEL: return "RoundingModeRTNINTEL";
+    case ExecutionMode::FloatingPointModeALTINTEL: return "FloatingPointModeALTINTEL";
+    case ExecutionMode::FloatingPointModeIEEEINTEL: return "FloatingPointModeIEEEINTEL";
+    case ExecutionMode::MaxWorkgroupSizeINTEL: return "MaxWorkgroupSizeINTEL";
+    case ExecutionMode::MaxWorkDimINTEL: return "MaxWorkDimINTEL";
+    case ExecutionMode::NoGlobalOffsetINTEL: return "NoGlobalOffsetINTEL";
+    case ExecutionMode::NumSIMDWorkitemsINTEL: return "NumSIMDWorkitemsINTEL";
+    case ExecutionMode::SchedulerTargetFmaxMhzINTEL: return "SchedulerTargetFmaxMhzINTEL";
+    case ExecutionMode::MaximallyReconvergesKHR: return "MaximallyReconvergesKHR";
+    case ExecutionMode::FPFastMathDefault: return "FPFastMathDefault";
+    case ExecutionMode::StreamingInterfaceINTEL: return "StreamingInterfaceINTEL";
+    case ExecutionMode::RegisterMapInterfaceINTEL: return "RegisterMapInterfaceINTEL";
+    case ExecutionMode::NamedBarrierCountINTEL: return "NamedBarrierCountINTEL";
+    case ExecutionMode::MaximumRegistersINTEL: return "MaximumRegistersINTEL";
+    case ExecutionMode::MaximumRegistersIdINTEL: return "MaximumRegistersIdINTEL";
+    case ExecutionMode::NamedMaximumRegistersINTEL: return "NamedMaximumRegistersINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* StorageClassToString(StorageClass value) {
+    switch (value) {
+    case StorageClass::UniformConstant: return "UniformConstant";
+    case StorageClass::Input: return "Input";
+    case StorageClass::Uniform: return "Uniform";
+    case StorageClass::Output: return "Output";
+    case StorageClass::Workgroup: return "Workgroup";
+    case StorageClass::CrossWorkgroup: return "CrossWorkgroup";
+    case StorageClass::Private: return "Private";
+    case StorageClass::Function: return "Function";
+    case StorageClass::Generic: return "Generic";
+    case StorageClass::PushConstant: return "PushConstant";
+    case StorageClass::AtomicCounter: return "AtomicCounter";
+    case StorageClass::Image: return "Image";
+    case StorageClass::StorageBuffer: return "StorageBuffer";
+    case StorageClass::TileImageEXT: return "TileImageEXT";
+    case StorageClass::NodePayloadAMDX: return "NodePayloadAMDX";
+    case StorageClass::CallableDataKHR: return "CallableDataKHR";
+    case StorageClass::IncomingCallableDataKHR: return "IncomingCallableDataKHR";
+    case StorageClass::RayPayloadKHR: return "RayPayloadKHR";
+    case StorageClass::HitAttributeKHR: return "HitAttributeKHR";
+    case StorageClass::IncomingRayPayloadKHR: return "IncomingRayPayloadKHR";
+    case StorageClass::ShaderRecordBufferKHR: return "ShaderRecordBufferKHR";
+    case StorageClass::PhysicalStorageBuffer: return "PhysicalStorageBuffer";
+    case StorageClass::HitObjectAttributeNV: return "HitObjectAttributeNV";
+    case StorageClass::TaskPayloadWorkgroupEXT: return "TaskPayloadWorkgroupEXT";
+    case StorageClass::CodeSectionINTEL: return "CodeSectionINTEL";
+    case StorageClass::DeviceOnlyINTEL: return "DeviceOnlyINTEL";
+    case StorageClass::HostOnlyINTEL: return "HostOnlyINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* DimToString(Dim value) {
+    switch (value) {
+    case Dim::Dim1D: return "1D";
+    case Dim::Dim2D: return "2D";
+    case Dim::Dim3D: return "3D";
+    case Dim::Cube: return "Cube";
+    case Dim::Rect: return "Rect";
+    case Dim::Buffer: return "Buffer";
+    case Dim::SubpassData: return "SubpassData";
+    case Dim::TileImageDataEXT: return "TileImageDataEXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SamplerAddressingModeToString(SamplerAddressingMode value) {
+    switch (value) {
+    case SamplerAddressingMode::None: return "None";
+    case SamplerAddressingMode::ClampToEdge: return "ClampToEdge";
+    case SamplerAddressingMode::Clamp: return "Clamp";
+    case SamplerAddressingMode::Repeat: return "Repeat";
+    case SamplerAddressingMode::RepeatMirrored: return "RepeatMirrored";
+    default: return "Unknown";
+    }
+}
+
+inline const char* SamplerFilterModeToString(SamplerFilterMode value) {
+    switch (value) {
+    case SamplerFilterMode::Nearest: return "Nearest";
+    case SamplerFilterMode::Linear: return "Linear";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ImageFormatToString(ImageFormat value) {
+    switch (value) {
+    case ImageFormat::Unknown: return "Unknown";
+    case ImageFormat::Rgba32f: return "Rgba32f";
+    case ImageFormat::Rgba16f: return "Rgba16f";
+    case ImageFormat::R32f: return "R32f";
+    case ImageFormat::Rgba8: return "Rgba8";
+    case ImageFormat::Rgba8Snorm: return "Rgba8Snorm";
+    case ImageFormat::Rg32f: return "Rg32f";
+    case ImageFormat::Rg16f: return "Rg16f";
+    case ImageFormat::R11fG11fB10f: return "R11fG11fB10f";
+    case ImageFormat::R16f: return "R16f";
+    case ImageFormat::Rgba16: return "Rgba16";
+    case ImageFormat::Rgb10A2: return "Rgb10A2";
+    case ImageFormat::Rg16: return "Rg16";
+    case ImageFormat::Rg8: return "Rg8";
+    case ImageFormat::R16: return "R16";
+    case ImageFormat::R8: return "R8";
+    case ImageFormat::Rgba16Snorm: return "Rgba16Snorm";
+    case ImageFormat::Rg16Snorm: return "Rg16Snorm";
+    case ImageFormat::Rg8Snorm: return "Rg8Snorm";
+    case ImageFormat::R16Snorm: return "R16Snorm";
+    case ImageFormat::R8Snorm: return "R8Snorm";
+    case ImageFormat::Rgba32i: return "Rgba32i";
+    case ImageFormat::Rgba16i: return "Rgba16i";
+    case ImageFormat::Rgba8i: return "Rgba8i";
+    case ImageFormat::R32i: return "R32i";
+    case ImageFormat::Rg32i: return "Rg32i";
+    case ImageFormat::Rg16i: return "Rg16i";
+    case ImageFormat::Rg8i: return "Rg8i";
+    case ImageFormat::R16i: return "R16i";
+    case ImageFormat::R8i: return "R8i";
+    case ImageFormat::Rgba32ui: return "Rgba32ui";
+    case ImageFormat::Rgba16ui: return "Rgba16ui";
+    case ImageFormat::Rgba8ui: return "Rgba8ui";
+    case ImageFormat::R32ui: return "R32ui";
+    case ImageFormat::Rgb10a2ui: return "Rgb10a2ui";
+    case ImageFormat::Rg32ui: return "Rg32ui";
+    case ImageFormat::Rg16ui: return "Rg16ui";
+    case ImageFormat::Rg8ui: return "Rg8ui";
+    case ImageFormat::R16ui: return "R16ui";
+    case ImageFormat::R8ui: return "R8ui";
+    case ImageFormat::R64ui: return "R64ui";
+    case ImageFormat::R64i: return "R64i";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ImageChannelOrderToString(ImageChannelOrder value) {
+    switch (value) {
+    case ImageChannelOrder::R: return "R";
+    case ImageChannelOrder::A: return "A";
+    case ImageChannelOrder::RG: return "RG";
+    case ImageChannelOrder::RA: return "RA";
+    case ImageChannelOrder::RGB: return "RGB";
+    case ImageChannelOrder::RGBA: return "RGBA";
+    case ImageChannelOrder::BGRA: return "BGRA";
+    case ImageChannelOrder::ARGB: return "ARGB";
+    case ImageChannelOrder::Intensity: return "Intensity";
+    case ImageChannelOrder::Luminance: return "Luminance";
+    case ImageChannelOrder::Rx: return "Rx";
+    case ImageChannelOrder::RGx: return "RGx";
+    case ImageChannelOrder::RGBx: return "RGBx";
+    case ImageChannelOrder::Depth: return "Depth";
+    case ImageChannelOrder::DepthStencil: return "DepthStencil";
+    case ImageChannelOrder::sRGB: return "sRGB";
+    case ImageChannelOrder::sRGBx: return "sRGBx";
+    case ImageChannelOrder::sRGBA: return "sRGBA";
+    case ImageChannelOrder::sBGRA: return "sBGRA";
+    case ImageChannelOrder::ABGR: return "ABGR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ImageChannelDataTypeToString(ImageChannelDataType value) {
+    switch (value) {
+    case ImageChannelDataType::SnormInt8: return "SnormInt8";
+    case ImageChannelDataType::SnormInt16: return "SnormInt16";
+    case ImageChannelDataType::UnormInt8: return "UnormInt8";
+    case ImageChannelDataType::UnormInt16: return "UnormInt16";
+    case ImageChannelDataType::UnormShort565: return "UnormShort565";
+    case ImageChannelDataType::UnormShort555: return "UnormShort555";
+    case ImageChannelDataType::UnormInt101010: return "UnormInt101010";
+    case ImageChannelDataType::SignedInt8: return "SignedInt8";
+    case ImageChannelDataType::SignedInt16: return "SignedInt16";
+    case ImageChannelDataType::SignedInt32: return "SignedInt32";
+    case ImageChannelDataType::UnsignedInt8: return "UnsignedInt8";
+    case ImageChannelDataType::UnsignedInt16: return "UnsignedInt16";
+    case ImageChannelDataType::UnsignedInt32: return "UnsignedInt32";
+    case ImageChannelDataType::HalfFloat: return "HalfFloat";
+    case ImageChannelDataType::Float: return "Float";
+    case ImageChannelDataType::UnormInt24: return "UnormInt24";
+    case ImageChannelDataType::UnormInt101010_2: return "UnormInt101010_2";
+    case ImageChannelDataType::UnsignedIntRaw10EXT: return "UnsignedIntRaw10EXT";
+    case ImageChannelDataType::UnsignedIntRaw12EXT: return "UnsignedIntRaw12EXT";
+    case ImageChannelDataType::UnormInt2_101010EXT: return "UnormInt2_101010EXT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FPRoundingModeToString(FPRoundingMode value) {
+    switch (value) {
+    case FPRoundingMode::RTE: return "RTE";
+    case FPRoundingMode::RTZ: return "RTZ";
+    case FPRoundingMode::RTP: return "RTP";
+    case FPRoundingMode::RTN: return "RTN";
+    default: return "Unknown";
+    }
+}
+
+inline const char* LinkageTypeToString(LinkageType value) {
+    switch (value) {
+    case LinkageType::Export: return "Export";
+    case LinkageType::Import: return "Import";
+    case LinkageType::LinkOnceODR: return "LinkOnceODR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* AccessQualifierToString(AccessQualifier value) {
+    switch (value) {
+    case AccessQualifier::ReadOnly: return "ReadOnly";
+    case AccessQualifier::WriteOnly: return "WriteOnly";
+    case AccessQualifier::ReadWrite: return "ReadWrite";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FunctionParameterAttributeToString(FunctionParameterAttribute value) {
+    switch (value) {
+    case FunctionParameterAttribute::Zext: return "Zext";
+    case FunctionParameterAttribute::Sext: return "Sext";
+    case FunctionParameterAttribute::ByVal: return "ByVal";
+    case FunctionParameterAttribute::Sret: return "Sret";
+    case FunctionParameterAttribute::NoAlias: return "NoAlias";
+    case FunctionParameterAttribute::NoCapture: return "NoCapture";
+    case FunctionParameterAttribute::NoWrite: return "NoWrite";
+    case FunctionParameterAttribute::NoReadWrite: return "NoReadWrite";
+    case FunctionParameterAttribute::RuntimeAlignedINTEL: return "RuntimeAlignedINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* DecorationToString(Decoration value) {
+    switch (value) {
+    case Decoration::RelaxedPrecision: return "RelaxedPrecision";
+    case Decoration::SpecId: return "SpecId";
+    case Decoration::Block: return "Block";
+    case Decoration::BufferBlock: return "BufferBlock";
+    case Decoration::RowMajor: return "RowMajor";
+    case Decoration::ColMajor: return "ColMajor";
+    case Decoration::ArrayStride: return "ArrayStride";
+    case Decoration::MatrixStride: return "MatrixStride";
+    case Decoration::GLSLShared: return "GLSLShared";
+    case Decoration::GLSLPacked: return "GLSLPacked";
+    case Decoration::CPacked: return "CPacked";
+    case Decoration::BuiltIn: return "BuiltIn";
+    case Decoration::NoPerspective: return "NoPerspective";
+    case Decoration::Flat: return "Flat";
+    case Decoration::Patch: return "Patch";
+    case Decoration::Centroid: return "Centroid";
+    case Decoration::Sample: return "Sample";
+    case Decoration::Invariant: return "Invariant";
+    case Decoration::Restrict: return "Restrict";
+    case Decoration::Aliased: return "Aliased";
+    case Decoration::Volatile: return "Volatile";
+    case Decoration::Constant: return "Constant";
+    case Decoration::Coherent: return "Coherent";
+    case Decoration::NonWritable: return "NonWritable";
+    case Decoration::NonReadable: return "NonReadable";
+    case Decoration::Uniform: return "Uniform";
+    case Decoration::UniformId: return "UniformId";
+    case Decoration::SaturatedConversion: return "SaturatedConversion";
+    case Decoration::Stream: return "Stream";
+    case Decoration::Location: return "Location";
+    case Decoration::Component: return "Component";
+    case Decoration::Index: return "Index";
+    case Decoration::Binding: return "Binding";
+    case Decoration::DescriptorSet: return "DescriptorSet";
+    case Decoration::Offset: return "Offset";
+    case Decoration::XfbBuffer: return "XfbBuffer";
+    case Decoration::XfbStride: return "XfbStride";
+    case Decoration::FuncParamAttr: return "FuncParamAttr";
+    case Decoration::FPRoundingMode: return "FPRoundingMode";
+    case Decoration::FPFastMathMode: return "FPFastMathMode";
+    case Decoration::LinkageAttributes: return "LinkageAttributes";
+    case Decoration::NoContraction: return "NoContraction";
+    case Decoration::InputAttachmentIndex: return "InputAttachmentIndex";
+    case Decoration::Alignment: return "Alignment";
+    case Decoration::MaxByteOffset: return "MaxByteOffset";
+    case Decoration::AlignmentId: return "AlignmentId";
+    case Decoration::MaxByteOffsetId: return "MaxByteOffsetId";
+    case Decoration::NoSignedWrap: return "NoSignedWrap";
+    case Decoration::NoUnsignedWrap: return "NoUnsignedWrap";
+    case Decoration::WeightTextureQCOM: return "WeightTextureQCOM";
+    case Decoration::BlockMatchTextureQCOM: return "BlockMatchTextureQCOM";
+    case Decoration::BlockMatchSamplerQCOM: return "BlockMatchSamplerQCOM";
+    case Decoration::ExplicitInterpAMD: return "ExplicitInterpAMD";
+    case Decoration::NodeSharesPayloadLimitsWithAMDX: return "NodeSharesPayloadLimitsWithAMDX";
+    case Decoration::NodeMaxPayloadsAMDX: return "NodeMaxPayloadsAMDX";
+    case Decoration::TrackFinishWritingAMDX: return "TrackFinishWritingAMDX";
+    case Decoration::PayloadNodeNameAMDX: return "PayloadNodeNameAMDX";
+    case Decoration::PayloadNodeBaseIndexAMDX: return "PayloadNodeBaseIndexAMDX";
+    case Decoration::PayloadNodeSparseArrayAMDX: return "PayloadNodeSparseArrayAMDX";
+    case Decoration::PayloadNodeArraySizeAMDX: return "PayloadNodeArraySizeAMDX";
+    case Decoration::PayloadDispatchIndirectAMDX: return "PayloadDispatchIndirectAMDX";
+    case Decoration::OverrideCoverageNV: return "OverrideCoverageNV";
+    case Decoration::PassthroughNV: return "PassthroughNV";
+    case Decoration::ViewportRelativeNV: return "ViewportRelativeNV";
+    case Decoration::SecondaryViewportRelativeNV: return "SecondaryViewportRelativeNV";
+    case Decoration::PerPrimitiveEXT: return "PerPrimitiveEXT";
+    case Decoration::PerViewNV: return "PerViewNV";
+    case Decoration::PerTaskNV: return "PerTaskNV";
+    case Decoration::PerVertexKHR: return "PerVertexKHR";
+    case Decoration::NonUniform: return "NonUniform";
+    case Decoration::RestrictPointer: return "RestrictPointer";
+    case Decoration::AliasedPointer: return "AliasedPointer";
+    case Decoration::HitObjectShaderRecordBufferNV: return "HitObjectShaderRecordBufferNV";
+    case Decoration::BindlessSamplerNV: return "BindlessSamplerNV";
+    case Decoration::BindlessImageNV: return "BindlessImageNV";
+    case Decoration::BoundSamplerNV: return "BoundSamplerNV";
+    case Decoration::BoundImageNV: return "BoundImageNV";
+    case Decoration::SIMTCallINTEL: return "SIMTCallINTEL";
+    case Decoration::ReferencedIndirectlyINTEL: return "ReferencedIndirectlyINTEL";
+    case Decoration::ClobberINTEL: return "ClobberINTEL";
+    case Decoration::SideEffectsINTEL: return "SideEffectsINTEL";
+    case Decoration::VectorComputeVariableINTEL: return "VectorComputeVariableINTEL";
+    case Decoration::FuncParamIOKindINTEL: return "FuncParamIOKindINTEL";
+    case Decoration::VectorComputeFunctionINTEL: return "VectorComputeFunctionINTEL";
+    case Decoration::StackCallINTEL: return "StackCallINTEL";
+    case Decoration::GlobalVariableOffsetINTEL: return "GlobalVariableOffsetINTEL";
+    case Decoration::CounterBuffer: return "CounterBuffer";
+    case Decoration::HlslSemanticGOOGLE: return "HlslSemanticGOOGLE";
+    case Decoration::UserTypeGOOGLE: return "UserTypeGOOGLE";
+    case Decoration::FunctionRoundingModeINTEL: return "FunctionRoundingModeINTEL";
+    case Decoration::FunctionDenormModeINTEL: return "FunctionDenormModeINTEL";
+    case Decoration::RegisterINTEL: return "RegisterINTEL";
+    case Decoration::MemoryINTEL: return "MemoryINTEL";
+    case Decoration::NumbanksINTEL: return "NumbanksINTEL";
+    case Decoration::BankwidthINTEL: return "BankwidthINTEL";
+    case Decoration::MaxPrivateCopiesINTEL: return "MaxPrivateCopiesINTEL";
+    case Decoration::SinglepumpINTEL: return "SinglepumpINTEL";
+    case Decoration::DoublepumpINTEL: return "DoublepumpINTEL";
+    case Decoration::MaxReplicatesINTEL: return "MaxReplicatesINTEL";
+    case Decoration::SimpleDualPortINTEL: return "SimpleDualPortINTEL";
+    case Decoration::MergeINTEL: return "MergeINTEL";
+    case Decoration::BankBitsINTEL: return "BankBitsINTEL";
+    case Decoration::ForcePow2DepthINTEL: return "ForcePow2DepthINTEL";
+    case Decoration::StridesizeINTEL: return "StridesizeINTEL";
+    case Decoration::WordsizeINTEL: return "WordsizeINTEL";
+    case Decoration::TrueDualPortINTEL: return "TrueDualPortINTEL";
+    case Decoration::BurstCoalesceINTEL: return "BurstCoalesceINTEL";
+    case Decoration::CacheSizeINTEL: return "CacheSizeINTEL";
+    case Decoration::DontStaticallyCoalesceINTEL: return "DontStaticallyCoalesceINTEL";
+    case Decoration::PrefetchINTEL: return "PrefetchINTEL";
+    case Decoration::StallEnableINTEL: return "StallEnableINTEL";
+    case Decoration::FuseLoopsInFunctionINTEL: return "FuseLoopsInFunctionINTEL";
+    case Decoration::MathOpDSPModeINTEL: return "MathOpDSPModeINTEL";
+    case Decoration::AliasScopeINTEL: return "AliasScopeINTEL";
+    case Decoration::NoAliasINTEL: return "NoAliasINTEL";
+    case Decoration::InitiationIntervalINTEL: return "InitiationIntervalINTEL";
+    case Decoration::MaxConcurrencyINTEL: return "MaxConcurrencyINTEL";
+    case Decoration::PipelineEnableINTEL: return "PipelineEnableINTEL";
+    case Decoration::BufferLocationINTEL: return "BufferLocationINTEL";
+    case Decoration::IOPipeStorageINTEL: return "IOPipeStorageINTEL";
+    case Decoration::FunctionFloatingPointModeINTEL: return "FunctionFloatingPointModeINTEL";
+    case Decoration::SingleElementVectorINTEL: return "SingleElementVectorINTEL";
+    case Decoration::VectorComputeCallableFunctionINTEL: return "VectorComputeCallableFunctionINTEL";
+    case Decoration::MediaBlockIOINTEL: return "MediaBlockIOINTEL";
+    case Decoration::StallFreeINTEL: return "StallFreeINTEL";
+    case Decoration::FPMaxErrorDecorationINTEL: return "FPMaxErrorDecorationINTEL";
+    case Decoration::LatencyControlLabelINTEL: return "LatencyControlLabelINTEL";
+    case Decoration::LatencyControlConstraintINTEL: return "LatencyControlConstraintINTEL";
+    case Decoration::ConduitKernelArgumentINTEL: return "ConduitKernelArgumentINTEL";
+    case Decoration::RegisterMapKernelArgumentINTEL: return "RegisterMapKernelArgumentINTEL";
+    case Decoration::MMHostInterfaceAddressWidthINTEL: return "MMHostInterfaceAddressWidthINTEL";
+    case Decoration::MMHostInterfaceDataWidthINTEL: return "MMHostInterfaceDataWidthINTEL";
+    case Decoration::MMHostInterfaceLatencyINTEL: return "MMHostInterfaceLatencyINTEL";
+    case Decoration::MMHostInterfaceReadWriteModeINTEL: return "MMHostInterfaceReadWriteModeINTEL";
+    case Decoration::MMHostInterfaceMaxBurstINTEL: return "MMHostInterfaceMaxBurstINTEL";
+    case Decoration::MMHostInterfaceWaitRequestINTEL: return "MMHostInterfaceWaitRequestINTEL";
+    case Decoration::StableKernelArgumentINTEL: return "StableKernelArgumentINTEL";
+    case Decoration::HostAccessINTEL: return "HostAccessINTEL";
+    case Decoration::InitModeINTEL: return "InitModeINTEL";
+    case Decoration::ImplementInRegisterMapINTEL: return "ImplementInRegisterMapINTEL";
+    case Decoration::CacheControlLoadINTEL: return "CacheControlLoadINTEL";
+    case Decoration::CacheControlStoreINTEL: return "CacheControlStoreINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* BuiltInToString(BuiltIn value) {
+    switch (value) {
+    case BuiltIn::Position: return "Position";
+    case BuiltIn::PointSize: return "PointSize";
+    case BuiltIn::ClipDistance: return "ClipDistance";
+    case BuiltIn::CullDistance: return "CullDistance";
+    case BuiltIn::VertexId: return "VertexId";
+    case BuiltIn::InstanceId: return "InstanceId";
+    case BuiltIn::PrimitiveId: return "PrimitiveId";
+    case BuiltIn::InvocationId: return "InvocationId";
+    case BuiltIn::Layer: return "Layer";
+    case BuiltIn::ViewportIndex: return "ViewportIndex";
+    case BuiltIn::TessLevelOuter: return "TessLevelOuter";
+    case BuiltIn::TessLevelInner: return "TessLevelInner";
+    case BuiltIn::TessCoord: return "TessCoord";
+    case BuiltIn::PatchVertices: return "PatchVertices";
+    case BuiltIn::FragCoord: return "FragCoord";
+    case BuiltIn::PointCoord: return "PointCoord";
+    case BuiltIn::FrontFacing: return "FrontFacing";
+    case BuiltIn::SampleId: return "SampleId";
+    case BuiltIn::SamplePosition: return "SamplePosition";
+    case BuiltIn::SampleMask: return "SampleMask";
+    case BuiltIn::FragDepth: return "FragDepth";
+    case BuiltIn::HelperInvocation: return "HelperInvocation";
+    case BuiltIn::NumWorkgroups: return "NumWorkgroups";
+    case BuiltIn::WorkgroupSize: return "WorkgroupSize";
+    case BuiltIn::WorkgroupId: return "WorkgroupId";
+    case BuiltIn::LocalInvocationId: return "LocalInvocationId";
+    case BuiltIn::GlobalInvocationId: return "GlobalInvocationId";
+    case BuiltIn::LocalInvocationIndex: return "LocalInvocationIndex";
+    case BuiltIn::WorkDim: return "WorkDim";
+    case BuiltIn::GlobalSize: return "GlobalSize";
+    case BuiltIn::EnqueuedWorkgroupSize: return "EnqueuedWorkgroupSize";
+    case BuiltIn::GlobalOffset: return "GlobalOffset";
+    case BuiltIn::GlobalLinearId: return "GlobalLinearId";
+    case BuiltIn::SubgroupSize: return "SubgroupSize";
+    case BuiltIn::SubgroupMaxSize: return "SubgroupMaxSize";
+    case BuiltIn::NumSubgroups: return "NumSubgroups";
+    case BuiltIn::NumEnqueuedSubgroups: return "NumEnqueuedSubgroups";
+    case BuiltIn::SubgroupId: return "SubgroupId";
+    case BuiltIn::SubgroupLocalInvocationId: return "SubgroupLocalInvocationId";
+    case BuiltIn::VertexIndex: return "VertexIndex";
+    case BuiltIn::InstanceIndex: return "InstanceIndex";
+    case BuiltIn::CoreIDARM: return "CoreIDARM";
+    case BuiltIn::CoreCountARM: return "CoreCountARM";
+    case BuiltIn::CoreMaxIDARM: return "CoreMaxIDARM";
+    case BuiltIn::WarpIDARM: return "WarpIDARM";
+    case BuiltIn::WarpMaxIDARM: return "WarpMaxIDARM";
+    case BuiltIn::SubgroupEqMask: return "SubgroupEqMask";
+    case BuiltIn::SubgroupGeMask: return "SubgroupGeMask";
+    case BuiltIn::SubgroupGtMask: return "SubgroupGtMask";
+    case BuiltIn::SubgroupLeMask: return "SubgroupLeMask";
+    case BuiltIn::SubgroupLtMask: return "SubgroupLtMask";
+    case BuiltIn::BaseVertex: return "BaseVertex";
+    case BuiltIn::BaseInstance: return "BaseInstance";
+    case BuiltIn::DrawIndex: return "DrawIndex";
+    case BuiltIn::PrimitiveShadingRateKHR: return "PrimitiveShadingRateKHR";
+    case BuiltIn::DeviceIndex: return "DeviceIndex";
+    case BuiltIn::ViewIndex: return "ViewIndex";
+    case BuiltIn::ShadingRateKHR: return "ShadingRateKHR";
+    case BuiltIn::BaryCoordNoPerspAMD: return "BaryCoordNoPerspAMD";
+    case BuiltIn::BaryCoordNoPerspCentroidAMD: return "BaryCoordNoPerspCentroidAMD";
+    case BuiltIn::BaryCoordNoPerspSampleAMD: return "BaryCoordNoPerspSampleAMD";
+    case BuiltIn::BaryCoordSmoothAMD: return "BaryCoordSmoothAMD";
+    case BuiltIn::BaryCoordSmoothCentroidAMD: return "BaryCoordSmoothCentroidAMD";
+    case BuiltIn::BaryCoordSmoothSampleAMD: return "BaryCoordSmoothSampleAMD";
+    case BuiltIn::BaryCoordPullModelAMD: return "BaryCoordPullModelAMD";
+    case BuiltIn::FragStencilRefEXT: return "FragStencilRefEXT";
+    case BuiltIn::RemainingRecursionLevelsAMDX: return "RemainingRecursionLevelsAMDX";
+    case BuiltIn::ShaderIndexAMDX: return "ShaderIndexAMDX";
+    case BuiltIn::ViewportMaskNV: return "ViewportMaskNV";
+    case BuiltIn::SecondaryPositionNV: return "SecondaryPositionNV";
+    case BuiltIn::SecondaryViewportMaskNV: return "SecondaryViewportMaskNV";
+    case BuiltIn::PositionPerViewNV: return "PositionPerViewNV";
+    case BuiltIn::ViewportMaskPerViewNV: return "ViewportMaskPerViewNV";
+    case BuiltIn::FullyCoveredEXT: return "FullyCoveredEXT";
+    case BuiltIn::TaskCountNV: return "TaskCountNV";
+    case BuiltIn::PrimitiveCountNV: return "PrimitiveCountNV";
+    case BuiltIn::PrimitiveIndicesNV: return "PrimitiveIndicesNV";
+    case BuiltIn::ClipDistancePerViewNV: return "ClipDistancePerViewNV";
+    case BuiltIn::CullDistancePerViewNV: return "CullDistancePerViewNV";
+    case BuiltIn::LayerPerViewNV: return "LayerPerViewNV";
+    case BuiltIn::MeshViewCountNV: return "MeshViewCountNV";
+    case BuiltIn::MeshViewIndicesNV: return "MeshViewIndicesNV";
+    case BuiltIn::BaryCoordKHR: return "BaryCoordKHR";
+    case BuiltIn::BaryCoordNoPerspKHR: return "BaryCoordNoPerspKHR";
+    case BuiltIn::FragSizeEXT: return "FragSizeEXT";
+    case BuiltIn::FragInvocationCountEXT: return "FragInvocationCountEXT";
+    case BuiltIn::PrimitivePointIndicesEXT: return "PrimitivePointIndicesEXT";
+    case BuiltIn::PrimitiveLineIndicesEXT: return "PrimitiveLineIndicesEXT";
+    case BuiltIn::PrimitiveTriangleIndicesEXT: return "PrimitiveTriangleIndicesEXT";
+    case BuiltIn::CullPrimitiveEXT: return "CullPrimitiveEXT";
+    case BuiltIn::LaunchIdKHR: return "LaunchIdKHR";
+    case BuiltIn::LaunchSizeKHR: return "LaunchSizeKHR";
+    case BuiltIn::WorldRayOriginKHR: return "WorldRayOriginKHR";
+    case BuiltIn::WorldRayDirectionKHR: return "WorldRayDirectionKHR";
+    case BuiltIn::ObjectRayOriginKHR: return "ObjectRayOriginKHR";
+    case BuiltIn::ObjectRayDirectionKHR: return "ObjectRayDirectionKHR";
+    case BuiltIn::RayTminKHR: return "RayTminKHR";
+    case BuiltIn::RayTmaxKHR: return "RayTmaxKHR";
+    case BuiltIn::InstanceCustomIndexKHR: return "InstanceCustomIndexKHR";
+    case BuiltIn::ObjectToWorldKHR: return "ObjectToWorldKHR";
+    case BuiltIn::WorldToObjectKHR: return "WorldToObjectKHR";
+    case BuiltIn::HitTNV: return "HitTNV";
+    case BuiltIn::HitKindKHR: return "HitKindKHR";
+    case BuiltIn::CurrentRayTimeNV: return "CurrentRayTimeNV";
+    case BuiltIn::HitTriangleVertexPositionsKHR: return "HitTriangleVertexPositionsKHR";
+    case BuiltIn::HitMicroTriangleVertexPositionsNV: return "HitMicroTriangleVertexPositionsNV";
+    case BuiltIn::HitMicroTriangleVertexBarycentricsNV: return "HitMicroTriangleVertexBarycentricsNV";
+    case BuiltIn::IncomingRayFlagsKHR: return "IncomingRayFlagsKHR";
+    case BuiltIn::RayGeometryIndexKHR: return "RayGeometryIndexKHR";
+    case BuiltIn::WarpsPerSMNV: return "WarpsPerSMNV";
+    case BuiltIn::SMCountNV: return "SMCountNV";
+    case BuiltIn::WarpIDNV: return "WarpIDNV";
+    case BuiltIn::SMIDNV: return "SMIDNV";
+    case BuiltIn::HitKindFrontFacingMicroTriangleNV: return "HitKindFrontFacingMicroTriangleNV";
+    case BuiltIn::HitKindBackFacingMicroTriangleNV: return "HitKindBackFacingMicroTriangleNV";
+    case BuiltIn::CullMaskKHR: return "CullMaskKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* ScopeToString(Scope value) {
+    switch (value) {
+    case Scope::CrossDevice: return "CrossDevice";
+    case Scope::Device: return "Device";
+    case Scope::Workgroup: return "Workgroup";
+    case Scope::Subgroup: return "Subgroup";
+    case Scope::Invocation: return "Invocation";
+    case Scope::QueueFamily: return "QueueFamily";
+    case Scope::ShaderCallKHR: return "ShaderCallKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* GroupOperationToString(GroupOperation value) {
+    switch (value) {
+    case GroupOperation::Reduce: return "Reduce";
+    case GroupOperation::InclusiveScan: return "InclusiveScan";
+    case GroupOperation::ExclusiveScan: return "ExclusiveScan";
+    case GroupOperation::ClusteredReduce: return "ClusteredReduce";
+    case GroupOperation::PartitionedReduceNV: return "PartitionedReduceNV";
+    case GroupOperation::PartitionedInclusiveScanNV: return "PartitionedInclusiveScanNV";
+    case GroupOperation::PartitionedExclusiveScanNV: return "PartitionedExclusiveScanNV";
+    default: return "Unknown";
+    }
+}
+
+inline const char* KernelEnqueueFlagsToString(KernelEnqueueFlags value) {
+    switch (value) {
+    case KernelEnqueueFlags::NoWait: return "NoWait";
+    case KernelEnqueueFlags::WaitKernel: return "WaitKernel";
+    case KernelEnqueueFlags::WaitWorkGroup: return "WaitWorkGroup";
+    default: return "Unknown";
+    }
+}
+
+inline const char* CapabilityToString(Capability value) {
+    switch (value) {
+    case Capability::Matrix: return "Matrix";
+    case Capability::Shader: return "Shader";
+    case Capability::Geometry: return "Geometry";
+    case Capability::Tessellation: return "Tessellation";
+    case Capability::Addresses: return "Addresses";
+    case Capability::Linkage: return "Linkage";
+    case Capability::Kernel: return "Kernel";
+    case Capability::Vector16: return "Vector16";
+    case Capability::Float16Buffer: return "Float16Buffer";
+    case Capability::Float16: return "Float16";
+    case Capability::Float64: return "Float64";
+    case Capability::Int64: return "Int64";
+    case Capability::Int64Atomics: return "Int64Atomics";
+    case Capability::ImageBasic: return "ImageBasic";
+    case Capability::ImageReadWrite: return "ImageReadWrite";
+    case Capability::ImageMipmap: return "ImageMipmap";
+    case Capability::Pipes: return "Pipes";
+    case Capability::Groups: return "Groups";
+    case Capability::DeviceEnqueue: return "DeviceEnqueue";
+    case Capability::LiteralSampler: return "LiteralSampler";
+    case Capability::AtomicStorage: return "AtomicStorage";
+    case Capability::Int16: return "Int16";
+    case Capability::TessellationPointSize: return "TessellationPointSize";
+    case Capability::GeometryPointSize: return "GeometryPointSize";
+    case Capability::ImageGatherExtended: return "ImageGatherExtended";
+    case Capability::StorageImageMultisample: return "StorageImageMultisample";
+    case Capability::UniformBufferArrayDynamicIndexing: return "UniformBufferArrayDynamicIndexing";
+    case Capability::SampledImageArrayDynamicIndexing: return "SampledImageArrayDynamicIndexing";
+    case Capability::StorageBufferArrayDynamicIndexing: return "StorageBufferArrayDynamicIndexing";
+    case Capability::StorageImageArrayDynamicIndexing: return "StorageImageArrayDynamicIndexing";
+    case Capability::ClipDistance: return "ClipDistance";
+    case Capability::CullDistance: return "CullDistance";
+    case Capability::ImageCubeArray: return "ImageCubeArray";
+    case Capability::SampleRateShading: return "SampleRateShading";
+    case Capability::ImageRect: return "ImageRect";
+    case Capability::SampledRect: return "SampledRect";
+    case Capability::GenericPointer: return "GenericPointer";
+    case Capability::Int8: return "Int8";
+    case Capability::InputAttachment: return "InputAttachment";
+    case Capability::SparseResidency: return "SparseResidency";
+    case Capability::MinLod: return "MinLod";
+    case Capability::Sampled1D: return "Sampled1D";
+    case Capability::Image1D: return "Image1D";
+    case Capability::SampledCubeArray: return "SampledCubeArray";
+    case Capability::SampledBuffer: return "SampledBuffer";
+    case Capability::ImageBuffer: return "ImageBuffer";
+    case Capability::ImageMSArray: return "ImageMSArray";
+    case Capability::StorageImageExtendedFormats: return "StorageImageExtendedFormats";
+    case Capability::ImageQuery: return "ImageQuery";
+    case Capability::DerivativeControl: return "DerivativeControl";
+    case Capability::InterpolationFunction: return "InterpolationFunction";
+    case Capability::TransformFeedback: return "TransformFeedback";
+    case Capability::GeometryStreams: return "GeometryStreams";
+    case Capability::StorageImageReadWithoutFormat: return "StorageImageReadWithoutFormat";
+    case Capability::StorageImageWriteWithoutFormat: return "StorageImageWriteWithoutFormat";
+    case Capability::MultiViewport: return "MultiViewport";
+    case Capability::SubgroupDispatch: return "SubgroupDispatch";
+    case Capability::NamedBarrier: return "NamedBarrier";
+    case Capability::PipeStorage: return "PipeStorage";
+    case Capability::GroupNonUniform: return "GroupNonUniform";
+    case Capability::GroupNonUniformVote: return "GroupNonUniformVote";
+    case Capability::GroupNonUniformArithmetic: return "GroupNonUniformArithmetic";
+    case Capability::GroupNonUniformBallot: return "GroupNonUniformBallot";
+    case Capability::GroupNonUniformShuffle: return "GroupNonUniformShuffle";
+    case Capability::GroupNonUniformShuffleRelative: return "GroupNonUniformShuffleRelative";
+    case Capability::GroupNonUniformClustered: return "GroupNonUniformClustered";
+    case Capability::GroupNonUniformQuad: return "GroupNonUniformQuad";
+    case Capability::ShaderLayer: return "ShaderLayer";
+    case Capability::ShaderViewportIndex: return "ShaderViewportIndex";
+    case Capability::UniformDecoration: return "UniformDecoration";
+    case Capability::CoreBuiltinsARM: return "CoreBuiltinsARM";
+    case Capability::TileImageColorReadAccessEXT: return "TileImageColorReadAccessEXT";
+    case Capability::TileImageDepthReadAccessEXT: return "TileImageDepthReadAccessEXT";
+    case Capability::TileImageStencilReadAccessEXT: return "TileImageStencilReadAccessEXT";
+    case Capability::CooperativeMatrixLayoutsARM: return "CooperativeMatrixLayoutsARM";
+    case Capability::FragmentShadingRateKHR: return "FragmentShadingRateKHR";
+    case Capability::SubgroupBallotKHR: return "SubgroupBallotKHR";
+    case Capability::DrawParameters: return "DrawParameters";
+    case Capability::WorkgroupMemoryExplicitLayoutKHR: return "WorkgroupMemoryExplicitLayoutKHR";
+    case Capability::WorkgroupMemoryExplicitLayout8BitAccessKHR: return "WorkgroupMemoryExplicitLayout8BitAccessKHR";
+    case Capability::WorkgroupMemoryExplicitLayout16BitAccessKHR: return "WorkgroupMemoryExplicitLayout16BitAccessKHR";
+    case Capability::SubgroupVoteKHR: return "SubgroupVoteKHR";
+    case Capability::StorageBuffer16BitAccess: return "StorageBuffer16BitAccess";
+    case Capability::StorageUniform16: return "StorageUniform16";
+    case Capability::StoragePushConstant16: return "StoragePushConstant16";
+    case Capability::StorageInputOutput16: return "StorageInputOutput16";
+    case Capability::DeviceGroup: return "DeviceGroup";
+    case Capability::MultiView: return "MultiView";
+    case Capability::VariablePointersStorageBuffer: return "VariablePointersStorageBuffer";
+    case Capability::VariablePointers: return "VariablePointers";
+    case Capability::AtomicStorageOps: return "AtomicStorageOps";
+    case Capability::SampleMaskPostDepthCoverage: return "SampleMaskPostDepthCoverage";
+    case Capability::StorageBuffer8BitAccess: return "StorageBuffer8BitAccess";
+    case Capability::UniformAndStorageBuffer8BitAccess: return "UniformAndStorageBuffer8BitAccess";
+    case Capability::StoragePushConstant8: return "StoragePushConstant8";
+    case Capability::DenormPreserve: return "DenormPreserve";
+    case Capability::DenormFlushToZero: return "DenormFlushToZero";
+    case Capability::SignedZeroInfNanPreserve: return "SignedZeroInfNanPreserve";
+    case Capability::RoundingModeRTE: return "RoundingModeRTE";
+    case Capability::RoundingModeRTZ: return "RoundingModeRTZ";
+    case Capability::RayQueryProvisionalKHR: return "RayQueryProvisionalKHR";
+    case Capability::RayQueryKHR: return "RayQueryKHR";
+    case Capability::UntypedPointersKHR: return "UntypedPointersKHR";
+    case Capability::RayTraversalPrimitiveCullingKHR: return "RayTraversalPrimitiveCullingKHR";
+    case Capability::RayTracingKHR: return "RayTracingKHR";
+    case Capability::TextureSampleWeightedQCOM: return "TextureSampleWeightedQCOM";
+    case Capability::TextureBoxFilterQCOM: return "TextureBoxFilterQCOM";
+    case Capability::TextureBlockMatchQCOM: return "TextureBlockMatchQCOM";
+    case Capability::TextureBlockMatch2QCOM: return "TextureBlockMatch2QCOM";
+    case Capability::Float16ImageAMD: return "Float16ImageAMD";
+    case Capability::ImageGatherBiasLodAMD: return "ImageGatherBiasLodAMD";
+    case Capability::FragmentMaskAMD: return "FragmentMaskAMD";
+    case Capability::StencilExportEXT: return "StencilExportEXT";
+    case Capability::ImageReadWriteLodAMD: return "ImageReadWriteLodAMD";
+    case Capability::Int64ImageEXT: return "Int64ImageEXT";
+    case Capability::ShaderClockKHR: return "ShaderClockKHR";
+    case Capability::ShaderEnqueueAMDX: return "ShaderEnqueueAMDX";
+    case Capability::QuadControlKHR: return "QuadControlKHR";
+    case Capability::SampleMaskOverrideCoverageNV: return "SampleMaskOverrideCoverageNV";
+    case Capability::GeometryShaderPassthroughNV: return "GeometryShaderPassthroughNV";
+    case Capability::ShaderViewportIndexLayerEXT: return "ShaderViewportIndexLayerEXT";
+    case Capability::ShaderViewportMaskNV: return "ShaderViewportMaskNV";
+    case Capability::ShaderStereoViewNV: return "ShaderStereoViewNV";
+    case Capability::PerViewAttributesNV: return "PerViewAttributesNV";
+    case Capability::FragmentFullyCoveredEXT: return "FragmentFullyCoveredEXT";
+    case Capability::MeshShadingNV: return "MeshShadingNV";
+    case Capability::ImageFootprintNV: return "ImageFootprintNV";
+    case Capability::MeshShadingEXT: return "MeshShadingEXT";
+    case Capability::FragmentBarycentricKHR: return "FragmentBarycentricKHR";
+    case Capability::ComputeDerivativeGroupQuadsKHR: return "ComputeDerivativeGroupQuadsKHR";
+    case Capability::FragmentDensityEXT: return "FragmentDensityEXT";
+    case Capability::GroupNonUniformPartitionedNV: return "GroupNonUniformPartitionedNV";
+    case Capability::ShaderNonUniform: return "ShaderNonUniform";
+    case Capability::RuntimeDescriptorArray: return "RuntimeDescriptorArray";
+    case Capability::InputAttachmentArrayDynamicIndexing: return "InputAttachmentArrayDynamicIndexing";
+    case Capability::UniformTexelBufferArrayDynamicIndexing: return "UniformTexelBufferArrayDynamicIndexing";
+    case Capability::StorageTexelBufferArrayDynamicIndexing: return "StorageTexelBufferArrayDynamicIndexing";
+    case Capability::UniformBufferArrayNonUniformIndexing: return "UniformBufferArrayNonUniformIndexing";
+    case Capability::SampledImageArrayNonUniformIndexing: return "SampledImageArrayNonUniformIndexing";
+    case Capability::StorageBufferArrayNonUniformIndexing: return "StorageBufferArrayNonUniformIndexing";
+    case Capability::StorageImageArrayNonUniformIndexing: return "StorageImageArrayNonUniformIndexing";
+    case Capability::InputAttachmentArrayNonUniformIndexing: return "InputAttachmentArrayNonUniformIndexing";
+    case Capability::UniformTexelBufferArrayNonUniformIndexing: return "UniformTexelBufferArrayNonUniformIndexing";
+    case Capability::StorageTexelBufferArrayNonUniformIndexing: return "StorageTexelBufferArrayNonUniformIndexing";
+    case Capability::RayTracingPositionFetchKHR: return "RayTracingPositionFetchKHR";
+    case Capability::RayTracingNV: return "RayTracingNV";
+    case Capability::RayTracingMotionBlurNV: return "RayTracingMotionBlurNV";
+    case Capability::VulkanMemoryModel: return "VulkanMemoryModel";
+    case Capability::VulkanMemoryModelDeviceScope: return "VulkanMemoryModelDeviceScope";
+    case Capability::PhysicalStorageBufferAddresses: return "PhysicalStorageBufferAddresses";
+    case Capability::ComputeDerivativeGroupLinearKHR: return "ComputeDerivativeGroupLinearKHR";
+    case Capability::RayTracingProvisionalKHR: return "RayTracingProvisionalKHR";
+    case Capability::CooperativeMatrixNV: return "CooperativeMatrixNV";
+    case Capability::FragmentShaderSampleInterlockEXT: return "FragmentShaderSampleInterlockEXT";
+    case Capability::FragmentShaderShadingRateInterlockEXT: return "FragmentShaderShadingRateInterlockEXT";
+    case Capability::ShaderSMBuiltinsNV: return "ShaderSMBuiltinsNV";
+    case Capability::FragmentShaderPixelInterlockEXT: return "FragmentShaderPixelInterlockEXT";
+    case Capability::DemoteToHelperInvocation: return "DemoteToHelperInvocation";
+    case Capability::DisplacementMicromapNV: return "DisplacementMicromapNV";
+    case Capability::RayTracingOpacityMicromapEXT: return "RayTracingOpacityMicromapEXT";
+    case Capability::ShaderInvocationReorderNV: return "ShaderInvocationReorderNV";
+    case Capability::BindlessTextureNV: return "BindlessTextureNV";
+    case Capability::RayQueryPositionFetchKHR: return "RayQueryPositionFetchKHR";
+    case Capability::AtomicFloat16VectorNV: return "AtomicFloat16VectorNV";
+    case Capability::RayTracingDisplacementMicromapNV: return "RayTracingDisplacementMicromapNV";
+    case Capability::RawAccessChainsNV: return "RawAccessChainsNV";
+    case Capability::CooperativeMatrixReductionsNV: return "CooperativeMatrixReductionsNV";
+    case Capability::CooperativeMatrixConversionsNV: return "CooperativeMatrixConversionsNV";
+    case Capability::CooperativeMatrixPerElementOperationsNV: return "CooperativeMatrixPerElementOperationsNV";
+    case Capability::CooperativeMatrixTensorAddressingNV: return "CooperativeMatrixTensorAddressingNV";
+    case Capability::CooperativeMatrixBlockLoadsNV: return "CooperativeMatrixBlockLoadsNV";
+    case Capability::TensorAddressingNV: return "TensorAddressingNV";
+    case Capability::SubgroupShuffleINTEL: return "SubgroupShuffleINTEL";
+    case Capability::SubgroupBufferBlockIOINTEL: return "SubgroupBufferBlockIOINTEL";
+    case Capability::SubgroupImageBlockIOINTEL: return "SubgroupImageBlockIOINTEL";
+    case Capability::SubgroupImageMediaBlockIOINTEL: return "SubgroupImageMediaBlockIOINTEL";
+    case Capability::RoundToInfinityINTEL: return "RoundToInfinityINTEL";
+    case Capability::FloatingPointModeINTEL: return "FloatingPointModeINTEL";
+    case Capability::IntegerFunctions2INTEL: return "IntegerFunctions2INTEL";
+    case Capability::FunctionPointersINTEL: return "FunctionPointersINTEL";
+    case Capability::IndirectReferencesINTEL: return "IndirectReferencesINTEL";
+    case Capability::AsmINTEL: return "AsmINTEL";
+    case Capability::AtomicFloat32MinMaxEXT: return "AtomicFloat32MinMaxEXT";
+    case Capability::AtomicFloat64MinMaxEXT: return "AtomicFloat64MinMaxEXT";
+    case Capability::AtomicFloat16MinMaxEXT: return "AtomicFloat16MinMaxEXT";
+    case Capability::VectorComputeINTEL: return "VectorComputeINTEL";
+    case Capability::VectorAnyINTEL: return "VectorAnyINTEL";
+    case Capability::ExpectAssumeKHR: return "ExpectAssumeKHR";
+    case Capability::SubgroupAvcMotionEstimationINTEL: return "SubgroupAvcMotionEstimationINTEL";
+    case Capability::SubgroupAvcMotionEstimationIntraINTEL: return "SubgroupAvcMotionEstimationIntraINTEL";
+    case Capability::SubgroupAvcMotionEstimationChromaINTEL: return "SubgroupAvcMotionEstimationChromaINTEL";
+    case Capability::VariableLengthArrayINTEL: return "VariableLengthArrayINTEL";
+    case Capability::FunctionFloatControlINTEL: return "FunctionFloatControlINTEL";
+    case Capability::FPGAMemoryAttributesINTEL: return "FPGAMemoryAttributesINTEL";
+    case Capability::FPFastMathModeINTEL: return "FPFastMathModeINTEL";
+    case Capability::ArbitraryPrecisionIntegersINTEL: return "ArbitraryPrecisionIntegersINTEL";
+    case Capability::ArbitraryPrecisionFloatingPointINTEL: return "ArbitraryPrecisionFloatingPointINTEL";
+    case Capability::UnstructuredLoopControlsINTEL: return "UnstructuredLoopControlsINTEL";
+    case Capability::FPGALoopControlsINTEL: return "FPGALoopControlsINTEL";
+    case Capability::KernelAttributesINTEL: return "KernelAttributesINTEL";
+    case Capability::FPGAKernelAttributesINTEL: return "FPGAKernelAttributesINTEL";
+    case Capability::FPGAMemoryAccessesINTEL: return "FPGAMemoryAccessesINTEL";
+    case Capability::FPGAClusterAttributesINTEL: return "FPGAClusterAttributesINTEL";
+    case Capability::LoopFuseINTEL: return "LoopFuseINTEL";
+    case Capability::FPGADSPControlINTEL: return "FPGADSPControlINTEL";
+    case Capability::MemoryAccessAliasingINTEL: return "MemoryAccessAliasingINTEL";
+    case Capability::FPGAInvocationPipeliningAttributesINTEL: return "FPGAInvocationPipeliningAttributesINTEL";
+    case Capability::FPGABufferLocationINTEL: return "FPGABufferLocationINTEL";
+    case Capability::ArbitraryPrecisionFixedPointINTEL: return "ArbitraryPrecisionFixedPointINTEL";
+    case Capability::USMStorageClassesINTEL: return "USMStorageClassesINTEL";
+    case Capability::RuntimeAlignedAttributeINTEL: return "RuntimeAlignedAttributeINTEL";
+    case Capability::IOPipesINTEL: return "IOPipesINTEL";
+    case Capability::BlockingPipesINTEL: return "BlockingPipesINTEL";
+    case Capability::FPGARegINTEL: return "FPGARegINTEL";
+    case Capability::DotProductInputAll: return "DotProductInputAll";
+    case Capability::DotProductInput4x8Bit: return "DotProductInput4x8Bit";
+    case Capability::DotProductInput4x8BitPacked: return "DotProductInput4x8BitPacked";
+    case Capability::DotProduct: return "DotProduct";
+    case Capability::RayCullMaskKHR: return "RayCullMaskKHR";
+    case Capability::CooperativeMatrixKHR: return "CooperativeMatrixKHR";
+    case Capability::ReplicatedCompositesEXT: return "ReplicatedCompositesEXT";
+    case Capability::BitInstructions: return "BitInstructions";
+    case Capability::GroupNonUniformRotateKHR: return "GroupNonUniformRotateKHR";
+    case Capability::FloatControls2: return "FloatControls2";
+    case Capability::AtomicFloat32AddEXT: return "AtomicFloat32AddEXT";
+    case Capability::AtomicFloat64AddEXT: return "AtomicFloat64AddEXT";
+    case Capability::LongCompositesINTEL: return "LongCompositesINTEL";
+    case Capability::OptNoneEXT: return "OptNoneEXT";
+    case Capability::AtomicFloat16AddEXT: return "AtomicFloat16AddEXT";
+    case Capability::DebugInfoModuleINTEL: return "DebugInfoModuleINTEL";
+    case Capability::BFloat16ConversionINTEL: return "BFloat16ConversionINTEL";
+    case Capability::SplitBarrierINTEL: return "SplitBarrierINTEL";
+    case Capability::ArithmeticFenceEXT: return "ArithmeticFenceEXT";
+    case Capability::FPGAClusterAttributesV2INTEL: return "FPGAClusterAttributesV2INTEL";
+    case Capability::FPGAKernelAttributesv2INTEL: return "FPGAKernelAttributesv2INTEL";
+    case Capability::FPMaxErrorINTEL: return "FPMaxErrorINTEL";
+    case Capability::FPGALatencyControlINTEL: return "FPGALatencyControlINTEL";
+    case Capability::FPGAArgumentInterfacesINTEL: return "FPGAArgumentInterfacesINTEL";
+    case Capability::GlobalVariableHostAccessINTEL: return "GlobalVariableHostAccessINTEL";
+    case Capability::GlobalVariableFPGADecorationsINTEL: return "GlobalVariableFPGADecorationsINTEL";
+    case Capability::SubgroupBufferPrefetchINTEL: return "SubgroupBufferPrefetchINTEL";
+    case Capability::GroupUniformArithmeticKHR: return "GroupUniformArithmeticKHR";
+    case Capability::MaskedGatherScatterINTEL: return "MaskedGatherScatterINTEL";
+    case Capability::CacheControlsINTEL: return "CacheControlsINTEL";
+    case Capability::RegisterLimitsINTEL: return "RegisterLimitsINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* RayQueryIntersectionToString(RayQueryIntersection value) {
+    switch (value) {
+    case RayQueryIntersection::RayQueryCandidateIntersectionKHR: return "RayQueryCandidateIntersectionKHR";
+    case RayQueryIntersection::RayQueryCommittedIntersectionKHR: return "RayQueryCommittedIntersectionKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* RayQueryCommittedIntersectionTypeToString(RayQueryCommittedIntersectionType value) {
+    switch (value) {
+    case RayQueryCommittedIntersectionType::RayQueryCommittedIntersectionNoneKHR: return "RayQueryCommittedIntersectionNoneKHR";
+    case RayQueryCommittedIntersectionType::RayQueryCommittedIntersectionTriangleKHR: return "RayQueryCommittedIntersectionTriangleKHR";
+    case RayQueryCommittedIntersectionType::RayQueryCommittedIntersectionGeneratedKHR: return "RayQueryCommittedIntersectionGeneratedKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* RayQueryCandidateIntersectionTypeToString(RayQueryCandidateIntersectionType value) {
+    switch (value) {
+    case RayQueryCandidateIntersectionType::RayQueryCandidateIntersectionTriangleKHR: return "RayQueryCandidateIntersectionTriangleKHR";
+    case RayQueryCandidateIntersectionType::RayQueryCandidateIntersectionAABBKHR: return "RayQueryCandidateIntersectionAABBKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FPDenormModeToString(FPDenormMode value) {
+    switch (value) {
+    case FPDenormMode::Preserve: return "Preserve";
+    case FPDenormMode::FlushToZero: return "FlushToZero";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FPOperationModeToString(FPOperationMode value) {
+    switch (value) {
+    case FPOperationMode::IEEE: return "IEEE";
+    case FPOperationMode::ALT: return "ALT";
+    default: return "Unknown";
+    }
+}
+
+inline const char* QuantizationModesToString(QuantizationModes value) {
+    switch (value) {
+    case QuantizationModes::TRN: return "TRN";
+    case QuantizationModes::TRN_ZERO: return "TRN_ZERO";
+    case QuantizationModes::RND: return "RND";
+    case QuantizationModes::RND_ZERO: return "RND_ZERO";
+    case QuantizationModes::RND_INF: return "RND_INF";
+    case QuantizationModes::RND_MIN_INF: return "RND_MIN_INF";
+    case QuantizationModes::RND_CONV: return "RND_CONV";
+    case QuantizationModes::RND_CONV_ODD: return "RND_CONV_ODD";
+    default: return "Unknown";
+    }
+}
+
+inline const char* OverflowModesToString(OverflowModes value) {
+    switch (value) {
+    case OverflowModes::WRAP: return "WRAP";
+    case OverflowModes::SAT: return "SAT";
+    case OverflowModes::SAT_ZERO: return "SAT_ZERO";
+    case OverflowModes::SAT_SYM: return "SAT_SYM";
+    default: return "Unknown";
+    }
+}
+
+inline const char* PackedVectorFormatToString(PackedVectorFormat value) {
+    switch (value) {
+    case PackedVectorFormat::PackedVectorFormat4x8Bit: return "PackedVectorFormat4x8Bit";
+    default: return "Unknown";
+    }
+}
+
+inline const char* CooperativeMatrixLayoutToString(CooperativeMatrixLayout value) {
+    switch (value) {
+    case CooperativeMatrixLayout::RowMajorKHR: return "RowMajorKHR";
+    case CooperativeMatrixLayout::ColumnMajorKHR: return "ColumnMajorKHR";
+    case CooperativeMatrixLayout::RowBlockedInterleavedARM: return "RowBlockedInterleavedARM";
+    case CooperativeMatrixLayout::ColumnBlockedInterleavedARM: return "ColumnBlockedInterleavedARM";
+    default: return "Unknown";
+    }
+}
+
+inline const char* CooperativeMatrixUseToString(CooperativeMatrixUse value) {
+    switch (value) {
+    case CooperativeMatrixUse::MatrixAKHR: return "MatrixAKHR";
+    case CooperativeMatrixUse::MatrixBKHR: return "MatrixBKHR";
+    case CooperativeMatrixUse::MatrixAccumulatorKHR: return "MatrixAccumulatorKHR";
+    default: return "Unknown";
+    }
+}
+
+inline const char* TensorClampModeToString(TensorClampMode value) {
+    switch (value) {
+    case TensorClampMode::Undefined: return "Undefined";
+    case TensorClampMode::Constant: return "Constant";
+    case TensorClampMode::ClampToEdge: return "ClampToEdge";
+    case TensorClampMode::Repeat: return "Repeat";
+    case TensorClampMode::RepeatMirrored: return "RepeatMirrored";
+    default: return "Unknown";
+    }
+}
+
+inline const char* InitializationModeQualifierToString(InitializationModeQualifier value) {
+    switch (value) {
+    case InitializationModeQualifier::InitOnDeviceReprogramINTEL: return "InitOnDeviceReprogramINTEL";
+    case InitializationModeQualifier::InitOnDeviceResetINTEL: return "InitOnDeviceResetINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* HostAccessQualifierToString(HostAccessQualifier value) {
+    switch (value) {
+    case HostAccessQualifier::NoneINTEL: return "NoneINTEL";
+    case HostAccessQualifier::ReadINTEL: return "ReadINTEL";
+    case HostAccessQualifier::WriteINTEL: return "WriteINTEL";
+    case HostAccessQualifier::ReadWriteINTEL: return "ReadWriteINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* LoadCacheControlToString(LoadCacheControl value) {
+    switch (value) {
+    case LoadCacheControl::UncachedINTEL: return "UncachedINTEL";
+    case LoadCacheControl::CachedINTEL: return "CachedINTEL";
+    case LoadCacheControl::StreamingINTEL: return "StreamingINTEL";
+    case LoadCacheControl::InvalidateAfterReadINTEL: return "InvalidateAfterReadINTEL";
+    case LoadCacheControl::ConstCachedINTEL: return "ConstCachedINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* StoreCacheControlToString(StoreCacheControl value) {
+    switch (value) {
+    case StoreCacheControl::UncachedINTEL: return "UncachedINTEL";
+    case StoreCacheControl::WriteThroughINTEL: return "WriteThroughINTEL";
+    case StoreCacheControl::WriteBackINTEL: return "WriteBackINTEL";
+    case StoreCacheControl::StreamingINTEL: return "StreamingINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* NamedMaximumNumberOfRegistersToString(NamedMaximumNumberOfRegisters value) {
+    switch (value) {
+    case NamedMaximumNumberOfRegisters::AutoINTEL: return "AutoINTEL";
+    default: return "Unknown";
+    }
+}
+
+inline const char* FPEncodingToString(FPEncoding value) {
+    switch (value) {
+    default: return "Unknown";
+    }
+}
+
+inline const char* OpToString(Op value) {
+    switch (value) {
+    case Op::OpNop: return "OpNop";
+    case Op::OpUndef: return "OpUndef";
+    case Op::OpSourceContinued: return "OpSourceContinued";
+    case Op::OpSource: return "OpSource";
+    case Op::OpSourceExtension: return "OpSourceExtension";
+    case Op::OpName: return "OpName";
+    case Op::OpMemberName: return "OpMemberName";
+    case Op::OpString: return "OpString";
+    case Op::OpLine: return "OpLine";
+    case Op::OpExtension: return "OpExtension";
+    case Op::OpExtInstImport: return "OpExtInstImport";
+    case Op::OpExtInst: return "OpExtInst";
+    case Op::OpMemoryModel: return "OpMemoryModel";
+    case Op::OpEntryPoint: return "OpEntryPoint";
+    case Op::OpExecutionMode: return "OpExecutionMode";
+    case Op::OpCapability: return "OpCapability";
+    case Op::OpTypeVoid: return "OpTypeVoid";
+    case Op::OpTypeBool: return "OpTypeBool";
+    case Op::OpTypeInt: return "OpTypeInt";
+    case Op::OpTypeFloat: return "OpTypeFloat";
+    case Op::OpTypeVector: return "OpTypeVector";
+    case Op::OpTypeMatrix: return "OpTypeMatrix";
+    case Op::OpTypeImage: return "OpTypeImage";
+    case Op::OpTypeSampler: return "OpTypeSampler";
+    case Op::OpTypeSampledImage: return "OpTypeSampledImage";
+    case Op::OpTypeArray: return "OpTypeArray";
+    case Op::OpTypeRuntimeArray: return "OpTypeRuntimeArray";
+    case Op::OpTypeStruct: return "OpTypeStruct";
+    case Op::OpTypeOpaque: return "OpTypeOpaque";
+    case Op::OpTypePointer: return "OpTypePointer";
+    case Op::OpTypeFunction: return "OpTypeFunction";
+    case Op::OpTypeEvent: return "OpTypeEvent";
+    case Op::OpTypeDeviceEvent: return "OpTypeDeviceEvent";
+    case Op::OpTypeReserveId: return "OpTypeReserveId";
+    case Op::OpTypeQueue: return "OpTypeQueue";
+    case Op::OpTypePipe: return "OpTypePipe";
+    case Op::OpTypeForwardPointer: return "OpTypeForwardPointer";
+    case Op::OpConstantTrue: return "OpConstantTrue";
+    case Op::OpConstantFalse: return "OpConstantFalse";
+    case Op::OpConstant: return "OpConstant";
+    case Op::OpConstantComposite: return "OpConstantComposite";
+    case Op::OpConstantSampler: return "OpConstantSampler";
+    case Op::OpConstantNull: return "OpConstantNull";
+    case Op::OpSpecConstantTrue: return "OpSpecConstantTrue";
+    case Op::OpSpecConstantFalse: return "OpSpecConstantFalse";
+    case Op::OpSpecConstant: return "OpSpecConstant";
+    case Op::OpSpecConstantComposite: return "OpSpecConstantComposite";
+    case Op::OpSpecConstantOp: return "OpSpecConstantOp";
+    case Op::OpFunction: return "OpFunction";
+    case Op::OpFunctionParameter: return "OpFunctionParameter";
+    case Op::OpFunctionEnd: return "OpFunctionEnd";
+    case Op::OpFunctionCall: return "OpFunctionCall";
+    case Op::OpVariable: return "OpVariable";
+    case Op::OpImageTexelPointer: return "OpImageTexelPointer";
+    case Op::OpLoad: return "OpLoad";
+    case Op::OpStore: return "OpStore";
+    case Op::OpCopyMemory: return "OpCopyMemory";
+    case Op::OpCopyMemorySized: return "OpCopyMemorySized";
+    case Op::OpAccessChain: return "OpAccessChain";
+    case Op::OpInBoundsAccessChain: return "OpInBoundsAccessChain";
+    case Op::OpPtrAccessChain: return "OpPtrAccessChain";
+    case Op::OpArrayLength: return "OpArrayLength";
+    case Op::OpGenericPtrMemSemantics: return "OpGenericPtrMemSemantics";
+    case Op::OpInBoundsPtrAccessChain: return "OpInBoundsPtrAccessChain";
+    case Op::OpDecorate: return "OpDecorate";
+    case Op::OpMemberDecorate: return "OpMemberDecorate";
+    case Op::OpDecorationGroup: return "OpDecorationGroup";
+    case Op::OpGroupDecorate: return "OpGroupDecorate";
+    case Op::OpGroupMemberDecorate: return "OpGroupMemberDecorate";
+    case Op::OpVectorExtractDynamic: return "OpVectorExtractDynamic";
+    case Op::OpVectorInsertDynamic: return "OpVectorInsertDynamic";
+    case Op::OpVectorShuffle: return "OpVectorShuffle";
+    case Op::OpCompositeConstruct: return "OpCompositeConstruct";
+    case Op::OpCompositeExtract: return "OpCompositeExtract";
+    case Op::OpCompositeInsert: return "OpCompositeInsert";
+    case Op::OpCopyObject: return "OpCopyObject";
+    case Op::OpTranspose: return "OpTranspose";
+    case Op::OpSampledImage: return "OpSampledImage";
+    case Op::OpImageSampleImplicitLod: return "OpImageSampleImplicitLod";
+    case Op::OpImageSampleExplicitLod: return "OpImageSampleExplicitLod";
+    case Op::OpImageSampleDrefImplicitLod: return "OpImageSampleDrefImplicitLod";
+    case Op::OpImageSampleDrefExplicitLod: return "OpImageSampleDrefExplicitLod";
+    case Op::OpImageSampleProjImplicitLod: return "OpImageSampleProjImplicitLod";
+    case Op::OpImageSampleProjExplicitLod: return "OpImageSampleProjExplicitLod";
+    case Op::OpImageSampleProjDrefImplicitLod: return "OpImageSampleProjDrefImplicitLod";
+    case Op::OpImageSampleProjDrefExplicitLod: return "OpImageSampleProjDrefExplicitLod";
+    case Op::OpImageFetch: return "OpImageFetch";
+    case Op::OpImageGather: return "OpImageGather";
+    case Op::OpImageDrefGather: return "OpImageDrefGather";
+    case Op::OpImageRead: return "OpImageRead";
+    case Op::OpImageWrite: return "OpImageWrite";
+    case Op::OpImage: return "OpImage";
+    case Op::OpImageQueryFormat: return "OpImageQueryFormat";
+    case Op::OpImageQueryOrder: return "OpImageQueryOrder";
+    case Op::OpImageQuerySizeLod: return "OpImageQuerySizeLod";
+    case Op::OpImageQuerySize: return "OpImageQuerySize";
+    case Op::OpImageQueryLod: return "OpImageQueryLod";
+    case Op::OpImageQueryLevels: return "OpImageQueryLevels";
+    case Op::OpImageQuerySamples: return "OpImageQuerySamples";
+    case Op::OpConvertFToU: return "OpConvertFToU";
+    case Op::OpConvertFToS: return "OpConvertFToS";
+    case Op::OpConvertSToF: return "OpConvertSToF";
+    case Op::OpConvertUToF: return "OpConvertUToF";
+    case Op::OpUConvert: return "OpUConvert";
+    case Op::OpSConvert: return "OpSConvert";
+    case Op::OpFConvert: return "OpFConvert";
+    case Op::OpQuantizeToF16: return "OpQuantizeToF16";
+    case Op::OpConvertPtrToU: return "OpConvertPtrToU";
+    case Op::OpSatConvertSToU: return "OpSatConvertSToU";
+    case Op::OpSatConvertUToS: return "OpSatConvertUToS";
+    case Op::OpConvertUToPtr: return "OpConvertUToPtr";
+    case Op::OpPtrCastToGeneric: return "OpPtrCastToGeneric";
+    case Op::OpGenericCastToPtr: return "OpGenericCastToPtr";
+    case Op::OpGenericCastToPtrExplicit: return "OpGenericCastToPtrExplicit";
+    case Op::OpBitcast: return "OpBitcast";
+    case Op::OpSNegate: return "OpSNegate";
+    case Op::OpFNegate: return "OpFNegate";
+    case Op::OpIAdd: return "OpIAdd";
+    case Op::OpFAdd: return "OpFAdd";
+    case Op::OpISub: return "OpISub";
+    case Op::OpFSub: return "OpFSub";
+    case Op::OpIMul: return "OpIMul";
+    case Op::OpFMul: return "OpFMul";
+    case Op::OpUDiv: return "OpUDiv";
+    case Op::OpSDiv: return "OpSDiv";
+    case Op::OpFDiv: return "OpFDiv";
+    case Op::OpUMod: return "OpUMod";
+    case Op::OpSRem: return "OpSRem";
+    case Op::OpSMod: return "OpSMod";
+    case Op::OpFRem: return "OpFRem";
+    case Op::OpFMod: return "OpFMod";
+    case Op::OpVectorTimesScalar: return "OpVectorTimesScalar";
+    case Op::OpMatrixTimesScalar: return "OpMatrixTimesScalar";
+    case Op::OpVectorTimesMatrix: return "OpVectorTimesMatrix";
+    case Op::OpMatrixTimesVector: return "OpMatrixTimesVector";
+    case Op::OpMatrixTimesMatrix: return "OpMatrixTimesMatrix";
+    case Op::OpOuterProduct: return "OpOuterProduct";
+    case Op::OpDot: return "OpDot";
+    case Op::OpIAddCarry: return "OpIAddCarry";
+    case Op::OpISubBorrow: return "OpISubBorrow";
+    case Op::OpUMulExtended: return "OpUMulExtended";
+    case Op::OpSMulExtended: return "OpSMulExtended";
+    case Op::OpAny: return "OpAny";
+    case Op::OpAll: return "OpAll";
+    case Op::OpIsNan: return "OpIsNan";
+    case Op::OpIsInf: return "OpIsInf";
+    case Op::OpIsFinite: return "OpIsFinite";
+    case Op::OpIsNormal: return "OpIsNormal";
+    case Op::OpSignBitSet: return "OpSignBitSet";
+    case Op::OpLessOrGreater: return "OpLessOrGreater";
+    case Op::OpOrdered: return "OpOrdered";
+    case Op::OpUnordered: return "OpUnordered";
+    case Op::OpLogicalEqual: return "OpLogicalEqual";
+    case Op::OpLogicalNotEqual: return "OpLogicalNotEqual";
+    case Op::OpLogicalOr: return "OpLogicalOr";
+    case Op::OpLogicalAnd: return "OpLogicalAnd";
+    case Op::OpLogicalNot: return "OpLogicalNot";
+    case Op::OpSelect: return "OpSelect";
+    case Op::OpIEqual: return "OpIEqual";
+    case Op::OpINotEqual: return "OpINotEqual";
+    case Op::OpUGreaterThan: return "OpUGreaterThan";
+    case Op::OpSGreaterThan: return "OpSGreaterThan";
+    case Op::OpUGreaterThanEqual: return "OpUGreaterThanEqual";
+    case Op::OpSGreaterThanEqual: return "OpSGreaterThanEqual";
+    case Op::OpULessThan: return "OpULessThan";
+    case Op::OpSLessThan: return "OpSLessThan";
+    case Op::OpULessThanEqual: return "OpULessThanEqual";
+    case Op::OpSLessThanEqual: return "OpSLessThanEqual";
+    case Op::OpFOrdEqual: return "OpFOrdEqual";
+    case Op::OpFUnordEqual: return "OpFUnordEqual";
+    case Op::OpFOrdNotEqual: return "OpFOrdNotEqual";
+    case Op::OpFUnordNotEqual: return "OpFUnordNotEqual";
+    case Op::OpFOrdLessThan: return "OpFOrdLessThan";
+    case Op::OpFUnordLessThan: return "OpFUnordLessThan";
+    case Op::OpFOrdGreaterThan: return "OpFOrdGreaterThan";
+    case Op::OpFUnordGreaterThan: return "OpFUnordGreaterThan";
+    case Op::OpFOrdLessThanEqual: return "OpFOrdLessThanEqual";
+    case Op::OpFUnordLessThanEqual: return "OpFUnordLessThanEqual";
+    case Op::OpFOrdGreaterThanEqual: return "OpFOrdGreaterThanEqual";
+    case Op::OpFUnordGreaterThanEqual: return "OpFUnordGreaterThanEqual";
+    case Op::OpShiftRightLogical: return "OpShiftRightLogical";
+    case Op::OpShiftRightArithmetic: return "OpShiftRightArithmetic";
+    case Op::OpShiftLeftLogical: return "OpShiftLeftLogical";
+    case Op::OpBitwiseOr: return "OpBitwiseOr";
+    case Op::OpBitwiseXor: return "OpBitwiseXor";
+    case Op::OpBitwiseAnd: return "OpBitwiseAnd";
+    case Op::OpNot: return "OpNot";
+    case Op::OpBitFieldInsert: return "OpBitFieldInsert";
+    case Op::OpBitFieldSExtract: return "OpBitFieldSExtract";
+    case Op::OpBitFieldUExtract: return "OpBitFieldUExtract";
+    case Op::OpBitReverse: return "OpBitReverse";
+    case Op::OpBitCount: return "OpBitCount";
+    case Op::OpDPdx: return "OpDPdx";
+    case Op::OpDPdy: return "OpDPdy";
+    case Op::OpFwidth: return "OpFwidth";
+    case Op::OpDPdxFine: return "OpDPdxFine";
+    case Op::OpDPdyFine: return "OpDPdyFine";
+    case Op::OpFwidthFine: return "OpFwidthFine";
+    case Op::OpDPdxCoarse: return "OpDPdxCoarse";
+    case Op::OpDPdyCoarse: return "OpDPdyCoarse";
+    case Op::OpFwidthCoarse: return "OpFwidthCoarse";
+    case Op::OpEmitVertex: return "OpEmitVertex";
+    case Op::OpEndPrimitive: return "OpEndPrimitive";
+    case Op::OpEmitStreamVertex: return "OpEmitStreamVertex";
+    case Op::OpEndStreamPrimitive: return "OpEndStreamPrimitive";
+    case Op::OpControlBarrier: return "OpControlBarrier";
+    case Op::OpMemoryBarrier: return "OpMemoryBarrier";
+    case Op::OpAtomicLoad: return "OpAtomicLoad";
+    case Op::OpAtomicStore: return "OpAtomicStore";
+    case Op::OpAtomicExchange: return "OpAtomicExchange";
+    case Op::OpAtomicCompareExchange: return "OpAtomicCompareExchange";
+    case Op::OpAtomicCompareExchangeWeak: return "OpAtomicCompareExchangeWeak";
+    case Op::OpAtomicIIncrement: return "OpAtomicIIncrement";
+    case Op::OpAtomicIDecrement: return "OpAtomicIDecrement";
+    case Op::OpAtomicIAdd: return "OpAtomicIAdd";
+    case Op::OpAtomicISub: return "OpAtomicISub";
+    case Op::OpAtomicSMin: return "OpAtomicSMin";
+    case Op::OpAtomicUMin: return "OpAtomicUMin";
+    case Op::OpAtomicSMax: return "OpAtomicSMax";
+    case Op::OpAtomicUMax: return "OpAtomicUMax";
+    case Op::OpAtomicAnd: return "OpAtomicAnd";
+    case Op::OpAtomicOr: return "OpAtomicOr";
+    case Op::OpAtomicXor: return "OpAtomicXor";
+    case Op::OpPhi: return "OpPhi";
+    case Op::OpLoopMerge: return "OpLoopMerge";
+    case Op::OpSelectionMerge: return "OpSelectionMerge";
+    case Op::OpLabel: return "OpLabel";
+    case Op::OpBranch: return "OpBranch";
+    case Op::OpBranchConditional: return "OpBranchConditional";
+    case Op::OpSwitch: return "OpSwitch";
+    case Op::OpKill: return "OpKill";
+    case Op::OpReturn: return "OpReturn";
+    case Op::OpReturnValue: return "OpReturnValue";
+    case Op::OpUnreachable: return "OpUnreachable";
+    case Op::OpLifetimeStart: return "OpLifetimeStart";
+    case Op::OpLifetimeStop: return "OpLifetimeStop";
+    case Op::OpGroupAsyncCopy: return "OpGroupAsyncCopy";
+    case Op::OpGroupWaitEvents: return "OpGroupWaitEvents";
+    case Op::OpGroupAll: return "OpGroupAll";
+    case Op::OpGroupAny: return "OpGroupAny";
+    case Op::OpGroupBroadcast: return "OpGroupBroadcast";
+    case Op::OpGroupIAdd: return "OpGroupIAdd";
+    case Op::OpGroupFAdd: return "OpGroupFAdd";
+    case Op::OpGroupFMin: return "OpGroupFMin";
+    case Op::OpGroupUMin: return "OpGroupUMin";
+    case Op::OpGroupSMin: return "OpGroupSMin";
+    case Op::OpGroupFMax: return "OpGroupFMax";
+    case Op::OpGroupUMax: return "OpGroupUMax";
+    case Op::OpGroupSMax: return "OpGroupSMax";
+    case Op::OpReadPipe: return "OpReadPipe";
+    case Op::OpWritePipe: return "OpWritePipe";
+    case Op::OpReservedReadPipe: return "OpReservedReadPipe";
+    case Op::OpReservedWritePipe: return "OpReservedWritePipe";
+    case Op::OpReserveReadPipePackets: return "OpReserveReadPipePackets";
+    case Op::OpReserveWritePipePackets: return "OpReserveWritePipePackets";
+    case Op::OpCommitReadPipe: return "OpCommitReadPipe";
+    case Op::OpCommitWritePipe: return "OpCommitWritePipe";
+    case Op::OpIsValidReserveId: return "OpIsValidReserveId";
+    case Op::OpGetNumPipePackets: return "OpGetNumPipePackets";
+    case Op::OpGetMaxPipePackets: return "OpGetMaxPipePackets";
+    case Op::OpGroupReserveReadPipePackets: return "OpGroupReserveReadPipePackets";
+    case Op::OpGroupReserveWritePipePackets: return "OpGroupReserveWritePipePackets";
+    case Op::OpGroupCommitReadPipe: return "OpGroupCommitReadPipe";
+    case Op::OpGroupCommitWritePipe: return "OpGroupCommitWritePipe";
+    case Op::OpEnqueueMarker: return "OpEnqueueMarker";
+    case Op::OpEnqueueKernel: return "OpEnqueueKernel";
+    case Op::OpGetKernelNDrangeSubGroupCount: return "OpGetKernelNDrangeSubGroupCount";
+    case Op::OpGetKernelNDrangeMaxSubGroupSize: return "OpGetKernelNDrangeMaxSubGroupSize";
+    case Op::OpGetKernelWorkGroupSize: return "OpGetKernelWorkGroupSize";
+    case Op::OpGetKernelPreferredWorkGroupSizeMultiple: return "OpGetKernelPreferredWorkGroupSizeMultiple";
+    case Op::OpRetainEvent: return "OpRetainEvent";
+    case Op::OpReleaseEvent: return "OpReleaseEvent";
+    case Op::OpCreateUserEvent: return "OpCreateUserEvent";
+    case Op::OpIsValidEvent: return "OpIsValidEvent";
+    case Op::OpSetUserEventStatus: return "OpSetUserEventStatus";
+    case Op::OpCaptureEventProfilingInfo: return "OpCaptureEventProfilingInfo";
+    case Op::OpGetDefaultQueue: return "OpGetDefaultQueue";
+    case Op::OpBuildNDRange: return "OpBuildNDRange";
+    case Op::OpImageSparseSampleImplicitLod: return "OpImageSparseSampleImplicitLod";
+    case Op::OpImageSparseSampleExplicitLod: return "OpImageSparseSampleExplicitLod";
+    case Op::OpImageSparseSampleDrefImplicitLod: return "OpImageSparseSampleDrefImplicitLod";
+    case Op::OpImageSparseSampleDrefExplicitLod: return "OpImageSparseSampleDrefExplicitLod";
+    case Op::OpImageSparseSampleProjImplicitLod: return "OpImageSparseSampleProjImplicitLod";
+    case Op::OpImageSparseSampleProjExplicitLod: return "OpImageSparseSampleProjExplicitLod";
+    case Op::OpImageSparseSampleProjDrefImplicitLod: return "OpImageSparseSampleProjDrefImplicitLod";
+    case Op::OpImageSparseSampleProjDrefExplicitLod: return "OpImageSparseSampleProjDrefExplicitLod";
+    case Op::OpImageSparseFetch: return "OpImageSparseFetch";
+    case Op::OpImageSparseGather: return "OpImageSparseGather";
+    case Op::OpImageSparseDrefGather: return "OpImageSparseDrefGather";
+    case Op::OpImageSparseTexelsResident: return "OpImageSparseTexelsResident";
+    case Op::OpNoLine: return "OpNoLine";
+    case Op::OpAtomicFlagTestAndSet: return "OpAtomicFlagTestAndSet";
+    case Op::OpAtomicFlagClear: return "OpAtomicFlagClear";
+    case Op::OpImageSparseRead: return "OpImageSparseRead";
+    case Op::OpSizeOf: return "OpSizeOf";
+    case Op::OpTypePipeStorage: return "OpTypePipeStorage";
+    case Op::OpConstantPipeStorage: return "OpConstantPipeStorage";
+    case Op::OpCreatePipeFromPipeStorage: return "OpCreatePipeFromPipeStorage";
+    case Op::OpGetKernelLocalSizeForSubgroupCount: return "OpGetKernelLocalSizeForSubgroupCount";
+    case Op::OpGetKernelMaxNumSubgroups: return "OpGetKernelMaxNumSubgroups";
+    case Op::OpTypeNamedBarrier: return "OpTypeNamedBarrier";
+    case Op::OpNamedBarrierInitialize: return "OpNamedBarrierInitialize";
+    case Op::OpMemoryNamedBarrier: return "OpMemoryNamedBarrier";
+    case Op::OpModuleProcessed: return "OpModuleProcessed";
+    case Op::OpExecutionModeId: return "OpExecutionModeId";
+    case Op::OpDecorateId: return "OpDecorateId";
+    case Op::OpGroupNonUniformElect: return "OpGroupNonUniformElect";
+    case Op::OpGroupNonUniformAll: return "OpGroupNonUniformAll";
+    case Op::OpGroupNonUniformAny: return "OpGroupNonUniformAny";
+    case Op::OpGroupNonUniformAllEqual: return "OpGroupNonUniformAllEqual";
+    case Op::OpGroupNonUniformBroadcast: return "OpGroupNonUniformBroadcast";
+    case Op::OpGroupNonUniformBroadcastFirst: return "OpGroupNonUniformBroadcastFirst";
+    case Op::OpGroupNonUniformBallot: return "OpGroupNonUniformBallot";
+    case Op::OpGroupNonUniformInverseBallot: return "OpGroupNonUniformInverseBallot";
+    case Op::OpGroupNonUniformBallotBitExtract: return "OpGroupNonUniformBallotBitExtract";
+    case Op::OpGroupNonUniformBallotBitCount: return "OpGroupNonUniformBallotBitCount";
+    case Op::OpGroupNonUniformBallotFindLSB: return "OpGroupNonUniformBallotFindLSB";
+    case Op::OpGroupNonUniformBallotFindMSB: return "OpGroupNonUniformBallotFindMSB";
+    case Op::OpGroupNonUniformShuffle: return "OpGroupNonUniformShuffle";
+    case Op::OpGroupNonUniformShuffleXor: return "OpGroupNonUniformShuffleXor";
+    case Op::OpGroupNonUniformShuffleUp: return "OpGroupNonUniformShuffleUp";
+    case Op::OpGroupNonUniformShuffleDown: return "OpGroupNonUniformShuffleDown";
+    case Op::OpGroupNonUniformIAdd: return "OpGroupNonUniformIAdd";
+    case Op::OpGroupNonUniformFAdd: return "OpGroupNonUniformFAdd";
+    case Op::OpGroupNonUniformIMul: return "OpGroupNonUniformIMul";
+    case Op::OpGroupNonUniformFMul: return "OpGroupNonUniformFMul";
+    case Op::OpGroupNonUniformSMin: return "OpGroupNonUniformSMin";
+    case Op::OpGroupNonUniformUMin: return "OpGroupNonUniformUMin";
+    case Op::OpGroupNonUniformFMin: return "OpGroupNonUniformFMin";
+    case Op::OpGroupNonUniformSMax: return "OpGroupNonUniformSMax";
+    case Op::OpGroupNonUniformUMax: return "OpGroupNonUniformUMax";
+    case Op::OpGroupNonUniformFMax: return "OpGroupNonUniformFMax";
+    case Op::OpGroupNonUniformBitwiseAnd: return "OpGroupNonUniformBitwiseAnd";
+    case Op::OpGroupNonUniformBitwiseOr: return "OpGroupNonUniformBitwiseOr";
+    case Op::OpGroupNonUniformBitwiseXor: return "OpGroupNonUniformBitwiseXor";
+    case Op::OpGroupNonUniformLogicalAnd: return "OpGroupNonUniformLogicalAnd";
+    case Op::OpGroupNonUniformLogicalOr: return "OpGroupNonUniformLogicalOr";
+    case Op::OpGroupNonUniformLogicalXor: return "OpGroupNonUniformLogicalXor";
+    case Op::OpGroupNonUniformQuadBroadcast: return "OpGroupNonUniformQuadBroadcast";
+    case Op::OpGroupNonUniformQuadSwap: return "OpGroupNonUniformQuadSwap";
+    case Op::OpCopyLogical: return "OpCopyLogical";
+    case Op::OpPtrEqual: return "OpPtrEqual";
+    case Op::OpPtrNotEqual: return "OpPtrNotEqual";
+    case Op::OpPtrDiff: return "OpPtrDiff";
+    case Op::OpColorAttachmentReadEXT: return "OpColorAttachmentReadEXT";
+    case Op::OpDepthAttachmentReadEXT: return "OpDepthAttachmentReadEXT";
+    case Op::OpStencilAttachmentReadEXT: return "OpStencilAttachmentReadEXT";
+    case Op::OpTerminateInvocation: return "OpTerminateInvocation";
+    case Op::OpTypeUntypedPointerKHR: return "OpTypeUntypedPointerKHR";
+    case Op::OpUntypedVariableKHR: return "OpUntypedVariableKHR";
+    case Op::OpUntypedAccessChainKHR: return "OpUntypedAccessChainKHR";
+    case Op::OpUntypedInBoundsAccessChainKHR: return "OpUntypedInBoundsAccessChainKHR";
+    case Op::OpSubgroupBallotKHR: return "OpSubgroupBallotKHR";
+    case Op::OpSubgroupFirstInvocationKHR: return "OpSubgroupFirstInvocationKHR";
+    case Op::OpUntypedPtrAccessChainKHR: return "OpUntypedPtrAccessChainKHR";
+    case Op::OpUntypedInBoundsPtrAccessChainKHR: return "OpUntypedInBoundsPtrAccessChainKHR";
+    case Op::OpUntypedArrayLengthKHR: return "OpUntypedArrayLengthKHR";
+    case Op::OpUntypedPrefetchKHR: return "OpUntypedPrefetchKHR";
+    case Op::OpSubgroupAllKHR: return "OpSubgroupAllKHR";
+    case Op::OpSubgroupAnyKHR: return "OpSubgroupAnyKHR";
+    case Op::OpSubgroupAllEqualKHR: return "OpSubgroupAllEqualKHR";
+    case Op::OpGroupNonUniformRotateKHR: return "OpGroupNonUniformRotateKHR";
+    case Op::OpSubgroupReadInvocationKHR: return "OpSubgroupReadInvocationKHR";
+    case Op::OpExtInstWithForwardRefsKHR: return "OpExtInstWithForwardRefsKHR";
+    case Op::OpTraceRayKHR: return "OpTraceRayKHR";
+    case Op::OpExecuteCallableKHR: return "OpExecuteCallableKHR";
+    case Op::OpConvertUToAccelerationStructureKHR: return "OpConvertUToAccelerationStructureKHR";
+    case Op::OpIgnoreIntersectionKHR: return "OpIgnoreIntersectionKHR";
+    case Op::OpTerminateRayKHR: return "OpTerminateRayKHR";
+    case Op::OpSDot: return "OpSDot";
+    case Op::OpUDot: return "OpUDot";
+    case Op::OpSUDot: return "OpSUDot";
+    case Op::OpSDotAccSat: return "OpSDotAccSat";
+    case Op::OpUDotAccSat: return "OpUDotAccSat";
+    case Op::OpSUDotAccSat: return "OpSUDotAccSat";
+    case Op::OpTypeCooperativeMatrixKHR: return "OpTypeCooperativeMatrixKHR";
+    case Op::OpCooperativeMatrixLoadKHR: return "OpCooperativeMatrixLoadKHR";
+    case Op::OpCooperativeMatrixStoreKHR: return "OpCooperativeMatrixStoreKHR";
+    case Op::OpCooperativeMatrixMulAddKHR: return "OpCooperativeMatrixMulAddKHR";
+    case Op::OpCooperativeMatrixLengthKHR: return "OpCooperativeMatrixLengthKHR";
+    case Op::OpConstantCompositeReplicateEXT: return "OpConstantCompositeReplicateEXT";
+    case Op::OpSpecConstantCompositeReplicateEXT: return "OpSpecConstantCompositeReplicateEXT";
+    case Op::OpCompositeConstructReplicateEXT: return "OpCompositeConstructReplicateEXT";
+    case Op::OpTypeRayQueryKHR: return "OpTypeRayQueryKHR";
+    case Op::OpRayQueryInitializeKHR: return "OpRayQueryInitializeKHR";
+    case Op::OpRayQueryTerminateKHR: return "OpRayQueryTerminateKHR";
+    case Op::OpRayQueryGenerateIntersectionKHR: return "OpRayQueryGenerateIntersectionKHR";
+    case Op::OpRayQueryConfirmIntersectionKHR: return "OpRayQueryConfirmIntersectionKHR";
+    case Op::OpRayQueryProceedKHR: return "OpRayQueryProceedKHR";
+    case Op::OpRayQueryGetIntersectionTypeKHR: return "OpRayQueryGetIntersectionTypeKHR";
+    case Op::OpImageSampleWeightedQCOM: return "OpImageSampleWeightedQCOM";
+    case Op::OpImageBoxFilterQCOM: return "OpImageBoxFilterQCOM";
+    case Op::OpImageBlockMatchSSDQCOM: return "OpImageBlockMatchSSDQCOM";
+    case Op::OpImageBlockMatchSADQCOM: return "OpImageBlockMatchSADQCOM";
+    case Op::OpImageBlockMatchWindowSSDQCOM: return "OpImageBlockMatchWindowSSDQCOM";
+    case Op::OpImageBlockMatchWindowSADQCOM: return "OpImageBlockMatchWindowSADQCOM";
+    case Op::OpImageBlockMatchGatherSSDQCOM: return "OpImageBlockMatchGatherSSDQCOM";
+    case Op::OpImageBlockMatchGatherSADQCOM: return "OpImageBlockMatchGatherSADQCOM";
+    case Op::OpGroupIAddNonUniformAMD: return "OpGroupIAddNonUniformAMD";
+    case Op::OpGroupFAddNonUniformAMD: return "OpGroupFAddNonUniformAMD";
+    case Op::OpGroupFMinNonUniformAMD: return "OpGroupFMinNonUniformAMD";
+    case Op::OpGroupUMinNonUniformAMD: return "OpGroupUMinNonUniformAMD";
+    case Op::OpGroupSMinNonUniformAMD: return "OpGroupSMinNonUniformAMD";
+    case Op::OpGroupFMaxNonUniformAMD: return "OpGroupFMaxNonUniformAMD";
+    case Op::OpGroupUMaxNonUniformAMD: return "OpGroupUMaxNonUniformAMD";
+    case Op::OpGroupSMaxNonUniformAMD: return "OpGroupSMaxNonUniformAMD";
+    case Op::OpFragmentMaskFetchAMD: return "OpFragmentMaskFetchAMD";
+    case Op::OpFragmentFetchAMD: return "OpFragmentFetchAMD";
+    case Op::OpReadClockKHR: return "OpReadClockKHR";
+    case Op::OpAllocateNodePayloadsAMDX: return "OpAllocateNodePayloadsAMDX";
+    case Op::OpEnqueueNodePayloadsAMDX: return "OpEnqueueNodePayloadsAMDX";
+    case Op::OpTypeNodePayloadArrayAMDX: return "OpTypeNodePayloadArrayAMDX";
+    case Op::OpFinishWritingNodePayloadAMDX: return "OpFinishWritingNodePayloadAMDX";
+    case Op::OpNodePayloadArrayLengthAMDX: return "OpNodePayloadArrayLengthAMDX";
+    case Op::OpIsNodePayloadValidAMDX: return "OpIsNodePayloadValidAMDX";
+    case Op::OpConstantStringAMDX: return "OpConstantStringAMDX";
+    case Op::OpSpecConstantStringAMDX: return "OpSpecConstantStringAMDX";
+    case Op::OpGroupNonUniformQuadAllKHR: return "OpGroupNonUniformQuadAllKHR";
+    case Op::OpGroupNonUniformQuadAnyKHR: return "OpGroupNonUniformQuadAnyKHR";
+    case Op::OpHitObjectRecordHitMotionNV: return "OpHitObjectRecordHitMotionNV";
+    case Op::OpHitObjectRecordHitWithIndexMotionNV: return "OpHitObjectRecordHitWithIndexMotionNV";
+    case Op::OpHitObjectRecordMissMotionNV: return "OpHitObjectRecordMissMotionNV";
+    case Op::OpHitObjectGetWorldToObjectNV: return "OpHitObjectGetWorldToObjectNV";
+    case Op::OpHitObjectGetObjectToWorldNV: return "OpHitObjectGetObjectToWorldNV";
+    case Op::OpHitObjectGetObjectRayDirectionNV: return "OpHitObjectGetObjectRayDirectionNV";
+    case Op::OpHitObjectGetObjectRayOriginNV: return "OpHitObjectGetObjectRayOriginNV";
+    case Op::OpHitObjectTraceRayMotionNV: return "OpHitObjectTraceRayMotionNV";
+    case Op::OpHitObjectGetShaderRecordBufferHandleNV: return "OpHitObjectGetShaderRecordBufferHandleNV";
+    case Op::OpHitObjectGetShaderBindingTableRecordIndexNV: return "OpHitObjectGetShaderBindingTableRecordIndexNV";
+    case Op::OpHitObjectRecordEmptyNV: return "OpHitObjectRecordEmptyNV";
+    case Op::OpHitObjectTraceRayNV: return "OpHitObjectTraceRayNV";
+    case Op::OpHitObjectRecordHitNV: return "OpHitObjectRecordHitNV";
+    case Op::OpHitObjectRecordHitWithIndexNV: return "OpHitObjectRecordHitWithIndexNV";
+    case Op::OpHitObjectRecordMissNV: return "OpHitObjectRecordMissNV";
+    case Op::OpHitObjectExecuteShaderNV: return "OpHitObjectExecuteShaderNV";
+    case Op::OpHitObjectGetCurrentTimeNV: return "OpHitObjectGetCurrentTimeNV";
+    case Op::OpHitObjectGetAttributesNV: return "OpHitObjectGetAttributesNV";
+    case Op::OpHitObjectGetHitKindNV: return "OpHitObjectGetHitKindNV";
+    case Op::OpHitObjectGetPrimitiveIndexNV: return "OpHitObjectGetPrimitiveIndexNV";
+    case Op::OpHitObjectGetGeometryIndexNV: return "OpHitObjectGetGeometryIndexNV";
+    case Op::OpHitObjectGetInstanceIdNV: return "OpHitObjectGetInstanceIdNV";
+    case Op::OpHitObjectGetInstanceCustomIndexNV: return "OpHitObjectGetInstanceCustomIndexNV";
+    case Op::OpHitObjectGetWorldRayDirectionNV: return "OpHitObjectGetWorldRayDirectionNV";
+    case Op::OpHitObjectGetWorldRayOriginNV: return "OpHitObjectGetWorldRayOriginNV";
+    case Op::OpHitObjectGetRayTMaxNV: return "OpHitObjectGetRayTMaxNV";
+    case Op::OpHitObjectGetRayTMinNV: return "OpHitObjectGetRayTMinNV";
+    case Op::OpHitObjectIsEmptyNV: return "OpHitObjectIsEmptyNV";
+    case Op::OpHitObjectIsHitNV: return "OpHitObjectIsHitNV";
+    case Op::OpHitObjectIsMissNV: return "OpHitObjectIsMissNV";
+    case Op::OpReorderThreadWithHitObjectNV: return "OpReorderThreadWithHitObjectNV";
+    case Op::OpReorderThreadWithHintNV: return "OpReorderThreadWithHintNV";
+    case Op::OpTypeHitObjectNV: return "OpTypeHitObjectNV";
+    case Op::OpImageSampleFootprintNV: return "OpImageSampleFootprintNV";
+    case Op::OpCooperativeMatrixConvertNV: return "OpCooperativeMatrixConvertNV";
+    case Op::OpEmitMeshTasksEXT: return "OpEmitMeshTasksEXT";
+    case Op::OpSetMeshOutputsEXT: return "OpSetMeshOutputsEXT";
+    case Op::OpGroupNonUniformPartitionNV: return "OpGroupNonUniformPartitionNV";
+    case Op::OpWritePackedPrimitiveIndices4x8NV: return "OpWritePackedPrimitiveIndices4x8NV";
+    case Op::OpFetchMicroTriangleVertexPositionNV: return "OpFetchMicroTriangleVertexPositionNV";
+    case Op::OpFetchMicroTriangleVertexBarycentricNV: return "OpFetchMicroTriangleVertexBarycentricNV";
+    case Op::OpReportIntersectionKHR: return "OpReportIntersectionKHR";
+    case Op::OpIgnoreIntersectionNV: return "OpIgnoreIntersectionNV";
+    case Op::OpTerminateRayNV: return "OpTerminateRayNV";
+    case Op::OpTraceNV: return "OpTraceNV";
+    case Op::OpTraceMotionNV: return "OpTraceMotionNV";
+    case Op::OpTraceRayMotionNV: return "OpTraceRayMotionNV";
+    case Op::OpRayQueryGetIntersectionTriangleVertexPositionsKHR: return "OpRayQueryGetIntersectionTriangleVertexPositionsKHR";
+    case Op::OpTypeAccelerationStructureKHR: return "OpTypeAccelerationStructureKHR";
+    case Op::OpExecuteCallableNV: return "OpExecuteCallableNV";
+    case Op::OpTypeCooperativeMatrixNV: return "OpTypeCooperativeMatrixNV";
+    case Op::OpCooperativeMatrixLoadNV: return "OpCooperativeMatrixLoadNV";
+    case Op::OpCooperativeMatrixStoreNV: return "OpCooperativeMatrixStoreNV";
+    case Op::OpCooperativeMatrixMulAddNV: return "OpCooperativeMatrixMulAddNV";
+    case Op::OpCooperativeMatrixLengthNV: return "OpCooperativeMatrixLengthNV";
+    case Op::OpBeginInvocationInterlockEXT: return "OpBeginInvocationInterlockEXT";
+    case Op::OpEndInvocationInterlockEXT: return "OpEndInvocationInterlockEXT";
+    case Op::OpCooperativeMatrixReduceNV: return "OpCooperativeMatrixReduceNV";
+    case Op::OpCooperativeMatrixLoadTensorNV: return "OpCooperativeMatrixLoadTensorNV";
+    case Op::OpCooperativeMatrixStoreTensorNV: return "OpCooperativeMatrixStoreTensorNV";
+    case Op::OpCooperativeMatrixPerElementOpNV: return "OpCooperativeMatrixPerElementOpNV";
+    case Op::OpTypeTensorLayoutNV: return "OpTypeTensorLayoutNV";
+    case Op::OpTypeTensorViewNV: return "OpTypeTensorViewNV";
+    case Op::OpCreateTensorLayoutNV: return "OpCreateTensorLayoutNV";
+    case Op::OpTensorLayoutSetDimensionNV: return "OpTensorLayoutSetDimensionNV";
+    case Op::OpTensorLayoutSetStrideNV: return "OpTensorLayoutSetStrideNV";
+    case Op::OpTensorLayoutSliceNV: return "OpTensorLayoutSliceNV";
+    case Op::OpTensorLayoutSetClampValueNV: return "OpTensorLayoutSetClampValueNV";
+    case Op::OpCreateTensorViewNV: return "OpCreateTensorViewNV";
+    case Op::OpTensorViewSetDimensionNV: return "OpTensorViewSetDimensionNV";
+    case Op::OpTensorViewSetStrideNV: return "OpTensorViewSetStrideNV";
+    case Op::OpDemoteToHelperInvocation: return "OpDemoteToHelperInvocation";
+    case Op::OpIsHelperInvocationEXT: return "OpIsHelperInvocationEXT";
+    case Op::OpTensorViewSetClipNV: return "OpTensorViewSetClipNV";
+    case Op::OpTensorLayoutSetBlockSizeNV: return "OpTensorLayoutSetBlockSizeNV";
+    case Op::OpCooperativeMatrixTransposeNV: return "OpCooperativeMatrixTransposeNV";
+    case Op::OpConvertUToImageNV: return "OpConvertUToImageNV";
+    case Op::OpConvertUToSamplerNV: return "OpConvertUToSamplerNV";
+    case Op::OpConvertImageToUNV: return "OpConvertImageToUNV";
+    case Op::OpConvertSamplerToUNV: return "OpConvertSamplerToUNV";
+    case Op::OpConvertUToSampledImageNV: return "OpConvertUToSampledImageNV";
+    case Op::OpConvertSampledImageToUNV: return "OpConvertSampledImageToUNV";
+    case Op::OpSamplerImageAddressingModeNV: return "OpSamplerImageAddressingModeNV";
+    case Op::OpRawAccessChainNV: return "OpRawAccessChainNV";
+    case Op::OpSubgroupShuffleINTEL: return "OpSubgroupShuffleINTEL";
+    case Op::OpSubgroupShuffleDownINTEL: return "OpSubgroupShuffleDownINTEL";
+    case Op::OpSubgroupShuffleUpINTEL: return "OpSubgroupShuffleUpINTEL";
+    case Op::OpSubgroupShuffleXorINTEL: return "OpSubgroupShuffleXorINTEL";
+    case Op::OpSubgroupBlockReadINTEL: return "OpSubgroupBlockReadINTEL";
+    case Op::OpSubgroupBlockWriteINTEL: return "OpSubgroupBlockWriteINTEL";
+    case Op::OpSubgroupImageBlockReadINTEL: return "OpSubgroupImageBlockReadINTEL";
+    case Op::OpSubgroupImageBlockWriteINTEL: return "OpSubgroupImageBlockWriteINTEL";
+    case Op::OpSubgroupImageMediaBlockReadINTEL: return "OpSubgroupImageMediaBlockReadINTEL";
+    case Op::OpSubgroupImageMediaBlockWriteINTEL: return "OpSubgroupImageMediaBlockWriteINTEL";
+    case Op::OpUCountLeadingZerosINTEL: return "OpUCountLeadingZerosINTEL";
+    case Op::OpUCountTrailingZerosINTEL: return "OpUCountTrailingZerosINTEL";
+    case Op::OpAbsISubINTEL: return "OpAbsISubINTEL";
+    case Op::OpAbsUSubINTEL: return "OpAbsUSubINTEL";
+    case Op::OpIAddSatINTEL: return "OpIAddSatINTEL";
+    case Op::OpUAddSatINTEL: return "OpUAddSatINTEL";
+    case Op::OpIAverageINTEL: return "OpIAverageINTEL";
+    case Op::OpUAverageINTEL: return "OpUAverageINTEL";
+    case Op::OpIAverageRoundedINTEL: return "OpIAverageRoundedINTEL";
+    case Op::OpUAverageRoundedINTEL: return "OpUAverageRoundedINTEL";
+    case Op::OpISubSatINTEL: return "OpISubSatINTEL";
+    case Op::OpUSubSatINTEL: return "OpUSubSatINTEL";
+    case Op::OpIMul32x16INTEL: return "OpIMul32x16INTEL";
+    case Op::OpUMul32x16INTEL: return "OpUMul32x16INTEL";
+    case Op::OpConstantFunctionPointerINTEL: return "OpConstantFunctionPointerINTEL";
+    case Op::OpFunctionPointerCallINTEL: return "OpFunctionPointerCallINTEL";
+    case Op::OpAsmTargetINTEL: return "OpAsmTargetINTEL";
+    case Op::OpAsmINTEL: return "OpAsmINTEL";
+    case Op::OpAsmCallINTEL: return "OpAsmCallINTEL";
+    case Op::OpAtomicFMinEXT: return "OpAtomicFMinEXT";
+    case Op::OpAtomicFMaxEXT: return "OpAtomicFMaxEXT";
+    case Op::OpAssumeTrueKHR: return "OpAssumeTrueKHR";
+    case Op::OpExpectKHR: return "OpExpectKHR";
+    case Op::OpDecorateString: return "OpDecorateString";
+    case Op::OpMemberDecorateString: return "OpMemberDecorateString";
+    case Op::OpVmeImageINTEL: return "OpVmeImageINTEL";
+    case Op::OpTypeVmeImageINTEL: return "OpTypeVmeImageINTEL";
+    case Op::OpTypeAvcImePayloadINTEL: return "OpTypeAvcImePayloadINTEL";
+    case Op::OpTypeAvcRefPayloadINTEL: return "OpTypeAvcRefPayloadINTEL";
+    case Op::OpTypeAvcSicPayloadINTEL: return "OpTypeAvcSicPayloadINTEL";
+    case Op::OpTypeAvcMcePayloadINTEL: return "OpTypeAvcMcePayloadINTEL";
+    case Op::OpTypeAvcMceResultINTEL: return "OpTypeAvcMceResultINTEL";
+    case Op::OpTypeAvcImeResultINTEL: return "OpTypeAvcImeResultINTEL";
+    case Op::OpTypeAvcImeResultSingleReferenceStreamoutINTEL: return "OpTypeAvcImeResultSingleReferenceStreamoutINTEL";
+    case Op::OpTypeAvcImeResultDualReferenceStreamoutINTEL: return "OpTypeAvcImeResultDualReferenceStreamoutINTEL";
+    case Op::OpTypeAvcImeSingleReferenceStreaminINTEL: return "OpTypeAvcImeSingleReferenceStreaminINTEL";
+    case Op::OpTypeAvcImeDualReferenceStreaminINTEL: return "OpTypeAvcImeDualReferenceStreaminINTEL";
+    case Op::OpTypeAvcRefResultINTEL: return "OpTypeAvcRefResultINTEL";
+    case Op::OpTypeAvcSicResultINTEL: return "OpTypeAvcSicResultINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultInterBaseMultiReferencePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterBaseMultiReferencePenaltyINTEL";
+    case Op::OpSubgroupAvcMceSetInterBaseMultiReferencePenaltyINTEL: return "OpSubgroupAvcMceSetInterBaseMultiReferencePenaltyINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultInterShapePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterShapePenaltyINTEL";
+    case Op::OpSubgroupAvcMceSetInterShapePenaltyINTEL: return "OpSubgroupAvcMceSetInterShapePenaltyINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultInterDirectionPenaltyINTEL: return "OpSubgroupAvcMceGetDefaultInterDirectionPenaltyINTEL";
+    case Op::OpSubgroupAvcMceSetInterDirectionPenaltyINTEL: return "OpSubgroupAvcMceSetInterDirectionPenaltyINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultIntraLumaShapePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraLumaShapePenaltyINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultInterMotionVectorCostTableINTEL: return "OpSubgroupAvcMceGetDefaultInterMotionVectorCostTableINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultHighPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultHighPenaltyCostTableINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultMediumPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultMediumPenaltyCostTableINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultLowPenaltyCostTableINTEL: return "OpSubgroupAvcMceGetDefaultLowPenaltyCostTableINTEL";
+    case Op::OpSubgroupAvcMceSetMotionVectorCostFunctionINTEL: return "OpSubgroupAvcMceSetMotionVectorCostFunctionINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultIntraLumaModePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraLumaModePenaltyINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultNonDcLumaIntraPenaltyINTEL: return "OpSubgroupAvcMceGetDefaultNonDcLumaIntraPenaltyINTEL";
+    case Op::OpSubgroupAvcMceGetDefaultIntraChromaModeBasePenaltyINTEL: return "OpSubgroupAvcMceGetDefaultIntraChromaModeBasePenaltyINTEL";
+    case Op::OpSubgroupAvcMceSetAcOnlyHaarINTEL: return "OpSubgroupAvcMceSetAcOnlyHaarINTEL";
+    case Op::OpSubgroupAvcMceSetSourceInterlacedFieldPolarityINTEL: return "OpSubgroupAvcMceSetSourceInterlacedFieldPolarityINTEL";
+    case Op::OpSubgroupAvcMceSetSingleReferenceInterlacedFieldPolarityINTEL: return "OpSubgroupAvcMceSetSingleReferenceInterlacedFieldPolarityINTEL";
+    case Op::OpSubgroupAvcMceSetDualReferenceInterlacedFieldPolaritiesINTEL: return "OpSubgroupAvcMceSetDualReferenceInterlacedFieldPolaritiesINTEL";
+    case Op::OpSubgroupAvcMceConvertToImePayloadINTEL: return "OpSubgroupAvcMceConvertToImePayloadINTEL";
+    case Op::OpSubgroupAvcMceConvertToImeResultINTEL: return "OpSubgroupAvcMceConvertToImeResultINTEL";
+    case Op::OpSubgroupAvcMceConvertToRefPayloadINTEL: return "OpSubgroupAvcMceConvertToRefPayloadINTEL";
+    case Op::OpSubgroupAvcMceConvertToRefResultINTEL: return "OpSubgroupAvcMceConvertToRefResultINTEL";
+    case Op::OpSubgroupAvcMceConvertToSicPayloadINTEL: return "OpSubgroupAvcMceConvertToSicPayloadINTEL";
+    case Op::OpSubgroupAvcMceConvertToSicResultINTEL: return "OpSubgroupAvcMceConvertToSicResultINTEL";
+    case Op::OpSubgroupAvcMceGetMotionVectorsINTEL: return "OpSubgroupAvcMceGetMotionVectorsINTEL";
+    case Op::OpSubgroupAvcMceGetInterDistortionsINTEL: return "OpSubgroupAvcMceGetInterDistortionsINTEL";
+    case Op::OpSubgroupAvcMceGetBestInterDistortionsINTEL: return "OpSubgroupAvcMceGetBestInterDistortionsINTEL";
+    case Op::OpSubgroupAvcMceGetInterMajorShapeINTEL: return "OpSubgroupAvcMceGetInterMajorShapeINTEL";
+    case Op::OpSubgroupAvcMceGetInterMinorShapeINTEL: return "OpSubgroupAvcMceGetInterMinorShapeINTEL";
+    case Op::OpSubgroupAvcMceGetInterDirectionsINTEL: return "OpSubgroupAvcMceGetInterDirectionsINTEL";
+    case Op::OpSubgroupAvcMceGetInterMotionVectorCountINTEL: return "OpSubgroupAvcMceGetInterMotionVectorCountINTEL";
+    case Op::OpSubgroupAvcMceGetInterReferenceIdsINTEL: return "OpSubgroupAvcMceGetInterReferenceIdsINTEL";
+    case Op::OpSubgroupAvcMceGetInterReferenceInterlacedFieldPolaritiesINTEL: return "OpSubgroupAvcMceGetInterReferenceInterlacedFieldPolaritiesINTEL";
+    case Op::OpSubgroupAvcImeInitializeINTEL: return "OpSubgroupAvcImeInitializeINTEL";
+    case Op::OpSubgroupAvcImeSetSingleReferenceINTEL: return "OpSubgroupAvcImeSetSingleReferenceINTEL";
+    case Op::OpSubgroupAvcImeSetDualReferenceINTEL: return "OpSubgroupAvcImeSetDualReferenceINTEL";
+    case Op::OpSubgroupAvcImeRefWindowSizeINTEL: return "OpSubgroupAvcImeRefWindowSizeINTEL";
+    case Op::OpSubgroupAvcImeAdjustRefOffsetINTEL: return "OpSubgroupAvcImeAdjustRefOffsetINTEL";
+    case Op::OpSubgroupAvcImeConvertToMcePayloadINTEL: return "OpSubgroupAvcImeConvertToMcePayloadINTEL";
+    case Op::OpSubgroupAvcImeSetMaxMotionVectorCountINTEL: return "OpSubgroupAvcImeSetMaxMotionVectorCountINTEL";
+    case Op::OpSubgroupAvcImeSetUnidirectionalMixDisableINTEL: return "OpSubgroupAvcImeSetUnidirectionalMixDisableINTEL";
+    case Op::OpSubgroupAvcImeSetEarlySearchTerminationThresholdINTEL: return "OpSubgroupAvcImeSetEarlySearchTerminationThresholdINTEL";
+    case Op::OpSubgroupAvcImeSetWeightedSadINTEL: return "OpSubgroupAvcImeSetWeightedSadINTEL";
+    case Op::OpSubgroupAvcImeEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceINTEL";
+    case Op::OpSubgroupAvcImeEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceINTEL";
+    case Op::OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminINTEL";
+    case Op::OpSubgroupAvcImeEvaluateWithDualReferenceStreaminINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreaminINTEL";
+    case Op::OpSubgroupAvcImeEvaluateWithSingleReferenceStreamoutINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreamoutINTEL";
+    case Op::OpSubgroupAvcImeEvaluateWithDualReferenceStreamoutINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreamoutINTEL";
+    case Op::OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminoutINTEL: return "OpSubgroupAvcImeEvaluateWithSingleReferenceStreaminoutINTEL";
+    case Op::OpSubgroupAvcImeEvaluateWithDualReferenceStreaminoutINTEL: return "OpSubgroupAvcImeEvaluateWithDualReferenceStreaminoutINTEL";
+    case Op::OpSubgroupAvcImeConvertToMceResultINTEL: return "OpSubgroupAvcImeConvertToMceResultINTEL";
+    case Op::OpSubgroupAvcImeGetSingleReferenceStreaminINTEL: return "OpSubgroupAvcImeGetSingleReferenceStreaminINTEL";
+    case Op::OpSubgroupAvcImeGetDualReferenceStreaminINTEL: return "OpSubgroupAvcImeGetDualReferenceStreaminINTEL";
+    case Op::OpSubgroupAvcImeStripSingleReferenceStreamoutINTEL: return "OpSubgroupAvcImeStripSingleReferenceStreamoutINTEL";
+    case Op::OpSubgroupAvcImeStripDualReferenceStreamoutINTEL: return "OpSubgroupAvcImeStripDualReferenceStreamoutINTEL";
+    case Op::OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeMotionVectorsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeMotionVectorsINTEL";
+    case Op::OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeDistortionsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeDistortionsINTEL";
+    case Op::OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeReferenceIdsINTEL: return "OpSubgroupAvcImeGetStreamoutSingleReferenceMajorShapeReferenceIdsINTEL";
+    case Op::OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeMotionVectorsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeMotionVectorsINTEL";
+    case Op::OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeDistortionsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeDistortionsINTEL";
+    case Op::OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeReferenceIdsINTEL: return "OpSubgroupAvcImeGetStreamoutDualReferenceMajorShapeReferenceIdsINTEL";
+    case Op::OpSubgroupAvcImeGetBorderReachedINTEL: return "OpSubgroupAvcImeGetBorderReachedINTEL";
+    case Op::OpSubgroupAvcImeGetTruncatedSearchIndicationINTEL: return "OpSubgroupAvcImeGetTruncatedSearchIndicationINTEL";
+    case Op::OpSubgroupAvcImeGetUnidirectionalEarlySearchTerminationINTEL: return "OpSubgroupAvcImeGetUnidirectionalEarlySearchTerminationINTEL";
+    case Op::OpSubgroupAvcImeGetWeightingPatternMinimumMotionVectorINTEL: return "OpSubgroupAvcImeGetWeightingPatternMinimumMotionVectorINTEL";
+    case Op::OpSubgroupAvcImeGetWeightingPatternMinimumDistortionINTEL: return "OpSubgroupAvcImeGetWeightingPatternMinimumDistortionINTEL";
+    case Op::OpSubgroupAvcFmeInitializeINTEL: return "OpSubgroupAvcFmeInitializeINTEL";
+    case Op::OpSubgroupAvcBmeInitializeINTEL: return "OpSubgroupAvcBmeInitializeINTEL";
+    case Op::OpSubgroupAvcRefConvertToMcePayloadINTEL: return "OpSubgroupAvcRefConvertToMcePayloadINTEL";
+    case Op::OpSubgroupAvcRefSetBidirectionalMixDisableINTEL: return "OpSubgroupAvcRefSetBidirectionalMixDisableINTEL";
+    case Op::OpSubgroupAvcRefSetBilinearFilterEnableINTEL: return "OpSubgroupAvcRefSetBilinearFilterEnableINTEL";
+    case Op::OpSubgroupAvcRefEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithSingleReferenceINTEL";
+    case Op::OpSubgroupAvcRefEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithDualReferenceINTEL";
+    case Op::OpSubgroupAvcRefEvaluateWithMultiReferenceINTEL: return "OpSubgroupAvcRefEvaluateWithMultiReferenceINTEL";
+    case Op::OpSubgroupAvcRefEvaluateWithMultiReferenceInterlacedINTEL: return "OpSubgroupAvcRefEvaluateWithMultiReferenceInterlacedINTEL";
+    case Op::OpSubgroupAvcRefConvertToMceResultINTEL: return "OpSubgroupAvcRefConvertToMceResultINTEL";
+    case Op::OpSubgroupAvcSicInitializeINTEL: return "OpSubgroupAvcSicInitializeINTEL";
+    case Op::OpSubgroupAvcSicConfigureSkcINTEL: return "OpSubgroupAvcSicConfigureSkcINTEL";
+    case Op::OpSubgroupAvcSicConfigureIpeLumaINTEL: return "OpSubgroupAvcSicConfigureIpeLumaINTEL";
+    case Op::OpSubgroupAvcSicConfigureIpeLumaChromaINTEL: return "OpSubgroupAvcSicConfigureIpeLumaChromaINTEL";
+    case Op::OpSubgroupAvcSicGetMotionVectorMaskINTEL: return "OpSubgroupAvcSicGetMotionVectorMaskINTEL";
+    case Op::OpSubgroupAvcSicConvertToMcePayloadINTEL: return "OpSubgroupAvcSicConvertToMcePayloadINTEL";
+    case Op::OpSubgroupAvcSicSetIntraLumaShapePenaltyINTEL: return "OpSubgroupAvcSicSetIntraLumaShapePenaltyINTEL";
+    case Op::OpSubgroupAvcSicSetIntraLumaModeCostFunctionINTEL: return "OpSubgroupAvcSicSetIntraLumaModeCostFunctionINTEL";
+    case Op::OpSubgroupAvcSicSetIntraChromaModeCostFunctionINTEL: return "OpSubgroupAvcSicSetIntraChromaModeCostFunctionINTEL";
+    case Op::OpSubgroupAvcSicSetBilinearFilterEnableINTEL: return "OpSubgroupAvcSicSetBilinearFilterEnableINTEL";
+    case Op::OpSubgroupAvcSicSetSkcForwardTransformEnableINTEL: return "OpSubgroupAvcSicSetSkcForwardTransformEnableINTEL";
+    case Op::OpSubgroupAvcSicSetBlockBasedRawSkipSadINTEL: return "OpSubgroupAvcSicSetBlockBasedRawSkipSadINTEL";
+    case Op::OpSubgroupAvcSicEvaluateIpeINTEL: return "OpSubgroupAvcSicEvaluateIpeINTEL";
+    case Op::OpSubgroupAvcSicEvaluateWithSingleReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithSingleReferenceINTEL";
+    case Op::OpSubgroupAvcSicEvaluateWithDualReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithDualReferenceINTEL";
+    case Op::OpSubgroupAvcSicEvaluateWithMultiReferenceINTEL: return "OpSubgroupAvcSicEvaluateWithMultiReferenceINTEL";
+    case Op::OpSubgroupAvcSicEvaluateWithMultiReferenceInterlacedINTEL: return "OpSubgroupAvcSicEvaluateWithMultiReferenceInterlacedINTEL";
+    case Op::OpSubgroupAvcSicConvertToMceResultINTEL: return "OpSubgroupAvcSicConvertToMceResultINTEL";
+    case Op::OpSubgroupAvcSicGetIpeLumaShapeINTEL: return "OpSubgroupAvcSicGetIpeLumaShapeINTEL";
+    case Op::OpSubgroupAvcSicGetBestIpeLumaDistortionINTEL: return "OpSubgroupAvcSicGetBestIpeLumaDistortionINTEL";
+    case Op::OpSubgroupAvcSicGetBestIpeChromaDistortionINTEL: return "OpSubgroupAvcSicGetBestIpeChromaDistortionINTEL";
+    case Op::OpSubgroupAvcSicGetPackedIpeLumaModesINTEL: return "OpSubgroupAvcSicGetPackedIpeLumaModesINTEL";
+    case Op::OpSubgroupAvcSicGetIpeChromaModeINTEL: return "OpSubgroupAvcSicGetIpeChromaModeINTEL";
+    case Op::OpSubgroupAvcSicGetPackedSkcLumaCountThresholdINTEL: return "OpSubgroupAvcSicGetPackedSkcLumaCountThresholdINTEL";
+    case Op::OpSubgroupAvcSicGetPackedSkcLumaSumThresholdINTEL: return "OpSubgroupAvcSicGetPackedSkcLumaSumThresholdINTEL";
+    case Op::OpSubgroupAvcSicGetInterRawSadsINTEL: return "OpSubgroupAvcSicGetInterRawSadsINTEL";
+    case Op::OpVariableLengthArrayINTEL: return "OpVariableLengthArrayINTEL";
+    case Op::OpSaveMemoryINTEL: return "OpSaveMemoryINTEL";
+    case Op::OpRestoreMemoryINTEL: return "OpRestoreMemoryINTEL";
+    case Op::OpArbitraryFloatSinCosPiINTEL: return "OpArbitraryFloatSinCosPiINTEL";
+    case Op::OpArbitraryFloatCastINTEL: return "OpArbitraryFloatCastINTEL";
+    case Op::OpArbitraryFloatCastFromIntINTEL: return "OpArbitraryFloatCastFromIntINTEL";
+    case Op::OpArbitraryFloatCastToIntINTEL: return "OpArbitraryFloatCastToIntINTEL";
+    case Op::OpArbitraryFloatAddINTEL: return "OpArbitraryFloatAddINTEL";
+    case Op::OpArbitraryFloatSubINTEL: return "OpArbitraryFloatSubINTEL";
+    case Op::OpArbitraryFloatMulINTEL: return "OpArbitraryFloatMulINTEL";
+    case Op::OpArbitraryFloatDivINTEL: return "OpArbitraryFloatDivINTEL";
+    case Op::OpArbitraryFloatGTINTEL: return "OpArbitraryFloatGTINTEL";
+    case Op::OpArbitraryFloatGEINTEL: return "OpArbitraryFloatGEINTEL";
+    case Op::OpArbitraryFloatLTINTEL: return "OpArbitraryFloatLTINTEL";
+    case Op::OpArbitraryFloatLEINTEL: return "OpArbitraryFloatLEINTEL";
+    case Op::OpArbitraryFloatEQINTEL: return "OpArbitraryFloatEQINTEL";
+    case Op::OpArbitraryFloatRecipINTEL: return "OpArbitraryFloatRecipINTEL";
+    case Op::OpArbitraryFloatRSqrtINTEL: return "OpArbitraryFloatRSqrtINTEL";
+    case Op::OpArbitraryFloatCbrtINTEL: return "OpArbitraryFloatCbrtINTEL";
+    case Op::OpArbitraryFloatHypotINTEL: return "OpArbitraryFloatHypotINTEL";
+    case Op::OpArbitraryFloatSqrtINTEL: return "OpArbitraryFloatSqrtINTEL";
+    case Op::OpArbitraryFloatLogINTEL: return "OpArbitraryFloatLogINTEL";
+    case Op::OpArbitraryFloatLog2INTEL: return "OpArbitraryFloatLog2INTEL";
+    case Op::OpArbitraryFloatLog10INTEL: return "OpArbitraryFloatLog10INTEL";
+    case Op::OpArbitraryFloatLog1pINTEL: return "OpArbitraryFloatLog1pINTEL";
+    case Op::OpArbitraryFloatExpINTEL: return "OpArbitraryFloatExpINTEL";
+    case Op::OpArbitraryFloatExp2INTEL: return "OpArbitraryFloatExp2INTEL";
+    case Op::OpArbitraryFloatExp10INTEL: return "OpArbitraryFloatExp10INTEL";
+    case Op::OpArbitraryFloatExpm1INTEL: return "OpArbitraryFloatExpm1INTEL";
+    case Op::OpArbitraryFloatSinINTEL: return "OpArbitraryFloatSinINTEL";
+    case Op::OpArbitraryFloatCosINTEL: return "OpArbitraryFloatCosINTEL";
+    case Op::OpArbitraryFloatSinCosINTEL: return "OpArbitraryFloatSinCosINTEL";
+    case Op::OpArbitraryFloatSinPiINTEL: return "OpArbitraryFloatSinPiINTEL";
+    case Op::OpArbitraryFloatCosPiINTEL: return "OpArbitraryFloatCosPiINTEL";
+    case Op::OpArbitraryFloatASinINTEL: return "OpArbitraryFloatASinINTEL";
+    case Op::OpArbitraryFloatASinPiINTEL: return "OpArbitraryFloatASinPiINTEL";
+    case Op::OpArbitraryFloatACosINTEL: return "OpArbitraryFloatACosINTEL";
+    case Op::OpArbitraryFloatACosPiINTEL: return "OpArbitraryFloatACosPiINTEL";
+    case Op::OpArbitraryFloatATanINTEL: return "OpArbitraryFloatATanINTEL";
+    case Op::OpArbitraryFloatATanPiINTEL: return "OpArbitraryFloatATanPiINTEL";
+    case Op::OpArbitraryFloatATan2INTEL: return "OpArbitraryFloatATan2INTEL";
+    case Op::OpArbitraryFloatPowINTEL: return "OpArbitraryFloatPowINTEL";
+    case Op::OpArbitraryFloatPowRINTEL: return "OpArbitraryFloatPowRINTEL";
+    case Op::OpArbitraryFloatPowNINTEL: return "OpArbitraryFloatPowNINTEL";
+    case Op::OpLoopControlINTEL: return "OpLoopControlINTEL";
+    case Op::OpAliasDomainDeclINTEL: return "OpAliasDomainDeclINTEL";
+    case Op::OpAliasScopeDeclINTEL: return "OpAliasScopeDeclINTEL";
+    case Op::OpAliasScopeListDeclINTEL: return "OpAliasScopeListDeclINTEL";
+    case Op::OpFixedSqrtINTEL: return "OpFixedSqrtINTEL";
+    case Op::OpFixedRecipINTEL: return "OpFixedRecipINTEL";
+    case Op::OpFixedRsqrtINTEL: return "OpFixedRsqrtINTEL";
+    case Op::OpFixedSinINTEL: return "OpFixedSinINTEL";
+    case Op::OpFixedCosINTEL: return "OpFixedCosINTEL";
+    case Op::OpFixedSinCosINTEL: return "OpFixedSinCosINTEL";
+    case Op::OpFixedSinPiINTEL: return "OpFixedSinPiINTEL";
+    case Op::OpFixedCosPiINTEL: return "OpFixedCosPiINTEL";
+    case Op::OpFixedSinCosPiINTEL: return "OpFixedSinCosPiINTEL";
+    case Op::OpFixedLogINTEL: return "OpFixedLogINTEL";
+    case Op::OpFixedExpINTEL: return "OpFixedExpINTEL";
+    case Op::OpPtrCastToCrossWorkgroupINTEL: return "OpPtrCastToCrossWorkgroupINTEL";
+    case Op::OpCrossWorkgroupCastToPtrINTEL: return "OpCrossWorkgroupCastToPtrINTEL";
+    case Op::OpReadPipeBlockingINTEL: return "OpReadPipeBlockingINTEL";
+    case Op::OpWritePipeBlockingINTEL: return "OpWritePipeBlockingINTEL";
+    case Op::OpFPGARegINTEL: return "OpFPGARegINTEL";
+    case Op::OpRayQueryGetRayTMinKHR: return "OpRayQueryGetRayTMinKHR";
+    case Op::OpRayQueryGetRayFlagsKHR: return "OpRayQueryGetRayFlagsKHR";
+    case Op::OpRayQueryGetIntersectionTKHR: return "OpRayQueryGetIntersectionTKHR";
+    case Op::OpRayQueryGetIntersectionInstanceCustomIndexKHR: return "OpRayQueryGetIntersectionInstanceCustomIndexKHR";
+    case Op::OpRayQueryGetIntersectionInstanceIdKHR: return "OpRayQueryGetIntersectionInstanceIdKHR";
+    case Op::OpRayQueryGetIntersectionInstanceShaderBindingTableRecordOffsetKHR: return "OpRayQueryGetIntersectionInstanceShaderBindingTableRecordOffsetKHR";
+    case Op::OpRayQueryGetIntersectionGeometryIndexKHR: return "OpRayQueryGetIntersectionGeometryIndexKHR";
+    case Op::OpRayQueryGetIntersectionPrimitiveIndexKHR: return "OpRayQueryGetIntersectionPrimitiveIndexKHR";
+    case Op::OpRayQueryGetIntersectionBarycentricsKHR: return "OpRayQueryGetIntersectionBarycentricsKHR";
+    case Op::OpRayQueryGetIntersectionFrontFaceKHR: return "OpRayQueryGetIntersectionFrontFaceKHR";
+    case Op::OpRayQueryGetIntersectionCandidateAABBOpaqueKHR: return "OpRayQueryGetIntersectionCandidateAABBOpaqueKHR";
+    case Op::OpRayQueryGetIntersectionObjectRayDirectionKHR: return "OpRayQueryGetIntersectionObjectRayDirectionKHR";
+    case Op::OpRayQueryGetIntersectionObjectRayOriginKHR: return "OpRayQueryGetIntersectionObjectRayOriginKHR";
+    case Op::OpRayQueryGetWorldRayDirectionKHR: return "OpRayQueryGetWorldRayDirectionKHR";
+    case Op::OpRayQueryGetWorldRayOriginKHR: return "OpRayQueryGetWorldRayOriginKHR";
+    case Op::OpRayQueryGetIntersectionObjectToWorldKHR: return "OpRayQueryGetIntersectionObjectToWorldKHR";
+    case Op::OpRayQueryGetIntersectionWorldToObjectKHR: return "OpRayQueryGetIntersectionWorldToObjectKHR";
+    case Op::OpAtomicFAddEXT: return "OpAtomicFAddEXT";
+    case Op::OpTypeBufferSurfaceINTEL: return "OpTypeBufferSurfaceINTEL";
+    case Op::OpTypeStructContinuedINTEL: return "OpTypeStructContinuedINTEL";
+    case Op::OpConstantCompositeContinuedINTEL: return "OpConstantCompositeContinuedINTEL";
+    case Op::OpSpecConstantCompositeContinuedINTEL: return "OpSpecConstantCompositeContinuedINTEL";
+    case Op::OpCompositeConstructContinuedINTEL: return "OpCompositeConstructContinuedINTEL";
+    case Op::OpConvertFToBF16INTEL: return "OpConvertFToBF16INTEL";
+    case Op::OpConvertBF16ToFINTEL: return "OpConvertBF16ToFINTEL";
+    case Op::OpControlBarrierArriveINTEL: return "OpControlBarrierArriveINTEL";
+    case Op::OpControlBarrierWaitINTEL: return "OpControlBarrierWaitINTEL";
+    case Op::OpArithmeticFenceEXT: return "OpArithmeticFenceEXT";
+    case Op::OpSubgroupBlockPrefetchINTEL: return "OpSubgroupBlockPrefetchINTEL";
+    case Op::OpGroupIMulKHR: return "OpGroupIMulKHR";
+    case Op::OpGroupFMulKHR: return "OpGroupFMulKHR";
+    case Op::OpGroupBitwiseAndKHR: return "OpGroupBitwiseAndKHR";
+    case Op::OpGroupBitwiseOrKHR: return "OpGroupBitwiseOrKHR";
+    case Op::OpGroupBitwiseXorKHR: return "OpGroupBitwiseXorKHR";
+    case Op::OpGroupLogicalAndKHR: return "OpGroupLogicalAndKHR";
+    case Op::OpGroupLogicalOrKHR: return "OpGroupLogicalOrKHR";
+    case Op::OpGroupLogicalXorKHR: return "OpGroupLogicalXorKHR";
+    case Op::OpMaskedGatherINTEL: return "OpMaskedGatherINTEL";
+    case Op::OpMaskedScatterINTEL: return "OpMaskedScatterINTEL";
+    default: return "Unknown";
+    }
+}
+
 #endif /* SPV_ENABLE_UTILITY_CODE */
 
 // Overload bitwise operators for mask bit combining
@@ -2897,6 +4917,18 @@ constexpr CooperativeMatrixOperandsMask operator|(CooperativeMatrixOperandsMask
 constexpr CooperativeMatrixOperandsMask operator&(CooperativeMatrixOperandsMask a, CooperativeMatrixOperandsMask b) { return CooperativeMatrixOperandsMask(unsigned(a) & unsigned(b)); }
 constexpr CooperativeMatrixOperandsMask operator^(CooperativeMatrixOperandsMask a, CooperativeMatrixOperandsMask b) { return CooperativeMatrixOperandsMask(unsigned(a) ^ unsigned(b)); }
 constexpr CooperativeMatrixOperandsMask operator~(CooperativeMatrixOperandsMask a) { return CooperativeMatrixOperandsMask(~unsigned(a)); }
+constexpr CooperativeMatrixReduceMask operator|(CooperativeMatrixReduceMask a, CooperativeMatrixReduceMask b) { return CooperativeMatrixReduceMask(unsigned(a) | unsigned(b)); }
+constexpr CooperativeMatrixReduceMask operator&(CooperativeMatrixReduceMask a, CooperativeMatrixReduceMask b) { return CooperativeMatrixReduceMask(unsigned(a) & unsigned(b)); }
+constexpr CooperativeMatrixReduceMask operator^(CooperativeMatrixReduceMask a, CooperativeMatrixReduceMask b) { return CooperativeMatrixReduceMask(unsigned(a) ^ unsigned(b)); }
+constexpr CooperativeMatrixReduceMask operator~(CooperativeMatrixReduceMask a) { return CooperativeMatrixReduceMask(~unsigned(a)); }
+constexpr TensorAddressingOperandsMask operator|(TensorAddressingOperandsMask a, TensorAddressingOperandsMask b) { return TensorAddressingOperandsMask(unsigned(a) | unsigned(b)); }
+constexpr TensorAddressingOperandsMask operator&(TensorAddressingOperandsMask a, TensorAddressingOperandsMask b) { return TensorAddressingOperandsMask(unsigned(a) & unsigned(b)); }
+constexpr TensorAddressingOperandsMask operator^(TensorAddressingOperandsMask a, TensorAddressingOperandsMask b) { return TensorAddressingOperandsMask(unsigned(a) ^ unsigned(b)); }
+constexpr TensorAddressingOperandsMask operator~(TensorAddressingOperandsMask a) { return TensorAddressingOperandsMask(~unsigned(a)); }
+constexpr RawAccessChainOperandsMask operator|(RawAccessChainOperandsMask a, RawAccessChainOperandsMask b) { return RawAccessChainOperandsMask(unsigned(a) | unsigned(b)); }
+constexpr RawAccessChainOperandsMask operator&(RawAccessChainOperandsMask a, RawAccessChainOperandsMask b) { return RawAccessChainOperandsMask(unsigned(a) & unsigned(b)); }
+constexpr RawAccessChainOperandsMask operator^(RawAccessChainOperandsMask a, RawAccessChainOperandsMask b) { return RawAccessChainOperandsMask(unsigned(a) ^ unsigned(b)); }
+constexpr RawAccessChainOperandsMask operator~(RawAccessChainOperandsMask a) { return RawAccessChainOperandsMask(~unsigned(a)); }
 
 }  // end namespace spv
 
diff --git a/include/spirv/unified1/spirv.json b/include/spirv/unified1/spirv.json
index ee03b6c..e9cbf74 100644
--- a/include/spirv/unified1/spirv.json
+++ b/include/spirv/unified1/spirv.json
@@ -20,7 +20,7 @@
                     "",
                     "MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS",
                     "STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND",
-                    "HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ ",
+                    "HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/",
                     "",
                     "THE MATERIALS ARE PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS",
                     "OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,",
@@ -193,6 +193,7 @@
                     "EarlyAndLateFragmentTestsAMD": 5017,
                     "StencilRefReplacingEXT": 5027,
                     "CoalescingAMDX": 5069,
+                    "IsApiEntryAMDX": 5070,
                     "MaxNodeRecursionAMDX": 5071,
                     "StaticNumWorkgroupsAMDX": 5072,
                     "ShaderIndexAMDX": 5073,
@@ -205,11 +206,14 @@
                     "StencilRefLessBackAMD": 5084,
                     "QuadDerivativesKHR": 5088,
                     "RequireFullQuadsKHR": 5089,
+                    "SharesInputWithAMDX": 5102,
                     "OutputLinesEXT": 5269,
                     "OutputLinesNV": 5269,
                     "OutputPrimitivesEXT": 5270,
                     "OutputPrimitivesNV": 5270,
+                    "DerivativeGroupQuadsKHR": 5289,
                     "DerivativeGroupQuadsNV": 5289,
+                    "DerivativeGroupLinearKHR": 5290,
                     "DerivativeGroupLinearNV": 5290,
                     "OutputTrianglesEXT": 5298,
                     "OutputTrianglesNV": 5298,
@@ -233,7 +237,10 @@
                     "FPFastMathDefault": 6028,
                     "StreamingInterfaceINTEL": 6154,
                     "RegisterMapInterfaceINTEL": 6160,
-                    "NamedBarrierCountINTEL": 6417
+                    "NamedBarrierCountINTEL": 6417,
+                    "MaximumRegistersINTEL": 6461,
+                    "MaximumRegistersIdINTEL": 6462,
+                    "NamedMaximumRegistersINTEL": 6463
                 }
             },
             {
@@ -256,7 +263,6 @@
                     "StorageBuffer": 12,
                     "TileImageEXT": 4172,
                     "NodePayloadAMDX": 5068,
-                    "NodeOutputPayloadAMDX": 5076,
                     "CallableDataKHR": 5328,
                     "CallableDataNV": 5328,
                     "IncomingCallableDataKHR": 5329,
@@ -413,7 +419,8 @@
                     "UnormInt24": 15,
                     "UnormInt101010_2": 16,
                     "UnsignedIntRaw10EXT": 19,
-                    "UnsignedIntRaw12EXT": 20
+                    "UnsignedIntRaw12EXT": 20,
+                    "UnormInt2_101010EXT": 21
                 }
             },
             {
@@ -563,11 +570,16 @@
                     "NoUnsignedWrap": 4470,
                     "WeightTextureQCOM": 4487,
                     "BlockMatchTextureQCOM": 4488,
+                    "BlockMatchSamplerQCOM": 4499,
                     "ExplicitInterpAMD": 4999,
                     "NodeSharesPayloadLimitsWithAMDX": 5019,
                     "NodeMaxPayloadsAMDX": 5020,
                     "TrackFinishWritingAMDX": 5078,
                     "PayloadNodeNameAMDX": 5091,
+                    "PayloadNodeBaseIndexAMDX": 5098,
+                    "PayloadNodeSparseArrayAMDX": 5099,
+                    "PayloadNodeArraySizeAMDX": 5100,
+                    "PayloadDispatchIndirectAMDX": 5105,
                     "OverrideCoverageNV": 5248,
                     "PassthroughNV": 5250,
                     "ViewportRelativeNV": 5252,
@@ -734,7 +746,7 @@
                     "BaryCoordSmoothSampleAMD": 4997,
                     "BaryCoordPullModelAMD": 4998,
                     "FragStencilRefEXT": 5014,
-                    "CoalescedInputCountAMDX": 5021,
+                    "RemainingRecursionLevelsAMDX": 5021,
                     "ShaderIndexAMDX": 5073,
                     "ViewportMaskNV": 5253,
                     "SecondaryPositionNV": 5257,
@@ -847,6 +859,7 @@
                     "DontInline": 1,
                     "Pure": 2,
                     "Const": 3,
+                    "OptNoneEXT": 16,
                     "OptNoneINTEL": 16
                 }
             },
@@ -1018,6 +1031,7 @@
                     "TileImageColorReadAccessEXT": 4166,
                     "TileImageDepthReadAccessEXT": 4167,
                     "TileImageStencilReadAccessEXT": 4168,
+                    "CooperativeMatrixLayoutsARM": 4201,
                     "FragmentShadingRateKHR": 4422,
                     "SubgroupBallotKHR": 4423,
                     "DrawParameters": 4427,
@@ -1047,11 +1061,13 @@
                     "RoundingModeRTZ": 4468,
                     "RayQueryProvisionalKHR": 4471,
                     "RayQueryKHR": 4472,
+                    "UntypedPointersKHR": 4473,
                     "RayTraversalPrimitiveCullingKHR": 4478,
                     "RayTracingKHR": 4479,
                     "TextureSampleWeightedQCOM": 4484,
                     "TextureBoxFilterQCOM": 4485,
                     "TextureBlockMatchQCOM": 4486,
+                    "TextureBlockMatch2QCOM": 4498,
                     "Float16ImageAMD": 5008,
                     "ImageGatherBiasLodAMD": 5009,
                     "FragmentMaskAMD": 5010,
@@ -1074,6 +1090,7 @@
                     "MeshShadingEXT": 5283,
                     "FragmentBarycentricKHR": 5284,
                     "FragmentBarycentricNV": 5284,
+                    "ComputeDerivativeGroupQuadsKHR": 5288,
                     "ComputeDerivativeGroupQuadsNV": 5288,
                     "FragmentDensityEXT": 5291,
                     "ShadingRateNV": 5291,
@@ -1111,6 +1128,7 @@
                     "VulkanMemoryModelDeviceScopeKHR": 5346,
                     "PhysicalStorageBufferAddresses": 5347,
                     "PhysicalStorageBufferAddressesEXT": 5347,
+                    "ComputeDerivativeGroupLinearKHR": 5350,
                     "ComputeDerivativeGroupLinearNV": 5350,
                     "RayTracingProvisionalKHR": 5353,
                     "CooperativeMatrixNV": 5357,
@@ -1125,7 +1143,15 @@
                     "ShaderInvocationReorderNV": 5383,
                     "BindlessTextureNV": 5390,
                     "RayQueryPositionFetchKHR": 5391,
+                    "AtomicFloat16VectorNV": 5404,
                     "RayTracingDisplacementMicromapNV": 5409,
+                    "RawAccessChainsNV": 5414,
+                    "CooperativeMatrixReductionsNV": 5430,
+                    "CooperativeMatrixConversionsNV": 5431,
+                    "CooperativeMatrixPerElementOperationsNV": 5432,
+                    "CooperativeMatrixTensorAddressingNV": 5433,
+                    "CooperativeMatrixBlockLoadsNV": 5434,
+                    "TensorAddressingNV": 5439,
                     "SubgroupShuffleINTEL": 5568,
                     "SubgroupBufferBlockIOINTEL": 5569,
                     "SubgroupImageBlockIOINTEL": 5570,
@@ -1178,17 +1204,20 @@
                     "DotProductKHR": 6019,
                     "RayCullMaskKHR": 6020,
                     "CooperativeMatrixKHR": 6022,
+                    "ReplicatedCompositesEXT": 6024,
                     "BitInstructions": 6025,
                     "GroupNonUniformRotateKHR": 6026,
                     "FloatControls2": 6029,
                     "AtomicFloat32AddEXT": 6033,
                     "AtomicFloat64AddEXT": 6034,
                     "LongCompositesINTEL": 6089,
+                    "OptNoneEXT": 6094,
                     "OptNoneINTEL": 6094,
                     "AtomicFloat16AddEXT": 6095,
                     "DebugInfoModuleINTEL": 6114,
                     "BFloat16ConversionINTEL": 6115,
                     "SplitBarrierINTEL": 6141,
+                    "ArithmeticFenceEXT": 6144,
                     "FPGAClusterAttributesV2INTEL": 6150,
                     "FPGAKernelAttributesv2INTEL": 6161,
                     "FPMaxErrorINTEL": 6169,
@@ -1196,9 +1225,11 @@
                     "FPGAArgumentInterfacesINTEL": 6174,
                     "GlobalVariableHostAccessINTEL": 6187,
                     "GlobalVariableFPGADecorationsINTEL": 6189,
+                    "SubgroupBufferPrefetchINTEL": 6220,
                     "GroupUniformArithmeticKHR": 6400,
                     "MaskedGatherScatterINTEL": 6427,
-                    "CacheControlsINTEL": 6441
+                    "CacheControlsINTEL": 6441,
+                    "RegisterLimitsINTEL": 6460
                 }
             },
             {
@@ -1329,7 +1360,9 @@
                 "Values":
                 {
                     "RowMajorKHR": 0,
-                    "ColumnMajorKHR": 1
+                    "ColumnMajorKHR": 1,
+                    "RowBlockedInterleavedARM": 4202,
+                    "ColumnBlockedInterleavedARM": 4203
                 }
             },
             {
@@ -1342,6 +1375,37 @@
                     "MatrixAccumulatorKHR": 2
                 }
             },
+            {
+                "Name": "CooperativeMatrixReduce",
+                "Type": "Bit",
+                "Values":
+                {
+                    "Row": 0,
+                    "Column": 1,
+                    "CooperativeMatrixReduce2x2": 2
+                }
+            },
+            {
+                "Name": "TensorClampMode",
+                "Type": "Value",
+                "Values":
+                {
+                    "Undefined": 0,
+                    "Constant": 1,
+                    "ClampToEdge": 2,
+                    "Repeat": 3,
+                    "RepeatMirrored": 4
+                }
+            },
+            {
+                "Name": "TensorAddressingOperands",
+                "Type": "Bit",
+                "Values":
+                {
+                    "TensorView": 0,
+                    "DecodeFunc": 1
+                }
+            },
             {
                 "Name": "InitializationModeQualifier",
                 "Type": "Value",
@@ -1385,6 +1449,30 @@
                     "StreamingINTEL": 3
                 }
             },
+            {
+                "Name": "NamedMaximumNumberOfRegisters",
+                "Type": "Value",
+                "Values":
+                {
+                    "AutoINTEL": 0
+                }
+            },
+            {
+                "Name": "RawAccessChainOperands",
+                "Type": "Bit",
+                "Values":
+                {
+                    "RobustnessPerComponentNV": 0,
+                    "RobustnessPerElementNV": 1
+                }
+            },
+            {
+                "Name": "FPEncoding",
+                "Type": "Value",
+                "Values":
+                {
+                }
+            },
             {
                 "Name": "Op",
                 "Type": "Value",
@@ -1738,13 +1826,22 @@
                     "OpDepthAttachmentReadEXT": 4161,
                     "OpStencilAttachmentReadEXT": 4162,
                     "OpTerminateInvocation": 4416,
+                    "OpTypeUntypedPointerKHR": 4417,
+                    "OpUntypedVariableKHR": 4418,
+                    "OpUntypedAccessChainKHR": 4419,
+                    "OpUntypedInBoundsAccessChainKHR": 4420,
                     "OpSubgroupBallotKHR": 4421,
                     "OpSubgroupFirstInvocationKHR": 4422,
+                    "OpUntypedPtrAccessChainKHR": 4423,
+                    "OpUntypedInBoundsPtrAccessChainKHR": 4424,
+                    "OpUntypedArrayLengthKHR": 4425,
+                    "OpUntypedPrefetchKHR": 4426,
                     "OpSubgroupAllKHR": 4428,
                     "OpSubgroupAnyKHR": 4429,
                     "OpSubgroupAllEqualKHR": 4430,
                     "OpGroupNonUniformRotateKHR": 4431,
                     "OpSubgroupReadInvocationKHR": 4432,
+                    "OpExtInstWithForwardRefsKHR": 4433,
                     "OpTraceRayKHR": 4445,
                     "OpExecuteCallableKHR": 4446,
                     "OpConvertUToAccelerationStructureKHR": 4447,
@@ -1767,6 +1864,9 @@
                     "OpCooperativeMatrixStoreKHR": 4458,
                     "OpCooperativeMatrixMulAddKHR": 4459,
                     "OpCooperativeMatrixLengthKHR": 4460,
+                    "OpConstantCompositeReplicateEXT": 4461,
+                    "OpSpecConstantCompositeReplicateEXT": 4462,
+                    "OpCompositeConstructReplicateEXT": 4463,
                     "OpTypeRayQueryKHR": 4472,
                     "OpRayQueryInitializeKHR": 4473,
                     "OpRayQueryTerminateKHR": 4474,
@@ -1778,6 +1878,10 @@
                     "OpImageBoxFilterQCOM": 4481,
                     "OpImageBlockMatchSSDQCOM": 4482,
                     "OpImageBlockMatchSADQCOM": 4483,
+                    "OpImageBlockMatchWindowSSDQCOM": 4500,
+                    "OpImageBlockMatchWindowSADQCOM": 4501,
+                    "OpImageBlockMatchGatherSSDQCOM": 4502,
+                    "OpImageBlockMatchGatherSADQCOM": 4503,
                     "OpGroupIAddNonUniformAMD": 5000,
                     "OpGroupFAddNonUniformAMD": 5001,
                     "OpGroupFMinNonUniformAMD": 5002,
@@ -1789,9 +1893,14 @@
                     "OpFragmentMaskFetchAMD": 5011,
                     "OpFragmentFetchAMD": 5012,
                     "OpReadClockKHR": 5056,
-                    "OpFinalizeNodePayloadsAMDX": 5075,
+                    "OpAllocateNodePayloadsAMDX": 5074,
+                    "OpEnqueueNodePayloadsAMDX": 5075,
+                    "OpTypeNodePayloadArrayAMDX": 5076,
                     "OpFinishWritingNodePayloadAMDX": 5078,
-                    "OpInitializeNodePayloadsAMDX": 5090,
+                    "OpNodePayloadArrayLengthAMDX": 5090,
+                    "OpIsNodePayloadValidAMDX": 5101,
+                    "OpConstantStringAMDX": 5103,
+                    "OpSpecConstantStringAMDX": 5104,
                     "OpGroupNonUniformQuadAllKHR": 5110,
                     "OpGroupNonUniformQuadAnyKHR": 5111,
                     "OpHitObjectRecordHitMotionNV": 5249,
@@ -1828,6 +1937,7 @@
                     "OpReorderThreadWithHintNV": 5280,
                     "OpTypeHitObjectNV": 5281,
                     "OpImageSampleFootprintNV": 5283,
+                    "OpCooperativeMatrixConvertNV": 5293,
                     "OpEmitMeshTasksEXT": 5294,
                     "OpSetMeshOutputsEXT": 5295,
                     "OpGroupNonUniformPartitionNV": 5296,
@@ -1852,9 +1962,26 @@
                     "OpCooperativeMatrixLengthNV": 5362,
                     "OpBeginInvocationInterlockEXT": 5364,
                     "OpEndInvocationInterlockEXT": 5365,
+                    "OpCooperativeMatrixReduceNV": 5366,
+                    "OpCooperativeMatrixLoadTensorNV": 5367,
+                    "OpCooperativeMatrixStoreTensorNV": 5368,
+                    "OpCooperativeMatrixPerElementOpNV": 5369,
+                    "OpTypeTensorLayoutNV": 5370,
+                    "OpTypeTensorViewNV": 5371,
+                    "OpCreateTensorLayoutNV": 5372,
+                    "OpTensorLayoutSetDimensionNV": 5373,
+                    "OpTensorLayoutSetStrideNV": 5374,
+                    "OpTensorLayoutSliceNV": 5375,
+                    "OpTensorLayoutSetClampValueNV": 5376,
+                    "OpCreateTensorViewNV": 5377,
+                    "OpTensorViewSetDimensionNV": 5378,
+                    "OpTensorViewSetStrideNV": 5379,
                     "OpDemoteToHelperInvocation": 5380,
                     "OpDemoteToHelperInvocationEXT": 5380,
                     "OpIsHelperInvocationEXT": 5381,
+                    "OpTensorViewSetClipNV": 5382,
+                    "OpTensorLayoutSetBlockSizeNV": 5384,
+                    "OpCooperativeMatrixTransposeNV": 5390,
                     "OpConvertUToImageNV": 5391,
                     "OpConvertUToSamplerNV": 5392,
                     "OpConvertImageToUNV": 5393,
@@ -1862,6 +1989,7 @@
                     "OpConvertUToSampledImageNV": 5395,
                     "OpConvertSampledImageToUNV": 5396,
                     "OpSamplerImageAddressingModeNV": 5397,
+                    "OpRawAccessChainNV": 5398,
                     "OpSubgroupShuffleINTEL": 5571,
                     "OpSubgroupShuffleDownINTEL": 5572,
                     "OpSubgroupShuffleUpINTEL": 5573,
@@ -2108,6 +2236,8 @@
                     "OpConvertBF16ToFINTEL": 6117,
                     "OpControlBarrierArriveINTEL": 6142,
                     "OpControlBarrierWaitINTEL": 6143,
+                    "OpArithmeticFenceEXT": 6145,
+                    "OpSubgroupBlockPrefetchINTEL": 6221,
                     "OpGroupIMulKHR": 6401,
                     "OpGroupFMulKHR": 6402,
                     "OpGroupBitwiseAndKHR": 6403,
diff --git a/include/spirv/unified1/spirv.lua b/include/spirv/unified1/spirv.lua
index 391939d..855608c 100644
--- a/include/spirv/unified1/spirv.lua
+++ b/include/spirv/unified1/spirv.lua
@@ -12,7 +12,7 @@
 -- 
 -- MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 -- STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
--- HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+-- HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
 -- 
 -- THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 -- OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -65,6 +65,7 @@ spv = {
         WGSL = 10,
         Slang = 11,
         Zig = 12,
+        Max = 0x7fffffff,
     },
 
     ExecutionModel = {
@@ -91,6 +92,7 @@ spv = {
         CallableNV = 5318,
         TaskEXT = 5364,
         MeshEXT = 5365,
+        Max = 0x7fffffff,
     },
 
     AddressingModel = {
@@ -99,6 +101,7 @@ spv = {
         Physical64 = 2,
         PhysicalStorageBuffer64 = 5348,
         PhysicalStorageBuffer64EXT = 5348,
+        Max = 0x7fffffff,
     },
 
     MemoryModel = {
@@ -107,6 +110,7 @@ spv = {
         OpenCL = 2,
         Vulkan = 3,
         VulkanKHR = 3,
+        Max = 0x7fffffff,
     },
 
     ExecutionMode = {
@@ -161,6 +165,7 @@ spv = {
         EarlyAndLateFragmentTestsAMD = 5017,
         StencilRefReplacingEXT = 5027,
         CoalescingAMDX = 5069,
+        IsApiEntryAMDX = 5070,
         MaxNodeRecursionAMDX = 5071,
         StaticNumWorkgroupsAMDX = 5072,
         ShaderIndexAMDX = 5073,
@@ -173,11 +178,14 @@ spv = {
         StencilRefLessBackAMD = 5084,
         QuadDerivativesKHR = 5088,
         RequireFullQuadsKHR = 5089,
+        SharesInputWithAMDX = 5102,
         OutputLinesEXT = 5269,
         OutputLinesNV = 5269,
         OutputPrimitivesEXT = 5270,
         OutputPrimitivesNV = 5270,
+        DerivativeGroupQuadsKHR = 5289,
         DerivativeGroupQuadsNV = 5289,
+        DerivativeGroupLinearKHR = 5290,
         DerivativeGroupLinearNV = 5290,
         OutputTrianglesEXT = 5298,
         OutputTrianglesNV = 5298,
@@ -202,6 +210,10 @@ spv = {
         StreamingInterfaceINTEL = 6154,
         RegisterMapInterfaceINTEL = 6160,
         NamedBarrierCountINTEL = 6417,
+        MaximumRegistersINTEL = 6461,
+        MaximumRegistersIdINTEL = 6462,
+        NamedMaximumRegistersINTEL = 6463,
+        Max = 0x7fffffff,
     },
 
     StorageClass = {
@@ -220,7 +232,6 @@ spv = {
         StorageBuffer = 12,
         TileImageEXT = 4172,
         NodePayloadAMDX = 5068,
-        NodeOutputPayloadAMDX = 5076,
         CallableDataKHR = 5328,
         CallableDataNV = 5328,
         IncomingCallableDataKHR = 5329,
@@ -240,6 +251,7 @@ spv = {
         CodeSectionINTEL = 5605,
         DeviceOnlyINTEL = 5936,
         HostOnlyINTEL = 5937,
+        Max = 0x7fffffff,
     },
 
     Dim = {
@@ -251,6 +263,7 @@ spv = {
         Buffer = 5,
         SubpassData = 6,
         TileImageDataEXT = 4173,
+        Max = 0x7fffffff,
     },
 
     SamplerAddressingMode = {
@@ -259,11 +272,13 @@ spv = {
         Clamp = 2,
         Repeat = 3,
         RepeatMirrored = 4,
+        Max = 0x7fffffff,
     },
 
     SamplerFilterMode = {
         Nearest = 0,
         Linear = 1,
+        Max = 0x7fffffff,
     },
 
     ImageFormat = {
@@ -309,6 +324,7 @@ spv = {
         R8ui = 39,
         R64ui = 40,
         R64i = 41,
+        Max = 0x7fffffff,
     },
 
     ImageChannelOrder = {
@@ -332,6 +348,7 @@ spv = {
         sRGBA = 17,
         sBGRA = 18,
         ABGR = 19,
+        Max = 0x7fffffff,
     },
 
     ImageChannelDataType = {
@@ -354,6 +371,8 @@ spv = {
         UnormInt101010_2 = 16,
         UnsignedIntRaw10EXT = 19,
         UnsignedIntRaw12EXT = 20,
+        UnormInt2_101010EXT = 21,
+        Max = 0x7fffffff,
     },
 
     ImageOperandsShift = {
@@ -377,6 +396,7 @@ spv = {
         ZeroExtend = 13,
         Nontemporal = 14,
         Offsets = 16,
+        Max = 0x7fffffff,
     },
 
     ImageOperandsMask = {
@@ -414,6 +434,7 @@ spv = {
         AllowReassoc = 17,
         AllowReassocINTEL = 17,
         AllowTransform = 18,
+        Max = 0x7fffffff,
     },
 
     FPFastMathModeMask = {
@@ -435,18 +456,21 @@ spv = {
         RTZ = 1,
         RTP = 2,
         RTN = 3,
+        Max = 0x7fffffff,
     },
 
     LinkageType = {
         Export = 0,
         Import = 1,
         LinkOnceODR = 2,
+        Max = 0x7fffffff,
     },
 
     AccessQualifier = {
         ReadOnly = 0,
         WriteOnly = 1,
         ReadWrite = 2,
+        Max = 0x7fffffff,
     },
 
     FunctionParameterAttribute = {
@@ -459,6 +483,7 @@ spv = {
         NoWrite = 6,
         NoReadWrite = 7,
         RuntimeAlignedINTEL = 5940,
+        Max = 0x7fffffff,
     },
 
     Decoration = {
@@ -513,11 +538,16 @@ spv = {
         NoUnsignedWrap = 4470,
         WeightTextureQCOM = 4487,
         BlockMatchTextureQCOM = 4488,
+        BlockMatchSamplerQCOM = 4499,
         ExplicitInterpAMD = 4999,
         NodeSharesPayloadLimitsWithAMDX = 5019,
         NodeMaxPayloadsAMDX = 5020,
         TrackFinishWritingAMDX = 5078,
         PayloadNodeNameAMDX = 5091,
+        PayloadNodeBaseIndexAMDX = 5098,
+        PayloadNodeSparseArrayAMDX = 5099,
+        PayloadNodeArraySizeAMDX = 5100,
+        PayloadDispatchIndirectAMDX = 5105,
         OverrideCoverageNV = 5248,
         PassthroughNV = 5250,
         ViewportRelativeNV = 5252,
@@ -606,6 +636,7 @@ spv = {
         ImplementInRegisterMapINTEL = 6191,
         CacheControlLoadINTEL = 6442,
         CacheControlStoreINTEL = 6443,
+        Max = 0x7fffffff,
     },
 
     BuiltIn = {
@@ -680,7 +711,7 @@ spv = {
         BaryCoordSmoothSampleAMD = 4997,
         BaryCoordPullModelAMD = 4998,
         FragStencilRefEXT = 5014,
-        CoalescedInputCountAMDX = 5021,
+        RemainingRecursionLevelsAMDX = 5021,
         ShaderIndexAMDX = 5073,
         ViewportMaskNV = 5253,
         SecondaryPositionNV = 5257,
@@ -747,11 +778,13 @@ spv = {
         HitKindFrontFacingMicroTriangleNV = 5405,
         HitKindBackFacingMicroTriangleNV = 5406,
         CullMaskKHR = 6021,
+        Max = 0x7fffffff,
     },
 
     SelectionControlShift = {
         Flatten = 0,
         DontFlatten = 1,
+        Max = 0x7fffffff,
     },
 
     SelectionControlMask = {
@@ -780,6 +813,7 @@ spv = {
         NoFusionINTEL = 23,
         LoopCountINTEL = 24,
         MaxReinvocationDelayINTEL = 25,
+        Max = 0x7fffffff,
     },
 
     LoopControlMask = {
@@ -810,7 +844,9 @@ spv = {
         DontInline = 1,
         Pure = 2,
         Const = 3,
+        OptNoneEXT = 16,
         OptNoneINTEL = 16,
+        Max = 0x7fffffff,
     },
 
     FunctionControlMask = {
@@ -819,6 +855,7 @@ spv = {
         DontInline = 0x00000002,
         Pure = 0x00000004,
         Const = 0x00000008,
+        OptNoneEXT = 0x00010000,
         OptNoneINTEL = 0x00010000,
     },
 
@@ -840,6 +877,7 @@ spv = {
         MakeVisible = 14,
         MakeVisibleKHR = 14,
         Volatile = 15,
+        Max = 0x7fffffff,
     },
 
     MemorySemanticsMask = {
@@ -875,6 +913,7 @@ spv = {
         NonPrivatePointerKHR = 5,
         AliasScopeINTELMask = 16,
         NoAliasINTELMask = 17,
+        Max = 0x7fffffff,
     },
 
     MemoryAccessMask = {
@@ -901,6 +940,7 @@ spv = {
         QueueFamily = 5,
         QueueFamilyKHR = 5,
         ShaderCallKHR = 6,
+        Max = 0x7fffffff,
     },
 
     GroupOperation = {
@@ -911,16 +951,19 @@ spv = {
         PartitionedReduceNV = 6,
         PartitionedInclusiveScanNV = 7,
         PartitionedExclusiveScanNV = 8,
+        Max = 0x7fffffff,
     },
 
     KernelEnqueueFlags = {
         NoWait = 0,
         WaitKernel = 1,
         WaitWorkGroup = 2,
+        Max = 0x7fffffff,
     },
 
     KernelProfilingInfoShift = {
         CmdExecTime = 0,
+        Max = 0x7fffffff,
     },
 
     KernelProfilingInfoMask = {
@@ -1003,6 +1046,7 @@ spv = {
         TileImageColorReadAccessEXT = 4166,
         TileImageDepthReadAccessEXT = 4167,
         TileImageStencilReadAccessEXT = 4168,
+        CooperativeMatrixLayoutsARM = 4201,
         FragmentShadingRateKHR = 4422,
         SubgroupBallotKHR = 4423,
         DrawParameters = 4427,
@@ -1032,11 +1076,13 @@ spv = {
         RoundingModeRTZ = 4468,
         RayQueryProvisionalKHR = 4471,
         RayQueryKHR = 4472,
+        UntypedPointersKHR = 4473,
         RayTraversalPrimitiveCullingKHR = 4478,
         RayTracingKHR = 4479,
         TextureSampleWeightedQCOM = 4484,
         TextureBoxFilterQCOM = 4485,
         TextureBlockMatchQCOM = 4486,
+        TextureBlockMatch2QCOM = 4498,
         Float16ImageAMD = 5008,
         ImageGatherBiasLodAMD = 5009,
         FragmentMaskAMD = 5010,
@@ -1059,6 +1105,7 @@ spv = {
         MeshShadingEXT = 5283,
         FragmentBarycentricKHR = 5284,
         FragmentBarycentricNV = 5284,
+        ComputeDerivativeGroupQuadsKHR = 5288,
         ComputeDerivativeGroupQuadsNV = 5288,
         FragmentDensityEXT = 5291,
         ShadingRateNV = 5291,
@@ -1096,6 +1143,7 @@ spv = {
         VulkanMemoryModelDeviceScopeKHR = 5346,
         PhysicalStorageBufferAddresses = 5347,
         PhysicalStorageBufferAddressesEXT = 5347,
+        ComputeDerivativeGroupLinearKHR = 5350,
         ComputeDerivativeGroupLinearNV = 5350,
         RayTracingProvisionalKHR = 5353,
         CooperativeMatrixNV = 5357,
@@ -1110,7 +1158,15 @@ spv = {
         ShaderInvocationReorderNV = 5383,
         BindlessTextureNV = 5390,
         RayQueryPositionFetchKHR = 5391,
+        AtomicFloat16VectorNV = 5404,
         RayTracingDisplacementMicromapNV = 5409,
+        RawAccessChainsNV = 5414,
+        CooperativeMatrixReductionsNV = 5430,
+        CooperativeMatrixConversionsNV = 5431,
+        CooperativeMatrixPerElementOperationsNV = 5432,
+        CooperativeMatrixTensorAddressingNV = 5433,
+        CooperativeMatrixBlockLoadsNV = 5434,
+        TensorAddressingNV = 5439,
         SubgroupShuffleINTEL = 5568,
         SubgroupBufferBlockIOINTEL = 5569,
         SubgroupImageBlockIOINTEL = 5570,
@@ -1163,17 +1219,20 @@ spv = {
         DotProductKHR = 6019,
         RayCullMaskKHR = 6020,
         CooperativeMatrixKHR = 6022,
+        ReplicatedCompositesEXT = 6024,
         BitInstructions = 6025,
         GroupNonUniformRotateKHR = 6026,
         FloatControls2 = 6029,
         AtomicFloat32AddEXT = 6033,
         AtomicFloat64AddEXT = 6034,
         LongCompositesINTEL = 6089,
+        OptNoneEXT = 6094,
         OptNoneINTEL = 6094,
         AtomicFloat16AddEXT = 6095,
         DebugInfoModuleINTEL = 6114,
         BFloat16ConversionINTEL = 6115,
         SplitBarrierINTEL = 6141,
+        ArithmeticFenceEXT = 6144,
         FPGAClusterAttributesV2INTEL = 6150,
         FPGAKernelAttributesv2INTEL = 6161,
         FPMaxErrorINTEL = 6169,
@@ -1181,9 +1240,12 @@ spv = {
         FPGAArgumentInterfacesINTEL = 6174,
         GlobalVariableHostAccessINTEL = 6187,
         GlobalVariableFPGADecorationsINTEL = 6189,
+        SubgroupBufferPrefetchINTEL = 6220,
         GroupUniformArithmeticKHR = 6400,
         MaskedGatherScatterINTEL = 6427,
         CacheControlsINTEL = 6441,
+        RegisterLimitsINTEL = 6460,
+        Max = 0x7fffffff,
     },
 
     RayFlagsShift = {
@@ -1198,6 +1260,7 @@ spv = {
         SkipTrianglesKHR = 8,
         SkipAABBsKHR = 9,
         ForceOpacityMicromap2StateEXT = 10,
+        Max = 0x7fffffff,
     },
 
     RayFlagsMask = {
@@ -1218,17 +1281,20 @@ spv = {
     RayQueryIntersection = {
         RayQueryCandidateIntersectionKHR = 0,
         RayQueryCommittedIntersectionKHR = 1,
+        Max = 0x7fffffff,
     },
 
     RayQueryCommittedIntersectionType = {
         RayQueryCommittedIntersectionNoneKHR = 0,
         RayQueryCommittedIntersectionTriangleKHR = 1,
         RayQueryCommittedIntersectionGeneratedKHR = 2,
+        Max = 0x7fffffff,
     },
 
     RayQueryCandidateIntersectionType = {
         RayQueryCandidateIntersectionTriangleKHR = 0,
         RayQueryCandidateIntersectionAABBKHR = 1,
+        Max = 0x7fffffff,
     },
 
     FragmentShadingRateShift = {
@@ -1236,6 +1302,7 @@ spv = {
         Vertical4Pixels = 1,
         Horizontal2Pixels = 2,
         Horizontal4Pixels = 3,
+        Max = 0x7fffffff,
     },
 
     FragmentShadingRateMask = {
@@ -1249,11 +1316,13 @@ spv = {
     FPDenormMode = {
         Preserve = 0,
         FlushToZero = 1,
+        Max = 0x7fffffff,
     },
 
     FPOperationMode = {
         IEEE = 0,
         ALT = 1,
+        Max = 0x7fffffff,
     },
 
     QuantizationModes = {
@@ -1265,6 +1334,7 @@ spv = {
         RND_MIN_INF = 5,
         RND_CONV = 6,
         RND_CONV_ODD = 7,
+        Max = 0x7fffffff,
     },
 
     OverflowModes = {
@@ -1272,11 +1342,13 @@ spv = {
         SAT = 1,
         SAT_ZERO = 2,
         SAT_SYM = 3,
+        Max = 0x7fffffff,
     },
 
     PackedVectorFormat = {
         PackedVectorFormat4x8Bit = 0,
         PackedVectorFormat4x8BitKHR = 0,
+        Max = 0x7fffffff,
     },
 
     CooperativeMatrixOperandsShift = {
@@ -1285,6 +1357,7 @@ spv = {
         MatrixCSignedComponentsKHR = 2,
         MatrixResultSignedComponentsKHR = 3,
         SaturatingAccumulationKHR = 4,
+        Max = 0x7fffffff,
     },
 
     CooperativeMatrixOperandsMask = {
@@ -1299,17 +1372,57 @@ spv = {
     CooperativeMatrixLayout = {
         RowMajorKHR = 0,
         ColumnMajorKHR = 1,
+        RowBlockedInterleavedARM = 4202,
+        ColumnBlockedInterleavedARM = 4203,
+        Max = 0x7fffffff,
     },
 
     CooperativeMatrixUse = {
         MatrixAKHR = 0,
         MatrixBKHR = 1,
         MatrixAccumulatorKHR = 2,
+        Max = 0x7fffffff,
+    },
+
+    CooperativeMatrixReduceShift = {
+        Row = 0,
+        Column = 1,
+        CooperativeMatrixReduce2x2 = 2,
+        Max = 0x7fffffff,
+    },
+
+    CooperativeMatrixReduceMask = {
+        MaskNone = 0,
+        Row = 0x00000001,
+        Column = 0x00000002,
+        CooperativeMatrixReduce2x2 = 0x00000004,
+    },
+
+    TensorClampMode = {
+        Undefined = 0,
+        Constant = 1,
+        ClampToEdge = 2,
+        Repeat = 3,
+        RepeatMirrored = 4,
+        Max = 0x7fffffff,
+    },
+
+    TensorAddressingOperandsShift = {
+        TensorView = 0,
+        DecodeFunc = 1,
+        Max = 0x7fffffff,
+    },
+
+    TensorAddressingOperandsMask = {
+        MaskNone = 0,
+        TensorView = 0x00000001,
+        DecodeFunc = 0x00000002,
     },
 
     InitializationModeQualifier = {
         InitOnDeviceReprogramINTEL = 0,
         InitOnDeviceResetINTEL = 1,
+        Max = 0x7fffffff,
     },
 
     HostAccessQualifier = {
@@ -1317,6 +1430,7 @@ spv = {
         ReadINTEL = 1,
         WriteINTEL = 2,
         ReadWriteINTEL = 3,
+        Max = 0x7fffffff,
     },
 
     LoadCacheControl = {
@@ -1325,6 +1439,7 @@ spv = {
         StreamingINTEL = 2,
         InvalidateAfterReadINTEL = 3,
         ConstCachedINTEL = 4,
+        Max = 0x7fffffff,
     },
 
     StoreCacheControl = {
@@ -1332,6 +1447,28 @@ spv = {
         WriteThroughINTEL = 1,
         WriteBackINTEL = 2,
         StreamingINTEL = 3,
+        Max = 0x7fffffff,
+    },
+
+    NamedMaximumNumberOfRegisters = {
+        AutoINTEL = 0,
+        Max = 0x7fffffff,
+    },
+
+    RawAccessChainOperandsShift = {
+        RobustnessPerComponentNV = 0,
+        RobustnessPerElementNV = 1,
+        Max = 0x7fffffff,
+    },
+
+    RawAccessChainOperandsMask = {
+        MaskNone = 0,
+        RobustnessPerComponentNV = 0x00000001,
+        RobustnessPerElementNV = 0x00000002,
+    },
+
+    FPEncoding = {
+        Max = 0x7fffffff,
     },
 
     Op = {
@@ -1683,13 +1820,22 @@ spv = {
         OpDepthAttachmentReadEXT = 4161,
         OpStencilAttachmentReadEXT = 4162,
         OpTerminateInvocation = 4416,
+        OpTypeUntypedPointerKHR = 4417,
+        OpUntypedVariableKHR = 4418,
+        OpUntypedAccessChainKHR = 4419,
+        OpUntypedInBoundsAccessChainKHR = 4420,
         OpSubgroupBallotKHR = 4421,
         OpSubgroupFirstInvocationKHR = 4422,
+        OpUntypedPtrAccessChainKHR = 4423,
+        OpUntypedInBoundsPtrAccessChainKHR = 4424,
+        OpUntypedArrayLengthKHR = 4425,
+        OpUntypedPrefetchKHR = 4426,
         OpSubgroupAllKHR = 4428,
         OpSubgroupAnyKHR = 4429,
         OpSubgroupAllEqualKHR = 4430,
         OpGroupNonUniformRotateKHR = 4431,
         OpSubgroupReadInvocationKHR = 4432,
+        OpExtInstWithForwardRefsKHR = 4433,
         OpTraceRayKHR = 4445,
         OpExecuteCallableKHR = 4446,
         OpConvertUToAccelerationStructureKHR = 4447,
@@ -1712,6 +1858,9 @@ spv = {
         OpCooperativeMatrixStoreKHR = 4458,
         OpCooperativeMatrixMulAddKHR = 4459,
         OpCooperativeMatrixLengthKHR = 4460,
+        OpConstantCompositeReplicateEXT = 4461,
+        OpSpecConstantCompositeReplicateEXT = 4462,
+        OpCompositeConstructReplicateEXT = 4463,
         OpTypeRayQueryKHR = 4472,
         OpRayQueryInitializeKHR = 4473,
         OpRayQueryTerminateKHR = 4474,
@@ -1723,6 +1872,10 @@ spv = {
         OpImageBoxFilterQCOM = 4481,
         OpImageBlockMatchSSDQCOM = 4482,
         OpImageBlockMatchSADQCOM = 4483,
+        OpImageBlockMatchWindowSSDQCOM = 4500,
+        OpImageBlockMatchWindowSADQCOM = 4501,
+        OpImageBlockMatchGatherSSDQCOM = 4502,
+        OpImageBlockMatchGatherSADQCOM = 4503,
         OpGroupIAddNonUniformAMD = 5000,
         OpGroupFAddNonUniformAMD = 5001,
         OpGroupFMinNonUniformAMD = 5002,
@@ -1734,9 +1887,14 @@ spv = {
         OpFragmentMaskFetchAMD = 5011,
         OpFragmentFetchAMD = 5012,
         OpReadClockKHR = 5056,
-        OpFinalizeNodePayloadsAMDX = 5075,
+        OpAllocateNodePayloadsAMDX = 5074,
+        OpEnqueueNodePayloadsAMDX = 5075,
+        OpTypeNodePayloadArrayAMDX = 5076,
         OpFinishWritingNodePayloadAMDX = 5078,
-        OpInitializeNodePayloadsAMDX = 5090,
+        OpNodePayloadArrayLengthAMDX = 5090,
+        OpIsNodePayloadValidAMDX = 5101,
+        OpConstantStringAMDX = 5103,
+        OpSpecConstantStringAMDX = 5104,
         OpGroupNonUniformQuadAllKHR = 5110,
         OpGroupNonUniformQuadAnyKHR = 5111,
         OpHitObjectRecordHitMotionNV = 5249,
@@ -1773,6 +1931,7 @@ spv = {
         OpReorderThreadWithHintNV = 5280,
         OpTypeHitObjectNV = 5281,
         OpImageSampleFootprintNV = 5283,
+        OpCooperativeMatrixConvertNV = 5293,
         OpEmitMeshTasksEXT = 5294,
         OpSetMeshOutputsEXT = 5295,
         OpGroupNonUniformPartitionNV = 5296,
@@ -1797,9 +1956,26 @@ spv = {
         OpCooperativeMatrixLengthNV = 5362,
         OpBeginInvocationInterlockEXT = 5364,
         OpEndInvocationInterlockEXT = 5365,
+        OpCooperativeMatrixReduceNV = 5366,
+        OpCooperativeMatrixLoadTensorNV = 5367,
+        OpCooperativeMatrixStoreTensorNV = 5368,
+        OpCooperativeMatrixPerElementOpNV = 5369,
+        OpTypeTensorLayoutNV = 5370,
+        OpTypeTensorViewNV = 5371,
+        OpCreateTensorLayoutNV = 5372,
+        OpTensorLayoutSetDimensionNV = 5373,
+        OpTensorLayoutSetStrideNV = 5374,
+        OpTensorLayoutSliceNV = 5375,
+        OpTensorLayoutSetClampValueNV = 5376,
+        OpCreateTensorViewNV = 5377,
+        OpTensorViewSetDimensionNV = 5378,
+        OpTensorViewSetStrideNV = 5379,
         OpDemoteToHelperInvocation = 5380,
         OpDemoteToHelperInvocationEXT = 5380,
         OpIsHelperInvocationEXT = 5381,
+        OpTensorViewSetClipNV = 5382,
+        OpTensorLayoutSetBlockSizeNV = 5384,
+        OpCooperativeMatrixTransposeNV = 5390,
         OpConvertUToImageNV = 5391,
         OpConvertUToSamplerNV = 5392,
         OpConvertImageToUNV = 5393,
@@ -1807,6 +1983,7 @@ spv = {
         OpConvertUToSampledImageNV = 5395,
         OpConvertSampledImageToUNV = 5396,
         OpSamplerImageAddressingModeNV = 5397,
+        OpRawAccessChainNV = 5398,
         OpSubgroupShuffleINTEL = 5571,
         OpSubgroupShuffleDownINTEL = 5572,
         OpSubgroupShuffleUpINTEL = 5573,
@@ -2053,6 +2230,8 @@ spv = {
         OpConvertBF16ToFINTEL = 6117,
         OpControlBarrierArriveINTEL = 6142,
         OpControlBarrierWaitINTEL = 6143,
+        OpArithmeticFenceEXT = 6145,
+        OpSubgroupBlockPrefetchINTEL = 6221,
         OpGroupIMulKHR = 6401,
         OpGroupFMulKHR = 6402,
         OpGroupBitwiseAndKHR = 6403,
@@ -2063,6 +2242,7 @@ spv = {
         OpGroupLogicalXorKHR = 6408,
         OpMaskedGatherINTEL = 6428,
         OpMaskedScatterINTEL = 6429,
+        Max = 0x7fffffff,
     },
 
 }
diff --git a/include/spirv/unified1/spirv.py b/include/spirv/unified1/spirv.py
index 3ab1f07..44f2a58 100644
--- a/include/spirv/unified1/spirv.py
+++ b/include/spirv/unified1/spirv.py
@@ -12,7 +12,7 @@
 # 
 # MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 # STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-# HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+# HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
 # 
 # THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -161,6 +161,7 @@ spv = {
         'EarlyAndLateFragmentTestsAMD' : 5017,
         'StencilRefReplacingEXT' : 5027,
         'CoalescingAMDX' : 5069,
+        'IsApiEntryAMDX' : 5070,
         'MaxNodeRecursionAMDX' : 5071,
         'StaticNumWorkgroupsAMDX' : 5072,
         'ShaderIndexAMDX' : 5073,
@@ -173,11 +174,14 @@ spv = {
         'StencilRefLessBackAMD' : 5084,
         'QuadDerivativesKHR' : 5088,
         'RequireFullQuadsKHR' : 5089,
+        'SharesInputWithAMDX' : 5102,
         'OutputLinesEXT' : 5269,
         'OutputLinesNV' : 5269,
         'OutputPrimitivesEXT' : 5270,
         'OutputPrimitivesNV' : 5270,
+        'DerivativeGroupQuadsKHR' : 5289,
         'DerivativeGroupQuadsNV' : 5289,
+        'DerivativeGroupLinearKHR' : 5290,
         'DerivativeGroupLinearNV' : 5290,
         'OutputTrianglesEXT' : 5298,
         'OutputTrianglesNV' : 5298,
@@ -202,6 +206,9 @@ spv = {
         'StreamingInterfaceINTEL' : 6154,
         'RegisterMapInterfaceINTEL' : 6160,
         'NamedBarrierCountINTEL' : 6417,
+        'MaximumRegistersINTEL' : 6461,
+        'MaximumRegistersIdINTEL' : 6462,
+        'NamedMaximumRegistersINTEL' : 6463,
     },
 
     'StorageClass' : {
@@ -220,7 +227,6 @@ spv = {
         'StorageBuffer' : 12,
         'TileImageEXT' : 4172,
         'NodePayloadAMDX' : 5068,
-        'NodeOutputPayloadAMDX' : 5076,
         'CallableDataKHR' : 5328,
         'CallableDataNV' : 5328,
         'IncomingCallableDataKHR' : 5329,
@@ -354,6 +360,7 @@ spv = {
         'UnormInt101010_2' : 16,
         'UnsignedIntRaw10EXT' : 19,
         'UnsignedIntRaw12EXT' : 20,
+        'UnormInt2_101010EXT' : 21,
     },
 
     'ImageOperandsShift' : {
@@ -513,11 +520,16 @@ spv = {
         'NoUnsignedWrap' : 4470,
         'WeightTextureQCOM' : 4487,
         'BlockMatchTextureQCOM' : 4488,
+        'BlockMatchSamplerQCOM' : 4499,
         'ExplicitInterpAMD' : 4999,
         'NodeSharesPayloadLimitsWithAMDX' : 5019,
         'NodeMaxPayloadsAMDX' : 5020,
         'TrackFinishWritingAMDX' : 5078,
         'PayloadNodeNameAMDX' : 5091,
+        'PayloadNodeBaseIndexAMDX' : 5098,
+        'PayloadNodeSparseArrayAMDX' : 5099,
+        'PayloadNodeArraySizeAMDX' : 5100,
+        'PayloadDispatchIndirectAMDX' : 5105,
         'OverrideCoverageNV' : 5248,
         'PassthroughNV' : 5250,
         'ViewportRelativeNV' : 5252,
@@ -680,7 +692,7 @@ spv = {
         'BaryCoordSmoothSampleAMD' : 4997,
         'BaryCoordPullModelAMD' : 4998,
         'FragStencilRefEXT' : 5014,
-        'CoalescedInputCountAMDX' : 5021,
+        'RemainingRecursionLevelsAMDX' : 5021,
         'ShaderIndexAMDX' : 5073,
         'ViewportMaskNV' : 5253,
         'SecondaryPositionNV' : 5257,
@@ -810,6 +822,7 @@ spv = {
         'DontInline' : 1,
         'Pure' : 2,
         'Const' : 3,
+        'OptNoneEXT' : 16,
         'OptNoneINTEL' : 16,
     },
 
@@ -819,6 +832,7 @@ spv = {
         'DontInline' : 0x00000002,
         'Pure' : 0x00000004,
         'Const' : 0x00000008,
+        'OptNoneEXT' : 0x00010000,
         'OptNoneINTEL' : 0x00010000,
     },
 
@@ -1003,6 +1017,7 @@ spv = {
         'TileImageColorReadAccessEXT' : 4166,
         'TileImageDepthReadAccessEXT' : 4167,
         'TileImageStencilReadAccessEXT' : 4168,
+        'CooperativeMatrixLayoutsARM' : 4201,
         'FragmentShadingRateKHR' : 4422,
         'SubgroupBallotKHR' : 4423,
         'DrawParameters' : 4427,
@@ -1032,11 +1047,13 @@ spv = {
         'RoundingModeRTZ' : 4468,
         'RayQueryProvisionalKHR' : 4471,
         'RayQueryKHR' : 4472,
+        'UntypedPointersKHR' : 4473,
         'RayTraversalPrimitiveCullingKHR' : 4478,
         'RayTracingKHR' : 4479,
         'TextureSampleWeightedQCOM' : 4484,
         'TextureBoxFilterQCOM' : 4485,
         'TextureBlockMatchQCOM' : 4486,
+        'TextureBlockMatch2QCOM' : 4498,
         'Float16ImageAMD' : 5008,
         'ImageGatherBiasLodAMD' : 5009,
         'FragmentMaskAMD' : 5010,
@@ -1059,6 +1076,7 @@ spv = {
         'MeshShadingEXT' : 5283,
         'FragmentBarycentricKHR' : 5284,
         'FragmentBarycentricNV' : 5284,
+        'ComputeDerivativeGroupQuadsKHR' : 5288,
         'ComputeDerivativeGroupQuadsNV' : 5288,
         'FragmentDensityEXT' : 5291,
         'ShadingRateNV' : 5291,
@@ -1096,6 +1114,7 @@ spv = {
         'VulkanMemoryModelDeviceScopeKHR' : 5346,
         'PhysicalStorageBufferAddresses' : 5347,
         'PhysicalStorageBufferAddressesEXT' : 5347,
+        'ComputeDerivativeGroupLinearKHR' : 5350,
         'ComputeDerivativeGroupLinearNV' : 5350,
         'RayTracingProvisionalKHR' : 5353,
         'CooperativeMatrixNV' : 5357,
@@ -1110,7 +1129,15 @@ spv = {
         'ShaderInvocationReorderNV' : 5383,
         'BindlessTextureNV' : 5390,
         'RayQueryPositionFetchKHR' : 5391,
+        'AtomicFloat16VectorNV' : 5404,
         'RayTracingDisplacementMicromapNV' : 5409,
+        'RawAccessChainsNV' : 5414,
+        'CooperativeMatrixReductionsNV' : 5430,
+        'CooperativeMatrixConversionsNV' : 5431,
+        'CooperativeMatrixPerElementOperationsNV' : 5432,
+        'CooperativeMatrixTensorAddressingNV' : 5433,
+        'CooperativeMatrixBlockLoadsNV' : 5434,
+        'TensorAddressingNV' : 5439,
         'SubgroupShuffleINTEL' : 5568,
         'SubgroupBufferBlockIOINTEL' : 5569,
         'SubgroupImageBlockIOINTEL' : 5570,
@@ -1163,17 +1190,20 @@ spv = {
         'DotProductKHR' : 6019,
         'RayCullMaskKHR' : 6020,
         'CooperativeMatrixKHR' : 6022,
+        'ReplicatedCompositesEXT' : 6024,
         'BitInstructions' : 6025,
         'GroupNonUniformRotateKHR' : 6026,
         'FloatControls2' : 6029,
         'AtomicFloat32AddEXT' : 6033,
         'AtomicFloat64AddEXT' : 6034,
         'LongCompositesINTEL' : 6089,
+        'OptNoneEXT' : 6094,
         'OptNoneINTEL' : 6094,
         'AtomicFloat16AddEXT' : 6095,
         'DebugInfoModuleINTEL' : 6114,
         'BFloat16ConversionINTEL' : 6115,
         'SplitBarrierINTEL' : 6141,
+        'ArithmeticFenceEXT' : 6144,
         'FPGAClusterAttributesV2INTEL' : 6150,
         'FPGAKernelAttributesv2INTEL' : 6161,
         'FPMaxErrorINTEL' : 6169,
@@ -1181,9 +1211,11 @@ spv = {
         'FPGAArgumentInterfacesINTEL' : 6174,
         'GlobalVariableHostAccessINTEL' : 6187,
         'GlobalVariableFPGADecorationsINTEL' : 6189,
+        'SubgroupBufferPrefetchINTEL' : 6220,
         'GroupUniformArithmeticKHR' : 6400,
         'MaskedGatherScatterINTEL' : 6427,
         'CacheControlsINTEL' : 6441,
+        'RegisterLimitsINTEL' : 6460,
     },
 
     'RayFlagsShift' : {
@@ -1299,6 +1331,8 @@ spv = {
     'CooperativeMatrixLayout' : {
         'RowMajorKHR' : 0,
         'ColumnMajorKHR' : 1,
+        'RowBlockedInterleavedARM' : 4202,
+        'ColumnBlockedInterleavedARM' : 4203,
     },
 
     'CooperativeMatrixUse' : {
@@ -1307,6 +1341,38 @@ spv = {
         'MatrixAccumulatorKHR' : 2,
     },
 
+    'CooperativeMatrixReduceShift' : {
+        'Row' : 0,
+        'Column' : 1,
+        'CooperativeMatrixReduce2x2' : 2,
+    },
+
+    'CooperativeMatrixReduceMask' : {
+        'MaskNone' : 0,
+        'Row' : 0x00000001,
+        'Column' : 0x00000002,
+        'CooperativeMatrixReduce2x2' : 0x00000004,
+    },
+
+    'TensorClampMode' : {
+        'Undefined' : 0,
+        'Constant' : 1,
+        'ClampToEdge' : 2,
+        'Repeat' : 3,
+        'RepeatMirrored' : 4,
+    },
+
+    'TensorAddressingOperandsShift' : {
+        'TensorView' : 0,
+        'DecodeFunc' : 1,
+    },
+
+    'TensorAddressingOperandsMask' : {
+        'MaskNone' : 0,
+        'TensorView' : 0x00000001,
+        'DecodeFunc' : 0x00000002,
+    },
+
     'InitializationModeQualifier' : {
         'InitOnDeviceReprogramINTEL' : 0,
         'InitOnDeviceResetINTEL' : 1,
@@ -1334,6 +1400,24 @@ spv = {
         'StreamingINTEL' : 3,
     },
 
+    'NamedMaximumNumberOfRegisters' : {
+        'AutoINTEL' : 0,
+    },
+
+    'RawAccessChainOperandsShift' : {
+        'RobustnessPerComponentNV' : 0,
+        'RobustnessPerElementNV' : 1,
+    },
+
+    'RawAccessChainOperandsMask' : {
+        'MaskNone' : 0,
+        'RobustnessPerComponentNV' : 0x00000001,
+        'RobustnessPerElementNV' : 0x00000002,
+    },
+
+    'FPEncoding' : {
+    },
+
     'Op' : {
         'OpNop' : 0,
         'OpUndef' : 1,
@@ -1683,13 +1767,22 @@ spv = {
         'OpDepthAttachmentReadEXT' : 4161,
         'OpStencilAttachmentReadEXT' : 4162,
         'OpTerminateInvocation' : 4416,
+        'OpTypeUntypedPointerKHR' : 4417,
+        'OpUntypedVariableKHR' : 4418,
+        'OpUntypedAccessChainKHR' : 4419,
+        'OpUntypedInBoundsAccessChainKHR' : 4420,
         'OpSubgroupBallotKHR' : 4421,
         'OpSubgroupFirstInvocationKHR' : 4422,
+        'OpUntypedPtrAccessChainKHR' : 4423,
+        'OpUntypedInBoundsPtrAccessChainKHR' : 4424,
+        'OpUntypedArrayLengthKHR' : 4425,
+        'OpUntypedPrefetchKHR' : 4426,
         'OpSubgroupAllKHR' : 4428,
         'OpSubgroupAnyKHR' : 4429,
         'OpSubgroupAllEqualKHR' : 4430,
         'OpGroupNonUniformRotateKHR' : 4431,
         'OpSubgroupReadInvocationKHR' : 4432,
+        'OpExtInstWithForwardRefsKHR' : 4433,
         'OpTraceRayKHR' : 4445,
         'OpExecuteCallableKHR' : 4446,
         'OpConvertUToAccelerationStructureKHR' : 4447,
@@ -1712,6 +1805,9 @@ spv = {
         'OpCooperativeMatrixStoreKHR' : 4458,
         'OpCooperativeMatrixMulAddKHR' : 4459,
         'OpCooperativeMatrixLengthKHR' : 4460,
+        'OpConstantCompositeReplicateEXT' : 4461,
+        'OpSpecConstantCompositeReplicateEXT' : 4462,
+        'OpCompositeConstructReplicateEXT' : 4463,
         'OpTypeRayQueryKHR' : 4472,
         'OpRayQueryInitializeKHR' : 4473,
         'OpRayQueryTerminateKHR' : 4474,
@@ -1723,6 +1819,10 @@ spv = {
         'OpImageBoxFilterQCOM' : 4481,
         'OpImageBlockMatchSSDQCOM' : 4482,
         'OpImageBlockMatchSADQCOM' : 4483,
+        'OpImageBlockMatchWindowSSDQCOM' : 4500,
+        'OpImageBlockMatchWindowSADQCOM' : 4501,
+        'OpImageBlockMatchGatherSSDQCOM' : 4502,
+        'OpImageBlockMatchGatherSADQCOM' : 4503,
         'OpGroupIAddNonUniformAMD' : 5000,
         'OpGroupFAddNonUniformAMD' : 5001,
         'OpGroupFMinNonUniformAMD' : 5002,
@@ -1734,9 +1834,14 @@ spv = {
         'OpFragmentMaskFetchAMD' : 5011,
         'OpFragmentFetchAMD' : 5012,
         'OpReadClockKHR' : 5056,
-        'OpFinalizeNodePayloadsAMDX' : 5075,
+        'OpAllocateNodePayloadsAMDX' : 5074,
+        'OpEnqueueNodePayloadsAMDX' : 5075,
+        'OpTypeNodePayloadArrayAMDX' : 5076,
         'OpFinishWritingNodePayloadAMDX' : 5078,
-        'OpInitializeNodePayloadsAMDX' : 5090,
+        'OpNodePayloadArrayLengthAMDX' : 5090,
+        'OpIsNodePayloadValidAMDX' : 5101,
+        'OpConstantStringAMDX' : 5103,
+        'OpSpecConstantStringAMDX' : 5104,
         'OpGroupNonUniformQuadAllKHR' : 5110,
         'OpGroupNonUniformQuadAnyKHR' : 5111,
         'OpHitObjectRecordHitMotionNV' : 5249,
@@ -1773,6 +1878,7 @@ spv = {
         'OpReorderThreadWithHintNV' : 5280,
         'OpTypeHitObjectNV' : 5281,
         'OpImageSampleFootprintNV' : 5283,
+        'OpCooperativeMatrixConvertNV' : 5293,
         'OpEmitMeshTasksEXT' : 5294,
         'OpSetMeshOutputsEXT' : 5295,
         'OpGroupNonUniformPartitionNV' : 5296,
@@ -1797,9 +1903,26 @@ spv = {
         'OpCooperativeMatrixLengthNV' : 5362,
         'OpBeginInvocationInterlockEXT' : 5364,
         'OpEndInvocationInterlockEXT' : 5365,
+        'OpCooperativeMatrixReduceNV' : 5366,
+        'OpCooperativeMatrixLoadTensorNV' : 5367,
+        'OpCooperativeMatrixStoreTensorNV' : 5368,
+        'OpCooperativeMatrixPerElementOpNV' : 5369,
+        'OpTypeTensorLayoutNV' : 5370,
+        'OpTypeTensorViewNV' : 5371,
+        'OpCreateTensorLayoutNV' : 5372,
+        'OpTensorLayoutSetDimensionNV' : 5373,
+        'OpTensorLayoutSetStrideNV' : 5374,
+        'OpTensorLayoutSliceNV' : 5375,
+        'OpTensorLayoutSetClampValueNV' : 5376,
+        'OpCreateTensorViewNV' : 5377,
+        'OpTensorViewSetDimensionNV' : 5378,
+        'OpTensorViewSetStrideNV' : 5379,
         'OpDemoteToHelperInvocation' : 5380,
         'OpDemoteToHelperInvocationEXT' : 5380,
         'OpIsHelperInvocationEXT' : 5381,
+        'OpTensorViewSetClipNV' : 5382,
+        'OpTensorLayoutSetBlockSizeNV' : 5384,
+        'OpCooperativeMatrixTransposeNV' : 5390,
         'OpConvertUToImageNV' : 5391,
         'OpConvertUToSamplerNV' : 5392,
         'OpConvertImageToUNV' : 5393,
@@ -1807,6 +1930,7 @@ spv = {
         'OpConvertUToSampledImageNV' : 5395,
         'OpConvertSampledImageToUNV' : 5396,
         'OpSamplerImageAddressingModeNV' : 5397,
+        'OpRawAccessChainNV' : 5398,
         'OpSubgroupShuffleINTEL' : 5571,
         'OpSubgroupShuffleDownINTEL' : 5572,
         'OpSubgroupShuffleUpINTEL' : 5573,
@@ -2053,6 +2177,8 @@ spv = {
         'OpConvertBF16ToFINTEL' : 6117,
         'OpControlBarrierArriveINTEL' : 6142,
         'OpControlBarrierWaitINTEL' : 6143,
+        'OpArithmeticFenceEXT' : 6145,
+        'OpSubgroupBlockPrefetchINTEL' : 6221,
         'OpGroupIMulKHR' : 6401,
         'OpGroupFMulKHR' : 6402,
         'OpGroupBitwiseAndKHR' : 6403,
diff --git a/include/spirv/unified1/spv.d b/include/spirv/unified1/spv.d
index 7df78cc..73e72c9 100644
--- a/include/spirv/unified1/spv.d
+++ b/include/spirv/unified1/spv.d
@@ -13,7 +13,7 @@
  + 
  + MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
  + STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
- + HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+ + HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
  + 
  + THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  + OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -73,6 +73,7 @@ enum SourceLanguage : uint
     WGSL = 10,
     Slang = 11,
     Zig = 12,
+    Max = 0x7fffffff,
 }
 
 enum ExecutionModel : uint
@@ -100,6 +101,7 @@ enum ExecutionModel : uint
     CallableNV = 5318,
     TaskEXT = 5364,
     MeshEXT = 5365,
+    Max = 0x7fffffff,
 }
 
 enum AddressingModel : uint
@@ -109,6 +111,7 @@ enum AddressingModel : uint
     Physical64 = 2,
     PhysicalStorageBuffer64 = 5348,
     PhysicalStorageBuffer64EXT = 5348,
+    Max = 0x7fffffff,
 }
 
 enum MemoryModel : uint
@@ -118,6 +121,7 @@ enum MemoryModel : uint
     OpenCL = 2,
     Vulkan = 3,
     VulkanKHR = 3,
+    Max = 0x7fffffff,
 }
 
 enum ExecutionMode : uint
@@ -173,6 +177,7 @@ enum ExecutionMode : uint
     EarlyAndLateFragmentTestsAMD = 5017,
     StencilRefReplacingEXT = 5027,
     CoalescingAMDX = 5069,
+    IsApiEntryAMDX = 5070,
     MaxNodeRecursionAMDX = 5071,
     StaticNumWorkgroupsAMDX = 5072,
     ShaderIndexAMDX = 5073,
@@ -185,11 +190,14 @@ enum ExecutionMode : uint
     StencilRefLessBackAMD = 5084,
     QuadDerivativesKHR = 5088,
     RequireFullQuadsKHR = 5089,
+    SharesInputWithAMDX = 5102,
     OutputLinesEXT = 5269,
     OutputLinesNV = 5269,
     OutputPrimitivesEXT = 5270,
     OutputPrimitivesNV = 5270,
+    DerivativeGroupQuadsKHR = 5289,
     DerivativeGroupQuadsNV = 5289,
+    DerivativeGroupLinearKHR = 5290,
     DerivativeGroupLinearNV = 5290,
     OutputTrianglesEXT = 5298,
     OutputTrianglesNV = 5298,
@@ -214,6 +222,10 @@ enum ExecutionMode : uint
     StreamingInterfaceINTEL = 6154,
     RegisterMapInterfaceINTEL = 6160,
     NamedBarrierCountINTEL = 6417,
+    MaximumRegistersINTEL = 6461,
+    MaximumRegistersIdINTEL = 6462,
+    NamedMaximumRegistersINTEL = 6463,
+    Max = 0x7fffffff,
 }
 
 enum StorageClass : uint
@@ -233,7 +245,6 @@ enum StorageClass : uint
     StorageBuffer = 12,
     TileImageEXT = 4172,
     NodePayloadAMDX = 5068,
-    NodeOutputPayloadAMDX = 5076,
     CallableDataKHR = 5328,
     CallableDataNV = 5328,
     IncomingCallableDataKHR = 5329,
@@ -253,6 +264,7 @@ enum StorageClass : uint
     CodeSectionINTEL = 5605,
     DeviceOnlyINTEL = 5936,
     HostOnlyINTEL = 5937,
+    Max = 0x7fffffff,
 }
 
 enum Dim : uint
@@ -265,6 +277,7 @@ enum Dim : uint
     Buffer = 5,
     SubpassData = 6,
     TileImageDataEXT = 4173,
+    Max = 0x7fffffff,
 }
 
 enum SamplerAddressingMode : uint
@@ -274,12 +287,14 @@ enum SamplerAddressingMode : uint
     Clamp = 2,
     Repeat = 3,
     RepeatMirrored = 4,
+    Max = 0x7fffffff,
 }
 
 enum SamplerFilterMode : uint
 {
     Nearest = 0,
     Linear = 1,
+    Max = 0x7fffffff,
 }
 
 enum ImageFormat : uint
@@ -326,6 +341,7 @@ enum ImageFormat : uint
     R8ui = 39,
     R64ui = 40,
     R64i = 41,
+    Max = 0x7fffffff,
 }
 
 enum ImageChannelOrder : uint
@@ -350,6 +366,7 @@ enum ImageChannelOrder : uint
     sRGBA = 17,
     sBGRA = 18,
     ABGR = 19,
+    Max = 0x7fffffff,
 }
 
 enum ImageChannelDataType : uint
@@ -373,6 +390,8 @@ enum ImageChannelDataType : uint
     UnormInt101010_2 = 16,
     UnsignedIntRaw10EXT = 19,
     UnsignedIntRaw12EXT = 20,
+    UnormInt2_101010EXT = 21,
+    Max = 0x7fffffff,
 }
 
 enum ImageOperandsShift : uint
@@ -397,6 +416,7 @@ enum ImageOperandsShift : uint
     ZeroExtend = 13,
     Nontemporal = 14,
     Offsets = 16,
+    Max = 0x7fffffff,
 }
 
 enum ImageOperandsMask : uint
@@ -436,6 +456,7 @@ enum FPFastMathModeShift : uint
     AllowReassoc = 17,
     AllowReassocINTEL = 17,
     AllowTransform = 18,
+    Max = 0x7fffffff,
 }
 
 enum FPFastMathModeMask : uint
@@ -459,6 +480,7 @@ enum FPRoundingMode : uint
     RTZ = 1,
     RTP = 2,
     RTN = 3,
+    Max = 0x7fffffff,
 }
 
 enum LinkageType : uint
@@ -466,6 +488,7 @@ enum LinkageType : uint
     Export = 0,
     Import = 1,
     LinkOnceODR = 2,
+    Max = 0x7fffffff,
 }
 
 enum AccessQualifier : uint
@@ -473,6 +496,7 @@ enum AccessQualifier : uint
     ReadOnly = 0,
     WriteOnly = 1,
     ReadWrite = 2,
+    Max = 0x7fffffff,
 }
 
 enum FunctionParameterAttribute : uint
@@ -486,6 +510,7 @@ enum FunctionParameterAttribute : uint
     NoWrite = 6,
     NoReadWrite = 7,
     RuntimeAlignedINTEL = 5940,
+    Max = 0x7fffffff,
 }
 
 enum Decoration : uint
@@ -541,11 +566,16 @@ enum Decoration : uint
     NoUnsignedWrap = 4470,
     WeightTextureQCOM = 4487,
     BlockMatchTextureQCOM = 4488,
+    BlockMatchSamplerQCOM = 4499,
     ExplicitInterpAMD = 4999,
     NodeSharesPayloadLimitsWithAMDX = 5019,
     NodeMaxPayloadsAMDX = 5020,
     TrackFinishWritingAMDX = 5078,
     PayloadNodeNameAMDX = 5091,
+    PayloadNodeBaseIndexAMDX = 5098,
+    PayloadNodeSparseArrayAMDX = 5099,
+    PayloadNodeArraySizeAMDX = 5100,
+    PayloadDispatchIndirectAMDX = 5105,
     OverrideCoverageNV = 5248,
     PassthroughNV = 5250,
     ViewportRelativeNV = 5252,
@@ -634,6 +664,7 @@ enum Decoration : uint
     ImplementInRegisterMapINTEL = 6191,
     CacheControlLoadINTEL = 6442,
     CacheControlStoreINTEL = 6443,
+    Max = 0x7fffffff,
 }
 
 enum BuiltIn : uint
@@ -709,7 +740,7 @@ enum BuiltIn : uint
     BaryCoordSmoothSampleAMD = 4997,
     BaryCoordPullModelAMD = 4998,
     FragStencilRefEXT = 5014,
-    CoalescedInputCountAMDX = 5021,
+    RemainingRecursionLevelsAMDX = 5021,
     ShaderIndexAMDX = 5073,
     ViewportMaskNV = 5253,
     SecondaryPositionNV = 5257,
@@ -776,12 +807,14 @@ enum BuiltIn : uint
     HitKindFrontFacingMicroTriangleNV = 5405,
     HitKindBackFacingMicroTriangleNV = 5406,
     CullMaskKHR = 6021,
+    Max = 0x7fffffff,
 }
 
 enum SelectionControlShift : uint
 {
     Flatten = 0,
     DontFlatten = 1,
+    Max = 0x7fffffff,
 }
 
 enum SelectionControlMask : uint
@@ -812,6 +845,7 @@ enum LoopControlShift : uint
     NoFusionINTEL = 23,
     LoopCountINTEL = 24,
     MaxReinvocationDelayINTEL = 25,
+    Max = 0x7fffffff,
 }
 
 enum LoopControlMask : uint
@@ -844,7 +878,9 @@ enum FunctionControlShift : uint
     DontInline = 1,
     Pure = 2,
     Const = 3,
+    OptNoneEXT = 16,
     OptNoneINTEL = 16,
+    Max = 0x7fffffff,
 }
 
 enum FunctionControlMask : uint
@@ -854,6 +890,7 @@ enum FunctionControlMask : uint
     DontInline = 0x00000002,
     Pure = 0x00000004,
     Const = 0x00000008,
+    OptNoneEXT = 0x00010000,
     OptNoneINTEL = 0x00010000,
 }
 
@@ -876,6 +913,7 @@ enum MemorySemanticsShift : uint
     MakeVisible = 14,
     MakeVisibleKHR = 14,
     Volatile = 15,
+    Max = 0x7fffffff,
 }
 
 enum MemorySemanticsMask : uint
@@ -913,6 +951,7 @@ enum MemoryAccessShift : uint
     NonPrivatePointerKHR = 5,
     AliasScopeINTELMask = 16,
     NoAliasINTELMask = 17,
+    Max = 0x7fffffff,
 }
 
 enum MemoryAccessMask : uint
@@ -941,6 +980,7 @@ enum Scope : uint
     QueueFamily = 5,
     QueueFamilyKHR = 5,
     ShaderCallKHR = 6,
+    Max = 0x7fffffff,
 }
 
 enum GroupOperation : uint
@@ -952,6 +992,7 @@ enum GroupOperation : uint
     PartitionedReduceNV = 6,
     PartitionedInclusiveScanNV = 7,
     PartitionedExclusiveScanNV = 8,
+    Max = 0x7fffffff,
 }
 
 enum KernelEnqueueFlags : uint
@@ -959,11 +1000,13 @@ enum KernelEnqueueFlags : uint
     NoWait = 0,
     WaitKernel = 1,
     WaitWorkGroup = 2,
+    Max = 0x7fffffff,
 }
 
 enum KernelProfilingInfoShift : uint
 {
     CmdExecTime = 0,
+    Max = 0x7fffffff,
 }
 
 enum KernelProfilingInfoMask : uint
@@ -1048,6 +1091,7 @@ enum Capability : uint
     TileImageColorReadAccessEXT = 4166,
     TileImageDepthReadAccessEXT = 4167,
     TileImageStencilReadAccessEXT = 4168,
+    CooperativeMatrixLayoutsARM = 4201,
     FragmentShadingRateKHR = 4422,
     SubgroupBallotKHR = 4423,
     DrawParameters = 4427,
@@ -1077,11 +1121,13 @@ enum Capability : uint
     RoundingModeRTZ = 4468,
     RayQueryProvisionalKHR = 4471,
     RayQueryKHR = 4472,
+    UntypedPointersKHR = 4473,
     RayTraversalPrimitiveCullingKHR = 4478,
     RayTracingKHR = 4479,
     TextureSampleWeightedQCOM = 4484,
     TextureBoxFilterQCOM = 4485,
     TextureBlockMatchQCOM = 4486,
+    TextureBlockMatch2QCOM = 4498,
     Float16ImageAMD = 5008,
     ImageGatherBiasLodAMD = 5009,
     FragmentMaskAMD = 5010,
@@ -1104,6 +1150,7 @@ enum Capability : uint
     MeshShadingEXT = 5283,
     FragmentBarycentricKHR = 5284,
     FragmentBarycentricNV = 5284,
+    ComputeDerivativeGroupQuadsKHR = 5288,
     ComputeDerivativeGroupQuadsNV = 5288,
     FragmentDensityEXT = 5291,
     ShadingRateNV = 5291,
@@ -1141,6 +1188,7 @@ enum Capability : uint
     VulkanMemoryModelDeviceScopeKHR = 5346,
     PhysicalStorageBufferAddresses = 5347,
     PhysicalStorageBufferAddressesEXT = 5347,
+    ComputeDerivativeGroupLinearKHR = 5350,
     ComputeDerivativeGroupLinearNV = 5350,
     RayTracingProvisionalKHR = 5353,
     CooperativeMatrixNV = 5357,
@@ -1155,7 +1203,15 @@ enum Capability : uint
     ShaderInvocationReorderNV = 5383,
     BindlessTextureNV = 5390,
     RayQueryPositionFetchKHR = 5391,
+    AtomicFloat16VectorNV = 5404,
     RayTracingDisplacementMicromapNV = 5409,
+    RawAccessChainsNV = 5414,
+    CooperativeMatrixReductionsNV = 5430,
+    CooperativeMatrixConversionsNV = 5431,
+    CooperativeMatrixPerElementOperationsNV = 5432,
+    CooperativeMatrixTensorAddressingNV = 5433,
+    CooperativeMatrixBlockLoadsNV = 5434,
+    TensorAddressingNV = 5439,
     SubgroupShuffleINTEL = 5568,
     SubgroupBufferBlockIOINTEL = 5569,
     SubgroupImageBlockIOINTEL = 5570,
@@ -1208,17 +1264,20 @@ enum Capability : uint
     DotProductKHR = 6019,
     RayCullMaskKHR = 6020,
     CooperativeMatrixKHR = 6022,
+    ReplicatedCompositesEXT = 6024,
     BitInstructions = 6025,
     GroupNonUniformRotateKHR = 6026,
     FloatControls2 = 6029,
     AtomicFloat32AddEXT = 6033,
     AtomicFloat64AddEXT = 6034,
     LongCompositesINTEL = 6089,
+    OptNoneEXT = 6094,
     OptNoneINTEL = 6094,
     AtomicFloat16AddEXT = 6095,
     DebugInfoModuleINTEL = 6114,
     BFloat16ConversionINTEL = 6115,
     SplitBarrierINTEL = 6141,
+    ArithmeticFenceEXT = 6144,
     FPGAClusterAttributesV2INTEL = 6150,
     FPGAKernelAttributesv2INTEL = 6161,
     FPMaxErrorINTEL = 6169,
@@ -1226,9 +1285,12 @@ enum Capability : uint
     FPGAArgumentInterfacesINTEL = 6174,
     GlobalVariableHostAccessINTEL = 6187,
     GlobalVariableFPGADecorationsINTEL = 6189,
+    SubgroupBufferPrefetchINTEL = 6220,
     GroupUniformArithmeticKHR = 6400,
     MaskedGatherScatterINTEL = 6427,
     CacheControlsINTEL = 6441,
+    RegisterLimitsINTEL = 6460,
+    Max = 0x7fffffff,
 }
 
 enum RayFlagsShift : uint
@@ -1244,6 +1306,7 @@ enum RayFlagsShift : uint
     SkipTrianglesKHR = 8,
     SkipAABBsKHR = 9,
     ForceOpacityMicromap2StateEXT = 10,
+    Max = 0x7fffffff,
 }
 
 enum RayFlagsMask : uint
@@ -1266,6 +1329,7 @@ enum RayQueryIntersection : uint
 {
     RayQueryCandidateIntersectionKHR = 0,
     RayQueryCommittedIntersectionKHR = 1,
+    Max = 0x7fffffff,
 }
 
 enum RayQueryCommittedIntersectionType : uint
@@ -1273,12 +1337,14 @@ enum RayQueryCommittedIntersectionType : uint
     RayQueryCommittedIntersectionNoneKHR = 0,
     RayQueryCommittedIntersectionTriangleKHR = 1,
     RayQueryCommittedIntersectionGeneratedKHR = 2,
+    Max = 0x7fffffff,
 }
 
 enum RayQueryCandidateIntersectionType : uint
 {
     RayQueryCandidateIntersectionTriangleKHR = 0,
     RayQueryCandidateIntersectionAABBKHR = 1,
+    Max = 0x7fffffff,
 }
 
 enum FragmentShadingRateShift : uint
@@ -1287,6 +1353,7 @@ enum FragmentShadingRateShift : uint
     Vertical4Pixels = 1,
     Horizontal2Pixels = 2,
     Horizontal4Pixels = 3,
+    Max = 0x7fffffff,
 }
 
 enum FragmentShadingRateMask : uint
@@ -1302,12 +1369,14 @@ enum FPDenormMode : uint
 {
     Preserve = 0,
     FlushToZero = 1,
+    Max = 0x7fffffff,
 }
 
 enum FPOperationMode : uint
 {
     IEEE = 0,
     ALT = 1,
+    Max = 0x7fffffff,
 }
 
 enum QuantizationModes : uint
@@ -1320,6 +1389,7 @@ enum QuantizationModes : uint
     RND_MIN_INF = 5,
     RND_CONV = 6,
     RND_CONV_ODD = 7,
+    Max = 0x7fffffff,
 }
 
 enum OverflowModes : uint
@@ -1328,12 +1398,14 @@ enum OverflowModes : uint
     SAT = 1,
     SAT_ZERO = 2,
     SAT_SYM = 3,
+    Max = 0x7fffffff,
 }
 
 enum PackedVectorFormat : uint
 {
     PackedVectorFormat4x8Bit = 0,
     PackedVectorFormat4x8BitKHR = 0,
+    Max = 0x7fffffff,
 }
 
 enum CooperativeMatrixOperandsShift : uint
@@ -1343,6 +1415,7 @@ enum CooperativeMatrixOperandsShift : uint
     MatrixCSignedComponentsKHR = 2,
     MatrixResultSignedComponentsKHR = 3,
     SaturatingAccumulationKHR = 4,
+    Max = 0x7fffffff,
 }
 
 enum CooperativeMatrixOperandsMask : uint
@@ -1359,6 +1432,9 @@ enum CooperativeMatrixLayout : uint
 {
     RowMajorKHR = 0,
     ColumnMajorKHR = 1,
+    RowBlockedInterleavedARM = 4202,
+    ColumnBlockedInterleavedARM = 4203,
+    Max = 0x7fffffff,
 }
 
 enum CooperativeMatrixUse : uint
@@ -1366,12 +1442,54 @@ enum CooperativeMatrixUse : uint
     MatrixAKHR = 0,
     MatrixBKHR = 1,
     MatrixAccumulatorKHR = 2,
+    Max = 0x7fffffff,
+}
+
+enum CooperativeMatrixReduceShift : uint
+{
+    Row = 0,
+    Column = 1,
+    _2x2 = 2,
+    Max = 0x7fffffff,
+}
+
+enum CooperativeMatrixReduceMask : uint
+{
+    MaskNone = 0,
+    Row = 0x00000001,
+    Column = 0x00000002,
+    _2x2 = 0x00000004,
+}
+
+enum TensorClampMode : uint
+{
+    Undefined = 0,
+    Constant = 1,
+    ClampToEdge = 2,
+    Repeat = 3,
+    RepeatMirrored = 4,
+    Max = 0x7fffffff,
+}
+
+enum TensorAddressingOperandsShift : uint
+{
+    TensorView = 0,
+    DecodeFunc = 1,
+    Max = 0x7fffffff,
+}
+
+enum TensorAddressingOperandsMask : uint
+{
+    MaskNone = 0,
+    TensorView = 0x00000001,
+    DecodeFunc = 0x00000002,
 }
 
 enum InitializationModeQualifier : uint
 {
     InitOnDeviceReprogramINTEL = 0,
     InitOnDeviceResetINTEL = 1,
+    Max = 0x7fffffff,
 }
 
 enum HostAccessQualifier : uint
@@ -1380,6 +1498,7 @@ enum HostAccessQualifier : uint
     ReadINTEL = 1,
     WriteINTEL = 2,
     ReadWriteINTEL = 3,
+    Max = 0x7fffffff,
 }
 
 enum LoadCacheControl : uint
@@ -1389,6 +1508,7 @@ enum LoadCacheControl : uint
     StreamingINTEL = 2,
     InvalidateAfterReadINTEL = 3,
     ConstCachedINTEL = 4,
+    Max = 0x7fffffff,
 }
 
 enum StoreCacheControl : uint
@@ -1397,6 +1517,32 @@ enum StoreCacheControl : uint
     WriteThroughINTEL = 1,
     WriteBackINTEL = 2,
     StreamingINTEL = 3,
+    Max = 0x7fffffff,
+}
+
+enum NamedMaximumNumberOfRegisters : uint
+{
+    AutoINTEL = 0,
+    Max = 0x7fffffff,
+}
+
+enum RawAccessChainOperandsShift : uint
+{
+    RobustnessPerComponentNV = 0,
+    RobustnessPerElementNV = 1,
+    Max = 0x7fffffff,
+}
+
+enum RawAccessChainOperandsMask : uint
+{
+    MaskNone = 0,
+    RobustnessPerComponentNV = 0x00000001,
+    RobustnessPerElementNV = 0x00000002,
+}
+
+enum FPEncoding : uint
+{
+    Max = 0x7fffffff,
 }
 
 enum Op : uint
@@ -1749,13 +1895,22 @@ enum Op : uint
     OpDepthAttachmentReadEXT = 4161,
     OpStencilAttachmentReadEXT = 4162,
     OpTerminateInvocation = 4416,
+    OpTypeUntypedPointerKHR = 4417,
+    OpUntypedVariableKHR = 4418,
+    OpUntypedAccessChainKHR = 4419,
+    OpUntypedInBoundsAccessChainKHR = 4420,
     OpSubgroupBallotKHR = 4421,
     OpSubgroupFirstInvocationKHR = 4422,
+    OpUntypedPtrAccessChainKHR = 4423,
+    OpUntypedInBoundsPtrAccessChainKHR = 4424,
+    OpUntypedArrayLengthKHR = 4425,
+    OpUntypedPrefetchKHR = 4426,
     OpSubgroupAllKHR = 4428,
     OpSubgroupAnyKHR = 4429,
     OpSubgroupAllEqualKHR = 4430,
     OpGroupNonUniformRotateKHR = 4431,
     OpSubgroupReadInvocationKHR = 4432,
+    OpExtInstWithForwardRefsKHR = 4433,
     OpTraceRayKHR = 4445,
     OpExecuteCallableKHR = 4446,
     OpConvertUToAccelerationStructureKHR = 4447,
@@ -1778,6 +1933,9 @@ enum Op : uint
     OpCooperativeMatrixStoreKHR = 4458,
     OpCooperativeMatrixMulAddKHR = 4459,
     OpCooperativeMatrixLengthKHR = 4460,
+    OpConstantCompositeReplicateEXT = 4461,
+    OpSpecConstantCompositeReplicateEXT = 4462,
+    OpCompositeConstructReplicateEXT = 4463,
     OpTypeRayQueryKHR = 4472,
     OpRayQueryInitializeKHR = 4473,
     OpRayQueryTerminateKHR = 4474,
@@ -1789,6 +1947,10 @@ enum Op : uint
     OpImageBoxFilterQCOM = 4481,
     OpImageBlockMatchSSDQCOM = 4482,
     OpImageBlockMatchSADQCOM = 4483,
+    OpImageBlockMatchWindowSSDQCOM = 4500,
+    OpImageBlockMatchWindowSADQCOM = 4501,
+    OpImageBlockMatchGatherSSDQCOM = 4502,
+    OpImageBlockMatchGatherSADQCOM = 4503,
     OpGroupIAddNonUniformAMD = 5000,
     OpGroupFAddNonUniformAMD = 5001,
     OpGroupFMinNonUniformAMD = 5002,
@@ -1800,9 +1962,14 @@ enum Op : uint
     OpFragmentMaskFetchAMD = 5011,
     OpFragmentFetchAMD = 5012,
     OpReadClockKHR = 5056,
-    OpFinalizeNodePayloadsAMDX = 5075,
+    OpAllocateNodePayloadsAMDX = 5074,
+    OpEnqueueNodePayloadsAMDX = 5075,
+    OpTypeNodePayloadArrayAMDX = 5076,
     OpFinishWritingNodePayloadAMDX = 5078,
-    OpInitializeNodePayloadsAMDX = 5090,
+    OpNodePayloadArrayLengthAMDX = 5090,
+    OpIsNodePayloadValidAMDX = 5101,
+    OpConstantStringAMDX = 5103,
+    OpSpecConstantStringAMDX = 5104,
     OpGroupNonUniformQuadAllKHR = 5110,
     OpGroupNonUniformQuadAnyKHR = 5111,
     OpHitObjectRecordHitMotionNV = 5249,
@@ -1839,6 +2006,7 @@ enum Op : uint
     OpReorderThreadWithHintNV = 5280,
     OpTypeHitObjectNV = 5281,
     OpImageSampleFootprintNV = 5283,
+    OpCooperativeMatrixConvertNV = 5293,
     OpEmitMeshTasksEXT = 5294,
     OpSetMeshOutputsEXT = 5295,
     OpGroupNonUniformPartitionNV = 5296,
@@ -1863,9 +2031,26 @@ enum Op : uint
     OpCooperativeMatrixLengthNV = 5362,
     OpBeginInvocationInterlockEXT = 5364,
     OpEndInvocationInterlockEXT = 5365,
+    OpCooperativeMatrixReduceNV = 5366,
+    OpCooperativeMatrixLoadTensorNV = 5367,
+    OpCooperativeMatrixStoreTensorNV = 5368,
+    OpCooperativeMatrixPerElementOpNV = 5369,
+    OpTypeTensorLayoutNV = 5370,
+    OpTypeTensorViewNV = 5371,
+    OpCreateTensorLayoutNV = 5372,
+    OpTensorLayoutSetDimensionNV = 5373,
+    OpTensorLayoutSetStrideNV = 5374,
+    OpTensorLayoutSliceNV = 5375,
+    OpTensorLayoutSetClampValueNV = 5376,
+    OpCreateTensorViewNV = 5377,
+    OpTensorViewSetDimensionNV = 5378,
+    OpTensorViewSetStrideNV = 5379,
     OpDemoteToHelperInvocation = 5380,
     OpDemoteToHelperInvocationEXT = 5380,
     OpIsHelperInvocationEXT = 5381,
+    OpTensorViewSetClipNV = 5382,
+    OpTensorLayoutSetBlockSizeNV = 5384,
+    OpCooperativeMatrixTransposeNV = 5390,
     OpConvertUToImageNV = 5391,
     OpConvertUToSamplerNV = 5392,
     OpConvertImageToUNV = 5393,
@@ -1873,6 +2058,7 @@ enum Op : uint
     OpConvertUToSampledImageNV = 5395,
     OpConvertSampledImageToUNV = 5396,
     OpSamplerImageAddressingModeNV = 5397,
+    OpRawAccessChainNV = 5398,
     OpSubgroupShuffleINTEL = 5571,
     OpSubgroupShuffleDownINTEL = 5572,
     OpSubgroupShuffleUpINTEL = 5573,
@@ -2119,6 +2305,8 @@ enum Op : uint
     OpConvertBF16ToFINTEL = 6117,
     OpControlBarrierArriveINTEL = 6142,
     OpControlBarrierWaitINTEL = 6143,
+    OpArithmeticFenceEXT = 6145,
+    OpSubgroupBlockPrefetchINTEL = 6221,
     OpGroupIMulKHR = 6401,
     OpGroupFMulKHR = 6402,
     OpGroupBitwiseAndKHR = 6403,
@@ -2129,6 +2317,7 @@ enum Op : uint
     OpGroupLogicalXorKHR = 6408,
     OpMaskedGatherINTEL = 6428,
     OpMaskedScatterINTEL = 6429,
+    Max = 0x7fffffff,
 }
 
 
diff --git a/tests/CMakeLists.txt b/tests/CMakeLists.txt
index 956cbd6..88a956c 100644
--- a/tests/CMakeLists.txt
+++ b/tests/CMakeLists.txt
@@ -24,15 +24,22 @@
 # TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # MATERIALS OR THE USE OR OTHER DEALINGS IN THE MATERIALS.
 
-add_library(simple_test STATIC)
+add_executable(spirv_headers_simple_test example.cpp)
+target_compile_definitions(spirv_headers_simple_test PRIVATE SPV_ENABLE_UTILITY_CODE)
+target_link_libraries(spirv_headers_simple_test PRIVATE SPIRV-Headers::SPIRV-Headers)
+add_test(NAME spirv_headers_simple_test COMMAND spirv_headers_simple_test)
 
-target_sources(simple_test PRIVATE
-    example.cpp
-)
+add_executable(spirv_headers_simple_test_cpp11 example11.cpp)
+target_compile_definitions(spirv_headers_simple_test_cpp11 PRIVATE SPV_ENABLE_UTILITY_CODE)
+target_link_libraries(spirv_headers_simple_test_cpp11 PRIVATE SPIRV-Headers::SPIRV-Headers)
+set_target_properties(spirv_headers_simple_test_cpp11 PROPERTIES CXX_STANDARD 11)
+add_test(NAME spirv_headers_simple_test_cpp11 COMMAND spirv_headers_simple_test_cpp11)
 
-target_link_libraries(simple_test PRIVATE
-    SPIRV-Headers::SPIRV-Headers
-)
+add_executable(spirv_headers_simple_test_c example.c)
+target_compile_definitions(spirv_headers_simple_test_c PRIVATE SPV_ENABLE_UTILITY_CODE)
+target_link_libraries(spirv_headers_simple_test_c PRIVATE SPIRV-Headers::SPIRV-Headers)
+set_target_properties(spirv_headers_simple_test_c PROPERTIES C_STANDARD 99 LINKER_LANGUAGE C)
+add_test(NAME spirv_headers_simple_test_c COMMAND spirv_headers_simple_test_c)
 
 if (NOT TARGET SPIRV-Headers)
     message(FATAL_ERROR "SPIRV-Headers target not defined!")
diff --git a/tests/example.c b/tests/example.c
new file mode 100644
index 0000000..11e8e81
--- /dev/null
+++ b/tests/example.c
@@ -0,0 +1,37 @@
+// Copyright (c) 2016-2024 The Khronos Group Inc.
+//
+// Permission is hereby granted, free of charge, to any person obtaining a
+// copy of this software and/or associated documentation files (the
+// "Materials"), to deal in the Materials without restriction, including
+// without limitation the rights to use, copy, modify, merge, publish,
+// distribute, sublicense, and/or sell copies of the Materials, and to
+// permit persons to whom the Materials are furnished to do so, subject to
+// the following conditions:
+//
+// The above copyright notice and this permission notice shall be included
+// in all copies or substantial portions of the Materials.
+//
+// MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS
+// KHRONOS STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS
+// SPECIFICATIONS AND HEADER INFORMATION ARE LOCATED AT
+//    https://www.khronos.org/registry/
+//
+// THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+// MATERIALS OR THE USE OR OTHER DEALINGS IN THE MATERIALS.
+
+#include <spirv/unified1/GLSL.std.450.h>
+#include <spirv/unified1/OpenCL.std.h>
+#include <spirv/unified1/spirv.h>
+
+const enum GLSLstd450 kSin = GLSLstd450Sin;
+const enum OpenCLstd_Entrypoints kNative_cos = OpenCLstd_Native_cos;
+const SpvOp kNop = SpvOpNop;
+
+int main() {
+  return 0;
+}
diff --git a/tests/example.cpp b/tests/example.cpp
index 1920e80..b506236 100644
--- a/tests/example.cpp
+++ b/tests/example.cpp
@@ -1,5 +1,5 @@
 // Copyright (c) 2016-2024 The Khronos Group Inc.
-// 
+//
 // Permission is hereby granted, free of charge, to any person obtaining a
 // copy of this software and/or associated documentation files (the
 // "Materials"), to deal in the Materials without restriction, including
@@ -7,15 +7,15 @@
 // distribute, sublicense, and/or sell copies of the Materials, and to
 // permit persons to whom the Materials are furnished to do so, subject to
 // the following conditions:
-// 
+//
 // The above copyright notice and this permission notice shall be included
 // in all copies or substantial portions of the Materials.
-// 
+//
 // MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS
 // KHRONOS STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS
 // SPECIFICATIONS AND HEADER INFORMATION ARE LOCATED AT
 //    https://www.khronos.org/registry/
-// 
+//
 // THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 // EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
@@ -35,3 +35,7 @@ const OpenCLLIB::Entrypoints kNative_cos = OpenCLLIB::Native_cos;
 const spv::Op kNop = spv::OpNop;
 
 }  // anonymous namespace
+
+int main() {
+  return 0;
+}
diff --git a/tests/example11.cpp b/tests/example11.cpp
new file mode 100644
index 0000000..c1f0a79
--- /dev/null
+++ b/tests/example11.cpp
@@ -0,0 +1,41 @@
+// Copyright (c) 2016-2024 The Khronos Group Inc.
+//
+// Permission is hereby granted, free of charge, to any person obtaining a
+// copy of this software and/or associated documentation files (the
+// "Materials"), to deal in the Materials without restriction, including
+// without limitation the rights to use, copy, modify, merge, publish,
+// distribute, sublicense, and/or sell copies of the Materials, and to
+// permit persons to whom the Materials are furnished to do so, subject to
+// the following conditions:
+//
+// The above copyright notice and this permission notice shall be included
+// in all copies or substantial portions of the Materials.
+//
+// MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS
+// KHRONOS STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS
+// SPECIFICATIONS AND HEADER INFORMATION ARE LOCATED AT
+//    https://www.khronos.org/registry/
+//
+// THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+// MATERIALS OR THE USE OR OTHER DEALINGS IN THE MATERIALS.
+
+#include <spirv/unified1/GLSL.std.450.h>
+#include <spirv/unified1/OpenCL.std.h>
+#include <spirv/unified1/spirv.hpp11>
+
+namespace {
+
+const GLSLstd450 kSin = GLSLstd450Sin;
+const OpenCLLIB::Entrypoints kNative_cos = OpenCLLIB::Native_cos;
+const spv::Op kNop = spv::Op::OpNop;
+
+}  // anonymous namespace
+
+int main() {
+  return 0;
+}
diff --git a/tools/buildHeaders/header.cpp b/tools/buildHeaders/header.cpp
index d125a79..a557097 100644
--- a/tools/buildHeaders/header.cpp
+++ b/tools/buildHeaders/header.cpp
@@ -98,7 +98,7 @@ namespace {
         virtual void printEpilogue(std::ostream&) const { }
         virtual void printMeta(std::ostream&)     const;
         virtual void printTypes(std::ostream&)    const { }
-        virtual void printHasResultType(std::ostream&)     const { };
+        virtual void printUtility(std::ostream&)     const { };
 
         virtual std::string escapeComment(const std::string& s) const;
 
@@ -119,9 +119,9 @@ namespace {
                                     enumStyle_t, bool isLast = false) const {
             return "";
         }
-        virtual std::string maxEnumFmt(const std::string&, const valpair_t&,
-                                       enumStyle_t) const {
-            return "";
+        virtual std::string maxEnumFmt(const std::string& s, const valpair_t& v,
+                               enumStyle_t style) const {
+            return enumFmt(s, v, style, true);
         }
 
         virtual std::string fmtConstInt(unsigned val, const std::string& name,
@@ -183,7 +183,7 @@ all copies or substantial portions of the Materials.
 
 MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
+HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
 
 THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
@@ -243,6 +243,10 @@ IN THE MATERIALS.
             for (auto& enumRow : enumSet) {
                 std::string name = enumRow.name;
                 enums[e - spv::OperandSource]["Values"][name] = enumRow.value;
+                // Add aliases
+                for (auto& alias : enumRow.aliases) {
+                    enums[e - spv::OperandSource]["Values"][alias] = enumRow.value;
+                }
             }
 
             enums[e - spv::OperandSource]["Type"] = mask ? "Bit" : "Value";
@@ -255,6 +259,10 @@ IN THE MATERIALS.
             for (auto& enumRow : spv::InstructionDesc) {
                 std::string name = enumRow.name;
                 entry["Values"][name] = enumRow.value;
+                // Add aliases
+                for (auto& alias : enumRow.aliases) {
+                    entry["Values"][alias] = enumRow.value;
+                }
             }
             entry["Type"] = "Value";
             entry["Name"] = "Op";
@@ -369,7 +377,7 @@ IN THE MATERIALS.
         printTypes(out);
         printMeta(out);
         printDefs(out);
-        printHasResultType(out);
+        printUtility(out);
         printEpilogue(out);
     }
 
@@ -464,6 +472,10 @@ IN THE MATERIALS.
             return indent(5) + '"' + prependIfDigit(s, v.second) + "\": " + fmtNum("%d", v.first) +
                 (isLast ? "\n" : ",\n");
         }
+        std::string maxEnumFmt(const std::string& s, const valpair_t& v,
+                               enumStyle_t style) const override {
+            return "";
+        }
     };
 
     // base for C and C++
@@ -501,10 +513,22 @@ IN THE MATERIALS.
         virtual std::string pre() const { return ""; } // C name prefix
         virtual std::string headerGuardSuffix() const = 0;
 
-        virtual std::string fmtEnumUse(const std::string& opPrefix, const std::string& name) const { return pre() + name; }
+        virtual std::string fmtEnumUse(const std::string &opPrefix, const std::string &opEnum, const std::string &name) const { return pre() + opPrefix + name; }
 
-        virtual void printHasResultType(std::ostream& out) const override
+        void printUtility(std::ostream& out) const override
         {
+            out << "#ifdef SPV_ENABLE_UTILITY_CODE" << std::endl;
+            out << "#ifndef __cplusplus" << std::endl;
+            out << "#include <stdbool.h>" << std::endl;
+            out << "#endif" << std::endl;
+
+            printHasResultType(out);
+            printStringFunctions(out);
+
+            out << "#endif /* SPV_ENABLE_UTILITY_CODE */" << std::endl << std::endl;
+        }
+
+        void printHasResultType(std::ostream& out) const {
             const Json::Value& enums = spvRoot["spv"]["enum"];
 
             std::set<unsigned> seenValues;
@@ -515,10 +539,7 @@ IN THE MATERIALS.
                     continue;
                 }
 
-                out << "#ifdef SPV_ENABLE_UTILITY_CODE" << std::endl;
-                out << "#ifndef __cplusplus" << std::endl;
-                out << "#include <stdbool.h>" << std::endl;
-                out << "#endif" << std::endl;
+
                 out << "inline void " << pre() << "HasResultAndType(" << pre() << opName << " opcode, bool *hasResult, bool *hasResultType) {" << std::endl;
                 out << "    *hasResult = *hasResultType = false;" << std::endl;
                 out << "    switch (opcode) {" << std::endl;
@@ -534,12 +555,50 @@ IN THE MATERIALS.
                     seenValues.insert(inst.value);
 
                     std::string name = inst.name;
-                    out << "    case " << fmtEnumUse("Op", name) << ": *hasResult = " << (inst.hasResult() ? "true" : "false") << "; *hasResultType = " << (inst.hasType() ? "true" : "false") << "; break;" << std::endl;
+                    out << "    case " << fmtEnumUse("", "Op", name) << ": *hasResult = " << (inst.hasResult() ? "true" : "false") << "; *hasResultType = " << (inst.hasType() ? "true" : "false") << "; break;" << std::endl;
                 }
 
                 out << "    }" << std::endl;
                 out << "}" << std::endl;
-                out << "#endif /* SPV_ENABLE_UTILITY_CODE */" << std::endl << std::endl;
+            }
+        }
+
+        void printStringFunctions(std::ostream& out) const {
+            const Json::Value& enums = spvRoot["spv"]["enum"];
+
+            for (auto it = enums.begin(); it != enums.end(); ++it) {
+                const auto type   = (*it)["Type"].asString();
+                // Skip bitmasks
+                if (type == "Bit") {
+                    continue;
+                }
+                const auto name   = (*it)["Name"].asString();
+                const auto sorted = getSortedVals((*it)["Values"]);
+
+                std::set<unsigned> seenValues;
+                std::string fullName = pre() + name;
+
+                out << "inline const char* " << fullName << "ToString(" << fullName << " value) {" << std::endl;
+                out << "    switch (value) {" << std::endl;
+                for (const auto& v : sorted) {
+                    // Filter out duplicate enum values, which would break the switch statement.
+                    // These are probably just extension enums promoted to core.
+                    if (seenValues.count(v.first)) {
+                        continue;
+                    }
+                    seenValues.insert(v.first);
+
+                    out << "    " << "case ";
+                    if (name == "Op") {
+                        out << fmtEnumUse("", name, v.second);
+                    }
+                    else
+                        out << fmtEnumUse(name, name, v.second);
+                    out << ": return " << "\"" << v.second << "\";" << std::endl;
+                }
+                out << "    default: return \"Unknown\";" << std::endl;
+                out << "    }" << std::endl;
+                out << "}" << std::endl << std::endl;
             }
         }
     };
@@ -564,11 +623,6 @@ IN THE MATERIALS.
             return indent() + pre() + s + v.second + styleStr(style) + " = " + fmtStyleVal(v.first, style) + ",\n";
         }
 
-        std::string maxEnumFmt(const std::string& s, const valpair_t& v,
-                               enumStyle_t style) const override {
-            return enumFmt(s, v, style, true);
-        }
-
         std::string pre() const override { return "Spv"; } // C name prefix
         std::string headerGuardSuffix() const override { return "H"; }
     };
@@ -631,11 +685,6 @@ IN THE MATERIALS.
             return indent() + s + v.second + styleStr(style) + " = " + fmtStyleVal(v.first, style) + ",\n";
         }
 
-        virtual std::string maxEnumFmt(const std::string& s, const valpair_t& v,
-                                       enumStyle_t style) const override {
-            return enumFmt(s, v, style, true);
-        }
-
         // The C++ and C++11 headers define types with the same name. So they
         // should use the same header guard.
         std::string headerGuardSuffix() const override { return "HPP"; }
@@ -660,13 +709,8 @@ IN THE MATERIALS.
             return indent() + prependIfDigit(s, v.second) + " = " + fmtStyleVal(v.first, style) + ",\n";
         }
 
-        std::string maxEnumFmt(const std::string& s, const valpair_t& v,
-                               enumStyle_t style) const override {
-            return enumFmt(s, v, style, true);
-        }
-
         // Add type prefix for scoped enum
-        virtual std::string fmtEnumUse(const std::string& opPrefix, const std::string& name) const override { return opPrefix + "::" + name; }
+        std::string fmtEnumUse(const std::string& opPrefix, const std::string& opEnum, const std::string& name) const override { return opEnum + "::" + prependIfDigit(opEnum, name); }
 
         std::string headerGuardSuffix() const override { return "HPP"; }
     };
@@ -721,7 +765,10 @@ IN THE MATERIALS.
                             enumStyle_t style, bool isLast) const override {
             return indent(2) + "'" + prependIfDigit(s, v.second) + "'" + " : " + fmtStyleVal(v.first, style) + ",\n";
         }
-
+        std::string maxEnumFmt(const std::string& s, const valpair_t& v,
+                               enumStyle_t style) const override {
+            return "";
+        }
         std::string fmtConstInt(unsigned val, const std::string& name,
                                 const char* fmt, bool isLast) const override
         {
diff --git a/tools/buildHeaders/jsonToSpirv.cpp b/tools/buildHeaders/jsonToSpirv.cpp
index 6eed13c..ddc299d 100644
--- a/tools/buildHeaders/jsonToSpirv.cpp
+++ b/tools/buildHeaders/jsonToSpirv.cpp
@@ -1,19 +1,19 @@
 // Copyright (c) 2014-2024 The Khronos Group Inc.
-// 
+//
 // Permission is hereby granted, free of charge, to any person obtaining a copy
 // of this software and/or associated documentation files (the "Materials"),
 // to deal in the Materials without restriction, including without limitation
 // the rights to use, copy, modify, merge, publish, distribute, sublicense,
 // and/or sell copies of the Materials, and to permit persons to whom the
 // Materials are furnished to do so, subject to the following conditions:
-// 
+//
 // The above copyright notice and this permission notice shall be included in
 // all copies or substantial portions of the Materials.
-// 
+//
 // MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 // STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
-// 
+// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
+//
 // THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
@@ -24,10 +24,8 @@
 
 #include <assert.h>
 #include <string.h>
-#include <algorithm>
 #include <cstdlib>
 #include <iostream>
-#include <unordered_map>
 #include <unordered_set>
 #include <utility>
 #include <fstream>
@@ -268,10 +266,16 @@ EnumValues PackedVectorFormatParams;
 EnumValues CooperativeMatrixOperandsParams;
 EnumValues CooperativeMatrixLayoutParams;
 EnumValues CooperativeMatrixUseParams;
+EnumValues CooperativeMatrixReduceParams;
+EnumValues TensorClampModeParams;
+EnumValues TensorAddressingOperandsParams;
 EnumValues InitializationModeQualifierParams;
 EnumValues HostAccessQualifierParams;
 EnumValues LoadCacheControlParams;
 EnumValues StoreCacheControlParams;
+EnumValues NamedMaximumNumberOfRegistersParams;
+EnumValues RawAccessChainOperandsParams;
+EnumValues FPEncodingParams;
 
 std::pair<bool, std::string> ReadFile(const std::string& path)
 {
@@ -422,10 +426,16 @@ ClassOptionality ToOperandClassAndOptionality(const std::string& operandKind, co
             type = OperandPackedVectorFormat;
         } else if (operandKind == "CooperativeMatrixOperands") {
             type = OperandCooperativeMatrixOperands;
+        } else if (operandKind == "TensorAddressingOperands") {
+            type = OperandTensorAddressingOperands;
         } else if (operandKind == "CooperativeMatrixLayout") {
             type = OperandCooperativeMatrixLayout;
         } else if (operandKind == "CooperativeMatrixUse") {
             type = OperandCooperativeMatrixUse;
+        } else if (operandKind == "CooperativeMatrixReduce") {
+            type = OperandCooperativeMatrixReduce;
+        } else if (operandKind == "TensorClampMode") {
+            type = OperandTensorClampMode;
         } else if (operandKind == "InitializationModeQualifier") {
             type = OperandInitializationModeQualifier;
         } else if (operandKind == "HostAccessQualifier") {
@@ -434,6 +444,12 @@ ClassOptionality ToOperandClassAndOptionality(const std::string& operandKind, co
             type = OperandLoadCacheControl;
         } else if (operandKind == "StoreCacheControl") {
             type = OperandStoreCacheControl;
+        } else if (operandKind == "NamedMaximumNumberOfRegisters") {
+            type = OperandNamedMaximumNumberOfRegisters;
+        } else if (operandKind == "RawAccessChainOperands") {
+            type = OperandRawAccessChainOperands;
+        } else if (operandKind == "FPEncoding") {
+            type = OperandFPEncoding;
         }
 
         if (type == OperandNone) {
@@ -522,6 +538,18 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
         return result;
     };
 
+    const auto getAliases = [](const Json::Value& object) {
+        Aliases result;
+        const auto& aliases = object["aliases"];
+        if (!aliases.empty()) {
+            assert(aliases.isArray());
+            for (const auto& alias : aliases) {
+                result.emplace_back(alias.asString());
+            }
+        }
+        return result;
+    };
+
     // set up the printing classes
     std::unordered_set<std::string> tags;  // short-lived local for error checking below
     const Json::Value printingClasses = root["instruction_printing_class"];
@@ -541,6 +569,8 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
     // process the instructions
     const Json::Value insts = root["instructions"];
     unsigned maxOpcode = 0;
+    std::string maxName = "";
+    bool maxCore = false;
     bool firstOpcode = true;
     for (const auto& inst : insts) {
         const auto printingClass = inst["class"].asString();
@@ -559,8 +589,11 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
         }
         const auto opcode = inst["opcode"].asUInt();
         const std::string name = inst["opname"].asString();
+        std::string version = inst["version"].asString();
         if (firstOpcode) {
           maxOpcode = opcode;
+          maxName = name;
+          maxCore = version != "None";
           firstOpcode = false;
         } else {
           if (maxOpcode > opcode) {
@@ -568,12 +601,18 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
                       << " is out of order. It follows the instruction with opcode " << maxOpcode
                       << std::endl;
             std::exit(1);
+          } else if (maxOpcode == opcode) {
+            std::cerr << "Error: " << name << " is an alias of " << maxName
+            << ". Use \"aliases\" instead." << std::endl;
+            std::exit(1);
           } else {
             maxOpcode = opcode;
+            maxName = name;
+            maxCore = version != "None";
           }
         }
+        Aliases aliases = getAliases(inst);
         EnumCaps caps = getCaps(inst);
-        std::string version = inst["version"].asString();
         std::string lastVersion = inst["lastVersion"].asString();
         Extensions exts = getExts(inst);
         OperandParameters operands;
@@ -589,7 +628,7 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
             }
         }
         InstructionDesc.emplace_back(
-            std::move(EnumValue(opcode, name,
+            std::move(EnumValue(opcode, name, std::move(aliases),
                                 std::move(caps), std::move(version), std::move(lastVersion), std::move(exts),
                                 std::move(operands))),
              printingClass, defTypeId, defResultId);
@@ -601,7 +640,7 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
     // Specific additional context-dependent operands
 
     // Populate dest with EnumValue objects constructed from source.
-    const auto populateEnumValues = [&getCaps,&getExts,&errorCount](EnumValues* dest, const Json::Value& source, bool bitEnum) {
+    const auto populateEnumValues = [&getCaps,&getAliases,&getExts,&errorCount](EnumValues* dest, const Json::Value& source, bool bitEnum) {
         // A lambda for determining the numeric value to be used for a given
         // enumerant in JSON form, and whether that value is a 0 in a bitfield.
         auto getValue = [&bitEnum](const Json::Value& enumerant) {
@@ -619,28 +658,40 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
         };
 
         unsigned maxValue = 0;
+        std::string maxName = "";
+        bool maxCore = false;
         bool firstValue = true;
         for (const auto& enumerant : source["enumerants"]) {
             unsigned value;
             bool skip_zero_in_bitfield;
             std::tie(value, skip_zero_in_bitfield) = getValue(enumerant);
+            std::string name = enumerant["enumerant"].asString();
+            std::string version = enumerant["version"].asString();
             if (skip_zero_in_bitfield)
                 continue;
             if (firstValue) {
               maxValue = value;
+              maxName = name;
+              maxCore = version != "None";
               firstValue = false;
             } else {
               if (maxValue > value) {
-                std::cerr << "Error: " << source["kind"] << " enumerant " << enumerant["enumerant"]
+                std::cerr << "Error: " << source["kind"] << " enumerant " << name
                           << " is out of order. It has value " <<  value
                           << " but follows the enumerant with value " << maxValue << std::endl;
                 std::exit(1);
+              } else if (maxValue == value ) {
+                std::cerr << "Error: " << source["kind"] << " enumerant " << name
+                          << " is an alias of " << maxName << ". Use \"aliases\" instead." << std::endl;
+                std::exit(1);
               } else {
                 maxValue = value;
+                maxName = name;
+                maxCore = version != "None";
               }
             }
+            Aliases aliases = getAliases(enumerant);
             EnumCaps caps(getCaps(enumerant));
-            std::string version = enumerant["version"].asString();
             std::string lastVersion = enumerant["lastVersion"].asString();
             Extensions exts(getExts(enumerant));
             OperandParameters params;
@@ -655,7 +706,7 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
                 }
             }
             dest->emplace_back(
-                value, enumerant["enumerant"].asString(),
+                value, enumerant["enumerant"].asString(), std::move(aliases),
                 std::move(caps), std::move(version), std::move(lastVersion), std::move(exts), std::move(params));
         }
     };
@@ -765,10 +816,16 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
             establishOperandClass(enumName, OperandPackedVectorFormat, &PackedVectorFormatParams, operandEnum, category);
         } else if (enumName == "CooperativeMatrixOperands") {
             establishOperandClass(enumName, OperandCooperativeMatrixOperands, &CooperativeMatrixOperandsParams, operandEnum, category);
+        } else if (enumName == "TensorAddressingOperands") {
+            establishOperandClass(enumName, OperandTensorAddressingOperands, &TensorAddressingOperandsParams, operandEnum, category);
         } else if (enumName == "CooperativeMatrixLayout") {
             establishOperandClass(enumName, OperandCooperativeMatrixLayout, &CooperativeMatrixLayoutParams, operandEnum, category);
         } else if (enumName == "CooperativeMatrixUse") {
             establishOperandClass(enumName, OperandCooperativeMatrixUse, &CooperativeMatrixUseParams, operandEnum, category);
+        } else if (enumName == "CooperativeMatrixReduce") {
+            establishOperandClass(enumName, OperandCooperativeMatrixReduce, &CooperativeMatrixReduceParams, operandEnum, category);
+        } else if (enumName == "TensorClampMode") {
+            establishOperandClass(enumName, OperandTensorClampMode, &TensorClampModeParams, operandEnum, category);
         } else if (enumName == "InitializationModeQualifier") {
             establishOperandClass(enumName, OperandInitializationModeQualifier, &InitializationModeQualifierParams, operandEnum, category);
         } else if (enumName == "HostAccessQualifier") {
@@ -777,6 +834,12 @@ void jsonToSpirv(const std::string& jsonPath, bool buildingHeaders)
             establishOperandClass(enumName, OperandLoadCacheControl, &LoadCacheControlParams, operandEnum, category);
         } else if (enumName == "StoreCacheControl") {
             establishOperandClass(enumName, OperandStoreCacheControl, &StoreCacheControlParams, operandEnum, category);
+        } else if (enumName == "NamedMaximumNumberOfRegisters") {
+            establishOperandClass(enumName, OperandNamedMaximumNumberOfRegisters, &NamedMaximumNumberOfRegistersParams, operandEnum, category);
+        } else if (enumName == "RawAccessChainOperands") {
+            establishOperandClass(enumName, OperandRawAccessChainOperands, &RawAccessChainOperandsParams, operandEnum, category);
+        } else if (enumName == "FPEncoding") {
+            establishOperandClass(enumName, OperandFPEncoding, &FPEncodingParams, operandEnum, category);
         }
     }
 
diff --git a/tools/buildHeaders/jsonToSpirv.h b/tools/buildHeaders/jsonToSpirv.h
index 4afbeb7..9ad3413 100644
--- a/tools/buildHeaders/jsonToSpirv.h
+++ b/tools/buildHeaders/jsonToSpirv.h
@@ -1,19 +1,19 @@
 // Copyright (c) 2014-2024 The Khronos Group Inc.
-// 
+//
 // Permission is hereby granted, free of charge, to any person obtaining a copy
 // of this software and/or associated documentation files (the "Materials"),
 // to deal in the Materials without restriction, including without limitation
 // the rights to use, copy, modify, merge, publish, distribute, sublicense,
 // and/or sell copies of the Materials, and to permit persons to whom the
 // Materials are furnished to do so, subject to the following conditions:
-// 
+//
 // The above copyright notice and this permission notice shall be included in
 // all copies or substantial portions of the Materials.
-// 
+//
 // MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS KHRONOS
 // STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS SPECIFICATIONS AND
-// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/ 
-// 
+// HEADER INFORMATION ARE LOCATED AT https://www.khronos.org/registry/
+//
 // THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
@@ -99,10 +99,16 @@ enum OperandClass {
     OperandCooperativeMatrixOperands,
     OperandCooperativeMatrixLayout,
     OperandCooperativeMatrixUse,
+    OperandCooperativeMatrixReduce,
+    OperandTensorClampMode,
+    OperandTensorAddressingOperands,
     OperandInitializationModeQualifier,
     OperandHostAccessQualifier,
     OperandLoadCacheControl,
     OperandStoreCacheControl,
+    OperandNamedMaximumNumberOfRegisters,
+    OperandRawAccessChainOperands,
+    OperandFPEncoding,
 
     OperandOpcode,
 
@@ -122,6 +128,9 @@ typedef std::vector<std::string> EnumCaps;
 // A set of extensions.
 typedef std::vector<std::string> Extensions;
 
+// A set of aliases.
+typedef std::vector<std::string> Aliases;
+
 // Parameterize a set of operands with their OperandClass(es) and descriptions.
 class OperandParameters {
 public:
@@ -202,18 +211,21 @@ private:
 class EnumValue {
 public:
     EnumValue() : value(0), desc(nullptr) {}
-    EnumValue(unsigned int the_value, const std::string& the_name, EnumCaps&& the_caps,
+    EnumValue(unsigned int the_value, const std::string& the_name, Aliases&& the_aliases, EnumCaps&& the_caps,
         const std::string& the_firstVersion, const std::string& the_lastVersion,
         Extensions&& the_extensions, OperandParameters&& the_operands) :
-      value(the_value), name(the_name), capabilities(std::move(the_caps)),
+      value(the_value), name(the_name), aliases(std::move(the_aliases)), capabilities(std::move(the_caps)),
       firstVersion(std::move(the_firstVersion)), lastVersion(std::move(the_lastVersion)),
       extensions(std::move(the_extensions)), operands(std::move(the_operands)), desc(nullptr) { }
 
+    bool hasAliases() const { return !aliases.empty(); }
+
     // For ValueEnum, the value from the JSON file.
     // For BitEnum, the index of the bit position represented by this mask.
     // (That is, what you shift 1 by to get the mask.)
     unsigned value;
     std::string name;
+    Aliases aliases;
     EnumCaps capabilities;
     std::string firstVersion;
     std::string lastVersion;
@@ -273,21 +285,16 @@ public:
     InstructionValue(EnumValue&& e, const std::string& printClass, bool has_type, bool has_result)
      : EnumValue(std::move(e)),
        printingClass(printClass),
-       opDesc("TBD"),
+       opDesc("TBD."),
        typePresent(has_type),
-       resultPresent(has_result),
-       alias(this) { }
+       resultPresent(has_result) { }
     InstructionValue(const InstructionValue& v)
     {
         *this = v;
-        alias = this;
     }
 
     bool hasResult() const { return resultPresent != 0; }
     bool hasType()   const { return typePresent != 0; }
-    void setAlias(const InstructionValue& a) { alias = &a; }
-    const InstructionValue& getAlias() const { return *alias; }
-    bool isAlias() const { return alias != this; }
 
     std::string printingClass;
     const char* opDesc;
@@ -295,7 +302,6 @@ public:
 protected:
     int typePresent   : 1;
     int resultPresent : 1;
-    const InstructionValue* alias;    // correct only after discovering the aliases; otherwise points to this
 };
 
 using InstructionValues = EnumValuesContainer<InstructionValue>;
diff --git a/tools/buildHeaders/jsoncpp/dist/json/json-forwards.h b/tools/buildHeaders/jsoncpp/dist/json/json-forwards.h
index ccbdb2b..901bc06 100644
--- a/tools/buildHeaders/jsoncpp/dist/json/json-forwards.h
+++ b/tools/buildHeaders/jsoncpp/dist/json/json-forwards.h
@@ -7,28 +7,28 @@
 // //////////////////////////////////////////////////////////////////////
 
 /*
-The JsonCpp library's source code, including accompanying documentation, 
+The JsonCpp library's source code, including accompanying documentation,
 tests and demonstration applications, are licensed under the following
 conditions...
 
-The author (Baptiste Lepilleur) explicitly disclaims copyright in all 
-jurisdictions which recognize such a disclaimer. In such jurisdictions, 
+The author (Baptiste Lepilleur) explicitly disclaims copyright in all
+jurisdictions which recognize such a disclaimer. In such jurisdictions,
 this software is released into the Public Domain.
 
 In jurisdictions which do not recognize Public Domain property (e.g. Germany as of
 2010), this software is Copyright (c) 2007-2010 by Baptiste Lepilleur, and is
 released under the terms of the MIT License (see below).
 
-In jurisdictions which recognize Public Domain property, the user of this 
-software may choose to accept it either as 1) Public Domain, 2) under the 
-conditions of the MIT License (see below), or 3) under the terms of dual 
+In jurisdictions which recognize Public Domain property, the user of this
+software may choose to accept it either as 1) Public Domain, 2) under the
+conditions of the MIT License (see below), or 3) under the terms of dual
 Public Domain/MIT License conditions described here, as they choose.
 
 The MIT License is about as close to Public Domain as a license can get, and is
 described in clear, concise terms at:
 
    http://en.wikipedia.org/wiki/MIT_License
-   
+
 The full text of the MIT License follows:
 
 ========================================================================
diff --git a/tools/buildHeaders/jsoncpp/dist/json/json.h b/tools/buildHeaders/jsoncpp/dist/json/json.h
index e01991e..7145b1a 100644
--- a/tools/buildHeaders/jsoncpp/dist/json/json.h
+++ b/tools/buildHeaders/jsoncpp/dist/json/json.h
@@ -6,28 +6,28 @@
 // //////////////////////////////////////////////////////////////////////
 
 /*
-The JsonCpp library's source code, including accompanying documentation, 
+The JsonCpp library's source code, including accompanying documentation,
 tests and demonstration applications, are licensed under the following
 conditions...
 
-The author (Baptiste Lepilleur) explicitly disclaims copyright in all 
-jurisdictions which recognize such a disclaimer. In such jurisdictions, 
+The author (Baptiste Lepilleur) explicitly disclaims copyright in all
+jurisdictions which recognize such a disclaimer. In such jurisdictions,
 this software is released into the Public Domain.
 
 In jurisdictions which do not recognize Public Domain property (e.g. Germany as of
 2010), this software is Copyright (c) 2007-2010 by Baptiste Lepilleur, and is
 released under the terms of the MIT License (see below).
 
-In jurisdictions which recognize Public Domain property, the user of this 
-software may choose to accept it either as 1) Public Domain, 2) under the 
-conditions of the MIT License (see below), or 3) under the terms of dual 
+In jurisdictions which recognize Public Domain property, the user of this
+software may choose to accept it either as 1) Public Domain, 2) under the
+conditions of the MIT License (see below), or 3) under the terms of dual
 Public Domain/MIT License conditions described here, as they choose.
 
 The MIT License is about as close to Public Domain as a license can get, and is
 described in clear, concise terms at:
 
    http://en.wikipedia.org/wiki/MIT_License
-   
+
 The full text of the MIT License follows:
 
 ========================================================================
@@ -398,14 +398,14 @@ class JSON_API Exception;
 /** Exceptions which the user cannot easily avoid.
  *
  * E.g. out-of-memory (when we use malloc), stack-overflow, malicious input
- * 
+ *
  * \remark derived from Json::Exception
  */
 class JSON_API RuntimeError;
 /** Exceptions thrown by JSON_ASSERT/JSON_FAIL macros.
  *
  * These are precondition-violations (user bugs) and internal errors (our bugs).
- * 
+ *
  * \remark derived from Json::Exception
  */
 class JSON_API LogicError;
diff --git a/tools/buildHeaders/jsoncpp/dist/jsoncpp.cpp b/tools/buildHeaders/jsoncpp/dist/jsoncpp.cpp
index 1304914..49569f9 100644
--- a/tools/buildHeaders/jsoncpp/dist/jsoncpp.cpp
+++ b/tools/buildHeaders/jsoncpp/dist/jsoncpp.cpp
@@ -6,28 +6,28 @@
 // //////////////////////////////////////////////////////////////////////
 
 /*
-The JsonCpp library's source code, including accompanying documentation, 
+The JsonCpp library's source code, including accompanying documentation,
 tests and demonstration applications, are licensed under the following
 conditions...
 
-The author (Baptiste Lepilleur) explicitly disclaims copyright in all 
-jurisdictions which recognize such a disclaimer. In such jurisdictions, 
+The author (Baptiste Lepilleur) explicitly disclaims copyright in all
+jurisdictions which recognize such a disclaimer. In such jurisdictions,
 this software is released into the Public Domain.
 
 In jurisdictions which do not recognize Public Domain property (e.g. Germany as of
 2010), this software is Copyright (c) 2007-2010 by Baptiste Lepilleur, and is
 released under the terms of the MIT License (see below).
 
-In jurisdictions which recognize Public Domain property, the user of this 
-software may choose to accept it either as 1) Public Domain, 2) under the 
-conditions of the MIT License (see below), or 3) under the terms of dual 
+In jurisdictions which recognize Public Domain property, the user of this
+software may choose to accept it either as 1) Public Domain, 2) under the
+conditions of the MIT License (see below), or 3) under the terms of dual
 Public Domain/MIT License conditions described here, as they choose.
 
 The MIT License is about as close to Public Domain as a license can get, and is
 described in clear, concise terms at:
 
    http://en.wikipedia.org/wiki/MIT_License
-   
+
 The full text of the MIT License follows:
 
 ========================================================================
@@ -3971,7 +3971,7 @@ Value& Path::make(Value& root) const {
 #define snprintf std::snprintf
 #endif
 
-#if defined(__BORLANDC__)  
+#if defined(__BORLANDC__)
 #include <float.h>
 #define isfinite _finite
 #define snprintf _snprintf
```

