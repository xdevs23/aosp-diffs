```diff
diff --git a/.gitignore b/.gitignore
index bf25160..e08b24e 100644
--- a/.gitignore
+++ b/.gitignore
@@ -5,6 +5,7 @@ third_party/clspv-clang
 third_party/clspv-llvm
 third_party/cpplint
 third_party/dxc
+third_party/DirectX-Headers
 third_party/glslang
 third_party/googletest
 third_party/json
@@ -16,6 +17,7 @@ third_party/swiftshader
 third_party/vulkan-headers
 third_party/vulkan-loader
 third_party/vulkan-validationlayers/
+third_party/vulkan-utility-libraries/
 third_party/robin-hood-hashing
 .vs
 
@@ -27,3 +29,9 @@ third_party/robin-hood-hashing
 # C-Lion
 .idea/
 cmake-build-*/
+
+### Clangd cached index files
+/.cache
+
+### The 'compile_commands' file can be generated at root
+compile_commands.json
diff --git a/AUTHORS b/AUTHORS
index 8097dd7..a1724f8 100644
--- a/AUTHORS
+++ b/AUTHORS
@@ -5,3 +5,4 @@
 # of contributors, see the revision history in source control.
 
 Google LLC
+Advanced Micro Devices, Inc.
diff --git a/Android.bp b/Android.bp
index 8bf7e02..04d58c2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,6 +42,7 @@ cc_library_static {
         "deqp_vulkan_headers",
     ],
     srcs: [
+	"src/acceleration_structure.cc",
         "src/amber.cc",
         "src/amberscript/parser.cc",
         "src/buffer.cc",
@@ -73,6 +74,7 @@ cc_library_static {
         "src/vkscript/parser.cc",
         "src/vkscript/section_parser.cc",
         "src/vulkan_engine_config.cc",
+        "src/vulkan/blas.cc",
         "src/vulkan/buffer_backed_descriptor.cc",
         "src/vulkan/buffer_descriptor.cc",
         "src/vulkan/command_buffer.cc",
@@ -87,9 +89,13 @@ cc_library_static {
         "src/vulkan/index_buffer.cc",
         "src/vulkan/pipeline.cc",
         "src/vulkan/push_constant.cc",
+        "src/vulkan/raytracing_pipeline.cc",
         "src/vulkan/resource.cc",
         "src/vulkan/sampler_descriptor.cc",
         "src/vulkan/sampler.cc",
+        "src/vulkan/sbt.cc",
+        "src/vulkan/tlas.cc",
+        "src/vulkan/tlas_descriptor.cc",
         "src/vulkan/transfer_buffer.cc",
         "src/vulkan/transfer_image.cc",
         "src/vulkan/vertex_buffer.cc",
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 66fb14b..10a90e1 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -12,7 +12,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-cmake_minimum_required(VERSION 3.0)
+cmake_minimum_required(VERSION 3.13)
 if (POLICY CMP0048)
   cmake_policy(SET CMP0048 NEW)
 endif()
@@ -26,6 +26,7 @@ endif()
 project(amber)
 enable_testing()
 
+set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
 set(CMAKE_POSITION_INDEPENDENT_CODE ON)
 
@@ -56,11 +57,7 @@ if (${AMBER_ENABLE_VK_DEBUGGING})
   message(FATAL_ERROR "Amber no longer supports Vulkan debugging")
 endif()
 
-if (${AMBER_USE_CLSPV} OR ${AMBER_ENABLE_SWIFTSHADER})
-  set(CMAKE_CXX_STANDARD 17)
-else()
-  set(CMAKE_CXX_STANDARD 11)
-endif()
+set(CMAKE_CXX_STANDARD 17)
 
 if(WIN32)
   # On Windows, CMake by default compiles with the shared CRT.
@@ -124,7 +121,7 @@ if (${AMBER_USE_CLSPV} OR ${AMBER_ENABLE_SWIFTSHADER})
 endif()
 
 message(STATUS "Using python3")
-find_package(PythonInterp 3 REQUIRED)
+find_package(Python3 REQUIRED)
 
 message(STATUS "Amber enable SPIRV-Tools: ${AMBER_ENABLE_SPIRV_TOOLS}")
 message(STATUS "Amber enable Shaderc: ${AMBER_ENABLE_SHADERC}")
@@ -213,6 +210,7 @@ function(amber_default_compile_options TARGET)
       -Wno-padded
       -Wno-switch-enum
       -Wno-unknown-pragmas
+      -Wno-unsafe-buffer-usage
       -pedantic-errors
     )
     if (NOT ${AMBER_DISABLE_WERROR})
diff --git a/DEPS b/DEPS
index a06a335..c5a16b7 100644
--- a/DEPS
+++ b/DEPS
@@ -14,19 +14,20 @@ vars = {
   'clspv_llvm_revision': 'b70366c9c430e1eadd59d5a1dfbb9c4d84f83de5',
   'clspv_revision': 'f99809bdab1710846633b4ec24f5448263e75da7',
   'cpplint_revision': 'fa12a0bbdafa15291276ddd2a2dcd2ac7a2ce4cb',
-  'dxc_revision': 'c45db48d565a9edc14b025e43b90e62264d06eea',
-  'glslang_revision': '81cc10a498b25a90147cccd6e8939493c1e9e20e',
+  'dxc_revision': '773b01272719e07ea369bc17f5ddfce248751c7a',
+  'directx_headers_revision': '980971e835876dc0cde415e8f9bc646e64667bf7',
+  'glslang_revision': 'e8dd0b6903b34f1879520b444634c75ea2deedf5',
   'googletest_revision': '16f637fbf4ffc3f7a01fa4eceb7906634565242f',
   'json_revision': '4f8fba14066156b73f1189a2b8bd568bde5284c5',
   'lodepng_revision': '5601b8272a6850b7c5d693dd0c0e16da50be8d8d',
-  'shaderc_revision': 'e72186b66bb90ed06aaf15cbdc9a053581a0616b',
-  'spirv_headers_revision': 'd13b52222c39a7e9a401b44646f0ca3a640fbd47',
-  'spirv_tools_revision': 'd87f61605b3647fbceae9aaa922fce0031afdc63',
-  'swiftshader_revision': 'bca23447ad4667a7b79973569ab5d8d905d211ac',
-  'vulkan_headers_revision': '1dace16d8044758d32736eb59802d171970e9448',
-  'vulkan_loader_revision': '8aad559a09388ceb5b968af64a2b965d3886e5a0',
-  'vulkan_validationlayers_revision': 'a6c1ddca49331d8addde052554487180ee8aec13',
-  'robin_hood_hashing_revision': '24b3f50f9532153edc23b29ae277dcccfd75a462',
+  'shaderc_revision': 'f59f0d11b80fd622383199c867137ededf89d43b',
+  'spirv_headers_revision': '36d5e2ddaa54c70d2f29081510c66f4fc98e5e53',
+  'spirv_tools_revision': '3fb52548bc8a68d349d31e21bd4e80e3d953e87c',
+  'swiftshader_revision': 'da334852e70510d259bfa8cbaa7c5412966b2f41',
+  'vulkan_headers_revision': '49af1bfe467dd5a9efc22f7867d95fdde50e2b00',
+  'vulkan_loader_revision': 'ce2d68b24b66a91ed798d870ca205f899ee6e79d',
+  'vulkan_utility_libraries_revision': 'b538fb5b08513aa78346cd414ad5e576a2a3e920',
+  'vulkan_validationlayers_revision': '902f3cf8d51e76be0c0deb4be39c6223abebbae2',
 }
 
 deps = {
@@ -42,6 +43,9 @@ deps = {
   'third_party/dxc': Var('microsoft_git') + '/DirectXShaderCompiler.git@' +
       Var('dxc_revision'),
 
+  'third_party/DirectX-Headers': Var('microsoft_git') + '/DirectX-Headers.git@' +
+      Var('directx_headers_revision'),
+
   'third_party/googletest': Var('google_git') + '/googletest.git@' +
       Var('googletest_revision'),
 
@@ -75,6 +79,6 @@ deps = {
   'third_party/vulkan-loader': Var('khronos_git') + '/Vulkan-Loader.git@' +
       Var('vulkan_loader_revision'),
 
-  'third_party/robin-hood-hashing': Var('martinus_git') + '/robin-hood-hashing.git@' +
-      Var('robin_hood_hashing_revision'),
+  'third_party/vulkan-utility-libraries': Var('khronos_git') + '/Vulkan-Utility-Libraries.git@' +
+      Var('vulkan_utility_libraries_revision'),
 }
diff --git a/README.md b/README.md
index 6d7080a..8fab3d4 100644
--- a/README.md
+++ b/README.md
@@ -93,7 +93,7 @@ relative probe rect rgba (0.0, 0.0, 1.0, 1.0) (0, 0, 0, 0)
  * Git
  * CMake (version 3.7+ enables automatic discovery of an installed Vulkan SDK)
  * Ninja (or other build tool)
- * Python, for fetching dependencies and building Vulkan wrappers
+ * Python3, for fetching dependencies and building Vulkan wrappers
 
 
 ## Building
@@ -171,7 +171,85 @@ cd /data/local/tmp
 ./amber_ndk -d <shader-test-files>
 ```
 
-### Optional Components
+### ChromeOS plain executable (not officially supported)
+
+It is possible to obtain produce a cross compiled amber binary for ChromeOS.
+Start with the standard amber checkout
+```
+git clone https://github.com/google/amber.git
+cd amber
+./tools/git-sync-deps
+./tools/update_build_version.py . samples/ third_party/
+./tools/update_vk_wrappers.py . .
+```
+
+Then add the cmake cross compiling variable to the root amber /CMakeLists.txt
+
+The example ChromeOS platform used here is trogdor.
+
+```
+# Top of CMakeLists.txt file 
+cmake_minimum_required(VERSION 3.13)
+
+set(CMAKE_SYSTEM_NAME Linux)
+# The example processor here is 64 bit arm
+set(CMAKE_SYSTEM_PROCESSOR aarch64)
+
+set(CMAKE_SYSROOT "$ENV{HOME}/chromium/src/build/cros_cache/chrome-sdk/symlinks/trogdor+16074.0.0-1064250+sysroot_chromeos-base_chromeos-chrome.tar.xz/")
+
+set(tools "$ENV{HOME}/chromium/src/build/cros_cache/chrome-sdk/symlinks/trogdor+16074.0.0-1064250+target_toolchain")
+set(CMAKE_C_COMPILER ${tools}/bin/aarch64-cros-linux-gnu-gcc)
+set(CMAKE_CXX_COMPILER ${tools}/bin/aarch64-cros-linux-gnu-g++)
+
+set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
+set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
+# To avoid having the host try to execute a cross compiled binary 'asm_offset'
+set(USE_GAS OFF)
+
+```
+We statically link c++ to avoid missing libstdc++.so.X 
+
+Replace these lines
+```
+  if (NOT ${AMBER_ENABLE_SHARED_CRT})
+    # For MinGW cross compile, statically link to the C++ runtime.
+    # But it still depends on MSVCRT.dll.
+    if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
+      if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
+	set_target_properties(${TARGET} PROPERTIES LINK_FLAGS
+	  -static
+	  -static-libgcc
+	  -static-libstdc++)
+      endif()
+    endif()
+  endif()
+
+```
+With this line.
+```
+	set_target_properties(${TARGET} PROPERTIES LINK_FLAGS -static-libstdc++)
+```
+
+Finally we can build and deploy the amber binary.
+
+```
+mkdir -p out/Debug
+cd out/Debug
+cmake -GNinja ../..  -DAMBER_USE_LOCAL_VULKAN=1  
+ninja amber
+# Copy over the amber binary to the DUT (note the root disk partion has limited space)
+scp amber device:/root/amber
+# An example of how to copy over some amber scripts
+scp ../../tests/cases/* device:/root/
+
+```
+Now by ssh-ing into the DUT you can locally run any amber script. Also, vulkan layers
+may not be available to this executable, so make sure to use the `-d` flag to disable
+Vulkan layers.
+
+### Optional components
 
 The components which build up Amber can be enabled or disabled as needed. Any
 option with `_SKIP_` in the name is on by default, any with `_USE_` is off by
diff --git a/android_sample/jni/main.cc b/android_sample/jni/main.cc
index 77d3157..38d90d4 100644
--- a/android_sample/jni/main.cc
+++ b/android_sample/jni/main.cc
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 #include <android/log.h>
+#include <android/looper.h>
 #include <android_native_app_glue.h>
 
 #include "amber/amber.h"
@@ -93,13 +94,17 @@ void android_main(struct android_app* app) {
   app->onAppCmd = handle_cmd;
 
   // Used to poll the events in the main loop
-  int events;
   android_poll_source* source;
 
   // Main loop
   while (app->destroyRequested == 0) {
-    if (ALooper_pollAll(1, nullptr, &events, (void**)&source) >= 0) {
-      if (source != NULL)
+    auto result = ALooper_pollOnce(1, nullptr, nullptr, (void**)&source);
+    if (result == ALOOPER_POLL_ERROR) {
+      LOGE("ALooper_pollOnce returned an error.");
+      exit(1);
+    }
+
+    if (result >= 0 && source != nullptr) {
         source->process(app, source);
     }
   }
diff --git a/docs/amber_script.md b/docs/amber_script.md
index 9bd58d7..ccf20de 100644
--- a/docs/amber_script.md
+++ b/docs/amber_script.md
@@ -62,7 +62,9 @@ with:
  * `SubgroupSupportedStages.geometry`
  * `SubgroupSupportedStages.fragment`
  * `SubgroupSupportedStages.compute`
-
+ * `RayTracingPipelineFeaturesKHR.rayTracingPipeline`
+ * `AccelerationStructureFeaturesKHR.accelerationStructure`
+ * `BufferDeviceAddressFeatures.bufferDeviceAddress`
 
 Extensions can be enabled with the `DEVICE_EXTENSION` and `INSTANCE_EXTENSION`
 commands.
@@ -109,7 +111,7 @@ file system, before falling back to the standard file system.
 
 Shader programs are declared using the `SHADER` command. \
 Shaders can be declared as `PASSTHROUGH`, with inlined source or using source
-from a `VIRTUAL_FILE`.
+from a `VIRTUAL_FILE` or from a `FILE` in the file system.
 
 Pass-through shader:
 
@@ -130,12 +132,12 @@ SHADER {shader_type} {shader_name} {shader_format} [ TARGET_ENV {target_env} ]
 END
 ```
 
-Shader using source from `VIRTUAL_FILE`:
+Shader using source from `VIRTUAL_FILE` or `FILE`:
 
 ```groovy
 # Creates a shader of |shader_type| with the given |shader_name|. The shader
 # will be of |shader_format|. The shader will use the virtual file with |path|.
-SHADER {shader_type} {shader_name} {shader_format} [ TARGET_ENV {target_env} ] VIRTUAL_FILE {path}
+SHADER {shader_type} {shader_name} {shader_format} [ TARGET_ENV {target_env} ] ( VIRTUAL_FILE | FILE ) {path}
 ```
 
 `{shader_name}` is used to identify the shader to attach to `PIPELINE`s,
@@ -149,18 +151,26 @@ SHADER {shader_type} {shader_name} {shader_format} [ TARGET_ENV {target_env} ] V
  * `tessellation_evaluation`
  * `tessellation_control`
  * `compute`
+ * `ray_generation`
+ * `any_hit`
+ * `closest_hit`
+ * `miss`
+ * `intersection`
+ * `callable`
  * `multi`
 
 The compute pipeline can only contain compute shaders. The graphics pipeline
 can not contain compute shaders, and must contain a vertex shader and a fragment
-shader.
+shader. Ray tracing pipeline can contain only shaders of ray tracing types:
+ray generation, any hit, closest hit, miss, intersection, and callable shaders.
 
-The provided `multi` shader can only be used with `SPIRV-ASM` and `SPIRV-HEX`
-and allows for providing multiple shaders in a single module (so the `vertex`
-and `fragment` shaders can be provided together.)
+The provided `multi` shader can only be used with `SPIRV-ASM`, `SPIRV-HEX`, and
+`SPIRV-BIN` and allows for providing multiple shaders in a single module (so the
+`vertex` and `fragment` shaders can be provided together.)
 
-Note, `SPIRV-ASM` and `SPIRV-HEX` can also be used with each of the other shader
-types, but in that case must only provide a single shader type in the module.
+Note, `SPIRV-ASM`, `SPIRV-HEX`, and `SPIRV-BIN` can also be used with each of
+the other shader types, but in that case must only provide a single shader type
+in the module.
 
 #### Shader Format
  * `GLSL`  (with glslang)
@@ -168,6 +178,7 @@ types, but in that case must only provide a single shader type in the module.
  * `SPIRV-ASM` (with spirv-as; specifying `TARGET_ENV` is _highly recommended_
     in this case, as explained below)
  * `SPIRV-HEX` (decoded straight to SPIR-V)
+ * `SPIRV-BIN` (read as binary SPIR-V, only with `FILE`)
  * `OPENCL-C` (with clspv)
 
 ### Target environment
@@ -181,8 +192,8 @@ SPIR-V environment. For example:
  * `vulkan1.2`
 
 Check the help text of the corresponding tool (e.g. spirv-as, glslangValidator)
-for the full list. The `SPIRV-HEX` shader format is not affected by the target
-environment.
+for the full list. The `SPIRV-HEX` and `SPIRV-BIN` shader formats are not
+affected by the target environment.
 
 The specified target environment for the shader overrides the default (`spv1.0`)
 or the one specified on the command line.
@@ -389,15 +400,113 @@ Note: currently the border color is always transparent black.
 Note: the addressing mode is used for all coordinates currently. Arrayed images
 should use `clamp_to_edge` for the array index.
 
+### Acceleration Structures
+
+Acceleration structures are used to enumerate geometries to describe a scene.
+There are two kinds of acceleration structures:
+ * Bottom level
+ * Top level
+
+#### Bottom Level
+
+Bottom level acceleration structures consists of a set of geometries.
+Each bottom level acceleration structure can consists either of triangle or
+axis aligned bounding box (AABB) geometries. It is prohibited to mix triangle
+geometries and AABBs inside same bottom level acceleration structures.
+
+A bottom level acceleration structure consisting of triangle geometries is defined as:
+
+```groovy
+  # Bottom level acceleration structure consisting of triangles
+  ACCELERATION_STRUCTURE BOTTOM_LEVEL {name_of_bottom_level_acceleration_structure}
+    {GEOMETRY TRIANGLES
+      [FLAGS <geometry_flags>]
+      {x0 y0 z0
+       x1 y1 z1
+       x2 y2 z2}+
+    END}+
+  END
+```
+
+A bottom level acceleration structure consisting of axis aligned bounding boxes is defined as:
+
+```groovy
+  # Bottom level acceleration structure consisting of AABBs
+  ACCELERATION_STRUCTURE BOTTOM_LEVEL {name_of_bottom_level_acceleration_structure}
+    {GEOMETRY AABBS
+      [FLAGS <geometry_flags>]
+      {x0 y0 z0 x1 y1 z1}+
+    END}+
+  END
+```
+
+Each coordinate |x{n}|, |y{n}|, and |z{n}| should be floating point values.
+
+FLAGS is a space separated list of following geometry flags:
+ * OPAQUE
+ * NO_DUPLICATE_ANY_HIT
+
+#### Top Level
+
+Top level acceleration structures consists of a set of instances of bottom
+level acceleration structures.
+
+```groovy
+  # Acceleration structure with instance defined in one line
+  ACCELERATION_STRUCTURE TOP_LEVEL {name_of_top_level_acceleration_structure}
+    {BLAS_INSTANCE USE {name_of_bottom_level_acceleration_structure}}+
+  END
+
+  # Acceleration structure with instance defined in multiple lines
+  ACCELERATION_STRUCTURE TOP_LEVEL {name_of_top_level_acceleration_structure}
+    {BOTTOM_LEVEL_INSTANCE {name_of_bottom_level_acceleration_structure}
+      [INDEX {index}]
+      [OFFSET {offset}]
+      [FLAGS {flags}]
+      [MASK {mask}]
+      [TRANSFORM \
+        {transform} \
+      END]
+    END}+
+  END
+```
+
+The value of |index| should be an integer in range of [0..16,777,215] is a 24-bit user-specified
+index value accessible to ray shaders in the InstanceCustomIndexKHR built-in.
+
+The value of |offset| should be an integer in range of [0..16,777,215] is a 24-bit offset used
+in calculating the hit shader binding table index.
+
+The value of |mask| should be an integer in range of [0..255] (may be specified as 0xNN) is an
+8-bit visibility mask for the geometry.
+
+The value of |flags| is space-separated or EOL-separated list of following:
+ * `TRIANGLE_FACING_CULL_DISABLE`
+ * `TRIANGLE_FLIP_FACING`
+ * `FORCE_OPAQUE`
+ * `FORCE_NO_OPAQUE`
+ * `FORCE_OPACITY_MICROMAP_2_STATE`
+ * `DISABLE_OPACITY_MICROMAPS`
+ * <any integer number>
+
+If |flags| is a EOL-separated list it should be ended with END statement.
+If |flags| is a space-separated list it should not be ended with END statement.
+
+The |transform| is 12 space-separated values describing a 3x4 row-major affine transformation matrix applied to
+the acceleration structure.
+
+
 ### Pipelines
 
 #### Pipeline type
  * `compute`
  * `graphics`
-
+ * `ray_tracing`
+ 
 ```groovy
-# The PIPELINE command creates a pipeline. This can be either compute or
-# graphics. Shaders are attached to the pipeline at pipeline creation time.
+# The PIPELINE command creates a pipeline. This can be either compute,
+# graphics, or ray_tracing. Shaders are attached to the pipeline
+# at pipeline creation time.
 PIPELINE {pipeline_type} {pipeline_name}
 ...
 END
@@ -458,6 +567,94 @@ The following commands are all specified within the `PIPELINE` command.
   PATCH_CONTROL_POINTS {control_points}
 ```
 
+Ray tracing pipelines do not attach shaders directly like compute or graphics pipelines.
+Ray tracing pipelines organize shaders into shader groups in one of four ways
+depending on shader types used:
+
+```groovy
+  # Four possible shader group definitions
+  SHADER_GROUP {group_name_1} {ray_generation_shader_name}
+  SHADER_GROUP {group_name_2} {miss_shader_name}
+  SHADER_GROUP {group_name_3} {call_shader_name}
+  SHADER_GROUP {group_name_4} [closest_hit_shader_name] [any_hit_shader_name] [intersection_shader_name]
+```
+
+Shader group cannot be empty.
+Each group name must be unique within a pipeline. The same shader can be used within one or more
+shader groups. The shader group order is important, further commands as shader code might refer
+them directly. With the shader groups defined, they are then added into shader binding tables:
+
+```groovy
+  # Create shader binding tables and set shader groups into it
+  SHADER_BINDING_TABLE {sbt_name}
+    {group_name_1}
+    [ | {group_name_n}]
+  END
+```
+
+Generally a program needs three shader binding tables:
+ * ray generation shader binding table with one ray generation shader group
+ * miss shader binding table containing one or more miss shader groups
+ * hit shader binding table containing one or more hit shader groups
+
+Shader binding tables for call shaders are optional.
+
+Ray tracing pipelines support pipeline libraries. To declare a pipeline as a pipeline library
+the pipeline should declare itself a library by specifying `LIBRARY` in `FLAGS`:
+
+```groovy
+  # Declare this pipeline as a library
+  FLAGS LIBRARY
+```
+
+or multiline version:
+
+```groovy
+  # Declare this pipeline as a library
+  FLAGS
+    LIBRARY
+  END
+```
+
+Pipeline `FLAGS` can contain:
+
+ * `LIBRARY`
+
+Ray tracing pipeline can include one or more pipeline libraries:
+
+```groovy
+  # Specify list of libraries to use
+  USE_LIBRARY {library_name_1} [{library_name_2} [...]]
+```
+
+Ray tracing pipelines that declare and use pipeline libraries should declare
+the maximum ray payload size and the maximum ray hit attribute size:
+```groovy
+  # Define maximum ray payload size
+  MAX_RAY_PAYLOAD_SIZE <max_ray_payload_size>
+  # Define maximum ray hit attribute size
+  MAX_RAY_HIT_ATTRIBUTE_SIZE <max_ray_hit_attribute_size>
+```
+
+Default for both maximum ray payload size and maximum ray hit attribute size is zero.
+If there is a pipeline which uses a pipeline library then the `MAX_RAY_PAYLOAD_SIZE` and `MAX_RAY_HIT_ATTRIBUTE_SIZE`
+values must be the same between the pipeline and all the pipeline libraries used.
+
+Used libraries must precede shader group `SHADER_GROUP` and shader binding tables
+`SHADER_BINDING_TABLE` declarations. A pipeline can be a library and use other pipelines as a libraries.
+
+Ray tracing pipelines can declare a maximum ray recursion depth:
+
+```groovy
+  # Define maximum ray recursion depth
+  MAX_RAY_RECURSION_DEPTH <max_ray_recursion_depth>
+```
+
+If the MAX_RAY_RECURSION_DEPTH is not specified, then maximum ray recursion depth is set to 1.
+
+If a pipeline library is used within this pipeline (via `USE_LIBRARY` keyword), then the
+shader binding table can use shader groups from any of the used libraries.
+
 #### Compare operations
  * `never`
  * `less`
@@ -746,6 +943,13 @@ ranges can be used also with dynamic buffers.
   INDEX_DATA {buffer_name}
 ```
 
+Ray tracing pipelines allow bind top level acceleration structures.
+
+```groovy
+  # Bind the top level acceleration structure at the given descriptor set and binding.
+  BIND ACCELERATION_STRUCTURE {tlas_name} DESCRIPTOR_SET _set_id_ BINDING _id_
+```
+
 #### OpenCL Plain-Old-Data Arguments
 OpenCL kernels can have plain-old-data (pod or pod_ubo in the desriptor map)
 arguments set their data via this command. Amber will generate the appropriate
@@ -787,18 +991,22 @@ value for `START_IDX` is 0. The default value for `COUNT` is the item count of
 vertex buffer minus the `START_IDX`. The same applies to `START_INSTANCE`
 (default 0) and `INSTANCE_COUNT` (default 1).
 
+The `TIMED_EXECUTION` is an optional flag that can be passed to the run command.
+This will cause Amber to insert device specific counters to time the execution
+of this pipeline command.
+
 ```groovy
 # Run the given |pipeline_name| which must be a `compute` pipeline. The
 # pipeline will be run with the given number of workgroups in the |x|, |y|, |z|
 # dimensions. Each of the x, y and z values must be a uint32.
-RUN {pipeline_name} _x_ _y_ _z_
+RUN [TIMED_EXECUTION] {pipeline_name} _x_ _y_ _z_
 ```
 
 ```groovy
 # Run the given |pipeline_name| which must be a `graphics` pipeline. The
 # rectangle at |x|, |y|, |width|x|height| will be rendered. Ignores VERTEX_DATA
 # and INDEX_DATA on the given pipeline.
-RUN {pipeline_name} \
+RUN [TIMED_EXECUTION] {pipeline_name} \
   DRAW_RECT POS _x_in_pixels_ _y_in_pixels_ \
   SIZE _width_in_pixels_ _height_in_pixels_
 ```
@@ -808,7 +1016,7 @@ RUN {pipeline_name} \
 # grid at |x|, |y|, |width|x|height|, |columns|x|rows| will be rendered.
 # Ignores VERTEX_DATA and INDEX_DATA on the given pipeline.
 # For columns, rows of (5, 4) a total of 5*4=20 rectangles will be drawn.
-RUN {pipeline_name} \
+RUN [TIMED_EXECUTION] {pipeline_name} \
   DRAW_GRID POS _x_in_pixels_ _y_in_pixels_ \
   SIZE _width_in_pixels_ _height_in_pixels_ \
   CELLS _columns_of_cells_ _rows_of_cells_
@@ -822,7 +1030,7 @@ RUN {pipeline_name} \
 # will be processed. The draw is instanced if |inst_count_value| is greater
 # than one. In case of instanced draw |inst_value| controls the starting
 # instance ID.
-RUN {pipeline_name} DRAW_ARRAY AS {topology} \
+RUN [TIMED_EXECUTION] {pipeline_name} DRAW_ARRAY AS {topology} \
     [ START_IDX _value_ (default 0) ] \
     [ COUNT _count_value_ (default vertex_buffer size - start_idx) ] \
     [ START_INSTANCE _inst_value_ (default 0) ] \
@@ -838,13 +1046,32 @@ RUN {pipeline_name} DRAW_ARRAY AS {topology} \
 # will be processed. The draw is instanced if |inst_count_value| is greater
 # than one. In case of instanced draw |inst_value| controls the starting
 # instance ID.
-RUN {pipeline_name} DRAW_ARRAY AS {topology} INDEXED \
+RUN [TIMED_EXECUTION] {pipeline_name} DRAW_ARRAY AS {topology} INDEXED \
     [ START_IDX _value_ (default 0) ] \
     [ COUNT _count_value_ (default index_buffer size - start_idx) ] \
     [ START_INSTANCE _inst_value_ (default 0) ] \
     [ INSTANCE_COUNT _inst_count_value_ (default 1) ]
 ```
 
+```groovy
+# Run the |pipeline_name| which must be a `ray tracing` pipeline.
+# Next four shader binding table names should be specified:
+# * RAYGEN |ray_gen_sbt_name| - shader binding table containing ray generation shader group
+# * MISS |miss_sbt_name| - shader binding table containing one or more miss shader groups
+# * HIT |hit_sbt_name| - shader binding table containing one or more hit shader groups
+# * CALL |call_sbt_name| - shader binding table containing one or more call shader groups
+# RAYGEN is required, other shader binding tables (MISS, HIT and CALL) are optional.
+#
+# The pipeline will be run with the given ray tracing dimensions |x|, |y|, |z|.
+# Each of the x, y and z values must be a uint32.
+RUN [TIMED_EXECUTION] {pipeline_name} \
+    RAYGEN {ray_gen_sbt_name} \
+    [MISS {miss_sbt_name}] \
+    [HIT {hit_sbt_name}] \
+    [CALL {call_sbt_name}] \
+     _x_ _y_ _z_
+```
+
 ### Repeating commands
 
 ```groovy
@@ -950,7 +1177,7 @@ SHADER compute kComputeShader GLSL
 #version 450
 
 layout(binding = 3) buffer block {
-  vec2 values[];
+  uvec2 values[];
 };
 
 void main() {
diff --git a/include/amber/amber.h b/include/amber/amber.h
index 0c679a3..fafc49b 100644
--- a/include/amber/amber.h
+++ b/include/amber/amber.h
@@ -101,6 +101,12 @@ class Delegate {
   virtual amber::Result LoadBufferData(const std::string file_name,
                                        BufferDataFileType file_type,
                                        amber::BufferInfo* buffer) const = 0;
+  /// Load a raw file
+  virtual amber::Result LoadFile(const std::string file_name,
+                                 std::vector<char>* buffer) const = 0;
+
+  /// Mechanism for gathering timing from 'TIME_EXECUTION'
+  virtual void ReportExecutionTiming(double){}
 };
 
 /// Stores configuration options for Amber.
diff --git a/include/amber/amber_vulkan.h b/include/amber/amber_vulkan.h
index d031579..307a58a 100644
--- a/include/amber/amber_vulkan.h
+++ b/include/amber/amber_vulkan.h
@@ -49,6 +49,18 @@ struct VulkanEngineConfig : public EngineConfig {
   /// the extension is not enabled, |available_features| will be used.
   VkPhysicalDeviceFeatures2KHR available_features2;
 
+  /// Physical device properties available for |physical_device|. The
+  /// |available_properties| will be ignored if
+  /// VK_KHR_get_physical_device_properties2 is enabled, |available_properties2|
+  /// will be used in that case.
+  VkPhysicalDeviceProperties available_properties;
+
+  /// Physical device properties for |physical_device|.The
+  /// |available_properties2| will only be used if
+  /// VK_KHR_get_physical_device_properties2 is enabled. If the extension is not
+  /// enabled, |available_properties| will be used.
+  VkPhysicalDeviceProperties2KHR available_properties2;
+
   /// Instance extensions available.
   std::vector<std::string> available_instance_extensions;
 
diff --git a/include/amber/recipe.h b/include/amber/recipe.h
index 0fd2445..4b8d877 100644
--- a/include/amber/recipe.h
+++ b/include/amber/recipe.h
@@ -35,6 +35,9 @@ class RecipeImpl {
   /// Returns required features in the given recipe.
   virtual std::vector<std::string> GetRequiredFeatures() const = 0;
 
+  /// Returns required features in the given recipe.
+  virtual std::vector<std::string> GetRequiredProperties() const = 0;
+
   /// Returns required device extensions in the given recipe.
   virtual std::vector<std::string> GetRequiredDeviceExtensions() const = 0;
 
@@ -67,6 +70,9 @@ class Recipe {
   /// Returns required features in the given recipe.
   std::vector<std::string> GetRequiredFeatures() const;
 
+  /// Returns required properties in the given recipe.
+  std::vector<std::string> GetRequiredProperties() const;
+
   /// Returns required device extensions in the given recipe.
   std::vector<std::string> GetRequiredDeviceExtensions() const;
 
diff --git a/include/amber/shader_info.h b/include/amber/shader_info.h
index b5ce751..e0772a9 100644
--- a/include/amber/shader_info.h
+++ b/include/amber/shader_info.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -28,6 +29,7 @@ enum ShaderFormat {
   kShaderFormatHlsl,
   kShaderFormatSpirvAsm,
   kShaderFormatSpirvHex,
+  kShaderFormatSpirvBin,
   kShaderFormatOpenCLC,
 };
 
@@ -38,9 +40,21 @@ enum ShaderType {
   kShaderTypeVertex,
   kShaderTypeTessellationControl,
   kShaderTypeTessellationEvaluation,
+  kShaderTypeRayGeneration,
+  kShaderTypeAnyHit,
+  kShaderTypeClosestHit,
+  kShaderTypeMiss,
+  kShaderTypeIntersection,
+  kShaderTypeCall,
   kShaderTypeMulti,
 };
 
+inline bool isRayTracingShaderType(ShaderType type) {
+  return type == kShaderTypeRayGeneration || type == kShaderTypeAnyHit ||
+         type == kShaderTypeClosestHit || type == kShaderTypeMiss ||
+         type == kShaderTypeIntersection || type == kShaderTypeCall;
+}
+
 /// Stores information for a shader.
 struct ShaderInfo {
   /// The format of the shader.
diff --git a/kokoro/scripts/linux/build-docker.sh b/kokoro/scripts/linux/build-docker.sh
index 6b56d0b..9af4635 100755
--- a/kokoro/scripts/linux/build-docker.sh
+++ b/kokoro/scripts/linux/build-docker.sh
@@ -26,6 +26,7 @@ git config --global --add safe.directory '*'
 
 using cmake-3.17.2
 using ninja-1.10.0
+using python-3.12
 
 if [ ! -z "$COMPILER" ]; then
     using "$COMPILER"
diff --git a/kokoro/scripts/linux/build_dawn-docker.sh b/kokoro/scripts/linux/build_dawn-docker.sh
index 16467ae..3b51dfc 100755
--- a/kokoro/scripts/linux/build_dawn-docker.sh
+++ b/kokoro/scripts/linux/build_dawn-docker.sh
@@ -26,6 +26,7 @@ git config --global --add safe.directory '*'
 
 using cmake-3.17.2
 using ninja-1.10.0
+using python-3.12
 
 if [ ! -z "$COMPILER" ]; then
     using "$COMPILER"
@@ -57,6 +58,9 @@ cp scripts/standalone.gclient .gclient
 # Fetch external dependencies and toolchains with gclient
 gclient sync
 
+sudo chown -R "$(id -u):$(id -g)" build/
+sudo chown -R "$(id -u):$(id -g)" third_party/
+
 # Generate build files
 mkdir -p out/Release
 touch out/Release/args.gn
diff --git a/kokoro/scripts/macos/build.sh b/kokoro/scripts/macos/build.sh
index 5f4808c..17f4312 100755
--- a/kokoro/scripts/macos/build.sh
+++ b/kokoro/scripts/macos/build.sh
@@ -28,6 +28,13 @@ unzip -q ninja-mac.zip
 chmod +x ninja
 export PATH="$PWD:$PATH"
 
+# Get Cmake (required for Kokoro Apple Silicon images)
+CMAKE_VER=3.30.2
+wget -q https://github.com/Kitware/CMake/releases/download/v$CMAKE_VER/cmake-$CMAKE_VER-macos-universal.tar.gz
+tar xf cmake-$CMAKE_VER-macos-universal.tar.gz
+chmod +x cmake-$CMAKE_VER-macos-universal/CMake.app/Contents/bin/*
+export PATH="$PWD/cmake-$CMAKE_VER-macos-universal/CMake.app/Contents/bin:$PATH"
+
 echo $(date): $(cmake --version)
 
 DEPS_ARGS=""
diff --git a/kokoro/scripts/windows/build.bat b/kokoro/scripts/windows/build.bat
index 42ccff8..222fdf8 100644
--- a/kokoro/scripts/windows/build.bat
+++ b/kokoro/scripts/windows/build.bat
@@ -30,8 +30,8 @@ python tools\git-sync-deps
 :: #########################################
 :: set up msvc build env
 :: #########################################
-call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
-echo "Using VS 2017..."
+call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
+echo "Using VS 2019..."
 
 cmake --version
 
diff --git a/license-checker.cfg b/license-checker.cfg
index 72a470b..42a2beb 100644
--- a/license-checker.cfg
+++ b/license-checker.cfg
@@ -16,6 +16,7 @@
                 "**.gitignore",
                 "**.md",
                 "**.png",
+                "**.spv",
 
                 "build/**",
                 "third_party/*/**",
diff --git a/samples/CMakeLists.txt b/samples/CMakeLists.txt
index 1e91c4d..1a7ae26 100644
--- a/samples/CMakeLists.txt
+++ b/samples/CMakeLists.txt
@@ -57,7 +57,7 @@ amber_default_compile_options(amber)
 add_custom_command(
     OUTPUT ${CMAKE_BINARY_DIR}/src/build-versions.h.fake
     COMMAND
-      ${PYTHON_EXECUTABLE}
+        ${Python3_EXECUTABLE}
         ${PROJECT_SOURCE_DIR}/tools/update_build_version.py
         ${CMAKE_BINARY_DIR}
         ${CMAKE_CURRENT_SOURCE_DIR}
diff --git a/samples/amber.cc b/samples/amber.cc
index f6d91c5..15baaa2 100644
--- a/samples/amber.cc
+++ b/samples/amber.cc
@@ -23,6 +23,7 @@
 #include <fstream>
 #include <iomanip>
 #include <iostream>
+#include <ostream>
 #include <set>
 #include <string>
 #include <utility>
@@ -55,7 +56,7 @@ struct Options {
   std::vector<std::string> fb_names;
   std::vector<amber::BufferInfo> buffer_to_dump;
   uint32_t engine_major = 1;
-  uint32_t engine_minor = 0;
+  uint32_t engine_minor = 1;
   int32_t fence_timeout = -1;
   int32_t selected_device = -1;
   bool parse_only = false;
@@ -67,6 +68,7 @@ struct Options {
   bool log_graphics_calls = false;
   bool log_graphics_calls_time = false;
   bool log_execute_calls = false;
+  bool log_execution_timing = false;
   bool disable_spirv_validation = false;
   bool enable_pipeline_runtime_layer = false;
   std::string shader_filename;
@@ -103,6 +105,7 @@ const char kUsage[] = R"(Usage: amber [options] SCRIPT [SCRIPTS...]
   --log-graphics-calls      -- Log graphics API calls (only for Vulkan so far).
   --log-graphics-calls-time -- Log timing of graphics API calls timing (Vulkan only).
   --log-execute-calls       -- Log each execute call before run.
+  --log-execution-timing    -- Log timing results from each command with the 'TIMED_EXECUTION' flag.
   --disable-spirv-val       -- Disable SPIR-V validation.
   --enable-runtime-layer    -- Enable pipeline runtime layer.
   -h                        -- This help text.
@@ -278,6 +281,8 @@ bool ParseArgs(const std::vector<std::string>& args, Options* opts) {
       opts->log_graphics_calls = true;
     } else if (arg == "--log-graphics-calls-time") {
       opts->log_graphics_calls_time = true;
+    } else if (arg == "--log-execution-timing") {
+      opts->log_execution_timing = true;
     } else if (arg == "--log-execute-calls") {
       opts->log_execute_calls = true;
     } else if (arg == "--disable-spirv-val") {
@@ -361,6 +366,16 @@ class SampleDelegate : public amber::Delegate {
     }
   }
 
+  void ReportExecutionTiming(double time_in_ms) override {
+    reported_execution_timing.push_back(time_in_ms);
+  }
+
+  std::vector<double> GetAndClearExecutionTiming() {
+    auto returning = reported_execution_timing;
+    reported_execution_timing.clear();
+    return returning;
+  }
+
   uint64_t GetTimestampNs() const override {
     return timestamp::SampleGetTimestampNs();
   }
@@ -395,11 +410,20 @@ class SampleDelegate : public amber::Delegate {
     return {};
   }
 
+  amber::Result LoadFile(const std::string file_name,
+                         std::vector<char>* buffer) const override {
+    *buffer = ReadFile(path_ + file_name);
+    if (buffer->empty())
+      return amber::Result("Failed to load file " + file_name);
+    return {};
+  }
+
  private:
   bool log_graphics_calls_ = false;
   bool log_graphics_calls_time_ = false;
   bool log_execute_calls_ = false;
   std::string path_ = "";
+  std::vector<double> reported_execution_timing;
 };
 
 std::string disassemble(const std::string& env,
@@ -519,7 +543,7 @@ int main(int argc, const char** argv) {
       recipe->SetFenceTimeout(static_cast<uint32_t>(options.fence_timeout));
 
     recipe->SetPipelineRuntimeLayerEnabled(
-      options.enable_pipeline_runtime_layer);
+        options.enable_pipeline_runtime_layer);
 
     recipe_data.emplace_back();
     recipe_data.back().file = file;
@@ -621,12 +645,35 @@ int main(int argc, const char** argv) {
     amber::Amber am(&delegate);
     result = am.Execute(recipe, &amber_options);
     if (!result.IsSuccess()) {
-      std::cerr << file << ": " << result.Error() << std::endl;
+      std::cerr << file << ": " << result.Error() << "\n";
       failures.push_back(file);
       // Note, we continue after failure to allow dumping the buffers which may
       // give clues as to the failure.
     }
 
+    auto execution_timing = delegate.GetAndClearExecutionTiming();
+    if (result.IsSuccess() && options.log_execution_timing &&
+        !execution_timing.empty()) {
+      std::cout << "Execution timing (in script-order):" << "\n";
+      std::cout << "    ";
+      bool is_first_iter = true;
+      for (auto& timing : execution_timing) {
+        if (!is_first_iter) {
+          std::cout << ", ";
+        }
+        is_first_iter = false;
+        std::cout << timing;
+      }
+      std::cout << "\n";
+      std::sort(execution_timing.begin(), execution_timing.end());
+      auto report_median =
+          (execution_timing[execution_timing.size() / 2] +
+           execution_timing[(execution_timing.size() - 1) / 2]) /
+          2;
+      std::cout << "\n";
+      std::cout << "Execution time median = " << report_median << " ms" << "\n";
+    }
+
     // Dump the shader assembly
     if (!options.shader_filename.empty()) {
 #if AMBER_ENABLE_SPIRV_TOOLS
diff --git a/samples/config_helper_vulkan.cc b/samples/config_helper_vulkan.cc
index 9bad7ab..213c47b 100644
--- a/samples/config_helper_vulkan.cc
+++ b/samples/config_helper_vulkan.cc
@@ -72,6 +72,13 @@ const char kComputeFullSubgroups[] = "SubgroupSizeControl.computeFullSubgroups";
 const char kShaderSubgroupExtendedTypes[] =
     "ShaderSubgroupExtendedTypesFeatures.shaderSubgroupExtendedTypes";
 
+const char kAccelerationStructure[] =
+    "AccelerationStructureFeaturesKHR.accelerationStructure";
+const char kBufferDeviceAddress[] =
+    "BufferDeviceAddressFeatures.bufferDeviceAddress";
+const char kRayTracingPipeline[] =
+    "RayTracingPipelineFeaturesKHR.rayTracingPipeline";
+
 const char kExtensionForValidationLayer[] = "VK_EXT_debug_report";
 
 VKAPI_ATTR VkBool32 VKAPI_CALL debugCallback(VkDebugReportFlagsEXT flag,
@@ -649,7 +656,13 @@ ConfigHelperVulkan::ConfigHelperVulkan()
       storage_8bit_feature_(VkPhysicalDevice8BitStorageFeaturesKHR()),
       storage_16bit_feature_(VkPhysicalDevice16BitStorageFeaturesKHR()),
       subgroup_size_control_feature_(
-          VkPhysicalDeviceSubgroupSizeControlFeaturesEXT()) {}
+          VkPhysicalDeviceSubgroupSizeControlFeaturesEXT()),
+      acceleration_structure_feature_(
+          VkPhysicalDeviceAccelerationStructureFeaturesKHR()),
+      buffer_device_address_feature_(
+          VkPhysicalDeviceBufferDeviceAddressFeatures()),
+      ray_tracing_pipeline_feature_(
+          VkPhysicalDeviceRayTracingPipelineFeaturesKHR()) {}
 
 ConfigHelperVulkan::~ConfigHelperVulkan() {
   if (vulkan_device_)
@@ -793,6 +806,14 @@ amber::Result ConfigHelperVulkan::CheckVulkanPhysicalDeviceRequirements(
       supports_subgroup_size_control_ = true;
     else if (ext == "VK_KHR_shader_subgroup_extended_types")
       supports_shader_subgroup_extended_types_ = true;
+    else if (ext == "VK_KHR_variable_pointers")
+      supports_variable_pointers_ = true;
+    else if (ext == "VK_KHR_acceleration_structure")
+      supports_acceleration_structure_ = true;
+    else if (ext == "VK_KHR_buffer_device_address")
+      supports_buffer_device_address_ = true;
+    else if (ext == "VK_KHR_ray_tracing_pipeline")
+      supports_ray_tracing_pipeline_ = true;
   }
 
   VkPhysicalDeviceFeatures required_vulkan_features =
@@ -807,39 +828,71 @@ amber::Result ConfigHelperVulkan::CheckVulkanPhysicalDeviceRequirements(
     VkPhysicalDeviceFloat16Int8FeaturesKHR float16_int8_features = {};
     VkPhysicalDevice8BitStorageFeaturesKHR storage_8bit_features = {};
     VkPhysicalDevice16BitStorageFeaturesKHR storage_16bit_features = {};
+    VkPhysicalDeviceAccelerationStructureFeaturesKHR
+        acceleration_structure_features = {};
+    VkPhysicalDeviceBufferDeviceAddressFeatures buffer_device_address_features =
+        {};
+    VkPhysicalDeviceRayTracingPipelineFeaturesKHR
+        ray_tracing_pipeline_features = {};
+    void* next_ptr = nullptr;
 
-    subgroup_size_control_features.sType =
-        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_FEATURES_EXT;
-    subgroup_size_control_features.pNext = nullptr;
+    if (supports_subgroup_size_control_) {
+      subgroup_size_control_features.sType =
+          VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_FEATURES_EXT;
+      subgroup_size_control_features.pNext = next_ptr;
+      next_ptr = &subgroup_size_control_features;
+    }
 
-    // Add subgroup size control struct into the chain only if
-    // VK_EXT_subgroup_size_control is supported.
     variable_pointers_features.sType =
         VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VARIABLE_POINTER_FEATURES_KHR;
-    variable_pointers_features.pNext = supports_subgroup_size_control_
-                                           ? &subgroup_size_control_features
-                                           : nullptr;
+    variable_pointers_features.pNext = next_ptr;
+    next_ptr = &variable_pointers_features;
 
     shader_subgroup_extended_types_features.sType =
         // NOLINTNEXTLINE(whitespace/line_length)
         VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_SUBGROUP_EXTENDED_TYPES_FEATURES;
-    shader_subgroup_extended_types_features.pNext = &variable_pointers_features;
+    shader_subgroup_extended_types_features.pNext = next_ptr;
+    next_ptr = &shader_subgroup_extended_types_features;
 
     float16_int8_features.sType =
         VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FLOAT16_INT8_FEATURES_KHR;
-    float16_int8_features.pNext = &shader_subgroup_extended_types_features;
+    float16_int8_features.pNext = next_ptr;
+    next_ptr = &float16_int8_features;
 
     storage_8bit_features.sType =
         VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_8BIT_STORAGE_FEATURES_KHR;
-    storage_8bit_features.pNext = &float16_int8_features;
+    storage_8bit_features.pNext = next_ptr;
+    next_ptr = &storage_8bit_features;
 
     storage_16bit_features.sType =
         VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_16BIT_STORAGE_FEATURES_KHR;
-    storage_16bit_features.pNext = &storage_8bit_features;
+    storage_16bit_features.pNext = next_ptr;
+    next_ptr = &storage_16bit_features;
+
+    if (supports_acceleration_structure_) {
+      acceleration_structure_features.sType =
+          VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ACCELERATION_STRUCTURE_FEATURES_KHR;
+      acceleration_structure_features.pNext = next_ptr;
+      next_ptr = &acceleration_structure_features;
+    }
+
+    if (supports_buffer_device_address_) {
+      buffer_device_address_features.sType =
+          VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES;
+      buffer_device_address_features.pNext = next_ptr;
+      next_ptr = &buffer_device_address_features;
+    }
+
+    if (supports_ray_tracing_pipeline_) {
+      ray_tracing_pipeline_features.sType =
+          VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_PIPELINE_FEATURES_KHR;
+      ray_tracing_pipeline_features.pNext = next_ptr;
+      next_ptr = &ray_tracing_pipeline_features;
+    }
 
     VkPhysicalDeviceFeatures2KHR features2 = VkPhysicalDeviceFeatures2KHR();
     features2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2_KHR;
-    features2.pNext = &storage_16bit_features;
+    features2.pNext = next_ptr;
 
     auto vkGetPhysicalDeviceFeatures2KHR =
         reinterpret_cast<PFN_vkGetPhysicalDeviceFeatures2KHR>(
@@ -887,7 +940,13 @@ amber::Result ConfigHelperVulkan::CheckVulkanPhysicalDeviceRequirements(
                VK_FALSE) ||
           (feature == kShaderSubgroupExtendedTypes &&
            shader_subgroup_extended_types_features
-                   .shaderSubgroupExtendedTypes == VK_FALSE)) {
+                   .shaderSubgroupExtendedTypes == VK_FALSE) ||
+          (feature == kAccelerationStructure &&
+           acceleration_structure_features.accelerationStructure == VK_FALSE) ||
+          (feature == kBufferDeviceAddress &&
+           buffer_device_address_features.bufferDeviceAddress == VK_FALSE) ||
+          (feature == kRayTracingPipeline &&
+           ray_tracing_pipeline_features.rayTracingPipeline == VK_FALSE)) {
         return amber::Result("Device does not support all required features");
       }
     }
@@ -980,28 +1039,32 @@ amber::Result ConfigHelperVulkan::CreateVulkanDevice(
   queue_info.queueCount = 1;
   queue_info.pQueuePriorities = priorities;
 
-  std::vector<const char*> required_extensions_in_char;
-  std::transform(
-      required_extensions.begin(), required_extensions.end(),
-      std::back_inserter(required_extensions_in_char),
-      [](const std::string& ext) -> const char* { return ext.c_str(); });
-
   VkDeviceCreateInfo info = VkDeviceCreateInfo();
   info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
   info.pQueueCreateInfos = &queue_info;
   info.queueCreateInfoCount = 1;
-  info.enabledExtensionCount =
-      static_cast<uint32_t>(required_extensions_in_char.size());
-  info.ppEnabledExtensionNames = required_extensions_in_char.data();
 
   if (supports_get_physical_device_properties2_)
-    return CreateDeviceWithFeatures2(required_features, &info);
-  return CreateDeviceWithFeatures1(required_features, &info);
+    return CreateDeviceWithFeatures2(required_features, required_extensions,
+                                     &info);
+  return CreateDeviceWithFeatures1(required_features, required_extensions,
+                                   &info);
 }
 
 amber::Result ConfigHelperVulkan::CreateDeviceWithFeatures1(
     const std::vector<std::string>& required_features,
+    const std::vector<std::string>& required_extensions,
     VkDeviceCreateInfo* info) {
+  std::vector<const char*> required_extensions_in_char;
+  std::transform(
+      required_extensions.begin(), required_extensions.end(),
+      std::back_inserter(required_extensions_in_char),
+      [](const std::string& ext) -> const char* { return ext.c_str(); });
+
+  info->enabledExtensionCount =
+      static_cast<uint32_t>(required_extensions_in_char.size());
+  info->ppEnabledExtensionNames = required_extensions_in_char.data();
+
   VkPhysicalDeviceFeatures required_vulkan_features =
       VkPhysicalDeviceFeatures();
   amber::Result r =
@@ -1015,6 +1078,7 @@ amber::Result ConfigHelperVulkan::CreateDeviceWithFeatures1(
 
 amber::Result ConfigHelperVulkan::CreateDeviceWithFeatures2(
     const std::vector<std::string>& required_features,
+    const std::vector<std::string>& required_extensions,
     VkDeviceCreateInfo* info) {
   variable_pointers_feature_.sType =
       VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VARIABLE_POINTER_FEATURES_KHR;
@@ -1040,35 +1104,127 @@ amber::Result ConfigHelperVulkan::CreateDeviceWithFeatures2(
       VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_SUBGROUP_EXTENDED_TYPES_FEATURES;
   shader_subgroup_extended_types_feature_.pNext = nullptr;
 
-  void** next_ptr = &variable_pointers_feature_.pNext;
+  acceleration_structure_feature_.sType =
+      VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ACCELERATION_STRUCTURE_FEATURES_KHR;
+  acceleration_structure_feature_.pNext = nullptr;
+
+  buffer_device_address_feature_.sType =
+      VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES;
+  buffer_device_address_feature_.pNext = nullptr;
+
+  ray_tracing_pipeline_feature_.sType =
+      VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_PIPELINE_FEATURES_KHR;
+  ray_tracing_pipeline_feature_.pNext = nullptr;
+
+  std::vector<std::string> exts = required_extensions;
+
+  void* pnext = nullptr;
+  void** next_ptr = nullptr;
+
+  if (supports_variable_pointers_) {
+    if (pnext == nullptr) {
+      pnext = &variable_pointers_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &variable_pointers_feature_.pNext;
+    }
+    next_ptr = &variable_pointers_feature_.pNext;
+    exts.push_back(VK_KHR_VARIABLE_POINTERS_EXTENSION_NAME);
+  }
 
   if (supports_shader_float16_int8_) {
-    *next_ptr = &float16_int8_feature_;
+    if (pnext == nullptr) {
+      pnext = &float16_int8_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &float16_int8_feature_;
+    }
     next_ptr = &float16_int8_feature_.pNext;
   }
 
   if (supports_shader_8bit_storage_) {
-    *next_ptr = &storage_8bit_feature_;
+    if (pnext == nullptr) {
+      pnext = &storage_8bit_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &storage_8bit_feature_;
+    }
     next_ptr = &storage_8bit_feature_.pNext;
   }
 
   if (supports_shader_16bit_storage_) {
-    *next_ptr = &storage_16bit_feature_;
+    if (pnext == nullptr) {
+      pnext = &storage_16bit_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &storage_16bit_feature_;
+    }
     next_ptr = &storage_16bit_feature_.pNext;
   }
 
   if (supports_subgroup_size_control_) {
-    *next_ptr = &subgroup_size_control_feature_;
+    if (pnext == nullptr) {
+      pnext = &subgroup_size_control_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &subgroup_size_control_feature_;
+    }
     next_ptr = &subgroup_size_control_feature_.pNext;
+
+    exts.push_back(VK_EXT_SUBGROUP_SIZE_CONTROL_EXTENSION_NAME);
   }
 
   if (supports_shader_subgroup_extended_types_) {
-    *next_ptr = &shader_subgroup_extended_types_feature_;
+    if (pnext == nullptr) {
+      pnext = &shader_subgroup_extended_types_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &shader_subgroup_extended_types_feature_;
+    }
     next_ptr = &shader_subgroup_extended_types_feature_.pNext;
   }
 
+  if (supports_acceleration_structure_) {
+    if (pnext == nullptr) {
+      pnext = &acceleration_structure_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &acceleration_structure_feature_;
+    }
+    next_ptr = &acceleration_structure_feature_.pNext;
+  }
+
+  if (supports_buffer_device_address_) {
+    if (pnext == nullptr) {
+      pnext = &buffer_device_address_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &buffer_device_address_feature_;
+    }
+    next_ptr = &buffer_device_address_feature_.pNext;
+  }
+
+  if (supports_ray_tracing_pipeline_) {
+    if (pnext == nullptr) {
+      pnext = &ray_tracing_pipeline_feature_;
+    }
+    if (next_ptr != nullptr) {
+      *next_ptr = &ray_tracing_pipeline_feature_;
+    }
+    next_ptr = &ray_tracing_pipeline_feature_.pNext;
+  }
+
   available_features2_.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2_KHR;
-  available_features2_.pNext = &variable_pointers_feature_;
+  available_features2_.pNext = pnext;
+
+  std::vector<const char*> required_extensions_in_char;
+  std::transform(
+      exts.begin(), exts.end(), std::back_inserter(required_extensions_in_char),
+      [](const std::string& ext) -> const char* { return ext.c_str(); });
+
+  info->enabledExtensionCount =
+      static_cast<uint32_t>(required_extensions_in_char.size());
+  info->ppEnabledExtensionNames = required_extensions_in_char.data();
 
   std::vector<std::string> feature1_names;
   for (const auto& feature : required_features) {
@@ -1107,6 +1263,12 @@ amber::Result ConfigHelperVulkan::CreateDeviceWithFeatures2(
     else if (feature == kShaderSubgroupExtendedTypes)
       shader_subgroup_extended_types_feature_.shaderSubgroupExtendedTypes =
           VK_TRUE;
+    else if (feature == kAccelerationStructure)
+      acceleration_structure_feature_.accelerationStructure = VK_TRUE;
+    else if (feature == kBufferDeviceAddress)
+      buffer_device_address_feature_.bufferDeviceAddress = VK_TRUE;
+    else if (feature == kRayTracingPipeline)
+      ray_tracing_pipeline_feature_.rayTracingPipeline = VK_TRUE;
   }
 
   VkPhysicalDeviceFeatures required_vulkan_features =
diff --git a/samples/config_helper_vulkan.h b/samples/config_helper_vulkan.h
index 216a05f..4cb90ff 100644
--- a/samples/config_helper_vulkan.h
+++ b/samples/config_helper_vulkan.h
@@ -89,10 +89,12 @@ class ConfigHelperVulkan : public ConfigHelperImpl {
   /// Sets up the device creation to use VkPhysicalDeviceFeatures.
   amber::Result CreateDeviceWithFeatures1(
       const std::vector<std::string>& required_features,
+      const std::vector<std::string>& required_extensions,
       VkDeviceCreateInfo* info);
   /// Sets up the device creation to use VkPhysicalDeviceFeatures2KHR.
   amber::Result CreateDeviceWithFeatures2(
       const std::vector<std::string>& required_features,
+      const std::vector<std::string>& required_extensions,
       VkDeviceCreateInfo* info);
 
   /// Creates the physical device given the device |info|.
@@ -111,11 +113,15 @@ class ConfigHelperVulkan : public ConfigHelperImpl {
   VkDevice vulkan_device_ = VK_NULL_HANDLE;
 
   bool supports_get_physical_device_properties2_ = false;
+  bool supports_variable_pointers_ = false;
   bool supports_shader_float16_int8_ = false;
   bool supports_shader_8bit_storage_ = false;
   bool supports_shader_16bit_storage_ = false;
   bool supports_subgroup_size_control_ = false;
   bool supports_shader_subgroup_extended_types_ = false;
+  bool supports_acceleration_structure_ = false;
+  bool supports_buffer_device_address_ = false;
+  bool supports_ray_tracing_pipeline_ = false;
   VkPhysicalDeviceFeatures available_features_;
   VkPhysicalDeviceFeatures2KHR available_features2_;
   VkPhysicalDeviceVariablePointerFeaturesKHR variable_pointers_feature_;
@@ -125,6 +131,10 @@ class ConfigHelperVulkan : public ConfigHelperImpl {
   VkPhysicalDeviceSubgroupSizeControlFeaturesEXT subgroup_size_control_feature_;
   VkPhysicalDeviceShaderSubgroupExtendedTypesFeatures
       shader_subgroup_extended_types_feature_;
+  VkPhysicalDeviceAccelerationStructureFeaturesKHR
+      acceleration_structure_feature_;
+  VkPhysicalDeviceBufferDeviceAddressFeatures buffer_device_address_feature_;
+  VkPhysicalDeviceRayTracingPipelineFeaturesKHR ray_tracing_pipeline_feature_;
 };
 
 }  // namespace sample
diff --git a/src/CMakeLists.txt b/src/CMakeLists.txt
index 3b7a4a5..6fd6446 100644
--- a/src/CMakeLists.txt
+++ b/src/CMakeLists.txt
@@ -1,4 +1,5 @@
 # Copyright 2018 The Amber Authors.
+# Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,6 +14,7 @@
 # limitations under the License.
 
 set(AMBER_SOURCES
+    acceleration_structure.cc
     amber.cc
     amberscript/parser.cc
     buffer.cc
@@ -141,14 +143,17 @@ if (${AMBER_ENABLE_TESTS})
     amberscript/parser_copy_test.cc
     amberscript/parser_depth_test.cc
     amberscript/parser_device_feature_test.cc
+    amberscript/parser_device_property_test.cc
     amberscript/parser_expect_test.cc
     amberscript/parser_extension_test.cc
     amberscript/parser_framebuffer_test.cc
     amberscript/parser_image_test.cc
     amberscript/parser_pipeline_test.cc
     amberscript/parser_pipeline_set_test.cc
+    amberscript/parser_raytracing_test.cc
     amberscript/parser_repeat_test.cc
     amberscript/parser_run_test.cc
+    amberscript/parser_run_timed_execution_test.cc
     amberscript/parser_sampler_test.cc
     amberscript/parser_set_test.cc
     amberscript/parser_shader_opt_test.cc
diff --git a/src/acceleration_structure.cc b/src/acceleration_structure.cc
new file mode 100644
index 0000000..4507b5e
--- /dev/null
+++ b/src/acceleration_structure.cc
@@ -0,0 +1,51 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "src/acceleration_structure.h"
+
+#include <algorithm>
+#include <cassert>
+#include <cmath>
+#include <cstring>
+
+namespace amber {
+
+Geometry::Geometry() = default;
+Geometry::~Geometry() = default;
+
+BLAS::BLAS() = default;
+BLAS::~BLAS() = default;
+
+BLASInstance::~BLASInstance() = default;
+
+TLAS::TLAS() = default;
+TLAS::~TLAS() = default;
+
+ShaderGroup::ShaderGroup()
+    : name_(),
+      generalShader_(nullptr),
+      closestHitShader_(nullptr),
+      anyHitShader_(nullptr),
+      intersectionShader_(nullptr) {}
+
+ShaderGroup::~ShaderGroup() = default;
+
+SBTRecord::SBTRecord() = default;
+SBTRecord::~SBTRecord() = default;
+
+SBT::SBT() = default;
+SBT::~SBT() = default;
+
+}  // namespace amber
diff --git a/src/acceleration_structure.h b/src/acceleration_structure.h
new file mode 100644
index 0000000..180fde0
--- /dev/null
+++ b/src/acceleration_structure.h
@@ -0,0 +1,278 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef SRC_ACCELERATION_STRUCTURE_H_
+#define SRC_ACCELERATION_STRUCTURE_H_
+
+#include <cstdint>
+#include <memory>
+#include <string>
+#include <utility>
+#include <vector>
+
+#include "amber/amber.h"
+#include "amber/result.h"
+#include "amber/value.h"
+#include "src/format.h"
+#include "src/image.h"
+
+namespace amber {
+
+enum class GeometryType : int8_t {
+  kUnknown = 0,
+  kTriangle,
+  kAABB,
+};
+
+class Shader;
+
+class Geometry {
+ public:
+  Geometry();
+  ~Geometry();
+
+  void SetType(GeometryType type) { type_ = type; }
+  GeometryType GetType() { return type_; }
+
+  void SetData(std::vector<float>& data) { data_.swap(data); }
+  std::vector<float>& GetData() { return data_; }
+
+  void SetFlags(uint32_t flags) { flags_ = flags; }
+  uint32_t GetFlags() { return flags_; }
+
+  size_t getVertexCount() const {
+    return data_.size() / 3;  // Three floats to define vertex
+  }
+
+  size_t getPrimitiveCount() const {
+    return IsTriangle() ? (getVertexCount() / 3)  // 3 vertices per triangle
+           : IsAABB()   ? (getVertexCount() / 2)  // 2 vertices per AABB
+                        : 0;
+  }
+
+  bool IsTriangle() const { return type_ == GeometryType::kTriangle; }
+  bool IsAABB() const { return type_ == GeometryType::kAABB; }
+
+ private:
+  GeometryType type_ = GeometryType::kUnknown;
+  std::vector<float> data_;
+  uint32_t flags_ = 0u;
+};
+
+class BLAS {
+ public:
+  BLAS();
+  ~BLAS();
+
+  void SetName(const std::string& name) { name_ = name; }
+  std::string GetName() const { return name_; }
+
+  void AddGeometry(std::unique_ptr<Geometry>* geometry) {
+    geometry_.push_back(std::move(*geometry));
+  }
+  size_t GetGeometrySize() { return geometry_.size(); }
+  std::vector<std::unique_ptr<Geometry>>& GetGeometries() { return geometry_; }
+
+ private:
+  std::string name_;
+  std::vector<std::unique_ptr<Geometry>> geometry_;
+};
+
+class BLASInstance {
+ public:
+  BLASInstance()
+      : used_blas_name_(),
+        used_blas_(nullptr),
+        transform_(0),
+        instance_custom_index_(0),
+        mask_(0xFF),
+        instanceShaderBindingTableRecordOffset_(0),
+        flags_(0) {}
+  ~BLASInstance();
+
+  void SetUsedBLAS(const std::string& name, BLAS* blas) {
+    used_blas_name_ = name;
+    used_blas_ = blas;
+  }
+  std::string GetUsedBLASName() const { return used_blas_name_; }
+  BLAS* GetUsedBLAS() const { return used_blas_; }
+
+  void SetTransform(const std::vector<float>& transform) {
+    transform_ = transform;
+  }
+  const float* GetTransform() const { return transform_.data(); }
+
+  void SetInstanceIndex(uint32_t instance_custom_index) {
+    instance_custom_index_ = instance_custom_index;
+    // Make sure argument was not cut off
+    assert(instance_custom_index_ == instance_custom_index);
+  }
+  uint32_t GetInstanceIndex() const { return instance_custom_index_; }
+
+  void SetMask(uint32_t mask) {
+    mask_ = mask;
+    // Make sure argument was not cut off
+    assert(mask_ == mask);
+  }
+  uint32_t GetMask() const { return mask_; }
+
+  void SetOffset(uint32_t offset) {
+    instanceShaderBindingTableRecordOffset_ = offset;
+    // Make sure argument was not cut off
+    assert(instanceShaderBindingTableRecordOffset_ == offset);
+  }
+  uint32_t GetOffset() const { return instanceShaderBindingTableRecordOffset_; }
+
+  void SetFlags(uint32_t flags) {
+    flags_ = flags;
+    // Make sure argument was not cut off
+    assert(flags_ == flags);
+  }
+  uint32_t GetFlags() const { return flags_; }
+
+ private:
+  std::string used_blas_name_;
+  BLAS* used_blas_;
+  std::vector<float> transform_;
+  uint32_t instance_custom_index_ : 24;
+  uint32_t mask_ : 8;
+  uint32_t instanceShaderBindingTableRecordOffset_ : 24;
+  uint32_t flags_ : 8;
+};
+
+class TLAS {
+ public:
+  TLAS();
+  ~TLAS();
+
+  void SetName(const std::string& name) { name_ = name; }
+  std::string GetName() const { return name_; }
+
+  void AddInstance(std::unique_ptr<BLASInstance> instance) {
+    blas_instances_.push_back(
+        std::unique_ptr<BLASInstance>(instance.release()));
+  }
+  size_t GetInstanceSize() { return blas_instances_.size(); }
+  std::vector<std::unique_ptr<BLASInstance>>& GetInstances() {
+    return blas_instances_;
+  }
+
+ private:
+  std::string name_;
+  std::vector<std::unique_ptr<BLASInstance>> blas_instances_;
+};
+
+class ShaderGroup {
+ public:
+  ShaderGroup();
+  ~ShaderGroup();
+
+  void SetName(const std::string& name) { name_ = name; }
+  std::string GetName() const { return name_; }
+
+  void SetGeneralShader(Shader* shader) { generalShader_ = shader; }
+  Shader* GetGeneralShader() const { return generalShader_; }
+
+  void SetClosestHitShader(Shader* shader) { closestHitShader_ = shader; }
+  Shader* GetClosestHitShader() const { return closestHitShader_; }
+
+  void SetAnyHitShader(Shader* shader) { anyHitShader_ = shader; }
+  Shader* GetAnyHitShader() const { return anyHitShader_; }
+
+  void SetIntersectionShader(Shader* shader) { intersectionShader_ = shader; }
+  Shader* GetIntersectionShader() const { return intersectionShader_; }
+
+  bool IsGeneralGroup() const { return generalShader_ != nullptr; }
+  bool IsHitGroup() const {
+    return closestHitShader_ != nullptr || anyHitShader_ != nullptr ||
+           intersectionShader_ != nullptr;
+  }
+  Shader* GetShaderByType(ShaderType type) const {
+    switch (type) {
+      case kShaderTypeRayGeneration:
+      case kShaderTypeMiss:
+      case kShaderTypeCall:
+        return generalShader_;
+      case kShaderTypeAnyHit:
+        return anyHitShader_;
+      case kShaderTypeClosestHit:
+        return closestHitShader_;
+      case kShaderTypeIntersection:
+        return intersectionShader_;
+      default:
+        assert(0 && "Unsupported shader type");
+        return nullptr;
+    }
+  }
+
+ private:
+  std::string name_;
+  Shader* generalShader_;
+  Shader* closestHitShader_;
+  Shader* anyHitShader_;
+  Shader* intersectionShader_;
+};
+
+class SBTRecord {
+ public:
+  SBTRecord();
+  ~SBTRecord();
+
+  void SetUsedShaderGroupName(const std::string& shader_group_name) {
+    used_shader_group_name_ = shader_group_name;
+  }
+  std::string GetUsedShaderGroupName() const { return used_shader_group_name_; }
+
+  void SetCount(const uint32_t count) { count_ = count; }
+  uint32_t GetCount() const { return count_; }
+
+  void SetIndex(const uint32_t index) { index_ = index; }
+  uint32_t GetIndex() const { return index_; }
+
+ private:
+  std::string used_shader_group_name_;
+  uint32_t count_ = 1;
+  uint32_t index_ = static_cast<uint32_t>(-1);
+};
+
+class SBT {
+ public:
+  SBT();
+  ~SBT();
+
+  void SetName(const std::string& name) { name_ = name; }
+  std::string GetName() const { return name_; }
+
+  void AddSBTRecord(std::unique_ptr<SBTRecord> record) {
+    records_.push_back(std::move(record));
+  }
+  size_t GetSBTRecordCount() { return records_.size(); }
+  std::vector<std::unique_ptr<SBTRecord>>& GetSBTRecords() { return records_; }
+  uint32_t GetSBTSize() {
+    uint32_t size = 0;
+    for (auto& x : records_)
+      size += x->GetCount();
+
+    return size;
+  }
+
+ private:
+  std::string name_;
+  std::vector<std::unique_ptr<SBTRecord>> records_;
+};
+
+}  // namespace amber
+
+#endif  // SRC_ACCELERATION_STRUCTURE_H_
diff --git a/src/amber.cc b/src/amber.cc
index 9bf806e..20ebcf8 100644
--- a/src/amber.cc
+++ b/src/amber.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -131,10 +132,10 @@ Result CreateEngineAndCheckRequirements(const Recipe* recipe,
 
   // Engine initialization checks requirements.  Current backends don't do
   // much else.  Refactor this if they end up doing to much here.
-  Result r =
-      engine->Initialize(opts->config, delegate, script->GetRequiredFeatures(),
-                         script->GetRequiredInstanceExtensions(),
-                         script->GetRequiredDeviceExtensions());
+  Result r = engine->Initialize(
+      opts->config, delegate, script->GetRequiredFeatures(),
+      script->GetRequiredProperties(), script->GetRequiredInstanceExtensions(),
+      script->GetRequiredDeviceExtensions());
   if (!r.IsSuccess())
     return r;
 
diff --git a/src/amberscript/parser.cc b/src/amberscript/parser.cc
index a2e837f..6ea3118 100644
--- a/src/amberscript/parser.cc
+++ b/src/amberscript/parser.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -22,6 +23,7 @@
 #include <utility>
 #include <vector>
 
+#include "amber/vulkan_header.h"
 #include "src/image.h"
 #include "src/make_unique.h"
 #include "src/sampler.h"
@@ -304,6 +306,8 @@ Result Parser::Parse(const std::string& data) {
       r = ParseDeviceFeature();
     } else if (tok == "DEVICE_EXTENSION") {
       r = ParseDeviceExtension();
+    } else if (tok == "DEVICE_PROPERTY") {
+      r = ParseDeviceProperty();
     } else if (tok == "IMAGE") {
       r = ParseImage();
     } else if (tok == "INSTANCE_EXTENSION") {
@@ -322,6 +326,8 @@ Result Parser::Parse(const std::string& data) {
       r = ParseSampler();
     } else if (tok == "VIRTUAL_FILE") {
       r = ParseVirtualFile();
+    } else if (tok == "ACCELERATION_STRUCTURE") {
+      r = ParseAS();
     } else {
       r = Result("unknown token: " + tok);
     }
@@ -404,6 +410,18 @@ Result Parser::ToShaderType(const std::string& str, ShaderType* type) {
     *type = kShaderTypeTessellationControl;
   else if (str == "compute")
     *type = kShaderTypeCompute;
+  else if (str == "ray_generation")
+    *type = kShaderTypeRayGeneration;
+  else if (str == "any_hit")
+    *type = kShaderTypeAnyHit;
+  else if (str == "closest_hit")
+    *type = kShaderTypeClosestHit;
+  else if (str == "miss")
+    *type = kShaderTypeMiss;
+  else if (str == "intersection")
+    *type = kShaderTypeIntersection;
+  else if (str == "callable")
+    *type = kShaderTypeCall;
   else if (str == "multi")
     *type = kShaderTypeMulti;
   else
@@ -422,6 +440,8 @@ Result Parser::ToShaderFormat(const std::string& str, ShaderFormat* fmt) {
     *fmt = kShaderFormatSpirvAsm;
   else if (str == "SPIRV-HEX")
     *fmt = kShaderFormatSpirvHex;
+  else if (str == "SPIRV-BIN")
+    *fmt = kShaderFormatSpirvBin;
   else if (str == "OPENCL-C")
     *fmt = kShaderFormatOpenCLC;
   else
@@ -436,6 +456,8 @@ Result Parser::ToPipelineType(const std::string& str, PipelineType* type) {
     *type = PipelineType::kCompute;
   else if (str == "graphics")
     *type = PipelineType::kGraphics;
+  else if (str == "raytracing")
+    *type = PipelineType::kRayTracing;
   else
     return Result("unknown pipeline type: " + str);
   return {};
@@ -506,19 +528,33 @@ Result Parser::ParseShaderBlock() {
   }
 
   token = tokenizer_->PeekNextToken();
-  if (token->IsIdentifier() && token->AsString() == "VIRTUAL_FILE") {
-    tokenizer_->NextToken();  // Skip VIRTUAL_FILE
+  if (token->IsIdentifier() &&
+      (token->AsString() == "VIRTUAL_FILE" || token->AsString() == "FILE")) {
+    bool isVirtual = token->AsString() == "VIRTUAL_FILE";
+    tokenizer_->NextToken();  // Skip VIRTUAL_FILE or FILE
 
     token = tokenizer_->NextToken();
     if (!token->IsIdentifier() && !token->IsString())
-      return Result("expected virtual file path after VIRTUAL_FILE");
+      return Result("expected file path after VIRTUAL_FILE or FILE");
 
     auto path = token->AsString();
 
     std::string data;
-    r = script_->GetVirtualFile(path, &data);
-    if (!r.IsSuccess())
-      return r;
+    if (isVirtual) {
+      r = script_->GetVirtualFile(path, &data);
+      if (!r.IsSuccess())
+        return r;
+    } else {
+      if (!delegate_)
+        return Result("missing delegate for loading shader file");
+
+      std::vector<char> buffer;
+      r = delegate_->LoadFile(path, &buffer);
+      if (!r.IsSuccess())
+        return r;
+
+      data.insert(data.begin(), buffer.begin(), buffer.end());
+    }
 
     shader->SetData(data);
     shader->SetFilePath(path);
@@ -548,6 +584,9 @@ Result Parser::ParseShaderBlock() {
   if (!token->IsIdentifier() || token->AsString() != "END")
     return Result("SHADER missing END command");
 
+  if (shader->GetTargetEnv().empty() && IsRayTracingShader(type))
+    shader->SetTargetEnv("spv1.4");
+
   r = script_->AddShader(std::move(shader));
   if (!r.IsSuccess())
     return r;
@@ -624,6 +663,20 @@ Result Parser::ParsePipelineBody(const std::string& cmd_name,
       r = ParsePipelinePatchControlPoints(pipeline.get());
     } else if (tok == "BLEND") {
       r = ParsePipelineBlend(pipeline.get());
+    } else if (tok == "SHADER_GROUP") {
+      r = ParsePipelineShaderGroup(pipeline.get());
+    } else if (tok == "SHADER_BINDING_TABLE") {
+      r = ParseSBT(pipeline.get());
+    } else if (tok == "MAX_RAY_PAYLOAD_SIZE") {
+      r = ParseMaxRayPayloadSize(pipeline.get());
+    } else if (tok == "MAX_RAY_HIT_ATTRIBUTE_SIZE") {
+      r = ParseMaxRayHitAttributeSize(pipeline.get());
+    } else if (tok == "MAX_RAY_RECURSION_DEPTH") {
+      r = ParseMaxRayRecursionDepth(pipeline.get());
+    } else if (tok == "FLAGS") {
+      r = ParseFlags(pipeline.get());
+    } else if (tok == "USE_LIBRARY") {
+      r = ParseUseLibrary(pipeline.get());
     } else {
       r = Result("unknown token in pipeline block: " + tok);
     }
@@ -1075,8 +1128,8 @@ Result Parser::ParsePipelineBind(Pipeline* pipeline) {
 
   if (!token->IsIdentifier()) {
     return Result(
-        "missing BUFFER, BUFFER_ARRAY, SAMPLER, or SAMPLER_ARRAY in BIND "
-        "command");
+        "missing BUFFER, BUFFER_ARRAY, SAMPLER, SAMPLER_ARRAY, or "
+        "ACCELERATION_STRUCTURE in BIND command");
   }
 
   auto object_type = token->AsString();
@@ -1416,6 +1469,38 @@ Result Parser::ParsePipelineBind(Pipeline* pipeline) {
     } else {
       return Result("missing DESCRIPTOR_SET or KERNEL for BIND command");
     }
+  } else if (object_type == "ACCELERATION_STRUCTURE") {
+    token = tokenizer_->NextToken();
+    if (!token->IsIdentifier())
+      return Result(
+          "missing top level acceleration structure name in BIND command");
+
+    TLAS* tlas = script_->GetTLAS(token->AsString());
+    if (!tlas)
+      return Result("unknown top level acceleration structure: " +
+                    token->AsString());
+
+    token = tokenizer_->NextToken();
+    if (token->AsString() == "DESCRIPTOR_SET") {
+      token = tokenizer_->NextToken();
+      if (!token->IsInteger())
+        return Result("invalid value for DESCRIPTOR_SET in BIND command");
+      uint32_t descriptor_set = token->AsUint32();
+
+      token = tokenizer_->NextToken();
+      if (!token->IsIdentifier() || token->AsString() != "BINDING")
+        return Result("missing BINDING for BIND command");
+
+      token = tokenizer_->NextToken();
+      if (!token->IsInteger())
+        return Result("invalid value for BINDING in BIND command");
+
+      uint32_t binding = token->AsUint32();
+
+      pipeline->AddTLAS(tlas, descriptor_set, binding);
+    } else {
+      return Result("missing DESCRIPTOR_SET or BINDING in BIND command");
+    }
   } else {
     return Result("missing BUFFER or SAMPLER in BIND command");
   }
@@ -1955,6 +2040,80 @@ Result Parser::ParsePipelineBlend(Pipeline* pipeline) {
   return ValidateEndOfStatement("BLEND command");
 }
 
+Result Parser::ParsePipelineShaderGroup(Pipeline* pipeline) {
+  std::unique_ptr<Token> token = tokenizer_->NextToken();
+  if (!token->IsIdentifier())
+    return Result("Group name expected");
+
+  auto tok = token->AsString();
+  if (pipeline->GetShaderGroup(tok))
+    return Result("Group name already exists");
+  std::unique_ptr<ShaderGroup> group = MakeUnique<ShaderGroup>();
+  group->SetName(tok);
+
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOL() || token->IsEOS())
+      break;
+    if (!token->IsIdentifier())
+      return Result("Shader name expected");
+
+    tok = token->AsString();
+    Shader* shader = script_->GetShader(tok);
+    if (shader == nullptr)
+      return Result("Shader not found: " + tok);
+
+    if (script_->FindShader(pipeline, shader) == nullptr) {
+      Result r = pipeline->AddShader(shader, shader->GetType());
+      if (!r.IsSuccess())
+        return r;
+    }
+
+    switch (shader->GetType()) {
+      case kShaderTypeRayGeneration:
+      case kShaderTypeMiss:
+      case kShaderTypeCall: {
+        if (group->IsHitGroup())
+          return Result("Hit group cannot contain general shaders");
+        if (group->GetGeneralShader() != nullptr)
+          return Result("Two general shaders cannot be in one group");
+        group->SetGeneralShader(shader);
+        break;
+      }
+      case kShaderTypeAnyHit: {
+        if (group->IsGeneralGroup())
+          return Result("General group cannot contain any hit shaders");
+        if (group->GetAnyHitShader() != nullptr)
+          return Result("Two any hit shaders cannot be in one group");
+        group->SetAnyHitShader(shader);
+        break;
+      }
+      case kShaderTypeClosestHit: {
+        if (group->IsGeneralGroup())
+          return Result("General group cannot contain closest hit shaders");
+        if (group->GetClosestHitShader() != nullptr)
+          return Result("Two closest hit shaders cannot be in one group");
+        group->SetClosestHitShader(shader);
+        break;
+      }
+      case kShaderTypeIntersection: {
+        if (group->IsGeneralGroup())
+          return Result("General group cannot contain intersection shaders");
+        if (group->GetIntersectionShader() != nullptr)
+          return Result("Two intersection shaders cannot be in one group");
+        group->SetIntersectionShader(shader);
+        break;
+      }
+      default:
+        return Result("Shader must be of raytracing type");
+    }
+  }
+
+  pipeline->AddShaderGroup(std::move(group));
+
+  return {};
+}
+
 Result Parser::ParseStruct() {
   auto token = tokenizer_->NextToken();
   if (!token->IsIdentifier())
@@ -2563,6 +2722,14 @@ Result Parser::ParseBufferInitializerFile(Buffer* buffer) {
 
 Result Parser::ParseRun() {
   auto token = tokenizer_->NextToken();
+
+  // Timed execution option for this specific run.
+  bool is_timed_execution = false;
+  if (token->AsString() == "TIMED_EXECUTION") {
+    token = tokenizer_->NextToken();
+    is_timed_execution = true;
+  }
+
   if (!token->IsIdentifier())
     return Result("missing pipeline name for RUN command");
 
@@ -2572,6 +2739,74 @@ Result Parser::ParseRun() {
   if (!pipeline)
     return Result("unknown pipeline for RUN command: " + token->AsString());
 
+  if (pipeline->IsRayTracing()) {
+    auto cmd = MakeUnique<RayTracingCommand>(pipeline);
+    cmd->SetLine(line);
+    if (is_timed_execution) {
+      cmd->SetTimedExecution();
+    }
+
+    while (true) {
+      if (tokenizer_->PeekNextToken()->IsInteger())
+        break;
+
+      token = tokenizer_->NextToken();
+
+      if (token->IsEOL() || token->IsEOS())
+        return Result("Incomplete RUN command");
+
+      if (!token->IsIdentifier())
+        return Result("Shader binding table type is expected");
+
+      std::string tok = token->AsString();
+      token = tokenizer_->NextToken();
+
+      if (!token->IsIdentifier())
+        return Result("Shader binding table name expected");
+
+      std::string sbtname = token->AsString();
+      if (pipeline->GetSBT(sbtname) == nullptr)
+        return Result("Shader binding table with this name was not defined");
+
+      if (tok == "RAYGEN") {
+        if (!cmd->GetRayGenSBTName().empty())
+          return Result("RAYGEN shader binding table can specified only once");
+        cmd->SetRGenSBTName(sbtname);
+      } else if (tok == "MISS") {
+        if (!cmd->GetMissSBTName().empty())
+          return Result("MISS shader binding table can specified only once");
+        cmd->SetMissSBTName(sbtname);
+      } else if (tok == "HIT") {
+        if (!cmd->GetHitsSBTName().empty())
+          return Result("HIT shader binding table can specified only once");
+        cmd->SetHitsSBTName(sbtname);
+      } else if (tok == "CALL") {
+        if (!cmd->GetCallSBTName().empty())
+          return Result("CALL shader binding table can specified only once");
+        cmd->SetCallSBTName(sbtname);
+      } else {
+        return Result("Unknown shader binding table type");
+      }
+    }
+
+    for (int i = 0; i < 3; i++) {
+      token = tokenizer_->NextToken();
+
+      if (!token->IsInteger())
+        return Result("invalid parameter for RUN command: " +
+                      token->ToOriginalString());
+      if (i == 0)
+        cmd->SetX(token->AsUint32());
+      else if (i == 1)
+        cmd->SetY(token->AsUint32());
+      else
+        cmd->SetZ(token->AsUint32());
+    }
+
+    command_list_.push_back(std::move(cmd));
+    return ValidateEndOfStatement("RUN command");
+  }
+
   token = tokenizer_->NextToken();
   if (token->IsEOL() || token->IsEOS())
     return Result("RUN command requires parameters");
@@ -2583,6 +2818,9 @@ Result Parser::ParseRun() {
     auto cmd = MakeUnique<ComputeCommand>(pipeline);
     cmd->SetLine(line);
     cmd->SetX(token->AsUint32());
+    if (is_timed_execution) {
+      cmd->SetTimedExecution();
+    }
 
     token = tokenizer_->NextToken();
     if (!token->IsInteger()) {
@@ -2632,6 +2870,9 @@ Result Parser::ParseRun() {
         MakeUnique<DrawRectCommand>(pipeline, *pipeline->GetPipelineData());
     cmd->SetLine(line);
     cmd->EnableOrtho();
+    if (is_timed_execution) {
+      cmd->SetTimedExecution();
+    }
 
     Result r = token->ConvertToDouble();
     if (!r.IsSuccess())
@@ -2701,6 +2942,9 @@ Result Parser::ParseRun() {
     auto cmd =
         MakeUnique<DrawGridCommand>(pipeline, *pipeline->GetPipelineData());
     cmd->SetLine(line);
+    if (is_timed_execution) {
+      cmd->SetTimedExecution();
+    }
 
     Result r = token->ConvertToDouble();
     if (!r.IsSuccess())
@@ -2874,6 +3118,9 @@ Result Parser::ParseRun() {
     cmd->SetVertexCount(count);
     cmd->SetInstanceCount(instance_count);
     cmd->SetFirstInstance(start_instance);
+    if (is_timed_execution) {
+      cmd->SetTimedExecution();
+    }
 
     if (indexed)
       cmd->EnableIndexed();
@@ -3421,6 +3668,20 @@ Result Parser::ParseDeviceFeature() {
   return ValidateEndOfStatement("DEVICE_FEATURE command");
 }
 
+Result Parser::ParseDeviceProperty() {
+  auto token = tokenizer_->NextToken();
+  if (token->IsEOS() || token->IsEOL())
+    return Result("missing property name for DEVICE_PROPERTY command");
+  if (!token->IsIdentifier())
+    return Result("invalid property name for DEVICE_PROPERTY command");
+  if (!script_->IsKnownProperty(token->AsString()))
+    return Result("unknown property name for DEVICE_PROPERTY command");
+
+  script_->AddRequiredProperty(token->AsString());
+
+  return ValidateEndOfStatement("DEVICE_PROPERTY command");
+}
+
 Result Parser::ParseRepeat() {
   auto token = tokenizer_->NextToken();
   if (token->IsEOL() || token->IsEOL())
@@ -3712,6 +3973,625 @@ Result Parser::ParseSampler() {
   return script_->AddSampler(std::move(sampler));
 }
 
+bool Parser::IsRayTracingShader(ShaderType type) {
+  return type == kShaderTypeRayGeneration || type == kShaderTypeAnyHit ||
+         type == kShaderTypeClosestHit || type == kShaderTypeMiss ||
+         type == kShaderTypeIntersection || type == kShaderTypeCall;
+}
+
+Result Parser::ParseAS() {
+  auto token = tokenizer_->NextToken();
+  if (!token->IsIdentifier())
+    return Result("Acceleration structure requires TOP_LEVEL or BOTTOM_LEVEL");
+
+  Result r;
+  auto type = token->AsString();
+  if (type == "BOTTOM_LEVEL")
+    r = ParseBLAS();
+  else if (type == "TOP_LEVEL")
+    r = ParseTLAS();
+  else
+    return Result("Unexpected acceleration structure type");
+
+  return r;
+}
+
+Result Parser::ParseBLAS() {
+  auto token = tokenizer_->NextToken();
+  if (!token->IsIdentifier())
+    return Result("Bottom level acceleration structure requires a name");
+
+  auto name = token->AsString();
+  if (script_->GetBLAS(name) != nullptr)
+    return Result(
+        "Bottom level acceleration structure with this name already defined");
+
+  std::unique_ptr<BLAS> blas = MakeUnique<BLAS>();
+  blas->SetName(name);
+
+  token = tokenizer_->NextToken();
+  if (!token->IsEOL())
+    return Result("New line expected");
+
+  Result r;
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOL()) {
+      continue;
+    }
+    if (token->IsEOS()) {
+      return Result("END command missing");
+    }
+    if (!token->IsIdentifier()) {
+      return Result("Identifier expected");
+    }
+
+    auto geom = token->AsString();
+    if (geom == "END") {
+      break;
+    } else if (geom == "GEOMETRY") {
+      token = tokenizer_->NextToken();
+      if (!token->IsIdentifier()) {
+        return Result("Identifier expected");
+      }
+
+      auto type = token->AsString();
+      if (type == "TRIANGLES") {
+        r = ParseBLASTriangle(blas.get());
+      } else if (type == "AABBS") {
+        r = ParseBLASAABB(blas.get());
+      } else {
+        return Result("Unexpected geometry type");
+      }
+    } else {
+      return Result("Unexpected identifier");
+    }
+
+    if (!r.IsSuccess()) {
+      return r;
+    }
+  }
+
+  if (blas->GetGeometrySize() > 0) {
+    auto type = blas->GetGeometries()[0]->GetType();
+    auto& geometries = blas->GetGeometries();
+    for (auto& g : geometries)
+      if (g->GetType() != type)
+        return Result("Only one type of geometry is allowed within a BLAS");
+  }
+
+  return script_->AddBLAS(std::move(blas));
+}
+
+Result Parser::ParseBLASTriangle(BLAS* blas) {
+  std::unique_ptr<Geometry> geometry = MakeUnique<Geometry>();
+  std::vector<float> g;
+  uint32_t flags = 0;
+  geometry->SetType(GeometryType::kTriangle);
+
+  while (true) {
+    auto token = tokenizer_->NextToken();
+
+    if (token->IsEOS())
+      return Result("END expected");
+    if (token->IsEOL())
+      continue;
+
+    if (token->IsIdentifier()) {
+      std::string tok = token->AsString();
+      if (tok == "END") {
+        break;
+      } else if (tok == "FLAGS") {
+        Result r = ParseGeometryFlags(&flags);
+        if (!r.IsSuccess())
+          return r;
+      } else {
+        return Result("END or float value is expected");
+      }
+    } else if (token->IsInteger() || token->IsDouble()) {
+      g.push_back(token->AsFloat());
+    } else {
+      return Result("Unexpected data type");
+    }
+  }
+
+  if (g.empty())
+    return Result("No triangles have been specified.");
+
+  if (g.size() % 3 != 0)
+    return Result("Each vertex consists of three float coordinates.");
+
+  if ((g.size() / 3) % 3 != 0)
+    return Result("Each triangle should include three vertices.");
+
+  geometry->SetData(g);
+  geometry->SetFlags(flags);
+
+  blas->AddGeometry(&geometry);
+
+  return {};
+}
+
+Result Parser::ParseBLASAABB(BLAS* blas) {
+  std::unique_ptr<Geometry> geometry = MakeUnique<Geometry>();
+  std::vector<float> g;
+  uint32_t flags = 0;
+  geometry->SetType(GeometryType::kAABB);
+
+  while (true) {
+    auto token = tokenizer_->NextToken();
+
+    if (token->IsEOS())
+      return Result("END expected");
+    if (token->IsEOL())
+      continue;
+
+    if (token->IsIdentifier()) {
+      std::string tok = token->AsString();
+      if (tok == "END") {
+        break;
+      } else if (tok == "FLAGS") {
+        Result r = ParseGeometryFlags(&flags);
+        if (!r.IsSuccess())
+          return r;
+      } else {
+        return Result("END or float value is expected");
+      }
+    } else if (token->IsDouble()) {
+      g.push_back(token->AsFloat());
+    } else if (token->IsInteger()) {
+      g.push_back(static_cast<float>(token->AsInt64()));
+    } else {
+      return Result("Unexpected data type");
+    }
+  }
+
+  if (g.empty())
+    return Result("No AABBs have been specified.");
+
+  if ((g.size() % 6) != 0)
+    return Result(
+        "Each vertex consists of three float coordinates. Each AABB should "
+        "include two vertices.");
+
+  geometry->SetData(g);
+  geometry->SetFlags(flags);
+
+  blas->AddGeometry(&geometry);
+
+  return {};
+}
+
+Result Parser::ParseGeometryFlags(uint32_t* flags) {
+  std::unique_ptr<Token> token;
+  bool first_eol = true;
+  bool singleline = true;
+  Result r;
+
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOL()) {
+      if (first_eol) {
+        first_eol = false;
+        singleline = (*flags != 0);
+      }
+      if (singleline)
+        break;
+      else
+        continue;
+    }
+    if (token->IsEOS())
+      return Result("END command missing");
+
+    if (token->IsIdentifier()) {
+      if (token->AsString() == "END")
+        break;
+      else if (token->AsString() == "OPAQUE")
+        *flags |= VK_GEOMETRY_OPAQUE_BIT_KHR;
+      else if (token->AsString() == "NO_DUPLICATE_ANY_HIT")
+        *flags |= VK_GEOMETRY_NO_DUPLICATE_ANY_HIT_INVOCATION_BIT_KHR;
+      else
+        return Result("Unknown flag: " + token->AsString());
+    } else {
+      r = Result("Identifier expected");
+    }
+
+    if (!r.IsSuccess())
+      return r;
+  }
+
+  return {};
+}
+
+Result Parser::ParseTLAS() {
+  auto token = tokenizer_->NextToken();
+  if (!token->IsIdentifier())
+    return Result("invalid TLAS name provided");
+
+  auto name = token->AsString();
+
+  token = tokenizer_->NextToken();
+  if (!token->IsEOL())
+    return Result("New line expected");
+
+  std::unique_ptr<TLAS> tlas = MakeUnique<TLAS>();
+
+  tlas->SetName(name);
+
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOL())
+      continue;
+    if (token->IsEOS())
+      return Result("END command missing");
+    if (!token->IsIdentifier())
+      return Result("expected identifier");
+
+    Result r;
+    std::string tok = token->AsString();
+    if (tok == "END")
+      break;
+    if (tok == "BOTTOM_LEVEL_INSTANCE")
+      r = ParseBLASInstance(tlas.get());
+    else
+      r = Result("unknown token: " + tok);
+
+    if (!r.IsSuccess())
+      return r;
+  }
+
+  Result r = script_->AddTLAS(std::move(tlas));
+  if (!r.IsSuccess())
+    return r;
+
+  return {};
+}
+
+// BOTTOM_LEVEL_INSTANCE <blas_name> [MASK 0-255] [OFFSET 0-16777215] [INDEX
+// 0-16777215] [FLAGS {flags}] [TRANSFORM {float x 12} END]
+Result Parser::ParseBLASInstance(TLAS* tlas) {
+  std::unique_ptr<Token> token;
+  std::unique_ptr<BLASInstance> instance = MakeUnique<BLASInstance>();
+
+  token = tokenizer_->NextToken();
+
+  if (!token->IsIdentifier())
+    return Result("Bottom level acceleration structure name expected");
+
+  std::string name = token->AsString();
+  auto ptr = script_->GetBLAS(name);
+
+  if (!ptr)
+    return Result(
+        "Bottom level acceleration structure with given name not found");
+
+  instance->SetUsedBLAS(name, ptr);
+
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOS())
+      return Result("Unexpected end");
+    if (token->IsEOL())
+      continue;
+
+    if (!token->IsIdentifier())
+      return Result("expected identifier");
+
+    Result r;
+    std::string tok = token->AsString();
+    if (tok == "END") {
+      break;
+    } else if (tok == "TRANSFORM") {
+      r = ParseBLASInstanceTransform(instance.get());
+    } else if (tok == "FLAGS") {
+      r = ParseBLASInstanceFlags(instance.get());
+    } else if (tok == "MASK") {
+      token = tokenizer_->NextToken();
+      uint64_t v;
+
+      if (token->IsInteger())
+        v = token->AsUint64();
+      else if (token->IsHex())
+        v = token->AsHex();
+      else
+        return Result("Integer or hex value expected");
+
+      instance->SetMask(uint32_t(v));
+    } else if (tok == "OFFSET") {
+      token = tokenizer_->NextToken();
+      uint64_t v;
+
+      if (token->IsInteger())
+        v = token->AsUint64();
+      else if (token->IsHex())
+        v = token->AsHex();
+      else
+        return Result("Integer or hex value expected");
+
+      instance->SetOffset(uint32_t(v));
+    } else if (tok == "INDEX") {
+      token = tokenizer_->NextToken();
+      uint64_t v;
+
+      if (token->IsInteger())
+        v = token->AsUint64();
+      else if (token->IsHex())
+        v = token->AsHex();
+      else
+        return Result("Integer or hex value expected");
+
+      instance->SetInstanceIndex(uint32_t(v));
+    } else {
+      r = Result("Unknown token in BOTTOM_LEVEL_INSTANCE block: " + tok);
+    }
+
+    if (!r.IsSuccess())
+      return r;
+  }
+
+  tlas->AddInstance(std::move(instance));
+
+  return {};
+}
+
+Result Parser::ParseBLASInstanceTransform(BLASInstance* instance) {
+  std::unique_ptr<Token> token;
+  std::vector<float> transform;
+
+  transform.reserve(12);
+
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOL())
+      continue;
+    if (token->IsEOS())
+      return Result("END command missing");
+
+    if (token->IsIdentifier() && token->AsString() == "END")
+      break;
+    else if (token->IsDouble() || token->IsInteger())
+      transform.push_back(token->AsFloat());
+    else
+      return Result("Unknown token: " + token->AsString());
+  }
+
+  if (transform.size() != 12)
+    return Result("Transform matrix expected to have 12 numbers");
+
+  instance->SetTransform(transform);
+
+  return {};
+}
+
+Result Parser::ParseBLASInstanceFlags(BLASInstance* instance) {
+  std::unique_ptr<Token> token;
+  uint32_t flags = 0;
+  bool first_eol = true;
+  bool singleline = true;
+  Result r;
+
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOL()) {
+      if (first_eol) {
+        first_eol = false;
+        singleline = (flags != 0);
+      }
+      if (singleline)
+        break;
+      else
+        continue;
+    }
+    if (token->IsEOS())
+      return Result("END command missing");
+
+    if (token->IsInteger()) {
+      flags |= token->AsUint32();
+    } else if (token->IsHex()) {
+      flags |= uint32_t(token->AsHex());
+    } else if (token->IsIdentifier()) {
+      if (token->AsString() == "END")
+        break;
+      else if (token->AsString() == "TRIANGLE_FACING_CULL_DISABLE")
+        flags |= VK_GEOMETRY_INSTANCE_TRIANGLE_FACING_CULL_DISABLE_BIT_KHR;
+      else if (token->AsString() == "TRIANGLE_FLIP_FACING")
+        flags |= VK_GEOMETRY_INSTANCE_TRIANGLE_FLIP_FACING_BIT_KHR;
+      else if (token->AsString() == "FORCE_OPAQUE")
+        flags |= VK_GEOMETRY_INSTANCE_FORCE_OPAQUE_BIT_KHR;
+      else if (token->AsString() == "FORCE_NO_OPAQUE")
+        flags |= VK_GEOMETRY_INSTANCE_FORCE_NO_OPAQUE_BIT_KHR;
+      else if (token->AsString() == "FORCE_OPACITY_MICROMAP_2_STATE")
+        flags |= VK_GEOMETRY_INSTANCE_FORCE_OPACITY_MICROMAP_2_STATE_EXT;
+      else if (token->AsString() == "DISABLE_OPACITY_MICROMAPS")
+        flags |= VK_GEOMETRY_INSTANCE_DISABLE_OPACITY_MICROMAPS_EXT;
+      else
+        return Result("Unknown flag: " + token->AsString());
+    } else {
+      r = Result("Identifier expected");
+    }
+
+    if (!r.IsSuccess())
+      return r;
+  }
+
+  if (r.IsSuccess())
+    instance->SetFlags(flags);
+
+  return {};
+}
+
+Result Parser::ParseSBT(Pipeline* pipeline) {
+  auto token = tokenizer_->NextToken();
+  if (!token->IsIdentifier())
+    return Result("SHADER_BINDINGS_TABLE requires a name");
+
+  auto name = token->AsString();
+  if (pipeline->GetSBT(name) != nullptr)
+    return Result("SHADER_BINDINGS_TABLE with this name already defined");
+
+  std::unique_ptr<SBT> sbt = MakeUnique<SBT>();
+  sbt->SetName(name);
+
+  token = tokenizer_->NextToken();
+  if (!token->IsEOL())
+    return Result("New line expected");
+
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOL()) {
+      continue;
+    }
+    if (token->IsEOS()) {
+      return Result("END command missing");
+    }
+    if (!token->IsIdentifier()) {
+      return Result("Identifier expected");
+    }
+
+    auto tok = token->AsString();
+    if (tok == "END") {
+      break;
+    }
+
+    uint32_t index = 0;
+    ShaderGroup* shader_group = script_->FindShaderGroup(pipeline, tok, &index);
+
+    if (shader_group == nullptr)
+      return Result(
+          "Shader group not found neither in pipeline, nor in libraries");
+
+    std::unique_ptr<SBTRecord> sbtrecord = MakeUnique<SBTRecord>();
+
+    sbtrecord->SetUsedShaderGroupName(tok);
+    sbtrecord->SetIndex(index);
+    sbtrecord->SetCount(1);
+
+    sbt->AddSBTRecord(std::move(sbtrecord));
+  }
+
+  return pipeline->AddSBT(std::move(sbt));
+}
+
+Result Parser::ParseMaxRayPayloadSize(Pipeline* pipeline) {
+  if (!pipeline->IsRayTracing())
+    return Result(
+        "Ray payload size parameter is allowed only for ray tracing pipeline");
+
+  auto token = tokenizer_->NextToken();
+  if (!token->IsInteger())
+    return Result("Ray payload size expects an integer");
+
+  pipeline->SetMaxPipelineRayPayloadSize(token->AsUint32());
+
+  return {};
+}
+
+Result Parser::ParseMaxRayHitAttributeSize(Pipeline* pipeline) {
+  if (!pipeline->IsRayTracing())
+    return Result(
+        "Ray hit attribute size is allowed only for ray tracing pipeline");
+
+  auto token = tokenizer_->NextToken();
+  if (!token->IsInteger())
+    return Result("Ray hit attribute size expects an integer");
+
+  pipeline->SetMaxPipelineRayHitAttributeSize(token->AsUint32());
+
+  return {};
+}
+
+Result Parser::ParseMaxRayRecursionDepth(Pipeline* pipeline) {
+  if (!pipeline->IsRayTracing())
+    return Result(
+        "Ray recursion depth is allowed only for ray tracing pipeline");
+
+  auto token = tokenizer_->NextToken();
+  if (!token->IsInteger())
+    return Result("Ray recursion depth expects an integer");
+
+  pipeline->SetMaxPipelineRayRecursionDepth(token->AsUint32());
+
+  return {};
+}
+
+Result Parser::ParseFlags(Pipeline* pipeline) {
+  if (!pipeline->IsRayTracing())
+    return Result("Flags are allowed only for ray tracing pipeline");
+
+  std::unique_ptr<Token> token;
+  uint32_t flags = pipeline->GetCreateFlags();
+  bool first_eol = true;
+  bool singleline = true;
+  Result r;
+
+  while (true) {
+    token = tokenizer_->NextToken();
+    if (token->IsEOL()) {
+      if (first_eol) {
+        first_eol = false;
+        singleline = (flags != 0);
+      }
+      if (singleline)
+        break;
+      else
+        continue;
+    }
+    if (token->IsEOS())
+      return Result("END command missing");
+
+    if (token->IsInteger()) {
+      flags |= token->AsUint32();
+    } else if (token->IsHex()) {
+      flags |= uint32_t(token->AsHex());
+    } else if (token->IsIdentifier()) {
+      if (token->AsString() == "END")
+        break;
+      else if (token->AsString() == "LIBRARY")
+        flags |= VK_PIPELINE_CREATE_LIBRARY_BIT_KHR;
+      else
+        return Result("Unknown flag: " + token->AsString());
+    } else {
+      r = Result("Identifier expected");
+    }
+
+    if (!r.IsSuccess())
+      return r;
+  }
+
+  if (r.IsSuccess())
+    pipeline->SetCreateFlags(flags);
+
+  return {};
+}
+
+Result Parser::ParseUseLibrary(Pipeline* pipeline) {
+  if (!pipeline->IsRayTracing())
+    return Result("Use library is allowed only for ray tracing pipeline");
+
+  while (true) {
+    auto token = tokenizer_->NextToken();
+
+    if (token->IsEOS())
+      return Result("EOL expected");
+    if (token->IsEOL())
+      break;
+
+    if (token->IsIdentifier()) {
+      std::string tok = token->AsString();
+
+      Pipeline* use_pipeline = script_->GetPipeline(tok);
+      if (!use_pipeline)
+        return Result("Pipeline not found: " + tok);
+
+      pipeline->AddPipelineLibrary(use_pipeline);
+    } else {
+      return Result("Unexpected data type");
+    }
+  }
+
+  return {};
+}
+
 Result Parser::ParseTolerances(std::vector<Probe::Tolerance>* tolerances) {
   auto token = tokenizer_->PeekNextToken();
   while (!token->IsEOL() && !token->IsEOS()) {
diff --git a/src/amberscript/parser.h b/src/amberscript/parser.h
index fb81c82..83c8c99 100644
--- a/src/amberscript/parser.h
+++ b/src/amberscript/parser.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -75,6 +76,7 @@ class Parser : public amber::Parser {
   Result ParsePipelineDepth(Pipeline* pipeline);
   Result ParsePipelineStencil(Pipeline* pipeline);
   Result ParsePipelineBlend(Pipeline* pipeline);
+  Result ParsePipelineShaderGroup(Pipeline* pipeline);
   Result ParseRun();
   Result ParseClear();
   Result ParseClearColor();
@@ -84,6 +86,7 @@ class Parser : public amber::Parser {
   Result ParseCopy();
   Result ParseDeviceFeature();
   Result ParseDeviceExtension();
+  Result ParseDeviceProperty();
   Result ParseInstanceExtension();
   Result ParseRepeat();
   Result ParseSet();
@@ -94,6 +97,22 @@ class Parser : public amber::Parser {
                            std::unique_ptr<Pipeline> pipeline);
   Result ParseShaderSpecialization(Pipeline* pipeline);
   Result ParseSampler();
+  bool IsRayTracingShader(ShaderType type);
+  Result ParseAS();
+  Result ParseBLAS();
+  Result ParseBLASTriangle(BLAS* blas);
+  Result ParseBLASAABB(BLAS* blas);
+  Result ParseGeometryFlags(uint32_t* flags);
+  Result ParseTLAS();
+  Result ParseBLASInstance(TLAS* tlas);
+  Result ParseBLASInstanceTransform(BLASInstance* instance);
+  Result ParseBLASInstanceFlags(BLASInstance* instance);
+  Result ParseSBT(Pipeline* pipeline);
+  Result ParseMaxRayPayloadSize(Pipeline* pipeline);
+  Result ParseMaxRayHitAttributeSize(Pipeline* pipeline);
+  Result ParseMaxRayRecursionDepth(Pipeline* pipeline);
+  Result ParseFlags(Pipeline* pipeline);
+  Result ParseUseLibrary(Pipeline* pipeline);
   Result ParseTolerances(std::vector<Probe::Tolerance>* tolerances);
 
   /// Parses a set of values out of the token stream. |name| is the name of the
diff --git a/src/amberscript/parser_buffer_test.cc b/src/amberscript/parser_buffer_test.cc
index aeac2cb..ab4824a 100644
--- a/src/amberscript/parser_buffer_test.cc
+++ b/src/amberscript/parser_buffer_test.cc
@@ -31,10 +31,12 @@ class DummyDelegate : public amber::Delegate {
   bool LogExecuteCalls() const override { return false; }
   void SetLogExecuteCalls(bool) {}
   bool LogGraphicsCallsTime() const override { return false; }
+
   void SetLogGraphicsCallsTime(bool) {}
   uint64_t GetTimestampNs() const override { return 0; }
   void SetScriptPath(std::string) {}
 
+  void ReportExecutionTiming(double) override {}
   amber::Result LoadBufferData(const std::string,
                                amber::BufferDataFileType type,
                                amber::BufferInfo* buffer) const override {
@@ -46,6 +48,10 @@ class DummyDelegate : public amber::Delegate {
 
     return {};
   }
+
+  amber::Result LoadFile(const std::string, std::vector<char>*) const override {
+    return Result("DummyDelegate::LoadFile not implemented");
+  }
 };
 
 TEST_F(AmberScriptParserTest, BufferData) {
diff --git a/src/amberscript/parser_device_property_test.cc b/src/amberscript/parser_device_property_test.cc
new file mode 100644
index 0000000..f42fafe
--- /dev/null
+++ b/src/amberscript/parser_device_property_test.cc
@@ -0,0 +1,120 @@
+// Copyright 2024 The Amber Authors.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or parseried.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "gtest/gtest.h"
+#include "src/amberscript/parser.h"
+
+namespace amber {
+namespace amberscript {
+
+using AmberScriptParserTest = testing::Test;
+
+TEST_F(AmberScriptParserTest, DeviceProperty) {
+  std::string in = R"(
+DEVICE_PROPERTY FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat16
+DEVICE_PROPERTY FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat32
+DEVICE_PROPERTY FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat64
+DEVICE_PROPERTY FloatControlsProperties.shaderDenormPreserveFloat16
+DEVICE_PROPERTY FloatControlsProperties.shaderDenormPreserveFloat32
+DEVICE_PROPERTY FloatControlsProperties.shaderDenormPreserveFloat64
+DEVICE_PROPERTY FloatControlsProperties.shaderDenormFlushToZeroFloat16
+DEVICE_PROPERTY FloatControlsProperties.shaderDenormFlushToZeroFloat32
+DEVICE_PROPERTY FloatControlsProperties.shaderDenormFlushToZeroFloat64
+DEVICE_PROPERTY FloatControlsProperties.shaderRoundingModeRTEFloat16
+DEVICE_PROPERTY FloatControlsProperties.shaderRoundingModeRTEFloat32
+DEVICE_PROPERTY FloatControlsProperties.shaderRoundingModeRTEFloat64
+DEVICE_PROPERTY FloatControlsProperties.shaderRoundingModeRTZFloat16
+DEVICE_PROPERTY FloatControlsProperties.shaderRoundingModeRTZFloat32
+DEVICE_PROPERTY FloatControlsProperties.shaderRoundingModeRTZFloat64)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess()) << r.Error();
+
+  auto script = parser.GetScript();
+  const auto& properties = script->GetRequiredProperties();
+  ASSERT_EQ(15U, properties.size());
+  EXPECT_EQ("FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat16",
+            properties[0]);
+  EXPECT_EQ("FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat32",
+            properties[1]);
+  EXPECT_EQ("FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat64",
+            properties[2]);
+  EXPECT_EQ("FloatControlsProperties.shaderDenormPreserveFloat16",
+            properties[3]);
+  EXPECT_EQ("FloatControlsProperties.shaderDenormPreserveFloat32",
+            properties[4]);
+  EXPECT_EQ("FloatControlsProperties.shaderDenormPreserveFloat64",
+            properties[5]);
+  EXPECT_EQ("FloatControlsProperties.shaderDenormFlushToZeroFloat16",
+            properties[6]);
+  EXPECT_EQ("FloatControlsProperties.shaderDenormFlushToZeroFloat32",
+            properties[7]);
+  EXPECT_EQ("FloatControlsProperties.shaderDenormFlushToZeroFloat64",
+            properties[8]);
+  EXPECT_EQ("FloatControlsProperties.shaderRoundingModeRTEFloat16",
+            properties[9]);
+  EXPECT_EQ("FloatControlsProperties.shaderRoundingModeRTEFloat32",
+            properties[10]);
+  EXPECT_EQ("FloatControlsProperties.shaderRoundingModeRTEFloat64",
+            properties[11]);
+  EXPECT_EQ("FloatControlsProperties.shaderRoundingModeRTZFloat16",
+            properties[12]);
+  EXPECT_EQ("FloatControlsProperties.shaderRoundingModeRTZFloat32",
+            properties[13]);
+  EXPECT_EQ("FloatControlsProperties.shaderRoundingModeRTZFloat64",
+            properties[14]);
+}
+
+TEST_F(AmberScriptParserTest, DevicePropertyMissingProperty) {
+  std::string in = "DEVICE_PROPERTY";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("1: missing property name for DEVICE_PROPERTY command", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, DevicePropertyUnknown) {
+  std::string in = "DEVICE_PROPERTY unknown";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("1: unknown property name for DEVICE_PROPERTY command", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, DevicePropertyInvalid) {
+  std::string in = "DEVICE_PROPERTY 12345";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("1: invalid property name for DEVICE_PROPERTY command", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, DevicePropertyExtraParams) {
+  std::string in =
+      "DEVICE_PROPERTY FloatControlsProperties.shaderDenormPreserveFloat16 "
+      "EXTRA";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("1: extra parameters after DEVICE_PROPERTY command: EXTRA",
+            r.Error());
+}
+
+}  // namespace amberscript
+}  // namespace amber
diff --git a/src/amberscript/parser_raytracing_test.cc b/src/amberscript/parser_raytracing_test.cc
new file mode 100644
index 0000000..c92dfe6
--- /dev/null
+++ b/src/amberscript/parser_raytracing_test.cc
@@ -0,0 +1,1596 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or parseried.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "gtest/gtest.h"
+#include "src/amberscript/parser.h"
+
+namespace amber {
+namespace amberscript {
+
+using AmberScriptParserTest = testing::Test;
+
+TEST_F(AmberScriptParserTest, RayTracingBlasName) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Bottom level acceleration structure requires a name",
+            r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasNameDup) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+END
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ(
+      "4: Bottom level acceleration structure with this name already defined",
+      r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasNameNoEOL) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("2: New line expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasNoEND) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: END command missing", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasNoId) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+1)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Identifier expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasUnexpId) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  UNEXPECTED)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Unexpected identifier", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasUnexpGeomId) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY 1)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Identifier expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasUnexpGeom) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY UNEXPECTED)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Unexpected geometry type", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasGeomSingleType) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY TRIANGLES
+    0 0 0  0 1 0  1 0 0
+  END
+  GEOMETRY AABBS
+    0 0 0  1 1 1
+  END
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Only one type of geometry is allowed within a BLAS", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasTriangleEmpty) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY TRIANGLES
+  END
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("4: No triangles have been specified.", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasTriangleThreeVertices) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY TRIANGLES
+    0.0 0.0 0.0  0.0 0.0 0.0
+  END
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("5: Each triangle should include three vertices.", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasTriangleThreeFloats) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY TRIANGLES
+    0.0 0.0 0.0  0.0 0.0 0.0  0.0
+  END
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("5: Each vertex consists of three float coordinates.", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasTriangleNoEND) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY TRIANGLES
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("4: END expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasTriangleUnexpDataType) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY TRIANGLES "unexpected_string"
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Unexpected data type", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasTriangleGeometryFlags) {
+  {
+    std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY TRIANGLES
+    FLAGS OPAQUE NO_DUPLICATE_ANY_HIT NO_SUCH_FLAG
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("4: Unknown flag: NO_SUCH_FLAG", r.Error());
+  }
+  {
+    std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY TRIANGLES
+    FLAGS 1
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("4: Identifier expected", r.Error());
+  }
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasAABBEmpty) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+  END
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("4: No AABBs have been specified.", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasAABBInvalidData) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  0.0 0.0 0.0  0.0
+  END
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ(
+      "5: Each vertex consists of three float coordinates. Each AABB should "
+      "include two vertices.",
+      r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasAABBNoEND) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("4: END expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasAABBUnexpDataType) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS "unexpected_string"
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Unexpected data type", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingBlasAABBGeometryFlags) {
+  {
+    std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    FLAGS OPAQUE NO_DUPLICATE_ANY_HIT NO_SUCH_FLAG
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("4: Unknown flag: NO_SUCH_FLAG", r.Error());
+  }
+  {
+    std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    FLAGS 1
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("4: Identifier expected", r.Error());
+  }
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasName) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE TOP_LEVEL
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: invalid TLAS name provided", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasNameDup) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE TOP_LEVEL tlas_name
+END
+ACCELERATION_STRUCTURE TOP_LEVEL tlas_name
+END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("5: duplicate TLAS name provided", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasNameNoEOL) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE TOP_LEVEL tlas_name END)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("2: New line expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasNoEND) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE TOP_LEVEL tlas_name
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: END command missing", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasNoId) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE TOP_LEVEL tlas_name
+1)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: expected identifier", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasUnexpId) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE TOP_LEVEL tlas_name
+  UNEXPECTED)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: unknown token: UNEXPECTED", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstNoName) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Bottom level acceleration structure name expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstNoBlas) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas1)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Bottom level acceleration structure with given name not found",
+            r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstUnexpEnd) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Unexpected end", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstExpId) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name 1)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: expected identifier", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstInvalidToken) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name TOKEN)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Unknown token in BOTTOM_LEVEL_INSTANCE block: TOKEN",
+            r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstMask) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name MASK no_mask)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Integer or hex value expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstOffset) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name OFFSET no_offset)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Integer or hex value expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstIndex) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name INDEX no_index)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Integer or hex value expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstFlagsEmpty) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name FLAGS)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: END command missing", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstFlagsUnkFlag) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name FLAGS 16 0x0F NO_SUCH_FLAG)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Unknown flag: NO_SUCH_FLAG", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstFlagsIdExp) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name FLAGS "no_id")";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Identifier expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstTransformNoEnd) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name
+    TRANSFORM
+      1 0 0 0  0 1 0 0  0 0 1 0
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("12: END command missing", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstTransformUnknownToken) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name TRANSFORM
+    INVALID_TOKEN
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("10: Unknown token: INVALID_TOKEN", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingTlasBlasInstTransformIncomplete) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name TRANSFORM
+    1 2
+  END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("11: Transform matrix expected to have 12 numbers", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBind) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name
+  END
+END
+
+PIPELINE raytracing my_rtpipeline
+  BIND 0 tlas1 DESCRIPTOR_SET 0 BINDING 0
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ(
+      "14: missing BUFFER, BUFFER_ARRAY, SAMPLER, SAMPLER_ARRAY, or "
+      "ACCELERATION_STRUCTURE in BIND command",
+      r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindNothing) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name
+  END
+END
+
+PIPELINE raytracing my_rtpipeline
+  BIND ACCELERATION_STRUCTURE 0
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: missing top level acceleration structure name in BIND command",
+            r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindNoTlas) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name
+  END
+END
+
+PIPELINE raytracing my_rtpipeline
+  BIND ACCELERATION_STRUCTURE no_tlas
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: unknown top level acceleration structure: no_tlas", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindNoSetOrBinding) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name
+  END
+END
+
+PIPELINE raytracing my_rtpipeline
+  BIND ACCELERATION_STRUCTURE tlas1 NO_TOKEN
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: missing DESCRIPTOR_SET or BINDING in BIND command", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindBadSet) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name
+  END
+END
+
+PIPELINE raytracing my_rtpipeline
+  BIND ACCELERATION_STRUCTURE tlas1 DESCRIPTOR_SET 0.0
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: invalid value for DESCRIPTOR_SET in BIND command", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindBadBindingKeyword) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name
+  END
+END
+
+PIPELINE raytracing my_rtpipeline
+  BIND ACCELERATION_STRUCTURE tlas1 DESCRIPTOR_SET 0 NOT_BINDING
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: missing BINDING for BIND command", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindBadBindingValue) {
+  std::string in = R"(
+ACCELERATION_STRUCTURE BOTTOM_LEVEL blas_name
+  GEOMETRY AABBS
+    0.0 0.0 0.0  1.0 1.0 1.0
+  END
+END
+
+ACCELERATION_STRUCTURE TOP_LEVEL tlas1
+  BOTTOM_LEVEL_INSTANCE blas_name
+  END
+END
+
+PIPELINE raytracing my_rtpipeline
+  BIND ACCELERATION_STRUCTURE tlas1 DESCRIPTOR_SET 0 BINDING 0.0
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: invalid value for BINDING in BIND command", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupNoName) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP 1
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Group name expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupNoNameDup) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP group raygen1
+  SHADER_GROUP group raygen1
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("9: Group name already exists", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupEmpty) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP group
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupNoShaderName) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP group 1
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Shader name expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupNoShader) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP group no_shader
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: Shader not found: no_shader", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupInvalidShader) {
+  std::string in = R"(
+SHADER vertex vertex1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP group vertex1
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("8: Shader must be of raytracing type", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupTwoGeneral) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+SHADER ray_generation raygen2 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP group raygen1 raygen2
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("13: Two general shaders cannot be in one group", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupAddGenToHit) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+SHADER intersection intersection1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP hit_group intersection1 raygen1
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("13: Hit group cannot contain general shaders", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupAddAHitToGen) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+SHADER any_hit ahit1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP gen_group raygen1 ahit1
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("13: General group cannot contain any hit shaders", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupAddCHitToGen) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+SHADER closest_hit chit1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP gen_group raygen1 chit1
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("13: General group cannot contain closest hit shaders", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupAddSectToGen) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+SHADER intersection sect1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP gen_group raygen1 sect1
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("13: General group cannot contain intersection shaders", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupAHitDouble) {
+  std::string in = R"(
+SHADER any_hit ahit1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+SHADER any_hit ahit2 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP gen_group ahit1 ahit2
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("13: Two any hit shaders cannot be in one group", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupCHitDouble) {
+  std::string in = R"(
+SHADER closest_hit chit1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+SHADER closest_hit chit2 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP gen_group chit1 chit2
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("13: Two closest hit shaders cannot be in one group", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineBindShaderGroupSectDouble) {
+  std::string in = R"(
+SHADER intersection sect1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+SHADER intersection sect2 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP gen_group sect1 sect2
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("13: Two intersection shaders cannot be in one group", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineSBTNoName) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+  SHADER_BINDING_TABLE
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("4: SHADER_BINDINGS_TABLE requires a name", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineSBTDup) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP gen_group raygen1
+  SHADER_BINDING_TABLE sbt1
+  END
+  SHADER_BINDING_TABLE sbt1
+  END
+END
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("11: SHADER_BINDINGS_TABLE with this name already defined",
+            r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineSBTExtraToken) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+  SHADER_BINDING_TABLE sbt1 extra_token
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("3: New line expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineSBTNoEnd) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+  SHADER_BINDING_TABLE sbt1
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("4: END command missing", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineSBTNoId) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+  SHADER_BINDING_TABLE sbt1
+    0
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("4: Identifier expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRun) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 raygen1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline RAYGEN sbt1 1 1 z
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: invalid parameter for RUN command: z", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRunIncomplete) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 raygen1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("15: Incomplete RUN command", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRunExpectsSBTType) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 raygen1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline 0.0
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: Shader binding table type is expected", r.Error());
+}
+
+
+TEST_F(AmberScriptParserTest, RayTracingRunExpectsSBTName) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 raygen1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline RAYGEN 0.0
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: Shader binding table name expected", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRunExpectsSBTUndefined) {
+  std::string in = R"(
+PIPELINE raytracing my_rtpipeline
+END
+RUN my_rtpipeline RAYGEN sbt3
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("4: Shader binding table with this name was not defined",
+            r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRunExpectsSBTUnknownType) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 raygen1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline RAYGEN2 sbt1
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: Unknown shader binding table type", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRunSBTRGenDup) {
+  std::string in = R"(
+SHADER ray_generation raygen1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 raygen1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline RAYGEN sbt1 RAYGEN sbt1
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: RAYGEN shader binding table can specified only once",
+            r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRunSBTMissDup) {
+  std::string in = R"(
+SHADER miss miss1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 miss1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline MISS sbt1 MISS sbt1
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: MISS shader binding table can specified only once",
+            r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRunSBTHitDup) {
+  std::string in = R"(
+SHADER any_hit ahit1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 ahit1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline HIT sbt1 HIT sbt1
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: HIT shader binding table can specified only once", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingRunSBTCallDup) {
+  std::string in = R"(
+SHADER callable call1 GLSL
+  #version 460 core
+  void main() {}
+END
+
+PIPELINE raytracing my_rtpipeline
+  SHADER_GROUP g1 call1
+  SHADER_BINDING_TABLE sbt1
+    g1
+  END
+END
+
+RUN my_rtpipeline CALL sbt1 CALL sbt1
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_FALSE(r.IsSuccess());
+  EXPECT_EQ("14: CALL shader binding table can specified only once", r.Error());
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineMaxRaypayloadSize) {
+  {
+    std::string in = R"(
+PIPELINE compute my_pipeline
+  MAX_RAY_PAYLOAD_SIZE 16
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ(
+        "3: Ray payload size parameter is allowed only for ray tracing "
+        "pipeline",
+        r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE graphics my_pipeline
+  MAX_RAY_PAYLOAD_SIZE 16
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ(
+        "3: Ray payload size parameter is allowed only for ray tracing "
+        "pipeline",
+        r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  MAX_RAY_PAYLOAD_SIZE a
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Ray payload size expects an integer", r.Error());
+  }
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineMaxRayHitAttributeSize) {
+  {
+    std::string in = R"(
+PIPELINE compute my_pipeline
+  MAX_RAY_HIT_ATTRIBUTE_SIZE 16
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ(
+        "3: Ray hit attribute size is allowed only for ray tracing pipeline",
+        r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE graphics my_pipeline
+  MAX_RAY_HIT_ATTRIBUTE_SIZE 16
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ(
+        "3: Ray hit attribute size is allowed only for ray tracing pipeline",
+        r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  MAX_RAY_HIT_ATTRIBUTE_SIZE a
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Ray hit attribute size expects an integer", r.Error());
+  }
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineMaxRecursionDepthSize) {
+  {
+    std::string in = R"(
+PIPELINE compute my_pipeline
+  MAX_RAY_RECURSION_DEPTH 1
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Ray recursion depth is allowed only for ray tracing pipeline",
+              r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE graphics my_pipeline
+  MAX_RAY_RECURSION_DEPTH 1
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Ray recursion depth is allowed only for ray tracing pipeline",
+              r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  MAX_RAY_RECURSION_DEPTH a
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Ray recursion depth expects an integer", r.Error());
+  }
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineFlags) {
+  {
+    std::string in = R"(
+PIPELINE compute my_pipeline
+  FLAGS LIBRARY
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Flags are allowed only for ray tracing pipeline", r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE graphics my_pipeline
+  FLAGS LIBRARY
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Flags are allowed only for ray tracing pipeline", r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  FLAGS
+    LIBRARY
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("5: END command missing", r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  FLAGS UNKNOWN_FLAG
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Unknown flag: UNKNOWN_FLAG", r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  FLAGS 1.0
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Identifier expected", r.Error());
+  }
+}
+
+TEST_F(AmberScriptParserTest, RayTracingPipelineUseLibrary) {
+  {
+    std::string in = R"(
+PIPELINE raytracing base_pipeline_lib
+  FLAGS LIBRARY
+END
+
+PIPELINE compute my_pipeline
+  USE_LIBRARY base_pipeline_lib
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("7: Use library is allowed only for ray tracing pipeline",
+              r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing base_pipeline_lib
+  FLAGS LIBRARY
+END
+
+PIPELINE graphics my_pipeline
+  USE_LIBRARY base_pipeline_lib
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("7: Use library is allowed only for ray tracing pipeline",
+              r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  USE_LIBRARY base_pipeline_lib
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Pipeline not found: base_pipeline_lib", r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  USE_LIBRARY)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: EOL expected", r.Error());
+  }
+  {
+    std::string in = R"(
+PIPELINE raytracing my_pipeline
+  USE_LIBRARY 1
+)";
+
+    Parser parser;
+    Result r = parser.Parse(in);
+    ASSERT_FALSE(r.IsSuccess());
+    EXPECT_EQ("3: Unexpected data type", r.Error());
+  }
+}
+
+}  // namespace amberscript
+}  // namespace amber
diff --git a/src/amberscript/parser_run_test.cc b/src/amberscript/parser_run_test.cc
index 0f6b23f..f823527 100644
--- a/src/amberscript/parser_run_test.cc
+++ b/src/amberscript/parser_run_test.cc
@@ -48,6 +48,7 @@ RUN my_pipeline 2 4 5
   EXPECT_EQ(2U, cmd->AsCompute()->GetX());
   EXPECT_EQ(4U, cmd->AsCompute()->GetY());
   EXPECT_EQ(5U, cmd->AsCompute()->GetZ());
+  EXPECT_FALSE(cmd->AsCompute()->IsTimedExecution());
 }
 
 TEST_F(AmberScriptParserTest, RunWithoutPipeline) {
@@ -218,6 +219,7 @@ RUN my_pipeline DRAW_RECT POS 2 4 SIZE 10 20)";
   EXPECT_FLOAT_EQ(4.f, cmd->AsDrawRect()->GetY());
   EXPECT_FLOAT_EQ(10.f, cmd->AsDrawRect()->GetWidth());
   EXPECT_FLOAT_EQ(20.f, cmd->AsDrawRect()->GetHeight());
+  EXPECT_FALSE(cmd->AsDrawRect()->IsTimedExecution());
 }
 
 TEST_F(AmberScriptParserTest, RunDrawRectWithComputePipelineInvalid) {
@@ -519,6 +521,7 @@ RUN my_pipeline DRAW_GRID POS 2 4 SIZE 10 20 CELLS 4 5)";
   EXPECT_FLOAT_EQ(20.f, cmd->AsDrawGrid()->GetHeight());
   EXPECT_EQ(4u, cmd->AsDrawGrid()->GetColumns());
   EXPECT_EQ(5u, cmd->AsDrawGrid()->GetRows());
+  EXPECT_FALSE(cmd->AsDrawGrid()->IsTimedExecution());
 }
 
 TEST_F(AmberScriptParserTest, RunDrawGridWithComputePipelineInvalid) {
@@ -887,6 +890,7 @@ RUN my_pipeline DRAW_ARRAY AS TRIANGLE_LIST START_IDX 1 COUNT 2)";
   EXPECT_EQ(Topology::kTriangleList, cmd->GetTopology());
   EXPECT_EQ(1U, cmd->GetFirstVertexIndex());
   EXPECT_EQ(2U, cmd->GetVertexCount());
+  EXPECT_FALSE(cmd->IsTimedExecution());
 }
 
 TEST_F(AmberScriptParserTest, RunDrawArraysInstanced) {
@@ -926,6 +930,7 @@ RUN my_pipeline DRAW_ARRAY AS TRIANGLE_LIST START_IDX 1 COUNT 2 START_INSTANCE 2
   EXPECT_EQ(Topology::kTriangleList, cmd->GetTopology());
   EXPECT_EQ(1U, cmd->GetFirstVertexIndex());
   EXPECT_EQ(2U, cmd->GetVertexCount());
+  EXPECT_FALSE(cmd->IsTimedExecution());
 }
 
 TEST_F(AmberScriptParserTest, RunDrawArraysCountOmitted) {
@@ -966,6 +971,7 @@ RUN my_pipeline DRAW_ARRAY AS TRIANGLE_LIST START_IDX 1)";
   EXPECT_EQ(1U, cmd->GetFirstVertexIndex());
   // There are 3 elements in the vertex buffer, but we start at element 1.
   EXPECT_EQ(2U, cmd->GetVertexCount());
+  EXPECT_FALSE(cmd->IsTimedExecution());
 }
 
 TEST_F(AmberScriptParserTest, RunDrawArraysStartIdxAndCountOmitted) {
@@ -1006,6 +1012,7 @@ RUN my_pipeline DRAW_ARRAY AS TRIANGLE_LIST)";
   EXPECT_EQ(static_cast<uint32_t>(0U), cmd->GetFirstVertexIndex());
   // There are 3 elements in the vertex buffer.
   EXPECT_EQ(3U, cmd->GetVertexCount());
+  EXPECT_FALSE(cmd->IsTimedExecution());
 }
 
 TEST_F(AmberScriptParserTest, RunDrawArraysIndexed) {
@@ -1052,6 +1059,7 @@ RUN my_pipeline DRAW_ARRAY AS TRIANGLE_LIST INDEXED)";
   EXPECT_EQ(static_cast<uint32_t>(0U), cmd->GetFirstVertexIndex());
   // There are 3 elements in the vertex buffer.
   EXPECT_EQ(3U, cmd->GetVertexCount());
+  EXPECT_FALSE(cmd->IsTimedExecution());
 }
 
 TEST_F(AmberScriptParserTest, RunDrawArraysIndexedMissingIndexData) {
diff --git a/src/amberscript/parser_run_timed_execution_test.cc b/src/amberscript/parser_run_timed_execution_test.cc
new file mode 100644
index 0000000..a794b2c
--- /dev/null
+++ b/src/amberscript/parser_run_timed_execution_test.cc
@@ -0,0 +1,279 @@
+// Copyright 2024 The Amber Authors.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or parseried.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "gtest/gtest.h"
+#include "src/amberscript/parser.h"
+
+namespace amber {
+namespace amberscript {
+
+using AmberScriptParserTest = testing::Test;
+
+TEST_F(AmberScriptParserTest, RunComputeTimedExecution) {
+  std::string in = R"(
+SHADER compute my_shader GLSL
+void main() {
+  gl_FragColor = vec3(2, 3, 4);
+}
+END
+
+PIPELINE compute my_pipeline
+  ATTACH my_shader
+END
+
+RUN TIMED_EXECUTION my_pipeline 2 4 5
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess()) << r.Error();
+
+  auto script = parser.GetScript();
+  const auto& commands = script->GetCommands();
+  ASSERT_EQ(1U, commands.size());
+
+  auto* cmd = commands[0].get();
+  ASSERT_TRUE(cmd->IsCompute());
+  EXPECT_EQ(2U, cmd->AsCompute()->GetX());
+  EXPECT_EQ(4U, cmd->AsCompute()->GetY());
+  EXPECT_EQ(5U, cmd->AsCompute()->GetZ());
+  EXPECT_TRUE(cmd->AsCompute()->IsTimedExecution());
+}
+
+TEST_F(AmberScriptParserTest, RunComputeNoTimedExecution) {
+  std::string in = R"(
+SHADER compute my_shader GLSL
+void main() {
+  gl_FragColor = vec3(2, 3, 4);
+}
+END
+
+PIPELINE compute my_pipeline
+  ATTACH my_shader
+END
+
+RUN my_pipeline 2 4 5
+)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess()) << r.Error();
+
+  auto script = parser.GetScript();
+  const auto& commands = script->GetCommands();
+  ASSERT_EQ(1U, commands.size());
+
+  auto* cmd = commands[0].get();
+  ASSERT_TRUE(cmd->IsCompute());
+  EXPECT_EQ(2U, cmd->AsCompute()->GetX());
+  EXPECT_EQ(4U, cmd->AsCompute()->GetY());
+  EXPECT_EQ(5U, cmd->AsCompute()->GetZ());
+  EXPECT_FALSE(cmd->AsCompute()->IsTimedExecution());
+}
+
+TEST_F(AmberScriptParserTest, RunDrawRectTimedExecution) {
+  std::string in = R"(
+SHADER vertex my_shader PASSTHROUGH
+SHADER fragment my_fragment GLSL
+# GLSL Shader
+END
+
+PIPELINE graphics my_pipeline
+  ATTACH my_shader
+  ATTACH my_fragment
+END
+
+RUN TIMED_EXECUTION my_pipeline DRAW_RECT POS 2 4 SIZE 10 20)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess()) << r.Error();
+
+  auto script = parser.GetScript();
+  const auto& commands = script->GetCommands();
+  ASSERT_EQ(1U, commands.size());
+
+  auto* cmd = commands[0].get();
+  ASSERT_TRUE(cmd->IsDrawRect());
+  EXPECT_TRUE(cmd->AsDrawRect()->IsOrtho());
+  EXPECT_FALSE(cmd->AsDrawRect()->IsPatch());
+  EXPECT_FLOAT_EQ(2.f, cmd->AsDrawRect()->GetX());
+  EXPECT_FLOAT_EQ(4.f, cmd->AsDrawRect()->GetY());
+  EXPECT_FLOAT_EQ(10.f, cmd->AsDrawRect()->GetWidth());
+  EXPECT_FLOAT_EQ(20.f, cmd->AsDrawRect()->GetHeight());
+  EXPECT_TRUE(cmd->AsDrawRect()->IsTimedExecution());
+}
+
+TEST_F(AmberScriptParserTest, RunDrawGridTimedExecution) {
+  std::string in = R"(
+SHADER vertex my_shader PASSTHROUGH
+SHADER fragment my_fragment GLSL
+# GLSL Shader
+END
+
+PIPELINE graphics my_pipeline
+  ATTACH my_shader
+  ATTACH my_fragment
+END
+
+RUN TIMED_EXECUTION my_pipeline DRAW_GRID POS 2 4 SIZE 10 20 CELLS 4 5)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess()) << r.Error();
+
+  auto script = parser.GetScript();
+  const auto& commands = script->GetCommands();
+  ASSERT_EQ(1U, commands.size());
+
+  auto* cmd = commands[0].get();
+  ASSERT_TRUE(cmd->IsDrawGrid());
+  EXPECT_FLOAT_EQ(2.f, cmd->AsDrawGrid()->GetX());
+  EXPECT_FLOAT_EQ(4.f, cmd->AsDrawGrid()->GetY());
+  EXPECT_FLOAT_EQ(10.f, cmd->AsDrawGrid()->GetWidth());
+  EXPECT_FLOAT_EQ(20.f, cmd->AsDrawGrid()->GetHeight());
+  EXPECT_EQ(4u, cmd->AsDrawGrid()->GetColumns());
+  EXPECT_EQ(5u, cmd->AsDrawGrid()->GetRows());
+  EXPECT_TRUE(cmd->AsDrawGrid()->IsTimedExecution());
+}
+
+TEST_F(AmberScriptParserTest, RunDrawArraysTimedExecution) {
+  std::string in = R"(
+SHADER vertex my_shader PASSTHROUGH
+SHADER fragment my_fragment GLSL
+# GLSL Shader
+END
+BUFFER vtex_buf DATA_TYPE vec3<float> DATA
+1 2 3
+4 5 6
+7 8 9
+END
+
+PIPELINE graphics my_pipeline
+  ATTACH my_shader
+  ATTACH my_fragment
+  VERTEX_DATA vtex_buf LOCATION 0
+END
+
+RUN TIMED_EXECUTION my_pipeline DRAW_ARRAY AS TRIANGLE_LIST START_IDX 1 COUNT 2)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess()) << r.Error();
+
+  auto script = parser.GetScript();
+  const auto& commands = script->GetCommands();
+  ASSERT_EQ(1U, commands.size());
+
+  ASSERT_TRUE(commands[0]->IsDrawArrays());
+
+  auto* cmd = commands[0]->AsDrawArrays();
+  EXPECT_FALSE(cmd->IsIndexed());
+  EXPECT_EQ(static_cast<uint32_t>(1U), cmd->GetInstanceCount());
+  EXPECT_EQ(static_cast<uint32_t>(0U), cmd->GetFirstInstance());
+  EXPECT_EQ(Topology::kTriangleList, cmd->GetTopology());
+  EXPECT_EQ(1U, cmd->GetFirstVertexIndex());
+  EXPECT_EQ(2U, cmd->GetVertexCount());
+  EXPECT_TRUE(cmd->IsTimedExecution());
+}
+
+TEST_F(AmberScriptParserTest, RunDrawArraysInstancedTimedExecution) {
+  std::string in = R"(
+SHADER vertex my_shader PASSTHROUGH
+SHADER fragment my_fragment GLSL
+# GLSL Shader
+END
+BUFFER vtex_buf DATA_TYPE vec3<float> DATA
+1 2 3
+4 5 6
+7 8 9
+END
+
+PIPELINE graphics my_pipeline
+  ATTACH my_shader
+  ATTACH my_fragment
+  VERTEX_DATA vtex_buf LOCATION 0
+END
+
+RUN TIMED_EXECUTION my_pipeline DRAW_ARRAY AS TRIANGLE_LIST START_IDX 1 COUNT 2 START_INSTANCE 2 INSTANCE_COUNT 10)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess()) << r.Error();
+
+  auto script = parser.GetScript();
+  const auto& commands = script->GetCommands();
+  ASSERT_EQ(1U, commands.size());
+
+  ASSERT_TRUE(commands[0]->IsDrawArrays());
+
+  auto* cmd = commands[0]->AsDrawArrays();
+  EXPECT_FALSE(cmd->IsIndexed());
+  EXPECT_EQ(static_cast<uint32_t>(10U), cmd->GetInstanceCount());
+  EXPECT_EQ(static_cast<uint32_t>(2U), cmd->GetFirstInstance());
+  EXPECT_EQ(Topology::kTriangleList, cmd->GetTopology());
+  EXPECT_EQ(1U, cmd->GetFirstVertexIndex());
+  EXPECT_EQ(2U, cmd->GetVertexCount());
+  EXPECT_TRUE(cmd->IsTimedExecution());
+}
+
+TEST_F(AmberScriptParserTest, RunDrawArraysIndexedTimedExecution) {
+  std::string in = R"(
+SHADER vertex my_shader PASSTHROUGH
+SHADER fragment my_fragment GLSL
+# GLSL Shader
+END
+BUFFER vtex_buf DATA_TYPE vec3<float> DATA
+1 2 3
+4 5 6
+7 8 9
+END
+BUFFER idx_buf DATA_TYPE vec3<float> DATA
+9 8 7
+6 5 4
+3 2 1
+END
+
+PIPELINE graphics my_pipeline
+  ATTACH my_shader
+  ATTACH my_fragment
+  VERTEX_DATA vtex_buf LOCATION 0
+  INDEX_DATA idx_buf
+END
+
+RUN TIMED_EXECUTION my_pipeline DRAW_ARRAY AS TRIANGLE_LIST INDEXED)";
+
+  Parser parser;
+  Result r = parser.Parse(in);
+  ASSERT_TRUE(r.IsSuccess()) << r.Error();
+
+  auto script = parser.GetScript();
+  const auto& commands = script->GetCommands();
+  ASSERT_EQ(1U, commands.size());
+
+  ASSERT_TRUE(commands[0]->IsDrawArrays());
+
+  auto* cmd = commands[0]->AsDrawArrays();
+  EXPECT_TRUE(cmd->IsIndexed());
+  EXPECT_EQ(static_cast<uint32_t>(1U), cmd->GetInstanceCount());
+  EXPECT_EQ(static_cast<uint32_t>(0U), cmd->GetFirstInstance());
+  EXPECT_EQ(Topology::kTriangleList, cmd->GetTopology());
+  EXPECT_EQ(static_cast<uint32_t>(0U), cmd->GetFirstVertexIndex());
+  // There are 3 elements in the vertex buffer.
+  EXPECT_EQ(3U, cmd->GetVertexCount());
+  EXPECT_TRUE(cmd->IsTimedExecution());
+}
+
+}  // namespace amberscript
+}  // namespace amber
diff --git a/src/command.cc b/src/command.cc
index ea242b7..75e5916 100644
--- a/src/command.cc
+++ b/src/command.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -46,6 +47,10 @@ ComputeCommand* Command::AsCompute() {
   return static_cast<ComputeCommand*>(this);
 }
 
+RayTracingCommand* Command::AsRayTracing() {
+  return static_cast<RayTracingCommand*>(this);
+}
+
 CopyCommand* Command::AsCopy() {
   return static_cast<CopyCommand*>(this);
 }
@@ -184,4 +189,14 @@ RepeatCommand::RepeatCommand(uint32_t count)
 
 RepeatCommand::~RepeatCommand() = default;
 
+TLASCommand::TLASCommand(Pipeline* pipeline)
+    : BindableResourceCommand(Type::kTLAS, pipeline) {}
+
+TLASCommand::~TLASCommand() = default;
+
+RayTracingCommand::RayTracingCommand(Pipeline* pipeline)
+    : PipelineCommand(Type::kRayTracing, pipeline) {}
+
+RayTracingCommand::~RayTracingCommand() = default;
+
 }  // namespace amber
diff --git a/src/command.h b/src/command.h
index 213d7b8..485fc60 100644
--- a/src/command.h
+++ b/src/command.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -23,6 +24,7 @@
 
 #include "amber/shader_info.h"
 #include "amber/value.h"
+#include "src/acceleration_structure.h"
 #include "src/buffer.h"
 #include "src/command_data.h"
 #include "src/pipeline_data.h"
@@ -46,7 +48,9 @@ class PatchParameterVerticesCommand;
 class Pipeline;
 class ProbeCommand;
 class ProbeSSBOCommand;
+class RayTracingCommand;
 class RepeatCommand;
+class TLASCommand;
 
 /// Base class for all commands.
 class Command {
@@ -69,7 +73,9 @@ class Command {
     kProbeSSBO,
     kBuffer,
     kRepeat,
-    kSampler
+    kSampler,
+    kTLAS,
+    kRayTracing
   };
 
   virtual ~Command();
@@ -81,6 +87,8 @@ class Command {
   bool IsDrawArrays() const { return command_type_ == Type::kDrawArrays; }
   bool IsCompareBuffer() const { return command_type_ == Type::kCompareBuffer; }
   bool IsCompute() const { return command_type_ == Type::kCompute; }
+  bool IsRayTracing() const { return command_type_ == Type::kRayTracing; }
+  bool IsTLAS() const { return command_type_ == Type::kTLAS; }
   bool IsCopy() const { return command_type_ == Type::kCopy; }
   bool IsProbe() const { return command_type_ == Type::kProbe; }
   bool IsProbeSSBO() const { return command_type_ == Type::kProbeSSBO; }
@@ -101,6 +109,7 @@ class Command {
   ClearStencilCommand* AsClearStencil();
   CompareBufferCommand* AsCompareBuffer();
   ComputeCommand* AsCompute();
+  RayTracingCommand* AsRayTracing();
   CopyCommand* AsCopy();
   DrawArraysCommand* AsDrawArrays();
   DrawRectCommand* AsDrawRect();
@@ -133,10 +142,14 @@ class PipelineCommand : public Command {
 
   Pipeline* GetPipeline() const { return pipeline_; }
 
+  void SetTimedExecution() { timed_execution_ = true; }
+  bool IsTimedExecution() const { return timed_execution_; }
+
  protected:
   PipelineCommand(Type type, Pipeline* pipeline);
 
   Pipeline* pipeline_ = nullptr;
+  bool timed_execution_ = false;
 };
 
 /// Command to draw a rectangle on screen.
@@ -711,6 +724,60 @@ class RepeatCommand : public Command {
   std::vector<std::unique_ptr<Command>> commands_;
 };
 
+/// Command for setting TLAS parameters and binding.
+class TLASCommand : public BindableResourceCommand {
+ public:
+  explicit TLASCommand(Pipeline* pipeline);
+  ~TLASCommand() override;
+
+  void SetTLAS(TLAS* tlas) { tlas_ = tlas; }
+  TLAS* GetTLAS() const { return tlas_; }
+
+  std::string ToString() const override { return "TLASCommand"; }
+
+ private:
+  TLAS* tlas_ = nullptr;
+};
+
+/// Command to execute a ray tracing command.
+class RayTracingCommand : public PipelineCommand {
+ public:
+  explicit RayTracingCommand(Pipeline* pipeline);
+  ~RayTracingCommand() override;
+
+  void SetX(uint32_t x) { x_ = x; }
+  uint32_t GetX() const { return x_; }
+
+  void SetY(uint32_t y) { y_ = y; }
+  uint32_t GetY() const { return y_; }
+
+  void SetZ(uint32_t z) { z_ = z; }
+  uint32_t GetZ() const { return z_; }
+
+  void SetRGenSBTName(const std::string& name) { rgen_sbt_name_ = name; }
+  std::string GetRayGenSBTName() const { return rgen_sbt_name_; }
+
+  void SetMissSBTName(const std::string& name) { miss_sbt_name_ = name; }
+  std::string GetMissSBTName() const { return miss_sbt_name_; }
+
+  void SetHitsSBTName(const std::string& name) { hits_sbt_name_ = name; }
+  std::string GetHitsSBTName() const { return hits_sbt_name_; }
+
+  void SetCallSBTName(const std::string& name) { call_sbt_name_ = name; }
+  std::string GetCallSBTName() const { return call_sbt_name_; }
+
+  std::string ToString() const override { return "RayTracingCommand"; }
+
+ private:
+  uint32_t x_ = 0;
+  uint32_t y_ = 0;
+  uint32_t z_ = 0;
+  std::string rgen_sbt_name_;
+  std::string miss_sbt_name_;
+  std::string hits_sbt_name_;
+  std::string call_sbt_name_;
+};
+
 }  // namespace amber
 
 #endif  // SRC_COMMAND_H_
diff --git a/src/dxc_helper.cc b/src/dxc_helper.cc
index 0e15dd4..2ef6789 100644
--- a/src/dxc_helper.cc
+++ b/src/dxc_helper.cc
@@ -41,6 +41,13 @@
 #pragma clang diagnostic ignored "-Wunused-function"
 #pragma clang diagnostic ignored "-Wunused-parameter"
 #pragma clang diagnostic ignored "-Wzero-as-null-pointer-constant"
+#pragma clang diagnostic ignored "-Wreserved-identifier"
+#pragma clang diagnostic ignored "-Wnon-virtual-dtor"
+#pragma clang diagnostic ignored "-Wglobal-constructors"
+#pragma clang diagnostic ignored "-Wdocumentation-deprecated-sync"
+#pragma clang diagnostic ignored "-Wsuggest-override"
+#pragma clang diagnostic ignored "-Wmissing-variable-declarations"
+#pragma clang diagnostic ignored "-Wdeprecated"
 #pragma GCC diagnostic push
 #pragma GCC diagnostic ignored "-Wunused-function"
 #pragma GCC diagnostic ignored "-Wunused-parameter"
@@ -65,7 +72,6 @@ namespace {
 
 const wchar_t* kDxcFlags[] = {
     L"-spirv",               // SPIR-V compilation
-    L"-fcgl",                // No SPIR-V Optimization
     L"-enable-16bit-types",  // Enabling 16bit types
 };
 const size_t kDxcFlagsCount = sizeof(kDxcFlags) / sizeof(const wchar_t*);
@@ -83,7 +89,11 @@ void ConvertIDxcBlobToUint32(IDxcBlob* blob,
 }
 
 class IncludeHandler : public IDxcIncludeHandler {
+  DXC_MICROCOM_REF_FIELD(dw_ref_)
+
  public:
+  DXC_MICROCOM_ADDREF_RELEASE_IMPL(dw_ref_)
+
   IncludeHandler(const VirtualFileStore* file_store,
                  IDxcLibrary* dxc_lib,
                  IDxcIncludeHandler* fallback)
diff --git a/src/dxc_helper.h b/src/dxc_helper.h
index eb83216..43cb130 100644
--- a/src/dxc_helper.h
+++ b/src/dxc_helper.h
@@ -17,6 +17,7 @@
 
 #include <string>
 #include <vector>
+#include <cstdint>
 
 #include "amber/result.h"
 
diff --git a/src/engine.h b/src/engine.h
index d444258..71c14c8 100644
--- a/src/engine.h
+++ b/src/engine.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -71,6 +72,7 @@ class Engine {
       EngineConfig* config,
       Delegate* delegate,
       const std::vector<std::string>& features,
+      const std::vector<std::string>& properties,
       const std::vector<std::string>& instance_extensions,
       const std::vector<std::string>& device_extensions) = 0;
 
@@ -101,6 +103,9 @@ class Engine {
   /// Execute the compute command
   virtual Result DoCompute(const ComputeCommand* cmd) = 0;
 
+  /// Execute the trace rays command
+  virtual Result DoTraceRays(const RayTracingCommand* cmd) = 0;
+
   /// Execute the entry point command
   virtual Result DoEntryPoint(const EntryPointCommand* cmd) = 0;
 
diff --git a/src/executor.cc b/src/executor.cc
index 53e3e55..40cb353 100644
--- a/src/executor.cc
+++ b/src/executor.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -159,6 +160,8 @@ Result Executor::ExecuteCommand(Engine* engine, Command* cmd) {
     return engine->DoDrawArrays(cmd->AsDrawArrays());
   if (cmd->IsCompute())
     return engine->DoCompute(cmd->AsCompute());
+  if (cmd->IsRayTracing())
+    return engine->DoTraceRays(cmd->AsRayTracing());
   if (cmd->IsEntryPoint())
     return engine->DoEntryPoint(cmd->AsEntryPoint());
   if (cmd->IsPatchParameterVertices())
diff --git a/src/executor_test.cc b/src/executor_test.cc
index fa57c74..2f9429e 100644
--- a/src/executor_test.cc
+++ b/src/executor_test.cc
@@ -37,9 +37,11 @@ class EngineStub : public Engine {
   Result Initialize(EngineConfig*,
                     Delegate*,
                     const std::vector<std::string>& features,
+                    const std::vector<std::string>& properties,
                     const std::vector<std::string>& instance_exts,
                     const std::vector<std::string>& device_exts) override {
     features_ = features;
+    properties_ = properties;
     instance_extensions_ = instance_exts;
     device_extensions_ = device_exts;
     return {};
@@ -167,6 +169,10 @@ class EngineStub : public Engine {
     return {};
   }
 
+  Result DoTraceRays(const RayTracingCommand*) override {
+    return Result("traceray stub not implemented");
+  }
+
  private:
   bool fail_clear_command_ = false;
   bool fail_clear_color_command_ = false;
@@ -193,6 +199,7 @@ class EngineStub : public Engine {
   bool did_buffer_command_ = false;
 
   std::vector<std::string> features_;
+  std::vector<std::string> properties_;
   std::vector<std::string> instance_extensions_;
   std::vector<std::string> device_extensions_;
 
@@ -207,11 +214,12 @@ class VkScriptExecutorTest : public testing::Test {
   std::unique_ptr<Engine> MakeEngine() { return MakeUnique<EngineStub>(); }
   std::unique_ptr<Engine> MakeAndInitializeEngine(
       const std::vector<std::string>& features,
+      const std::vector<std::string>& properties,
       const std::vector<std::string>& instance_extensions,
       const std::vector<std::string>& device_extensions) {
     std::unique_ptr<Engine> engine = MakeUnique<EngineStub>();
-    engine->Initialize(nullptr, nullptr, features, instance_extensions,
-                       device_extensions);
+    engine->Initialize(nullptr, nullptr, features, properties,
+                       instance_extensions, device_extensions);
     return engine;
   }
   EngineStub* ToStub(Engine* engine) {
@@ -233,6 +241,7 @@ logicOp)";
 
   auto script = parser.GetScript();
   auto engine = MakeAndInitializeEngine(script->GetRequiredFeatures(),
+                                        script->GetRequiredProperties(),
                                         script->GetRequiredInstanceExtensions(),
                                         script->GetRequiredDeviceExtensions());
 
@@ -263,6 +272,7 @@ VK_KHR_variable_pointers)";
 
   auto script = parser.GetScript();
   auto engine = MakeAndInitializeEngine(script->GetRequiredFeatures(),
+                                        script->GetRequiredProperties(),
                                         script->GetRequiredInstanceExtensions(),
                                         script->GetRequiredDeviceExtensions());
 
@@ -293,6 +303,7 @@ depthstencil D24_UNORM_S8_UINT)";
 
   auto script = parser.GetScript();
   auto engine = MakeAndInitializeEngine(script->GetRequiredFeatures(),
+                                        script->GetRequiredProperties(),
                                         script->GetRequiredInstanceExtensions(),
                                         script->GetRequiredDeviceExtensions());
 
@@ -320,6 +331,7 @@ fence_timeout 12345)";
 
   auto script = parser.GetScript();
   auto engine = MakeAndInitializeEngine(script->GetRequiredFeatures(),
+                                        script->GetRequiredProperties(),
                                         script->GetRequiredInstanceExtensions(),
                                         script->GetRequiredDeviceExtensions());
 
@@ -355,6 +367,7 @@ fence_timeout 12345)";
 
   auto script = parser.GetScript();
   auto engine = MakeAndInitializeEngine(script->GetRequiredFeatures(),
+                                        script->GetRequiredProperties(),
                                         script->GetRequiredInstanceExtensions(),
                                         script->GetRequiredDeviceExtensions());
 
diff --git a/src/pipeline.cc b/src/pipeline.cc
index a9b66ca..4be1de2 100644
--- a/src/pipeline.cc
+++ b/src/pipeline.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -61,7 +62,8 @@ Pipeline::ShaderInfo::ShaderInfo(const ShaderInfo&) = default;
 
 Pipeline::ShaderInfo::~ShaderInfo() = default;
 
-Pipeline::Pipeline(PipelineType type) : pipeline_type_(type) {}
+Pipeline::Pipeline(PipelineType type) : pipeline_type_(type) {
+}
 
 Pipeline::~Pipeline() = default;
 
@@ -99,13 +101,15 @@ Result Pipeline::AddShader(Shader* shader, ShaderType shader_type) {
     return Result("can not add a compute shader to a graphics pipeline");
   }
 
-  for (auto& info : shaders_) {
-    const auto* is = info.GetShader();
-    if (is == shader)
-      return Result("can not add duplicate shader to pipeline");
-    if (is->GetType() == shader_type) {
-      info.SetShader(shader);
-      return {};
+  if (pipeline_type_ != PipelineType::kRayTracing) {
+    for (auto& info : shaders_) {
+      const auto* is = info.GetShader();
+      if (is == shader)
+        return Result("can not add duplicate shader to pipeline");
+      if (is->GetType() == shader_type) {
+        info.SetShader(shader);
+        return {};
+      }
     }
   }
 
@@ -292,12 +296,21 @@ Result Pipeline::Validate() const {
     }
   }
 
-  if (pipeline_type_ == PipelineType::kGraphics)
+  if (pipeline_type_ == PipelineType::kRayTracing)
+    return ValidateRayTracing();
+  else if (pipeline_type_ == PipelineType::kGraphics)
     return ValidateGraphics();
 
   return ValidateCompute();
 }
 
+Result Pipeline::ValidateRayTracing() const {
+  if (shader_groups_.empty() && shaders_.empty() && tlases_.empty())
+    return Result("Shader groups are missing");
+
+  return {};
+}
+
 Result Pipeline::ValidateGraphics() const {
   if (color_attachments_.empty())
     return Result("PIPELINE missing color attachment");
@@ -655,6 +668,15 @@ void Pipeline::AddSampler(uint32_t mask,
   info.binding = binding;
 }
 
+void Pipeline::AddTLAS(TLAS* tlas, uint32_t descriptor_set, uint32_t binding) {
+  tlases_.push_back(TLASInfo(tlas));
+
+  auto& info = tlases_.back();
+
+  info.descriptor_set = descriptor_set;
+  info.binding = binding;
+}
+
 void Pipeline::ClearSamplers(uint32_t descriptor_set, uint32_t binding) {
   samplers_.erase(
       std::remove_if(samplers_.begin(), samplers_.end(),
diff --git a/src/pipeline.h b/src/pipeline.h
index 12792f0..3c93d6c 100644
--- a/src/pipeline.h
+++ b/src/pipeline.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -23,6 +24,7 @@
 #include <vector>
 
 #include "amber/result.h"
+#include "src/acceleration_structure.h"
 #include "src/buffer.h"
 #include "src/command_data.h"
 #include "src/pipeline_data.h"
@@ -31,7 +33,7 @@
 
 namespace amber {
 
-enum class PipelineType { kCompute = 0, kGraphics };
+enum class PipelineType { kCompute = 0, kGraphics, kRayTracing };
 
 /// Stores all information related to a pipeline.
 class Pipeline {
@@ -216,6 +218,15 @@ class Pipeline {
     uint32_t mask = 0;
   };
 
+  /// Information on a top level acceleration structure at the pipeline.
+  struct TLASInfo {
+    TLASInfo() = default;
+    explicit TLASInfo(TLAS* as) : tlas(as) {}
+
+    TLAS* tlas = nullptr;
+    uint32_t descriptor_set = 0;
+    uint32_t binding = 0;
+  };
   static const char* kGeneratedColorBuffer;
   static const char* kGeneratedDepthBuffer;
   static const char* kGeneratedPushConstantBuffer;
@@ -227,6 +238,9 @@ class Pipeline {
 
   bool IsGraphics() const { return pipeline_type_ == PipelineType::kGraphics; }
   bool IsCompute() const { return pipeline_type_ == PipelineType::kCompute; }
+  bool IsRayTracing() const {
+    return pipeline_type_ == PipelineType::kRayTracing;
+  }
 
   PipelineType GetType() const { return pipeline_type_; }
 
@@ -261,6 +275,28 @@ class Pipeline {
     return nullptr;
   }
 
+  /// Adds |shaders| to the pipeline.
+  /// Designed to support libraries
+  Result AddShaders(const std::vector<ShaderInfo>& lib_shaders) {
+    shaders_.reserve(shaders_.size() + lib_shaders.size());
+    shaders_.insert(std::end(shaders_), std::begin(lib_shaders),
+                    std::end(lib_shaders));
+
+    return {};
+  }
+
+  /// Returns a success result if |shader| found and the shader index is
+  /// returned in |out|. Returns failure otherwise.
+  Result GetShaderIndex(Shader* shader, uint32_t* out) const {
+    for (size_t index = 0; index < shaders_.size(); index++) {
+      if (shaders_[index].GetShader() == shader) {
+        *out = static_cast<uint32_t>(index);
+        return {};
+      }
+    }
+    return Result("Referred shader not found in group");
+  }
+
   /// Sets the |type| of |shader| in the pipeline.
   Result SetShaderType(const Shader* shader, ShaderType type);
   /// Sets the entry point |name| for |shader| in this pipeline.
@@ -377,6 +413,73 @@ class Pipeline {
   /// Returns information on all samplers in this pipeline.
   const std::vector<SamplerInfo>& GetSamplers() const { return samplers_; }
 
+  /// Adds |tlas| to the pipeline at the given |descriptor_set| and
+  /// |binding|.
+  void AddTLAS(TLAS* tlas, uint32_t descriptor_set, uint32_t binding);
+
+  /// Returns information on all bound TLAS in the pipeline.
+  std::vector<TLASInfo>& GetTLASes() { return tlases_; }
+
+  /// Adds |sbt| to the list of known shader binding tables.
+  /// The |sbt| must have a unique name within pipeline.
+  Result AddSBT(std::unique_ptr<SBT> sbt) {
+    if (name_to_sbt_.count(sbt->GetName()) > 0)
+      return Result("duplicate SBT name provided");
+
+    sbts_.push_back(std::move(sbt));
+    name_to_sbt_[sbts_.back()->GetName()] = sbts_.back().get();
+
+    return {};
+  }
+
+  /// Retrieves the SBT with |name|, |nullptr| if not found.
+  SBT* GetSBT(const std::string& name) const {
+    auto it = name_to_sbt_.find(name);
+    return it == name_to_sbt_.end() ? nullptr : it->second;
+  }
+
+  /// Retrieves a list of all SBTs.
+  const std::vector<std::unique_ptr<SBT>>& GetSBTs() const { return sbts_; }
+
+  /// Adds |group| to the list of known shader groups.
+  /// The |group| must have a unique name within pipeline.
+  Result AddShaderGroup(std::shared_ptr<ShaderGroup> group) {
+    if (name_to_shader_group_.count(group->GetName()) > 0)
+      return Result("shader group name already exists");
+
+    shader_groups_.push_back(std::move(group));
+    name_to_shader_group_[shader_groups_.back()->GetName()] =
+        shader_groups_.back().get();
+
+    return {};
+  }
+
+  /// Retrieves the Shader Group with |name|, |nullptr| if not found.
+  ShaderGroup* GetShaderGroup(const std::string& name) const {
+    auto it = name_to_shader_group_.find(name);
+    return it == name_to_shader_group_.end() ? nullptr : it->second;
+  }
+  /// Retrieves a Shader Group at given |index|.
+  ShaderGroup* GetShaderGroupByIndex(uint32_t index) const {
+    return shader_groups_[index].get();
+  }
+  /// Retreives index of shader group specified by |name|
+  uint32_t GetShaderGroupIndex(const std::string& name) const {
+    ShaderGroup* shader_group = GetShaderGroup(name);
+
+    for (size_t i = 0; i < shader_groups_.size(); i++) {
+      if (shader_groups_[i].get() == shader_group) {
+        return static_cast<uint32_t>(i);
+      }
+    }
+
+    return static_cast<uint32_t>(-1);
+  }
+  /// Retrieves a list of all Shader Groups.
+  const std::vector<std::shared_ptr<ShaderGroup>>& GetShaderGroups() const {
+    return shader_groups_;
+  }
+
   /// Updates the descriptor set and binding info for the OpenCL-C kernel bound
   /// to the pipeline. No effect for other shader formats.
   Result UpdateOpenCLBufferBindings();
@@ -423,6 +526,34 @@ class Pipeline {
   /// Generate the push constant buffers necessary for OpenCL kernels.
   Result GenerateOpenCLPushConstants();
 
+  void SetMaxPipelineRayPayloadSize(uint32_t size) {
+    max_pipeline_ray_payload_size_ = size;
+  }
+  uint32_t GetMaxPipelineRayPayloadSize() {
+    return max_pipeline_ray_payload_size_;
+  }
+  void SetMaxPipelineRayHitAttributeSize(uint32_t size) {
+    max_pipeline_ray_hit_attribute_size_ = size;
+  }
+  uint32_t GetMaxPipelineRayHitAttributeSize() {
+    return max_pipeline_ray_hit_attribute_size_;
+  }
+  void SetMaxPipelineRayRecursionDepth(uint32_t depth) {
+    max_pipeline_ray_recursion_depth_ = depth;
+  }
+  uint32_t GetMaxPipelineRayRecursionDepth() {
+    return max_pipeline_ray_recursion_depth_;
+  }
+  void SetCreateFlags(uint32_t flags) {
+    create_flags_ = flags;
+  }
+  uint32_t GetCreateFlags() const {
+    return create_flags_;
+  }
+
+  void AddPipelineLibrary(Pipeline* pipeline) { libs_.push_back(pipeline); }
+  const std::vector<Pipeline*>& GetPipelineLibraries() const { return libs_; }
+
  private:
   void UpdateFramebufferSizes();
 
@@ -435,10 +566,12 @@ class Pipeline {
 
   Result ValidateGraphics() const;
   Result ValidateCompute() const;
+  Result ValidateRayTracing() const;
 
   PipelineType pipeline_type_ = PipelineType::kCompute;
   std::string name_;
   std::vector<ShaderInfo> shaders_;
+  std::vector<TLASInfo> tlases_;
   std::vector<BufferInfo> color_attachments_;
   std::vector<BufferInfo> resolve_targets_;
   std::vector<BufferInfo> vertex_buffers_;
@@ -459,6 +592,16 @@ class Pipeline {
   std::map<std::pair<uint32_t, uint32_t>, Buffer*> opencl_pod_buffer_map_;
   std::vector<std::unique_ptr<Sampler>> opencl_literal_samplers_;
   std::unique_ptr<Buffer> opencl_push_constants_;
+
+  std::map<std::string, ShaderGroup*> name_to_shader_group_;
+  std::vector<std::shared_ptr<ShaderGroup>> shader_groups_;
+  std::map<std::string, SBT*> name_to_sbt_;
+  std::vector<std::unique_ptr<SBT>> sbts_;
+  uint32_t max_pipeline_ray_payload_size_ = 0;
+  uint32_t max_pipeline_ray_hit_attribute_size_ = 0;
+  uint32_t max_pipeline_ray_recursion_depth_ = 1;
+  uint32_t create_flags_ = 0;
+  std::vector<Pipeline*> libs_;
 };
 
 }  // namespace amber
diff --git a/src/recipe.cc b/src/recipe.cc
index 7e22bd4..7d46f05 100644
--- a/src/recipe.cc
+++ b/src/recipe.cc
@@ -35,6 +35,10 @@ std::vector<std::string> Recipe::GetRequiredFeatures() const {
   return impl_ ? impl_->GetRequiredFeatures() : std::vector<std::string>();
 }
 
+std::vector<std::string> Recipe::GetRequiredProperties() const {
+  return impl_ ? impl_->GetRequiredProperties() : std::vector<std::string>();
+}
+
 std::vector<std::string> Recipe::GetRequiredDeviceExtensions() const {
   return impl_ ? impl_->GetRequiredDeviceExtensions()
                : std::vector<std::string>();
diff --git a/src/script.cc b/src/script.cc
index 091949e..a5d8bed 100644
--- a/src/script.cc
+++ b/src/script.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -131,7 +132,32 @@ bool Script::IsKnownFeature(const std::string& name) const {
          name == "SubgroupSupportedStages.compute" ||
          name == "IndexTypeUint8Features.indexTypeUint8" ||
          name ==
-             "ShaderSubgroupExtendedTypesFeatures.shaderSubgroupExtendedTypes";
+             "ShaderSubgroupExtendedTypesFeatures"
+             ".shaderSubgroupExtendedTypes" ||
+         name == "RayTracingPipelineFeaturesKHR.rayTracingPipeline" ||
+         name == "AccelerationStructureFeaturesKHR.accelerationStructure" ||
+         name == "BufferDeviceAddressFeatures.bufferDeviceAddress";
+}
+
+bool Script::IsKnownProperty(const std::string& name) const {
+  return name ==
+             "FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat16" ||
+         name ==
+             "FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat32" ||
+         name ==
+             "FloatControlsProperties.shaderSignedZeroInfNanPreserveFloat64" ||
+         name == "FloatControlsProperties.shaderDenormPreserveFloat16" ||
+         name == "FloatControlsProperties.shaderDenormPreserveFloat32" ||
+         name == "FloatControlsProperties.shaderDenormPreserveFloat64" ||
+         name == "FloatControlsProperties.shaderDenormFlushToZeroFloat16" ||
+         name == "FloatControlsProperties.shaderDenormFlushToZeroFloat32" ||
+         name == "FloatControlsProperties.shaderDenormFlushToZeroFloat64" ||
+         name == "FloatControlsProperties.shaderRoundingModeRTEFloat16" ||
+         name == "FloatControlsProperties.shaderRoundingModeRTEFloat32" ||
+         name == "FloatControlsProperties.shaderRoundingModeRTEFloat64" ||
+         name == "FloatControlsProperties.shaderRoundingModeRTZFloat16" ||
+         name == "FloatControlsProperties.shaderRoundingModeRTZFloat32" ||
+         name == "FloatControlsProperties.shaderRoundingModeRTZFloat64";
 }
 
 type::Type* Script::ParseType(const std::string& str) {
diff --git a/src/script.h b/src/script.h
index b4c6e1a..1b36e8b 100644
--- a/src/script.h
+++ b/src/script.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -25,6 +26,7 @@
 
 #include "amber/recipe.h"
 #include "amber/result.h"
+#include "src/acceleration_structure.h"
 #include "src/buffer.h"
 #include "src/command.h"
 #include "src/engine.h"
@@ -43,6 +45,7 @@ class Script : public RecipeImpl {
   ~Script() override;
 
   bool IsKnownFeature(const std::string& name) const;
+  bool IsKnownProperty(const std::string& name) const;
 
   /// Retrieves information on the shaders in the given script.
   std::vector<ShaderInfo> GetShaderInfo() const override;
@@ -52,6 +55,10 @@ class Script : public RecipeImpl {
     return engine_info_.required_features;
   }
 
+  std::vector<std::string> GetRequiredProperties() const override {
+    return engine_info_.required_properties;
+  }
+
   /// Returns required device extensions in the given recipe.
   std::vector<std::string> GetRequiredDeviceExtensions() const override {
     return engine_info_.required_device_extensions;
@@ -116,6 +123,54 @@ class Script : public RecipeImpl {
     return shaders_;
   }
 
+  /// Search |pipeline| and all included into pipeline libraries whether shader
+  /// with |name| is present in pipeline groups. Returns shader if found,
+  /// |nullptr| if not found.
+  Shader* FindShader(const Pipeline* pipeline, Shader* shader) const {
+    if (shader) {
+      for (auto group : pipeline->GetShaderGroups()) {
+        Shader* test_shader = group->GetShaderByType(shader->GetType());
+        if (test_shader == shader)
+          return shader;
+      }
+
+      for (auto lib : pipeline->GetPipelineLibraries()) {
+        shader = FindShader(lib, shader);
+        if (shader)
+          return shader;
+      }
+    }
+
+    return nullptr;
+  }
+
+  /// Search |pipeline| and all included into pipeline libraries whether shader
+  /// group with |name| is present. Returns shader group if found, |nullptr|
+  /// if not found. |index| is an shader group index in pipeline or library.
+  ShaderGroup* FindShaderGroup(const Pipeline* pipeline,
+                               const std::string& name,
+                               uint32_t* index) const {
+    ShaderGroup* result = nullptr;
+    uint32_t shader_group_index = pipeline->GetShaderGroupIndex(name);
+    if (shader_group_index != static_cast<uint32_t>(-1)) {
+      (*index) += shader_group_index;
+      result = pipeline->GetShaderGroupByIndex(shader_group_index);
+      return result;
+    } else {
+      (*index) += static_cast<uint32_t>(pipeline->GetShaderGroups().size());
+    }
+
+    for (auto lib : pipeline->GetPipelineLibraries()) {
+      result = FindShaderGroup(lib, name, index);
+      if (result)
+        return result;
+    }
+
+    *index = static_cast<uint32_t>(-1);
+
+    return nullptr;
+  }
+
   /// Adds |buffer| to the list of known buffers. The |buffer| must have a
   /// unique name over all buffers in the script.
   Result AddBuffer(std::unique_ptr<Buffer> buffer) {
@@ -160,12 +215,64 @@ class Script : public RecipeImpl {
     return samplers_;
   }
 
+  /// Adds |blas| to the list of known bottom level acceleration structures.
+  /// The |blas| must have a unique name over all BLASes in the script.
+  Result AddBLAS(std::unique_ptr<BLAS> blas) {
+    if (name_to_blas_.count(blas->GetName()) > 0)
+      return Result("duplicate BLAS name provided");
+
+    blases_.push_back(std::move(blas));
+    name_to_blas_[blases_.back()->GetName()] = blases_.back().get();
+
+    return {};
+  }
+
+  /// Retrieves the BLAS with |name|, |nullptr| if not found.
+  BLAS* GetBLAS(const std::string& name) const {
+    auto it = name_to_blas_.find(name);
+    return it == name_to_blas_.end() ? nullptr : it->second;
+  }
+
+  /// Retrieves a list of all BLASes.
+  const std::vector<std::unique_ptr<BLAS>>& GetBLASes() const {
+    return blases_;
+  }
+
+  /// Adds |tlas| to the list of known top level acceleration structures.
+  /// The |tlas| must have a unique name over all TLASes in the script.
+  Result AddTLAS(std::unique_ptr<TLAS> tlas) {
+    if (name_to_tlas_.count(tlas->GetName()) > 0)
+      return Result("duplicate TLAS name provided");
+
+    tlases_.push_back(std::move(tlas));
+    name_to_tlas_[tlases_.back()->GetName()] = tlases_.back().get();
+
+    return {};
+  }
+
+  /// Retrieves the TLAS with |name|, |nullptr| if not found.
+  TLAS* GetTLAS(const std::string& name) const {
+    auto it = name_to_tlas_.find(name);
+    return it == name_to_tlas_.end() ? nullptr : it->second;
+  }
+
+  /// Retrieves a list of all TLASes.
+  const std::vector<std::unique_ptr<TLAS>>& GetTLASes() const {
+    return tlases_;
+  }
+
   /// Adds |feature| to the list of features that must be supported by the
   /// engine.
   void AddRequiredFeature(const std::string& feature) {
     engine_info_.required_features.push_back(feature);
   }
 
+  /// Adds |prop| to the list of properties that must be supported by the
+  /// engine.
+  void AddRequiredProperty(const std::string& prop) {
+    engine_info_.required_properties.push_back(prop);
+  }
+
   /// Checks if |feature| is in required features
   bool IsRequiredFeature(const std::string& feature) const {
     return std::find(engine_info_.required_features.begin(),
@@ -173,6 +280,13 @@ class Script : public RecipeImpl {
                      feature) != engine_info_.required_features.end();
   }
 
+  /// Checks if |prop| is in required features
+  bool IsRequiredProperty(const std::string& prop) const {
+    return std::find(engine_info_.required_properties.begin(),
+                     engine_info_.required_properties.end(),
+                     prop) != engine_info_.required_properties.end();
+  }
+
   /// Adds |ext| to the list of device extensions that must be supported.
   void AddRequiredDeviceExtension(const std::string& ext) {
     engine_info_.required_device_extensions.push_back(ext);
@@ -257,6 +371,7 @@ class Script : public RecipeImpl {
  private:
   struct {
     std::vector<std::string> required_features;
+    std::vector<std::string> required_properties;
     std::vector<std::string> required_device_extensions;
     std::vector<std::string> required_instance_extensions;
   } engine_info_;
@@ -267,12 +382,16 @@ class Script : public RecipeImpl {
   std::map<std::string, Buffer*> name_to_buffer_;
   std::map<std::string, Sampler*> name_to_sampler_;
   std::map<std::string, Pipeline*> name_to_pipeline_;
+  std::map<std::string, BLAS*> name_to_blas_;
+  std::map<std::string, TLAS*> name_to_tlas_;
   std::map<std::string, std::unique_ptr<type::Type>> name_to_type_;
   std::vector<std::unique_ptr<Shader>> shaders_;
   std::vector<std::unique_ptr<Command>> commands_;
   std::vector<std::unique_ptr<Buffer>> buffers_;
   std::vector<std::unique_ptr<Sampler>> samplers_;
   std::vector<std::unique_ptr<Pipeline>> pipelines_;
+  std::vector<std::unique_ptr<BLAS>> blases_;
+  std::vector<std::unique_ptr<TLAS>> tlases_;
   std::vector<std::unique_ptr<type::Type>> types_;
   std::vector<std::unique_ptr<Format>> formats_;
   std::unique_ptr<VirtualFileStore> virtual_files_;
diff --git a/src/shader_compiler.cc b/src/shader_compiler.cc
index 285dd97..1615fb9 100644
--- a/src/shader_compiler.cc
+++ b/src/shader_compiler.cc
@@ -16,6 +16,7 @@
 
 #include <algorithm>
 #include <cstdlib>
+#include <cstring>
 #include <iterator>
 #include <string>
 #include <utility>
@@ -123,6 +124,9 @@ std::pair<Result, std::vector<uint32_t>> ShaderCompiler::Compile(
     Result r = ParseHex(shader->GetData(), &results);
     if (!r.IsSuccess())
       return {Result("Unable to parse shader hex."), {}};
+  } else if (shader->GetFormat() == kShaderFormatSpirvBin) {
+    results.resize(shader->GetData().size() / 4);
+    memcpy(results.data(), shader->GetData().data(), shader->GetData().size());
 
 #if AMBER_ENABLE_SHADERC
   } else if (shader->GetFormat() == kShaderFormatGlsl) {
@@ -241,6 +245,18 @@ Result ShaderCompiler::CompileGlsl(const Shader* shader,
     kind = shaderc_tess_control_shader;
   else if (shader->GetType() == kShaderTypeTessellationEvaluation)
     kind = shaderc_tess_evaluation_shader;
+  else if (shader->GetType() == kShaderTypeRayGeneration)
+    kind = shaderc_raygen_shader;
+  else if (shader->GetType() == kShaderTypeAnyHit)
+    kind = shaderc_anyhit_shader;
+  else if (shader->GetType() == kShaderTypeClosestHit)
+    kind = shaderc_closesthit_shader;
+  else if (shader->GetType() == kShaderTypeMiss)
+    kind = shaderc_miss_shader;
+  else if (shader->GetType() == kShaderTypeIntersection)
+    kind = shaderc_intersection_shader;
+  else if (shader->GetType() == kShaderTypeCall)
+    kind = shaderc_callable_shader;
   else
     return Result("Unknown shader type");
 
diff --git a/src/vulkan/CMakeLists.txt b/src/vulkan/CMakeLists.txt
index 8b029ea..7065890 100644
--- a/src/vulkan/CMakeLists.txt
+++ b/src/vulkan/CMakeLists.txt
@@ -1,4 +1,5 @@
 # Copyright 2018 The Amber Authors.
+# Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,6 +14,7 @@
 # limitations under the License.
 
 set(VULKAN_ENGINE_SOURCES
+    blas.cc
     buffer_descriptor.cc
     buffer_backed_descriptor.cc
     command_buffer.cc
@@ -27,9 +29,13 @@ set(VULKAN_ENGINE_SOURCES
     index_buffer.cc
     pipeline.cc
     push_constant.cc
+    raytracing_pipeline.cc
     resource.cc
     sampler.cc
     sampler_descriptor.cc
+    sbt.cc
+    tlas.cc
+    tlas_descriptor.cc
     transfer_buffer.cc
     transfer_image.cc
     vertex_buffer.cc
@@ -39,8 +45,9 @@ set(VULKAN_ENGINE_SOURCES
 add_library(libamberenginevulkan ${VULKAN_ENGINE_SOURCES})
 amber_default_compile_options(libamberenginevulkan)
 target_include_directories(libamberenginevulkan PRIVATE "${CMAKE_BINARY_DIR}")
+
 # Add the Vulkan include directory to the list of include paths.
-target_include_directories(libamberenginevulkan PRIVATE "${VulkanHeaders_INCLUDE_DIR}")
+target_include_directories(libamberenginevulkan PUBLIC "${VulkanHeaders_INCLUDE_DIR}")
 
 # When building with dEQP Vulkan CTS the inl files needs to be included and a dependency
 # must be added to the target `deqp-vk-inl` that generates the inl files.
@@ -66,7 +73,7 @@ endif()
 add_custom_command(
     OUTPUT ${CMAKE_BINARY_DIR}/src/vk-wrappers.inc.fake
     COMMAND
-      ${PYTHON_EXECUTABLE}
+      ${Python3_EXECUTABLE}
         ${PROJECT_SOURCE_DIR}/tools/update_vk_wrappers.py
         ${CMAKE_BINARY_DIR}
         ${PROJECT_SOURCE_DIR}
diff --git a/src/vulkan/blas.cc b/src/vulkan/blas.cc
new file mode 100644
index 0000000..bdd4101
--- /dev/null
+++ b/src/vulkan/blas.cc
@@ -0,0 +1,270 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "src/vulkan/blas.h"
+
+#include <cstring>
+
+#include "src/vulkan/command_buffer.h"
+
+namespace amber {
+namespace vulkan {
+
+inline VkDeviceSize align(VkDeviceSize v, VkDeviceSize a) {
+  return (v + a - 1) & ~(a - 1);
+}
+
+BLAS::BLAS(Device* device) : device_(device) {}
+
+BLAS::~BLAS() {
+  if (blas_ != VK_NULL_HANDLE) {
+    device_->GetPtrs()->vkDestroyAccelerationStructureKHR(
+        device_->GetVkDevice(), blas_, nullptr);
+  }
+}
+
+Result BLAS::CreateBLAS(amber::BLAS* blas) {
+  if (blas_ != VK_NULL_HANDLE)
+    return Result("Cannot recreate acceleration structure");
+
+  std::vector<std::unique_ptr<Geometry>>& geometries = blas->GetGeometries();
+  std::vector<VkDeviceSize> vertexBufferOffsets;
+  VkDeviceSize vertexBufferSize = 0;
+
+  VkDeviceOrHostAddressConstKHR const_null_placeholder = {};
+  VkDeviceOrHostAddressKHR null_placeholder = {};
+
+  accelerationStructureGeometriesKHR_.resize(geometries.size());
+  accelerationStructureBuildRangeInfoKHR_.resize(geometries.size());
+  maxPrimitiveCounts_.resize(geometries.size());
+  vertexBufferOffsets.resize(geometries.size());
+
+  for (size_t geometryNdx = 0; geometryNdx < geometries.size(); ++geometryNdx) {
+    const std::unique_ptr<Geometry>& geometryData = geometries[geometryNdx];
+    VkDeviceOrHostAddressConstKHR vertexData = {};
+    VkAccelerationStructureGeometryDataKHR geometry;
+    VkGeometryTypeKHR geometryType = VK_GEOMETRY_TYPE_MAX_ENUM_KHR;
+
+    if (geometryData->IsTriangle()) {
+      VkAccelerationStructureGeometryTrianglesDataKHR
+          accelerationStructureGeometryTrianglesDataKHR = {
+              // NOLINTNEXTLINE(whitespace/line_length)
+              VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_TRIANGLES_DATA_KHR,
+              nullptr,
+              VK_FORMAT_R32G32B32_SFLOAT,
+              vertexData,
+              3 * sizeof(float),
+              static_cast<uint32_t>(geometryData->getVertexCount()),
+              VK_INDEX_TYPE_NONE_KHR,
+              const_null_placeholder,
+              const_null_placeholder,
+          };
+
+      geometryType = VK_GEOMETRY_TYPE_TRIANGLES_KHR;
+      geometry.triangles = accelerationStructureGeometryTrianglesDataKHR;
+    } else if (geometryData->IsAABB()) {
+      const VkAccelerationStructureGeometryAabbsDataKHR
+          accelerationStructureGeometryAabbsDataKHR = {
+              VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_AABBS_DATA_KHR,
+              nullptr, vertexData, sizeof(VkAabbPositionsKHR)};
+
+      geometryType = VK_GEOMETRY_TYPE_AABBS_KHR;
+      geometry.aabbs = accelerationStructureGeometryAabbsDataKHR;
+    } else {
+      assert(false && "unknown geometry type");
+    }
+
+    const VkAccelerationStructureGeometryKHR accelerationStructureGeometry = {
+            VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_KHR,
+            nullptr,
+            geometryType,
+            geometry,
+            VkGeometryFlagsKHR(geometryData->GetFlags())
+        };
+    const VkAccelerationStructureBuildRangeInfoKHR
+        accelerationStructureBuildRangeInfosKHR = {
+            static_cast<uint32_t>(geometryData->getPrimitiveCount()), 0, 0, 0};
+
+    accelerationStructureGeometriesKHR_[geometryNdx] =
+        accelerationStructureGeometry;
+    accelerationStructureBuildRangeInfoKHR_[geometryNdx] =
+        accelerationStructureBuildRangeInfosKHR;
+    maxPrimitiveCounts_[geometryNdx] =
+        accelerationStructureBuildRangeInfosKHR.primitiveCount;
+    vertexBufferOffsets[geometryNdx] = vertexBufferSize;
+    size_t s1 = sizeof(geometryData->GetData()[0]);
+    vertexBufferSize += align(geometryData->GetData().size() * s1, 8);
+  }
+
+  const VkAccelerationStructureGeometryKHR*
+      accelerationStructureGeometriesKHRPointer =
+          accelerationStructureGeometriesKHR_.data();
+  accelerationStructureBuildGeometryInfoKHR_ = {
+      VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_GEOMETRY_INFO_KHR,
+      nullptr,
+      VK_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL_KHR,
+      0u,
+      VK_BUILD_ACCELERATION_STRUCTURE_MODE_BUILD_KHR,
+      VK_NULL_HANDLE,
+      VK_NULL_HANDLE,
+      static_cast<uint32_t>(accelerationStructureGeometriesKHR_.size()),
+      accelerationStructureGeometriesKHRPointer,
+      nullptr,
+      null_placeholder,
+  };
+  VkAccelerationStructureBuildSizesInfoKHR sizeInfo = {
+      VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_SIZES_INFO_KHR, nullptr, 0,
+      0, 0};
+
+  device_->GetPtrs()->vkGetAccelerationStructureBuildSizesKHR(
+      device_->GetVkDevice(), VK_ACCELERATION_STRUCTURE_BUILD_TYPE_DEVICE_KHR,
+      &accelerationStructureBuildGeometryInfoKHR_, maxPrimitiveCounts_.data(),
+      &sizeInfo);
+
+  const uint32_t accelerationStructureSize =
+      static_cast<uint32_t>(sizeInfo.accelerationStructureSize);
+
+  buffer_ =
+      MakeUnique<TransferBuffer>(device_, accelerationStructureSize, nullptr);
+  buffer_->AddUsageFlags(
+      VK_BUFFER_USAGE_ACCELERATION_STRUCTURE_STORAGE_BIT_KHR |
+      VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT);
+  buffer_->AddAllocateFlags(VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT);
+  buffer_->Initialize();
+
+  const VkAccelerationStructureCreateInfoKHR accelerationStructureCreateInfoKHR{
+      VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_CREATE_INFO_KHR,
+      nullptr,
+      0,
+      buffer_->GetVkBuffer(),
+      0,
+      accelerationStructureSize,
+      VK_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL_KHR,
+      0};
+
+  if (device_->GetPtrs()->vkCreateAccelerationStructureKHR(
+          device_->GetVkDevice(), &accelerationStructureCreateInfoKHR, nullptr,
+          &blas_) != VK_SUCCESS)
+    return Result("Vulkan::Calling vkCreateAccelerationStructureKHR failed");
+
+  accelerationStructureBuildGeometryInfoKHR_.dstAccelerationStructure = blas_;
+
+  if (sizeInfo.buildScratchSize > 0) {
+    scratch_buffer_ = MakeUnique<TransferBuffer>(
+        device_, static_cast<uint32_t>(sizeInfo.buildScratchSize), nullptr);
+    scratch_buffer_->AddUsageFlags(VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
+                                   VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT);
+    scratch_buffer_->AddAllocateFlags(VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT);
+    scratch_buffer_->Initialize();
+
+    accelerationStructureBuildGeometryInfoKHR_.scratchData.deviceAddress =
+        scratch_buffer_->getBufferDeviceAddress();
+  }
+
+  if (vertexBufferSize > 0) {
+    vertex_buffer_ = MakeUnique<TransferBuffer>(
+        device_, static_cast<uint32_t>(vertexBufferSize), nullptr);
+    vertex_buffer_->AddUsageFlags(
+        VK_BUFFER_USAGE_ACCELERATION_STRUCTURE_BUILD_INPUT_READ_ONLY_BIT_KHR |
+        VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT);
+    vertex_buffer_->AddAllocateFlags(VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT);
+    vertex_buffer_->SetMemoryPropertiesFlags(
+        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
+        VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
+    vertex_buffer_->Initialize();
+
+    void* memory_ptr = vertex_buffer_->HostAccessibleMemoryPtr();
+    assert(memory_ptr != nullptr);
+
+    for (size_t geometryNdx = 0; geometryNdx < geometries.size();
+         ++geometryNdx) {
+      VkDeviceOrHostAddressConstKHR p;
+
+      p.deviceAddress = vertex_buffer_.get()->getBufferDeviceAddress() +
+                        vertexBufferOffsets[geometryNdx];
+
+      const auto& data = geometries[geometryNdx]->GetData();
+      std::memcpy(reinterpret_cast<char*>(memory_ptr) +
+                      vertexBufferOffsets[geometryNdx],
+                  data.data(), data.size() * sizeof(*data.data()));
+
+      if (geometries[geometryNdx]->IsTriangle()) {
+        accelerationStructureGeometriesKHR_[geometryNdx]
+            .geometry.triangles.vertexData = p;
+      } else if (geometries[geometryNdx]->IsAABB()) {
+        accelerationStructureGeometriesKHR_[geometryNdx].geometry.aabbs.data =
+            p;
+      } else {
+        assert(false && "unknown geometry type");
+      }
+      accelerationStructureGeometriesKHR_[geometryNdx].flags =
+          VkGeometryFlagsKHR(geometries[geometryNdx]->GetFlags());
+    }
+  }
+
+  return {};
+}
+
+Result BLAS::BuildBLAS(CommandBuffer* command_buffer) {
+  if (blas_ == VK_NULL_HANDLE)
+    return Result("Acceleration structure should be created first");
+  if (built_)
+    return {};
+
+  VkCommandBuffer cmdBuffer = command_buffer->GetVkCommandBuffer();
+
+  vertex_buffer_->CopyToDevice(command_buffer);
+
+  VkAccelerationStructureBuildRangeInfoKHR*
+      accelerationStructureBuildRangeInfoKHRPtr =
+          accelerationStructureBuildRangeInfoKHR_.data();
+
+  device_->GetPtrs()->vkCmdBuildAccelerationStructuresKHR(
+      cmdBuffer, 1, &accelerationStructureBuildGeometryInfoKHR_,
+      &accelerationStructureBuildRangeInfoKHRPtr);
+
+  const VkAccessFlags accessMasks =
+      VK_ACCESS_ACCELERATION_STRUCTURE_WRITE_BIT_KHR |
+      VK_ACCESS_ACCELERATION_STRUCTURE_READ_BIT_KHR;
+  const VkMemoryBarrier memBarrier{
+      VK_STRUCTURE_TYPE_MEMORY_BARRIER,
+      nullptr,
+      accessMasks,
+      accessMasks,
+  };
+
+  device_->GetPtrs()->vkCmdPipelineBarrier(
+      cmdBuffer, VK_PIPELINE_STAGE_ACCELERATION_STRUCTURE_BUILD_BIT_KHR,
+      VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, 0, 1, &memBarrier, 0, nullptr, 0,
+      nullptr);
+
+  built_ = true;
+
+  return {};
+}
+
+VkDeviceAddress BLAS::getVkBLASDeviceAddress() {
+  VkAccelerationStructureDeviceAddressInfoKHR info = {
+      VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_DEVICE_ADDRESS_INFO_KHR, nullptr,
+      blas_};
+
+  assert(blas_ != VK_NULL_HANDLE);
+
+  return device_->GetPtrs()->vkGetAccelerationStructureDeviceAddressKHR(
+      device_->GetVkDevice(), &info);
+}
+
+}  // namespace vulkan
+}  // namespace amber
diff --git a/src/vulkan/blas.h b/src/vulkan/blas.h
new file mode 100644
index 0000000..7a22097
--- /dev/null
+++ b/src/vulkan/blas.h
@@ -0,0 +1,58 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef SRC_VULKAN_BLAS_H_
+#define SRC_VULKAN_BLAS_H_
+
+#include <vector>
+#include <memory>
+
+#include "src/acceleration_structure.h"
+#include "src/vulkan/device.h"
+#include "src/vulkan/transfer_buffer.h"
+
+namespace amber {
+namespace vulkan {
+
+class BLAS {
+ public:
+  explicit BLAS(Device* device);
+  ~BLAS();
+
+  Result CreateBLAS(amber::BLAS* blas);
+  Result BuildBLAS(CommandBuffer* command_buffer);
+  VkAccelerationStructureKHR GetVkBLAS() { return blas_; }
+  VkDeviceAddress getVkBLASDeviceAddress();
+
+ private:
+  Device* device_ = nullptr;
+  VkAccelerationStructureKHR blas_ = VK_NULL_HANDLE;
+  bool built_ = false;
+  std::unique_ptr<TransferBuffer> buffer_;
+  std::unique_ptr<TransferBuffer> scratch_buffer_;
+  std::unique_ptr<TransferBuffer> vertex_buffer_;
+  VkAccelerationStructureBuildGeometryInfoKHR
+      accelerationStructureBuildGeometryInfoKHR_;
+  std::vector<VkAccelerationStructureGeometryKHR>
+      accelerationStructureGeometriesKHR_;
+  std::vector<VkAccelerationStructureBuildRangeInfoKHR>
+      accelerationStructureBuildRangeInfoKHR_;
+  std::vector<uint32_t> maxPrimitiveCounts_;
+};
+
+}  // namespace vulkan
+}  // namespace amber
+
+#endif  // SRC_VULKAN_BLAS_H_
diff --git a/src/vulkan/command_buffer.cc b/src/vulkan/command_buffer.cc
index b4d28a6..d5546a8 100644
--- a/src/vulkan/command_buffer.cc
+++ b/src/vulkan/command_buffer.cc
@@ -74,7 +74,7 @@ Result CommandBuffer::BeginRecording() {
 }
 
 Result CommandBuffer::SubmitAndReset(uint32_t timeout_ms,
-  bool pipeline_runtime_layer_enabled) {
+                                     bool pipeline_runtime_layer_enabled) {
   if (device_->GetPtrs()->vkEndCommandBuffer(command_) != VK_SUCCESS)
     return Result("Vulkan::Calling vkEndCommandBuffer Fail");
 
@@ -87,6 +87,7 @@ Result CommandBuffer::SubmitAndReset(uint32_t timeout_ms,
   submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
   submit_info.commandBufferCount = 1;
   submit_info.pCommandBuffers = &command_;
+
   if (device_->GetPtrs()->vkQueueSubmit(device_->GetVkQueue(), 1, &submit_info,
                                         fence_) != VK_SUCCESS) {
     return Result("Vulkan::Calling vkQueueSubmit Fail");
@@ -94,9 +95,12 @@ Result CommandBuffer::SubmitAndReset(uint32_t timeout_ms,
 
   guarded_ = false;
 
+  const uint64_t timeout_ns =
+      timeout_ms == static_cast<uint32_t>(~0u)  // honor 32bit infinity
+          ? ~0ull
+          : static_cast<uint64_t>(timeout_ms) * 1000ULL * 1000ULL;
   VkResult r = device_->GetPtrs()->vkWaitForFences(
-      device_->GetVkDevice(), 1, &fence_, VK_TRUE,
-      static_cast<uint64_t>(timeout_ms) * 1000ULL * 1000ULL /* nanosecond */);
+      device_->GetVkDevice(), 1, &fence_, VK_TRUE, timeout_ns);
   if (r == VK_TIMEOUT)
     return Result("Vulkan::Calling vkWaitForFences Timeout");
   if (r != VK_SUCCESS) {
@@ -118,12 +122,12 @@ Result CommandBuffer::SubmitAndReset(uint32_t timeout_ms,
     return Result("Vulkan::Calling vkWaitForFences Fail (" + result_str + ")");
   }
 
-    /*
-  google/vulkan-performance-layers requires a call to vkDeviceWaitIdle or
-  vkQueueWaitIdle in order to report the information. Since we want to be
-  able to use that layer in conjunction with Amber we need to somehow
-  communicate that the Amber script has completed.
-  */
+  /*
+google/vulkan-performance-layers requires a call to vkDeviceWaitIdle or
+vkQueueWaitIdle in order to report the information. Since we want to be
+able to use that layer in conjunction with Amber we need to somehow
+communicate that the Amber script has completed.
+*/
   if (pipeline_runtime_layer_enabled)
     device_->GetPtrs()->vkQueueWaitIdle(device_->GetVkQueue());
 
@@ -152,7 +156,7 @@ CommandBufferGuard::~CommandBufferGuard() {
 }
 
 Result CommandBufferGuard::Submit(uint32_t timeout_ms,
-  bool pipeline_runtime_layer_enabled) {
+                                  bool pipeline_runtime_layer_enabled) {
   assert(buffer_->guarded_);
   return buffer_->SubmitAndReset(timeout_ms, pipeline_runtime_layer_enabled);
 }
diff --git a/src/vulkan/command_buffer.h b/src/vulkan/command_buffer.h
index 349cce4..67bfa11 100644
--- a/src/vulkan/command_buffer.h
+++ b/src/vulkan/command_buffer.h
@@ -84,8 +84,7 @@ class CommandBufferGuard {
   Result GetResult() { return result_; }
 
   /// Submits and resets the internal command buffer.
-  Result Submit(uint32_t timeout_ms,
-                bool pipeline_runtime_layer_enabled);
+  Result Submit(uint32_t timeout_ms, bool pipeline_runtime_layer_enabled);
 
  private:
   Result result_;
diff --git a/src/vulkan/compute_pipeline.cc b/src/vulkan/compute_pipeline.cc
index dd7a990..23fd127 100644
--- a/src/vulkan/compute_pipeline.cc
+++ b/src/vulkan/compute_pipeline.cc
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 #include "src/vulkan/compute_pipeline.h"
+#include <cstdint>
 
 #include "src/vulkan/command_pool.h"
 #include "src/vulkan/device.h"
@@ -66,7 +67,10 @@ Result ComputePipeline::CreateVkComputePipeline(
   return {};
 }
 
-Result ComputePipeline::Compute(uint32_t x, uint32_t y, uint32_t z) {
+Result ComputePipeline::Compute(uint32_t x,
+                                uint32_t y,
+                                uint32_t z,
+                                bool is_timed_execution) {
   Result r = SendDescriptorDataToDeviceIfNeeded();
   if (!r.IsSuccess())
     return r;
@@ -85,7 +89,7 @@ Result ComputePipeline::Compute(uint32_t x, uint32_t y, uint32_t z) {
   // it must be submitted separately, because using a descriptor set
   // while updating it is not safe.
   UpdateDescriptorSetsIfNeeded();
-
+  CreateTimingQueryObjectIfNeeded(is_timed_execution);
   {
     CommandBufferGuard guard(GetCommandBuffer());
     if (!guard.IsRecording())
@@ -100,13 +104,15 @@ Result ComputePipeline::Compute(uint32_t x, uint32_t y, uint32_t z) {
     device_->GetPtrs()->vkCmdBindPipeline(command_->GetVkCommandBuffer(),
                                           VK_PIPELINE_BIND_POINT_COMPUTE,
                                           pipeline);
+    BeginTimerQuery();
     device_->GetPtrs()->vkCmdDispatch(command_->GetVkCommandBuffer(), x, y, z);
+    EndTimerQuery();
 
     r = guard.Submit(GetFenceTimeout(), GetPipelineRuntimeLayerEnabled());
     if (!r.IsSuccess())
       return r;
   }
-
+  DestroyTimingQueryObjectIfNeeded();
   r = ReadbackDescriptorsToHostDataQueue();
   if (!r.IsSuccess())
     return r;
diff --git a/src/vulkan/compute_pipeline.h b/src/vulkan/compute_pipeline.h
index d6597be..53f2221 100644
--- a/src/vulkan/compute_pipeline.h
+++ b/src/vulkan/compute_pipeline.h
@@ -36,7 +36,7 @@ class ComputePipeline : public Pipeline {
 
   Result Initialize(CommandPool* pool);
 
-  Result Compute(uint32_t x, uint32_t y, uint32_t z);
+  Result Compute(uint32_t x, uint32_t y, uint32_t z, bool is_timed_execution);
 
  private:
   Result CreateVkComputePipeline(const VkPipelineLayout& pipeline_layout,
diff --git a/src/vulkan/descriptor.cc b/src/vulkan/descriptor.cc
index 169c71c..fd605be 100644
--- a/src/vulkan/descriptor.cc
+++ b/src/vulkan/descriptor.cc
@@ -1,4 +1,5 @@
 // Copyright 2019 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -54,6 +55,8 @@ VkDescriptorType Descriptor::GetVkDescriptorType() const {
       return VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER;
     case DescriptorType::kStorageTexelBuffer:
       return VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER;
+    case DescriptorType::kTLAS:
+      return VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_KHR;
     default:
       assert(type_ == DescriptorType::kSampledImage);
       return VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE;
diff --git a/src/vulkan/descriptor.h b/src/vulkan/descriptor.h
index 88f6813..cc3c7c1 100644
--- a/src/vulkan/descriptor.h
+++ b/src/vulkan/descriptor.h
@@ -1,4 +1,5 @@
 // Copyright 2019 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -34,6 +35,7 @@ class BufferDescriptor;
 class ImageDescriptor;
 class BufferBackedDescriptor;
 class SamplerDescriptor;
+class TLASDescriptor;
 
 enum class DescriptorType : uint8_t {
   kStorageBuffer = 0,
@@ -45,7 +47,8 @@ enum class DescriptorType : uint8_t {
   kCombinedImageSampler,
   kUniformTexelBuffer,
   kStorageTexelBuffer,
-  kSampler
+  kSampler,
+  kTLAS
 };
 
 class Descriptor {
@@ -66,6 +69,7 @@ class Descriptor {
   virtual ImageDescriptor* AsImageDescriptor() { return nullptr; }
   virtual BufferBackedDescriptor* AsBufferBackedDescriptor() { return nullptr; }
   virtual SamplerDescriptor* AsSamplerDescriptor() { return nullptr; }
+  virtual TLASDescriptor* AsTLASDescriptor() { return nullptr; }
   uint32_t GetDescriptorSet() const { return descriptor_set_; }
   uint32_t GetBinding() const { return binding_; }
   VkDescriptorType GetVkDescriptorType() const;
diff --git a/src/vulkan/device.cc b/src/vulkan/device.cc
index 43a1d8b..061f130 100644
--- a/src/vulkan/device.cc
+++ b/src/vulkan/device.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -86,8 +87,14 @@ const char kSubgroupSupportedStagesCompute[] =
 const char kShaderSubgroupExtendedTypes[] =
     "ShaderSubgroupExtendedTypesFeatures.shaderSubgroupExtendedTypes";
 
-const char kIndexTypeUint8[] =
-    "IndexTypeUint8Features.indexTypeUint8";
+const char kIndexTypeUint8[] = "IndexTypeUint8Features.indexTypeUint8";
+
+const char kAccelerationStructure[] =
+    "AccelerationStructureFeaturesKHR.accelerationStructure";
+const char kBufferDeviceAddress[] =
+    "BufferDeviceAddressFeatures.bufferDeviceAddress";
+const char kRayTracingPipeline[] =
+    "RayTracingPipelineFeaturesKHR.rayTracingPipeline";
 
 struct BaseOutStructure {
   VkStructureType sType;
@@ -404,12 +411,14 @@ Device::Device(VkInstance instance,
                VkPhysicalDevice physical_device,
                uint32_t queue_family_index,
                VkDevice device,
-               VkQueue queue)
+               VkQueue queue,
+               Delegate* delegate)
     : instance_(instance),
       physical_device_(physical_device),
       device_(device),
       queue_(queue),
-      queue_family_index_(queue_family_index) {}
+      queue_family_index_(queue_family_index),
+      delegate_(delegate) {}
 
 Device::~Device() = default;
 
@@ -443,15 +452,22 @@ bool Device::SupportsApiVersion(uint32_t major,
 #pragma clang diagnostic pop
 }
 
+void Device::ReportExecutionTiming(double time_in_ms) {
+  if (delegate_) {
+    delegate_->ReportExecutionTiming(time_in_ms);
+  }
+}
+
 Result Device::Initialize(
     PFN_vkGetInstanceProcAddr getInstanceProcAddr,
-    Delegate* delegate,
     const std::vector<std::string>& required_features,
+    const std::vector<std::string>& required_properties,
     const std::vector<std::string>& required_device_extensions,
     const VkPhysicalDeviceFeatures& available_features,
     const VkPhysicalDeviceFeatures2KHR& available_features2,
+    const VkPhysicalDeviceProperties2KHR& available_properties2,
     const std::vector<std::string>& available_extensions) {
-  Result r = LoadVulkanPointers(getInstanceProcAddr, delegate);
+  Result r = LoadVulkanPointers(getInstanceProcAddr, delegate_);
   if (!r.IsSuccess())
     return r;
 
@@ -474,11 +490,18 @@ Result Device::Initialize(
   VkPhysicalDeviceVulkan11Features* vulkan11_ptrs = nullptr;
   VkPhysicalDeviceVulkan12Features* vulkan12_ptrs = nullptr;
   VkPhysicalDeviceVulkan13Features* vulkan13_ptrs = nullptr;
+  VkPhysicalDeviceVulkan14Features* vulkan14_ptrs = nullptr;
   VkPhysicalDeviceSubgroupSizeControlFeaturesEXT*
       subgroup_size_control_features = nullptr;
   VkPhysicalDeviceShaderSubgroupExtendedTypesFeatures*
       shader_subgroup_extended_types_ptrs = nullptr;
   VkPhysicalDeviceIndexTypeUint8FeaturesEXT* index_type_uint8_ptrs = nullptr;
+  VkPhysicalDeviceAccelerationStructureFeaturesKHR*
+      acceleration_structure_ptrs = nullptr;
+  VkPhysicalDeviceBufferDeviceAddressFeatures* bda_ptrs = nullptr;
+  VkPhysicalDeviceRayTracingPipelineFeaturesKHR* ray_tracing_pipeline_ptrs =
+      nullptr;
+
   void* ptr = available_features2.pNext;
   while (ptr != nullptr) {
     BaseOutStructure* s = static_cast<BaseOutStructure*>(ptr);
@@ -513,6 +536,19 @@ Result Device::Initialize(
         index_type_uint8_ptrs =
             static_cast<VkPhysicalDeviceIndexTypeUint8FeaturesEXT*>(ptr);
         break;
+      // NOLINTNEXTLINE(whitespace/line_length)
+      case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ACCELERATION_STRUCTURE_FEATURES_KHR:
+        acceleration_structure_ptrs =
+            static_cast<VkPhysicalDeviceAccelerationStructureFeaturesKHR*>(ptr);
+        break;
+      case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES:
+        bda_ptrs =
+            static_cast<VkPhysicalDeviceBufferDeviceAddressFeatures*>(ptr);
+        break;
+      case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_PIPELINE_FEATURES_KHR:
+        ray_tracing_pipeline_ptrs =
+            static_cast<VkPhysicalDeviceRayTracingPipelineFeaturesKHR*>(ptr);
+        break;
       case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_1_FEATURES:
         vulkan11_ptrs = static_cast<VkPhysicalDeviceVulkan11Features*>(ptr);
         break;
@@ -520,8 +556,11 @@ Result Device::Initialize(
         vulkan12_ptrs = static_cast<VkPhysicalDeviceVulkan12Features*>(ptr);
         break;
       case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES:
-          vulkan13_ptrs = static_cast<VkPhysicalDeviceVulkan13Features*>(ptr);
-          break;
+        vulkan13_ptrs = static_cast<VkPhysicalDeviceVulkan13Features*>(ptr);
+        break;
+      case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_4_FEATURES:
+        vulkan14_ptrs = static_cast<VkPhysicalDeviceVulkan14Features*>(ptr);
+        break;
       default:
         break;
     }
@@ -575,13 +614,53 @@ Result Device::Initialize(
       return amber::Result(
           "Subgroup extended types requested but feature not returned");
     }
-    if (feature == kIndexTypeUint8 &&
-        (index_type_uint8_ptrs == nullptr ||
-         index_type_uint8_ptrs->indexTypeUint8 != VK_TRUE)) {
+    if (feature == kAccelerationStructure) {
+      if (acceleration_structure_ptrs == nullptr)
+        return amber::Result(
+            "Acceleration structure requested but feature not returned");
+      if (ptrs_.vkCreateAccelerationStructureKHR == nullptr)
+        return amber::Result(
+            "vkCreateAccelerationStructureKHR is required, but not provided");
+      if (ptrs_.vkDestroyAccelerationStructureKHR == nullptr)
+        return amber::Result(
+            "vkDestroyAccelerationStructureKHR is required, but not provided");
+      if (ptrs_.vkGetAccelerationStructureBuildSizesKHR == nullptr)
+        return amber::Result(
+            "vkGetAccelerationStructureBuildSizesKHR is required, but not "
+            "provided");
+      if (ptrs_.vkBuildAccelerationStructuresKHR == nullptr)
+        return amber::Result(
+            "vkBuildAccelerationStructuresKHR is required, but not "
+            "provided");
+      if (ptrs_.vkCmdBuildAccelerationStructuresKHR == nullptr)
+        return amber::Result(
+            "vkCmdBuildAccelerationStructuresKHR is required, but not "
+            "provided");
+      if (ptrs_.vkGetAccelerationStructureDeviceAddressKHR == nullptr)
+        return amber::Result(
+            "vkGetAccelerationStructureDeviceAddressKHR is required, but not "
+            "provided");
+    }
+    if (feature == kBufferDeviceAddress && bda_ptrs == nullptr &&
+        vulkan12_ptrs == nullptr) {
       return amber::Result(
-          "Index type uint8_t requested but feature not returned");
+          "Buffer device address requested but feature not returned");
+    }
+    if (feature == kRayTracingPipeline) {
+      if (ray_tracing_pipeline_ptrs == nullptr)
+        return amber::Result(
+            "Ray tracing pipeline requested but feature not returned");
+      if (ptrs_.vkCreateRayTracingPipelinesKHR == nullptr)
+        return amber::Result(
+            "vkCreateRayTracingPipelinesKHR is required, but not provided");
+      if (ptrs_.vkCmdTraceRaysKHR == nullptr)
+        return amber::Result(
+            "vkCmdTraceRaysKHR is required, but not provided");
+      if (ptrs_.vkGetRayTracingShaderGroupHandlesKHR == nullptr)
+        return amber::Result(
+            "vkGetRayTracingShaderGroupHandlesKHR is required, but not "
+            "provided");
     }
-
 
     // Next check the fields of the feature structures.
 
@@ -668,6 +747,10 @@ Result Device::Initialize(
           vulkan12_ptrs->shaderSubgroupExtendedTypes != VK_TRUE) {
         return amber::Result("Missing subgroup extended types");
       }
+      if (feature == kBufferDeviceAddress &&
+          vulkan12_ptrs->bufferDeviceAddress != VK_TRUE) {
+        return amber::Result("Missing buffer device address");
+      }
     } else {
       // Vulkan 1.2 structure was not found. Use separate structures per each
       // feature.
@@ -695,18 +778,22 @@ Result Device::Initialize(
               VK_TRUE) {
         return amber::Result("Missing subgroup extended types");
       }
+      if (feature == kBufferDeviceAddress &&
+          bda_ptrs->bufferDeviceAddress != VK_TRUE) {
+        return amber::Result("Missing buffer device address");
+      }
     }
 
     // If Vulkan 1.3 structure exists the features are set there.
     if (vulkan13_ptrs) {
-        if (feature == kSubgroupSizeControl &&
-            vulkan13_ptrs->subgroupSizeControl != VK_TRUE) {
-          return amber::Result("Missing subgroup size control feature");
-        }
-        if (feature == kComputeFullSubgroups &&
-            vulkan13_ptrs->computeFullSubgroups != VK_TRUE) {
-          return amber::Result("Missing compute full subgroups feature");
-        }
+      if (feature == kSubgroupSizeControl &&
+          vulkan13_ptrs->subgroupSizeControl != VK_TRUE) {
+        return amber::Result("Missing subgroup size control feature");
+      }
+      if (feature == kComputeFullSubgroups &&
+          vulkan13_ptrs->computeFullSubgroups != VK_TRUE) {
+        return amber::Result("Missing compute full subgroups feature");
+      }
     } else {
       if (feature == kSubgroupSizeControl &&
           subgroup_size_control_features->subgroupSizeControl != VK_TRUE) {
@@ -717,6 +804,22 @@ Result Device::Initialize(
         return amber::Result("Missing compute full subgroups feature");
       }
     }
+
+    // If Vulkan 1.4 structure exists the features are set there.
+    if (vulkan14_ptrs) {
+      if (feature == kIndexTypeUint8 &&
+          vulkan14_ptrs->indexTypeUint8 != VK_TRUE) {
+        return amber::Result(
+            "Index type uint8_t requested but feature not returned");
+      }
+    } else {
+      if (feature == kIndexTypeUint8 &&
+          (index_type_uint8_ptrs == nullptr ||
+           index_type_uint8_ptrs->indexTypeUint8 != VK_TRUE)) {
+        return amber::Result(
+            "Index type uint8_t requested but feature not returned");
+      }
+    }
   }
 
   if (!AreAllExtensionsSupported(available_extensions,
@@ -726,6 +829,86 @@ Result Device::Initialize(
         "required extensions");
   }
 
+  const bool needs_shader_group_handle_size =
+      std::find(required_features.begin(), required_features.end(),
+                kAccelerationStructure) != required_features.end();
+
+  if (needs_shader_group_handle_size) {
+    VkPhysicalDeviceRayTracingPipelinePropertiesKHR rt_pipeline_properties = {};
+    rt_pipeline_properties.sType =
+        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_PIPELINE_PROPERTIES_KHR;
+
+    VkPhysicalDeviceProperties2KHR properties2 = {};
+    properties2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
+    properties2.pNext = &rt_pipeline_properties;
+
+    ptrs_.vkGetPhysicalDeviceProperties2(physical_device_, &properties2);
+
+    shader_group_handle_size_ = rt_pipeline_properties.shaderGroupHandleSize;
+  }
+
+  VkPhysicalDeviceVulkan12Properties* pv12 = nullptr;
+  VkPhysicalDeviceFloatControlsProperties* pfc = nullptr;
+
+  ptr = available_properties2.pNext;
+  while (ptr != nullptr) {
+    BaseOutStructure* s = static_cast<BaseOutStructure*>(ptr);
+    switch (s->sType) {
+      case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_PROPERTIES:
+        pv12 = static_cast<VkPhysicalDeviceVulkan12Properties*>(ptr);
+        break;
+      case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FLOAT_CONTROLS_PROPERTIES_KHR:
+        pfc = static_cast<VkPhysicalDeviceFloatControlsPropertiesKHR*>(ptr);
+        break;
+      default:
+        break;
+    }
+    ptr = s->pNext;
+  }
+
+#define CHK_P(R, P, NAME, S1, S2)                         \
+  do {                                                    \
+    if (R == -1 && P == #NAME)                            \
+      R = ((S1 && S1->NAME) || (S2 && S2->NAME)) ? 1 : 0; \
+  } while (false)
+
+  for (const std::string& prop : required_properties) {
+    const size_t dot_pos = prop.find('.');
+    const size_t dot_found = dot_pos != std::string::npos;
+    const std::string prefix = dot_found ? prop.substr(0, dot_pos) : "";
+    const std::string name = dot_found ? prop.substr(dot_pos + 1) : prop;
+    int supported = -1;
+
+    if (supported == -1 && prefix == "FloatControlsProperties") {
+      if (pfc == nullptr && pv12 == nullptr)
+        return Result(
+            "Vulkan: Device::Initialize given physical device does not support "
+            "required float control properties");
+
+      CHK_P(supported, name, shaderSignedZeroInfNanPreserveFloat16, pfc, pv12);
+      CHK_P(supported, name, shaderSignedZeroInfNanPreserveFloat32, pfc, pv12);
+      CHK_P(supported, name, shaderSignedZeroInfNanPreserveFloat64, pfc, pv12);
+      CHK_P(supported, name, shaderDenormPreserveFloat16, pfc, pv12);
+      CHK_P(supported, name, shaderDenormPreserveFloat32, pfc, pv12);
+      CHK_P(supported, name, shaderDenormPreserveFloat64, pfc, pv12);
+      CHK_P(supported, name, shaderDenormFlushToZeroFloat16, pfc, pv12);
+      CHK_P(supported, name, shaderDenormFlushToZeroFloat32, pfc, pv12);
+      CHK_P(supported, name, shaderDenormFlushToZeroFloat64, pfc, pv12);
+      CHK_P(supported, name, shaderRoundingModeRTEFloat16, pfc, pv12);
+      CHK_P(supported, name, shaderRoundingModeRTEFloat32, pfc, pv12);
+      CHK_P(supported, name, shaderRoundingModeRTEFloat64, pfc, pv12);
+      CHK_P(supported, name, shaderRoundingModeRTZFloat16, pfc, pv12);
+      CHK_P(supported, name, shaderRoundingModeRTZFloat32, pfc, pv12);
+      CHK_P(supported, name, shaderRoundingModeRTZFloat64, pfc, pv12);
+    }
+
+    if (supported == 0)
+      return Result("Vulkan: Device::Initialize missing " + prop + " property");
+
+    if (supported == -1)
+      return Result("Vulkan: Device::Initialize property not handled " + prop);
+  }
+
   ptrs_.vkGetPhysicalDeviceMemoryProperties(physical_device_,
                                             &physical_memory_properties_);
 
@@ -944,6 +1127,14 @@ uint32_t Device::GetMaxPushConstants() const {
   return physical_device_properties_.limits.maxPushConstantsSize;
 }
 
+bool Device::IsTimestampComputeAndGraphicsSupported() const {
+  return physical_device_properties_.limits.timestampComputeAndGraphics;
+}
+
+float Device::GetTimestampPeriod() const {
+  return physical_device_properties_.limits.timestampPeriod;
+}
+
 bool Device::IsDescriptorSetInBounds(uint32_t descriptor_set) const {
   VkPhysicalDeviceProperties properties = VkPhysicalDeviceProperties();
   GetPtrs()->vkGetPhysicalDeviceProperties(physical_device_, &properties);
@@ -1396,5 +1587,9 @@ uint32_t Device::GetMaxSubgroupSize() const {
   return subgroup_size_control_properties_.maxSubgroupSize;
 }
 
+uint32_t Device::GetRayTracingShaderGroupHandleSize() const {
+  return shader_group_handle_size_;
+}
+
 }  // namespace vulkan
 }  // namespace amber
diff --git a/src/vulkan/device.h b/src/vulkan/device.h
index ff76c0f..0ce0529 100644
--- a/src/vulkan/device.h
+++ b/src/vulkan/device.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -41,15 +42,17 @@ class Device {
          VkPhysicalDevice physical_device,
          uint32_t queue_family_index,
          VkDevice device,
-         VkQueue queue);
+         VkQueue queue,
+         Delegate* delegate);
   virtual ~Device();
 
   Result Initialize(PFN_vkGetInstanceProcAddr getInstanceProcAddr,
-                    Delegate* delegate,
                     const std::vector<std::string>& required_features,
+                    const std::vector<std::string>& required_properties,
                     const std::vector<std::string>& required_device_extensions,
                     const VkPhysicalDeviceFeatures& available_features,
                     const VkPhysicalDeviceFeatures2KHR& available_features2,
+                    const VkPhysicalDeviceProperties2KHR& available_properties2,
                     const std::vector<std::string>& available_extensions);
 
   /// Returns true if |format| and the |buffer|s buffer type combination is
@@ -88,6 +91,17 @@ class Device {
   /// Returns the maximum required subgroup size or 0 if subgroup size control
   /// is not supported.
   uint32_t GetMaxSubgroupSize() const;
+  /// Returns ray tracing shader group handle size.
+  uint32_t GetRayTracingShaderGroupHandleSize() const;
+
+  // Returns true if we have support for timestamps.
+  bool IsTimestampComputeAndGraphicsSupported() const;
+
+  // Returns a float used to convert between timestamps and actual elapsed time.
+  float GetTimestampPeriod() const;
+
+  // Each timed execution reports timing to the device and on to the delegate.
+  void ReportExecutionTiming(double time_in_ns);
 
  private:
   Result LoadVulkanPointers(PFN_vkGetInstanceProcAddr, Delegate* delegate);
@@ -102,8 +116,11 @@ class Device {
   VkDevice device_ = VK_NULL_HANDLE;
   VkQueue queue_ = VK_NULL_HANDLE;
   uint32_t queue_family_index_ = 0;
+  uint32_t shader_group_handle_size_ = 0;
 
   VulkanPtrs ptrs_;
+
+  Delegate* delegate_ = nullptr;
 };
 
 }  // namespace vulkan
diff --git a/src/vulkan/engine_vulkan.cc b/src/vulkan/engine_vulkan.cc
index b0842ec..18e506a 100644
--- a/src/vulkan/engine_vulkan.cc
+++ b/src/vulkan/engine_vulkan.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -23,6 +24,7 @@
 #include "src/type_parser.h"
 #include "src/vulkan/compute_pipeline.h"
 #include "src/vulkan/graphics_pipeline.h"
+#include "src/vulkan/raytracing_pipeline.h"
 
 namespace amber {
 namespace vulkan {
@@ -48,6 +50,24 @@ Result ToVkShaderStage(ShaderType type, VkShaderStageFlagBits* ret) {
     case kShaderTypeTessellationEvaluation:
       *ret = VK_SHADER_STAGE_TESSELLATION_EVALUATION_BIT;
       break;
+    case kShaderTypeRayGeneration:
+      *ret = VK_SHADER_STAGE_RAYGEN_BIT_KHR;
+      break;
+    case kShaderTypeAnyHit:
+      *ret = VK_SHADER_STAGE_ANY_HIT_BIT_KHR;
+      break;
+    case kShaderTypeClosestHit:
+      *ret = VK_SHADER_STAGE_CLOSEST_HIT_BIT_KHR;
+      break;
+    case kShaderTypeMiss:
+      *ret = VK_SHADER_STAGE_MISS_BIT_KHR;
+      break;
+    case kShaderTypeIntersection:
+      *ret = VK_SHADER_STAGE_INTERSECTION_BIT_KHR;
+      break;
+    case kShaderTypeCall:
+      *ret = VK_SHADER_STAGE_CALLABLE_BIT_KHR;
+      break;
     case kShaderTypeCompute:
       *ret = VK_SHADER_STAGE_COMPUTE_BIT;
       break;
@@ -85,6 +105,9 @@ EngineVulkan::~EngineVulkan() {
       device_->GetPtrs()->vkDestroyShaderModule(vk_device, shader.second,
                                                 nullptr);
     }
+    pipeline_map_.clear();
+    tlases_.clear();
+    blases_.clear();
   }
 }
 
@@ -92,6 +115,7 @@ Result EngineVulkan::Initialize(
     EngineConfig* config,
     Delegate* delegate,
     const std::vector<std::string>& features,
+    const std::vector<std::string>& properties,
     const std::vector<std::string>& instance_extensions,
     const std::vector<std::string>& device_extensions) {
   if (device_)
@@ -115,12 +139,12 @@ Result EngineVulkan::Initialize(
 
   device_ = MakeUnique<Device>(vk_config->instance, vk_config->physical_device,
                                vk_config->queue_family_index, vk_config->device,
-                               vk_config->queue);
+                               vk_config->queue, delegate);
 
   Result r = device_->Initialize(
-      vk_config->vkGetInstanceProcAddr, delegate, features, device_extensions,
+      vk_config->vkGetInstanceProcAddr, features, properties, device_extensions,
       vk_config->available_features, vk_config->available_features2,
-      vk_config->available_device_extensions);
+      vk_config->available_properties2, vk_config->available_device_extensions);
   if (!r.IsSuccess())
     return r;
 
@@ -139,8 +163,8 @@ Result EngineVulkan::CreatePipeline(amber::Pipeline* pipeline) {
   pipeline_map_[pipeline] = PipelineInfo();
   auto& info = pipeline_map_[pipeline];
 
-  for (const auto& shader_info : pipeline->GetShaders()) {
-    Result r = SetShader(pipeline, shader_info);
+  for (size_t i = 0; i < pipeline->GetShaders().size(); i++) {
+    Result r = SetShader(pipeline, pipeline->GetShaders()[i], i);
     if (!r.IsSuccess())
       return r;
   }
@@ -168,13 +192,24 @@ Result EngineVulkan::CreatePipeline(amber::Pipeline* pipeline) {
 
   const auto& engine_data = GetEngineData();
   std::unique_ptr<Pipeline> vk_pipeline;
-  if (pipeline->GetType() == PipelineType::kCompute) {
+  if (pipeline->GetType() == PipelineType::kRayTracing) {
+    std::vector<VkRayTracingShaderGroupCreateInfoKHR> shader_group_create_info;
+
+    r = GetVkShaderGroupInfo(pipeline, &shader_group_create_info);
+    if (!r.IsSuccess())
+      return r;
+
+    vk_pipeline = MakeUnique<RayTracingPipeline>(
+        device_.get(), &blases_, &tlases_, engine_data.fence_timeout_ms,
+        engine_data.pipeline_runtime_layer_enabled, stage_create_info,
+        pipeline->GetCreateFlags());
+    r = vk_pipeline->AsRayTracingPipeline()->Initialize(
+        pool_.get(), shader_group_create_info);
+  } else if (pipeline->GetType() == PipelineType::kCompute) {
     vk_pipeline = MakeUnique<ComputePipeline>(
         device_.get(), engine_data.fence_timeout_ms,
         engine_data.pipeline_runtime_layer_enabled, stage_create_info);
     r = vk_pipeline->AsCompute()->Initialize(pool_.get());
-    if (!r.IsSuccess())
-      return r;
   } else {
     vk_pipeline = MakeUnique<GraphicsPipeline>(
         device_.get(), pipeline->GetColorAttachments(),
@@ -188,10 +223,11 @@ Result EngineVulkan::CreatePipeline(amber::Pipeline* pipeline) {
     r = vk_pipeline->AsGraphics()->Initialize(pipeline->GetFramebufferWidth(),
                                               pipeline->GetFramebufferHeight(),
                                               pool_.get());
-    if (!r.IsSuccess())
-      return r;
   }
 
+  if (!r.IsSuccess())
+    return r;
+
   info.vk_pipeline = std::move(vk_pipeline);
 
   // Set the entry point names for the pipeline.
@@ -286,21 +322,38 @@ Result EngineVulkan::CreatePipeline(amber::Pipeline* pipeline) {
       return r;
   }
 
+  if (info.vk_pipeline->IsRayTracing()) {
+    for (const auto& tlas_info : pipeline->GetTLASes()) {
+      auto cmd = MakeUnique<TLASCommand>(pipeline);
+      cmd->SetDescriptorSet(tlas_info.descriptor_set);
+      cmd->SetBinding(tlas_info.binding);
+      cmd->SetTLAS(tlas_info.tlas);
+
+      r = info.vk_pipeline->AddTLASDescriptor(cmd.get());
+      if (!r.IsSuccess())
+        return r;
+    }
+  }
+
   return {};
 }
 
 Result EngineVulkan::SetShader(amber::Pipeline* pipeline,
-                               const amber::Pipeline::ShaderInfo& shader) {
+                               const amber::Pipeline::ShaderInfo& shader,
+                               size_t index) {
+  const bool rt = pipeline->IsRayTracing();
   const auto type = shader.GetShaderType();
   const auto& data = shader.GetData();
   const auto shader_name = shader.GetShader()->GetName();
   auto& info = pipeline_map_[pipeline];
 
-  auto it = info.shader_info.find(type);
-  if (it != info.shader_info.end())
-    return Result("Vulkan::Setting Duplicated Shader Types Fail");
+  if (!rt) {
+    auto it = info.shader_info.find(type);
+    if (it != info.shader_info.end())
+      return Result("Vulkan::Setting Duplicated Shader Types Fail");
+  }
 
-  VkShaderModule shader_module;
+  VkShaderModule shader_module = VK_NULL_HANDLE;
   if (shaders_.find(shader_name) != shaders_.end()) {
     shader_module = shaders_[shader_name];
   } else {
@@ -318,7 +371,18 @@ Result EngineVulkan::SetShader(amber::Pipeline* pipeline,
     shaders_[shader_name] = shader_module;
   }
 
-  info.shader_info[type].shader = shader_module;
+  if (!rt) {
+    info.shader_info[type].shader = shader_module;
+  } else {
+    assert(index <= info.shader_info_rt.size());
+    if (info.shader_info_rt.size() == index) {
+      info.shader_info_rt.push_back(PipelineInfo::ShaderInfo());
+    }
+    info.shader_info_rt[index].shader = shader_module;
+    info.shader_info_rt[index].type = type;
+
+    return {};
+  }
 
   for (auto& shader_info : pipeline->GetShaders()) {
     if (shader_info.GetShaderType() != type)
@@ -348,6 +412,7 @@ Result EngineVulkan::SetShader(amber::Pipeline* pipeline,
             "device.");
       }
     }
+
     info.shader_info[type].required_subgroup_size = required_subgroup_size_uint;
 
     info.shader_info[type].create_flags = 0;
@@ -387,49 +452,139 @@ Result EngineVulkan::SetShader(amber::Pipeline* pipeline,
   return {};
 }
 
+Result EngineVulkan::GetVkShaderStageInfo(
+    ShaderType shader_type,
+    const PipelineInfo::ShaderInfo& shader_info,
+    VkPipelineShaderStageCreateInfo* stage_info) {
+  VkShaderStageFlagBits stage = VK_SHADER_STAGE_FLAG_BITS_MAX_ENUM;
+  Result r = ToVkShaderStage(shader_type, &stage);
+  if (!r.IsSuccess())
+    return r;
+
+  *stage_info = VkPipelineShaderStageCreateInfo();
+  stage_info->sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
+  stage_info->flags = shader_info.create_flags;
+  stage_info->stage = stage;
+  stage_info->module = shader_info.shader;
+
+  stage_info->pName = nullptr;
+  if (shader_info.specialization_entries &&
+      !shader_info.specialization_entries->empty()) {
+    stage_info->pSpecializationInfo = shader_info.specialization_info.get();
+  }
+
+  return {};
+}
+
 Result EngineVulkan::GetVkShaderStageInfo(
     amber::Pipeline* pipeline,
     std::vector<VkPipelineShaderStageCreateInfo>* out) {
   auto& info = pipeline_map_[pipeline];
 
-  std::vector<VkPipelineShaderStageCreateInfo> stage_info(
-      info.shader_info.size());
-  uint32_t stage_count = 0;
-  for (auto& it : info.shader_info) {
-    VkShaderStageFlagBits stage = VK_SHADER_STAGE_FLAG_BITS_MAX_ENUM;
-    Result r = ToVkShaderStage(it.first, &stage);
-    if (!r.IsSuccess())
-      return r;
-
-    stage_info[stage_count] = VkPipelineShaderStageCreateInfo();
-    stage_info[stage_count].sType =
-        VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
-    stage_info[stage_count].flags = it.second.create_flags;
-    stage_info[stage_count].stage = stage;
-    stage_info[stage_count].module = it.second.shader;
-    stage_info[stage_count].pName = nullptr;
-    if (it.second.specialization_entries &&
-        !it.second.specialization_entries->empty()) {
-      stage_info[stage_count].pSpecializationInfo =
-          it.second.specialization_info.get();
+  const size_t size = pipeline->IsRayTracing() ? info.shader_info_rt.size()
+                                               : info.shader_info.size();
+  std::vector<VkPipelineShaderStageCreateInfo> stage_info(size);
+  if (pipeline->IsRayTracing()) {
+    for (size_t i = 0; i < info.shader_info_rt.size(); i++) {
+      Result r = GetVkShaderStageInfo(info.shader_info_rt[i].type,
+                                      info.shader_info_rt[i], &stage_info[i]);
+      if (!r.IsSuccess())
+        return r;
     }
-
-    if (stage == VK_SHADER_STAGE_COMPUTE_BIT &&
-        it.second.required_subgroup_size > 0) {
-      VkPipelineShaderStageRequiredSubgroupSizeCreateInfoEXT* pSubgroupSize =
-          new VkPipelineShaderStageRequiredSubgroupSizeCreateInfoEXT();
-      pSubgroupSize->sType =
-          VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_REQUIRED_SUBGROUP_SIZE_CREATE_INFO_EXT;  // NOLINT(whitespace/line_length)
-      pSubgroupSize->pNext = nullptr;
-      pSubgroupSize->requiredSubgroupSize = it.second.required_subgroup_size;
-      stage_info[stage_count].pNext = pSubgroupSize;
+  } else {
+    uint32_t stage_count = 0;
+    for (auto& it : info.shader_info) {
+      Result r =
+          GetVkShaderStageInfo(it.first, it.second, &stage_info[stage_count]);
+      if (!r.IsSuccess())
+        return r;
+
+      if (it.first == kShaderTypeCompute &&
+          it.second.required_subgroup_size > 0) {
+        VkPipelineShaderStageRequiredSubgroupSizeCreateInfoEXT* pSubgroupSize =
+            new VkPipelineShaderStageRequiredSubgroupSizeCreateInfoEXT();
+        pSubgroupSize->sType =
+            VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_REQUIRED_SUBGROUP_SIZE_CREATE_INFO_EXT;  // NOLINT(whitespace/line_length)
+        pSubgroupSize->pNext = nullptr;
+        pSubgroupSize->requiredSubgroupSize = it.second.required_subgroup_size;
+        stage_info[stage_count].pNext = pSubgroupSize;
+      }
+      ++stage_count;
     }
-    ++stage_count;
   }
   *out = stage_info;
   return {};
 }
 
+Result EngineVulkan::GetVkShaderGroupInfo(
+    amber::Pipeline* pipeline,
+    std::vector<VkRayTracingShaderGroupCreateInfoKHR>* out) {
+  auto& groups = pipeline->GetShaderGroups();
+  const size_t shader_group_count = groups.size();
+
+  out->clear();
+  out->reserve(shader_group_count);
+
+  for (size_t i = 0; i < shader_group_count; ++i) {
+    Result r;
+    auto& g = groups[i];
+    ShaderGroup* sg = g.get();
+
+    if (sg == nullptr)
+      return Result("Invalid shader group");
+
+    VkRayTracingShaderGroupCreateInfoKHR group_info = {
+        VK_STRUCTURE_TYPE_RAY_TRACING_SHADER_GROUP_CREATE_INFO_KHR,
+        nullptr,
+        VK_RAY_TRACING_SHADER_GROUP_TYPE_MAX_ENUM_KHR,
+        VK_SHADER_UNUSED_KHR,
+        VK_SHADER_UNUSED_KHR,
+        VK_SHADER_UNUSED_KHR,
+        VK_SHADER_UNUSED_KHR,
+        nullptr};
+
+    if (sg->IsGeneralGroup()) {
+      group_info.type = VK_RAY_TRACING_SHADER_GROUP_TYPE_GENERAL_KHR;
+      r = pipeline->GetShaderIndex(sg->GetGeneralShader(),
+                                   &group_info.generalShader);
+      if (!r.IsSuccess())
+        return r;
+    } else if (sg->IsHitGroup()) {
+      group_info.type =
+          sg->GetIntersectionShader() == nullptr
+              ? VK_RAY_TRACING_SHADER_GROUP_TYPE_TRIANGLES_HIT_GROUP_KHR
+              : VK_RAY_TRACING_SHADER_GROUP_TYPE_PROCEDURAL_HIT_GROUP_KHR;
+
+      if (sg->GetClosestHitShader()) {
+        r = pipeline->GetShaderIndex(sg->GetClosestHitShader(),
+                                     &group_info.closestHitShader);
+        if (!r.IsSuccess())
+          return r;
+      }
+
+      if (sg->GetAnyHitShader()) {
+        r = pipeline->GetShaderIndex(sg->GetAnyHitShader(),
+                                     &group_info.anyHitShader);
+        if (!r.IsSuccess())
+          return r;
+      }
+
+      if (sg->GetIntersectionShader()) {
+        r = pipeline->GetShaderIndex(sg->GetIntersectionShader(),
+                                     &group_info.intersectionShader);
+        if (!r.IsSuccess())
+          return r;
+      }
+    } else {
+      return Result("Uninitialized shader group");
+    }
+
+    out->push_back(group_info);
+  }
+
+  return {};
+}
+
 Result EngineVulkan::DoClearColor(const ClearColorCommand* command) {
   auto& info = pipeline_map_[command->GetPipeline()];
   if (!info.vk_pipeline->IsGraphics())
@@ -515,13 +670,17 @@ Result EngineVulkan::DoDrawRect(const DrawRectCommand* command) {
                          buf->GetFormat()->SizeInBytes());
 
   DrawArraysCommand draw(command->GetPipeline(), *command->GetPipelineData());
+  if (command->IsTimedExecution()) {
+    draw.SetTimedExecution();
+  }
   draw.SetTopology(command->IsPatch() ? Topology::kPatchList
                                       : Topology::kTriangleStrip);
   draw.SetFirstVertexIndex(0);
   draw.SetVertexCount(4);
   draw.SetInstanceCount(1);
 
-  Result r = graphics->Draw(&draw, vertex_buffer.get());
+  Result r =
+      graphics->Draw(&draw, vertex_buffer.get(), command->IsTimedExecution());
   if (!r.IsSuccess())
     return r;
 
@@ -603,12 +762,16 @@ Result EngineVulkan::DoDrawGrid(const DrawGridCommand* command) {
                          buf->GetFormat()->SizeInBytes());
 
   DrawArraysCommand draw(command->GetPipeline(), *command->GetPipelineData());
+  if (command->IsTimedExecution()) {
+    draw.SetTimedExecution();
+  }
   draw.SetTopology(Topology::kTriangleList);
   draw.SetFirstVertexIndex(0);
   draw.SetVertexCount(vertices);
   draw.SetInstanceCount(1);
 
-  Result r = graphics->Draw(&draw, vertex_buffer.get());
+  Result r =
+      graphics->Draw(&draw, vertex_buffer.get(), command->IsTimedExecution());
   if (!r.IsSuccess())
     return r;
 
@@ -620,17 +783,79 @@ Result EngineVulkan::DoDrawArrays(const DrawArraysCommand* command) {
   if (!info.vk_pipeline)
     return Result("Vulkan::DrawArrays for Non-Graphics Pipeline");
 
-  return info.vk_pipeline->AsGraphics()->Draw(command,
-                                              info.vertex_buffer.get());
+  return info.vk_pipeline->AsGraphics()->Draw(command, info.vertex_buffer.get(),
+                                              command->IsTimedExecution());
 }
 
 Result EngineVulkan::DoCompute(const ComputeCommand* command) {
   auto& info = pipeline_map_[command->GetPipeline()];
-  if (info.vk_pipeline->IsGraphics())
-    return Result("Vulkan: Compute called for graphics pipeline.");
+  if (!info.vk_pipeline->IsCompute())
+    return Result("Vulkan: Compute called for non-compute pipeline.");
 
   return info.vk_pipeline->AsCompute()->Compute(
-      command->GetX(), command->GetY(), command->GetZ());
+      command->GetX(), command->GetY(), command->GetZ(),
+      command->IsTimedExecution());
+}
+
+Result EngineVulkan::InitDependendLibraries(amber::Pipeline* pipeline,
+                                            std::vector<VkPipeline>* libs) {
+  for (auto& p : pipeline->GetPipelineLibraries()) {
+    for (auto& s : pipeline_map_) {
+      amber::Pipeline* sub_pipeline = s.first;
+      Pipeline* vk_sub_pipeline = pipeline_map_[sub_pipeline].vk_pipeline.get();
+
+      if (sub_pipeline == p) {
+        std::vector<VkPipeline> sub_libs;
+
+        if (!sub_pipeline->GetPipelineLibraries().empty()) {
+          Result r = InitDependendLibraries(sub_pipeline, &sub_libs);
+
+          if (!r.IsSuccess())
+            return r;
+        }
+
+        if (vk_sub_pipeline->GetVkPipeline() == VK_NULL_HANDLE) {
+          vk_sub_pipeline->AsRayTracingPipeline()->InitLibrary(
+              sub_libs, sub_pipeline->GetMaxPipelineRayPayloadSize(),
+              sub_pipeline->GetMaxPipelineRayHitAttributeSize(),
+              sub_pipeline->GetMaxPipelineRayRecursionDepth());
+        }
+
+        libs->push_back(vk_sub_pipeline->GetVkPipeline());
+
+        break;
+      }
+    }
+  }
+
+  return {};
+}
+
+Result EngineVulkan::DoTraceRays(const RayTracingCommand* command) {
+  auto& info = pipeline_map_[command->GetPipeline()];
+  if (!info.vk_pipeline->IsRayTracing())
+    return Result("Vulkan: RayTracing called for non-RayTracing pipeline.");
+
+  amber::Pipeline* pipeline = command->GetPipeline();
+  std::vector<VkPipeline> libs;
+
+  if (!pipeline->GetPipelineLibraries().empty()) {
+    Result r = InitDependendLibraries(pipeline, &libs);
+    if (!r.IsSuccess())
+      return r;
+  }
+
+  amber::SBT* rSBT = pipeline->GetSBT(command->GetRayGenSBTName());
+  amber::SBT* mSBT = pipeline->GetSBT(command->GetMissSBTName());
+  amber::SBT* hSBT = pipeline->GetSBT(command->GetHitsSBTName());
+  amber::SBT* cSBT = pipeline->GetSBT(command->GetCallSBTName());
+
+  return info.vk_pipeline->AsRayTracingPipeline()->TraceRays(
+      rSBT, mSBT, hSBT, cSBT, command->GetX(), command->GetY(), command->GetZ(),
+      pipeline->GetMaxPipelineRayPayloadSize(),
+      pipeline->GetMaxPipelineRayHitAttributeSize(),
+      pipeline->GetMaxPipelineRayRecursionDepth(), libs,
+      command->IsTimedExecution());
 }
 
 Result EngineVulkan::DoEntryPoint(const EntryPointCommand* command) {
diff --git a/src/vulkan/engine_vulkan.h b/src/vulkan/engine_vulkan.h
index 76668fb..baf5ad7 100644
--- a/src/vulkan/engine_vulkan.h
+++ b/src/vulkan/engine_vulkan.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -23,13 +24,17 @@
 #include <vector>
 
 #include "amber/vulkan_header.h"
+#include "src/acceleration_structure.h"
 #include "src/cast_hash.h"
 #include "src/engine.h"
 #include "src/pipeline.h"
+#include "src/vulkan/blas.h"
 #include "src/vulkan/buffer_descriptor.h"
 #include "src/vulkan/command_pool.h"
 #include "src/vulkan/device.h"
 #include "src/vulkan/pipeline.h"
+#include "src/vulkan/tlas.h"
+#include "src/vulkan/tlas_descriptor.h"
 #include "src/vulkan/vertex_buffer.h"
 
 namespace amber {
@@ -45,6 +50,7 @@ class EngineVulkan : public Engine {
   Result Initialize(EngineConfig* config,
                     Delegate* delegate,
                     const std::vector<std::string>& features,
+                    const std::vector<std::string>& properties,
                     const std::vector<std::string>& instance_extensions,
                     const std::vector<std::string>& device_extensions) override;
   Result CreatePipeline(amber::Pipeline* type) override;
@@ -57,6 +63,7 @@ class EngineVulkan : public Engine {
   Result DoDrawGrid(const DrawGridCommand* cmd) override;
   Result DoDrawArrays(const DrawArraysCommand* cmd) override;
   Result DoCompute(const ComputeCommand* cmd) override;
+  Result DoTraceRays(const RayTracingCommand* cmd) override;
   Result DoEntryPoint(const EntryPointCommand* cmd) override;
   Result DoPatchParameterVertices(
       const PatchParameterVerticesCommand* cmd) override;
@@ -67,6 +74,7 @@ class EngineVulkan : public Engine {
     std::unique_ptr<Pipeline> vk_pipeline;
     std::unique_ptr<VertexBuffer> vertex_buffer;
     struct ShaderInfo {
+      ShaderType type;
       VkShaderModule shader;
       std::unique_ptr<std::vector<VkSpecializationMapEntry>>
           specialization_entries;
@@ -77,14 +85,27 @@ class EngineVulkan : public Engine {
     };
     std::unordered_map<ShaderType, ShaderInfo, CastHash<ShaderType>>
         shader_info;
+    std::vector<PipelineInfo::ShaderInfo> shader_info_rt;
   };
 
+  Result GetVkShaderStageInfo(ShaderType shader_type,
+                              const PipelineInfo::ShaderInfo& shader_info,
+                              VkPipelineShaderStageCreateInfo* stage_ci);
+
   Result GetVkShaderStageInfo(
       amber::Pipeline* pipeline,
       std::vector<VkPipelineShaderStageCreateInfo>* out);
 
   Result SetShader(amber::Pipeline* pipeline,
-                   const amber::Pipeline::ShaderInfo& shader);
+                   const amber::Pipeline::ShaderInfo& shader,
+                   size_t index);
+
+  Result GetVkShaderGroupInfo(
+      amber::Pipeline* pipeline,
+      std::vector<VkRayTracingShaderGroupCreateInfoKHR>* out);
+
+  Result InitDependendLibraries(amber::Pipeline* pipeline,
+                                std::vector<VkPipeline>* libs);
 
   std::unique_ptr<Device> device_;
   std::unique_ptr<CommandPool> pool_;
@@ -92,6 +113,10 @@ class EngineVulkan : public Engine {
   std::map<amber::Pipeline*, PipelineInfo> pipeline_map_;
 
   std::map<std::string, VkShaderModule> shaders_;
+
+  BlasesMap blases_;
+
+  TlasesMap tlases_;
 };
 
 }  // namespace vulkan
diff --git a/src/vulkan/find_vulkan.cmake b/src/vulkan/find_vulkan.cmake
index 53e96fb..9e35d73 100644
--- a/src/vulkan/find_vulkan.cmake
+++ b/src/vulkan/find_vulkan.cmake
@@ -22,6 +22,7 @@ set(VULKAN_LIB "")
 if (NOT ${Vulkan_FOUND})
   if (${AMBER_USE_LOCAL_VULKAN})
     set(Vulkan_FOUND TRUE)
+
     set(VulkanHeaders_INCLUDE_DIR
       ${PROJECT_SOURCE_DIR}/third_party/vulkan-headers/include
       CACHE PATH "vk headers dir" FORCE)
@@ -33,7 +34,8 @@ if (NOT ${Vulkan_FOUND})
     set(VulkanRegistry_DIRS ${VulkanRegistry_DIR}
       CACHE PATH "vk_registry_dir" FORCE)
     set(VULKAN_LIB vulkan)
-    message(STATUS "Amber: using local vulkan")
+
+    message(STATUS "Amber: using local vulkan ${VulkanHeaders_INCLUDE_DIR}")
   endif()
 endif()
 
diff --git a/src/vulkan/graphics_pipeline.cc b/src/vulkan/graphics_pipeline.cc
index 485ebb6..556c91f 100644
--- a/src/vulkan/graphics_pipeline.cc
+++ b/src/vulkan/graphics_pipeline.cc
@@ -871,8 +871,8 @@ Result GraphicsPipeline::Clear() {
 
   frame_->TransferImagesToHost(command_.get());
 
-  Result r = cmd_buf_guard.Submit(GetFenceTimeout(),
-                                  GetPipelineRuntimeLayerEnabled());
+  Result r =
+      cmd_buf_guard.Submit(GetFenceTimeout(), GetPipelineRuntimeLayerEnabled());
   if (!r.IsSuccess())
     return r;
 
@@ -881,7 +881,8 @@ Result GraphicsPipeline::Clear() {
 }
 
 Result GraphicsPipeline::Draw(const DrawArraysCommand* command,
-                              VertexBuffer* vertex_buffer) {
+                              VertexBuffer* vertex_buffer,
+                              bool is_timed_execution) {
   Result r = SendDescriptorDataToDeviceIfNeeded();
   if (!r.IsSuccess())
     return r;
@@ -902,7 +903,7 @@ Result GraphicsPipeline::Draw(const DrawArraysCommand* command,
   // it must be submitted separately, because using a descriptor set
   // while updating it is not safe.
   UpdateDescriptorSetsIfNeeded();
-
+  CreateTimingQueryObjectIfNeeded(is_timed_execution);
   {
     CommandBufferGuard cmd_buf_guard(GetCommandBuffer());
     if (!cmd_buf_guard.IsRecording())
@@ -916,6 +917,10 @@ Result GraphicsPipeline::Draw(const DrawArraysCommand* command,
     frame_->CopyBuffersToImages();
     frame_->TransferImagesToDevice(GetCommandBuffer());
 
+    // Timing must be place outside the render pass scope. The full pipeline
+    // barrier used by our specific implementation cannot be within a
+    // renderpass.
+    BeginTimerQuery();
     {
       RenderPassGuard render_pass_guard(this);
 
@@ -943,6 +948,7 @@ Result GraphicsPipeline::Draw(const DrawArraysCommand* command,
         // VkRunner spec says
         //   "vertexCount will be used as the index count, firstVertex
         //    becomes the vertex offset and firstIndex will always be zero."
+
         device_->GetPtrs()->vkCmdDrawIndexed(
             command_->GetVkCommandBuffer(),
             command->GetVertexCount(),   /* indexCount */
@@ -958,7 +964,7 @@ Result GraphicsPipeline::Draw(const DrawArraysCommand* command,
             command->GetFirstInstance());
       }
     }
-
+    EndTimerQuery();
     frame_->TransferImagesToHost(command_.get());
 
     r = cmd_buf_guard.Submit(GetFenceTimeout(),
@@ -966,7 +972,7 @@ Result GraphicsPipeline::Draw(const DrawArraysCommand* command,
     if (!r.IsSuccess())
       return r;
   }
-
+  DestroyTimingQueryObjectIfNeeded();
   r = ReadbackDescriptorsToHostDataQueue();
   if (!r.IsSuccess())
     return r;
diff --git a/src/vulkan/graphics_pipeline.h b/src/vulkan/graphics_pipeline.h
index 4bc5f7d..c4bb657 100644
--- a/src/vulkan/graphics_pipeline.h
+++ b/src/vulkan/graphics_pipeline.h
@@ -59,7 +59,9 @@ class GraphicsPipeline : public Pipeline {
   Result SetClearStencil(uint32_t stencil);
   Result SetClearDepth(float depth);
 
-  Result Draw(const DrawArraysCommand* command, VertexBuffer* vertex_buffer);
+  Result Draw(const DrawArraysCommand* command,
+              VertexBuffer* vertex_buffer,
+              bool is_timed_execution);
 
   VkRenderPass GetVkRenderPass() const { return render_pass_; }
   FrameBuffer* GetFrameBuffer() const { return frame_.get(); }
diff --git a/src/vulkan/pipeline.cc b/src/vulkan/pipeline.cc
index d03b2de..fd8dd4e 100644
--- a/src/vulkan/pipeline.cc
+++ b/src/vulkan/pipeline.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -15,6 +16,7 @@
 #include "src/vulkan/pipeline.h"
 
 #include <algorithm>
+#include <array>
 #include <limits>
 #include <utility>
 
@@ -26,7 +28,9 @@
 #include "src/vulkan/device.h"
 #include "src/vulkan/graphics_pipeline.h"
 #include "src/vulkan/image_descriptor.h"
+#include "src/vulkan/raytracing_pipeline.h"
 #include "src/vulkan/sampler_descriptor.h"
+#include "src/vulkan/tlas_descriptor.h"
 
 namespace amber {
 namespace vulkan {
@@ -34,15 +38,24 @@ namespace {
 
 const char* kDefaultEntryPointName = "main";
 
+constexpr VkMemoryBarrier kMemoryBarrierFull = {
+    VK_STRUCTURE_TYPE_MEMORY_BARRIER, nullptr,
+    VK_ACCESS_2_MEMORY_READ_BIT_KHR | VK_ACCESS_2_MEMORY_WRITE_BIT_KHR,
+    VK_ACCESS_2_MEMORY_READ_BIT_KHR | VK_ACCESS_2_MEMORY_WRITE_BIT_KHR};
+
+constexpr uint32_t kNumQueryObjects = 2;
+
 }  // namespace
 
 Pipeline::Pipeline(
     PipelineType type,
     Device* device,
     uint32_t fence_timeout_ms,
-    bool    pipeline_runtime_layer_enabled,
-    const std::vector<VkPipelineShaderStageCreateInfo>& shader_stage_info)
+    bool pipeline_runtime_layer_enabled,
+    const std::vector<VkPipelineShaderStageCreateInfo>& shader_stage_info,
+    VkPipelineCreateFlags create_flags)
     : device_(device),
+      create_flags_(create_flags),
       pipeline_type_(type),
       shader_stage_info_(shader_stage_info),
       fence_timeout_ms_(fence_timeout_ms),
@@ -67,6 +80,18 @@ Pipeline::~Pipeline() {
                                                   info.pool, nullptr);
     }
   }
+
+  if (pipeline_layout_ != VK_NULL_HANDLE) {
+    device_->GetPtrs()->vkDestroyPipelineLayout(device_->GetVkDevice(),
+                                                pipeline_layout_, nullptr);
+    pipeline_layout_ = VK_NULL_HANDLE;
+  }
+
+  if (pipeline_ != VK_NULL_HANDLE) {
+    device_->GetPtrs()->vkDestroyPipeline(device_->GetVkDevice(), pipeline_,
+                                          nullptr);
+    pipeline_ = VK_NULL_HANDLE;
+  }
 }
 
 GraphicsPipeline* Pipeline::AsGraphics() {
@@ -77,6 +102,10 @@ ComputePipeline* Pipeline::AsCompute() {
   return static_cast<ComputePipeline*>(this);
 }
 
+RayTracingPipeline* Pipeline::AsRayTracingPipeline() {
+  return static_cast<RayTracingPipeline*>(this);
+}
+
 Result Pipeline::Initialize(CommandPool* pool) {
   push_constant_ = MakeUnique<PushConstant>(device_);
 
@@ -232,6 +261,84 @@ void Pipeline::UpdateDescriptorSetsIfNeeded() {
   }
 }
 
+void Pipeline::CreateTimingQueryObjectIfNeeded(bool is_timed_execution) {
+  if (!is_timed_execution ||
+      !device_->IsTimestampComputeAndGraphicsSupported()) {
+    return;
+  }
+  in_timed_execution_ = true;
+  VkQueryPoolCreateInfo pool_create_info{
+      VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO,
+      nullptr,
+      0,
+      VK_QUERY_TYPE_TIMESTAMP,
+      kNumQueryObjects,
+      0};
+  device_->GetPtrs()->vkCreateQueryPool(
+      device_->GetVkDevice(), &pool_create_info, nullptr, &query_pool_);
+}
+
+void Pipeline::DestroyTimingQueryObjectIfNeeded() {
+  if (!in_timed_execution_) {
+    return;
+  }
+
+  // Flags set so we may/will wait on the CPU for the availiblity of our
+  // queries.
+  const VkQueryResultFlags flags =
+      VK_QUERY_RESULT_WAIT_BIT | VK_QUERY_RESULT_64_BIT;
+  std::array<uint64_t, kNumQueryObjects> time_stamps = {};
+  constexpr VkDeviceSize kStrideBytes = sizeof(uint64_t);
+
+  device_->GetPtrs()->vkGetQueryPoolResults(
+      device_->GetVkDevice(), query_pool_, 0, kNumQueryObjects,
+      sizeof(time_stamps), time_stamps.data(), kStrideBytes, flags);
+  double time_in_ns = static_cast<double>(time_stamps[1] - time_stamps[0]) *
+                      static_cast<double>(device_->GetTimestampPeriod());
+
+  constexpr double kNsToMsTime = 1.0 / 1000000.0;
+  device_->ReportExecutionTiming(time_in_ns * kNsToMsTime);
+  device_->GetPtrs()->vkDestroyQueryPool(device_->GetVkDevice(), query_pool_,
+                                         nullptr);
+  in_timed_execution_ = false;
+}
+
+void Pipeline::BeginTimerQuery() {
+  if (!in_timed_execution_) {
+    return;
+  }
+
+  device_->GetPtrs()->vkCmdResetQueryPool(command_->GetVkCommandBuffer(),
+                                          query_pool_, 0, kNumQueryObjects);
+  // Full barrier prevents any work from before the point being still in the
+  // pipeline.
+  device_->GetPtrs()->vkCmdPipelineBarrier(
+      command_->GetVkCommandBuffer(), VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,
+      VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, 0, 1, &kMemoryBarrierFull, 0, nullptr,
+      0, nullptr);
+  constexpr uint32_t kBeginQueryIndexOffset = 0;
+  device_->GetPtrs()->vkCmdWriteTimestamp(command_->GetVkCommandBuffer(),
+                                          VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
+                                          query_pool_, kBeginQueryIndexOffset);
+}
+
+void Pipeline::EndTimerQuery() {
+  if (!in_timed_execution_) {
+    return;
+  }
+
+  // Full barrier ensures that work including in our timing is executed before
+  // the timestamp.
+  device_->GetPtrs()->vkCmdPipelineBarrier(
+      command_->GetVkCommandBuffer(), VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,
+      VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, 0, 1, &kMemoryBarrierFull, 0, nullptr,
+      0, nullptr);
+  constexpr uint32_t kEndQueryIndexOffset = 1;
+  device_->GetPtrs()->vkCmdWriteTimestamp(command_->GetVkCommandBuffer(),
+                                          VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
+                                          query_pool_, kEndQueryIndexOffset);
+}
+
 Result Pipeline::RecordPushConstant(const VkPipelineLayout& pipeline_layout) {
   return push_constant_->RecordPushConstantVkCommand(command_.get(),
                                                      pipeline_layout);
@@ -277,9 +384,9 @@ Result Pipeline::GetDescriptorSlot(uint32_t desc_set,
 
 Result Pipeline::AddDescriptorBuffer(Buffer* amber_buffer) {
   // Don't add the buffer if it's already added.
-  const auto& buffer = std::find_if(
-      descriptor_buffers_.begin(), descriptor_buffers_.end(),
-      [&](const Buffer* buf) { return buf == amber_buffer; });
+  const auto& buffer =
+      std::find_if(descriptor_buffers_.begin(), descriptor_buffers_.end(),
+                   [&](const Buffer* buf) { return buf == amber_buffer; });
   if (buffer != descriptor_buffers_.end()) {
     return {};
   }
@@ -411,6 +518,35 @@ Result Pipeline::AddSamplerDescriptor(const SamplerCommand* cmd) {
   return {};
 }
 
+Result Pipeline::AddTLASDescriptor(const TLASCommand* cmd) {
+  if (cmd == nullptr)
+    return Result("Pipeline::AddTLASDescriptor TLASCommand is nullptr");
+
+  Descriptor* desc;
+  Result r =
+      GetDescriptorSlot(cmd->GetDescriptorSet(), cmd->GetBinding(), &desc);
+  if (!r.IsSuccess())
+    return r;
+
+  auto& descriptors = descriptor_set_info_[cmd->GetDescriptorSet()].descriptors;
+
+  if (desc == nullptr) {
+    auto tlas_desc = MakeUnique<TLASDescriptor>(
+        cmd->GetTLAS(), DescriptorType::kTLAS, device_, GetBlases(),
+        GetTlases(), cmd->GetDescriptorSet(), cmd->GetBinding());
+    descriptors.push_back(std::move(tlas_desc));
+  } else {
+    if (desc->GetDescriptorType() != DescriptorType::kTLAS) {
+      return Result(
+          "Descriptors bound to the same binding needs to have matching "
+          "descriptor types");
+    }
+    desc->AsTLASDescriptor()->AddAmberTLAS(cmd->GetTLAS());
+  }
+
+  return {};
+}
+
 Result Pipeline::SendDescriptorDataToDeviceIfNeeded() {
   {
     CommandBufferGuard guard(GetCommandBuffer());
@@ -434,7 +570,7 @@ Result Pipeline::SendDescriptorDataToDeviceIfNeeded() {
       }
       Result r = descriptor_transfer_resources_[buffer]->Initialize();
       if (!r.IsSuccess())
-         return r;
+        return r;
     }
 
     // Note that if a buffer for a descriptor is host accessible and
@@ -443,8 +579,8 @@ Result Pipeline::SendDescriptorDataToDeviceIfNeeded() {
     // done after resizing backed buffer i.e., copying data to the new
     // buffer from the old one. Thus, we must submit commands here to
     // guarantee this.
-    Result r = guard.Submit(GetFenceTimeout(),
-                            GetPipelineRuntimeLayerEnabled());
+    Result r =
+        guard.Submit(GetFenceTimeout(), GetPipelineRuntimeLayerEnabled());
     if (!r.IsSuccess())
       return r;
   }
@@ -508,8 +644,10 @@ void Pipeline::BindVkDescriptorSets(const VkPipelineLayout& pipeline_layout) {
 
     device_->GetPtrs()->vkCmdBindDescriptorSets(
         command_->GetVkCommandBuffer(),
-        IsGraphics() ? VK_PIPELINE_BIND_POINT_GRAPHICS
-                     : VK_PIPELINE_BIND_POINT_COMPUTE,
+        IsGraphics()     ? VK_PIPELINE_BIND_POINT_GRAPHICS
+        : IsCompute()    ? VK_PIPELINE_BIND_POINT_COMPUTE
+        : IsRayTracing() ? VK_PIPELINE_BIND_POINT_RAY_TRACING_KHR
+                         : VK_PIPELINE_BIND_POINT_MAX_ENUM,
         pipeline_layout, static_cast<uint32_t>(i), 1,
         &descriptor_set_info_[i].vk_desc_set,
         static_cast<uint32_t>(dynamic_offsets.size()), dynamic_offsets.data());
@@ -517,6 +655,9 @@ void Pipeline::BindVkDescriptorSets(const VkPipelineLayout& pipeline_layout) {
 }
 
 Result Pipeline::ReadbackDescriptorsToHostDataQueue() {
+  if (descriptor_buffers_.empty())
+    return Result{};
+
   // Record required commands to copy the data to a host visible buffer.
   {
     CommandBufferGuard guard(GetCommandBuffer());
@@ -551,8 +692,8 @@ Result Pipeline::ReadbackDescriptorsToHostDataQueue() {
       }
     }
 
-    Result r = guard.Submit(GetFenceTimeout(),
-                            GetPipelineRuntimeLayerEnabled());
+    Result r =
+        guard.Submit(GetFenceTimeout(), GetPipelineRuntimeLayerEnabled());
     if (!r.IsSuccess())
       return r;
   }
diff --git a/src/vulkan/pipeline.h b/src/vulkan/pipeline.h
index 58cefcb..db93c00 100644
--- a/src/vulkan/pipeline.h
+++ b/src/vulkan/pipeline.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -38,6 +39,7 @@ namespace vulkan {
 class ComputePipeline;
 class Device;
 class GraphicsPipeline;
+class RayTracingPipeline;
 
 /// Base class for a pipeline in Vulkan.
 class Pipeline {
@@ -46,12 +48,17 @@ class Pipeline {
 
   bool IsGraphics() const { return pipeline_type_ == PipelineType::kGraphics; }
   bool IsCompute() const { return pipeline_type_ == PipelineType::kCompute; }
+  bool IsRayTracing() const {
+    return pipeline_type_ == PipelineType::kRayTracing;
+  }
 
   GraphicsPipeline* AsGraphics();
   ComputePipeline* AsCompute();
+  RayTracingPipeline* AsRayTracingPipeline();
 
   Result AddBufferDescriptor(const BufferCommand*);
   Result AddSamplerDescriptor(const SamplerCommand*);
+  Result AddTLASDescriptor(const TLASCommand*);
 
   /// Add |buffer| data to the push constants at |offset|.
   Result AddPushConstantBuffer(const Buffer* buf, uint32_t offset);
@@ -72,14 +79,19 @@ class Pipeline {
 
   CommandBuffer* GetCommandBuffer() const { return command_.get(); }
   Device* GetDevice() const { return device_; }
+  virtual BlasesMap* GetBlases() { return nullptr; }
+  virtual TlasesMap* GetTlases() { return nullptr; }
+  VkPipelineLayout GetVkPipelineLayout() const { return pipeline_layout_; }
+  VkPipeline GetVkPipeline() const { return pipeline_; }
 
  protected:
   Pipeline(
       PipelineType type,
       Device* device,
       uint32_t fence_timeout_ms,
-      bool    pipeline_runtime_layer_enabled,
-      const std::vector<VkPipelineShaderStageCreateInfo>& shader_stage_info);
+      bool pipeline_runtime_layer_enabled,
+      const std::vector<VkPipelineShaderStageCreateInfo>& shader_stage_info,
+      VkPipelineCreateFlags create_flags = 0);
 
   /// Initializes the pipeline.
   Result Initialize(CommandPool* pool);
@@ -89,6 +101,13 @@ class Pipeline {
                            Descriptor** desc);
   void UpdateDescriptorSetsIfNeeded();
 
+  // This functions are used in benchmarking when 'TIMED_EXECUTION' option is
+  // specifed.
+  void CreateTimingQueryObjectIfNeeded(bool is_timed_execution);
+  void DestroyTimingQueryObjectIfNeeded();
+  void BeginTimerQuery();
+  void EndTimerQuery();
+
   Result SendDescriptorDataToDeviceIfNeeded();
   void BindVkDescriptorSets(const VkPipelineLayout& pipeline_layout);
 
@@ -102,13 +121,29 @@ class Pipeline {
 
   const char* GetEntryPointName(VkShaderStageFlagBits stage) const;
   uint32_t GetFenceTimeout() const { return fence_timeout_ms_; }
-  bool     GetPipelineRuntimeLayerEnabled()
-       const { return pipeline_runtime_layer_enabled_; }
+  bool GetPipelineRuntimeLayerEnabled() const {
+    return pipeline_runtime_layer_enabled_;
+  }
 
   Result CreateVkPipelineLayout(VkPipelineLayout* pipeline_layout);
 
+  void SetVkPipelineLayout(VkPipelineLayout pipeline_layout) {
+    assert(pipeline_layout_ == VK_NULL_HANDLE);
+    pipeline_layout_ = pipeline_layout;
+  }
+
+  void SetVkPipeline(VkPipeline pipeline) {
+    assert(pipeline_ == VK_NULL_HANDLE);
+    pipeline_ = pipeline;
+  }
+
+  VkQueryPool query_pool_ = VK_NULL_HANDLE;
+  VkPipeline pipeline_ = VK_NULL_HANDLE;
+  VkPipelineLayout pipeline_layout_ = VK_NULL_HANDLE;
+
   Device* device_ = nullptr;
   std::unique_ptr<CommandBuffer> command_;
+  VkPipelineCreateFlags create_flags_ = 0;
 
  private:
   struct DescriptorSetInfo {
@@ -145,6 +180,7 @@ class Pipeline {
       entry_points_;
 
   std::unique_ptr<PushConstant> push_constant_;
+  bool in_timed_execution_ = false;
 };
 
 }  // namespace vulkan
diff --git a/src/vulkan/raytracing_pipeline.cc b/src/vulkan/raytracing_pipeline.cc
new file mode 100644
index 0000000..7a4f856
--- /dev/null
+++ b/src/vulkan/raytracing_pipeline.cc
@@ -0,0 +1,266 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include <utility>
+
+#include "src/vulkan/raytracing_pipeline.h"
+
+#include "src/vulkan/blas.h"
+#include "src/vulkan/command_pool.h"
+#include "src/vulkan/device.h"
+#include "src/vulkan/sbt.h"
+#include "src/vulkan/tlas.h"
+
+namespace amber {
+namespace vulkan {
+
+inline VkStridedDeviceAddressRegionKHR makeStridedDeviceAddressRegionKHR(
+    VkDeviceAddress deviceAddress,
+    VkDeviceSize stride,
+    VkDeviceSize size) {
+  VkStridedDeviceAddressRegionKHR res;
+  res.deviceAddress = deviceAddress;
+  res.stride = stride;
+  res.size = size;
+  return res;
+}
+
+inline VkDeviceAddress getBufferDeviceAddress(Device* device, VkBuffer buffer) {
+  const VkBufferDeviceAddressInfo bufferDeviceAddressInfo = {
+      VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO_KHR,
+      nullptr,
+      buffer,
+  };
+
+  return device->GetPtrs()->vkGetBufferDeviceAddress(device->GetVkDevice(),
+                                                     &bufferDeviceAddressInfo);
+}
+
+RayTracingPipeline::RayTracingPipeline(
+    Device* device,
+    BlasesMap* blases,
+    TlasesMap* tlases,
+    uint32_t fence_timeout_ms,
+    bool pipeline_runtime_layer_enabled,
+    const std::vector<VkPipelineShaderStageCreateInfo>& shader_stage_info,
+    VkPipelineCreateFlags create_flags)
+    : Pipeline(PipelineType::kRayTracing,
+               device,
+               fence_timeout_ms,
+               pipeline_runtime_layer_enabled,
+               shader_stage_info,
+               create_flags),
+      shader_group_create_info_(),
+      blases_(blases),
+      tlases_(tlases) {}
+
+RayTracingPipeline::~RayTracingPipeline() = default;
+
+Result RayTracingPipeline::Initialize(
+    CommandPool* pool,
+    std::vector<VkRayTracingShaderGroupCreateInfoKHR>&
+        shader_group_create_info) {
+  shader_group_create_info_.swap(shader_group_create_info);
+
+  return Pipeline::Initialize(pool);
+}
+
+Result RayTracingPipeline::CreateVkRayTracingPipeline(
+    const VkPipelineLayout& pipeline_layout,
+    VkPipeline* pipeline,
+    const std::vector<VkPipeline>& libs,
+    uint32_t maxPipelineRayPayloadSize,
+    uint32_t maxPipelineRayHitAttributeSize,
+    uint32_t maxPipelineRayRecursionDepth) {
+  std::vector<VkPipelineShaderStageCreateInfo> shader_stage_info =
+      GetVkShaderStageInfo();
+
+  for (auto& info : shader_stage_info)
+    info.pName = GetEntryPointName(info.stage);
+
+  const bool lib = (create_flags_ & VK_PIPELINE_CREATE_LIBRARY_BIT_KHR) != 0;
+  const VkPipelineLibraryCreateInfoKHR libraryInfo = {
+      VK_STRUCTURE_TYPE_PIPELINE_LIBRARY_CREATE_INFO_KHR, nullptr,
+      static_cast<uint32_t>(libs.size()), libs.size() ? &libs[0] : nullptr};
+  const VkRayTracingPipelineInterfaceCreateInfoKHR libraryInterface = {
+      VK_STRUCTURE_TYPE_RAY_TRACING_PIPELINE_INTERFACE_CREATE_INFO_KHR, nullptr,
+      maxPipelineRayPayloadSize, maxPipelineRayHitAttributeSize};
+
+  VkRayTracingPipelineCreateInfoKHR pipelineCreateInfo{
+      VK_STRUCTURE_TYPE_RAY_TRACING_PIPELINE_CREATE_INFO_KHR,
+      nullptr,
+      create_flags_,
+      static_cast<uint32_t>(shader_stage_info.size()),
+      shader_stage_info.data(),
+      static_cast<uint32_t>(shader_group_create_info_.size()),
+      shader_group_create_info_.data(),
+      maxPipelineRayRecursionDepth,
+      libs.empty() ? nullptr : &libraryInfo,
+      lib || !libs.empty() ? &libraryInterface : nullptr,
+      nullptr,
+      pipeline_layout,
+      VK_NULL_HANDLE,
+      0,
+  };
+
+  VkResult r = device_->GetPtrs()->vkCreateRayTracingPipelinesKHR(
+      device_->GetVkDevice(), VK_NULL_HANDLE, VK_NULL_HANDLE, 1u,
+      &pipelineCreateInfo, nullptr, pipeline);
+  if (r != VK_SUCCESS)
+    return Result("Vulkan::Calling vkCreateRayTracingPipelinesKHR Fail");
+
+  return {};
+}
+
+Result RayTracingPipeline::getVulkanSBTRegion(
+    VkPipeline pipeline,
+    amber::SBT* aSBT,
+    VkStridedDeviceAddressRegionKHR* region) {
+  const uint32_t handle_size = device_->GetRayTracingShaderGroupHandleSize();
+  if (aSBT != nullptr) {
+    SBT* vSBT = nullptr;
+    auto x = sbtses_.find(aSBT);
+
+    if (x == sbtses_.end()) {
+      auto p = MakeUnique<amber::vulkan::SBT>(device_);
+      sbts_.push_back(std::move(p));
+      auto sbt_vulkan = sbtses_.emplace(aSBT, sbts_.back().get());
+
+      vSBT = sbt_vulkan.first->second;
+
+      Result r = vSBT->Create(aSBT, pipeline);
+      if (!r.IsSuccess())
+        return r;
+    } else {
+      vSBT = x->second;
+    }
+
+    *region = makeStridedDeviceAddressRegionKHR(
+        getBufferDeviceAddress(device_, vSBT->getBuffer()->GetVkBuffer()),
+        handle_size, handle_size * aSBT->GetSBTSize());
+  } else {
+    *region = makeStridedDeviceAddressRegionKHR(0, 0, 0);
+  }
+
+  return {};
+}
+
+Result RayTracingPipeline::InitLibrary(const std::vector<VkPipeline>& libs,
+                                       uint32_t maxPipelineRayPayloadSize,
+                                       uint32_t maxPipelineRayHitAttributeSize,
+                                       uint32_t maxPipelineRayRecursionDepth) {
+  assert(pipeline_layout_ == VK_NULL_HANDLE);
+  Result r = CreateVkPipelineLayout(&pipeline_layout_);
+  if (!r.IsSuccess())
+    return r;
+
+  assert(pipeline_ == VK_NULL_HANDLE);
+  r = CreateVkRayTracingPipeline(
+      pipeline_layout_, &pipeline_, libs, maxPipelineRayPayloadSize,
+      maxPipelineRayHitAttributeSize, maxPipelineRayRecursionDepth);
+  if (!r.IsSuccess())
+    return r;
+
+  return {};
+}
+
+Result RayTracingPipeline::TraceRays(amber::SBT* rSBT,
+                                     amber::SBT* mSBT,
+                                     amber::SBT* hSBT,
+                                     amber::SBT* cSBT,
+                                     uint32_t x,
+                                     uint32_t y,
+                                     uint32_t z,
+                                     uint32_t maxPipelineRayPayloadSize,
+                                     uint32_t maxPipelineRayHitAttributeSize,
+                                     uint32_t maxPipelineRayRecursionDepth,
+                                     const std::vector<VkPipeline>& libs,
+                                     bool is_timed_execution) {
+  Result r = SendDescriptorDataToDeviceIfNeeded();
+  if (!r.IsSuccess())
+    return r;
+
+  r = InitLibrary(libs, maxPipelineRayPayloadSize,
+                  maxPipelineRayHitAttributeSize, maxPipelineRayRecursionDepth);
+  if (!r.IsSuccess())
+    return r;
+
+  // Note that a command updating a descriptor set and a command using
+  // it must be submitted separately, because using a descriptor set
+  // while updating it is not safe.
+  UpdateDescriptorSetsIfNeeded();
+  CreateTimingQueryObjectIfNeeded(is_timed_execution);
+  {
+    CommandBufferGuard guard(GetCommandBuffer());
+    if (!guard.IsRecording())
+      return guard.GetResult();
+
+    for (auto& i : *blases_) {
+      i.second->BuildBLAS(GetCommandBuffer());
+    }
+    for (auto& i : *tlases_) {
+      i.second->BuildTLAS(GetCommandBuffer()->GetVkCommandBuffer());
+    }
+
+    BindVkDescriptorSets(pipeline_layout_);
+
+    r = RecordPushConstant(pipeline_layout_);
+    if (!r.IsSuccess())
+      return r;
+
+    device_->GetPtrs()->vkCmdBindPipeline(
+        command_->GetVkCommandBuffer(), VK_PIPELINE_BIND_POINT_RAY_TRACING_KHR,
+        pipeline_);
+
+    VkStridedDeviceAddressRegionKHR rSBTRegion = {};
+    VkStridedDeviceAddressRegionKHR mSBTRegion = {};
+    VkStridedDeviceAddressRegionKHR hSBTRegion = {};
+    VkStridedDeviceAddressRegionKHR cSBTRegion = {};
+
+    r = getVulkanSBTRegion(pipeline_, rSBT, &rSBTRegion);
+    if (!r.IsSuccess())
+      return r;
+
+    r = getVulkanSBTRegion(pipeline_, mSBT, &mSBTRegion);
+    if (!r.IsSuccess())
+      return r;
+
+    r = getVulkanSBTRegion(pipeline_, hSBT, &hSBTRegion);
+    if (!r.IsSuccess())
+      return r;
+
+    r = getVulkanSBTRegion(pipeline_, cSBT, &cSBTRegion);
+    if (!r.IsSuccess())
+      return r;
+
+    device_->GetPtrs()->vkCmdTraceRaysKHR(command_->GetVkCommandBuffer(),
+                                          &rSBTRegion, &mSBTRegion, &hSBTRegion,
+                                          &cSBTRegion, x, y, z);
+    BeginTimerQuery();
+    r = guard.Submit(GetFenceTimeout(), GetPipelineRuntimeLayerEnabled());
+    EndTimerQuery();
+    if (!r.IsSuccess())
+      return r;
+  }
+  DestroyTimingQueryObjectIfNeeded();
+  r = ReadbackDescriptorsToHostDataQueue();
+  if (!r.IsSuccess())
+    return r;
+
+  return {};
+}
+
+}  // namespace vulkan
+}  // namespace amber
diff --git a/src/vulkan/raytracing_pipeline.h b/src/vulkan/raytracing_pipeline.h
new file mode 100644
index 0000000..6ef9c08
--- /dev/null
+++ b/src/vulkan/raytracing_pipeline.h
@@ -0,0 +1,91 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef SRC_VULKAN_RAYTRACING_PIPELINE_H_
+#define SRC_VULKAN_RAYTRACING_PIPELINE_H_
+
+#include <memory>
+#include <vector>
+
+#include "amber/result.h"
+#include "amber/vulkan_header.h"
+#include "src/vulkan/pipeline.h"
+
+namespace amber {
+namespace vulkan {
+
+/// Pipepline to handle compute commands.
+class RayTracingPipeline : public Pipeline {
+ public:
+  RayTracingPipeline(
+      Device* device,
+      BlasesMap* blases,
+      TlasesMap* tlases,
+      uint32_t fence_timeout_ms,
+      bool pipeline_runtime_layer_enabled,
+      const std::vector<VkPipelineShaderStageCreateInfo>& shader_stage_info,
+      VkPipelineCreateFlags create_flags);
+  ~RayTracingPipeline() override;
+
+  Result AddTLASDescriptor(const TLASCommand* cmd);
+
+  Result Initialize(CommandPool* pool,
+                    std::vector<VkRayTracingShaderGroupCreateInfoKHR>&
+                        shader_group_create_info);
+
+  Result getVulkanSBTRegion(VkPipeline pipeline,
+                            amber::SBT* aSBT,
+                            VkStridedDeviceAddressRegionKHR* region);
+
+  Result InitLibrary(const std::vector<VkPipeline>& lib,
+                     uint32_t maxPipelineRayPayloadSize,
+                     uint32_t maxPipelineRayHitAttributeSize,
+                     uint32_t maxPipelineRayRecursionDepth);
+
+  Result TraceRays(amber::SBT* rSBT,
+                   amber::SBT* mSBT,
+                   amber::SBT* hSBT,
+                   amber::SBT* cSBT,
+                   uint32_t x,
+                   uint32_t y,
+                   uint32_t z,
+                   uint32_t maxPipelineRayPayloadSize,
+                   uint32_t maxPipelineRayHitAttributeSize,
+                   uint32_t maxPipelineRayRecursionDepth,
+                   const std::vector<VkPipeline>& lib,
+                   bool is_timed_execution);
+
+  BlasesMap* GetBlases() override { return blases_; }
+  TlasesMap* GetTlases() override { return tlases_; }
+
+ private:
+  Result CreateVkRayTracingPipeline(const VkPipelineLayout& pipeline_layout,
+                                    VkPipeline* pipeline,
+                                    const std::vector<VkPipeline>& libs,
+                                    uint32_t maxPipelineRayPayloadSize,
+                                    uint32_t maxPipelineRayHitAttributeSize,
+                                    uint32_t maxPipelineRayRecursionDepth);
+
+  std::vector<VkRayTracingShaderGroupCreateInfoKHR> shader_group_create_info_;
+  BlasesMap* blases_;
+  TlasesMap* tlases_;
+  SbtsMap sbtses_;
+  std::vector<std::unique_ptr<amber::vulkan::SBT>> sbts_;
+};
+
+}  // namespace vulkan
+}  // namespace amber
+
+#endif  // SRC_VULKAN_RAYTRACING_PIPELINE_H_
diff --git a/src/vulkan/resource.cc b/src/vulkan/resource.cc
index a52df3d..15537a1 100644
--- a/src/vulkan/resource.cc
+++ b/src/vulkan/resource.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -141,9 +142,21 @@ Result Resource::AllocateMemory(VkDeviceMemory* memory,
                                 VkDeviceSize size,
                                 uint32_t memory_type_index) {
   VkMemoryAllocateInfo alloc_info = VkMemoryAllocateInfo();
+  VkMemoryAllocateFlagsInfo allocFlagsInfo = VkMemoryAllocateFlagsInfo();
+
   alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
   alloc_info.allocationSize = size;
   alloc_info.memoryTypeIndex = memory_type_index;
+
+  if (memory_allocate_flags_ != 0) {
+    allocFlagsInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_FLAGS_INFO;
+    allocFlagsInfo.pNext = nullptr;
+    allocFlagsInfo.flags = memory_allocate_flags_;
+    allocFlagsInfo.deviceMask = 0u;
+
+    alloc_info.pNext = &allocFlagsInfo;
+  }
+
   if (device_->GetPtrs()->vkAllocateMemory(device_->GetVkDevice(), &alloc_info,
                                            nullptr, memory) != VK_SUCCESS) {
     return Result("Vulkan::Calling vkAllocateMemory Fail");
diff --git a/src/vulkan/resource.h b/src/vulkan/resource.h
index d3cc0de..8ae4fec 100644
--- a/src/vulkan/resource.h
+++ b/src/vulkan/resource.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -15,6 +16,7 @@
 #ifndef SRC_VULKAN_RESOURCE_H_
 #define SRC_VULKAN_RESOURCE_H_
 
+#include <map>
 #include <memory>
 #include <vector>
 
@@ -23,12 +25,24 @@
 #include "amber/vulkan_header.h"
 
 namespace amber {
+
+class BLAS;
+class TLAS;
+class SBT;
+
 namespace vulkan {
 
 class CommandBuffer;
 class Device;
 class TransferBuffer;
 class TransferImage;
+class BLAS;
+class TLAS;
+class SBT;
+
+typedef std::map<amber::BLAS*, std::unique_ptr<amber::vulkan::BLAS>> BlasesMap;
+typedef std::map<amber::TLAS*, std::unique_ptr<amber::vulkan::TLAS>> TlasesMap;
+typedef std::map<amber::SBT*, amber::vulkan::SBT*> SbtsMap;
 
 // Class for Vulkan resources. Its children are Vulkan Buffer and Vulkan Image.
 class Resource {
@@ -52,6 +66,15 @@ class Resource {
   virtual Result Initialize() = 0;
   virtual TransferBuffer* AsTransferBuffer() { return nullptr; }
   virtual TransferImage* AsTransferImage() { return nullptr; }
+  virtual void AddAllocateFlags(VkMemoryAllocateFlags memory_allocate_flags) {
+    memory_allocate_flags_ |= memory_allocate_flags;
+  }
+  VkMemoryPropertyFlags GetMemoryPropertiesFlags() {
+    return memory_properties_flags_;
+  }
+  void SetMemoryPropertiesFlags(VkMemoryPropertyFlags flags) {
+    memory_properties_flags_ = flags;
+  }
 
  protected:
   Resource(Device* device, uint32_t size);
@@ -90,6 +113,10 @@ class Resource {
   uint32_t size_in_bytes_ = 0;
   void* memory_ptr_ = nullptr;
   bool is_read_only_ = false;
+  VkMemoryAllocateFlags memory_allocate_flags_ = 0u;
+  VkMemoryPropertyFlags memory_properties_flags_ =
+      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
+      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
 };
 
 }  // namespace vulkan
diff --git a/src/vulkan/sbt.cc b/src/vulkan/sbt.cc
new file mode 100644
index 0000000..e7fa49b
--- /dev/null
+++ b/src/vulkan/sbt.cc
@@ -0,0 +1,73 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include <cstring>
+
+#include "src/vulkan/sbt.h"
+#include "src/vulkan/pipeline.h"
+
+namespace amber {
+namespace vulkan {
+
+SBT::SBT(Device* device) : device_(device) {}
+
+Result SBT::Create(amber::SBT* sbt, VkPipeline pipeline) {
+  uint32_t handles_count = 0;
+  for (auto& x : sbt->GetSBTRecords())
+    handles_count += x->GetCount();
+
+  if (handles_count == 0)
+    return Result("SBT must contain at least one record");
+
+  const uint32_t handle_size = device_->GetRayTracingShaderGroupHandleSize();
+  const uint32_t buffer_size = handle_size * handles_count;
+  std::vector<uint8_t> handles(buffer_size);
+
+  buffer_ = MakeUnique<TransferBuffer>(device_, buffer_size, nullptr);
+  buffer_->AddUsageFlags(VK_BUFFER_USAGE_TRANSFER_DST_BIT |
+                         VK_BUFFER_USAGE_SHADER_BINDING_TABLE_BIT_KHR |
+                         VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT);
+  buffer_->AddAllocateFlags(VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT);
+  Result r = buffer_->Initialize();
+  if (!r.IsSuccess())
+    return r;
+
+  size_t start = 0;
+  for (auto& x : sbt->GetSBTRecords()) {
+    const uint32_t index = x->GetIndex();
+    const uint32_t count = x->GetCount();
+    if (index != static_cast<uint32_t>(-1)) {
+      VkResult vr = device_->GetPtrs()->vkGetRayTracingShaderGroupHandlesKHR(
+          device_->GetVkDevice(), pipeline, index, count, count * handle_size,
+          &handles[start * handle_size]);
+
+      if (vr != VK_SUCCESS)
+        return Result("vkGetRayTracingShaderGroupHandlesKHR has failed");
+    }
+
+    start += count;
+  }
+
+  memcpy(buffer_->HostAccessibleMemoryPtr(), handles.data(), handles.size());
+
+  // Skip flush as memory allocated for buffer is coherent
+
+  return r;
+}
+
+SBT::~SBT() = default;
+
+}  // namespace vulkan
+}  // namespace amber
diff --git a/src/vulkan/sbt.h b/src/vulkan/sbt.h
new file mode 100644
index 0000000..7ff1242
--- /dev/null
+++ b/src/vulkan/sbt.h
@@ -0,0 +1,45 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef SRC_VULKAN_SBT_H_
+#define SRC_VULKAN_SBT_H_
+
+#include <memory>
+#include <vector>
+
+#include "src/acceleration_structure.h"
+#include "src/vulkan/device.h"
+#include "src/vulkan/transfer_buffer.h"
+
+namespace amber {
+namespace vulkan {
+
+class SBT {
+ public:
+  explicit SBT(Device* device);
+  ~SBT();
+
+  Result Create(amber::SBT* sbt, VkPipeline pipeline);
+  TransferBuffer* getBuffer() { return buffer_.get(); }
+
+ private:
+  Device* device_ = nullptr;
+  std::unique_ptr<TransferBuffer> buffer_;
+};
+
+}  // namespace vulkan
+}  // namespace amber
+
+#endif  // SRC_VULKAN_SBT_H_
diff --git a/src/vulkan/tlas.cc b/src/vulkan/tlas.cc
new file mode 100644
index 0000000..c0fe422
--- /dev/null
+++ b/src/vulkan/tlas.cc
@@ -0,0 +1,245 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "src/vulkan/tlas.h"
+#include "src/vulkan/blas.h"
+
+namespace amber {
+namespace vulkan {
+
+static VkTransformMatrixKHR makeVkMatrix(const float* m) {
+  const VkTransformMatrixKHR identityMatrix3x4 = {{{1.0f, 0.0f, 0.0f, 0.0f},
+                                                   {0.0f, 1.0f, 0.0f, 0.0f},
+                                                   {0.0f, 0.0f, 1.0f, 0.0f}}};
+  VkTransformMatrixKHR v;
+
+  if (m == nullptr)
+    return identityMatrix3x4;
+
+  for (size_t i = 0; i < 12; i++) {
+    const size_t r = i / 4;
+    const size_t c = i % 4;
+    v.matrix[r][c] = m[i];
+  }
+
+  return v;
+}
+
+TLAS::TLAS(Device* device) : device_(device) {}
+
+Result TLAS::CreateTLAS(amber::TLAS* tlas,
+                        BlasesMap* blases) {
+  if (tlas_ != VK_NULL_HANDLE)
+    return {};
+
+  assert(tlas != nullptr);
+
+  VkDeviceOrHostAddressConstKHR const_default_ptr;
+  VkDeviceOrHostAddressKHR default_ptr;
+
+  const_default_ptr.hostAddress = nullptr;
+  default_ptr.hostAddress = nullptr;
+
+  instances_count_ = static_cast<uint32_t>(tlas->GetInstances().size());
+
+  const uint32_t ib_size =
+      uint32_t(instances_count_ * sizeof(VkAccelerationStructureInstanceKHR));
+
+  instance_buffer_ = MakeUnique<TransferBuffer>(device_, ib_size, nullptr);
+  instance_buffer_->AddUsageFlags(
+      VK_BUFFER_USAGE_ACCELERATION_STRUCTURE_BUILD_INPUT_READ_ONLY_BIT_KHR |
+      VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT);
+  instance_buffer_->AddAllocateFlags(VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT);
+  instance_buffer_->Initialize();
+
+  VkAccelerationStructureInstanceKHR* instances_ptr =
+      reinterpret_cast<VkAccelerationStructureInstanceKHR*>
+          (instance_buffer_->HostAccessibleMemoryPtr());
+
+  for (auto& instance : tlas->GetInstances()) {
+    auto blas = instance->GetUsedBLAS();
+
+    assert(blas != nullptr);
+
+    auto blas_vulkan_it = blases->find(blas);
+    amber::vulkan::BLAS* blas_vulkan_ptr = nullptr;
+
+    if (blas_vulkan_it == blases->end()) {
+      auto blas_vulkan =
+          blases->emplace(blas, new amber::vulkan::BLAS(device_));
+      blas_vulkan_ptr = blas_vulkan.first->second.get();
+
+      Result r = blas_vulkan_ptr->CreateBLAS(blas);
+
+      if (!r.IsSuccess())
+        return r;
+    } else {
+      blas_vulkan_ptr = blas_vulkan_it->second.get();
+    }
+
+    VkDeviceAddress accelerationStructureAddress =
+        blas_vulkan_ptr->getVkBLASDeviceAddress();
+
+    *instances_ptr = VkAccelerationStructureInstanceKHR{
+        makeVkMatrix(instance->GetTransform()),
+        instance->GetInstanceIndex(),
+        instance->GetMask(),
+        instance->GetOffset(),
+        instance->GetFlags(),
+        static_cast<uint64_t>(accelerationStructureAddress)};
+
+    instances_ptr++;
+  }
+
+  VkAccelerationStructureGeometryInstancesDataKHR
+      accelerationStructureGeometryInstancesDataKHR = {
+          VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_INSTANCES_DATA_KHR,
+          nullptr,
+          VK_FALSE,
+          const_default_ptr,
+      };
+  VkAccelerationStructureGeometryDataKHR geometry = {};
+  geometry.instances = accelerationStructureGeometryInstancesDataKHR;
+
+  accelerationStructureGeometryKHR_ = {
+      VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_GEOMETRY_KHR,
+      nullptr,
+      VK_GEOMETRY_TYPE_INSTANCES_KHR,
+      geometry,
+      0,
+  };
+
+  accelerationStructureBuildGeometryInfoKHR_ = {
+      VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_GEOMETRY_INFO_KHR,
+      nullptr,
+      VK_ACCELERATION_STRUCTURE_TYPE_TOP_LEVEL_KHR,
+      0,
+      VK_BUILD_ACCELERATION_STRUCTURE_MODE_BUILD_KHR,
+      VK_NULL_HANDLE,
+      VK_NULL_HANDLE,
+      1,
+      &accelerationStructureGeometryKHR_,
+      nullptr,
+      default_ptr,
+  };
+
+  VkAccelerationStructureBuildSizesInfoKHR sizeInfo = {
+      VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_SIZES_INFO_KHR,
+      nullptr,
+      0,
+      0,
+      0,
+  };
+
+  device_->GetPtrs()->vkGetAccelerationStructureBuildSizesKHR(
+      device_->GetVkDevice(), VK_ACCELERATION_STRUCTURE_BUILD_TYPE_DEVICE_KHR,
+      &accelerationStructureBuildGeometryInfoKHR_, &instances_count_,
+      &sizeInfo);
+
+  const uint32_t as_size =
+      static_cast<uint32_t>(sizeInfo.accelerationStructureSize);
+
+  buffer_ = MakeUnique<TransferBuffer>(device_, as_size, nullptr);
+  buffer_->AddUsageFlags(
+      VK_BUFFER_USAGE_ACCELERATION_STRUCTURE_STORAGE_BIT_KHR |
+      VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT);
+  buffer_->AddAllocateFlags(VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT);
+  buffer_->Initialize();
+
+  const VkAccelerationStructureCreateInfoKHR
+      accelerationStructureCreateInfoKHR = {
+          VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_CREATE_INFO_KHR,
+          nullptr,
+          0,
+          buffer_->GetVkBuffer(),
+          0,
+          as_size,
+          VK_ACCELERATION_STRUCTURE_TYPE_TOP_LEVEL_KHR,
+          0,
+      };
+
+  if (device_->GetPtrs()->vkCreateAccelerationStructureKHR(
+          device_->GetVkDevice(), &accelerationStructureCreateInfoKHR, nullptr,
+          &tlas_) != VK_SUCCESS) {
+    return Result(
+        "Vulkan::Calling vkCreateAccelerationStructureKHR "
+        "failed");
+  }
+
+  accelerationStructureBuildGeometryInfoKHR_.dstAccelerationStructure = tlas_;
+
+  if (sizeInfo.buildScratchSize > 0) {
+    scratch_buffer_ = MakeUnique<TransferBuffer>(
+        device_, static_cast<uint32_t>(sizeInfo.buildScratchSize), nullptr);
+    scratch_buffer_->AddUsageFlags(VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
+                                   VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT);
+    scratch_buffer_->AddAllocateFlags(VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT);
+    scratch_buffer_->Initialize();
+
+    accelerationStructureBuildGeometryInfoKHR_.scratchData.deviceAddress =
+        scratch_buffer_->getBufferDeviceAddress();
+  }
+
+  accelerationStructureGeometryKHR_.geometry.instances.data.deviceAddress =
+      instance_buffer_->getBufferDeviceAddress();
+
+  return {};
+}
+
+Result TLAS::BuildTLAS(VkCommandBuffer cmdBuffer) {
+  if (tlas_ == VK_NULL_HANDLE)
+    return Result("Acceleration structure should be created first");
+  if (built_)
+    return {};
+
+  VkAccelerationStructureBuildRangeInfoKHR
+      accelerationStructureBuildRangeInfoKHR = {instances_count_, 0, 0, 0};
+  VkAccelerationStructureBuildRangeInfoKHR*
+      accelerationStructureBuildRangeInfoKHRPtr =
+          &accelerationStructureBuildRangeInfoKHR;
+
+  device_->GetPtrs()->vkCmdBuildAccelerationStructuresKHR(
+      cmdBuffer, 1, &accelerationStructureBuildGeometryInfoKHR_,
+      &accelerationStructureBuildRangeInfoKHRPtr);
+
+  const VkAccessFlags accessMasks =
+      VK_ACCESS_ACCELERATION_STRUCTURE_WRITE_BIT_KHR |
+      VK_ACCESS_ACCELERATION_STRUCTURE_READ_BIT_KHR;
+  const VkMemoryBarrier memBarrier{
+      VK_STRUCTURE_TYPE_MEMORY_BARRIER,
+      nullptr,
+      accessMasks,
+      accessMasks,
+  };
+
+  device_->GetPtrs()->vkCmdPipelineBarrier(
+      cmdBuffer, VK_PIPELINE_STAGE_ACCELERATION_STRUCTURE_BUILD_BIT_KHR,
+      VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, 0, 1, &memBarrier, 0, nullptr, 0,
+      nullptr);
+
+  built_ = true;
+
+  return {};
+}
+
+TLAS::~TLAS() {
+  if (tlas_ != VK_NULL_HANDLE) {
+    device_->GetPtrs()->vkDestroyAccelerationStructureKHR(
+        device_->GetVkDevice(), tlas_, nullptr);
+  }
+}
+
+}  // namespace vulkan
+}  // namespace amber
diff --git a/src/vulkan/tlas.h b/src/vulkan/tlas.h
new file mode 100644
index 0000000..9046d65
--- /dev/null
+++ b/src/vulkan/tlas.h
@@ -0,0 +1,53 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef SRC_VULKAN_TLAS_H_
+#define SRC_VULKAN_TLAS_H_
+
+#include <memory>
+
+#include "src/acceleration_structure.h"
+#include "src/vulkan/device.h"
+#include "src/vulkan/transfer_buffer.h"
+
+namespace amber {
+namespace vulkan {
+
+class TLAS {
+ public:
+  explicit TLAS(Device* device);
+  ~TLAS();
+
+  Result CreateTLAS(amber::TLAS* tlas, BlasesMap* blases);
+  Result BuildTLAS(VkCommandBuffer cmdBuffer);
+  VkAccelerationStructureKHR GetVkTLAS() { return tlas_; }
+
+ private:
+  Device* device_ = nullptr;
+  VkAccelerationStructureKHR tlas_ = VK_NULL_HANDLE;
+  bool built_ = false;
+  std::unique_ptr<TransferBuffer> buffer_;
+  std::unique_ptr<TransferBuffer> scratch_buffer_;
+  std::unique_ptr<TransferBuffer> instance_buffer_;
+  uint32_t instances_count_ = 0;
+  VkAccelerationStructureGeometryKHR accelerationStructureGeometryKHR_;
+  VkAccelerationStructureBuildGeometryInfoKHR
+      accelerationStructureBuildGeometryInfoKHR_;
+};
+
+}  // namespace vulkan
+}  // namespace amber
+
+#endif  // SRC_VULKAN_TLAS_H_
diff --git a/src/vulkan/tlas_descriptor.cc b/src/vulkan/tlas_descriptor.cc
new file mode 100644
index 0000000..a1c7adf
--- /dev/null
+++ b/src/vulkan/tlas_descriptor.cc
@@ -0,0 +1,86 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "src/vulkan/tlas_descriptor.h"
+
+#include "src/vulkan/device.h"
+#include "src/vulkan/resource.h"
+
+namespace amber {
+namespace vulkan {
+
+TLASDescriptor::TLASDescriptor(amber::TLAS* tlas,
+                               DescriptorType type,
+                               Device* device,
+                               BlasesMap* blases,
+                               TlasesMap* tlases,
+                               uint32_t desc_set,
+                               uint32_t binding)
+    : Descriptor(type, device, desc_set, binding),
+      blases_(blases),
+      tlases_(tlases) {
+  assert(blases != nullptr);
+  assert(tlases != nullptr);
+  AddAmberTLAS(tlas);
+}
+
+TLASDescriptor::~TLASDescriptor() = default;
+
+Result TLASDescriptor::CreateResourceIfNeeded() {
+  for (amber::TLAS* amber_tlas : amber_tlases_) {
+    if (tlases_->find(amber_tlas) == tlases_->end()) {
+      auto& vulkan_tlas = ((*tlases_)[amber_tlas] = MakeUnique<TLAS>(device_));
+      Result r = vulkan_tlas->CreateTLAS(amber_tlas, blases_);
+      if (!r.IsSuccess())
+        return r;
+    }
+  }
+
+  return {};
+}
+
+void TLASDescriptor::UpdateDescriptorSetIfNeeded(
+    VkDescriptorSet descriptor_set) {
+  std::vector<VkAccelerationStructureKHR> as;
+
+  for (auto& amber_tlas : amber_tlases_) {
+    auto vulkan_tlas = tlases_->find(amber_tlas);
+    assert(vulkan_tlas != tlases_->end());
+    as.push_back(vulkan_tlas->second->GetVkTLAS());
+  }
+
+  VkWriteDescriptorSetAccelerationStructureKHR writeDescriptorTlas;
+  writeDescriptorTlas.sType =
+      VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_ACCELERATION_STRUCTURE_KHR;
+  writeDescriptorTlas.pNext = nullptr;
+  writeDescriptorTlas.accelerationStructureCount =
+      static_cast<uint32_t>(as.size());
+  writeDescriptorTlas.pAccelerationStructures = as.data();
+
+  VkWriteDescriptorSet write = VkWriteDescriptorSet();
+  write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
+  write.pNext = &writeDescriptorTlas;
+  write.dstSet = descriptor_set;
+  write.dstBinding = binding_;
+  write.dstArrayElement = 0;
+  write.descriptorCount = static_cast<uint32_t>(as.size());
+  write.descriptorType = GetVkDescriptorType();
+
+  device_->GetPtrs()->vkUpdateDescriptorSets(device_->GetVkDevice(), 1, &write,
+                                             0, nullptr);
+}
+
+}  // namespace vulkan
+}  // namespace amber
diff --git a/src/vulkan/tlas_descriptor.h b/src/vulkan/tlas_descriptor.h
new file mode 100644
index 0000000..d043ce2
--- /dev/null
+++ b/src/vulkan/tlas_descriptor.h
@@ -0,0 +1,59 @@
+// Copyright 2024 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef SRC_VULKAN_TLAS_DESCRIPTOR_H_
+#define SRC_VULKAN_TLAS_DESCRIPTOR_H_
+
+#include <memory>
+#include <vector>
+
+#include "src/vulkan/descriptor.h"
+#include "src/vulkan/tlas.h"
+#include "src/vulkan/transfer_image.h"
+
+namespace amber {
+namespace vulkan {
+
+class TLASDescriptor : public Descriptor {
+ public:
+  TLASDescriptor(amber::TLAS* tlas,
+                 DescriptorType type,
+                 Device* device,
+                 BlasesMap* blases,
+                 TlasesMap* tlases,
+                 uint32_t desc_set,
+                 uint32_t binding);
+  ~TLASDescriptor() override;
+
+  void UpdateDescriptorSetIfNeeded(VkDescriptorSet descriptor_set) override;
+
+  Result CreateResourceIfNeeded() override;
+
+  void AddAmberTLAS(amber::TLAS* tlas) { amber_tlases_.push_back(tlas); }
+  uint32_t GetDescriptorCount() override {
+    return static_cast<uint32_t>(amber_tlases_.size());
+  }
+  TLASDescriptor* AsTLASDescriptor() override { return this; }
+
+ private:
+  std::vector<amber::TLAS*> amber_tlases_;
+  BlasesMap* blases_;
+  TlasesMap* tlases_;
+};
+
+}  // namespace vulkan
+}  // namespace amber
+
+#endif  // SRC_VULKAN_TLAS_DESCRIPTOR_H_
diff --git a/src/vulkan/transfer_buffer.cc b/src/vulkan/transfer_buffer.cc
index 512fb7b..174c42b 100644
--- a/src/vulkan/transfer_buffer.cc
+++ b/src/vulkan/transfer_buffer.cc
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -56,10 +57,8 @@ Result TransferBuffer::Initialize() {
     return r;
 
   uint32_t memory_type_index = 0;
-  r = AllocateAndBindMemoryToVkBuffer(buffer_, &memory_,
-                                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
-                                          VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
-                                      true, &memory_type_index);
+  r = AllocateAndBindMemoryToVkBuffer(
+      buffer_, &memory_, GetMemoryPropertiesFlags(), true, &memory_type_index);
   if (!r.IsSuccess())
     return r;
 
@@ -90,6 +89,17 @@ Result TransferBuffer::Initialize() {
   return MapMemory(memory_);
 }
 
+VkDeviceAddress TransferBuffer::getBufferDeviceAddress() {
+  const VkBufferDeviceAddressInfo bufferDeviceAddressInfo = {
+      VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO_KHR,
+      nullptr,
+      GetVkBuffer(),
+  };
+
+  return device_->GetPtrs()->vkGetBufferDeviceAddress(device_->GetVkDevice(),
+                                                      &bufferDeviceAddressInfo);
+}
+
 void TransferBuffer::CopyToDevice(CommandBuffer* command_buffer) {
   // This is redundant because this buffer is always host visible
   // and coherent and vkQueueSubmit will make writes from host
diff --git a/src/vulkan/transfer_buffer.h b/src/vulkan/transfer_buffer.h
index 7d96bec..8734363 100644
--- a/src/vulkan/transfer_buffer.h
+++ b/src/vulkan/transfer_buffer.h
@@ -1,4 +1,5 @@
 // Copyright 2018 The Amber Authors.
+// Copyright (C) 2024 Advanced Micro Devices, Inc. All rights reserved.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -48,6 +49,7 @@ class TransferBuffer : public Resource {
   const VkBufferView* GetVkBufferView() const { return &view_; }
 
   VkBuffer GetVkBuffer() const { return buffer_; }
+  VkDeviceAddress getBufferDeviceAddress();
 
   /// Records a command on |command_buffer| to copy the buffer contents from the
   /// host to the device.
diff --git a/src/vulkan/vertex_buffer_test.cc b/src/vulkan/vertex_buffer_test.cc
index eb8a7bd..14b9ee9 100644
--- a/src/vulkan/vertex_buffer_test.cc
+++ b/src/vulkan/vertex_buffer_test.cc
@@ -36,7 +36,8 @@ class DummyDevice : public Device {
                VkPhysicalDevice(),
                0u,
                VkDevice(this),
-               VkQueue()) {
+               VkQueue(),
+               nullptr) {
     memory_.resize(64);
     dummyPtrs_.vkCreateBuffer = vkCreateBuffer;
     dummyPtrs_.vkGetBufferMemoryRequirements = vkGetBufferMemoryRequirements;
diff --git a/src/vulkan/vk-funcs-1-0.inc b/src/vulkan/vk-funcs-1-0.inc
index b5a7ac0..033e49f 100644
--- a/src/vulkan/vk-funcs-1-0.inc
+++ b/src/vulkan/vk-funcs-1-0.inc
@@ -19,8 +19,12 @@ AMBER_VK_FUNC(vkCmdDrawIndexed)
 AMBER_VK_FUNC(vkCmdEndRenderPass)
 AMBER_VK_FUNC(vkCmdPipelineBarrier)
 AMBER_VK_FUNC(vkCmdPushConstants)
+AMBER_VK_FUNC(vkCmdResetQueryPool)
+AMBER_VK_FUNC(vkCmdWriteTimestamp)
 AMBER_VK_FUNC(vkCreateBuffer)
 AMBER_VK_FUNC(vkCreateBufferView)
+AMBER_VK_FUNC(vkGetBufferDeviceAddress)
+AMBER_VK_FUNC(vkGetQueryPoolResults)
 AMBER_VK_FUNC(vkCreateCommandPool)
 AMBER_VK_FUNC(vkCreateComputePipelines)
 AMBER_VK_FUNC(vkCreateDescriptorPool)
@@ -31,6 +35,7 @@ AMBER_VK_FUNC(vkCreateGraphicsPipelines)
 AMBER_VK_FUNC(vkCreateImage)
 AMBER_VK_FUNC(vkCreateImageView)
 AMBER_VK_FUNC(vkCreatePipelineLayout)
+AMBER_VK_FUNC(vkCreateQueryPool)
 AMBER_VK_FUNC(vkCreateRenderPass)
 AMBER_VK_FUNC(vkCreateSampler)
 AMBER_VK_FUNC(vkCreateShaderModule)
@@ -45,6 +50,7 @@ AMBER_VK_FUNC(vkDestroyImage)
 AMBER_VK_FUNC(vkDestroyImageView)
 AMBER_VK_FUNC(vkDestroyPipeline)
 AMBER_VK_FUNC(vkDestroyPipelineLayout)
+AMBER_VK_FUNC(vkDestroyQueryPool)
 AMBER_VK_FUNC(vkDestroyRenderPass)
 AMBER_VK_FUNC(vkDestroySampler)
 AMBER_VK_FUNC(vkDestroyShaderModule)
diff --git a/src/vulkan/vk-funcs-1-1.inc b/src/vulkan/vk-funcs-1-1.inc
index 7fca3c5..a116864 100644
--- a/src/vulkan/vk-funcs-1-1.inc
+++ b/src/vulkan/vk-funcs-1-1.inc
@@ -1 +1,10 @@
 AMBER_VK_FUNC(vkGetPhysicalDeviceProperties2)
+OPTIONAL AMBER_VK_FUNC(vkCreateRayTracingPipelinesKHR)
+OPTIONAL AMBER_VK_FUNC(vkCreateAccelerationStructureKHR)
+OPTIONAL AMBER_VK_FUNC(vkDestroyAccelerationStructureKHR)
+OPTIONAL AMBER_VK_FUNC(vkGetAccelerationStructureBuildSizesKHR)
+OPTIONAL AMBER_VK_FUNC(vkBuildAccelerationStructuresKHR)
+OPTIONAL AMBER_VK_FUNC(vkCmdBuildAccelerationStructuresKHR)
+OPTIONAL AMBER_VK_FUNC(vkGetAccelerationStructureDeviceAddressKHR)
+OPTIONAL AMBER_VK_FUNC(vkCmdTraceRaysKHR)
+OPTIONAL AMBER_VK_FUNC(vkGetRayTracingShaderGroupHandlesKHR)
\ No newline at end of file
diff --git a/tests/benchmarks/README.md b/tests/benchmarks/README.md
new file mode 100644
index 0000000..a0ed074
--- /dev/null
+++ b/tests/benchmarks/README.md
@@ -0,0 +1,5 @@
+# Benchmarks
+
+These (micro) benchmarks are used to determine the performance of specific gpu operations and features.
+These benchmarks are WIP, as-is, and not considered stable.
+
diff --git a/tests/benchmarks/bandwidth/cache_random_access.amber b/tests/benchmarks/bandwidth/cache_random_access.amber
new file mode 100644
index 0000000..e848fba
--- /dev/null
+++ b/tests/benchmarks/bandwidth/cache_random_access.amber
@@ -0,0 +1,74 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# This benchmark tests the latency cached memory
+# Configs to manually modify:
+#  - kStride (prime number) : Caching behavior for pseudo random access
+#  - number of loop unrolls : latency of single thread
+
+SHADER compute cached_memory_random GLSL
+#version 430
+
+layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;
+
+layout(set = 0, binding = 0) buffer BlockA { 
+  uint data[];
+} ssbo_read;
+
+layout(set = 0, binding = 1) buffer BlockB {
+   uint data[];
+} ssbo_write;
+
+uint ReadStrided(uint iter_val, uint ii){
+ // iter_val param will always be zero
+ // Suggested strides (prime) 1, 3, 47, 14627
+ const uint kStride =  1u;
+ const uint kSizeMask16M = 0xFFFFFF;
+ return ssbo_read.data[(iter_val + (ii * kStride)) & kSizeMask16M];
+}
+
+void main() {
+    uint iter_val = ssbo_read.data[gl_GlobalInvocationID.x];
+    for(uint i = 0;i<10000;i+=10){
+      // 10x
+      iter_val = ReadStrided(iter_val, i);
+      iter_val = ReadStrided(iter_val, i+1);
+      iter_val = ReadStrided(iter_val, i+2);
+      iter_val = ReadStrided(iter_val, i+3);
+      iter_val = ReadStrided(iter_val, i+4);
+      iter_val = ReadStrided(iter_val, i+5);
+      iter_val = ReadStrided(iter_val, i+6);
+      iter_val = ReadStrided(iter_val, i+7);
+      iter_val = ReadStrided(iter_val, i+8);
+      iter_val = ReadStrided(iter_val, i+9);
+    }
+    ssbo_write.data[gl_GlobalInvocationID.x]  = iter_val;
+}
+END
+
+BUFFER buf_read DATA_TYPE uint32 SIZE 16777216 FILL 0
+BUFFER buf_write DATA_TYPE uint32 SIZE 1048576 FILL 0
+
+PIPELINE compute pipeline
+  ATTACH cached_memory_random
+  BIND BUFFER buf_read AS storage DESCRIPTOR_SET 0 BINDING 0
+  BIND BUFFER buf_write AS storage DESCRIPTOR_SET 0 BINDING 1
+END
+
+REPEAT 333
+RUN TIMED_EXECUTION pipeline 1 1 1
+END
+
diff --git a/tests/benchmarks/conditional/test_and_write.amber b/tests/benchmarks/conditional/test_and_write.amber
new file mode 100644
index 0000000..72247f0
--- /dev/null
+++ b/tests/benchmarks/conditional/test_and_write.amber
@@ -0,0 +1,93 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# This benchmark is to test the cost of real branches
+# It has been crafted ensure that a select operation cannot be used.
+#
+# Configs to manually modify:
+#  - buf_init_data fill to non zero : Branch taken/not
+#  - local_size_x (workgroup size) : Single SM throughput
+#  - number of loop unrolls : latency of single thread
+#  - compute/dispatch size (currently 1) : Device throughput
+
+
+SHADER compute conditional_test GLSL
+#version 430
+
+layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;
+
+layout(set = 0, binding = 0) buffer BlockA { 
+  uint data[];
+} ssbo_init_data;
+
+layout(set = 0, binding = 1) buffer BlockB {
+  uint data[];
+} ssbo_write;
+
+uint TestAndOperate(uint iter_val, uint invx){
+  // We want this to be a real branch per thread
+  if(iter_val > invx){ 
+    // Simple LCGs that ensure iter_val is greater than 1024 
+    iter_val = ((iter_val*13u) % 6631u) + 1024;
+    iter_val = ((iter_val*213u) % 631u) + 1024;
+    // You must mutate memory to avoid the compiler just using a select
+    ssbo_write.data[invx] = iter_val;
+  }
+  return iter_val;
+}
+
+void main() {
+    uint invx = gl_GlobalInvocationID.x;
+    uint iter_val = ssbo_init_data.data[invx];
+    for(uint i = 0;i<1000;i++){
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+      iter_val = TestAndOperate(iter_val, invx);
+    }
+    ssbo_write.data[invx]  = iter_val;
+}
+END
+
+BUFFER buf_init_data DATA_TYPE uint32 SIZE 1048576 FILL 0
+BUFFER out_buff DATA_TYPE uint32 SIZE 1048576 FILL 0
+
+PIPELINE compute pipeline
+  ATTACH conditional_test
+  BIND BUFFER buf_init_data AS storage DESCRIPTOR_SET 0 BINDING 0
+  BIND BUFFER out_buff AS storage DESCRIPTOR_SET 0 BINDING 1
+END
+
+REPEAT 133
+RUN TIMED_EXECUTION pipeline 1 1 1
+END
diff --git a/tests/benchmarks/parallel_advantage/parallel_atan.amber b/tests/benchmarks/parallel_advantage/parallel_atan.amber
new file mode 100644
index 0000000..c606e8b
--- /dev/null
+++ b/tests/benchmarks/parallel_advantage/parallel_atan.amber
@@ -0,0 +1,81 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# This benchmark tests the latency and throughput of multiply atan function.
+# Configs to manually modify:
+#  - local_size_x (workgroup size) : Single SM throughput
+#  - number of loop unrolls : latency of single thread
+#  - compute/dispatch size (currently 1) : Device throughput
+
+SHADER compute parallel_madd_test GLSL
+#version 430
+
+layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;
+
+layout(set = 0, binding = 0) buffer BlockA {
+   float data[];
+} ssbo_fake_volatile;
+
+layout(set = 0, binding = 1) buffer BlockB {
+  float data[];
+} ssbo_array;
+
+void main() {
+  float val_iter = ssbo_fake_volatile.data[gl_GlobalInvocationID.x];
+   for(int i = 0 ;i < 1000;i++){
+      // Loop unroll to reduce looping logic overhead.
+      // 10x
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+
+
+      // 10x
+      // This additional 10 can removed to create a difference in measurement.
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+      val_iter = atan(val_iter);
+   }
+  ssbo_array.data[gl_GlobalInvocationID.x] = val_iter;
+}
+END
+
+BUFFER buf_fake_volatile DATA_TYPE float SIZE 1048576 FILL 0.915613
+BUFFER out_buff DATA_TYPE float SIZE 1048576 FILL 0.0
+
+PIPELINE compute pipeline
+  ATTACH parallel_madd_test
+  BIND BUFFER buf_fake_volatile AS storage DESCRIPTOR_SET 0 BINDING 0
+  BIND BUFFER out_buff AS storage DESCRIPTOR_SET 0 BINDING 1
+END
+
+REPEAT 333
+RUN TIMED_EXECUTION pipeline 1 1 1
+END
diff --git a/tests/benchmarks/parallel_advantage/parallel_cos.amber b/tests/benchmarks/parallel_advantage/parallel_cos.amber
new file mode 100644
index 0000000..81f1302
--- /dev/null
+++ b/tests/benchmarks/parallel_advantage/parallel_cos.amber
@@ -0,0 +1,82 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# This benchmark tests the latency and throughput of cos function.
+# Configs to manually modify:
+#  - local_size_x (workgroup size) : Single SM throughput
+#  - number of loop unrolls : latency of single thread
+#  - compute/dispatch size (currently 1) : Device throughput
+
+SHADER compute parallel_madd_test GLSL
+#version 430
+
+layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;
+
+layout(set = 0, binding = 0) buffer BlockA {
+   float data[];
+} ssbo_fake_volatile;
+
+layout(set = 0, binding = 1) buffer BlockB {
+  float data[];
+} ssbo_array;
+
+void main() {
+  float val_iter = ssbo_fake_volatile.data[gl_GlobalInvocationID.x];
+   for(int i = 0 ;i < 1000;i++){
+      // Loop unroll to reduce looping logic overhead.
+      // 10x
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+
+
+      // 10x
+      // This additional 10 can removed to create a difference in measurement.
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+      val_iter = cos(val_iter);
+
+   }
+  ssbo_array.data[gl_GlobalInvocationID.x] = val_iter;
+}
+END
+
+BUFFER buf_fake_volatile DATA_TYPE float SIZE 1048576 FILL 3.0
+BUFFER out_buff DATA_TYPE float SIZE 1048576 FILL 0.0
+
+PIPELINE compute pipeline
+  ATTACH parallel_madd_test
+  BIND BUFFER buf_fake_volatile AS storage DESCRIPTOR_SET 0 BINDING 0
+  BIND BUFFER out_buff AS storage DESCRIPTOR_SET 0 BINDING 1
+END
+
+REPEAT 333
+RUN TIMED_EXECUTION pipeline 1 1 1
+END
diff --git a/tests/benchmarks/parallel_advantage/parallel_inv_sqrt.amber b/tests/benchmarks/parallel_advantage/parallel_inv_sqrt.amber
new file mode 100644
index 0000000..2701919
--- /dev/null
+++ b/tests/benchmarks/parallel_advantage/parallel_inv_sqrt.amber
@@ -0,0 +1,81 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# This benchmark tests the latency and throughput of inverse sqrt.
+# Configs to manually modify:
+#  - local_size_x (workgroup size) : Single SM throughput
+#  - number of loop unrolls : latency of single thread
+#  - compute/dispatch size (currently 1) : Device throughput
+
+SHADER compute parallel_madd_test GLSL
+#version 430
+
+layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;
+
+layout(set = 0, binding = 0) buffer BlockA {
+   float data[];
+} ssbo_fake_volatile;
+
+layout(set = 0, binding = 1) buffer BlockB {
+  float data[];
+} ssbo_array;
+
+void main() {
+  float val_iter = ssbo_fake_volatile.data[gl_GlobalInvocationID.x];
+   for(int i = 0 ;i < 1000;i++){
+      // Loop unroll to reduce looping logic overhead.
+      // 10x
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+
+      // 10x
+      // This additional 10 can removed to create a difference in measurement.
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+      val_iter = inversesqrt(val_iter);
+
+   }
+  ssbo_array.data[gl_GlobalInvocationID.x] = val_iter;
+}
+END
+
+BUFFER buf_fake_volatile DATA_TYPE float SIZE 1048576 FILL 0.9991315
+BUFFER out_buff DATA_TYPE float SIZE 1048576 FILL 0.0
+
+PIPELINE compute pipeline
+  ATTACH parallel_madd_test
+  BIND BUFFER buf_fake_volatile AS storage DESCRIPTOR_SET 0 BINDING 0
+  BIND BUFFER out_buff AS storage DESCRIPTOR_SET 0 BINDING 1
+END
+
+REPEAT 333
+RUN TIMED_EXECUTION pipeline 1 1 1
+END
diff --git a/tests/benchmarks/parallel_advantage/parallel_madd.amber b/tests/benchmarks/parallel_advantage/parallel_madd.amber
new file mode 100644
index 0000000..cfd2f9c
--- /dev/null
+++ b/tests/benchmarks/parallel_advantage/parallel_madd.amber
@@ -0,0 +1,80 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# This benchmark tests the latency and throughput of multiply add (madd).
+# Configs to manually modify:
+#  - local_size_x (workgroup size) : Single SM throughput
+#  - number of loop unrolls : latency of single thread
+#  - compute/dispatch size (currently 1) : Device throughput
+
+SHADER compute parallel_madd_test GLSL
+#version 430
+
+layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;
+
+layout(set = 0, binding = 0) buffer BlockA {
+   float data[];
+} ssbo_fake_volatile;
+
+layout(set = 0, binding = 1) buffer BlockB {
+  float data[];
+} ssbo_array;
+
+void main() {
+  float val_iter = ssbo_fake_volatile.data[gl_GlobalInvocationID.x];
+   for(int i = 0; i < 1000; i++){
+      // Loop unroll to reduce looping logic overhead.
+      // 10x
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+
+      // 10x
+      // This additional 10 can removed to create a difference in measurment.
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+      val_iter += val_iter*0.001234;
+   }
+  ssbo_array.data[gl_GlobalInvocationID.x] = val_iter;
+}
+END
+
+BUFFER buf_fake_volatile DATA_TYPE float SIZE 1048576 FILL 0.0
+BUFFER out_buff DATA_TYPE float SIZE 1048576 FILL 0.0
+
+PIPELINE compute pipeline
+  ATTACH parallel_madd_test
+  BIND BUFFER buf_fake_volatile AS storage DESCRIPTOR_SET 0 BINDING 0
+  BIND BUFFER out_buff AS storage DESCRIPTOR_SET 0 BINDING 1
+END
+
+REPEAT 333
+RUN TIMED_EXECUTION pipeline 1 1 1
+END
diff --git a/tests/benchmarks/shared_local/internal_workgroup_ssbo.amber b/tests/benchmarks/shared_local/internal_workgroup_ssbo.amber
new file mode 100644
index 0000000..b6c9f5d
--- /dev/null
+++ b/tests/benchmarks/shared_local/internal_workgroup_ssbo.amber
@@ -0,0 +1,89 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# This benchmark tests the latency and throughput of
+# shared memory vs  ssbo (main cached) memory.
+# Configs to manually modify:
+#  - Comment in/out declaration : Shared vs ssbo
+#  - local_size_x (workgroup size) : Single SM throughput
+#  - number of loop unrolls : latency of single thread
+#  - compute/dispatch size (currently 1) : Device throughput
+
+
+SHADER compute workgroup_shared_vs_ssbo GLSL
+#version 430
+
+layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;
+
+// Comment in/out these two lines to test shared memory
+struct BlockB { uint data[8]; };  shared BlockB ssbo_wr;
+//layout(set = 0, binding = 0) buffer BlockB { uint data[];} ssbo_wr;
+
+layout(set = 0, binding = 1) buffer BlockA { 
+  uint data[];
+} ssbo_fake_volatile;
+
+
+void main() {
+    // This is required when using shared memory
+    if( gl_LocalInvocationID.x == 0){
+      ssbo_wr.data[0] = 0;
+    }
+    barrier();
+    uint fv = ssbo_fake_volatile.data[0];
+    uint iter_val = ssbo_wr.data[fv];
+    for(uint i = 0;i<1000;i++){
+      // 10x
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+
+      // 10x
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+      iter_val = ssbo_wr.data[iter_val];
+    }
+    ssbo_wr.data[gl_LocalInvocationID.x]  = iter_val;
+}
+END
+
+BUFFER buf_uint DATA_TYPE uint32 SIZE 1024 FILL 0
+BUFFER buf_fake_volatile DATA_TYPE uint32 SIZE 1048576 FILL 0
+
+PIPELINE compute pipeline
+  ATTACH workgroup_shared_vs_ssbo
+  BIND BUFFER buf_uint AS storage DESCRIPTOR_SET 0 BINDING 0
+  BIND BUFFER buf_fake_volatile AS storage DESCRIPTOR_SET 0 BINDING 1
+END
+
+REPEAT 333
+RUN TIMED_EXECUTION pipeline 1 1 1
+END
+
diff --git a/tests/cases/compute_timed_execution_single.amber b/tests/cases/compute_timed_execution_single.amber
new file mode 100644
index 0000000..77e295e
--- /dev/null
+++ b/tests/cases/compute_timed_execution_single.amber
@@ -0,0 +1,42 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+SHADER compute atomic_sum_all GLSL
+#version 430
+
+layout(local_size_x = 16, local_size_y = 16, local_size_z = 1) in;
+
+layout(set = 0, binding = 0) buffer BlockUint {
+  uint data;
+} ssbo_uint;
+
+void main() {
+    atomicAdd(ssbo_uint.data, uint(1));
+}
+END
+
+BUFFER buf_uint DATA_TYPE uint32 DATA
+0
+END
+
+
+PIPELINE compute pipeline
+  ATTACH atomic_sum_all
+  BIND BUFFER buf_uint AS storage DESCRIPTOR_SET 0 BINDING 0
+END
+
+RUN TIMED_EXECUTION pipeline 128 128 1
+
+EXPECT buf_uint IDX 0 EQ 4194304
diff --git a/tests/cases/draw_rect_timed_execution.amber b/tests/cases/draw_rect_timed_execution.amber
new file mode 100644
index 0000000..1309d8d
--- /dev/null
+++ b/tests/cases/draw_rect_timed_execution.amber
@@ -0,0 +1,42 @@
+#!amber
+# Copyright 2024 The Amber Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+SHADER vertex vert_shader PASSTHROUGH
+SHADER fragment frag_shader GLSL
+#version 430
+layout(location = 0) out vec4 color_out;
+void main() {
+  float x = gl_FragCoord.x;
+  // Small busy loop.
+  // x final result will be zero.
+  for(int i= 0;i <10;i++) {
+    x = x*0.00001;
+  }
+  color_out = vec4(x, 0.0, 0.0, 1.0);
+}
+END
+
+BUFFER framebuffer FORMAT B8G8R8A8_UNORM
+
+PIPELINE graphics my_pipeline
+  ATTACH vert_shader
+  ATTACH frag_shader
+  FRAMEBUFFER_SIZE 1024 1024
+  BIND BUFFER framebuffer AS color LOCATION 0
+END
+
+RUN TIMED_EXECUTION my_pipeline DRAW_RECT POS 0 0 SIZE 1024 1024
+EXPECT framebuffer IDX 0 0 SIZE 1024 1024 EQ_RGBA 0 0 0 255
+ 
\ No newline at end of file
diff --git a/tests/cases/float16.amber b/tests/cases/float16.amber
index 0a8fd04..81de3e6 100644
--- a/tests/cases/float16.amber
+++ b/tests/cases/float16.amber
@@ -18,6 +18,7 @@ DEVICE_EXTENSION VK_KHR_16bit_storage
 DEVICE_EXTENSION VK_KHR_storage_buffer_storage_class
 DEVICE_FEATURE Float16Int8Features.shaderFloat16
 DEVICE_FEATURE Storage16BitFeatures.storageBuffer16BitAccess
+DEVICE_FEATURE Storage16BitFeatures.uniformAndStorageBuffer16BitAccess
 
 SHADER compute f16 GLSL
 #version 450
diff --git a/tests/cases/shader_file.amber b/tests/cases/shader_file.amber
new file mode 100644
index 0000000..caaa2a0
--- /dev/null
+++ b/tests/cases/shader_file.amber
@@ -0,0 +1,25 @@
+#!amber
+# Copyright 2024 Advanced Micro Devices, Inc. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+SHADER compute shader GLSL FILE shader_file.comp
+BUFFER buffer DATA_TYPE uint32 DATA 0 END
+
+PIPELINE compute the_pipeline
+  ATTACH shader
+  BIND BUFFER buffer AS storage DESCRIPTOR_SET 0 BINDING 0
+END
+
+RUN the_pipeline 1 1 1
+EXPECT buffer IDX 0 EQ 1
diff --git a/tests/cases/shader_file.comp b/tests/cases/shader_file.comp
new file mode 100644
index 0000000..f3e86e1
--- /dev/null
+++ b/tests/cases/shader_file.comp
@@ -0,0 +1,22 @@
+// Copyright 2024 Advanced Micro Devices, Inc.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#version 430
+layout(set = 0, binding = 0) buffer buf {
+  uint x;
+};
+
+void main() {
+  x = 1;
+}
diff --git a/tests/cases/shader_spirv_bin.amber b/tests/cases/shader_spirv_bin.amber
new file mode 100644
index 0000000..28a54e6
--- /dev/null
+++ b/tests/cases/shader_spirv_bin.amber
@@ -0,0 +1,25 @@
+#!amber
+# Copyright 2024 Advanced Micro Devices, Inc. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+SHADER compute shader SPIRV-BIN FILE shader_spirv_bin.spv
+BUFFER buffer DATA_TYPE uint32 DATA 0 END
+
+PIPELINE compute the_pipeline
+  ATTACH shader
+  BIND BUFFER buffer AS storage DESCRIPTOR_SET 0 BINDING 0
+END
+
+RUN the_pipeline 1 1 1
+EXPECT buffer IDX 0 EQ 1
diff --git a/tests/cases/shader_spirv_bin.spv b/tests/cases/shader_spirv_bin.spv
new file mode 100644
index 0000000..6e836b1
Binary files /dev/null and b/tests/cases/shader_spirv_bin.spv differ
diff --git a/tests/run_tests.py b/tests/run_tests.py
index 30dc1bb..2dd77b2 100755
--- a/tests/run_tests.py
+++ b/tests/run_tests.py
@@ -86,6 +86,8 @@ SUPPRESSIONS_SWIFTSHADER = [
   "draw_indexed_uint8.amber",
   # Intermittent failures (https://github.com/google/amber/issues/1019).
   "draw_polygon_mode.amber",
+  # Missing opcapability abort
+  "draw_triangle_list_hlsl.amber",
 ]
 
 OPENCL_CASES = [
diff --git a/third_party/CMakeLists.txt b/third_party/CMakeLists.txt
index d98998b..eb95100 100644
--- a/third_party/CMakeLists.txt
+++ b/third_party/CMakeLists.txt
@@ -52,10 +52,13 @@ endif()
 if (${AMBER_USE_LOCAL_VULKAN})
   add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vulkan-headers)
 
+  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vulkan-utility-libraries)
+
   # Skip adding the validation layers and the Vulkan loader on Android.
   if (NOT ANDROID)
 
     set(BUILD_TESTS FALSE)
+    set(BUILD_WERROR OFF)
 
     # The vulkan-loader CMake file assumes that directory exists if
     # Wayland support is to be built.
@@ -66,8 +69,6 @@ if (${AMBER_USE_LOCAL_VULKAN})
     message(STATUS "Amber: Disabling X11 support in Vulkan-Loader")
     set(BUILD_WSI_XLIB_SUPPORT OFF CACHE BOOL "" FORCE)
 
-    set(ROBIN_HOOD_HASHING_INSTALL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/robin-hood-hashing" CACHE STRING "" FORCE)
-    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/robin-hood-hashing)
     set(SPIRV_HEADERS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/spirv-headers/include" CACHE STRING "" FORCE)
 
     add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vulkan-loader)
@@ -85,6 +86,10 @@ if (${AMBER_ENABLE_SWIFTSHADER})
   set(SWIFTSHADER_BUILD_VULKAN TRUE)
   set(SWIFTSHADER_BUILD_SAMPLES FALSE)
   set(SWIFTSHADER_BUILD_TESTS FALSE)
+  set(SWIFTSHADER_BUILD_PVR FALSE)
+  set(SWIFTSHADER_BUILD_BENCHMARKS FALSE)
+  set(SWIFTSHADER_WARNINGS_AS_ERRORS FALSE)
+  set(SWIFTSHADER_USE_GROUP_SOURCES FALSE)
   set(SWIFTSHADER_WARNINGS_AS_ERRORS FALSE)
   set(SWIFTSHADER_LOGGING_LEVEL "Error")
 
@@ -129,6 +134,13 @@ if (${AMBER_ENABLE_DXC})
   set(LLVM_BUILD_STATIC ON CACHE BOOL "")
   set(BUILD_SHARED_LIBS OFF CACHE BOOL "")
 
+  set(LLVM_ENABLE_WERROR OFF)
+
+  # Disable HCT.cmake looking for and using clang-format. This is used to compare generated files
+  # against the copy that is committed to the repo, but fails because the DXC .clangformat file is
+  # not visible from our build dir. We don't need this validation, so just disable it.
+  set(CLANG_FORMAT_EXE "" CACHE STRING "" FORCE)
+
   add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dxc EXCLUDE_FROM_ALL)
 
   if (MSVC)
diff --git a/tools/amber-mode.el b/tools/amber-mode.el
index 90173ec..0fdabbf 100644
--- a/tools/amber-mode.el
+++ b/tools/amber-mode.el
@@ -46,7 +46,7 @@
 ;;               "tessellation_control" "multi" "framebuffer" "graphics" "uniform"
 ;;               "storage" "push_constant" "color" "depth_stencil" "EQ" "NE" "LT"
 ;;               "LE" "GT" "GE" "EQ_RGB" "EQ_RGBA" "EQ_BUFFER" "GLSL" "HLSL"
-;;               "SPIRV-ASM" "SPIRV-HEX" "OPENCL-C"
+;;               "SPIRV-ASM" "SPIRV-HEX" "SPIRV-BIN" "OPENCL-C"
 ;;               ) t)
 
 ;; (regexp-opt '(
diff --git a/tools/amber-syntax.vim b/tools/amber-syntax.vim
index 4da5204..81f240f 100644
--- a/tools/amber-syntax.vim
+++ b/tools/amber-syntax.vim
@@ -63,7 +63,7 @@ syn keyword amberComparator EQ_HISTOGRAM_EMD_BUFFER
 syn keyword amberKeyword compute vertex geometry fragment graphics
 syn keyword amberKeyword tessellation_evaulation tessellation_control multi
 
-syn keyword amberFormat GLSL HLSL SPIRV-ASM SPIRV-HEX OPENCL-C
+syn keyword amberFormat GLSL HLSL SPIRV-ASM SPIRV-HEX SPIRV-BIN OPENCL-C
 
 syn keyword amberTopology point_list line_list line_list_with_adjacency
 syn keyword amberTopology line_strip line_strip_with_adjacency triangle_list
diff --git a/tools/amber.sublime-syntax b/tools/amber.sublime-syntax
index 3141153..e55dbbd 100644
--- a/tools/amber.sublime-syntax
+++ b/tools/amber.sublime-syntax
@@ -42,7 +42,7 @@ contexts:
       scope: constant.character.escape.amber
     - match: '\b(EQ|NE|LT|LE|GT|GE|EQ_RGB|EQ_RGBA|EQ_BUFFER|RMSE_BUFFER)\b'
       scope: constant.character.esape.amber
-    - match: '\b(GLSL|HLSL|SPIRV-ASM|SPIRV-HEX|OPENCL-C)\b'
+    - match: '\b(GLSL|HLSL|SPIRV-ASM|SPIRV-HEX|SPIRV-BIN|OPENCL-C)\b'
       scope: constant.character.escape.amber
 
     - match: '\b(point_list|line_list|line_list_with_adjacency|line_strip)\b'
diff --git a/tools/check_language.py b/tools/check_language.py
index b7ca528..c0e6858 100755
--- a/tools/check_language.py
+++ b/tools/check_language.py
@@ -1,4 +1,4 @@
-#!/usr/bin/env python
+#!/usr/bin/env python3
 
 # Copyright 2020 The Amber Authors. All rights reserved.
 #
diff --git a/tools/git-sync-deps b/tools/git-sync-deps
index 0a544d6..3cd5b7c 100755
--- a/tools/git-sync-deps
+++ b/tools/git-sync-deps
@@ -237,6 +237,9 @@ def git_sync_deps(deps_file_path, command_line_os_requests, verbose):
     if not with_dxc and directory == 'third_party/dxc':
       continue
 
+    if not with_dxc and directory == 'third_party/DirectX-Headers':
+      continue
+
     if not with_swiftshader and directory == 'third_party/swiftshader':
       continue
 
diff --git a/tools/run-lint.sh b/tools/run-lint.sh
index 3fbaf93..1f172cb 100755
--- a/tools/run-lint.sh
+++ b/tools/run-lint.sh
@@ -15,6 +15,6 @@
 
 set -e  # fail on error
 
-FILTERS=-build/header_guard
+FILTERS=-build/header_guard,-readability/fn_size
 ./third_party/cpplint/cpplint.py  --filter "$FILTERS" `find src samples -type f`
 ./third_party/cpplint/cpplint.py  --filter "$FILTERS" --root include `find ./include -type f`
diff --git a/tools/update_vk_wrappers.py b/tools/update_vk_wrappers.py
index 0fc9f87..d91115b 100755
--- a/tools/update_vk_wrappers.py
+++ b/tools/update_vk_wrappers.py
@@ -26,14 +26,18 @@ from string import Template
 
 def read_inc(file):
   methods = []
-  pattern = re.compile(r"AMBER_VK_FUNC\((\w+)\)")
+  pattern = re.compile(r"(|OPTIONAL )AMBER_VK_FUNC\((\w+)\)")
   with open(file, 'r') as f:
     for line in f:
       match = pattern.search(line)
       if match == None:
         raise Exception("FAILED TO MATCH PATTERN");
 
-      methods.append(match.group(1))
+      b = False
+      if match.group(1) != None and match.group(1) == "OPTIONAL ":
+        b = True
+      methods.append((match.group(2), b))
+
   return methods
 
 
@@ -69,7 +73,8 @@ def read_vk(file):
 
 def gen_wrappers(methods, xml):
   content = ""
-  for method in methods:
+  for method_ in methods:
+    method = method_[0]
     data = xml[method]
     if data == None:
       raise Exception("Failed to find {}".format(method))
@@ -137,7 +142,8 @@ def gen_wrappers(methods, xml):
 
 def gen_headers(methods, xml):
   content = ""
-  for method in methods:
+  for method_ in methods:
+    method = method_[0]
     data = xml[method]
     if data == None:
       raise Exception("Failed to find {}".format(method))
@@ -161,17 +167,26 @@ def gen_direct(methods):
 if (!(ptrs_.${method} = reinterpret_cast<PFN_${method}>(getInstanceProcAddr(instance_, "${method}")))) {
   return Result("Vulkan: Unable to load ${method} pointer");
 }
+''')
+  template_optional = Template(R'''
+ptrs_.${method} = reinterpret_cast<PFN_${method}>(getInstanceProcAddr(instance_, "${method}"));
 ''')
 
-  for method in methods:
-    content += template.substitute(method=method)
+  for method_ in methods:
+    method = method_[0]
+    optional = method_[1]
+    if (optional):
+      content += template_optional.substitute(method=method)
+    else:
+      content += template.substitute(method=method)
 
   return content
 
 
 def gen_direct_headers(methods):
   content = ""
-  for method in methods:
+  for method_ in methods:
+    method = method_[0]
     content += "PFN_{} {};\n".format(method, method);
 
   return content
```

