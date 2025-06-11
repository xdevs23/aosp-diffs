```diff
diff --git a/.github/workflows/c-cpp.yml b/.github/workflows/c-cpp.yml
new file mode 100644
index 0000000..131ed82
--- /dev/null
+++ b/.github/workflows/c-cpp.yml
@@ -0,0 +1,21 @@
+name: C/C++ CI
+
+on:
+  push:
+    branches: [ "master", "test" ]
+  pull_request:
+    branches: [ "master", "test" ]
+
+jobs:
+  build:
+
+    runs-on: ubuntu-latest
+
+    steps:
+    - uses: actions/checkout@v3
+    - name: install deps
+      run: sudo apt install -y meson ninja-build libdrm-dev libegl1-mesa-dev libgles2-mesa-dev libwayland-dev libx11-xcb-dev libx11-dev libgbm-dev libevdev-dev libfmt-dev
+    - name: configure
+      run: meson setup -Dkmscube=true -Dpykms=enabled -Dwerror=true -Db_lto=true build
+    - name: build
+      run: ninja -v -C build
diff --git a/.gitignore b/.gitignore
index 35f030e..7c59690 100644
--- a/.gitignore
+++ b/.gitignore
@@ -9,3 +9,4 @@ py/__pycache__
 meson.build.user
 subprojects/packagecache/
 subprojects/pybind11-*/
+.cache
diff --git a/METADATA b/METADATA
index f2c8934..a309679 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/libkmsxx
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "kms++"
 description: "libkmsxx is a small C++11 library for kernel mode setting. It tries to implement as little extra as possible while bringing the kms API in a C++ form to the user. It only implements a subset of what libdrm supports."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/tomba/kmsxx"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/tomba/kmsxx"
-  }
-  version: "b12aab5d4bb45e77934d9838576a817bc8defe4b"
   license_type: RECIPROCAL
   last_upgrade_date {
-    year: 2021
+    year: 2025
     month: 1
-    day: 5
+    day: 17
+  }
+  homepage: "https://github.com/tomba/kmsxx"
+  identifier {
+    type: "Git"
+    value: "https://github.com/tomba/kmsxx"
+    version: "aaab406251540429522c5ef7808ee049c65a06d2"
   }
 }
diff --git a/OWNERS b/OWNERS
index f3c79cc..131d7b2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
 adelva@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 9e465ed..f5a815c 100644
--- a/README.md
+++ b/README.md
@@ -1,4 +1,4 @@
-[![Build Status](https://travis-ci.org/tomba/kmsxx.svg?branch=master)](https://travis-ci.org/tomba/kmsxx)
+[![Build Status](https://github.com/tomba/kmsxx/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/tomba/kmsxx/actions/workflows/c-cpp.yml)
 
 # kms++ - C++ library for kernel mode setting
 
@@ -21,16 +21,8 @@ Also included are some simple utilities for KMS and python bindings for kms++.
 
 ## Build instructions:
 
-To build the Python bindings you need to set up the git-submodule for pybind11:
-
-```
-git submodule update --init
-```
-
-And to compile:
-
 ```
-meson build
+meson setup build
 ninja -C build
 ```
 
diff --git a/kms++/inc/kms++/blob.h b/kms++/inc/kms++/blob.h
index 011613d..386e9d5 100644
--- a/kms++/inc/kms++/blob.h
+++ b/kms++/inc/kms++/blob.h
@@ -2,6 +2,7 @@
 
 #include "drmobject.h"
 #include <vector>
+#include <stddef.h>
 
 namespace kms
 {
diff --git a/kms++/inc/kms++/drmobject.h b/kms++/inc/kms++/drmobject.h
index e15ed4c..587f122 100644
--- a/kms++/inc/kms++/drmobject.h
+++ b/kms++/inc/kms++/drmobject.h
@@ -1,5 +1,6 @@
 #pragma once
 
+#include <stdint.h>
 #include <map>
 
 #include "decls.h"
diff --git a/kms++/inc/kms++/framebuffer.h b/kms++/inc/kms++/framebuffer.h
index 6f77b98..fc50b02 100644
--- a/kms++/inc/kms++/framebuffer.h
+++ b/kms++/inc/kms++/framebuffer.h
@@ -40,7 +40,9 @@ public:
 
 	uint32_t width() const override { return m_width; }
 	uint32_t height() const override { return m_height; }
+	PixelFormat format() const override { return m_format; }
 
+	void flush(uint32_t x, uint32_t y, uint32_t width, uint32_t height);
 	void flush();
 
 protected:
@@ -49,6 +51,7 @@ protected:
 private:
 	uint32_t m_width;
 	uint32_t m_height;
+	PixelFormat m_format;
 };
 
 } // namespace kms
diff --git a/kms++/inc/kms++/pagefliphandler.h b/kms++/inc/kms++/pagefliphandler.h
index 2f5fdcd..e727375 100644
--- a/kms++/inc/kms++/pagefliphandler.h
+++ b/kms++/inc/kms++/pagefliphandler.h
@@ -1,5 +1,7 @@
 #pragma once
 
+#include <stdint.h>
+
 namespace kms
 {
 class PageFlipHandlerBase
diff --git a/kms++/inc/kms++/pixelformats.h b/kms++/inc/kms++/pixelformats.h
index 6f2671b..e334ee6 100644
--- a/kms++/inc/kms++/pixelformats.h
+++ b/kms++/inc/kms++/pixelformats.h
@@ -31,6 +31,10 @@ enum class PixelFormat : uint32_t {
 	YVYU = MakeFourCC("YVYU"),
 	VYUY = MakeFourCC("VYUY"),
 
+	Y210 = MakeFourCC("Y210"),
+	Y212 = MakeFourCC("Y212"),
+	Y216 = MakeFourCC("Y216"),
+
 	XRGB8888 = MakeFourCC("XR24"),
 	XBGR8888 = MakeFourCC("XB24"),
 	RGBX8888 = MakeFourCC("RX24"),
@@ -66,12 +70,12 @@ enum class PixelFormat : uint32_t {
 	BGRA1010102 = MakeFourCC("BA30"),
 };
 
-static inline PixelFormat FourCCToPixelFormat(const std::string& fourcc)
+inline PixelFormat FourCCToPixelFormat(const std::string& fourcc)
 {
 	return (PixelFormat)MakeFourCC(fourcc.c_str());
 }
 
-static inline std::string PixelFormatToFourCC(PixelFormat f)
+inline std::string PixelFormatToFourCC(PixelFormat f)
 {
 	char buf[5] = { (char)(((uint32_t)f >> 0) & 0xff),
 			(char)(((uint32_t)f >> 8) & 0xff),
diff --git a/kms++/inc/kms++/plane.h b/kms++/inc/kms++/plane.h
index d3cfde5..f6d0ca6 100644
--- a/kms++/inc/kms++/plane.h
+++ b/kms++/inc/kms++/plane.h
@@ -1,6 +1,8 @@
 #pragma once
 
 #include "drmpropobject.h"
+#include "pixelformats.h"
+#include <vector>
 
 namespace kms
 {
diff --git a/kms++/inc/kms++/property.h b/kms++/inc/kms++/property.h
index 7c7b834..e080962 100644
--- a/kms++/inc/kms++/property.h
+++ b/kms++/inc/kms++/property.h
@@ -2,6 +2,7 @@
 
 #include "drmobject.h"
 #include <map>
+#include <string>
 #include <vector>
 
 namespace kms
diff --git a/kms++/meson.build b/kms++/meson.build
index fee1b54..cd7a494 100644
--- a/kms++/meson.build
+++ b/kms++/meson.build
@@ -63,6 +63,9 @@ if libdrmomap_dep.found()
         'src/omap/omapcard.cpp',
         'src/omap/omapframebuffer.cpp',
     ])
+    omapdrm_enabled = true
+else
+    omapdrm_enabled = false
 endif
 
 libkmsxx_deps = [ libdrm_dep, libfmt_dep, libdrmomap_dep ]
@@ -71,7 +74,8 @@ libkmsxx = library('kms++',
                    libkmsxx_sources,
                    install : true,
                    include_directories : private_includes,
-                   dependencies : libkmsxx_deps)
+                   dependencies : libkmsxx_deps,
+                   version : meson.project_version())
 
 
 libkmsxx_dep = declare_dependency(include_directories : public_includes,
diff --git a/kms++/src/connector.cpp b/kms++/src/connector.cpp
index 92bab80..76c153f 100644
--- a/kms++/src/connector.cpp
+++ b/kms++/src/connector.cpp
@@ -15,6 +15,15 @@ namespace kms
 #ifndef DRM_MODE_CONNECTOR_DPI
 #define DRM_MODE_CONNECTOR_DPI 17
 #endif
+#ifndef DRM_MODE_CONNECTOR_WRITEBACK
+#define DRM_MODE_CONNECTOR_WRITEBACK 18
+#endif
+#ifndef DRM_MODE_CONNECTOR_SPI
+#define DRM_MODE_CONNECTOR_SPI 19
+#endif
+#ifndef DRM_MODE_CONNECTOR_USB
+#define DRM_MODE_CONNECTOR_USB 20
+#endif
 
 static const map<int, string> connector_names = {
 	{ DRM_MODE_CONNECTOR_Unknown, "Unknown" },
@@ -35,6 +44,9 @@ static const map<int, string> connector_names = {
 	{ DRM_MODE_CONNECTOR_VIRTUAL, "Virtual" },
 	{ DRM_MODE_CONNECTOR_DSI, "DSI" },
 	{ DRM_MODE_CONNECTOR_DPI, "DPI" },
+	{ DRM_MODE_CONNECTOR_WRITEBACK, "Writeback" },
+	{ DRM_MODE_CONNECTOR_SPI, "SPI" },
+	{ DRM_MODE_CONNECTOR_USB, "USB" },
 };
 
 static const map<int, string> connection_str = {
diff --git a/kms++/src/framebuffer.cpp b/kms++/src/framebuffer.cpp
index f1cba3b..3a76b73 100644
--- a/kms++/src/framebuffer.cpp
+++ b/kms++/src/framebuffer.cpp
@@ -20,13 +20,14 @@ Framebuffer::Framebuffer(Card& card, uint32_t width, uint32_t height)
 Framebuffer::Framebuffer(Card& card, uint32_t id)
 	: DrmObject(card, id, DRM_MODE_OBJECT_FB)
 {
-	auto fb = drmModeGetFB(card.fd(), id);
+	auto fb = drmModeGetFB2(card.fd(), id);
 
 	if (fb) {
 		m_width = fb->width;
 		m_height = fb->height;
+		m_format = (PixelFormat)fb->pixel_format;
 
-		drmModeFreeFB(fb);
+		drmModeFreeFB2(fb);
 	} else {
 		m_width = m_height = 0;
 	}
@@ -34,6 +35,17 @@ Framebuffer::Framebuffer(Card& card, uint32_t id)
 	card.m_framebuffers.push_back(this);
 }
 
+void Framebuffer::flush(uint32_t x, uint32_t y, uint32_t width, uint32_t height)
+{
+	drmModeClip clip{};
+	clip.x1 = x;
+	clip.y1 = y;
+	clip.x2 = x + width;
+	clip.y2 = y + height;
+
+	drmModeDirtyFB(card().fd(), id(), &clip, 1);
+}
+
 void Framebuffer::flush()
 {
 	drmModeClip clip{};
diff --git a/kms++/src/pixelformats.cpp b/kms++/src/pixelformats.cpp
index d739efd..5f13ef4 100644
--- a/kms++/src/pixelformats.cpp
+++ b/kms++/src/pixelformats.cpp
@@ -28,113 +28,73 @@ static const map<PixelFormat, PixelFormatInfo> format_info_array = {
 				     1,
 				     { { 16, 2, 1 } },
 			     } },
+	{ PixelFormat::Y210, {
+				     PixelColorType::YUV,
+				     1,
+				     { { 32, 2, 1 } },
+			     } },
+	{ PixelFormat::Y212, {
+				     PixelColorType::YUV,
+				     1,
+				     { { 32, 2, 1 } },
+			     } },
+	{ PixelFormat::Y216, {
+				     PixelColorType::YUV,
+				     1,
+				     { { 32, 2, 1 } },
+			     } },
+
 	/* YUV semi-planar */
 	{ PixelFormat::NV12, {
 				     PixelColorType::YUV,
 				     2,
-				     { {
-					       8,
-					       1,
-					       1,
-				       },
-				       { 8, 2, 2 } },
+				     { { 8, 1, 1 }, { 8, 2, 2 } },
 			     } },
 	{ PixelFormat::NV21, {
 				     PixelColorType::YUV,
 				     2,
-				     { {
-					       8,
-					       1,
-					       1,
-				       },
-				       { 8, 2, 2 } },
+				     { { 8, 1, 1 }, { 8, 2, 2 } },
 			     } },
 	{ PixelFormat::NV16, {
 				     PixelColorType::YUV,
 				     2,
-				     { {
-					       8,
-					       1,
-					       1,
-				       },
-				       { 8, 2, 1 } },
+				     { { 8, 1, 1 }, { 8, 2, 1 } },
 			     } },
 	{ PixelFormat::NV61, {
 				     PixelColorType::YUV,
 				     2,
-				     { {
-					       8,
-					       1,
-					       1,
-				       },
-				       { 8, 2, 1 } },
+				     { { 8, 1, 1 }, { 8, 2, 1 } },
 			     } },
 	/* YUV planar */
 	{ PixelFormat::YUV420, {
 				       PixelColorType::YUV,
 				       3,
-				       { {
-						 8,
-						 1,
-						 1,
-					 },
-					 { 8, 2, 2 },
-					 { 8, 2, 2 } },
+				       { { 8, 1, 1 }, { 8, 2, 2 }, { 8, 2, 2 } },
 			       } },
 	{ PixelFormat::YVU420, {
 				       PixelColorType::YUV,
 				       3,
-				       { {
-						 8,
-						 1,
-						 1,
-					 },
-					 { 8, 2, 2 },
-					 { 8, 2, 2 } },
+				       { { 8, 1, 1 }, { 8, 2, 2 }, { 8, 2, 2 } },
 			       } },
 	{ PixelFormat::YUV422, {
 				       PixelColorType::YUV,
 				       3,
-				       { {
-						 8,
-						 1,
-						 1,
-					 },
-					 { 8, 2, 1 },
-					 { 8, 2, 1 } },
+				       { { 8, 1, 1 }, { 8, 2, 1 }, { 8, 2, 1 } },
 			       } },
 	{ PixelFormat::YVU422, {
 				       PixelColorType::YUV,
 				       3,
-				       { {
-						 8,
-						 1,
-						 1,
-					 },
-					 { 8, 2, 1 },
-					 { 8, 2, 1 } },
+				       { { 8, 1, 1 }, { 8, 2, 1 }, { 8, 2, 1 } },
 			       } },
 	{ PixelFormat::YUV444, {
 				       PixelColorType::YUV,
 				       3,
-				       { {
-						 8,
-						 1,
-						 1,
-					 },
-					 { 8, 1, 1 },
-					 { 8, 1, 1 } },
+				       { { 8, 1, 1 }, { 8, 1, 1 }, { 8, 1, 1 } },
 			       } },
 	{ PixelFormat::YVU444, {
 				       PixelColorType::YUV,
 				       3,
-				       { {
-						 8,
-						 1,
-						 1,
-					 },
-					 { 8, 1, 1 },
-					 { 8, 1, 1 } },
+				       { { 8, 1, 1 }, { 8, 1, 1 }, { 8, 1, 1 } },
 			       } },
 	/* RGB8 */
 	{ PixelFormat::RGB332, {
diff --git a/kms++/src/videomode.cpp b/kms++/src/videomode.cpp
index b039059..4be6de7 100644
--- a/kms++/src/videomode.cpp
+++ b/kms++/src/videomode.cpp
@@ -110,18 +110,125 @@ static char sync_to_char(SyncPolarity pol)
 	}
 }
 
+#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
+
+template<typename T>
+std::string join(const T& values, const std::string& delim)
+{
+	std::ostringstream ss;
+	for (const auto& v : values) {
+		if (&v != &values[0])
+			ss << delim;
+		ss << v;
+	}
+	return ss.str();
+}
+
+static const map<int, string> mode_type_map = {
+	// the deprecated ones don't care about a short name
+	{ DRM_MODE_TYPE_BUILTIN, "builtin" }, // deprecated
+	{ DRM_MODE_TYPE_CLOCK_C, "clock_c" }, // deprecated
+	{ DRM_MODE_TYPE_CRTC_C, "crtc_c" }, // deprecated
+	{ DRM_MODE_TYPE_PREFERRED, "P" },
+	{ DRM_MODE_TYPE_DEFAULT, "default" }, // deprecated
+	{ DRM_MODE_TYPE_USERDEF, "U" },
+	{ DRM_MODE_TYPE_DRIVER, "D" },
+};
+
+static const map<int, string> mode_flag_map = {
+	// the first 5 flags are displayed elsewhere
+	{ DRM_MODE_FLAG_PHSYNC, "" },
+	{ DRM_MODE_FLAG_NHSYNC, "" },
+	{ DRM_MODE_FLAG_PVSYNC, "" },
+	{ DRM_MODE_FLAG_NVSYNC, "" },
+	{ DRM_MODE_FLAG_INTERLACE, "" },
+	{ DRM_MODE_FLAG_DBLSCAN, "dblscan" },
+	{ DRM_MODE_FLAG_CSYNC, "csync" },
+	{ DRM_MODE_FLAG_PCSYNC, "pcsync" },
+	{ DRM_MODE_FLAG_NCSYNC, "ncsync" },
+	{ DRM_MODE_FLAG_HSKEW, "hskew" },
+	{ DRM_MODE_FLAG_BCAST, "bcast" }, // deprecated
+	{ DRM_MODE_FLAG_PIXMUX, "pixmux" }, // deprecated
+	{ DRM_MODE_FLAG_DBLCLK, "2x" },
+	{ DRM_MODE_FLAG_CLKDIV2, "clkdiv2" },
+};
+
+static const map<int, string> mode_3d_map = {
+	{ DRM_MODE_FLAG_3D_NONE, "" },
+	{ DRM_MODE_FLAG_3D_FRAME_PACKING, "3dfp" },
+	{ DRM_MODE_FLAG_3D_FIELD_ALTERNATIVE, "3dfa" },
+	{ DRM_MODE_FLAG_3D_LINE_ALTERNATIVE, "3dla" },
+	{ DRM_MODE_FLAG_3D_SIDE_BY_SIDE_FULL, "3dsbs" },
+	{ DRM_MODE_FLAG_3D_L_DEPTH, "3dldepth" },
+	{ DRM_MODE_FLAG_3D_L_DEPTH_GFX_GFX_DEPTH, "3dgfx" },
+	{ DRM_MODE_FLAG_3D_TOP_AND_BOTTOM, "3dtab" },
+	{ DRM_MODE_FLAG_3D_SIDE_BY_SIDE_HALF, "3dsbs" },
+};
+
+static const map<int, string> mode_aspect_map = {
+	{ DRM_MODE_FLAG_PIC_AR_NONE, "" },
+	{ DRM_MODE_FLAG_PIC_AR_4_3, "4:3" },
+	{ DRM_MODE_FLAG_PIC_AR_16_9, "16:9" },
+	{ DRM_MODE_FLAG_PIC_AR_64_27, "64:27" },
+	{ DRM_MODE_FLAG_PIC_AR_256_135, "256:135" },
+};
+
+static string mode_type_str(uint32_t val)
+{
+	vector<string> s;
+	for (const auto& [k, v] : mode_type_map) {
+		if (val & k) {
+			if (!v.empty())
+				s.push_back(v);
+			val &= ~k;
+		}
+	}
+	// any unknown bits
+	if (val != 0)
+		s.push_back(fmt::format("{:#x}", val));
+	return join(s, "|");
+}
+
+static string mode_flag_str(uint32_t val)
+{
+	vector<string> s;
+	for (const auto& [k, v] : mode_flag_map) {
+		if (val & k) {
+			if (!v.empty())
+				s.push_back(v);
+			val &= ~k;
+		}
+	}
+	auto it = mode_3d_map.find(val & DRM_MODE_FLAG_3D_MASK);
+	if (it != mode_3d_map.end()) {
+		if (!it->second.empty())
+			s.push_back(it->second);
+		val &= ~DRM_MODE_FLAG_3D_MASK;
+	}
+	it = mode_aspect_map.find(val & DRM_MODE_FLAG_PIC_AR_MASK);
+	if (it != mode_aspect_map.end()) {
+		if (!it->second.empty())
+			s.push_back(it->second);
+		val &= ~DRM_MODE_FLAG_PIC_AR_MASK;
+	}
+	// any unknown bits
+	if (val != 0)
+		s.push_back(fmt::format("{:#x}", val));
+	return join(s, "|");
+}
+
 string Videomode::to_string_long() const
 {
 	string h = fmt::format("{}/{}/{}/{}/{}", hdisplay, hfp(), hsw(), hbp(), sync_to_char(hsync()));
 	string v = fmt::format("{}/{}/{}/{}/{}", vdisplay, vfp(), vsw(), vbp(), sync_to_char(vsync()));
 
-	string str = fmt::format("{} {:.3f} {} {} {} ({:.2f}) {:#x} {:#x}",
+	string str = fmt::format("{} {:.3f} {} {} {} ({:.2f}) {} {}",
 				 to_string_short(),
 				 clock / 1000.0,
 				 h, v,
 				 vrefresh, calculated_vrefresh(),
-				 flags,
-				 type);
+				 mode_type_str(type),
+				 mode_flag_str(flags));
 
 	return str;
 }
@@ -131,13 +238,13 @@ string Videomode::to_string_long_padded() const
 	string h = fmt::format("{}/{}/{}/{}/{}", hdisplay, hfp(), hsw(), hbp(), sync_to_char(hsync()));
 	string v = fmt::format("{}/{}/{}/{}/{}", vdisplay, vfp(), vsw(), vbp(), sync_to_char(vsync()));
 
-	string str = fmt::format("{:<16} {:7.3f} {:<18} {:<18} {:2} ({:.2f}) {:#10x} {:#6x}",
+	string str = fmt::format("{:<16} {:7.3f} {:<18} {:<18} {:2} ({:.2f}) {:<5} {}",
 				 to_string_short(),
 				 clock / 1000.0,
 				 h, v,
 				 vrefresh, calculated_vrefresh(),
-				 flags,
-				 type);
+				 mode_type_str(type),
+				 mode_flag_str(flags));
 
 	return str;
 }
diff --git a/kms++util/inc/kms++util/endian.h b/kms++util/inc/kms++util/endian.h
new file mode 100644
index 0000000..e77b3bd
--- /dev/null
+++ b/kms++util/inc/kms++util/endian.h
@@ -0,0 +1,48 @@
+#pragma once
+
+#include <type_traits>
+#include <byteswap.h>
+#include <stdint.h>
+
+static_assert((__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) ||
+		      (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__),
+	      "Unable to detect endianness");
+
+enum class endian {
+	little = __ORDER_LITTLE_ENDIAN__,
+	big = __ORDER_BIG_ENDIAN__,
+	native = __BYTE_ORDER__
+};
+
+template<typename T>
+constexpr T byteswap(T value) noexcept
+{
+	static_assert(std::is_integral<T>(), "Type is not integral");
+	static_assert(sizeof(T) == 2 ||
+			      sizeof(T) == 4 ||
+			      sizeof(T) == 8,
+		      "Illegal value size");
+
+	switch (sizeof(T)) {
+	case 2:
+		return bswap_16(value);
+	case 4:
+		return bswap_32(value);
+	case 8:
+		return bswap_64(value);
+	}
+}
+
+template<endian E, typename T>
+static void write_endian(T* dst, T val)
+{
+	if constexpr (E != endian::native)
+		val = byteswap(val);
+
+	*dst = val;
+}
+
+[[maybe_unused]] static void write16le(uint16_t* dst, uint16_t val)
+{
+	write_endian<endian::little, uint16_t>(dst, val);
+}
diff --git a/kms++util/inc/kms++util/resourcemanager.h b/kms++util/inc/kms++util/resourcemanager.h
index 11c11b3..78a2b9c 100644
--- a/kms++util/inc/kms++util/resourcemanager.h
+++ b/kms++util/inc/kms++util/resourcemanager.h
@@ -1,3 +1,5 @@
+#pragma once
+
 #include <kms++/kms++.h>
 #include <set>
 #include <string>
diff --git a/kms++util/inc/kms++util/stopwatch.h b/kms++util/inc/kms++util/stopwatch.h
index 9b60fa1..ea44ba4 100644
--- a/kms++util/inc/kms++util/stopwatch.h
+++ b/kms++util/inc/kms++util/stopwatch.h
@@ -1,3 +1,5 @@
+#pragma once
+
 #include <chrono>
 
 class Stopwatch
diff --git a/kms++util/inc/kms++util/strhelpers.h b/kms++util/inc/kms++util/strhelpers.h
index c4032d7..c352fad 100644
--- a/kms++util/inc/kms++util/strhelpers.h
+++ b/kms++util/inc/kms++util/strhelpers.h
@@ -1,3 +1,5 @@
+#pragma once
+
 #include <sstream>
 #include <string>
 #include <vector>
diff --git a/kms++util/inc/kms++util/videodevice.h b/kms++util/inc/kms++util/videodevice.h
deleted file mode 100644
index 3bce4a9..0000000
--- a/kms++util/inc/kms++util/videodevice.h
+++ /dev/null
@@ -1,88 +0,0 @@
-#pragma once
-
-#include <string>
-#include <memory>
-#include <kms++/kms++.h>
-
-class VideoStreamer;
-
-class VideoDevice
-{
-public:
-	struct VideoFrameSize {
-		uint32_t min_w, max_w, step_w;
-		uint32_t min_h, max_h, step_h;
-	};
-
-	VideoDevice(const std::string& dev);
-	VideoDevice(int fd);
-	~VideoDevice();
-
-	VideoDevice(const VideoDevice& other) = delete;
-	VideoDevice& operator=(const VideoDevice& other) = delete;
-
-	VideoStreamer* get_capture_streamer();
-	VideoStreamer* get_output_streamer();
-
-	std::vector<std::tuple<uint32_t, uint32_t>> get_discrete_frame_sizes(kms::PixelFormat fmt);
-	VideoFrameSize get_frame_sizes(kms::PixelFormat fmt);
-
-	int fd() const { return m_fd; }
-	bool has_capture() const { return m_has_capture; }
-	bool has_output() const { return m_has_output; }
-	bool has_m2m() const { return m_has_m2m; }
-
-	static std::vector<std::string> get_capture_devices();
-	static std::vector<std::string> get_m2m_devices();
-
-private:
-	int m_fd;
-
-	bool m_has_capture;
-	bool m_has_mplane_capture;
-
-	bool m_has_output;
-	bool m_has_mplane_output;
-
-	bool m_has_m2m;
-	bool m_has_mplane_m2m;
-
-	std::vector<kms::DumbFramebuffer*> m_capture_fbs;
-	std::vector<kms::DumbFramebuffer*> m_output_fbs;
-
-	std::unique_ptr<VideoStreamer> m_capture_streamer;
-	std::unique_ptr<VideoStreamer> m_output_streamer;
-};
-
-class VideoStreamer
-{
-public:
-	enum class StreamerType {
-		CaptureSingle,
-		CaptureMulti,
-		OutputSingle,
-		OutputMulti,
-	};
-
-	VideoStreamer(int fd, StreamerType type);
-
-	std::vector<std::string> get_ports();
-	void set_port(uint32_t index);
-
-	std::vector<kms::PixelFormat> get_formats();
-	void set_format(kms::PixelFormat fmt, uint32_t width, uint32_t height);
-	void get_selection(uint32_t& left, uint32_t& top, uint32_t& width, uint32_t& height);
-	void set_selection(uint32_t& left, uint32_t& top, uint32_t& width, uint32_t& height);
-	void set_queue_size(uint32_t queue_size);
-	void queue(kms::DumbFramebuffer* fb);
-	kms::DumbFramebuffer* dequeue();
-	void stream_on();
-	void stream_off();
-
-	int fd() const { return m_fd; }
-
-private:
-	int m_fd;
-	StreamerType m_type;
-	std::vector<kms::DumbFramebuffer*> m_fbs;
-};
diff --git a/kms++util/meson.build b/kms++util/meson.build
index 4105db6..61512ca 100644
--- a/kms++util/meson.build
+++ b/kms++util/meson.build
@@ -1,3 +1,10 @@
+if not get_option('libutils')
+    libutils_enabled = false
+    subdir_done()
+endif
+
+libutils_enabled = true
+
 libkmsxxutil_sources = files([
     'src/colorbar.cpp',
     'src/color.cpp',
@@ -8,7 +15,6 @@ libkmsxxutil_sources = files([
     'src/resourcemanager.cpp',
     'src/strhelpers.cpp',
     'src/testpat.cpp',
-    'src/videodevice.cpp',
 ])
 
 public_headers = [
@@ -20,7 +26,6 @@ public_headers = [
     'inc/kms++util/opts.h',
     'inc/kms++util/extcpuframebuffer.h',
     'inc/kms++util/resourcemanager.h',
-    'inc/kms++util/videodevice.h',
 ]
 
 private_includes = include_directories('src', 'inc')
@@ -41,7 +46,8 @@ libkmsxxutil = library('kms++util',
                        install : true,
                        include_directories : private_includes,
                        dependencies : libkmsxxutil_deps,
-                       cpp_args : libkmsxxutil_args)
+                       cpp_args : libkmsxxutil_args,
+                       version : meson.project_version())
 
 libkmsxxutil_dep = declare_dependency(include_directories : public_includes,
                                       link_with : libkmsxxutil)
diff --git a/kms++util/src/color.cpp b/kms++util/src/color.cpp
index 74ff8c9..c761e40 100644
--- a/kms++util/src/color.cpp
+++ b/kms++util/src/color.cpp
@@ -114,7 +114,8 @@ YUV RGB::yuv(YUVType type) const
 	{                                                                     \
 		((int)((a)*CF_ONE)), ((int)((b)*CF_ONE)), ((int)((c)*CF_ONE)) \
 	}
-#define CLAMP(a) ((a) > (CF_ONE - 1) ? (CF_ONE - 1) : (a) < 0 ? 0 : (a))
+#define CLAMP(a) ((a) > (CF_ONE - 1) ? (CF_ONE - 1) : (a) < 0 ? 0 \
+							      : (a))
 
 const int YUVcoef[static_cast<unsigned>(YUVType::MAX)][3][3] = {
 	[static_cast<unsigned>(YUVType::BT601_Lim)] = {
diff --git a/kms++util/src/drawing.cpp b/kms++util/src/drawing.cpp
index 79e0d90..862638b 100644
--- a/kms++util/src/drawing.cpp
+++ b/kms++util/src/drawing.cpp
@@ -3,6 +3,7 @@
 
 #include <kms++/kms++.h>
 #include <kms++util/kms++util.h>
+#include <kms++util/endian.h>
 
 using namespace std;
 
@@ -179,6 +180,62 @@ static void draw_yuv422_packed_macropixel(IFramebuffer& buf, unsigned x, unsigne
 	}
 }
 
+static void draw_y2xx_packed_macropixel(IFramebuffer& buf, unsigned x, unsigned y,
+					YUV yuv1, YUV yuv2)
+{
+	const uint32_t macro_size = 4;
+	uint16_t* p = (uint16_t*)(buf.map(0) + buf.stride(0) * y + x * macro_size);
+
+	switch (buf.format()) {
+	case PixelFormat::Y210: {
+		// XXX naive expansion to 10 bits, similar to 10-bit funcs in class RGB
+		uint16_t y0 = yuv1.y << 2;
+		uint16_t y1 = yuv2.y << 2;
+		uint16_t cb = ((yuv1.u << 2) + (yuv2.u << 2)) / 2;
+		uint16_t cr = ((yuv1.v << 2) + (yuv2.v << 2)) / 2;
+
+		// The 10 bits occupy the msb, so we shift left by 16-10 = 6
+		write16le(&p[0], y0 << 6);
+		write16le(&p[1], cb << 6);
+		write16le(&p[2], y1 << 6);
+		write16le(&p[3], cr << 6);
+		break;
+	}
+
+	case PixelFormat::Y212: {
+		// XXX naive expansion to 12 bits
+		uint16_t y0 = yuv1.y << 4;
+		uint16_t y1 = yuv2.y << 4;
+		uint16_t cb = ((yuv1.u << 4) + (yuv2.u << 4)) / 2;
+		uint16_t cr = ((yuv1.v << 4) + (yuv2.v << 4)) / 2;
+
+		// The 10 bits occupy the msb, so we shift left by 16-12 = 4
+		write16le(&p[0], y0 << 4);
+		write16le(&p[1], cb << 4);
+		write16le(&p[2], y1 << 4);
+		write16le(&p[3], cr << 4);
+		break;
+	}
+
+	case PixelFormat::Y216: {
+		// XXX naive expansion to 16 bits
+		uint16_t y0 = yuv1.y << 8;
+		uint16_t y1 = yuv2.y << 8;
+		uint16_t cb = ((yuv1.u << 8) + (yuv2.u << 8)) / 2;
+		uint16_t cr = ((yuv1.v << 8) + (yuv2.v << 8)) / 2;
+
+		write16le(&p[0], y0);
+		write16le(&p[1], cb);
+		write16le(&p[2], y1);
+		write16le(&p[3], cr);
+		break;
+	}
+
+	default:
+		throw std::invalid_argument("invalid pixelformat");
+	}
+}
+
 static void draw_yuv422_semiplanar_macropixel(IFramebuffer& buf, unsigned x, unsigned y,
 					      YUV yuv1, YUV yuv2)
 {
@@ -257,6 +314,12 @@ void draw_yuv422_macropixel(IFramebuffer& buf, unsigned x, unsigned y, YUV yuv1,
 		draw_yuv422_packed_macropixel(buf, x, y, yuv1, yuv2);
 		break;
 
+	case PixelFormat::Y210:
+	case PixelFormat::Y212:
+	case PixelFormat::Y216:
+		draw_y2xx_packed_macropixel(buf, x, y, yuv1, yuv2);
+		break;
+
 	case PixelFormat::NV16:
 	case PixelFormat::NV61:
 		draw_yuv422_semiplanar_macropixel(buf, x, y, yuv1, yuv2);
diff --git a/kms++util/src/font_8x8.h b/kms++util/src/font_8x8.h
index ed9bf3f..ea01ecb 100644
--- a/kms++util/src/font_8x8.h
+++ b/kms++util/src/font_8x8.h
@@ -4,6 +4,8 @@
 /*                                            */
 /**********************************************/
 
+#include <stdint.h>
+
 const uint8_t fontdata_8x8[] = {
 
 	/* 0 0x00 '^@' */
@@ -2565,5 +2567,4 @@ const uint8_t fontdata_8x8[] = {
 	0x00, /* 00000000 */
 	0x00, /* 00000000 */
 	0x00, /* 00000000 */
-
 };
diff --git a/kms++util/src/testpat.cpp b/kms++util/src/testpat.cpp
index 78c9d19..1102588 100644
--- a/kms++util/src/testpat.cpp
+++ b/kms++util/src/testpat.cpp
@@ -173,7 +173,7 @@ static void draw_test_pattern_impl(IFramebuffer& fb, YUVType yuvt)
 
 	// Create the mmaps before starting the threads
 	for (unsigned i = 0; i < fb.num_planes(); ++i)
-		fb.map(0);
+		fb.map(i);
 
 	unsigned num_threads = thread::hardware_concurrency();
 	vector<thread> workers;
diff --git a/kms++util/src/videodevice.cpp b/kms++util/src/videodevice.cpp
deleted file mode 100644
index 9530d60..0000000
--- a/kms++util/src/videodevice.cpp
+++ /dev/null
@@ -1,552 +0,0 @@
-#include <string>
-
-#include <sys/types.h>
-#include <sys/stat.h>
-#include <fcntl.h>
-#include <linux/videodev2.h>
-#include <sys/ioctl.h>
-#include <unistd.h>
-#include <system_error>
-
-#include <kms++/kms++.h>
-#include <kms++util/kms++util.h>
-#include <kms++util/videodevice.h>
-
-using namespace std;
-using namespace kms;
-
-/*
- * V4L2 and DRM differ in their interpretation of YUV420::NV12
- *
- * V4L2 NV12 is a Y and UV co-located planes in a single plane buffer.
- * DRM NV12 is a Y and UV planes presented as dual plane buffer,
- * which is known as NM12 in V4L2.
- *
- * Since here we have hybrid DRM/V4L2 user space helper functions
- * we need to translate DRM::NV12 to V4L2:NM12 pixel format back
- * and forth to keep the data view consistent.
- */
-
-/* V4L2 helper funcs */
-static vector<PixelFormat> v4l2_get_formats(int fd, uint32_t buf_type)
-{
-	vector<PixelFormat> v;
-
-	v4l2_fmtdesc desc{};
-	desc.type = buf_type;
-
-	while (ioctl(fd, VIDIOC_ENUM_FMT, &desc) == 0) {
-		if (desc.pixelformat == V4L2_PIX_FMT_NV12M)
-			v.push_back(PixelFormat::NV12);
-		else if (desc.pixelformat != V4L2_PIX_FMT_NV12)
-			v.push_back((PixelFormat)desc.pixelformat);
-
-		desc.index++;
-	}
-
-	return v;
-}
-
-static void v4l2_set_format(int fd, PixelFormat fmt, uint32_t width, uint32_t height, uint32_t buf_type)
-{
-	int r;
-
-	v4l2_format v4lfmt{};
-
-	v4lfmt.type = buf_type;
-	r = ioctl(fd, VIDIOC_G_FMT, &v4lfmt);
-	ASSERT(r == 0);
-
-	const PixelFormatInfo& pfi = get_pixel_format_info(fmt);
-
-	bool mplane = buf_type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE || buf_type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
-
-	if (mplane) {
-		v4l2_pix_format_mplane& mp = v4lfmt.fmt.pix_mp;
-		uint32_t used_fmt;
-
-		if (fmt == PixelFormat::NV12)
-			used_fmt = V4L2_PIX_FMT_NV12M;
-		else
-			used_fmt = (uint32_t)fmt;
-
-		mp.pixelformat = used_fmt;
-		mp.width = width;
-		mp.height = height;
-
-		mp.num_planes = pfi.num_planes;
-
-		for (unsigned i = 0; i < pfi.num_planes; ++i) {
-			const PixelFormatPlaneInfo& pfpi = pfi.planes[i];
-			v4l2_plane_pix_format& p = mp.plane_fmt[i];
-
-			p.bytesperline = width * pfpi.bitspp / 8;
-			p.sizeimage = p.bytesperline * height / pfpi.ysub;
-		}
-
-		r = ioctl(fd, VIDIOC_S_FMT, &v4lfmt);
-		ASSERT(r == 0);
-
-		ASSERT(mp.pixelformat == used_fmt);
-		ASSERT(mp.width == width);
-		ASSERT(mp.height == height);
-
-		ASSERT(mp.num_planes == pfi.num_planes);
-
-		for (unsigned i = 0; i < pfi.num_planes; ++i) {
-			const PixelFormatPlaneInfo& pfpi = pfi.planes[i];
-			v4l2_plane_pix_format& p = mp.plane_fmt[i];
-
-			ASSERT(p.bytesperline == width * pfpi.bitspp / 8);
-			ASSERT(p.sizeimage == p.bytesperline * height / pfpi.ysub);
-		}
-	} else {
-		ASSERT(pfi.num_planes == 1);
-
-		v4lfmt.fmt.pix.pixelformat = (uint32_t)fmt;
-		v4lfmt.fmt.pix.width = width;
-		v4lfmt.fmt.pix.height = height;
-		v4lfmt.fmt.pix.bytesperline = width * pfi.planes[0].bitspp / 8;
-
-		r = ioctl(fd, VIDIOC_S_FMT, &v4lfmt);
-		ASSERT(r == 0);
-
-		ASSERT(v4lfmt.fmt.pix.pixelformat == (uint32_t)fmt);
-		ASSERT(v4lfmt.fmt.pix.width == width);
-		ASSERT(v4lfmt.fmt.pix.height == height);
-		ASSERT(v4lfmt.fmt.pix.bytesperline == width * pfi.planes[0].bitspp / 8);
-	}
-}
-
-static void v4l2_get_selection(int fd, uint32_t& left, uint32_t& top, uint32_t& width, uint32_t& height, uint32_t buf_type)
-{
-	int r;
-	struct v4l2_selection selection;
-
-	if (buf_type == V4L2_BUF_TYPE_VIDEO_OUTPUT ||
-	    buf_type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
-		selection.type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
-		selection.target = V4L2_SEL_TGT_CROP;
-	} else if (buf_type == V4L2_BUF_TYPE_VIDEO_CAPTURE ||
-		   buf_type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
-		selection.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
-		selection.target = V4L2_SEL_TGT_COMPOSE;
-	} else {
-		FAIL("buf_type (%d) is not valid\n", buf_type);
-	}
-
-	r = ioctl(fd, VIDIOC_G_SELECTION, &selection);
-	ASSERT(r == 0);
-
-	left = selection.r.left;
-	top = selection.r.top;
-	width = selection.r.width;
-	height = selection.r.height;
-}
-
-static void v4l2_set_selection(int fd, uint32_t& left, uint32_t& top, uint32_t& width, uint32_t& height, uint32_t buf_type)
-{
-	int r;
-	struct v4l2_selection selection;
-
-	if (buf_type == V4L2_BUF_TYPE_VIDEO_OUTPUT ||
-	    buf_type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
-		selection.type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
-		selection.target = V4L2_SEL_TGT_CROP;
-	} else if (buf_type == V4L2_BUF_TYPE_VIDEO_CAPTURE ||
-		   buf_type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
-		selection.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
-		selection.target = V4L2_SEL_TGT_COMPOSE;
-	} else {
-		FAIL("buf_type (%d) is not valid\n", buf_type);
-	}
-
-	selection.r.left = left;
-	selection.r.top = top;
-	selection.r.width = width;
-	selection.r.height = height;
-
-	r = ioctl(fd, VIDIOC_S_SELECTION, &selection);
-	ASSERT(r == 0);
-
-	left = selection.r.left;
-	top = selection.r.top;
-	width = selection.r.width;
-	height = selection.r.height;
-}
-
-static void v4l2_request_bufs(int fd, uint32_t queue_size, uint32_t buf_type)
-{
-	v4l2_requestbuffers v4lreqbuf{};
-	v4lreqbuf.type = buf_type;
-	v4lreqbuf.memory = V4L2_MEMORY_DMABUF;
-	v4lreqbuf.count = queue_size;
-	int r = ioctl(fd, VIDIOC_REQBUFS, &v4lreqbuf);
-	ASSERT(r == 0);
-	ASSERT(v4lreqbuf.count == queue_size);
-}
-
-static void v4l2_queue_dmabuf(int fd, uint32_t index, DumbFramebuffer* fb, uint32_t buf_type)
-{
-	v4l2_buffer buf{};
-	buf.type = buf_type;
-	buf.memory = V4L2_MEMORY_DMABUF;
-	buf.index = index;
-
-	const PixelFormatInfo& pfi = get_pixel_format_info(fb->format());
-
-	bool mplane = buf_type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE || buf_type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
-
-	if (mplane) {
-		buf.length = pfi.num_planes;
-
-		v4l2_plane planes[4]{};
-		buf.m.planes = planes;
-
-		for (unsigned i = 0; i < pfi.num_planes; ++i) {
-			planes[i].m.fd = fb->prime_fd(i);
-			planes[i].bytesused = fb->size(i);
-			planes[i].length = fb->size(i);
-		}
-
-		int r = ioctl(fd, VIDIOC_QBUF, &buf);
-		ASSERT(r == 0);
-	} else {
-		buf.m.fd = fb->prime_fd(0);
-
-		int r = ioctl(fd, VIDIOC_QBUF, &buf);
-		ASSERT(r == 0);
-	}
-}
-
-static uint32_t v4l2_dequeue(int fd, uint32_t buf_type)
-{
-	v4l2_buffer buf{};
-	buf.type = buf_type;
-	buf.memory = V4L2_MEMORY_DMABUF;
-
-	// V4L2 crashes if planes are not set
-	v4l2_plane planes[4]{};
-	buf.m.planes = planes;
-	buf.length = 4;
-
-	int r = ioctl(fd, VIDIOC_DQBUF, &buf);
-	if (r)
-		throw system_error(errno, generic_category());
-
-	return buf.index;
-}
-
-VideoDevice::VideoDevice(const string& dev)
-	: VideoDevice(::open(dev.c_str(), O_RDWR | O_NONBLOCK))
-{
-}
-
-VideoDevice::VideoDevice(int fd)
-	: m_fd(fd), m_has_capture(false), m_has_output(false), m_has_m2m(false)
-{
-	if (fd < 0)
-		throw runtime_error("bad fd");
-
-	struct v4l2_capability cap = {};
-	int r = ioctl(fd, VIDIOC_QUERYCAP, &cap);
-	ASSERT(r == 0);
-
-	if (cap.capabilities & V4L2_CAP_VIDEO_CAPTURE_MPLANE) {
-		m_has_capture = true;
-		m_has_mplane_capture = true;
-	} else if (cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) {
-		m_has_capture = true;
-		m_has_mplane_capture = false;
-	}
-
-	if (cap.capabilities & V4L2_CAP_VIDEO_OUTPUT_MPLANE) {
-		m_has_output = true;
-		m_has_mplane_output = true;
-	} else if (cap.capabilities & V4L2_CAP_VIDEO_OUTPUT) {
-		m_has_output = true;
-		m_has_mplane_output = false;
-	}
-
-	if (cap.capabilities & V4L2_CAP_VIDEO_M2M_MPLANE) {
-		m_has_m2m = true;
-		m_has_capture = true;
-		m_has_output = true;
-		m_has_mplane_m2m = true;
-		m_has_mplane_capture = true;
-		m_has_mplane_output = true;
-	} else if (cap.capabilities & V4L2_CAP_VIDEO_M2M) {
-		m_has_m2m = true;
-		m_has_capture = true;
-		m_has_output = true;
-		m_has_mplane_m2m = false;
-		m_has_mplane_capture = false;
-		m_has_mplane_output = false;
-	}
-}
-
-VideoDevice::~VideoDevice()
-{
-	::close(m_fd);
-}
-
-VideoStreamer* VideoDevice::get_capture_streamer()
-{
-	ASSERT(m_has_capture);
-
-	if (!m_capture_streamer) {
-		auto type = m_has_mplane_capture ? VideoStreamer::StreamerType::CaptureMulti : VideoStreamer::StreamerType::CaptureSingle;
-		m_capture_streamer = std::unique_ptr<VideoStreamer>(new VideoStreamer(m_fd, type));
-	}
-
-	return m_capture_streamer.get();
-}
-
-VideoStreamer* VideoDevice::get_output_streamer()
-{
-	ASSERT(m_has_output);
-
-	if (!m_output_streamer) {
-		auto type = m_has_mplane_output ? VideoStreamer::StreamerType::OutputMulti : VideoStreamer::StreamerType::OutputSingle;
-		m_output_streamer = std::unique_ptr<VideoStreamer>(new VideoStreamer(m_fd, type));
-	}
-
-	return m_output_streamer.get();
-}
-
-vector<tuple<uint32_t, uint32_t>> VideoDevice::get_discrete_frame_sizes(PixelFormat fmt)
-{
-	vector<tuple<uint32_t, uint32_t>> v;
-
-	v4l2_frmsizeenum v4lfrms{};
-	v4lfrms.pixel_format = (uint32_t)fmt;
-
-	int r = ioctl(m_fd, VIDIOC_ENUM_FRAMESIZES, &v4lfrms);
-	ASSERT(r);
-
-	FAIL_IF(v4lfrms.type != V4L2_FRMSIZE_TYPE_DISCRETE, "No discrete frame sizes");
-
-	while (ioctl(m_fd, VIDIOC_ENUM_FRAMESIZES, &v4lfrms) == 0) {
-		v.emplace_back(v4lfrms.discrete.width, v4lfrms.discrete.height);
-		v4lfrms.index++;
-	};
-
-	return v;
-}
-
-VideoDevice::VideoFrameSize VideoDevice::get_frame_sizes(PixelFormat fmt)
-{
-	v4l2_frmsizeenum v4lfrms{};
-	v4lfrms.pixel_format = (uint32_t)fmt;
-
-	int r = ioctl(m_fd, VIDIOC_ENUM_FRAMESIZES, &v4lfrms);
-	ASSERT(r);
-
-	FAIL_IF(v4lfrms.type == V4L2_FRMSIZE_TYPE_DISCRETE, "No continuous frame sizes");
-
-	VideoFrameSize s;
-
-	s.min_w = v4lfrms.stepwise.min_width;
-	s.max_w = v4lfrms.stepwise.max_width;
-	s.step_w = v4lfrms.stepwise.step_width;
-
-	s.min_h = v4lfrms.stepwise.min_height;
-	s.max_h = v4lfrms.stepwise.max_height;
-	s.step_h = v4lfrms.stepwise.step_height;
-
-	return s;
-}
-
-vector<string> VideoDevice::get_capture_devices()
-{
-	vector<string> v;
-
-	for (int i = 0; i < 20; ++i) {
-		string name = "/dev/video" + to_string(i);
-
-		struct stat buffer;
-		if (stat(name.c_str(), &buffer) != 0)
-			continue;
-
-		try {
-			VideoDevice vid(name);
-
-			if (vid.has_capture() && !vid.has_m2m())
-				v.push_back(name);
-		} catch (...) {
-		}
-	}
-
-	return v;
-}
-
-vector<string> VideoDevice::get_m2m_devices()
-{
-	vector<string> v;
-
-	for (int i = 0; i < 20; ++i) {
-		string name = "/dev/video" + to_string(i);
-
-		struct stat buffer;
-		if (stat(name.c_str(), &buffer) != 0)
-			continue;
-
-		try {
-			VideoDevice vid(name);
-
-			if (vid.has_m2m())
-				v.push_back(name);
-		} catch (...) {
-		}
-	}
-
-	return v;
-}
-
-VideoStreamer::VideoStreamer(int fd, StreamerType type)
-	: m_fd(fd), m_type(type)
-{
-}
-
-std::vector<string> VideoStreamer::get_ports()
-{
-	vector<string> v;
-
-	switch (m_type) {
-	case StreamerType::CaptureSingle:
-	case StreamerType::CaptureMulti: {
-		struct v4l2_input input {
-		};
-
-		while (ioctl(m_fd, VIDIOC_ENUMINPUT, &input) == 0) {
-			v.push_back(string((char*)&input.name));
-			input.index++;
-		}
-
-		break;
-	}
-
-	case StreamerType::OutputSingle:
-	case StreamerType::OutputMulti: {
-		struct v4l2_output output {
-		};
-
-		while (ioctl(m_fd, VIDIOC_ENUMOUTPUT, &output) == 0) {
-			v.push_back(string((char*)&output.name));
-			output.index++;
-		}
-
-		break;
-	}
-
-	default:
-		FAIL("Bad StreamerType");
-	}
-
-	return v;
-}
-
-void VideoStreamer::set_port(uint32_t index)
-{
-	unsigned long req;
-
-	switch (m_type) {
-	case StreamerType::CaptureSingle:
-	case StreamerType::CaptureMulti:
-		req = VIDIOC_S_INPUT;
-		break;
-
-	case StreamerType::OutputSingle:
-	case StreamerType::OutputMulti:
-		req = VIDIOC_S_OUTPUT;
-		break;
-
-	default:
-		FAIL("Bad StreamerType");
-	}
-
-	int r = ioctl(m_fd, req, &index);
-	ASSERT(r == 0);
-}
-
-static v4l2_buf_type get_buf_type(VideoStreamer::StreamerType type)
-{
-	switch (type) {
-	case VideoStreamer::StreamerType::CaptureSingle:
-		return V4L2_BUF_TYPE_VIDEO_CAPTURE;
-	case VideoStreamer::StreamerType::CaptureMulti:
-		return V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
-	case VideoStreamer::StreamerType::OutputSingle:
-		return V4L2_BUF_TYPE_VIDEO_OUTPUT;
-	case VideoStreamer::StreamerType::OutputMulti:
-		return V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
-	default:
-		FAIL("Bad StreamerType");
-	}
-}
-
-std::vector<PixelFormat> VideoStreamer::get_formats()
-{
-	return v4l2_get_formats(m_fd, get_buf_type(m_type));
-}
-
-void VideoStreamer::set_format(PixelFormat fmt, uint32_t width, uint32_t height)
-{
-	v4l2_set_format(m_fd, fmt, width, height, get_buf_type(m_type));
-}
-
-void VideoStreamer::get_selection(uint32_t& left, uint32_t& top, uint32_t& width, uint32_t& height)
-{
-	v4l2_get_selection(m_fd, left, top, width, height, get_buf_type(m_type));
-}
-
-void VideoStreamer::set_selection(uint32_t& left, uint32_t& top, uint32_t& width, uint32_t& height)
-{
-	v4l2_set_selection(m_fd, left, top, width, height, get_buf_type(m_type));
-}
-
-void VideoStreamer::set_queue_size(uint32_t queue_size)
-{
-	v4l2_request_bufs(m_fd, queue_size, get_buf_type(m_type));
-	m_fbs.resize(queue_size);
-}
-
-void VideoStreamer::queue(DumbFramebuffer* fb)
-{
-	uint32_t idx;
-
-	for (idx = 0; idx < m_fbs.size(); ++idx) {
-		if (m_fbs[idx] == nullptr)
-			break;
-	}
-
-	FAIL_IF(idx == m_fbs.size(), "queue full");
-
-	m_fbs[idx] = fb;
-
-	v4l2_queue_dmabuf(m_fd, idx, fb, get_buf_type(m_type));
-}
-
-DumbFramebuffer* VideoStreamer::dequeue()
-{
-	uint32_t idx = v4l2_dequeue(m_fd, get_buf_type(m_type));
-
-	auto fb = m_fbs[idx];
-	m_fbs[idx] = nullptr;
-
-	return fb;
-}
-
-void VideoStreamer::stream_on()
-{
-	uint32_t buf_type = get_buf_type(m_type);
-	int r = ioctl(m_fd, VIDIOC_STREAMON, &buf_type);
-	FAIL_IF(r, "Failed to enable stream: %d", r);
-}
-
-void VideoStreamer::stream_off()
-{
-	uint32_t buf_type = get_buf_type(m_type);
-	int r = ioctl(m_fd, VIDIOC_STREAMOFF, &buf_type);
-	FAIL_IF(r, "Failed to disable stream: %d", r);
-}
diff --git a/kmscube/cube-egl.cpp b/kmscube/cube-egl.cpp
index 5f23c4e..372c978 100644
--- a/kmscube/cube-egl.cpp
+++ b/kmscube/cube-egl.cpp
@@ -22,7 +22,10 @@ static void print_egl_config(EGLDisplay dpy, EGLConfig cfg)
 	       getconf(EGL_NATIVE_VISUAL_TYPE));
 }
 
-EglState::EglState(void* native_display)
+EglState::EglState(void* native_display) : EglState(native_display, 0) {}
+
+EglState::EglState(void* native_display, EGLint native_visual_id)
+	: m_native_visual_id(native_visual_id)
 {
 	EGLBoolean b;
 	EGLint major, minor, n;
@@ -60,13 +63,14 @@ EglState::EglState(void* native_display)
 	b = eglBindAPI(EGL_OPENGL_ES_API);
 	FAIL_IF(!b, "failed to bind api EGL_OPENGL_ES_API");
 
-	if (s_verbose) {
-		EGLint numConfigs;
-		b = eglGetConfigs(m_display, nullptr, 0, &numConfigs);
-		FAIL_IF(!b, "failed to get number of configs");
+	EGLint numConfigs;
+	b = eglGetConfigs(m_display, nullptr, 0, &numConfigs);
+	FAIL_IF(!b, "failed to get number of configs");
 
+	if (s_verbose) {
 		EGLConfig configs[numConfigs];
 		b = eglGetConfigs(m_display, configs, numConfigs, &numConfigs);
+		FAIL_IF(!b, "failed to get configs");
 
 		printf("Available configs:\n");
 
@@ -74,8 +78,25 @@ EglState::EglState(void* native_display)
 			print_egl_config(m_display, configs[i]);
 	}
 
-	b = eglChooseConfig(m_display, config_attribs, &m_config, 1, &n);
-	FAIL_IF(!b || n != 1, "failed to choose config");
+	std::vector<EGLConfig> configs(numConfigs);
+	b = eglChooseConfig(m_display, config_attribs, configs.data(), numConfigs, &n);
+	FAIL_IF(!b || n < 1, "failed to choose config");
+
+	// elgChooseConfig does implement matching by EGL_NATIVE_VISUAL_ID, do a manual
+	// loop. Picks the first returned if native_visual_id is not set.
+	for (const auto& config : configs) {
+		EGLint id;
+		b = eglGetConfigAttrib(m_display, config, EGL_NATIVE_VISUAL_ID, &id);
+		if (!b) {
+			printf("failed to get native visual id\n");
+			continue;
+		}
+
+		if (id == native_visual_id || !native_visual_id) {
+			m_config = config;
+			break;
+		}
+	}
 
 	if (s_verbose) {
 		printf("Chosen config:\n");
diff --git a/kmscube/cube-egl.h b/kmscube/cube-egl.h
index f492d07..73e3ab1 100644
--- a/kmscube/cube-egl.h
+++ b/kmscube/cube-egl.h
@@ -6,16 +6,19 @@ class EglState
 {
 public:
 	EglState(void* native_display);
+	EglState(void* native_display, EGLint native_visual_id);
 	~EglState();
 
 	EGLDisplay display() const { return m_display; }
 	EGLConfig config() const { return m_config; }
 	EGLContext context() const { return m_context; }
+	EGLint native_visual_id() const { return m_native_visual_id; }
 
 private:
 	EGLDisplay m_display;
 	EGLConfig m_config;
 	EGLContext m_context;
+	EGLint m_native_visual_id;
 };
 
 class EglSurface
diff --git a/kmscube/cube-gbm.cpp b/kmscube/cube-gbm.cpp
index d998f0b..69930ee 100644
--- a/kmscube/cube-gbm.cpp
+++ b/kmscube/cube-gbm.cpp
@@ -11,6 +11,7 @@
 
 #include <kms++/kms++.h>
 #include <kms++util/kms++util.h>
+#include "cube.h"
 #include "cube-egl.h"
 #include "cube-gles2.h"
 
@@ -48,10 +49,10 @@ private:
 class GbmSurface
 {
 public:
-	GbmSurface(GbmDevice& gdev, int width, int height)
+	GbmSurface(GbmDevice& gdev, int width, int height, uint32_t format)
 	{
 		m_surface = gbm_surface_create(gdev.handle(), width, height,
-					       GBM_FORMAT_XRGB8888,
+					       format,
 					       GBM_BO_USE_SCANOUT | GBM_BO_USE_RENDERING);
 		FAIL_IF(!m_surface, "failed to create gbm surface");
 	}
@@ -92,7 +93,7 @@ public:
 		: card(card), egl(egl), m_width(width), m_height(height),
 		  bo_prev(0), bo_next(0)
 	{
-		gsurface = unique_ptr<GbmSurface>(new GbmSurface(gdev, width, height));
+		gsurface = unique_ptr<GbmSurface>(new GbmSurface(gdev, width, height, egl.native_visual_id()));
 		esurface = eglCreateWindowSurface(egl.display(), egl.config(), gsurface->handle(), NULL);
 		FAIL_IF(esurface == EGL_NO_SURFACE, "failed to create egl surface");
 	}
@@ -250,6 +251,10 @@ private:
 		if (m_plane)
 			m_surface2->free_prev();
 
+		if (s_num_frames && m_frame_num >= s_num_frames) {
+			s_need_exit = true;
+		}
+
 		if (s_need_exit)
 			return;
 
@@ -289,7 +294,7 @@ private:
 		s_flip_pending++;
 	}
 
-	int m_frame_num;
+	unsigned m_frame_num;
 	chrono::steady_clock::time_point m_t1;
 
 	Connector* m_connector;
@@ -314,7 +319,7 @@ void main_gbm()
 	FAIL_IF(!card.has_atomic(), "No atomic modesetting");
 
 	GbmDevice gdev(card);
-	EglState egl(gdev.handle());
+	EglState egl(gdev.handle(), GBM_FORMAT_XRGB8888);
 
 	ResourceManager resman(card);
 
diff --git a/kmscube/cube.cpp b/kmscube/cube.cpp
index 406bb8d..420c657 100644
--- a/kmscube/cube.cpp
+++ b/kmscube/cube.cpp
@@ -32,7 +32,7 @@ using namespace std;
 
 bool s_verbose;
 bool s_fullscreen;
-unsigned s_num_frames;
+unsigned s_num_frames = 0;
 
 int main(int argc, char* argv[])
 {
diff --git a/kmscube/meson.build b/kmscube/meson.build
index 68765f2..fd0fb96 100644
--- a/kmscube/meson.build
+++ b/kmscube/meson.build
@@ -1,3 +1,14 @@
+if not get_option('kmscube')
+   kmscube_enabled = false
+   subdir_done()
+endif
+
+if not get_option('libutils')
+    error('"kmscube" option requires "libutils" option enabled')
+endif
+
+kmscube_enabled = true
+
 kmscube_sources = files([
     'cube.cpp',
     'cube-egl.cpp',
diff --git a/meson.build b/meson.build
index cdc8cab..8dc031e 100644
--- a/meson.build
+++ b/meson.build
@@ -2,6 +2,7 @@ project('kms++', 'cpp',
     default_options : [
         'cpp_std=c++17',
     ],
+    version: '0.0.0',
 )
 
 cpp = meson.get_compiler('cpp')
@@ -23,30 +24,30 @@ endif
 
 add_project_arguments(cpp_arguments, language : 'cpp')
 
-link_arguments = []
-
-if get_option('static-libc')
-    link_arguments += ['-static-libgcc', '-static-libstdc++']
-endif
-
-add_global_link_arguments(link_arguments, language : 'cpp')
-
 libfmt_dep = dependency('fmt')
 
 libdrmomap_dep = dependency('libdrm_omap', required : get_option('omap'))
 
-subdir('kms++')
-
-if get_option('libutils')
-    subdir('kms++util')
+if libdrmomap_dep.found()
+    add_global_arguments('-DHAS_LIBDRM_OMAP', language : 'cpp')
 endif
 
-if get_option('utils')
-    subdir('utils')
+if get_option('libutils')
+	add_global_arguments('-DHAS_KMSXXUTIL', language : 'cpp')
 endif
 
+subdir('kms++')
+subdir('kms++util')
+subdir('utils')
+subdir('kmscube')
 subdir('py')
 
-if get_option('kmscube')
-    subdir('kmscube')
-endif
+summary({
+            'omapdrm extensions': omapdrm_enabled,
+            'kms++utils library': libutils_enabled,
+            'Python bindings': pybindings_enabled,
+            'kmscube': kmscube_enabled,
+            'Utilities': utils_enabled,
+        },
+        section : 'Configuration',
+        bool_yn : true)
diff --git a/meson_options.txt b/meson_options.txt
index d18988b..cc750c7 100644
--- a/meson_options.txt
+++ b/meson_options.txt
@@ -1,9 +1,6 @@
 option('omap', type : 'feature', value : 'auto',
        description : 'Build omapdrm extensions')
 
-option('static-libc', type : 'boolean', value : false,
-       description : 'Build with -static-libgcc -static-libstdc++')
-
 option('libutils', type : 'boolean', value : true,
        description : 'Build kms++utils library')
 
@@ -13,8 +10,5 @@ option('utils', type : 'boolean', value : true,
 option('pykms', type : 'feature', value : 'auto',
        description : 'Build python bindings')
 
-option('system-pybind11', type : 'feature', value : 'auto',
-       description : 'Use pybind11 from the system or from meson subproject')
-
 option('kmscube', type : 'boolean', value : false,
        description : 'Build kmscube test application')
diff --git a/py/pykms/meson.build b/py/pykms/meson.build
index b29cd9f..de05d12 100644
--- a/py/pykms/meson.build
+++ b/py/pykms/meson.build
@@ -1,27 +1,35 @@
+
+# Python bindings require libutils for now.
+if not get_option('libutils')
+    pybindings_enabled = false
+    subdir_done()
+endif
+
 py3_dep = dependency('python3', required : get_option('pykms'))
 
 if py3_dep.found() == false
+    pybindings_enabled = false
     subdir_done()
 endif
 
-if get_option('system-pybind11').enabled()
-    pybind11_dep = dependency('pybind11')
-elif get_option('system-pybind11').disabled()
-    pybind11_proj = subproject('pybind11')
-    pybind11_dep = pybind11_proj.get_variable('pybind11_dep')
-else
-    pybind11_dep = dependency('pybind11', fallback : ['pybind11', 'pybind11_dep'])
+pybind11_dep = dependency('pybind11', fallback : ['pybind11', 'pybind11_dep'],
+                          required : get_option('pykms'))
+
+if pybind11_dep.found() == false
+    pybindings_enabled = false
+    subdir_done()
 endif
 
+pybindings_enabled = true
+
 pykms_sources = files([
     'pykmsbase.cpp',
     'pykms.cpp',
 ])
 
-if get_option('utils')
+if get_option('libutils')
     pykms_sources += files([
         'pykmsutil.cpp',
-        'pyvid.cpp',
     ])
 endif
 
@@ -37,7 +45,7 @@ pykms_deps = [
     pybind11_dep,
 ]
 
-if get_option('utils')
+if get_option('libutils')
     pykms_deps += [ libkmsxxutil_dep ]
 endif
 
diff --git a/py/pykms/pykms.cpp b/py/pykms/pykms.cpp
index b91a1a9..0c17c4c 100644
--- a/py/pykms/pykms.cpp
+++ b/py/pykms/pykms.cpp
@@ -7,9 +7,11 @@ namespace py = pybind11;
 using namespace kms;
 using namespace std;
 
-void init_pykmstest(py::module& m);
 void init_pykmsbase(py::module& m);
-void init_pyvid(py::module& m);
+
+#if HAS_KMSXXUTIL
+void init_pykmsutils(py::module& m);
+#endif
 
 #if HAS_LIBDRM_OMAP
 void init_pykmsomap(py::module& m);
@@ -19,9 +21,9 @@ PYBIND11_MODULE(pykms, m)
 {
 	init_pykmsbase(m);
 
-	init_pykmstest(m);
-
-	init_pyvid(m);
+#if HAS_KMSXXUTIL
+	init_pykmsutils(m);
+#endif
 
 #if HAS_LIBDRM_OMAP
 	init_pykmsomap(m);
diff --git a/py/pykms/pykmsbase.cpp b/py/pykms/pykmsbase.cpp
index a963843..254dce6 100644
--- a/py/pykms/pykmsbase.cpp
+++ b/py/pykms/pykmsbase.cpp
@@ -46,6 +46,10 @@ void init_pykmsbase(py::module& m)
 			return convert_vector(self->get_planes());
 		})
 
+		.def_property_readonly("properties", [](Card* self) {
+			return convert_vector(self->get_properties());
+		})
+
 		.def_property_readonly("has_atomic", &Card::has_atomic)
 		.def("get_prop", (Property * (Card::*)(uint32_t) const) & Card::get_prop)
 
@@ -61,7 +65,7 @@ void init_pykmsbase(py::module& m)
 		.def("refresh_props", &DrmPropObject::refresh_props)
 		.def_property_readonly("prop_map", &DrmPropObject::get_prop_map)
 		.def("get_prop_value", (uint64_t(DrmPropObject::*)(const string&) const) & DrmPropObject::get_prop_value)
-		.def("set_prop_value", (int (DrmPropObject::*)(const string&, uint64_t)) & DrmPropObject::set_prop_value)
+		.def("set_prop_value", (int(DrmPropObject::*)(const string&, uint64_t)) & DrmPropObject::set_prop_value)
 		.def("get_prop_value_as_blob", &DrmPropObject::get_prop_value_as_blob)
 		.def("get_prop", &DrmPropObject::get_prop)
 		.def("has_prop", &DrmPropObject::has_prop);
@@ -81,8 +85,8 @@ void init_pykmsbase(py::module& m)
 		.def("refresh", &Connector::refresh);
 
 	py::class_<Crtc, DrmPropObject, unique_ptr<Crtc, py::nodelete>>(m, "Crtc")
-		.def("set_mode", (int (Crtc::*)(Connector*, const Videomode&)) & Crtc::set_mode)
-		.def("set_mode", (int (Crtc::*)(Connector*, Framebuffer&, const Videomode&)) & Crtc::set_mode)
+		.def("set_mode", (int(Crtc::*)(Connector*, const Videomode&)) & Crtc::set_mode)
+		.def("set_mode", (int(Crtc::*)(Connector*, Framebuffer&, const Videomode&)) & Crtc::set_mode)
 		.def("disable_mode", &Crtc::disable_mode)
 		.def(
 			"page_flip",
@@ -116,7 +120,18 @@ void init_pykmsbase(py::module& m)
 
 	py::class_<Property, DrmObject, unique_ptr<Property, py::nodelete>>(m, "Property")
 		.def_property_readonly("name", &Property::name)
-		.def_property_readonly("enums", &Property::get_enums);
+		.def_property_readonly("type", &Property::type)
+		.def_property_readonly("enums", &Property::get_enums)
+		.def_property_readonly("values", &Property::get_values)
+		.def("__repr__", [](const Property& o) { return "<pykms.Property " + to_string(o.id()) + " '" + o.name() + "'>"; });
+
+	py::enum_<PropertyType>(m, "PropertyType")
+		.value("Range", PropertyType::Range)
+		.value("Enum", PropertyType::Enum)
+		.value("Blob", PropertyType::Blob)
+		.value("Bitmask", PropertyType::Bitmask)
+		.value("Object", PropertyType::Object)
+		.value("SignedRange", PropertyType::SignedRange);
 
 	py::class_<Blob>(m, "Blob")
 		.def(py::init([](Card& card, py::buffer buf) {
@@ -148,27 +163,41 @@ void init_pykmsbase(py::module& m)
 		.def("offset", &Framebuffer::offset)
 		.def("fd", &Framebuffer::prime_fd)
 
+		.def("flush", (void(Framebuffer::*)(void)) & Framebuffer::flush)
+		.def("flush", (void(Framebuffer::*)(uint32_t x, uint32_t y, uint32_t width, uint32_t height)) & Framebuffer::flush)
+
 		// XXX pybind11 doesn't support a base object (DrmObject) with custom holder-type,
 		// and a subclass with standard holder-type.
 		// So we just copy the DrmObject members here.
 		// Note that this means that python thinks we don't derive from DrmObject
 		.def_property_readonly("id", &DrmObject::id)
 		.def_property_readonly("idx", &DrmObject::idx)
-		.def_property_readonly("card", &DrmObject::card);
+		.def_property_readonly("card", &DrmObject::card)
+		.def("map", [](Framebuffer& self, uint32_t plane) {
+			const auto& format_info = get_pixel_format_info(self.format());
+
+			if (plane >= format_info.num_planes)
+				throw runtime_error("map: bad plane number");
+
+			array<uint32_t, 2> shape{ self.height(), self.width() * format_info.planes[plane].bitspp / 8 };
+			array<uint32_t, 2> strides{ self.stride(plane), sizeof(uint8_t) };
+
+			return py::memoryview::from_buffer(self.map(plane), shape, strides);
+		});
 
 	py::class_<DumbFramebuffer, Framebuffer>(m, "DumbFramebuffer")
 		.def(py::init<Card&, uint32_t, uint32_t, const string&>(),
 		     py::keep_alive<1, 2>()) // Keep Card alive until this is destructed
 		.def(py::init<Card&, uint32_t, uint32_t, PixelFormat>(),
 		     py::keep_alive<1, 2>()) // Keep Card alive until this is destructed
-		;
+		.def("__repr__", [](const DumbFramebuffer& o) { return "<pykms.DumbFramebuffer " + to_string(o.id()) + ">"; });
 
 	py::class_<DmabufFramebuffer, Framebuffer>(m, "DmabufFramebuffer")
 		.def(py::init<Card&, uint32_t, uint32_t, const string&, vector<int>, vector<uint32_t>, vector<uint32_t>>(),
 		     py::keep_alive<1, 2>()) // Keep Card alive until this is destructed
 		.def(py::init<Card&, uint32_t, uint32_t, PixelFormat, vector<int>, vector<uint32_t>, vector<uint32_t>>(),
 		     py::keep_alive<1, 2>()) // Keep Card alive until this is destructed
-		;
+		.def("__repr__", [](const DmabufFramebuffer& o) { return "<pykms.DmabufFramebuffer " + to_string(o.id()) + ">"; });
 
 	py::enum_<PixelFormat>(m, "PixelFormat")
 		.value("Undefined", PixelFormat::Undefined)
@@ -224,6 +253,9 @@ void init_pykmsbase(py::module& m)
 		.value("RGBA1010102", PixelFormat::RGBA1010102)
 		.value("BGRA1010102", PixelFormat::BGRA1010102);
 
+	m.def("fourcc_to_pixelformat", &FourCCToPixelFormat);
+	m.def("pixelformat_to_fourcc", &PixelFormatToFourCC);
+
 	py::enum_<SyncPolarity>(m, "SyncPolarity")
 		.value("Undefined", SyncPolarity::Undefined)
 		.value("Positive", SyncPolarity::Positive)
@@ -266,9 +298,9 @@ void init_pykmsbase(py::module& m)
 	py::class_<AtomicReq>(m, "AtomicReq")
 		.def(py::init<Card&>(),
 		     py::keep_alive<1, 2>()) // Keep Card alive until this is destructed
-		.def("add", (void (AtomicReq::*)(DrmPropObject*, const string&, uint64_t)) & AtomicReq::add)
-		.def("add", (void (AtomicReq::*)(DrmPropObject*, Property*, uint64_t)) & AtomicReq::add)
-		.def("add", (void (AtomicReq::*)(DrmPropObject*, const map<string, uint64_t>&)) & AtomicReq::add)
+		.def("add", (void(AtomicReq::*)(DrmPropObject*, const string&, uint64_t)) & AtomicReq::add)
+		.def("add", (void(AtomicReq::*)(DrmPropObject*, Property*, uint64_t)) & AtomicReq::add)
+		.def("add", (void(AtomicReq::*)(DrmPropObject*, const map<string, uint64_t>&)) & AtomicReq::add)
 		.def("test", &AtomicReq::test, py::arg("allow_modeset") = false)
 		.def(
 			"commit",
@@ -277,4 +309,22 @@ void init_pykmsbase(py::module& m)
 			},
 			py::arg("data") = 0, py::arg("allow_modeset") = false)
 		.def("commit_sync", &AtomicReq::commit_sync, py::arg("allow_modeset") = false);
+
+	py::class_<PixelFormatPlaneInfo>(m, "PixelFormatPlaneInfo")
+		.def_readonly("bitspp", &PixelFormatPlaneInfo::bitspp)
+		.def_readonly("xsub", &PixelFormatPlaneInfo::xsub)
+		.def_readonly("ysub", &PixelFormatPlaneInfo::ysub);
+
+	py::class_<PixelFormatInfo>(m, "PixelFormatInfo")
+		.def_readonly("num_planes", &PixelFormatInfo::num_planes)
+		.def(
+			"plane", [](const PixelFormatInfo& self, uint32_t idx) {
+				if (idx >= self.num_planes)
+					throw runtime_error("invalid plane number");
+				return self.planes[idx];
+			},
+			py::return_value_policy::reference_internal);
+
+	m.def("get_pixel_format_info", &get_pixel_format_info,
+	      py::return_value_policy::reference_internal);
 }
diff --git a/py/pykms/pykmsutil.cpp b/py/pykms/pykmsutil.cpp
index 666cbdc..db91864 100644
--- a/py/pykms/pykmsutil.cpp
+++ b/py/pykms/pykmsutil.cpp
@@ -8,7 +8,7 @@ namespace py = pybind11;
 using namespace kms;
 using namespace std;
 
-void init_pykmstest(py::module& m)
+void init_pykmsutils(py::module& m)
 {
 	py::class_<RGB>(m, "RGB")
 		.def(py::init<>())
diff --git a/py/pykms/pyvid.cpp b/py/pykms/pyvid.cpp
deleted file mode 100644
index 54ad480..0000000
--- a/py/pykms/pyvid.cpp
+++ /dev/null
@@ -1,46 +0,0 @@
-#include <pybind11/pybind11.h>
-#include <pybind11/stl.h>
-#include <kms++/kms++.h>
-#include <kms++util/kms++util.h>
-#include <kms++util/videodevice.h>
-
-namespace py = pybind11;
-
-using namespace kms;
-using namespace std;
-
-void init_pyvid(py::module& m)
-{
-	py::class_<VideoDevice>(m, "VideoDevice")
-		.def(py::init<const string&>())
-		.def_property_readonly("fd", &VideoDevice::fd)
-		.def_property_readonly("has_capture", &VideoDevice::has_capture)
-		.def_property_readonly("has_output", &VideoDevice::has_output)
-		.def_property_readonly("has_m2m", &VideoDevice::has_m2m)
-		.def_property_readonly("capture_streamer", &VideoDevice::get_capture_streamer)
-		.def_property_readonly("output_streamer", &VideoDevice::get_output_streamer)
-		.def_property_readonly("discrete_frame_sizes", &VideoDevice::get_discrete_frame_sizes)
-		.def_property_readonly("frame_sizes", &VideoDevice::get_frame_sizes)
-		.def("get_capture_devices", &VideoDevice::get_capture_devices);
-
-	py::class_<VideoStreamer>(m, "VideoStreamer")
-		.def_property_readonly("fd", &VideoStreamer::fd)
-		.def_property_readonly("ports", &VideoStreamer::get_ports)
-		.def("set_port", &VideoStreamer::set_port)
-		.def_property_readonly("formats", &VideoStreamer::get_formats)
-		.def("set_format", &VideoStreamer::set_format)
-		.def("get_selection", [](VideoStreamer* self) {
-			uint32_t left, top, width, height;
-			self->get_selection(left, top, width, height);
-			return make_tuple(left, top, width, height);
-		})
-		.def("set_selection", [](VideoStreamer* self, uint32_t left, uint32_t top, uint32_t width, uint32_t height) {
-			self->set_selection(left, top, width, height);
-			return make_tuple(left, top, width, height);
-		})
-		.def("set_queue_size", &VideoStreamer::set_queue_size)
-		.def("queue", &VideoStreamer::queue)
-		.def("dequeue", &VideoStreamer::dequeue)
-		.def("stream_on", &VideoStreamer::stream_on)
-		.def("stream_off", &VideoStreamer::stream_off);
-}
diff --git a/py/tests/cam.py b/py/tests/cam.py
deleted file mode 100755
index b7294ed..0000000
--- a/py/tests/cam.py
+++ /dev/null
@@ -1,87 +0,0 @@
-#!/usr/bin/python3
-
-import sys
-import selectors
-import pykms
-import argparse
-import time
-
-parser = argparse.ArgumentParser()
-parser.add_argument("width", type=int)
-parser.add_argument("height", type=int)
-args = parser.parse_args()
-
-w = args.width
-h = args.height
-fmt = pykms.PixelFormat.YUYV
-
-print("Capturing in {}x{}".format(w, h))
-
-card = pykms.Card()
-res = pykms.ResourceManager(card)
-conn = res.reserve_connector()
-crtc = res.reserve_crtc(conn)
-plane = res.reserve_overlay_plane(crtc, fmt)
-
-mode = conn.get_default_mode()
-modeb = mode.to_blob(card)
-
-req = pykms.AtomicReq(card)
-req.add(conn, "CRTC_ID", crtc.id)
-req.add(crtc, {"ACTIVE": 1,
-        "MODE_ID": modeb.id})
-req.commit_sync(allow_modeset = True)
-
-NUM_BUFS = 5
-
-fbs = []
-for i in range(NUM_BUFS):
-    fb = pykms.DumbFramebuffer(card, w, h, fmt)
-    fbs.append(fb)
-
-vidpath = pykms.VideoDevice.get_capture_devices()[0]
-
-vid = pykms.VideoDevice(vidpath)
-cap = vid.capture_streamer
-cap.set_port(0)
-cap.set_format(fmt, w, h)
-cap.set_queue_size(NUM_BUFS)
-
-for fb in fbs:
-    cap.queue(fb)
-
-cap.stream_on()
-
-
-def readvid(conn, mask):
-    fb = cap.dequeue()
-
-    if card.has_atomic:
-        plane.set_props({
-            "FB_ID": fb.id,
-            "CRTC_ID": crtc.id,
-            "SRC_W": fb.width << 16,
-            "SRC_H": fb.height << 16,
-            "CRTC_W": fb.width,
-            "CRTC_H": fb.height,
-        })
-    else:
-        crtc.set_plane(plane, fb, 0, 0, fb.width, fb.height,
-            0, 0, fb.width, fb.height)
-
-    cap.queue(fb)
-
-def readkey(conn, mask):
-    #print("KEY EVENT");
-    sys.stdin.readline()
-    exit(0)
-
-sel = selectors.DefaultSelector()
-sel.register(cap.fd, selectors.EVENT_READ, readvid)
-sel.register(sys.stdin, selectors.EVENT_READ, readkey)
-
-while True:
-    events = sel.select()
-    for key, mask in events:
-        callback = key.data
-        callback(key.fileobj, mask)
diff --git a/py/tests/pic.py b/py/tests/pic.py
new file mode 100755
index 0000000..6ff2a05
--- /dev/null
+++ b/py/tests/pic.py
@@ -0,0 +1,30 @@
+#!/usr/bin/python3
+
+import pykms
+import argparse
+from PIL import Image
+import numpy as np
+
+parser = argparse.ArgumentParser()
+parser.add_argument("image")
+parser.add_argument("-f", "--fourcc", default="XR24")
+args = parser.parse_args()
+
+card = pykms.Card()
+res = pykms.ResourceManager(card)
+conn = res.reserve_connector()
+crtc = res.reserve_crtc(conn)
+mode = conn.get_default_mode()
+fb = pykms.DumbFramebuffer(card, mode.hdisplay, mode.vdisplay, args.fourcc)
+crtc.set_mode(conn, fb, mode)
+
+image = Image.open(args.image)
+image = image.resize((mode.hdisplay, mode.vdisplay),
+                     Image.Resampling.LANCZOS)
+pixels = np.array(image)
+
+map = fb.map(0)
+b = np.frombuffer(map, dtype=np.uint8).reshape(fb.height, fb.width, 4)
+b[:, :, :] = pixels
+
+input()
diff --git a/subprojects/pybind11.wrap b/subprojects/pybind11.wrap
index 38bc5f3..96ec57a 100644
--- a/subprojects/pybind11.wrap
+++ b/subprojects/pybind11.wrap
@@ -1,12 +1,13 @@
 [wrap-file]
-directory = pybind11-2.6.0
-source_url = https://github.com/pybind/pybind11/archive/v2.6.0.zip
-source_filename = pybind11-2.6.0.zip
-source_hash = c2ed3fc84db08f40a36ce1d03331624ed6977497b35dfed36a1423396928559a
-patch_url = https://wrapdb.mesonbuild.com/v1/projects/pybind11/2.6.0/1/get_zip
-patch_filename = pybind11-2.6.0-1-wrap.zip
-patch_hash = dd52c46ccfdbca06b6967e89c9981408c6a3f4ed3d50c32b809f392b4ac5b0d2
+directory = pybind11-2.10.4
+source_url = https://github.com/pybind/pybind11/archive/refs/tags/v2.10.4.tar.gz
+source_filename = pybind11-2.10.4.tar.gz
+source_hash = 832e2f309c57da9c1e6d4542dedd34b24e4192ecb4d62f6f4866a737454c9970
+patch_filename = pybind11_2.10.4-1_patch.zip
+patch_url = https://wrapdb.mesonbuild.com/v2/pybind11_2.10.4-1/get_patch
+patch_hash = 9489d0cdc1244078a3108c52b4591a6f07f3dc30ca7299d3a3c42b84fa763396
+source_fallback_url = https://github.com/mesonbuild/wrapdb/releases/download/pybind11_2.10.4-1/pybind11-2.10.4.tar.gz
+wrapdb_version = 2.10.4-1
 
 [provide]
 pybind11 = pybind11_dep
-
diff --git a/utils/fbtest.cpp b/utils/fbtest.cpp
index fba7ba7..913d773 100644
--- a/utils/fbtest.cpp
+++ b/utils/fbtest.cpp
@@ -40,7 +40,9 @@ int main(int argc, char** argv)
 
 	FAIL_IF(ptr == MAP_FAILED, "mmap failed");
 
-	ExtCPUFramebuffer buf(var.xres, var.yres, PixelFormat::XRGB8888,
+	PixelFormat fmt = var.bits_per_pixel == 16 ? PixelFormat::RGB565 : PixelFormat::XRGB8888;
+
+	ExtCPUFramebuffer buf(var.xres, var.yres, fmt,
 			      ptr, var.yres_virtual * fix.line_length, fix.line_length, 0);
 
 	printf("%s: res %dx%d, virtual %dx%d, line_len %d\n",
@@ -50,6 +52,7 @@ int main(int argc, char** argv)
 	       fix.line_length);
 
 	draw_test_pattern(buf);
+	// XXX this may draw over the edge for narrow displays
 	draw_text(buf, buf.width() / 2, 0, fbdev, RGB(255, 255, 255));
 
 	close(fd);
diff --git a/utils/kmsprint.cpp b/utils/kmsprint.cpp
index 7469b47..c573c2e 100644
--- a/utils/kmsprint.cpp
+++ b/utils/kmsprint.cpp
@@ -105,8 +105,8 @@ static string format_plane(Plane& p)
 				   (uint32_t)p.get_prop_value("SRC_Y") >> 16,
 				   (uint32_t)p.get_prop_value("SRC_W") >> 16,
 				   (uint32_t)p.get_prop_value("SRC_H") >> 16,
-				   (uint32_t)p.get_prop_value("CRTC_X"),
-				   (uint32_t)p.get_prop_value("CRTC_Y"),
+				   (int32_t)p.get_prop_value("CRTC_X"),
+				   (int32_t)p.get_prop_value("CRTC_Y"),
 				   (uint32_t)p.get_prop_value("CRTC_W"),
 				   (uint32_t)p.get_prop_value("CRTC_H"));
 	}
@@ -120,8 +120,9 @@ static string format_plane(Plane& p)
 
 static string format_fb(Framebuffer& fb)
 {
-	return fmt::format("FB {} {}x{}",
-			   fb.id(), fb.width(), fb.height());
+	return fmt::format("FB {} {}x{} {}",
+			   fb.id(), fb.width(), fb.height(),
+			   PixelFormatToFourCC(fb.format()));
 }
 
 static string format_property(const Property* prop, uint64_t val)
diff --git a/utils/kmstest.cpp b/utils/kmstest.cpp
index 3f1716f..de6957d 100644
--- a/utils/kmstest.cpp
+++ b/utils/kmstest.cpp
@@ -32,8 +32,8 @@ struct PropInfo {
 struct PlaneInfo {
 	Plane* plane;
 
-	unsigned x;
-	unsigned y;
+	signed x;
+	signed y;
 	unsigned w;
 	unsigned h;
 
@@ -118,8 +118,8 @@ static void parse_crtc(ResourceManager& resman, Card& card, const string& crtc_s
 
 	const regex modeline_re("(?:(@?)(\\d+):)?" // @12:
 				"(\\d+)," // 33000000,
-				"(\\d+)/(\\d+)/(\\d+)/(\\d+)/([+-])," // 800/210/30/16/-,
-				"(\\d+)/(\\d+)/(\\d+)/(\\d+)/([+-])" // 480/22/13/10/-
+				"(\\d+)/(\\d+)/(\\d+)/(\\d+)/([+-\\?])," // 800/210/30/16/-,
+				"(\\d+)/(\\d+)/(\\d+)/(\\d+)/([+-\\?])" // 480/22/13/10/-
 				"(?:,([i]+))?" // ,i
 	);
 
@@ -202,17 +202,29 @@ static void parse_crtc(ResourceManager& resman, Card& card, const string& crtc_s
 		unsigned hfp = stoul(sm[5]);
 		unsigned hsw = stoul(sm[6]);
 		unsigned hbp = stoul(sm[7]);
-		bool h_pos_sync = sm[8] == "+" ? true : false;
+
+		SyncPolarity h_sync;
+		switch (sm[8].str()[0]) {
+		case '+': h_sync = SyncPolarity::Positive; break;
+		case '-': h_sync = SyncPolarity::Negative; break;
+		default: h_sync = SyncPolarity::Undefined; break;
+		}
 
 		unsigned vact = stoul(sm[9]);
 		unsigned vfp = stoul(sm[10]);
 		unsigned vsw = stoul(sm[11]);
 		unsigned vbp = stoul(sm[12]);
-		bool v_pos_sync = sm[13] == "+" ? true : false;
+
+		SyncPolarity v_sync;
+		switch (sm[13].str()[0]) {
+		case '+': v_sync = SyncPolarity::Positive; break;
+		case '-': v_sync = SyncPolarity::Negative; break;
+		default: v_sync = SyncPolarity::Undefined; break;
+		}
 
 		output.mode = videomode_from_timings(clock / 1000, hact, hfp, hsw, hbp, vact, vfp, vsw, vbp);
-		output.mode.set_hsync(h_pos_sync ? SyncPolarity::Positive : SyncPolarity::Negative);
-		output.mode.set_vsync(v_pos_sync ? SyncPolarity::Positive : SyncPolarity::Negative);
+		output.mode.set_hsync(h_sync);
+		output.mode.set_vsync(v_sync);
 
 		if (sm[14].matched) {
 			for (int i = 0; i < sm[14].length(); ++i) {
@@ -244,7 +256,7 @@ static void parse_plane(ResourceManager& resman, Card& card, const string& plane
 {
 	// 3:400,400-400x400
 	const regex plane_re("(?:(@?)(\\d+):)?" // 3:
-			     "(?:(\\d+),(\\d+)-)?" // 400,400-
+			     "(?:(-?\\d+),(-?\\d+)-)?" // 400,400-
 			     "(\\d+)x(\\d+)"); // 400x400
 
 	smatch sm;
@@ -279,12 +291,12 @@ static void parse_plane(ResourceManager& resman, Card& card, const string& plane
 	pinfo.h = stoul(sm[6]);
 
 	if (sm[3].matched)
-		pinfo.x = stoul(sm[3]);
+		pinfo.x = stol(sm[3]);
 	else
 		pinfo.x = output.mode.hdisplay / 2 - pinfo.w / 2;
 
 	if (sm[4].matched)
-		pinfo.y = stoul(sm[4]);
+		pinfo.y = stol(sm[4]);
 	else
 		pinfo.y = output.mode.vdisplay / 2 - pinfo.h / 2;
 }
@@ -823,7 +835,9 @@ static void set_crtcs_n_planes_atomic(Card& card, const vector<OutputInfo>& outp
 
 	// XXX DRM framework doesn't allow moving an active plane from one crtc to another.
 	// See drm_atomic.c::plane_switching_crtc().
-	// For the time being, disable all crtcs and planes here.
+	// For the time being, try and disable all crtcs and planes here.
+	// Do not check the return value as some simple displays don't support the crtc being
+	// enabled but the primary plane being disabled.
 
 	AtomicReq disable_req(card);
 
@@ -844,9 +858,7 @@ static void set_crtcs_n_planes_atomic(Card& card, const vector<OutputInfo>& outp
 					       { "CRTC_ID", 0 },
 				       });
 
-	r = disable_req.commit_sync(true);
-	if (r)
-		EXIT("Atomic commit failed when disabling: %d\n", r);
+	disable_req.commit_sync(true);
 
 	// Keep blobs here so that we keep ref to them until we have committed the req
 	vector<unique_ptr<Blob>> blobs;
diff --git a/utils/meson.build b/utils/meson.build
index b1e7918..b1d3082 100644
--- a/utils/meson.build
+++ b/utils/meson.build
@@ -1,3 +1,15 @@
+if not get_option('utils')
+    utils_enabled = false
+    subdir_done()
+endif
+
+if not get_option('libutils')
+    utils_enabled = false
+    subdir_done()
+endif
+
+utils_enabled = true
+
 common_deps = [ libkmsxx_dep, libkmsxxutil_dep, libfmt_dep ]
 
 libevdev_dep = dependency('libevdev', required : false)
@@ -12,6 +24,3 @@ executable('kmsblank', 'kmsblank.cpp', dependencies : [ common_deps ], install :
 if libevdev_dep.found()
     executable('kmstouch', 'kmstouch.cpp', dependencies : [ common_deps, libevdev_dep ], install : false)
 endif
-
-executable('omap-wbcap', 'omap-wbcap.cpp', dependencies : [ common_deps ], install : false)
-executable('omap-wbm2m', 'omap-wbm2m.cpp', dependencies : [ common_deps ], install : false)
diff --git a/utils/omap-wbcap.cpp b/utils/omap-wbcap.cpp
deleted file mode 100644
index 8033869..0000000
--- a/utils/omap-wbcap.cpp
+++ /dev/null
@@ -1,411 +0,0 @@
-#include <cstdio>
-#include <poll.h>
-#include <unistd.h>
-#include <algorithm>
-#include <fstream>
-
-#include <kms++/kms++.h>
-#include <kms++util/kms++util.h>
-#include <kms++util/videodevice.h>
-
-#define CAMERA_BUF_QUEUE_SIZE 5
-
-using namespace std;
-using namespace kms;
-
-static vector<DumbFramebuffer*> s_fbs;
-static vector<DumbFramebuffer*> s_free_fbs;
-static vector<DumbFramebuffer*> s_wb_fbs;
-static vector<DumbFramebuffer*> s_ready_fbs;
-
-class WBStreamer
-{
-public:
-	WBStreamer(VideoStreamer* streamer, Crtc* crtc, PixelFormat pixfmt)
-		: m_capdev(*streamer)
-	{
-		Videomode m = crtc->mode();
-
-		m_capdev.set_port(crtc->idx());
-		m_capdev.set_format(pixfmt, m.hdisplay, m.vdisplay / (m.interlace() ? 2 : 1));
-		m_capdev.set_queue_size(s_fbs.size());
-
-		for (auto fb : s_free_fbs) {
-			m_capdev.queue(fb);
-			s_wb_fbs.push_back(fb);
-		}
-
-		s_free_fbs.clear();
-	}
-
-	~WBStreamer()
-	{
-	}
-
-	WBStreamer(const WBStreamer& other) = delete;
-	WBStreamer& operator=(const WBStreamer& other) = delete;
-
-	int fd() const { return m_capdev.fd(); }
-
-	void start_streaming()
-	{
-		m_capdev.stream_on();
-	}
-
-	void stop_streaming()
-	{
-		m_capdev.stream_off();
-	}
-
-	DumbFramebuffer* Dequeue()
-	{
-		auto fb = m_capdev.dequeue();
-
-		auto iter = find(s_wb_fbs.begin(), s_wb_fbs.end(), fb);
-		s_wb_fbs.erase(iter);
-
-		s_ready_fbs.insert(s_ready_fbs.begin(), fb);
-
-		return fb;
-	}
-
-	void Queue()
-	{
-		if (s_free_fbs.size() == 0)
-			return;
-
-		auto fb = s_free_fbs.back();
-		s_free_fbs.pop_back();
-
-		m_capdev.queue(fb);
-
-		s_wb_fbs.insert(s_wb_fbs.begin(), fb);
-	}
-
-private:
-	VideoStreamer& m_capdev;
-};
-
-class WBFlipState : private PageFlipHandlerBase
-{
-public:
-	WBFlipState(Card& card, Crtc* crtc, Plane* plane)
-		: m_card(card), m_crtc(crtc), m_plane(plane)
-	{
-		auto fb = s_ready_fbs.back();
-		s_ready_fbs.pop_back();
-
-		AtomicReq req(m_card);
-
-		req.add(m_plane, "CRTC_ID", m_crtc->id());
-		req.add(m_plane, "FB_ID", fb->id());
-
-		req.add(m_plane, "CRTC_X", 0);
-		req.add(m_plane, "CRTC_Y", 0);
-		req.add(m_plane, "CRTC_W", min((uint32_t)m_crtc->mode().hdisplay, fb->width()));
-		req.add(m_plane, "CRTC_H", min((uint32_t)m_crtc->mode().vdisplay, fb->height()));
-
-		req.add(m_plane, "SRC_X", 0);
-		req.add(m_plane, "SRC_Y", 0);
-		req.add(m_plane, "SRC_W", fb->width() << 16);
-		req.add(m_plane, "SRC_H", fb->height() << 16);
-
-		int r = req.commit_sync();
-		FAIL_IF(r, "initial plane setup failed");
-
-		m_current_fb = fb;
-	}
-
-	void queue_next()
-	{
-		if (m_queued_fb)
-			return;
-
-		if (s_ready_fbs.size() == 0)
-			return;
-
-		auto fb = s_ready_fbs.back();
-		s_ready_fbs.pop_back();
-
-		AtomicReq req(m_card);
-		req.add(m_plane, "FB_ID", fb->id());
-
-		int r = req.commit(this);
-		if (r)
-			EXIT("Flip commit failed: %d\n", r);
-
-		m_queued_fb = fb;
-	}
-
-private:
-	void handle_page_flip(uint32_t frame, double time)
-	{
-		if (m_queued_fb) {
-			if (m_current_fb)
-				s_free_fbs.insert(s_free_fbs.begin(), m_current_fb);
-
-			m_current_fb = m_queued_fb;
-			m_queued_fb = nullptr;
-		}
-
-		queue_next();
-	}
-
-	Card& m_card;
-	Crtc* m_crtc;
-	Plane* m_plane;
-
-	DumbFramebuffer* m_current_fb = nullptr;
-	DumbFramebuffer* m_queued_fb = nullptr;
-};
-
-class BarFlipState : private PageFlipHandlerBase
-{
-public:
-	BarFlipState(Card& card, Crtc* crtc, Plane* plane, uint32_t width, uint32_t height)
-		: m_card(card), m_crtc(crtc), m_plane(plane)
-	{
-		for (unsigned i = 0; i < s_num_buffers; ++i)
-			m_fbs[i] = new DumbFramebuffer(card, width, height, PixelFormat::XRGB8888);
-	}
-
-	~BarFlipState()
-	{
-		for (unsigned i = 0; i < s_num_buffers; ++i)
-			delete m_fbs[i];
-	}
-
-	void start_flipping()
-	{
-		m_frame_num = 0;
-		queue_next();
-	}
-
-private:
-	void handle_page_flip(uint32_t frame, double time)
-	{
-		m_frame_num++;
-		queue_next();
-	}
-
-	static unsigned get_bar_pos(DumbFramebuffer* fb, unsigned frame_num)
-	{
-		return (frame_num * bar_speed) % (fb->width() - bar_width + 1);
-	}
-
-	void draw_bar(DumbFramebuffer* fb, unsigned frame_num)
-	{
-		int old_xpos = frame_num < s_num_buffers ? -1 : get_bar_pos(fb, frame_num - s_num_buffers);
-		int new_xpos = get_bar_pos(fb, frame_num);
-
-		draw_color_bar(*fb, old_xpos, new_xpos, bar_width);
-		draw_text(*fb, fb->width() / 2, 0, to_string(frame_num), RGB(255, 255, 255));
-	}
-
-	void queue_next()
-	{
-		AtomicReq req(m_card);
-
-		unsigned cur = m_frame_num % s_num_buffers;
-
-		auto fb = m_fbs[cur];
-
-		draw_bar(fb, m_frame_num);
-
-		req.add(m_plane, {
-					 { "CRTC_ID", m_crtc->id() },
-					 { "FB_ID", fb->id() },
-
-					 { "CRTC_X", 0 },
-					 { "CRTC_Y", 0 },
-					 { "CRTC_W", min((uint32_t)m_crtc->mode().hdisplay, fb->width()) },
-					 { "CRTC_H", min((uint32_t)m_crtc->mode().vdisplay, fb->height()) },
-
-					 { "SRC_X", 0 },
-					 { "SRC_Y", 0 },
-					 { "SRC_W", fb->width() << 16 },
-					 { "SRC_H", fb->height() << 16 },
-				 });
-
-		int r = req.commit(this);
-		if (r)
-			EXIT("Flip commit failed: %d\n", r);
-	}
-
-	static const unsigned s_num_buffers = 3;
-
-	DumbFramebuffer* m_fbs[s_num_buffers];
-
-	Card& m_card;
-	Crtc* m_crtc;
-	Plane* m_plane;
-
-	unsigned m_frame_num;
-
-	static const unsigned bar_width = 20;
-	static const unsigned bar_speed = 8;
-};
-
-static const char* usage_str =
-	"Usage: wbcap [OPTIONS]\n\n"
-	"Options:\n"
-	"  -s, --src=CONN            Source connector\n"
-	"  -d, --dst=CONN            Destination connector\n"
-	"  -m, --smode=MODE          Source connector videomode\n"
-	"  -M, --dmode=MODE          Destination connector videomode\n"
-	"  -f, --format=4CC          Format\n"
-	"  -w, --write               Write captured frames to wbcap.raw file\n"
-	"  -h, --help                Print this help\n";
-
-int main(int argc, char** argv)
-{
-	string src_conn_name;
-	string src_mode_name;
-	string dst_conn_name;
-	string dst_mode_name;
-	PixelFormat pixfmt = PixelFormat::XRGB8888;
-	bool write_file = false;
-
-	OptionSet optionset = {
-		Option("s|src=", [&](string s) {
-			src_conn_name = s;
-		}),
-		Option("m|smode=", [&](string s) {
-			src_mode_name = s;
-		}),
-		Option("d|dst=", [&](string s) {
-			dst_conn_name = s;
-		}),
-		Option("M|dmode=", [&](string s) {
-			dst_mode_name = s;
-		}),
-		Option("f|format=", [&](string s) {
-			pixfmt = FourCCToPixelFormat(s);
-		}),
-		Option("w|write", [&]() {
-			write_file = true;
-		}),
-		Option("h|help", [&]() {
-			puts(usage_str);
-			exit(-1);
-		}),
-	};
-
-	optionset.parse(argc, argv);
-
-	if (optionset.params().size() > 0) {
-		puts(usage_str);
-		exit(-1);
-	}
-
-	if (src_conn_name.empty())
-		EXIT("No source connector defined");
-
-	if (dst_conn_name.empty())
-		EXIT("No destination connector defined");
-
-	VideoDevice vid("/dev/video11");
-
-	Card card;
-	ResourceManager resman(card);
-
-	card.disable_all();
-
-	auto src_conn = resman.reserve_connector(src_conn_name);
-	auto src_crtc = resman.reserve_crtc(src_conn);
-	auto src_plane = resman.reserve_generic_plane(src_crtc, pixfmt);
-	FAIL_IF(!src_plane, "Plane not found");
-	Videomode src_mode = src_mode_name.empty() ? src_conn->get_default_mode() : src_conn->get_mode(src_mode_name);
-	src_crtc->set_mode(src_conn, src_mode);
-
-	auto dst_conn = resman.reserve_connector(dst_conn_name);
-	auto dst_crtc = resman.reserve_crtc(dst_conn);
-	auto dst_plane = resman.reserve_overlay_plane(dst_crtc, pixfmt);
-	FAIL_IF(!dst_plane, "Plane not found");
-	Videomode dst_mode = dst_mode_name.empty() ? dst_conn->get_default_mode() : dst_conn->get_mode(dst_mode_name);
-	dst_crtc->set_mode(dst_conn, dst_mode);
-
-	uint32_t src_width = src_mode.hdisplay;
-	uint32_t src_height = src_mode.vdisplay;
-
-	uint32_t dst_width = src_mode.hdisplay;
-	uint32_t dst_height = src_mode.vdisplay;
-	if (src_mode.interlace())
-		dst_height /= 2;
-
-	printf("src %s, crtc %s\n", src_conn->fullname().c_str(), src_mode.to_string_short().c_str());
-
-	printf("dst %s, crtc %s\n", dst_conn->fullname().c_str(), dst_mode.to_string_short().c_str());
-
-	printf("src_fb %ux%u, dst_fb %ux%u\n", src_width, src_height, dst_width, dst_height);
-
-	for (int i = 0; i < CAMERA_BUF_QUEUE_SIZE; ++i) {
-		auto fb = new DumbFramebuffer(card, dst_width, dst_height, pixfmt);
-		s_fbs.push_back(fb);
-		s_free_fbs.push_back(fb);
-	}
-
-	// get one fb for initial setup
-	s_ready_fbs.push_back(s_free_fbs.back());
-	s_free_fbs.pop_back();
-
-	// This draws a moving bar to SRC display
-	BarFlipState barflipper(card, src_crtc, src_plane, src_width, src_height);
-	barflipper.start_flipping();
-
-	// This shows the captured SRC frames on DST display
-	WBFlipState wbflipper(card, dst_crtc, dst_plane);
-
-	WBStreamer wb(vid.get_capture_streamer(), src_crtc, pixfmt);
-	wb.start_streaming();
-
-	vector<pollfd> fds(3);
-
-	fds[0].fd = 0;
-	fds[0].events = POLLIN;
-	fds[1].fd = wb.fd();
-	fds[1].events = POLLIN;
-	fds[2].fd = card.fd();
-	fds[2].events = POLLIN;
-
-	uint32_t dst_frame_num = 0;
-
-	const string filename = "wbcap.raw";
-	unique_ptr<ofstream> os;
-	if (write_file)
-		os = unique_ptr<ofstream>(new ofstream(filename, ofstream::binary));
-
-	while (true) {
-		int r = poll(fds.data(), fds.size(), -1);
-		ASSERT(r > 0);
-
-		if (fds[0].revents != 0)
-			break;
-
-		if (fds[1].revents) {
-			fds[1].revents = 0;
-
-			DumbFramebuffer* fb = wb.Dequeue();
-
-			if (write_file) {
-				printf("Writing frame %u to %s\n", dst_frame_num, filename.c_str());
-
-				for (unsigned i = 0; i < fb->num_planes(); ++i)
-					os->write((char*)fb->map(i), fb->size(i));
-
-				dst_frame_num++;
-			}
-
-			wbflipper.queue_next();
-		}
-
-		if (fds[2].revents) {
-			fds[2].revents = 0;
-
-			card.call_page_flip_handlers();
-			wb.Queue();
-		}
-	}
-
-	printf("exiting...\n");
-}
diff --git a/utils/omap-wbm2m.cpp b/utils/omap-wbm2m.cpp
deleted file mode 100644
index a00fab2..0000000
--- a/utils/omap-wbm2m.cpp
+++ /dev/null
@@ -1,200 +0,0 @@
-#include <cstdio>
-#include <poll.h>
-#include <unistd.h>
-#include <algorithm>
-#include <regex>
-#include <fstream>
-#include <map>
-#include <system_error>
-#include <fmt/format.h>
-
-#include <kms++/kms++.h>
-#include <kms++util/kms++util.h>
-#include <kms++util/videodevice.h>
-
-const uint32_t NUM_SRC_BUFS = 2;
-const uint32_t NUM_DST_BUFS = 2;
-
-using namespace std;
-using namespace kms;
-
-static const char* usage_str =
-	"Usage: wbm2m [OPTIONS]\n\n"
-	"Options:\n"
-	"  -f, --format=4CC          Output format\n"
-	"  -c, --crop=CROP           CROP is <x>,<y>-<w>x<h>\n"
-	"  -h, --help                Print this help\n";
-
-const int bar_speed = 4;
-const int bar_width = 10;
-
-static unsigned get_bar_pos(DumbFramebuffer* fb, unsigned frame_num)
-{
-	return (frame_num * bar_speed) % (fb->width() - bar_width + 1);
-}
-
-static void read_frame(DumbFramebuffer* fb, unsigned frame_num)
-{
-	static map<DumbFramebuffer*, int> s_bar_pos_map;
-
-	int old_pos = -1;
-	if (s_bar_pos_map.find(fb) != s_bar_pos_map.end())
-		old_pos = s_bar_pos_map[fb];
-
-	int pos = get_bar_pos(fb, frame_num);
-	draw_color_bar(*fb, old_pos, pos, bar_width);
-	draw_text(*fb, fb->width() / 2, 0, to_string(frame_num), RGB(255, 255, 255));
-	s_bar_pos_map[fb] = pos;
-}
-
-static void parse_crop(const string& crop_str, uint32_t& c_left, uint32_t& c_top,
-		       uint32_t& c_width, uint32_t& c_height)
-{
-	const regex crop_re("(\\d+),(\\d+)-(\\d+)x(\\d+)"); // 400,400-400x400
-
-	smatch sm;
-	if (!regex_match(crop_str, sm, crop_re))
-		EXIT("Failed to parse crop option '%s'", crop_str.c_str());
-
-	c_left = stoul(sm[1]);
-	c_top = stoul(sm[2]);
-	c_width = stoul(sm[3]);
-	c_height = stoul(sm[4]);
-}
-
-int main(int argc, char** argv)
-{
-	// XXX get from args
-	const uint32_t src_width = 800;
-	const uint32_t src_height = 480;
-	const auto src_fmt = PixelFormat::XRGB8888;
-	const uint32_t num_src_frames = 10;
-
-	const uint32_t dst_width = 800;
-	const uint32_t dst_height = 480;
-	uint32_t c_top, c_left, c_width, c_height;
-
-	auto dst_fmt = PixelFormat::XRGB8888;
-	bool use_selection = false;
-
-	OptionSet optionset = {
-		Option("f|format=", [&](string s) {
-			dst_fmt = FourCCToPixelFormat(s);
-		}),
-		Option("c|crop=", [&](string s) {
-			parse_crop(s, c_left, c_top, c_width, c_height);
-			use_selection = true;
-		}),
-		Option("h|help", [&]() {
-			puts(usage_str);
-			exit(-1);
-		}),
-	};
-
-	optionset.parse(argc, argv);
-
-	if (optionset.params().size() > 0) {
-		puts(usage_str);
-		exit(-1);
-	}
-
-	printf("%ux%u-%s -> %ux%u-%s\n", src_width, src_height, PixelFormatToFourCC(src_fmt).c_str(),
-	       dst_width, dst_height, PixelFormatToFourCC(dst_fmt).c_str());
-
-	const string filename = fmt::format("wb-out-{}x{}-{}.raw", dst_width, dst_height,
-					    PixelFormatToFourCC(dst_fmt));
-
-	printf("writing to %s\n", filename.c_str());
-
-	VideoDevice vid("/dev/video10");
-
-	Card card;
-
-	uint32_t src_frame_num = 0;
-	uint32_t dst_frame_num = 0;
-
-	VideoStreamer* out = vid.get_output_streamer();
-	VideoStreamer* in = vid.get_capture_streamer();
-
-	out->set_format(src_fmt, src_width, src_height);
-	in->set_format(dst_fmt, dst_width, dst_height);
-
-	if (use_selection) {
-		out->set_selection(c_left, c_top, c_width, c_height);
-		printf("crop -> %u,%u-%ux%u\n", c_left, c_top, c_width, c_height);
-	}
-
-	out->set_queue_size(NUM_SRC_BUFS);
-	in->set_queue_size(NUM_DST_BUFS);
-
-	for (unsigned i = 0; i < min(NUM_SRC_BUFS, num_src_frames); ++i) {
-		auto fb = new DumbFramebuffer(card, src_width, src_height, src_fmt);
-
-		read_frame(fb, src_frame_num++);
-
-		out->queue(fb);
-	}
-
-	for (unsigned i = 0; i < min(NUM_DST_BUFS, num_src_frames); ++i) {
-		auto fb = new DumbFramebuffer(card, dst_width, dst_height, dst_fmt);
-		in->queue(fb);
-	}
-
-	vector<pollfd> fds(3);
-
-	fds[0].fd = 0;
-	fds[0].events = POLLIN;
-	fds[1].fd = vid.fd();
-	fds[1].events = POLLIN;
-	fds[2].fd = card.fd();
-	fds[2].events = POLLIN;
-
-	ofstream os(filename, ofstream::binary);
-
-	out->stream_on();
-	in->stream_on();
-
-	while (true) {
-		int r = poll(fds.data(), fds.size(), -1);
-		ASSERT(r > 0);
-
-		if (fds[0].revents != 0)
-			break;
-
-		if (fds[1].revents) {
-			fds[1].revents = 0;
-
-			try {
-				DumbFramebuffer* dst_fb = in->dequeue();
-				printf("Writing frame %u\n", dst_frame_num);
-				for (unsigned i = 0; i < dst_fb->num_planes(); ++i)
-					os.write((char*)dst_fb->map(i), dst_fb->size(i));
-				in->queue(dst_fb);
-
-				dst_frame_num++;
-
-				if (dst_frame_num >= num_src_frames)
-					break;
-
-			} catch (system_error& se) {
-				if (se.code() != errc::resource_unavailable_try_again)
-					FAIL("dequeue failed: %s", se.what());
-
-				break;
-			}
-
-			DumbFramebuffer* src_fb = out->dequeue();
-
-			if (src_frame_num < num_src_frames) {
-				read_frame(src_fb, src_frame_num++);
-				out->queue(src_fb);
-			}
-		}
-
-		if (fds[2].revents) {
-			fds[2].revents = 0;
-		}
-	}
-
-	printf("exiting...\n");
-}
```

