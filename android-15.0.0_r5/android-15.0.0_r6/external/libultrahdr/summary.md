```
2188c35: bump to 1.2.0 (Ram Mohan M <ram.mohan@ittiam.com>)
3a0fb6d: fix build issues seen with option UHDR_BUILD_JAVA=1 (Ram Mohan <ram.mohan@ittiam.com>)
42c693d: Reuse applyGainMap GL textures if effects are to be applied (Vivek Jadhav <vivek.jadhav@ittiam.com>)
322ad93: add riscv64 compile support (Xeonacid <h.dwwwwww@gmail.com>)
2694e7a: Modify few default encoding configurations (Ram Mohan M <ram.mohan@ittiam.com>)
4a59171: enable support for odd dimensions for rgb inputs (Ram Mohan M <ram.mohan@ittiam.com>)
d1ab30c: Add apis to access primary and gainmap compressed data (Ram Mohan M <ram.mohan@ittiam.com>)
0a3812c: Revert "Reuse applyGainMap GL textures if effects are to be applied" (DichenZhang1 <140119224+DichenZhang1@users.norep...)
d267330: Reuse applyGainMap GL textures if effects are to be applied (Vivek Jadhav <vivek.jadhav@ittiam.com>)
89480db: fix lazy checking during subsample format determination (Ram Mohan M <ram.mohan@ittiam.com>)
f1f8f56: Add java sample application for libuhdr (Vivek Jadhav <vivek.jadhav@ittiam.com>)
7b05e7a: update static library name in MSVC builds (Ram Mohan M <ram.mohan@ittiam.com>)
cc8cfd2: check result of find_library() before progressing (Ram Mohan M <ram.mohan@ittiam.com>)
5d9e396: Insert comment marker in gainmap image (Ram Mohan M <ram.mohan@ittiam.com>)
68ce76a: fix issues in pc config file generation (Ram Mohan M <ram.mohan@ittiam.com>)
95e83fa: update README.md (Ram Mohan M <ram.mohan@ittiam.com>)
e162b20: Add some more recipes to CI workflow (Ram Mohan M <ram.mohan@ittiam.com>)
68eff3d: add support for static linking of applications (Ram Mohan M <ram.mohan@ittiam.com>)
f627105: Correct cmake minimum version required. (Ram Mohan M <ram.mohan@ittiam.com>)
9137f61: fix build warnings (Ram Mohan M <ram.mohan@ittiam.com>)
dcb9622: Improve error checking for encoding scenario - 2 (Ram Mohan M <ram.mohan@ittiam.com>)
83c868f: Add support for installing static library (Ram Mohan M <ram.mohan@ittiam.com>)
1adadec: Do not apply gamma correction if gamma is 1.0 (Ram Mohan M <ram.mohan@ittiam.com>)
3250b81: Update CMakeLists.txt (DichenZhang1 <140119224+DichenZhang1@users.norep...)
679d460: ubsan: fix misaligned address load (Ram Mohan M <ram.mohan@ittiam.com>)
8f37ecc: Update documentation of api interface (Ram Mohan M <ram.mohan@ittiam.com>)
19db8c2: Improve rgb input handling (Ram Mohan M <ram.mohan@ittiam.com>)
e393651: Add libultrahdr java wrapper (Ram Mohan M <ram.mohan@ittiam.com>)
390f2f1: add support for configuring min/max content boost (Ram Mohan M <ram.mohan@ittiam.com>)
bddf8da: Android.bp: Add editorhelper_gl.cpp (Harish Mahendrakar <hmahendrakar@google.com>)
4c56a21: Add gpu acceleration support for editor helper functions (Vivek Jadhav <vivek.jadhav@ittiam.com>)
d5a4786: Update documentation of api interface (Ram Mohan M <ram.mohan@ittiam.com>)
04788ce: Allow for larger excursions of min, max content boost (Ram Mohan M <ram.mohan@ittiam.com>)
4ef6913: cmake: add version to the shared library (spvkgn <spvkgn@users.noreply.github.com>)
5c7b3fb: Update ultrahdr_app.cpp (DichenZhang1 <140119224+DichenZhang1@users.norep...)
c747fde: Update ultrahdr_app.cpp (DichenZhang1 <140119224+DichenZhang1@users.norep...)
d587009: Update ultrahdr_app.cpp (DichenZhang1 <140119224+DichenZhang1@users.norep...)
d20756e: Update ultrahdr_app.cpp (DichenZhang1 <140119224+DichenZhang1@users.norep...)
ea72bc8: ossfuzz.sh: Opt out of shift sanitizer (Harish Mahendrakar <harish.mahendrakar@ittiam.co...)
322228a: Fix gainmap initializations in API-4 encoding (Harish Mahendrakar <harish.mahendrakar@ittiam.co...)
be737db: Update README.md with additional build recipes (Ram Mohan M <ram.mohan@ittiam.com>)
a5cf281: fix aosp/external/libultrahdr builds (Ram Mohan M <ram.mohan@ittiam.com>)
174d343: update pkg-config file with opengles dependencies (Ram Mohan M <ram.mohan@ittiam.com>)
4170548: Add support for configuring max dimension (Ram Mohan M <ram.mohan@ittiam.com>)
cc3436d: Bug fixing: for luminance calculation in tone mapping method (#229) (DichenZhang1 <140119224+DichenZhang1@users.norep...)
eb24ed2: API: change a parameter type from bool to int (Ram Mohan M <ram.mohan@ittiam.com>)
6a4b75c: Add upper limit to gainmap scale factor (Ram Mohan M <ram.mohan@ittiam.com>)
ae7be9b: Add missing validation checks for raw intents (Ram Mohan M <ram.mohan@ittiam.com>)
946d7ce: Add support for GPU acceleration of applygainmap (Aayush Soni <aayush.soni@ittiam.com>)
201ce6b: Improve encoder input argument validation (Ram Mohan M <ram.mohan@ittiam.com>)
0a9569b: Correct inverse oetf functions of sRGB and PQ (Ram Mohan M <ram.mohan@ittiam.com>)
224a831: Do not allow effects to be configured in running state (Ram Mohan M <ram.mohan@ittiam.com>)
c796784: Apply gamma correction while decoding multichannel gainmaps (Ram Mohan M <ram.mohan@ittiam.com>)
9b3853a: Update fuzzers for better code coverage (Vivek Jadhav <vivek.jadhav@ittiam.com>)
0d2cf83: fix data type of gamma getter/setter function (Ram Mohan M <ram.mohan@ittiam.com>)
e899aec: Add support for 444 subsampling format in uhdr encoder (Ram Mohan M <ram.mohan@ittiam.com>)
635a0b5: extend sample app for few more getter setter apis (Ram Mohan M <ram.mohan@ittiam.com>)
3ad7644: update sample application usage (Ram Mohan M <ram.mohan@ittiam.com>)
40cdfc6: Update ultrahdr_app.cpp (DichenZhang1 <140119224+DichenZhang1@users.norep...)
a921ed1: Update ultrahdr_app.cpp (DichenZhang1 <140119224+DichenZhang1@users.norep...)
629c850: Update gainmapmath.cpp (DichenZhang1 <140119224+DichenZhang1@users.norep...)
3e302fb: use separate field to store configured gainmap gamma (Ram Mohan M <ram.mohan@ittiam.com>)
6fe2431: Add -fno-lax-vector-conversions for Arm builds (George Steed <george.steed@arm.com>)
c0c1845: Add gamma support in command line tool (Dichen Zhang <dichenzhang@google.com>)
2e3b248: add support for iso metadata parsing in probe path (Ram Mohan M <ram.mohan@ittiam.com>)
df2e9f2: enable benchmark tests for generate and applygain map (Ram Mohan M <ram.mohan@ittiam.com>)
260b255: fix android cross compilation build with logs enabled (Ram Mohan M <ram.mohan@ittiam.com>)
4253dab: Enable convertYuv_neon in 32bit builds (Harish Mahendrakar <hmahendrakar@google.com>)
37539f3: Add round factor during float to int conversion (Ram Mohan M <ram.mohan@ittiam.com>)
e78a04a: clamp output of gamut conversion to limit bounds (Ram Mohan M <ram.mohan@ittiam.com>)
a5f9569: Fix color hue shifting for encode API-0 (Dichen Zhang <dichenzhang@google.com>)
32cd68b: Add setup code for opengl acceleration (Vivek Jadhav <vivek.jadhav@ittiam.com>)
319512b: Fix build for 32-bit Arm (George Steed <george.steed@arm.com>)
f4529f2: Refactor vector creation with a single generalized function (Vivek Jadhav <vivek.jadhav@ittiam.com>)
ff415fc:  Fixed compiling ARM64 target for Windows (MajorMurphy <major@murphyindustries.net>)
f1ca340: fix incorrect row step configuration in generateGainMap job queue (Ram Mohan M <ram.mohan@ittiam.com>)
8fc6543: Refactoring, move reusable code to common (Ram Mohan M <ram.mohan@ittiam.com>)
0abd869: Add full color range support in the demo app (Dichen Zhang <dichenzhang@google.com>)
a6e7b32: Updates towards 4ab sub-sampling format support (Ram Mohan M <ram.mohan@ittiam.com>)
aad9408: Modify transfer functions in tone map method (#183) (DichenZhang1 <140119224+DichenZhang1@users.norep...)
c9c8c74: Update library to use definitions of ultrahdr_api everywhere (Ram Mohan M <ram.mohan@ittiam.com>)
fb3fb13: Update error checks for newly advertised encoder options (Ram Mohan M <ram.mohan@ittiam.com>)
e9932b3: Add error checks for color range field (Ram Mohan M <ram.mohan@ittiam.com>)
2ca4b5b: API: change a parameter type from bool to int (Daniel Bermond <danielbermond@gmail.com>)
277808a: Expose editing methods to ultrahdr_api.h (#173) (DichenZhang1 <140119224+DichenZhang1@users.norep...)
56b3e49: Fixing bug in command line tool (#171) (DichenZhang1 <140119224+DichenZhang1@users.norep...)
292759f: Support gamma in gain map metadata (#170) (DichenZhang1 <140119224+DichenZhang1@users.norep...)
073d5c7: Release knobs from users' input (Dichen Zhang <dichenzhang@google.com>)
209f3bc: Update jpegr.cpp (DichenZhang1 <140119224+DichenZhang1@users.norep...)
534abd9: Further optimize tone map (DichenZhang1 <140119224+DichenZhang1@users.norep...)
5d77edd: App change: supports full-range color for HDR input (Dichen Zhang <dichenzhang@google.com>)
cf7f5fd: Signal stride in pixel denomination and not bytes (Ram Mohan M <ram.mohan@ittiam.com>)
5be22fd: App change: supports full-range color for HDR input (Dichen Zhang <dichenzhang@google.com>)
253fbbf: Supported full-range color for HDR input (Dichen Zhang <dichenzhang@google.com>)
```

