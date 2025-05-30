```
65998fec: removed lz4c target (Yann Collet <cyan@fb.com>)
36df905a: update API and man page documentation for v1.10 (Yann Collet <cyan@fb.com>)
de6531b4: fixed minor conversion warning (Yann Collet <cyan@fb.com>)
8ce9e94c: improved lorem ipsum generator speed by a factor > x8 (Yann Collet <cyan@fb.com>)
2a1de078: improved speed of lorem ipsum generator (Yann Collet <cyan@fb.com>)
cc1508f5: more correct extDict detection (Yann Collet <cyan@fb.com>)
2ea0373b: level 2 compatibility with LZ4F dictionary compression (Yann Collet <cyan@fb.com>)
21837b96: fixed traces (Yann Collet <cyan@fb.com>)
d31aaac2: Level 2 is now compatible with dictionary attach mode (Yann Collet <cyan@fb.com>)
be35b7c5: minor documentation edit (Yann Collet <cyan@fb.com>)
1b12a151: fix minor conversion warning (Yann Collet <cyan@fb.com>)
f458b2b1: LZ4_loadDictHC is compatible with LZ4MID level 2 (Yann Collet <cyan@fb.com>)
7480aeed: added a dictionary loader dedicated to level 2 (LZ4MID) (Yann Collet <cyan@fb.com>)
33c62fa6: promote LZ4_attach_HC_dictionary() to stable (Yann Collet <cyan@fb.com>)
08bfdbe2: update changelog for v1.10 (Yann Collet <cyan@fb.com>)
0642ae2f: minor: document version for new entry point (Yann Collet <cyan@fb.com>)
089210b0: added CODING_STYLE documentation (Yann Collet <cyan@fb.com>)
4f88c7a4: exit on invalid frame (Yann Collet <cyan@fb.com>)
6d4d56e8: added runtime tests for binary produced by generated Visual solution (Yann Collet <cyan@fb.com>)
f8432bf8: removed problematic v140 version test (Yann Collet <cyan@fb.com>)
814d9bea: fix VS2022 directory for appveyor (Yann Collet <cyan@fb.com>)
4cc04310: remove Visual Solutions (Yann Collet <cyan@fb.com>)
a2a21bc7: removed failing tests (Yann Collet <cyan@fb.com>)
8017ca0e: add documentation about decompression side (Yann Collet <cyan@fb.com>)
9b72ddfa: removed failing tests (Yann Collet <cyan@fb.com>)
4f25e37a: --list automatically triggers -m (Yann Collet <cyan@fb.com>)
397d6846: Bump github/codeql-action from 3.25.11 to 3.25.12 (dependabot[bot] <49699333+dependabot[bot]@users....)
aa6a7483: Bump actions/setup-python from 5.1.0 to 5.1.1 (dependabot[bot] <49699333+dependabot[bot]@users....)
42a43c55: promote LZ4 dictionary API to stable (Yann Collet <cyan@fb.com>)
0990811a: promote LZ4F dictionary API to stable (Yann Collet <cyan@fb.com>)
2db419ee: removed implicit stdout (Yann Collet <cyan@fb.com>)
b20025fd: minor readability refactor for version extraction logic (Yann Collet <cyan@fb.com>)
f76c979f: add lz4file.h to include list (Yann Collet <cyan@fb.com>)
e5563ea2: update logic that determines LZ4_BUNDLED_MODE (Yann Collet <cyan@fb.com>)
6ce6e6da: improved logic to extract version number (Yann Collet <cyan@fb.com>)
b5139c79: do not test gcc/clang flags when building for visual (Yann Collet <cyan@fb.com>)
32c05eef: export the generated VS2022 solution as artifact (Yann Collet <cyan@fb.com>)
75391bdf: added test for script generating solution on GH (Yann Collet <cyan@fb.com>)
d2f2e186: fixed VS2017 build script (Yann Collet <cyan@fb.com>)
fae5a66b: provided scripts for other versions of Visual (2015+) (Yann Collet <cyan@fb.com>)
c292e7da: test some scripts to generate visual solutions on Windows (Yann Collet <cyan@fb.com>)
aafb56ee: update gpl license to 2.0-or-later (Yann Collet <cyan@fb.com>)
7aaf095d: disable multithreading when compiling for m68k (Yann Collet <cyan@fb.com>)
e36fadfd: support multithreading for linked blocks with dictionary (Yann Collet <cyan@fb.com>)
b3dd37f7: fix leak issue (Yann Collet <cyan@fb.com>)
ed4d7d19: Linked Blocks compression (-BD) can employ multiple threads (Yann Collet <cyan@fb.com>)
c78899a3: add support for environment variable LZ4_CLEVEL (Yann Collet <cyan@fb.com>)
c0e43059: Bump actions/upload-artifact from 4.3.3 to 4.3.4 (dependabot[bot] <49699333+dependabot[bot]@users....)
461881cf: fixed c90 compliance (Yann Collet <cyan@fb.com>)
461f3697: automatically enable multithreading by default on Windows (Yann Collet <cyan@fb.com>)
32f7fd3f: minor completion port update (Yann Collet <yann.collet.73@gmail.com>)
cfdb8ac6: completion ports: minor readability refactor (Yann Collet <yann.collet.73@gmail.com>)
c688b4bd: updated threadpool API (Yann Collet <yann.collet.73@gmail.com>)
50d541f9: simpler execution expression (Yann Collet <yann.collet.73@gmail.com>)
f0b29a97: updated completion ports logic (Yann Collet <yann.collet.73@gmail.com>)
1dc60aa1: minor: removed one variable (Yann Collet <yann.collet.73@gmail.com>)
5301a75c: fix cpuload measurements on Windows (Yann Collet <yann.collet.73@gmail.com>)
7ec8526d: build: minor: fix lz4 project in VS2017 solution (Yann Collet <cyan@fb.com>)
b7b0ee0a: Add MT control via Environment variable LZ4_NBWORKERS (Yann Collet <cyan@fb.com>)
8dd837fd: document LZ4_NBWORKERS_MAX (Yann Collet <yann.collet.73@gmail.com>)
718d1dca: warning message when nbThreads above limit (Yann Collet <yann.collet.73@gmail.com>)
79e72bee: minor optimization: allocate worker array at runtime (Yann Collet <yann.collet.73@gmail.com>)
04341f19: changed Makefile variable HAVE_THREAD -> HAVE_MULTITHREAD (Yann Collet <yann.collet.73@gmail.com>)
b5639ade: fixed Visual Studio type warning (Yann Collet <yann.collet.73@gmail.com>)
71ef5b72: Makefile: automatic MT detection under native msys2/mingw64 (Yann Collet <yann.collet.73@gmail.com>)
10cc4e38: fix C90 comment style (Yann Collet <yann.collet.73@gmail.com>)
604122c8: Makefile build automatically detect multithreading for Windows (Yann Collet <yann.collet.73@gmail.com>)
425cd51a: count nb cores on Windows (Yann Collet <yann.collet.73@gmail.com>)
c7fd52ae: fixed queue size control (Yann Collet <yann.collet.73@gmail.com>)
3628163d: minor: Semaphore init value (Yann Collet <yann.collet.73@gmail.com>)
097f0fba: minor parameter sanitization (Yann Collet <yann.collet.73@gmail.com>)
b4e37088: queueLock no longer required (Yann Collet <yann.collet.73@gmail.com>)
7183fe9e: minor simplification (Yann Collet <yann.collet.73@gmail.com>)
9443ed93: working implementation of completionPorts (Yann Collet <cyan@fb.com>)
04374588: fixed tsan warnings (Yann Collet <cyan@fb.com>)
c379947b: fix pedantic warning (Yann Collet <cyan@fb.com>)
2e867a5a: fix comments for C90 strict compatibility (Yann Collet <cyan@fb.com>)
7b4e8048: fix minor cast warnings related to -Wc++-compat (Yann Collet <cyan@fb.com>)
e9b89073: optimize asyncio parameters (Yann Collet <cyan@fb.com>)
091ec262: implemented ayncio for lz4f decompression (Yann Collet <cyan@fb.com>)
06ce31e7: add status update when decompressing legacy frames (Yann Collet <cyan@fb.com>)
03b1a996: Bump github/codeql-action from 3.25.1 to 3.25.11 (dependabot[bot] <49699333+dependabot[bot]@users....)
0501c0f4: Bump actions/checkout from 4.1.6 to 4.1.7 (dependabot[bot] <49699333+dependabot[bot]@users....)
2a7cb520: Update CMake tests to verify that the unified target always exists. (Theodore Tsirpanis <theodore.tsirpanis@tiledb.co...)
e554fde0: removed FreeBSD 13.2 test from Cirrus CI (Yann Collet <cyan@fb.com>)
e8a09f05: Fix lib32gcc versions for clang and clang-{8,9,10} (t-mat <t-mat@users.noreply.github.com>)
5d4a42f8: Fix for gh-actions breaking change (t-mat <t-mat@users.noreply.github.com>)
5b2af938: Bump actions/checkout from 4.1.5 to 4.1.6 (dependabot[bot] <49699333+dependabot[bot]@users....)
6aedc236: [cmake] Always create lz4 target. (Theodore Tsirpanis <theodore.tsirpanis@tiledb.co...)
a5a46f16: Bump ossf/scorecard-action from 2.3.1 to 2.3.3 (dependabot[bot] <49699333+dependabot[bot]@users....)
15e2f10f: Bump actions/checkout from 4.1.4 to 4.1.5 (dependabot[bot] <49699333+dependabot[bot]@users....)
bdc8e14e: [cmake]: just a minor refactor of the symlink installation paragraph (Yann Collet <cyan@fb.com>)
db10b08f: len should be unsigned (Rose <gfunni234@gmail.com>)
642f6b8f: Prefer OR over ADD for splicing numbers from byte-addressed memory (Rose <gfunni234@gmail.com>)
7f042fc1: Define mlen = MINMATCH at the start of the loop (Rose <gfunni234@gmail.com>)
9838a0de: Update function comment (Nicolas <nikodecarli@gmail.com>)
ae585f77: Bump actions/upload-artifact from 4.3.2 to 4.3.3 (dependabot[bot] <49699333+dependabot[bot]@users....)
6428f91f: Bump actions/checkout from 4.1.3 to 4.1.4 (dependabot[bot] <49699333+dependabot[bot]@users....)
ba744bd1: CMake: Separate symlinks creation and installation (ur4t <46435411+ur4t@users.noreply.github.com>)
fb301fa7: Bump github/codeql-action from 3.24.9 to 3.25.1 (dependabot[bot] <49699333+dependabot[bot]@users....)
7789c917: Bump actions/upload-artifact from 4.3.1 to 4.3.2 (dependabot[bot] <49699333+dependabot[bot]@users....)
667c5b18: Bump actions/checkout from 4.1.2 to 4.1.3 (dependabot[bot] <49699333+dependabot[bot]@users....)
1a5b83b8: benchmark results are displayed to stdout (Yann Collet <yann.collet.73@gmail.com>)
3cd6d011: Bump actions/setup-python from 5.0.0 to 5.1.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
5b44fd1e: Fix typo `libzstd` -> `liblz4` (t-mat <t-mat@users.noreply.github.com>)
993e77f2: Fix: 25 typos (RoboSchmied <github@roboschmie.de>)
58c3e9dc: Suppress VS2022 warnings (Jon Rumsey <jrumsey@uk.ibm.com>)
e1ccdfcd: Bump github/codeql-action from 3.24.7 to 3.24.9 (dependabot[bot] <49699333+dependabot[bot]@users....)
643a51ca: minor: assert successful context creation (Yann Collet <yann.collet.73@gmail.com>)
fab30686: add test for bug #1374 (Yann Collet <yann.collet.73@gmail.com>)
e50a8941: fix #1374 (Yann Collet <yann.collet.73@gmail.com>)
fc0943e7: Bump actions/checkout from 4.1.1 to 4.1.2 (dependabot[bot] <49699333+dependabot[bot]@users....)
d8f0e869: Bump github/codeql-action from 3.24.6 to 3.24.7 (dependabot[bot] <49699333+dependabot[bot]@users....)
6b88d0a3: fix to please C++ compiler (Yann Collet <cyan@fb.com>)
32336000: minor: keep old single-thread code (Yann Collet <cyan@fb.com>)
7a1b7050: fix variable LZ4IO_MULTITHREAD (Yann Collet <cyan@fb.com>)
43ae8c85: first implementation of async io for decoder (Yann Collet <cyan@fb.com>)
e0410ac4: reorganize mt code (Yann Collet <cyan@fb.com>)
56e80abb: Fix typo (Andreas Deininger <andreas@deininger.net>)
a1b741e8: Bump github/codeql-action from 3.24.3 to 3.24.6 (dependabot[bot] <49699333+dependabot[bot]@users....)
e5207e0c: Add unified CMake target if building only a shared or a statric library. (Theodore Tsirpanis <theodore.tsirpanis@tiledb.co...)
be8a4f65: Added preprocessor checks for Clang on Windows (Razakhel <romain.milbert@gmail.com>)
ed372363: minor: fix missing include (Yann Collet <cyan@fb.com>)
1de550fc: fixed minor conversion warnings (Yann Collet <cyan@fb.com>)
718fe2a8: updated lorem ipsum generator (Yann Collet <cyan@fb.com>)
1fa72668: Bump github/codeql-action from 3.24.0 to 3.24.3 (dependabot[bot] <49699333+dependabot[bot]@users....)
6423a733: Bump actions/upload-artifact from 4.3.0 to 4.3.1 (dependabot[bot] <49699333+dependabot[bot]@users....)
d6765765: fix incorrect assert (Yann Collet <cyan@fb.com>)
80b7db04: fix overly cautious static analyzer warning (Yann Collet <cyan@fb.com>)
9712d319: fix inaccurate address overflow condition (Yann Collet <cyan@fb.com>)
5ccd3347: fix out-of-limit match in level 2 (Yann Collet <cyan@fb.com>)
0abb17fd: fix back limit bug (Yann Collet <cyan@fb.com>)
cc0f2875: fix minor sign comparison warning (Yann Collet <cyan@fb.com>)
9e8649ef: removed assert always true (Yann Collet <cyan@fb.com>)
ad204dc0: fix "source has 2 buffers" for level 2 (Yann Collet <cyan@fb.com>)
bde614d8: fix dictionary support for level 2 (Yann Collet <cyan@fb.com>)
65ee88f1: fix _destSize() variant for level 2 (Yann Collet <cyan@fb.com>)
5a2516c2: made hash8Ptr compatible with big-endian systems (Yann Collet <cyan@fb.com>)
3dc0cafe: minor refactor, for clarity (Yann Collet <cyan@fb.com>)
7d304b5c: fill table more (Yann Collet <cyan@fb.com>)
67745512: skip over incompressible data (Yann Collet <cyan@fb.com>)
80026581: long matches look for 7 bytes (Yann Collet <cyan@fb.com>)
15ed8113: fix the hash8 formula (Yann Collet <cyan@fb.com>)
10921d86: another minor compression improvement for level 2 (Yann Collet <cyan@fb.com>)
3116d85d: slightly improved compression ratio of level 2 (Yann Collet <cyan@fb.com>)
ee866310: first implementation of level2 (Yann Collet <cyan@fb.com>)
75c9df73: Bump github/codeql-action from 3.23.2 to 3.24.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
372ce8ec: switch sparc test to ubuntu-20 (Yann Collet <cyan@fb.com>)
1a39244a: add sparc compilation test (Yann Collet <cyan@fb.com>)
95cb4da7: minor: lower literal range (Yann Collet <cyan@fb.com>)
e0cfe3eb: C90 comment style (Yann Collet <cyan@fb.com>)
f8a0a37c: improve LZ4F dictionary compression in fast mode (Yann Collet <cyan@fb.com>)
10ac725c: fix init for dictionary compression in HC streaming mode (Yann Collet <cyan@fb.com>)
b108debe: Bump github/codeql-action from 3.23.0 to 3.23.2 (dependabot[bot] <49699333+dependabot[bot]@users....)
72c1d520: Bump actions/upload-artifact from 4.2.0 to 4.3.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
ef7baa60: fixed visual studio solution (Yann Collet <cyan@fb.com>)
93a905ca: removed COMPRESSIBILITY_DEFAULT (Yann Collet <cyan@fb.com>)
72be5173: fixed meson build (Yann Collet <cyan@fb.com>)
0bac9ab8: fixed visual studio projects (Yann Collet <cyan@fb.com>)
47ffbfd6: finish generation with a newline character (Yann Collet <cyan@fb.com>)
65362838: datagen uses lorem ipsum generator by default (Yann Collet <cyan@fb.com>)
5f9a5c61: fix meson recipe (Yann Collet <cyan@fb.com>)
69d708dd: fixed minor unused variable (Yann Collet <cyan@fb.com>)
1511ec68: made lorem slightly less compressible (Yann Collet <cyan@fb.com>)
e6791b2d: fix a very picky visual studio warning (Yann Collet <cyan@fb.com>)
0a1499fb: fixed meson formula (Yann Collet <cyan@fb.com>)
dac61f75: fixed Visual Studio solutions (Yann Collet <cyan@fb.com>)
d3b5fe93: minor optimization (Yann Collet <cyan@fb.com>)
5bc39192: fix minor static analyzer warning (Yann Collet <cyan@fb.com>)
73dd539a: minor optimizations (Yann Collet <cyan@fb.com>)
823d37f7: bench.c does not longer need datagen (Yann Collet <cyan@fb.com>)
f9eb2666: added a lorem ipsum generator (Yann Collet <cyan@fb.com>)
87ad5e8a: Fix Python 3.6 string interpolation (Like Ma <likemartinma@gmail.com>)
34c22c9a: Bump actions/upload-artifact from 4.1.0 to 4.2.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
540b5399: change INSTALL_DIR into MAKE_DIR (Yann Collet <cyan@fb.com>)
a3934332: Bump actions/upload-artifact from 4.0.0 to 4.1.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
f484041c: Bump github/codeql-action from 3.22.12 to 3.23.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
1230f1ca: regrouped all compile-time variables into programs/lz4conf.h (Yann Collet <cyan@fb.com>)
d61b4f1f: LZ4IO_MULTITHREADING can be forcefully disabled at compile time (Yann Collet <cyan@fb.com>)
0d57b826: Build variable LZ4_NBTHREADS_DEFAULT (Yann Collet <cyan@fb.com>)
15c30728: update Github Actions tests (Yann Collet <cyan@fb.com>)
330b9beb: update cirrus CI FreeBSD tests (Yann Collet <cyan@fb.com>)
112c788c: added tsan tests (Yann Collet <cyan@fb.com>)
f4d9a942: added msan tests to Github Actions (Yann Collet <cyan@fb.com>)
196e7dbb: minor optimization: only create thread pools if needed (Yann Collet <yann.collet.73@gmail.com>)
1e4dce4d: minor optimization : share thread pools (Yann Collet <yann.collet.73@gmail.com>)
38f605f3: adjust tests for more parallelism (Yann Collet <cyan@fb.com>)
312693ba: fixed potential leak scenario detected by @t-mat (Yann Collet <cyan@fb.com>)
bde2e95d: fixed initialization issue (Yann Collet <cyan@fb.com>)
f3860a1f: sequential test, for easier debugging (Yann Collet <cyan@fb.com>)
93a1bc6b: fix leak when input is an exact multiple of job size (Yann Collet <cyan@fb.com>)
12866666: fix potential leak after failure in legacy format (Yann Collet <cyan@fb.com>)
6a3932d1: make file open errors recoverable in legacy mode (Yann Collet <cyan@fb.com>)
8e114d9b: fix MT compatibility with dictionaries (Yann Collet <cyan@fb.com>)
e9e9beb6: manually select single-thread path with -T1 (Yann Collet <cyan@fb.com>)
1f43e4d1: updated manuals (Yann Collet <cyan@fb.com>)
0dfbe965: report nb of threads in verbose mode (Yann Collet <yann.collet.73@gmail.com>)
132c2149: removed left-over trace (Yann Collet <yann.collet.73@gmail.com>)
88faa801: second attempt at fixing mingw32 (Yann Collet <yann.collet.73@gmail.com>)
34e9895c: fixed MT incompatibility with --content-size (Yann Collet <yann.collet.73@gmail.com>)
b45de8b4: attempt to fix mingw32 compilation issues (Yann Collet <yann.collet.73@gmail.com>)
2b232605: removed cancelled declaration (Yann Collet <yann.collet.73@gmail.com>)
3bdaad35: silence some clang x32 test (Yann Collet <cyan@fb.com>)
d7c82ffe: fixed a few Visual Studio Static Analyzer warnings (Yann Collet <cyan@fb.com>)
e1350f86: make visual compilation test on appveyor less permissive (Yann Collet <cyan@fb.com>)
3227a552: added a simple test for MT CLI commands (Yann Collet <cyan@fb.com>)
ef6442b5: fix minor static analyzer warnings (Yann Collet <cyan@fb.com>)
f376a90e: fix VS2022 solution (Yann Collet <cyan@fb.com>)
5fb1bd23: fix VS2010 solution (Yann Collet <cyan@fb.com>)
a2d5ce40: fix standard_variables test (Yann Collet <cyan@fb.com>)
4333be50: fix minor static analysis initialization warning (Yann Collet <cyan@fb.com>)
c6762ec1: fixed meson build (Yann Collet <yann.collet.73@gmail.com>)
db7495d0: fix another C90 pedantic warning (Yann Collet <cyan@fb.com>)
ee38a870: fixed several minor pedantic conversion warnings (Yann Collet <cyan@fb.com>)
94496a90: fix pedantic C90 compatibility warnings (Yann Collet <cyan@fb.com>)
bd477566: lz4io: verbose compress/decompress operations display a summary (Yann Collet <cyan@fb.com>)
a49ca221: fix cmake recipe (Yann Collet <cyan@fb.com>)
ca2e1060: fix minor conversion warnings (Yann Collet <cyan@fb.com>)
39845fab: fix minor unused assignment (Yann Collet <cyan@fb.com>)
d169286a: fixed minor conversion warnings (Yann Collet <cyan@fb.com>)
4984c7fd: updated Welcome message to specify if binary support multithreading or n... (Yann Collet <cyan@fb.com>)
cbe7211b: make: fix lz4 mt compilation on linux/posix (Yann Collet <yann.collet.73@gmail.com>)
d3ae8e0e: fix numCores detection on Linux (Yann Collet <cyan@fb.com>)
f4dda829: fix minor comparator warning (Yann Collet <cyan@fb.com>)
da5e8b7b: lz4frame: new API: LZ4F_compressBegin_usingDict() (Yann Collet <cyan@fb.com>)
fd5f76d7: minor traces upgrades (Yann Collet <cyan@fb.com>)
fc6029f8: preparation to support linked blocks (Yann Collet <cyan@fb.com>)
e58a06d1: fixed smaller block sizes (Yann Collet <cyan@fb.com>)
95c2bc7f: fix legacy format compression (Yann Collet <cyan@fb.com>)
d4c21a4d: fixed stdin support (Yann Collet <cyan@fb.com>)
815f3550: fix frame checksum in MT mode (Yann Collet <cyan@fb.com>)
3acabda1: multithreading works with lz4f format, but (Yann Collet <cyan@fb.com>)
610baf14: more generic read and write jobs (Yann Collet <cyan@fb.com>)
553962bd: better time measurement and reportin (Yann Collet <cyan@fb.com>)
127fa578: control over nbThreads (Yann Collet <cyan@fb.com>)
8a1c8aa3: first implementation, for compression of legacy format (Yann Collet <cyan@fb.com>)
b239d6af: added a simple (untested) threadpool implementation (Yann Collet <cyan@fb.com>)
88e477db: fix 1308 (Yann Collet <cyan@fb.com>)
af08a062: clarify man page on lz4 CLI being single threaded. (Yann Collet <cyan@fb.com>)
3f1eb79f: Appveyor: Visual: faster compilation for compilation-only tests (Yann Collet <cyan@fb.com>)
efd7029a: create local_LZ4_decompress_safe() to circumvent dllimport warning (Yann Collet <cyan@fb.com>)
467db788: make arrays static (Yann Collet <cyan@fb.com>)
f239a17a: fix read when requesting out-of-range codec (Yann Collet <cyan@fb.com>)
ded75e76: fixed minor conversion warning (Yann Collet <cyan@fb.com>)
4c5858e6: make appveyor ci tests faster (Yann Collet <cyan@fb.com>)
a03e877b: fullbench: -i0 runs a very fast (but still measured) run (Yann Collet <cyan@fb.com>)
f5d14ab9: can list algorithms to benchmark (Yann Collet <cyan@fb.com>)
df3b602a: array for benched compressors (Yann Collet <cyan@fb.com>)
fde31574: fullbench: record benched decompressors into a C90 array (Yann Collet <cyan@fb.com>)
2109153d: reduce appveyor CI test duration (Yann Collet <cyan@fb.com>)
16f33b17: Bump github/codeql-action from 3.22.11 to 3.22.12 (dependabot[bot] <49699333+dependabot[bot]@users....)
a37a62f5: update ossfuzz test time (Yann Collet <cyan@fb.com>)
a0abf19e: fixed -j for versionsTest (Yann Collet <yann.collet.73@gmail.com>)
f91702fb: use make -j more often for CI (Yann Collet <cyan@fb.com>)
5e663b90: refactor C++ tests (Yann Collet <cyan@fb.com>)
5c9e349c: changed test name cpp->cxx (Yann Collet <cyan@fb.com>)
e2e8d9b0: rename USERCFLAGS for consistency (Yann Collet <cyan@fb.com>)
dd7e9991: rename variable LIBDIR for consistency (Yann Collet <cyan@fb.com>)
fc25339a: rename variable to LIBDIR for consistency (Yann Collet <cyan@fb.com>)
631cd0f6: minor adjustments for examples/Makefile (Yann Collet <cyan@fb.com>)
7b7cecd1: fix attempt for ppc64 test on circleci (Yann Collet <yann.collet.73@gmail.com>)
cecb7f04: versionsTest: pass variables via MOREFLAGS (Yann Collet <yann.collet.73@gmail.com>)
669e2559: add traces to versionsTest (Yann Collet <cyan@fb.com>)
736bcf76: minor CI adjustments (Yann Collet <cyan@fb.com>)
098a987d: fix circleci tests (Yann Collet <cyan@fb.com>)
6bdfc56c: fix minor conversion warnings on macos (Yann Collet <cyan@fb.com>)
48db0b23: abiTests fixes (Yann Collet <yann.collet.73@gmail.com>)
a467d7eb: abiTest : add more traces and messages (Yann Collet <cyan@fb.com>)
63e73c15: adding traces to abiTest to better observe potential issues (Yann Collet <cyan@fb.com>)
bbe41f40: attempt to fix abi Test (Yann Collet <cyan@fb.com>)
6b5f5662: adjust speed python test (Yann Collet <cyan@fb.com>)
1ec11b1b: adjust appveyor windows test (Yann Collet <cyan@fb.com>)
e760561c: adjust test-lz4-speed for absence of MOREFLAGS (Yann Collet <cyan@fb.com>)
6beb1a6b: adjust appveyor tests for absence of MOREFLAGS (Yann Collet <cyan@fb.com>)
968134d6: adjust Github Actions tests for absence of MOREFLAGS (Yann Collet <cyan@fb.com>)
da955d71: streamlines tests/Makefile clean logic (Yann Collet <cyan@fb.com>)
c952eafb: centralized clean logic for lib/Makefile (Yann Collet <cyan@fb.com>)
fe18314d: more thorough target classification for programs/Makefile (Yann Collet <cyan@fb.com>)
854d13a1: fix uninitialized memory (Yann Collet <cyan@fb.com>)
6b9fc5fe: minor: C90 comment style (Yann Collet <cyan@fb.com>)
863cf7cb: streamline free logic (Yann Collet <cyan@fb.com>)
00ad605b: lz4file API returns more accurate error codes (Yann Collet <cyan@fb.com>)
06b22878: very minor conversion warning fix (Yann Collet <cyan@fb.com>)
4e8788ed: ensure make install target doesn't create files (Yann Collet <cyan@fb.com>)
dc474bd8: fix minor conversion warnings (Yann Collet <cyan@fb.com>)
38b7377b: refactor appveyor.yml (Yann Collet <cyan@fb.com>)
167623d7: Bump actions/upload-artifact from 3.1.3 to 4.0.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
675be982: Bump github/codeql-action from 2.22.9 to 3.22.11 (dependabot[bot] <49699333+dependabot[bot]@users....)
cd7ce04a: missing clean target (Yann Collet <cyan@fb.com>)
e2cb69c7: SED can be defined on command line and with environment variables (Yann Collet <cyan@fb.com>)
e52a8264: link final binary rather than copy (Yann Collet <cyan@fb.com>)
a86d5c81: avoid accidental redefinition of LZ4_STATIC_LINKING_ONLY (Yann Collet <cyan@fb.com>)
acf06f1c: Bump actions/setup-python from 4.7.1 to 5.0.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
b6eef8da: Bump github/codeql-action from 2.22.8 to 2.22.9 (dependabot[bot] <49699333+dependabot[bot]@users....)
a2e4da3e: updated code documentation (Yann Collet <cyan@fb.com>)
629ba802: decomp: refine read_variable_length codegen layout (Jun He <jun.he@arm.com>)
d09975f3: Bump github/codeql-action from 2.22.5 to 2.22.8 (dependabot[bot] <49699333+dependabot[bot]@users....)
ee25fc28: Add LZ4_compress_fast_extState_destSize() API (Tristan Partin <tristan@partin.io>)
aa9c54ec: Bump ossf/scorecard-action from 2.3.0 to 2.3.1 (dependabot[bot] <49699333+dependabot[bot]@users....)
d9ed2c06: Bump github/codeql-action from 2.22.4 to 2.22.5 (dependabot[bot] <49699333+dependabot[bot]@users....)
84a1e9c2: lz4: remove unnecessary check of ip (Jun He <jun.he@arm.com>)
9c7c87d8: Bump actions/checkout from 4.1.0 to 4.1.1 (dependabot[bot] <49699333+dependabot[bot]@users....)
64b7f0b7: Bump github/codeql-action from 2.22.3 to 2.22.4 (dependabot[bot] <49699333+dependabot[bot]@users....)
0e4b22dd: updated NEWS and raised version number (Yann Collet <cyan@fb.com>)
212da692: Fix compiler preprocessor (hamlin <hamlin@hamlin.eu.rivosinc.com>)
8de247b2: added new qemu targets for CI (MIPS, M68K, RISC-V) (Yann Collet <cyan@fb.com>)
39734d2f: Enable basic support on riscv64 (hamlin <hamlin@hamlin.eu.rivosinc.com>)
9fa9bf26: Add null pointer check before `FREEMEM()` (LocalSpook <56512186+LocalSpook@users.noreply.gi...)
3743fcf2: Bump github/codeql-action from 2.22.0 to 2.22.3 (dependabot[bot] <49699333+dependabot[bot]@users....)
f99c4382: Use `-Wpedantic` instead of `-pedantic` (LocalSpook <56512186+LocalSpook@users.noreply.gi...)
7c50ac99: fix: fix PR #1286 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
e270f2ed: Make Makefile version number parsing more robust (LocalSpook <56512186+LocalSpook@users.noreply.gi...)
b389bbf5: Make Meson version number parsing more robust (LocalSpook <56512186+LocalSpook@users.noreply.gi...)
47daa7ef: Make CMake version number parsing more robust (LocalSpook <56512186+LocalSpook@users.noreply.gi...)
86e43fd2: Ignore Visual Studio Code files in `.gitignore` (LocalSpook <56512186+LocalSpook@users.noreply.gi...)
0f432974: Introduce `.clang-format` rule file (LocalSpook <56512186+LocalSpook@users.noreply.gi...)
2acec864: add: cmake static lib test (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
5ba4803d: chore: suppress warning C6385 for MSVC 17.7 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
952c5031: Bump ossf/scorecard-action from 2.2.0 to 2.3.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
0ea32573: Bump actions/setup-python from 4.7.0 to 4.7.1 (dependabot[bot] <49699333+dependabot[bot]@users....)
496eb37f: Bump github/codeql-action from 2.21.9 to 2.22.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
e92efba7: fix: issue #1269 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
42c95e92: Bump actions/checkout from 4.0.0 to 4.1.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
0b7dc8bb: Bump github/codeql-action from 2.21.7 to 2.21.9 (dependabot[bot] <49699333+dependabot[bot]@users....)
21600596: Add Scorecard Action (Pedro Kaj Kjellerup Nacht <pnacht@google.com>)
fa834730: fixed meson build (Yann Collet <cyan@fb.com>)
0b8dc466: Bump actions/checkout from 4.0.0 to 4.1.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
8586d6a1: fix example for low resolution timers (Yann Collet <cyan@fb.com>)
6ea2ed7f: removed cxxtest (Yann Collet <cyan@fb.com>)
65d37725: fix minor c++ compat warning (Yann Collet <cyan@fb.com>)
67532ae3: fix examples (Yann Collet <cyan@fb.com>)
ac8d683a: removed x32 tests from inter-version-abi-test (Yann Collet <cyan@fb.com>)
b21ba41c: fix x32 CI tests (Yann Collet <cyan@fb.com>)
05d77ab1: minor comment update for x32 ABI (Yann Collet <cyan@fb.com>)
e79d3c31: update frame fuzzer to be able to generate bug1227 (Yann Collet <cyan@fb.com>)
f10aaa0a: created new test case bug1227 (Yann Collet <cyan@fb.com>)
2acbb0f1: minor unitTests refactor (Yann Collet <cyan@fb.com>)
ea7a3715: minor frametest refactoring (Yann Collet <cyan@fb.com>)
9a035706: update comment on @.stableDst parameter (Yann Collet <cyan@fb.com>)
eaae7159: frametest: added RAND_BITS() macro (Yann Collet <cyan@fb.com>)
6c95e591: Bump actions/upload-artifact from 3.1.2 to 3.1.3 (dependabot[bot] <49699333+dependabot[bot]@users....)
e23d0c95: Bump actions/checkout from 3.6.0 to 4.0.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
8a0d78f9: minor: fixed incorrectly position comma (,) (Yann Collet <cyan@fb.com>)
4bd6e028: lz4hc: increase count back search step (Jun He <jun.he@arm.com>)
b9343a68: Change test to decompress-partial that has no dependencies (Laszlo Dobcsanyi <laszlo.dobcsanyi@gmail.com>)
b2abefe9: Move GNUInstallDirs include before it is referenced first (Laszlo Dobcsanyi <laszlo.dobcsanyi@gmail.com>)
2afd9253: Add test cmake project and CI integration (Laszlo Dobcsanyi <laszlo.dobcsanyi@gmail.com>)
cf17807d: Bump actions/checkout from 3.5.3 to 3.6.0 (dependabot[bot] <49699333+dependabot[bot]@users....)
38cc73c9: Move GNUInstallDirs include before its referenced first (Laszlo Dobcsanyi <laszlo.dobcsanyi@gmail.com>)
4387beef: Improve the README (ltrk2 <107155950+ltrk2@users.noreply.github.com>)
eef01f77: Hide the functionality behind a feature flag and document it (ltrk2 <107155950+ltrk2@users.noreply.github.com>)
9e9664b1: bump cmake minimum to 3.5 (Harmen Stoppels <me@harmenstoppels.nl>)
f313ed99: Added namespace declaration for xxhash in CMake (Ludwig Füchsl <ludwig@fuechsl.org>)
cfee8d50: Apply pyupgrade suggestion to Python test scripts (Dimitri Papadopoulos <3234522+DimitriPapadopoulo...)
1bb50a1a: Hash-pin GitHub Actions (Pedro Kaj Kjellerup Nacht <pnacht@google.com>)
b6d94d24: Make hashes identical between LE and BE platforms (ltrk2 <107155950+ltrk2@users.noreply.github.com>)
06a27a66: fix: missing LZ4F_freeDecompressionContext (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
ccef95b8: fix: issue #1248 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
bdecb2e8: fix #1246 (Yann Collet <cyan@fb.com>)
13c508ea: Discard trailing spaces (Dimitri Papadopoulos <3234522+DimitriPapadopoulo...)
b7ec6e3f: Macros should not use a trailing semicolon (Dimitri Papadopoulos <3234522+DimitriPapadopoulo...)
bdfe4c0c: Enclose by a do-while loop to avoid possible if/else logic defects (Dimitri Papadopoulos <3234522+DimitriPapadopoulo...)
20241ecf: ci: fix batch files for msvc 2022 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
6d685dc4: ci: add clang-15 and clang++-15 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
0d645418: add: gcc-13 and g++-13 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
864c9b64: Set WINDRES only if it isn't already set. This resolves the problem with... (Joel Uckelman <juckelman@strozfriedberg.co.uk>)
34d91270: updated README with repology status (Yann Collet <cyan@fb.com>)
c8b856ea: Adjust output location of liblz4.dll and liblz4.dll.a. (Joel Uckelman <juckelman@strozfriedberg.co.uk>)
72618e54: Don't conflate the shared library name with the shared library filename.... (Joel Uckelman <juckelman@strozfriedberg.co.uk>)
2d7009ef: Ignore generated .rc files. (Joel Uckelman <juckelman@strozfriedberg.co.uk>)
4ac63d8d: WINBASED uses yes/no as values, not 0/1. Check for 'yes'. (Joel Uckelman <juckelman@strozfriedberg.co.uk>)
cb3a5ff8: Don't clobber default WINDRES in MinGW environments. (Joel Uckelman <juckelman@strozfriedberg.co.uk>)
7075bc29: fixed minor typo (Yann Collet <yann.collet.73@gmail.com>)
d3d7ad9d: Add security policy (Pedro Kaj Kjellerup Nacht <pnacht@google.com>)
56ee3172: Update README.md (Igor W <91321846+IgorWiecz@users.noreply.github....)
70ad629a: Update ci.yml (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
a26a46ca: add:  CI build test for VS2022 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
532c9231: refactor: Build script for VS2022 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
0784fefb: Create build.bat (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
eeb33d10: fix: workaround for false positive analysis from MSVC v17.6 (part 2) (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
099892ca: Add missing build/VS2022/lz4/ (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
9c0b42e4: Update .gitignore (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
d678159c: fix: workaround for false positive analysis from MSVC v17.6 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
0d109b2d: fixed github workflow (Yann Collet <cyan@fb.com>)
c0752209: fixed circle CI script (Yann Collet <cyan@fb.com>)
8c06506e: removed travis script and reference (Yann Collet <cyan@fb.com>)
990f8ab9: Set cmake policy max to something recent (Harmen Stoppels <harmenstoppels@gmail.com>)
42aef710: Reduce usage of variable cpy on decompression (Nicolas De Carli <nidecarl@microsoft.com>)
8ef36c0b: Fix build break on Visual Studio 2010 (Nicolas De Carli <nidecarl@microsoft.com>)
ae72509d: remove whitespace (Nicolas De Carli <nidecarl@microsoft.com>)
b87247f9: Add packing support for MSC (Nicolas De Carli <De.Nicolas@microsoft.com>)
0973fe52: Remove redundant error check (Nicolas De Carli <nidecarl@microsoft.com>)
5953ac18: lib/Makefile: Support building on legacy OS X (Sevan Janiyan <venture37@geeklan.co.uk>)
30608393: fix: GH-Actions - removed ubuntu-18.04 (Takayuki Matsuoka <takayuki.matsuoka@gmail.com>)
a5152191: merge into a single UTIL_isDirectory() method (Yann Collet <cyan@fb.com>)
45a4880b: refuse to compress directories (Yann Collet <yann.collet.73@gmail.com>)
1a3f35c5: Add 64-bit detection for LoongArch (zhaixiaojuan <zhaixiaojuan@loongson.cn>)
c3addfea: improve LZ4F_decompress() documentation (Elliot Gorokhovsky <embg@fb.com>)
7ab223b7: build: move meson files from contrib, to go alongside other build system... (Eli Schwartz <eschwartz@archlinux.org>)
ab8328bc: Clean up generation of internal static library (Tristan Partin <tristan@partin.io>)
b1fd838c: Fix typo found by codespell (Dimitri Papadopoulos <3234522+DimitriPapadopoulo...)
fe389cab: version note (Yann Collet <cyan@fb.com>)
2fc9a85b: Install lz4file.h only when default_library isn't shared (Tristan Partin <tristan@partin.io>)
3301f311: Only build the freestanding test on Linux x86_64 (Tristan Partin <tristan@partin.io>)
3946e3da: Add Meson override for the library (Tristan Partin <tristan@partin.io>)
5b83db47: Change the version of lib[x]gcc for clang-(11|12) -mx32 (Takayuki Matsuoka <t-mat@users.noreply.github.co...)
95d703ae: Remove PATH=$(PATH) prefix from all shell script invocation (Takayuki Matsuoka <t-mat@users.noreply.github.co...)
e4ea198b: Fixed const-ness of src data pointer in lz4file and install lz4file.h (Vladimir Solontsov <vsolontsov@volanttrading.com...)
2a782cc3: Add copying lz4file.h to make install (Vladimir Solontsov <vsolontsov@volanttrading.com...)
812c4b13: Declare read_long_length_no_check() static (Andrey Borodin <xformmm@amazon.com>)
08f1483b: Add environment check for freestanding test (Takayuki Matsuoka <t-mat@users.noreply.github.co...)
198e5323: Update Meson build to 1.9.4 (Tristan Partin <tristan@partin.io>)
7213a321: uncompressed-blocks: Allow uncompressed blocks for all modes (Alexander Mohr <alexander.m.mohr@mercedes-benz.c...)
4dafb855: fixed usan32 tests (Yann Collet <cyan@fb.com>)
e3974e5a: minor refactor of lz4.c (Yann Collet <cyan@fb.com>)
68848ec6: fix another ubsan warning in lz4hc (Yann Collet <yann.collet.73@gmail.com>)
a3d17620: use LZ4HC_match_t structure directly to store match candidates (Yann Collet <yann.collet.73@gmail.com>)
2fefb1da: removed virtual pointer from optimal parser (Yann Collet <cyan@fb.com>)
0a2e406d: removed virtual match pointer from HC parser (Yann Collet <cyan@fb.com>)
a0adc616: sequence encoder accepts offset as a value (Yann Collet <cyan@fb.com>)
952942d0: LZ4 HC matchfinder returns an offset value (Yann Collet <cyan@fb.com>)
586e9a4c: added code documentation on heap mode (Yann Collet <cyan@fb.com>)
1ae9a50d: Update snapcraft.yaml to reflect build of v1.9.4 (Edward Hope-Morley <edward.hope-morley@canonical...)
b2149023: added notes about LZ4_compressFrame() and stack/heap memory usage (Yann Collet <cyan@fb.com>)
dc944197: fix rare ub (Yann Collet <cyan@fb.com>)
7f54a564: fixed minor UB warning (Yann Collet <cyan@fb.com>)
2c8fd114: removed a few more usages of base ptr (Yann Collet <cyan@fb.com>)
2620c092: remove another usage of base (Yann Collet <cyan@fb.com>)
251e04a9: added test able to catch bug #1167 (Yann Collet <cyan@fb.com>)
ec0d3e6e: fix benchmark more using Dictionary (Yann Collet <cyan@fb.com>)
3c1d5812: add a test to catch issue #1164 (Yann Collet <cyan@fb.com>)
fdfbe3a2: update v1.9.4 NEWS (Yann Collet <cyan@fb.com>)
5799b2d4: document Makefile variables (Yann Collet <cyan@fb.com>)
5ccbd382: build: Support BUILD_SHARED=no (Fotis Xenakis <foxen@windowslive.com>)
72b9348f: Clarifiy documentation for LZ4F_HEAPMODE (Yann Collet <cyan@fb.com>)
32bfb209: clarify Data Block in the Frame format documentation (Yann Collet <cyan@fb.com>)
f6c18481: simplify getPosition (Yann Collet <cyan@fb.com>)
d91d16b4: updated documentation : no more issue with 32-bit compilation on recent ... (Yann Collet <cyan@fb.com>)
9bed6b56: updated Github Actions tests documentation (Yann Collet <cyan@fb.com>)
fbd2f9f0: fixed a few ubsan warnings in lz4hc (Yann Collet <cyan@fb.com>)
8b7c57a8: attempt to enable ubsan tests in CI (Yann Collet <cyan@fb.com>)
28228258: added LZ4F_compressUpdate() in fullbench (Yann Collet <cyan@fb.com>)
cedf9cd5: allocation optimization for lz4frame compression (Yann Collet <cyan@fb.com>)
36de5a51: Bump actions/upload-artifact from 1 to 3 (dependabot[bot] <49699333+dependabot[bot]@users....)
cd640537: Bump actions/checkout from 2 to 3 (dependabot[bot] <49699333+dependabot[bot]@users....)
19532ca0: Bump actions/setup-python from 2 to 4 (dependabot[bot] <49699333+dependabot[bot]@users....)
78b30782: Add dependabot (Tristan Partin <tristan@partin.io>)
c871a283: Cancel in-progress CI if a new commit workflow supplants it (Tristan Partin <tristan@partin.io>)
```

