```
5e787401: save: Make xmlEscapeTab signed (Nick Wellnhofer <wellnhofer@aevum.de>)
6e503eb7: encoding: Handle more ICU error codes (Nick Wellnhofer <wellnhofer@aevum.de>)
55d36c59: encoding: Fix error code in xmlUconvConvert (Nick Wellnhofer <wellnhofer@aevum.de>)
de10d4cd: include: Check whether _MSC_VER is defined (Nick Wellnhofer <wellnhofer@aevum.de>)
bd9eed46: parser: Make unsupported encodings an error in declarations (Nick Wellnhofer <wellnhofer@aevum.de>)
40abebbc: python: Fix SAX driver with character streams (Nick Wellnhofer <wellnhofer@aevum.de>)
8ae06d52: SAX2: Don't merge CDATA sections (Nick Wellnhofer <wellnhofer@aevum.de>)
dde62ae5: parser: Align push parsing of CDATA sections with pull parser (Nick Wellnhofer <wellnhofer@aevum.de>)
4d10e53a: parser: Make sure to set and increment input id (Nick Wellnhofer <wellnhofer@aevum.de>)
6d365ca0: doc: XML_PARSE_NO_XXE is available since 2.13.0 (Nick Wellnhofer <wellnhofer@aevum.de>)
8ad618d2: doc: Document all xmllint options (Nick Wellnhofer <wellnhofer@aevum.de>)
67ff748c: io: don't set the executable bit when creating files (triallax <triallax@tutanota.com>)
0bb0012e: catalog: Set xmlCatalogInitialized after setting default catalog (Nick Wellnhofer <wellnhofer@aevum.de>)
8625db28: xmlcatalog: Improved fix for #699 (Nick Wellnhofer <wellnhofer@aevum.de>)
4b007878: Revert "catalog: Fetch XML catalog before dumping" (Nick Wellnhofer <wellnhofer@aevum.de>)
57b92cab: catalog: Fix regression in xmlCatalogAdd (Nick Wellnhofer <wellnhofer@aevum.de>)
2abb9033: tests: Add fallback for glob() (Nick Wellnhofer <wellnhofer@aevum.de>)
567f612d: build: Check for declaration of glob() function (Nick Wellnhofer <wellnhofer@aevum.de>)
2191ccdf: autotools: Fix EXTRA_DIST (Nick Wellnhofer <wellnhofer@aevum.de>)
5c608609: Eliminate false positive -Warray-bounds on some compilers (makise-homura <akemi_homura@kurisa.ch>)
a3043b47: threads: define _WIN32_WINNT as 0x0600 to use InitOnceExecuteOnce() (makise-homura <akemi_homura@kurisa.ch>)
f59da1a3: hash: Suppress GCC 7.3 and MINGW maybe-uninitialized warning (makise-homura <akemi_homura@kurisa.ch>)
103aadbc: parser: Suppress EDG maybe-uninitialized warning (makise-homura <akemi_homura@kurisa.ch>)
f2c48847: io: Add missing calls to xmlInitParser (Nick Wellnhofer <wellnhofer@aevum.de>)
0c56eb82: tree: Restore return value of xmlNodeListGetString with NULL list (Nick Wellnhofer <wellnhofer@aevum.de>)
b45a0f0e: nanohttp: Avoid ctype(3) misuse. (Taylor R Campbell <campbell+libxml2@mumble.net>)
1d009fe3: parser: Report at least one fatal error (Nick Wellnhofer <wellnhofer@aevum.de>)
bfed6e6a: parser: Fix error handling after reaching limit (Nick Wellnhofer <wellnhofer@aevum.de>)
6e1e22dc: malloc-fail: Fix null-deref in xmlPatPushState (Nick Wellnhofer <wellnhofer@aevum.de>)
a530ff12: io: Always consume encoding handler when creating output buffers (Nick Wellnhofer <wellnhofer@aevum.de>)
36ea881b: malloc-fail: Fix memory leak in xmlOutputBufferCreateFilename (Nick Wellnhofer <wellnhofer@aevum.de>)
02fcb1ef: parser: Make xmlParseChunk return an error if parser was stopped (Nick Wellnhofer <wellnhofer@aevum.de>)
bc14d70f: xmlsave: Improve "unsupported encoding" error message (Nick Wellnhofer <wellnhofer@aevum.de>)
1a893230: [CVE-2024-40896] Fix XXE protection in downstream code (Nick Wellnhofer <wellnhofer@aevum.de>)
6cc2387e: shell: Only use readline on terminals (Nick Wellnhofer <wellnhofer@aevum.de>)
d04e152d: shell: Remove access(2) checks (Nick Wellnhofer <wellnhofer@aevum.de>)
aa6ca0b1: module: Deprecate module API (Nick Wellnhofer <wellnhofer@aevum.de>)
ec4340b8: Update NEWS (Nick Wellnhofer <wellnhofer@aevum.de>)
e1291059: build: Don't check for pthread.h (Nick Wellnhofer <wellnhofer@aevum.de>)
cc03c069: build: Don't check for standard POSIX headers (Nick Wellnhofer <wellnhofer@aevum.de>)
d7dc2eaf: build: Don't check for dlfcn.h and dl.h (Nick Wellnhofer <wellnhofer@aevum.de>)
7c10393f: build: Fix config.h macros (Nick Wellnhofer <wellnhofer@aevum.de>)
095b3c7f: cmake: Implement READLINE and HISTORY options (Nick Wellnhofer <wellnhofer@aevum.de>)
0172ffa9: build: Only check for required headers (Nick Wellnhofer <wellnhofer@aevum.de>)
3ef66611: build: Rework mmap checks (Nick Wellnhofer <wellnhofer@aevum.de>)
e1657f3f: build: Use AC_CHECK_DECLS/check_symbol_exists for getentropy (Nick Wellnhofer <wellnhofer@aevum.de>)
278fcf13: buf: Limit xmlBuffer size to INT_MAX (Nick Wellnhofer <wellnhofer@aevum.de>)
6a3c0b0d: parser: Increase XML_MAX_DICTIONARY_LIMIT (Nick Wellnhofer <wellnhofer@aevum.de>)
d2755cdb: buf: Fix memory leak if malloc fails before xmlBufBackToBuffer (Nick Wellnhofer <wellnhofer@aevum.de>)
322e733b: xinclude: Fix fallback for text includes (Nick Wellnhofer <wellnhofer@aevum.de>)
0dada804: threads: Fix 32-bit Windows build (Nick Wellnhofer <wellnhofer@aevum.de>)
7b98e8d6: io: Don't call getcwd in xmlParserGetDirectory (Nick Wellnhofer <wellnhofer@aevum.de>)
15202100: buf: Fix maxSize behavior (Nick Wellnhofer <wellnhofer@aevum.de>)
2440cb5d: buf: Fix xmlBufBackToBuffer (Nick Wellnhofer <wellnhofer@aevum.de>)
5862e9dd: Add NULL checks (Nick Wellnhofer <wellnhofer@aevum.de>)
4e93425a: threads: Prefer Win32 over pthreads (Nick Wellnhofer <wellnhofer@aevum.de>)
1f7d4af3: globals: Clean up macros and add comments (Nick Wellnhofer <wellnhofer@aevum.de>)
4f08a1a2: globals: Also use thread-specific storage on "main" thread (Nick Wellnhofer <wellnhofer@aevum.de>)
769e5a4a: threads: Allocate global RMutexes statically (Nick Wellnhofer <wellnhofer@aevum.de>)
5d36664f: memory: Deprecate xmlGcMemSetup (Nick Wellnhofer <wellnhofer@aevum.de>)
ff39f28b: schematron: Use xmlMalloc (Nick Wellnhofer <wellnhofer@aevum.de>)
a87944e9: windows: Use DllMain for cleanup (Nick Wellnhofer <wellnhofer@aevum.de>)
5f3f66c6: threads: Use pthread_once and InitOnceExecuteOnce (Nick Wellnhofer <wellnhofer@aevum.de>)
be250b79: xpath: Remove union swap optimization (Nick Wellnhofer <wellnhofer@aevum.de>)
79e11995: error: Make xmlLastError const (Nick Wellnhofer <wellnhofer@aevum.de>)
eb66d03e: io: Deprecate a few functions (Nick Wellnhofer <wellnhofer@aevum.de>)
97680d6c: io: Rework xmlParserInputBufferGrow (Nick Wellnhofer <wellnhofer@aevum.de>)
a6f54f05: io: Fine-tune initial IO buffer size (Nick Wellnhofer <wellnhofer@aevum.de>)
7148b778: parser: Optimize memory buffer I/O (Nick Wellnhofer <wellnhofer@aevum.de>)
34c9108f: encoding: Add sizeOut argument to xmlCharEncInput (Nick Wellnhofer <wellnhofer@aevum.de>)
8e871a31: buf: Rework xmlBuffer code (Nick Wellnhofer <wellnhofer@aevum.de>)
888f70c7: buf: Move xmlBuffer code to buf.c (Nick Wellnhofer <wellnhofer@aevum.de>)
92f30711: parser: Optimize buffer shrinking (Nick Wellnhofer <wellnhofer@aevum.de>)
a221cd78: buf: Rework xmlBuf code (Nick Wellnhofer <wellnhofer@aevum.de>)
2adcde39: save: Optimize xmlSerializeText (Nick Wellnhofer <wellnhofer@aevum.de>)
1b067082: save: Always serialize CR as decimal "&#13;" (Nick Wellnhofer <wellnhofer@aevum.de>)
1cfc5b80: entities: Rework serialization of numeric character references (Nick Wellnhofer <wellnhofer@aevum.de>)
8d160626: entities: Rework text escaping (Nick Wellnhofer <wellnhofer@aevum.de>)
cc45f618: save: Rework text escaping (Nick Wellnhofer <wellnhofer@aevum.de>)
e488695b: save: Deprecate xmlSaveSet*Escape (Nick Wellnhofer <wellnhofer@aevum.de>)
0ab07b21: io: Rework xmlOutputBufferWrite (Nick Wellnhofer <wellnhofer@aevum.de>)
bb1884cb: Enable CMake checks for MSVC (Markus Rickert <markus.rickert@uni-bamberg.de>)
e0494c0d: io: Add some deprecation warnings (Nick Wellnhofer <wellnhofer@aevum.de>)
2dcd561d: regexp: Don't print to stderr (Nick Wellnhofer <wellnhofer@aevum.de>)
4b1832c1: relaxng: Use error handler for internal errors (Nick Wellnhofer <wellnhofer@aevum.de>)
72886980: error: Add helper functions to print errors and abort (Nick Wellnhofer <wellnhofer@aevum.de>)
f6170b48: memory: Don't report OOM to stderr (Nick Wellnhofer <wellnhofer@aevum.de>)
6be79014: Remove unused code (Nick Wellnhofer <wellnhofer@aevum.de>)
fee0006a: parser: Fix memory leak after malloc failure in xml*ParseDTD (Nick Wellnhofer <wellnhofer@aevum.de>)
69f12d6d: encoding: Deprecate xmlByteConsumed (Nick Wellnhofer <wellnhofer@aevum.de>)
440d11af: reader: Deprecate xmlTextReaderByteConsumed (Nick Wellnhofer <wellnhofer@aevum.de>)
3528b81f: tools: Move codegen tools to 'tools' directory (Nick Wellnhofer <wellnhofer@aevum.de>)
c3b2f471: cmake: Update option description (Nick Wellnhofer <wellnhofer@aevum.de>)
30487932: meson: Also disable icu and thread_alloc by default (Nick Wellnhofer <wellnhofer@aevum.de>)
aa6aec19: parser: Fix xmlInputSetEncodingHandler again (Nick Wellnhofer <wellnhofer@aevum.de>)
8af55c8d: parser: Rename new input API functions (Nick Wellnhofer <wellnhofer@aevum.de>)
d74ca594: parser: Rename internal xmlNewInput functions (Nick Wellnhofer <wellnhofer@aevum.de>)
4f329dc5: parser: Implement xmlCtxtParseContent (Nick Wellnhofer <wellnhofer@aevum.de>)
673ca0ed: tests: Regenerate testapi.c (Nick Wellnhofer <wellnhofer@aevum.de>)
4fec0889: parser: Fix memory leak in xmlInputSetEncodingHandler (Nick Wellnhofer <wellnhofer@aevum.de>)
d0997956: encoding: Readd some UTF-8 validation to encoders (Nick Wellnhofer <wellnhofer@aevum.de>)
ae6e2ee7: fuzz: Adjust reader fuzzer (Nick Wellnhofer <wellnhofer@aevum.de>)
f48eefe3: encoding: Rework xmlByteConsumed (Nick Wellnhofer <wellnhofer@aevum.de>)
8c4cc0be: fuzz: Improve debug output of reader fuzzer (Nick Wellnhofer <wellnhofer@aevum.de>)
59354717: parser: Fix malloc failure handling in xmlInputSetEncodingHandler (Nick Wellnhofer <wellnhofer@aevum.de>)
da686399: io: Fix return value of xmlFileRead (Nick Wellnhofer <wellnhofer@aevum.de>)
f51ad063: parser: Fix error return of xmlParseBalancedChunkMemory (Nick Wellnhofer <wellnhofer@aevum.de>)
2e63656e: parser: Check return value of inputPush (Nick Wellnhofer <wellnhofer@aevum.de>)
ea31ac5b: fuzz: Fix spaceMax (Nick Wellnhofer <wellnhofer@aevum.de>)
82e0455c: Undeprecate some symbols for now (Nick Wellnhofer <wellnhofer@aevum.de>)
29e3ab92: fuzz: Make reallocs more likely (Nick Wellnhofer <wellnhofer@aevum.de>)
de3221b1: fuzz: Adjust for xmlNodeParseContent changes (Nick Wellnhofer <wellnhofer@aevum.de>)
1e5375c1: SAX2: Check return value of xmlPushInput (Nick Wellnhofer <wellnhofer@aevum.de>)
38195cf5: parser: Don't produce names with invalid UTF-8 in recovery mode (Nick Wellnhofer <wellnhofer@aevum.de>)
c45c15f5: ci: Add job for perl-XML-LibXML (Nick Wellnhofer <wellnhofer@aevum.de>)
ec088109: parser: Upgrade XML_IO_NETWORK_ATTEMPT to error (Nick Wellnhofer <wellnhofer@aevum.de>)
f86d17c1: encoding: Fix xmlParseCharEncoding (Nick Wellnhofer <wellnhofer@aevum.de>)
10082a3d: testchar: Don't invoke encoding handler directly (Nick Wellnhofer <wellnhofer@aevum.de>)
446a3610: test: add a downstream integration test job for nokogiri (Mike Dalessio <mike.dalessio@gmail.com>)
67fa4a43: meson: Disable python when python is disabled (Andrew Potter <agpotter@gmail.com>)
e2a49afe: build: Read version number from VERSION file (Nick Wellnhofer <wellnhofer@aevum.de>)
c3731347: build: Introduce LIBXML_MINOR_COMPAT (Nick Wellnhofer <wellnhofer@aevum.de>)
606310a3: meson: Set soversion (Nick Wellnhofer <wellnhofer@aevum.de>)
944cc23c: tree: Fix handling of empty strings in xmlNodeParseContent (Nick Wellnhofer <wellnhofer@aevum.de>)
46ec621e: encoding: Clarify xmlUconvConvert (Nick Wellnhofer <wellnhofer@aevum.de>)
48fec242: encoding: Remove duplicate code (Nick Wellnhofer <wellnhofer@aevum.de>)
71fb2579: encoding: Fix ICU build (Nick Wellnhofer <wellnhofer@aevum.de>)
80aabea1: SAX2: Reenable 'directory' as base URI fallback (Nick Wellnhofer <wellnhofer@aevum.de>)
842a0448: valid: Restore ID lookup (Nick Wellnhofer <wellnhofer@aevum.de>)
f9065261: SAX2: Fix HTML IDs (Nick Wellnhofer <wellnhofer@aevum.de>)
785ed5c4: meson: Don't auto-enable legacy and tls (Nick Wellnhofer <wellnhofer@aevum.de>)
96d850c3: save: Fix "Factor out xmlSaveWriteIndent" (Nick Wellnhofer <wellnhofer@aevum.de>)
205e56da: parser: Undeprecate ctxt->directory (Nick Wellnhofer <wellnhofer@aevum.de>)
8fb1dc9a: Clarify xpointer() extension removal (Nick Wellnhofer <wellnhofer@aevum.de>)
fdfeecfe: parser: Reenable ctxt->directory (Nick Wellnhofer <wellnhofer@aevum.de>)
c127c89f: catalog: Deprecate xmlCatalogSetDefaultPrefer (Nick Wellnhofer <wellnhofer@aevum.de>)
606f4108: parser: Allow to disable catalogs with parser options (Nick Wellnhofer <wellnhofer@aevum.de>)
6794c1b9: globals: Document remaining thread-local vars as deprecated (Nick Wellnhofer <wellnhofer@aevum.de>)
35146ff3: save: Implement xmlSaveSetIndentString (Nick Wellnhofer <wellnhofer@aevum.de>)
7cc619d5: save: Implement save options for indenting (Nick Wellnhofer <wellnhofer@aevum.de>)
2c4204ec: save: Factor out xmlSaveWriteIndent (Nick Wellnhofer <wellnhofer@aevum.de>)
202045f8: save: Pass options to xmlSaveCtxtInit (Nick Wellnhofer <wellnhofer@aevum.de>)
197e09d5: parser: Fix xmlLoadResource (Nick Wellnhofer <wellnhofer@aevum.de>)
ede5d99a: parser: Fix typo (Nick Wellnhofer <wellnhofer@aevum.de>)
866be54e: parser: Don't use deprecated xmlSplitQName (Nick Wellnhofer <wellnhofer@aevum.de>)
30ef7755: parser: Don't use deprecated xmlCopyChar (Nick Wellnhofer <wellnhofer@aevum.de>)
751ba00e: parser: Don't use deprecated xmlSwitchInputEncoding (Nick Wellnhofer <wellnhofer@aevum.de>)
9a4770ef: doc: Improve documentation (Nick Wellnhofer <wellnhofer@aevum.de>)
0b0dd989: parser: Fix EBCDIC detection (Nick Wellnhofer <wellnhofer@aevum.de>)
37a9ff11: encoding: Simplify xmlCharEncCloseFunc (Nick Wellnhofer <wellnhofer@aevum.de>)
1167c334: encoding: Don't include iconv.h from libxml/encoding.h (Nick Wellnhofer <wellnhofer@aevum.de>)
95d36333: encoding: Rework conversion error codes (Nick Wellnhofer <wellnhofer@aevum.de>)
dd8e3785: HTML: Rework UTF8ToHtml (Nick Wellnhofer <wellnhofer@aevum.de>)
30be984a: encoding: Rework ISO-8859-X conversion (Nick Wellnhofer <wellnhofer@aevum.de>)
282ec1d5: encoding: Rework xmlCharEncodingHandler layout (Nick Wellnhofer <wellnhofer@aevum.de>)
57e37dff: encoding: Rework UTF-16 conversion functions (Nick Wellnhofer <wellnhofer@aevum.de>)
bb8e81c7: encoding: Rework simple conversions function (Nick Wellnhofer <wellnhofer@aevum.de>)
501e5d19: encoding: Stop using XML_ENC_ERR_PARTIAL (Nick Wellnhofer <wellnhofer@aevum.de>)
221df375: parser: Support custom charset conversion implementations (Nick Wellnhofer <wellnhofer@aevum.de>)
c59c2449: encoding: Support custom implementations (Nick Wellnhofer <wellnhofer@aevum.de>)
1e3da9f4: encoding: Start with callbacks (Nick Wellnhofer <wellnhofer@aevum.de>)
6d8427dc: encoding: Rework encoding lookup (Nick Wellnhofer <wellnhofer@aevum.de>)
16e7ecd4: xinclude: Check URI length (Nick Wellnhofer <wellnhofer@aevum.de>)
37f72370: xmllint: Fix unsigned integer overflow (Nick Wellnhofer <wellnhofer@aevum.de>)
64b0c64e: cmake: Don't install man pages if LIBXML2_WITH_PROGRAMS=OFF (Nick Wellnhofer <wellnhofer@aevum.de>)
a24b08bf: meson: Don't always assume PThreads when using threads (Chun-wei Fan <fanc999@yahoo.com.tw>)
64685e98: autotools: Remove NON_PC_LIBS (Nick Wellnhofer <wellnhofer@aevum.de>)
044ddf07: parser: Undeprecate some parser context members (Nick Wellnhofer <wellnhofer@aevum.de>)
e72eda10: parser: Add NULL check in xmlNewIOInputStream (Nick Wellnhofer <wellnhofer@aevum.de>)
bc793390: parser: Update documentation (Nick Wellnhofer <wellnhofer@aevum.de>)
f4e63f7a: Regenerate libxml2-api.xml and testapi.c (Nick Wellnhofer <wellnhofer@aevum.de>)
193f4653: parser: Implement xmlCtxtGetStatus (Nick Wellnhofer <wellnhofer@aevum.de>)
f505dcae: tree: Remove underscores from xmlRegisterCallbacks (Nick Wellnhofer <wellnhofer@aevum.de>)
cc0cc2d3: parser: Add more parser context accessors (Nick Wellnhofer <wellnhofer@aevum.de>)
8b1f79ce: SAX2: Make xmlSAXDefaultVersion a no-op (Nick Wellnhofer <wellnhofer@aevum.de>)
5cf5b542: SAX2: Deprecate xmlSAX2StartElement (Nick Wellnhofer <wellnhofer@aevum.de>)
71eb7109: xmllint: Switch to xmlCtxtSetErrorHandler (Nick Wellnhofer <wellnhofer@aevum.de>)
c5750fc6: python: Switch to xmlCtxtSetErrorHandler (Nick Wellnhofer <wellnhofer@aevum.de>)
eca972e6: parser: Add getters for XML declaration to parser context (Nick Wellnhofer <wellnhofer@aevum.de>)
598ee0d2: error: Remove underscores from xmlRaiseError (Nick Wellnhofer <wellnhofer@aevum.de>)
3ff8a2c4: parser: Deprecate xmlIsLetter (Nick Wellnhofer <wellnhofer@aevum.de>)
fa50be92: parser: Move implementation of xmlCtxtGetLastError (Nick Wellnhofer <wellnhofer@aevum.de>)
7c11da2d: tests: Clarify licence of test/intsubset2.xml (Nick Wellnhofer <wellnhofer@aevum.de>)
b1a416bf: encoding: Restore old lookup order in xmlOpenCharEncodingHandler (Nick Wellnhofer <wellnhofer@aevum.de>)
e6f25fdc: uri: Fix documentation of xmlBuildRelativeURI (Nick Wellnhofer <wellnhofer@aevum.de>)
c195f06f: autotools: Use AX_GCC_FUNC_ATTRIBUTE from autoconf archives (Nick Wellnhofer <wellnhofer@aevum.de>)
1afaa371: build: Move definition of ATTRIBUTE_DESTRUCTOR to libxml.h (Nick Wellnhofer <wellnhofer@aevum.de>)
fd099dd8: autotools: Fix pkg.m4 check (Nick Wellnhofer <wellnhofer@aevum.de>)
c4d8343b: encoding: Make xmlFindCharEncodingHandler return UTF-8 handler (Nick Wellnhofer <wellnhofer@aevum.de>)
54c6c7e4: uri: Only set file scheme for special Windows paths (Nick Wellnhofer <wellnhofer@aevum.de>)
ec47add4: configure.ac: fix bashisms (Sam James <sam@gentoo.org>)
c14c20f5: doc: Add note about meson.build version bump (correctmost <136447-correctmost@users.noreply.gi...)
2ce70cde: uri: Handle filesystem paths in xmlBuildRelativeURISafe (Nick Wellnhofer <wellnhofer@aevum.de>)
7655ed2c: cmake: Implement dependent options (Nick Wellnhofer <wellnhofer@aevum.de>)
600c6ca4: cmake: Don't install meson build scripts in documentation (Daniel E <daniel.engberg.lists@pyret.net>)
28b9bb03: uri: Enable Windows paths on Cygwin (Nick Wellnhofer <wellnhofer@aevum.de>)
5b893fa9: encoding: Fix encoding lookup with xmlOpenCharEncodingHandler (Nick Wellnhofer <wellnhofer@aevum.de>)
b8903b9e: runtest: Remove result handling from schemasOneTest (Nick Wellnhofer <wellnhofer@aevum.de>)
a4703785: runtest: Remove result handling from rngOneTest (Nick Wellnhofer <wellnhofer@aevum.de>)
e68ccfa9: tests: Port Schematron tests to C (Nick Wellnhofer <wellnhofer@aevum.de>)
811373e2: tests: Remove old Python tests (Nick Wellnhofer <wellnhofer@aevum.de>)
0a279e2f: tests: Remove old timing tests (Nick Wellnhofer <wellnhofer@aevum.de>)
f06fc933: tests: Move tests for executables to separate script (Nick Wellnhofer <wellnhofer@aevum.de>)
2d96adb2: windows: fopen files with "wb" (Nick Wellnhofer <wellnhofer@aevum.de>)
5589c9ea: xmllint: Set stdin/stdout to binary on Windows (Nick Wellnhofer <wellnhofer@aevum.de>)
4b6e6828: cmake: Stop using win32config.h (Nick Wellnhofer <wellnhofer@aevum.de>)
84a4f84c: build: Don't check for required headers and functions (Nick Wellnhofer <wellnhofer@aevum.de>)
f23fc4fa: xmllint: Simplify time handling (Nick Wellnhofer <wellnhofer@aevum.de>)
dc6f55cf: build: Remove check for IPv6 (Nick Wellnhofer <wellnhofer@aevum.de>)
02326d72: build: Remove socklen_t checks (Nick Wellnhofer <wellnhofer@aevum.de>)
b01b55d5: README: Fix Meson examples (Nick Wellnhofer <wellnhofer@aevum.de>)
88cc61e3: meson: simplify thread_local check (Rosen Penev <rosenp@gmail.com>)
34fe4b88: meson: simplify IPv6 check (Rosen Penev <rosenp@gmail.com>)
609c51c5: meson: simplify socklen_t check (Rosen Penev <rosenp@gmail.com>)
9d46da17: ci: Test meson build with legacy enabled (Nick Wellnhofer <wellnhofer@aevum.de>)
c2ccbc0f: meson: Implement option dependencies (Nick Wellnhofer <wellnhofer@aevum.de>)
f9c33a55: parser: Undeprecate some xmlParserInput members (Nick Wellnhofer <wellnhofer@aevum.de>)
1228b4e0: parser: Deprecate xmlParserCtxt->lastError (Nick Wellnhofer <wellnhofer@aevum.de>)
f82ca02b: parser: Undeprecate some xmlParserCtxt members (Nick Wellnhofer <wellnhofer@aevum.de>)
7ba6c8fe: autotools: Remove libxml-2.0-uninstalled.pc (Nick Wellnhofer <wellnhofer@aevum.de>)
c106455c: build: Set Cflags.private on Windows (Nick Wellnhofer <wellnhofer@aevum.de>)
1a5ed747: build: Fix XML_LIBDIR usage (Nick Wellnhofer <wellnhofer@aevum.de>)
fc4bd04b: autotools: Remove unused variable (Nick Wellnhofer <wellnhofer@aevum.de>)
4c1b8851: autotools: Move MODULE_PLATFORM_LIBS into NON_PC_LIBS (Nick Wellnhofer <wellnhofer@aevum.de>)
29bf09ec: autotools: Remove XML_LIBTOOLLIBS (Nick Wellnhofer <wellnhofer@aevum.de>)
02f519e6: autotools: Use pkg-config to check for libreadline (Nick Wellnhofer <wellnhofer@aevum.de>)
2def7b4b: clang-tidy: move assignments out of if (Rosen Penev <rosenp@gmail.com>)
5803ad26: meson: change history to a feature (Rosen Penev <rosenp@gmail.com>)
e9948ee5: meson: change readline to a feature (Rosen Penev <rosenp@gmail.com>)
5d542fef: libxml: define ATTRIBUTE_UNUSED for clang (Rosen Penev <rosenp@gmail.com>)
bbbbbb46: parser: implement xmlCtxtGetOptions (Mike Dalessio <mike.dalessio@gmail.com>)
a4517bfe: meson: Add libxml2 part of include dir to pc file (Heiko Becker <mail@heiko-becker.de>)
217e9b7a: clang-tidy: don't return in void functions (Rosen Penev <rosenp@gmail.com>)
4c3d22b0: uri: Fix xmlBuildURI with NULL base (Nick Wellnhofer <wellnhofer@aevum.de>)
1dd5e76a: xinclude: Don't remove root element (Nick Wellnhofer <wellnhofer@aevum.de>)
860fb460: SAX2: Fix null deref after malloc failure (Nick Wellnhofer <wellnhofer@aevum.de>)
1d8bd126: meson: fix icu and iconv om BSDs again (Rosen Penev <rosenp@gmail.com>)
f61d23b8: meson: only apply threads_dep to runtest (Rosen Penev <rosenp@gmail.com>)
32cac377: parser: Selectively reenable reading from "-" (Nick Wellnhofer <wellnhofer@aevum.de>)
52ce0d70: tests: Add XInclude test for issue #733 (Nick Wellnhofer <wellnhofer@aevum.de>)
c5e9a5b2: parser: Use catalogs with resource loader (Nick Wellnhofer <wellnhofer@aevum.de>)
57004006: reader: Fix xmlTextReaderReadString (Nick Wellnhofer <wellnhofer@aevum.de>)
3c7c831c: xinclude: Set XPath context doc (Nick Wellnhofer <wellnhofer@aevum.de>)
6deebe03: parser: Make xmlInputCreateUrl handle HTTP input (Nick Wellnhofer <wellnhofer@aevum.de>)
d2fd9d37: parser: Fix swapped arguments (Nick Wellnhofer <wellnhofer@aevum.de>)
1ff48433: xinclude: Load included documents with XML_PARSE_DTDLOAD (Nick Wellnhofer <wellnhofer@aevum.de>)
3aca5bcf: doc: Ignore empty headers (Nick Wellnhofer <wellnhofer@aevum.de>)
5a9a0e6f: testapi: Don't test xmlunicode functions (Nick Wellnhofer <wellnhofer@aevum.de>)
1112699c: legacy: Remove most legacy functions from public headers (Nick Wellnhofer <wellnhofer@aevum.de>)
b4b4162f: meson: fix compilation on BSDs with icu+iconv (Rosen Penev <rosenp@gmail.com>)
915951b8: meson: add DEFS to CFLAGS (Rosen Penev <rosenp@gmail.com>)
faae3a91: SAX2: Split out legacy SAX1 handling (Nick Wellnhofer <wellnhofer@aevum.de>)
2b0c4abb: threads: Remove pthread weak symbol hack (Nick Wellnhofer <wellnhofer@aevum.de>)
38488027: xmllint: Support libreadline without history (Nick Wellnhofer <wellnhofer@aevum.de>)
5fca9498: doc: Hide internal macro (Nick Wellnhofer <wellnhofer@aevum.de>)
fb2b9cda: doc: Remove broken struct field description (Nick Wellnhofer <wellnhofer@aevum.de>)
33a1f897: legacy: Merge SAX.c into legacy.c (Nick Wellnhofer <wellnhofer@aevum.de>)
1341deac: xmllint: Move shell to xmllint (Nick Wellnhofer <wellnhofer@aevum.de>)
c9b06591: xmllint: Fix resetting error in xmlHTMLPrintError (Nick Wellnhofer <wellnhofer@aevum.de>)
481fd6bb: tests: Remove testThreads.c (Nick Wellnhofer <wellnhofer@aevum.de>)
1b640358: schemas: Stop using xmlValidateNotationUse (Nick Wellnhofer <wellnhofer@aevum.de>)
fa01278d: regexp: Hide experimental legacy code (Nick Wellnhofer <wellnhofer@aevum.de>)
10d60d15: regexp: Stop using LIBXML_AUTOMATA_ENABLED (Nick Wellnhofer <wellnhofer@aevum.de>)
11c3f84b: SAX2: Always make xmlSAX2{Start,End}Element public (Nick Wellnhofer <wellnhofer@aevum.de>)
f307237e: schemas: Use private copy of global NaN and Inf (Nick Wellnhofer <wellnhofer@aevum.de>)
b0fc67aa: build: Remove --with-tree configuration option (Nick Wellnhofer <wellnhofer@aevum.de>)
7cf7a54a: build: Only enable linker version script in legacy mode (Nick Wellnhofer <wellnhofer@aevum.de>)
7b65c90f: Regenerate libxml2-api.xml and testapi.c (Nick Wellnhofer <wellnhofer@aevum.de>)
49672779: parser: Make XML_INPUT constants signed (Nick Wellnhofer <wellnhofer@aevum.de>)
52d9d768: runtest: move catalog.h out of threads define. (Rosen Penev <rosenp@gmail.com>)
08a6a084: Fix previous commit (Nick Wellnhofer <wellnhofer@aevum.de>)
84666581: catalog: Fix initialization (Nick Wellnhofer <wellnhofer@aevum.de>)
898e5a14: build: Remove compiler TLS warning (Nick Wellnhofer <wellnhofer@aevum.de>)
e714f506: build: Stop installing libxml.m4 (Nick Wellnhofer <wellnhofer@aevum.de>)
6ed39a82: runtest: Allow catalogs (Nick Wellnhofer <wellnhofer@aevum.de>)
208f27f9: include: Don't define ATTRIBUTE_UNUSED in public header (Nick Wellnhofer <wellnhofer@aevum.de>)
387f0c78: include: Readd circular dependency between tree.h and parser.h (Nick Wellnhofer <wellnhofer@aevum.de>)
bd208d5f: xinclude: Add another missing include (Nick Wellnhofer <wellnhofer@aevum.de>)
f070acc5: autotools: Abort if external libraries couldn't be found (Nick Wellnhofer <wellnhofer@aevum.de>)
599ceaff: xinclude: Add missing include (Jan Alexander Steffens (heftig) <heftig@archlinu...)
86c4cf58: Fix typo in NEWS (--with-html -> --with-http) (Ryan Carsten Schmidt <git@ryandesign.com>)
7e83a089: win32, msvc: fix missing linking against Bcrypt.lib (Miklos Vajna <vmiklos@collabora.com>)
1aa37db0: xinclude: Don't raise error on empty nodeset (Nick Wellnhofer <wellnhofer@aevum.de>)
2608baaf: parser: Make failure to load main document a warning (Nick Wellnhofer <wellnhofer@aevum.de>)
2f128096: tree: Fix freeing entities via xmlFreeNode (Nick Wellnhofer <wellnhofer@aevum.de>)
039ce1e8: parser: Pass global object to sax->setDocumentLocator (Nick Wellnhofer <wellnhofer@aevum.de>)
```

