```
4a789712: This is tcpdump 4.99.5. (Denis Ovsienko <denis@ovsienko.info>)
0d7a688f: CHANGES: Refine the 4.99.5 section. (Denis Ovsienko <denis@ovsienko.info>)
78e9ac4e: Get the previous commit right. [skip appveyor] (Denis Ovsienko <denis@ovsienko.info>)
c55ee59b: Make illumos build warning-free. [skip appveyor] (Denis Ovsienko <denis@ovsienko.info>)
51ab30fe: CHANGES: Actualize the 4.99.5 section. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
798c5861: PPP: Fix the output (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
a1c5161a: Appveyor: Download WpdPack_4_1_2.zip from tcpdump-htdocs repository (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
ba0e4791: CHANGES: add a change backported to 4.99. [skip ci] (Guy Harris <gharris@sonic.net>)
9d036277: CHANGES: add changes backported to 4.99. [skip ci] (Guy Harris <gharris@sonic.net>)
58a740ea: Improve another invalid adapter index message. (Guy Harris <gharris@sonic.net>)
830c52e0: Improve a tcpdump error message, free device list before exiting. (Guy Harris <gharris@sonic.net>)
7ffcbcd2: tests: Print the number of skipped tests. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
37b75130: TESTrun: Print HAVE_FPTYPE1/HAVE_FPTYPE2 based on the --fp-type option (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
87b05096: esp: don't use EVP_add_cipher_alias(). (Guy Harris <gharris@sonic.net>)
74de6fcf: Appveyor: Download WpdPack_4_1_2.zip archive from our repository (Guy Harris <gharris@sonic.net>)
8e102b4f: crypto.tests: Remove an useless option (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
c34bc761: Autoconf: Lose V_GROUP. (Denis Ovsienko <denis@ovsienko.info>)
455e6cce: CHANGES: add some recent changes. [skip ci] (Guy Harris <gharris@sonic.net>)
9e37e838: CMake: fixes to cmakeconfig.h.in. (Guy Harris <gharris@sonic.net>)
791c536b: CMake: use pkg-config and Homebrew when looking for libcrypto. (Guy Harris <gharris@sonic.net>)
7b23ebfd: autotools: use pkg-config and Homebrew when looking for libcrypto. (Guy Harris <gharris@sonic.net>)
7f382f4c: CMake: fix a comment. [skip ci] (Guy Harris <gharris@sonic.net>)
06b34f6a: CMake: add a blank comment line to match the version in main. (Guy Harris <gharris@sonic.net>)
e75541cf: autotools, cmake: work around an Xcode 15+ issue. (Guy Harris <gharris@sonic.net>)
b7d50740: autotools: don't put anything before -I and -L flags for local libpcap. (Guy Harris <gharris@sonic.net>)
666f3d44: Autoconf: Use V_INCLS to update the list of include search paths (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
dcc86206: Update to the 1.13 SDK for Npcap. (Guy Harris <gharris@sonic.net>)
dd979968: CI: Remove a comment about a fixed warning (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e8a0bec3: funcattrs: Update the NORETURN definition condition for TinyCC (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
b187f7e6: CI: Add TinyCC (aka TCC) support (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
54580d9b: IPv6: Update a comment (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
f67e46a6: Include <config.h> unconditionally (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
c5c912ad: NFS: Add two length checks (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
4966c764: frag6: Fix invalid 32-bit versus 64-bit printouts (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
efe1c575: frag6: Refactor duplicate code (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
17f21ccc: Include <fcntl.h> unconditionally (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
6cc95485: Remove an unneeded include (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
ed777090: Autoconf: Update an AC_DEFINE() (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
41e3e814: AppVeyor: try building with Visual Studio 2022. (Guy Harris <gharris@sonic.net>)
b9ef2090: Extend "make shellcheck" onto mkdep too. [skip appveyor] (Denis Ovsienko <denis@ovsienko.info>)
57b9d78e: Add recent contributors to CREDITS. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
2d6da026: Makefile.in: Update the whitespacecheck target (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
a9fef42d: CMake: search for gethostbyaddr() in libnetwork (David Karoly <david.karoly@outlook.com>)
5194aca6: autoconf: search for gethostbyaddr() in libnetwork (Jerome Duval <jerome.duval@gmail.com>)
758101e5: configure: check for gethostbyaddr(), not gethostbyname(). (Guy Harris <gharris@sonic.net>)
0bdde63b: Rename the suffix of a pcap test file to .pcap (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
cbde7a81: CHANGES: Update an entry to avoid any misunderstanding (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
6a340265: doc: rename README.Win32.md to README.windows.md. (Guy Harris <gharris@sonic.net>)
1d652c22: mkdep: Use TMPDIR if it is set and not null (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
9a1321b0: CHANGES: Add two changes backported to the 4.99 branch (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
514c0399: mkdep: Exit with a non-zero status if a command fails (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
498a36e7: Makefile.in: Fix the depend target (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
6154a220: VERSION: Fix suffix (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
f245f70a: CHANGES: Move a backported change to the 4.99 branch (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
c7bb7b3b: CI: Expect warnings from Sun C on Solaris. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
d89fed10: Fix Sun C invocation from CMake. (Denis Ovsienko <denis@ovsienko.info>)
50a432cf: Cirrus CI: Synchronize with the master branch. (Denis Ovsienko <denis@ovsienko.info>)
91bd41e8: CI: Synchronize scripts with the master branch. (Denis Ovsienko <denis@ovsienko.info>)
fedd2e03: Fix propagation of cc_werr_cflags() output. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
fb182281: Update the install-sh script to the 2020-11-14.01 version (Rose <83477269+AtariDreams@users.noreply.github....)
51313958: Update the error message when checking for pcap_loop() (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
fa42fbe9: CHANGES: mention a change backported to 1.10. [skip ci] (Guy Harris <gharris@sonic.net>)
8ee84534: doc: fix RADME.Win32.md issues. [skip ci] (Guy Harris <gharris@sonic.net>)
208717ae: CHANGES: Fix an entry (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
ed6dce2e: man: Update the date (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
0ff3fd08: man: Update the -# (--number) option entry (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e61586f7: Fix an error when using update-test.sh with a Geneve test (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
59027674: CHANGES: Add some changes backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d96060f3: smbutil.c: Use the "%Y-%m-%d" date format (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
03199913: ZEP: Use the "%Y-%m-%d" date format (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
f8a83655: RX: Use the "%Y-%m-%d" date format (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
15b38a33: Update the "Error converting time" tests for packet times (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
94366a69: Fix warnings when building for 32-bit and defining _TIME_BITS=64 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
69f03c1c: Update some tests files if the packet time is > 2038-01-19 03:14:07 UTC (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
25218363: Update the GitHub issue template (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
9b275c2c: Update --version option to print 32/64-bit build and time_t size (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e9c0bfe6: Autoconf, CMake: Get the size of a void * and a time_t (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e0a36cd9: tests: Use -tttt option for the tests (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
20cc36b5: GeoNet: Update a test to use the current Ethertype (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d04ed2b6: RADIUS: Rename a test with an invalid length (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
7ea9a544: GeoNet: Rename a test to specify the version (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
b666df03: Autoconf, CMake: Add a warning flag (-Wundef) (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
18c17d1f: Zephyr: Rename a test file by putting zephyr in the name. (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d999b122: 802.15.4: Replace '> 0' with '!= 0' in some unsigned expression tests (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
0e762290: CHANGES: show a bug fix in main and 4.99. [skip ci] (Guy Harris <gharris@sonic.net>)
e9bff173: ppp: use the buffer stack for the de-escaping buffer. (Guy Harris <gharris@sonic.net>)
c4fdecbc: List more contributors in CREDITS. [ckip ci] (Denis Ovsienko <denis@ovsienko.info>)
e1d973a9: CHANGES: Add a change backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
512392d8: Capsicum support: Fix a 'not defined' macro error (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
272ca7ea: TCP: Add a missing extension string (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
8b8f8756: CHANGES: Add two changes backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
6f162d61: Multilink Frame Relay: Fix the Timestamp Information Element printing (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
68ea9775: IPv6: Use "header+payload length" in two messages (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
43b5bb07: ICMPv6: Fix printing the Home Agent Address Discovery Reply Message (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d0999e31: Fix a typo in CHANGES. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
483d14e7: CHANGES: more synchronization with main. [skip ci] (Guy Harris <gharris@sonic.net>)
6a436a5c: CHANGES: fix capitalization and indentation. [skip ci] (Guy Harris <gharris@sonic.net>)
3776ec31: CHANGES: add fix backported to 4.99 from a bigger main-branch change. [s... (Guy Harris <gharris@sonic.net>)
7cbe59ac: ospf: pad TLVs in LS_OPAQUE_TYPE_RI to multiples of 4 bytes. (Guy Harris <gharris@sonic.net>)
47e9bd2d: CHANGES: move a change that's been backported to 4.99. [skip ci] (Guy Harris <gharris@sonic.net>)
1f563c19: domain: handle too-short URI RRs correctly. (Guy Harris <gharris@sonic.net>)
93b107bb: domain: make sure the URI RR has a length of at least 4 bytes. (Guy Harris <gharris@sonic.net>)
8cf21a46: Untangle detection of pcap_findalldevs(). (Denis Ovsienko <denis@ovsienko.info>)
2f4f63b7: doc: Update Haiku particulars. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
0ef31b86: tcpdump.c: fix a comment.  [skip ci] (Guy Harris <gharris@sonic.net>)
12d1086a: README.haiku.md: we now require the latest Clang version. [skip ci] (Guy Harris <gharris@sonic.net>)
0cfcbc6d: doc: Update Clang in README.haiku.md. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
f9f7bdcb: Fixup the previous commit. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
b4ca222a: doc: Add initial README file for Haiku. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
9818a88a: configure: don't use egrep, use $EGREP. (Guy Harris <gharris@sonic.net>)
dd129d21: build_common: fix missing ldd on Haiku (David Karoly <david.karoly@outlook.com>)
1773d7da: TESTrun: Update Windows executable name to tcpdump.exe (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
c2df1790: TESTrun: Fix typos in the Windows code path (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
bcae245d: TESTrun: Use more 'newdir' and 'diffdir' variables (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
45b74a2f: IPv6: Add a test file with missing Jumbo Payload option (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
3d74bb58: Extend "make shellcheck" onto autogen.sh (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d8669b7e: Makefile.in: Move config.h.in~ configure~ configure.ac~ in clean target (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
03c3fad2: Makefile.in: don't remove configure and config.h.in in make distclean. (Guy Harris <gharris@sonic.net>)
243be465: Autoconf: Add autogen.sh, remove configure and config.h.in (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
ec947b8c: build_matrix.sh: Fix a shellcheck note (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
0ac492b9: Makefile.in: Add the Coverity Scan script to the shellcheck target (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
343fe888: .ci-coverity-scan-build.sh: Fix two shellcheck notes (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
a3d46170: Cirrus CI: drop FreeBSD 12.4 and add FreeBSD 14.0 (Ed Maste <emaste@FreeBSD.org>)
ab2d1be9: Autoconf: Update config.{guess,sub}, timestamps 2024-01-01 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
ac9ca499: ISAKMP: Fix printing Delete payload SPI when size is zero (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
4ca9a64a: Remove some useless "ethertype.h" includes (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
650f1434: SOME/IP: Remove an useless "udp.h" include (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e845d5ba: Have a #define to squelch -Wunused-result warnings. (Guy Harris <gharris@sonic.net>)
b3f58020: CMake: attempt to suppress deprecation errors. (Guy Harris <gharris@sonic.net>)
87aad6c4: CHANGES: Add a change backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
b9437c44: Initialize tzcode early. (Dag-Erling Smørgrav <des@FreeBSD.org>)
f8854fd1: Remove useless backslash before single-quotes from a string (style) (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
879d7ab9: Use symmetrical quotation characters in error messages (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
553ba27d: status exit codes: Remove a no more used enum value (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e16cfb27: Update LS-Ack printing to not run off the end of the packet (Bill Fenner <fenner@gmail.com>)
3d878026: NFS: Fix a MemorySanitizer error (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
cd600c4e: TCP: Sort #defines in the header file by port number (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
f62e9639: UDP: Fix two macro names in the header file (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
3e59c0b5: NFS: Avoid printing non-ASCII characters (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
deb44292: NFS: Avoid printing non-ASCII characters (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e34de675: NFS: Rename a printer (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
b87316ef: pflog: Fix a macro name (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
229472a7: pflog: Fix the minimum header length (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
21ce1e14: CHANGES: Add some changes backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
4c9a2df0: IP: Enable TSO (TCP Segmentation Offload) support (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
bf70c3ab: Text protocols: Fix printing truncation if it is not the case (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
0a393909: IP: Remove an unused and deprecated option number (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
ebfd00e6: IP: Report another invalid case as invalid, not truncated (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
1e828252: IP: Use ND_ICHECKMSG_ZU() to test the header length (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
27da447b: IP: Report an invalid case as invalid, not truncated (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
269ee0e6: IP: Print the protocol name before any test (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
2e1302f2: CHANGES: Add some changes backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
fd1fce90: IPv6: Print some header fields, even if the header is incomplete (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e0a19593: IPv6: Report another invalid case as invalid, not truncated (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
66650146: IPv6: Report another invalid case as invalid, not truncated (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
1fa692af: IPv6: Use ND_ICHECKMSG_U() to print an invalid version (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d6192666: IPv6: Report some invalid packets as invalid, not truncated (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
16b76979: IPv6: Add a Jumbogram test file (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
1681a1e6: CHANGES: Move a change backported to 4.99 (from the main section) (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
2155f8a5: Makefile.in: Add instrumentation configuration in releasecheck target (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
37ae1bef: autoconf: Add an option to help debugging (--enable-instrument-functions... (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
9a3a64a3: Remove an unnecessary semicolon (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d35e4bf4: man: Fix an example by quoting a filter expression (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
807f202a: CHANGES: Add a change backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
c8b6a749: Makefile.in: Add two "touch .devel" commands in the releasecheck target (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
cfd8d282: CONTRIBUTING.md: Set increasing numbers on lists of items (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
af8e7870: CONTRIBUTING: Number/renumber the items lists (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
1656633b: CONTRIBUTING: update to reflect that we require a C99 compiler. [skip ci... (Guy Harris <gharris@sonic.net>)
a3bb23d1: CONTRIBUTION: mention the nd_ types. (Guy Harris <gharris@sonic.net>)
382502bf: CONTRIBUTING: remove redundant information, add additional information. ... (Guy Harris <gharris@sonic.net>)
446dc7cf: CONTRIBUTING: add more details about GET_*() macros. [skip ci] (Guy Harris <gharris@sonic.net>)
30d0ffec: CONTRIBUTING.md: Update about 'struct tok' usage (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
681d62a2: CHANGES: Updates in the main and 4.99.5 sections (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d981a5c1: Bgp: Fix an undefined behavior when it tries to parse a too-short packet (Bill Fenner <fenner@gmail.com>)
5f60f0fc: pflog: use nd_ types in struct pfloghdr. (Guy Harris <gharris@sonic.net>)
33dd94cb: BOOTP: Fix a typo in a macro name (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d23952af: Fix spelling (Josh Soref <2119212+jsoref@users.noreply.github....)
371dd8a4: Fix a typo in a comment (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
62302263: Makefile.in: Make "depend" target quieter (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
59b65340: Make nd_trunc_longjmp() not static inline. (Guy Harris <gharris@sonic.net>)
66ae1e46: autoconf: Add some warning flags for clang 13 or newer (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e6e2db1c: Autoconf: Get --with-user and --with-chroot right.  [skip appveyor] (Denis Ovsienko <denis@ovsienko.info>)
46e3bdae: Autoconf: Fix --with-user and --with-chroot. [skip appveyor] (Denis Ovsienko <denis@ovsienko.info>)
b6f5ce7d: ptp: Add test for v2.1 packets (Casper Andersson <casper.casan@gmail.com>)
b3949969: ptp: Print majorSdoId field instead of just the first bit (Casper Andersson <casper.casan@gmail.com>)
e52b482d: ptp: Parse major and minor version correctly (Casper Andersson <casper.casan@gmail.com>)
7c5ff63b: DHCPv6: Add DUID-UUID printing (RFC6355) (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
481fe608: DHCPv6: client-id/server-id DUID type 2 correction (Eamon Doyle <eamonjd@arista.com>)
1182dc9a: bootp/dhcp6: DHCPv4/v6 ZTP and SZTP option support (Eamon Doyle <eamonjd@arista.com>)
432c2490: Add a nd_printjn() function (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
705725c2: Fix for backends which doesn't support capsicum. (Hans Petter Selasky <hps@selasky.org>)
a6e78f89: Ignore failures when setting the default "any" device DLL to LINUX_SLL2. (Guy Harris <gharris@sonic.net>)
d1648631: OSPF6: Fix an undefined behavior (Bill Fenner <fenner@gmail.com>)
e736b63e: NFS: A pointer should not be compared to zero (improve code readability) (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d954601e: CARP: Print the protocol name before any GET_() (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
f707282c: DVMRP: Update an error message (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
00e8b701: NSH: Update an error message (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
13e3472b: RT6: Update an error message (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
38b1f027: VTP: Update two error messages (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
fa183743: DTP: Update an error message (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
0f728a14: checksum.c: Remove a now useless include (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
71a26ca2: NTP: Remove three redundant tests with -vv option (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
617c7844: NTP: Remove three redundant tests with -vvv option (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
db56ebef: Makefile.in: Use the variable MAKE instead of the make command (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
7a56570f: lwres: Fix an undefined behavior in pointer arithmetic (Bill Fenner <fenner@gmail.com>)
aec6a425: PPP: Check if there is some data to hexdump (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
36d05440: SNMP: Fix two undefined behaviors (Bill Fenner <fenner@gmail.com>)
1ba8a396: child_cleanup: reap as many child processes as possible (Dominique Martinet <dominique.martinet@atmark-te...)
9c7ab8f6: EAP: Assign ndo_protocol in the eap_print() function (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
07b7c2f5: cdp: only hex-dump unknown TLVs in verbose mode. (Guy Harris <gharris@sonic.net>)
7e381d88: Autoconf: Update a stale comment in aclocal.m4. (Denis Ovsienko <denis@ovsienko.info>)
5909987f: Autoconf: Fix --static-pcap-only test on Solaris 10. [skip appveyor] (Denis Ovsienko <denis@ovsienko.info>)
5a26d4ac: Get Markdown right in the previous change. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
4217fdda: Fix minor issues in INSTALL.md. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
a2000163: Simplify conditional branching in diag-control.h. (Denis Ovsienko <denis@ovsienko.info>)
c16f454b: configure: Apply autoupdate 2.69. [skip appveyor] (Denis Ovsienko <denis@ovsienko.info>)
9c9c4117: Do not require vsnprintf(). (Denis Ovsienko <denis@ovsienko.info>)
d18a0ddb: Require a proof of suitable snprintf(3) implementation. (Denis Ovsienko <denis@ovsienko.info>)
7146ef7a: CMake: improve the comment before project(tcpdump C). [skip ci] (Guy Harris <gharris@sonic.net>)
698bb2f2: Include <time.h> from netdissect.h. (Denis Ovsienko <denis@ovsienko.info>)
512aa3c4: NFLOG: Use correct AF code points on all OSes. (Denis Ovsienko <denis@ovsienko.info>)
975a7880: Remove some unused declarations from aclocal.m4. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
4ac66fa5: Spell INSTALL.md in Autoconf messages. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
005b2613: Fixup a comment in CMakeLists.txt. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
2efa367d: Remove init_crc10_table() and the entourage. (Denis Ovsienko <denis@ovsienko.info>)
ee981db3: arista: update test pcap with hwinfo values (Bill Fenner <fenner@gmail.com>)
235e13d5: man: Lose an excess newline in tcpdump(1). (Denis Ovsienko <denis@ovsienko.info>)
d1e77544: Kerberos: Print the protocol name (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
abc9718d: Kerberos: Remove a redundant bounds check (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
a5fb110d: OpenFlow: Refine more length checks. (Denis Ovsienko <denis@ovsienko.info>)
32510ee6: OpenFlow 1.0: Improve handling of some lengths. (Denis Ovsienko <denis@ovsienko.info>)
5f3ed93e: Update the ND_LCHECK*() macros to ND_ICHECK*() macros (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
95093ac6: IEEE 802.11: include the "TA" field while printing Block Ack Control fra... (Gokul Sivakumar <gokulkumar792@gmail.com>)
a1481bd0: 802.11: make the length in the IE structures a u_int. (Guy Harris <gharris@sonic.net>)
3e8fdd9f: 802.11: no need for an element ID in the structures for IEs. (Guy Harris <gharris@sonic.net>)
3ebc3e78: Fixup formatting in tests/*.tests. (Denis Ovsienko <denis@ovsienko.info>)
f58d1940: ZMTP: Replace custom code with bittok2str(). (Denis Ovsienko <denis@ovsienko.info>)
a7abc20f: Remove some storage class specifier 'register' (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
346f3f6d: RPKI-Router: Refine length and bounds checks. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
459511c8: RIP: Make a couple trivial protocol updates. (Denis Ovsienko <denis@ovsienko.info>)
8d0baf65: OpenFlow 1.0: Fix indentation of PORT_MOD. (Denis Ovsienko <denis@ovsienko.info>)
6d72fd8d: Fix spelling of PTP type SIGNALING (Casper Andersson <casper.casan@gmail.com>)
9e3fa08f: Loopback/CTP: Use the Wayback Machine for the removed specification (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
60a0db5d: CHANGES: Move some changes backported to 4.99 (from the 5.0.0 list) (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
9fec4d6e: Print the supported time stamp types (-J) to stdout instead of stderr (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
dbb86593: Factorize some code (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
52b2294b: Print the list of data link types (-L) to stdout instead of stderr (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
6ce7a14a: CHANGES: Add a change backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
ba2cc21c: tcpdump: plug a memory leak. (Guy Harris <gharris@sonic.net>)
999e7723: man: Document interface and packet type (Janne Heß <janne@hess.ooo>)
c9215998: tcpdump.1.in: Delete Linux 2.0 references (Jesse Rosenstock <jmr@google.com>)
d6e3799e: man: Format "output format" subsections properly. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
e971577f: CHANGES: Add a change backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
75866fb1: Skip privilege dropping when using -Z root on --with-user builds (Martin Willi <martin@strongswan.org>)
393a1b1f: CHANGES: Add two changes backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e6720261: UDP: Test ports < 1024 in port order to select the printer (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
b82644b5: Moved source port equal BCM_LI_PORT to bottom of long if else chain (Jonas Chianu <jchianu@onx-jchianu-02.ciena.com>)
3f718778: CHANGES: Add a change backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
4a2cebac: LDP: Add missing fields of the Common Session Parameters TLV and a fix (Hannes Gredler <hannes@rtbrick.com>)
3d4490a7: Cirrus CI: Take some updates from master (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
c0ee2aa4: IPv6: Print the protocol name before any test (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
55826f1e: Fix a typo in a comment (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
5da3c6c4: Update an OLSR test file to avoid decoding problem in a future update (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
bf7f1f4d: Update a DHCPv6 test file to avoid decoding problem in a future update (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
dc4f0e44: UDP: Sort #defines in header file by port number (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
a1522c48: Clean up indentation (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
1ff4be23: CHANGES: Add a change backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
fdc52a72: TCP: Test ports < 1024 in port order to select the printer (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
f9888d37: Update a test file to avoid decoding problem in a future update (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
7a0ea7bb: Update a BGP test file to avoid decoding problem in a future update (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
d1523d62: Fix a typo in a comment (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
6c1901b5: Fix a typo in a comment (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
acf08565: Fix a typo in a comment (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
90ffd1e6: CHANGES: Add two changes backported to 4.99 (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
34de79d3: Update ND_BYTES_AVAILABLE_AFTER() macro for better accuracy (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
1de7ca1b: Update ND_BYTES_BETWEEN() macro for better accuracy (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
3018f369: Put "}" at beginning of line with "else" to keep a consistent style (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
e4ecc39f: Put "{" at end of line with "else" to keep a consistent style (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
1dc16ccb: Put "{" at end of line with "switch" to keep a consistent style (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
57746a30: Put "{" at end of line with "if" to keep a consistent style (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
0cf1fa7d: Put "{" at end of line with "for" to keep a consistent style (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
29ecc2de: Put "{" at end of line with "while" to keep a consistent style (Francois-Xavier Le Bail <devel.fx.lebail@orange....)
bfcce749: Start tcpdump 4.99.5-PRE_GIT. [skip ci] (Denis Ovsienko <denis@ovsienko.info>)
```

