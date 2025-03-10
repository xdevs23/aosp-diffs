```
7f4f899e2: ANDROID: Add lowmem and hwasan configurations using extra_test_configs (Edward Liaw <edliaw@google.com>)
817acb7e3: ANDROID: Move test definition from vts-testcase/kernel/ltp (Edward Liaw <edliaw@google.com>)
01fd306d6: libswap: fix tst_max_swapfiles() for SWP_SWAPIN_ERROR_NUM (Ajay Kaher <ajay.kaher@broadcom.com>)
cf41f0a51: ANDROID: memcg/regression: toybox swapon and swapoff need paths (Edward Liaw <edliaw@google.com>)
29f4e65e8: cgroup_core02: Requires cgroup2 mounted with nsdelegate (Edward Liaw <edliaw@google.com>)
953774a67: Revert "nft02: Fix initializer element is not a compile-time constant" (Edward Liaw <edliaw@google.com>)
6d391af90: ANDROID: Remove vts scenario_group (Edward Liaw <edliaw@google.com>)
68f2de545: scenario_groups/default: remove io, filecaps and cap_bounds (Po-Hsu Lin <po-hsu.lin@canonical.com>)
d862601d1: LTP 20240524 (Edward Liaw <edliaw@google.com>)
d25f1aad5: ANDROID: Don't build kvm_svm04 (Edward Liaw <edliaw@google.com>)
a21f47355: ANDROID: Add back package list generation (Edward Liaw <edliaw@google.com>)
2be5d01b5: Pin to C99. (Elliott Hughes <enh@google.com>)
4634c8dc0: ANDROID: update kernel timespec checks for Android (Edward Liaw <edliaw@google.com>)
a7558eecf: runtest/mm: create TMPFILE in TMPDIR for mmapstress07 (Edward Liaw <edliaw@google.com>)
178264313: ltp: syscalls: pipe2: Update pipe size check (Kalesh Singh <kaleshsingh@google.com>)
0e72ac7ea: ltp: syscalls: epoll_wait: Work around edge triggered semantics (Kalesh Singh <kaleshsingh@google.com>)
dd6fc8d8e: ltp: security: dirtyc0w_shmem: Fix backing file size (Kalesh Singh <kaleshsingh@google.com>)
85eab5a3f: ltp: syscalls: mincore: Iterate vector in kernel page size granule (Kalesh Singh <kaleshsingh@google.com>)
139a6b89a: ltp: syscalls: fcntl: Clarify default pipe size for previleged user (Kalesh Singh <kaleshsingh@google.com>)
f502aad17: ltp: controllers: memcg: Fix fault granularity (Kalesh Singh <kaleshsingh@google.com>)
a2b6c319b: ltp: syscalls: mlock: Fix fault granularity (Kalesh Singh <kaleshsingh@google.com>)
e5375f640: ltp: syscalls: signal: Fix alignment and size of altstack (Kalesh Singh <kaleshsingh@google.com>)
9f8d8a610: ltp: syscalls: msync: Fix pagemap index (Kalesh Singh <kaleshsingh@google.com>)
347abf561: ltp: Introduce pgsize_helpers.h (Kalesh Singh <kaleshsingh@google.com>)
8f21ebba4: LTP 20240524 (Petr Vorel <pvorel@suse.cz>)
0358f7a27: syscalls/msgstress01: Fix off by one in array access (Cyril Hrubis <chrubis@suse.cz>)
dac76a85f: syscalls/msgstress01: Fix timeouts (Cyril Hrubis <chrubis@suse.cz>)
8a2dca14e: syscalls/msgstress01: Fix the stop logic (Cyril Hrubis <chrubis@suse.cz>)
f888bc21f: sbrk03: Convert to detect support with flags (Petr Vorel <pvorel@suse.cz>)
7e08a58e5: Refactor fork14 using new LTP API (Andrea Cervesato <andrea.cervesato@suse.com>)
56f63e54e: lib: Add .needs_abi_bits (Petr Vorel <pvorel@suse.cz>)
374238e81: tst_kernel.h: Convert docs to sphinx (Petr Vorel <pvorel@suse.cz>)
3ec7b4ebc: libswap: Remove function description (Petr Vorel <pvorel@suse.cz>)
78a6e1f55: libswap: Fix tst_max_swapfiles() for SLE12-SP5 (Petr Vorel <pvorel@suse.cz>)
61ad7ef65: libswap: Split long lines (readability) (Petr Vorel <pvorel@suse.cz>)
6ab10dec5: setsockopt03: Fix typo in docs (Petr Vorel <pvorel@suse.cz>)
3922d75f3: setsockopt03: Convert docs to docparse (Petr Vorel <pvorel@suse.cz>)
e644691d3: docparse: Fix list formatting (Petr Vorel <pvorel@suse.cz>)
1c0bf86a4: getsockname01: Add case for errno EINVAL (Yang Xu <xuyang2018.jy@fujitsu.com>)
5dd33b797: getsockopt01: Add case for errno EINVAL (Yang Xu <xuyang2018.jy@fujitsu.com>)
4850d9a24: tcindex01: Pass if the tcindex module is blacklisted (Martin Doucha <mdoucha@suse.cz>)
ee1bf39b3: tst_netdevice: Add permissive macro for adding traffic filters (Martin Doucha <mdoucha@suse.cz>)
b1e97fd95: readahead01: pass on pidfd (Murphy Zhou <jencce.kernel@gmail.com>)
76c8c04b5: setitimer: Pass the kernel-defined struct __kernel_old_itimerval to sys_... (Mina Chou <minachou@andestech.com>)
7fd200fc3: open_posix_testsuite: Replace old -W command line argument (Detlef Riekenberg <wine.dev@web.de>)
02ef6efd8: syscalls/mlock05: add mlock test for locking and pre-faulting of memory (Filippo Storniolo <fstornio@redhat.com>)
09f729b18: bind: Add negative tests for bind (Yang Xu <xuyang2018.jy@fujitsu.com>)
ba69dd79e: KVM: Add functional test for VMSAVE/VMLOAD instructions (Martin Doucha <mdoucha@suse.cz>)
45069d033: KVM: Implement printf-like formatting for tst_res() and tst_brk() (Martin Doucha <mdoucha@suse.cz>)
8e97c8e56: KVM: Implement strchr() and basic sprintf() (Martin Doucha <mdoucha@suse.cz>)
7e10cebe2: KVM: Disable EBP register use in 32bit code (Martin Doucha <mdoucha@suse.cz>)
ff13d6750: syscalls/mmap08: Use macro TST_EXP_FAIL_PTR_VOID() (Avinesh Kumar <akumar@suse.de>)
11fb88089: syscalls/mmap06: use macro TST_EXP_FAIL_PTR_VOID() (Avinesh Kumar <akumar@suse.de>)
1bddece8b: madvise11: ignore EBUSY for MADV_SOFT_OFFLINE (Li Wang <liwang@redhat.com>)
8c9ecdfbf: wait01: Use TST_EXP_FAIL2() for wait (Petr Vorel <pvorel@suse.cz>)
059cb0233: swapping01: Add sleeps in the loop that dirties the memory (Wei Gao <wegao@suse.com>)
99b3e43c3: doc: Clarify that the only public CI testing is build only (Petr Vorel <pvorel@suse.cz>)
9e9654cf2: doc: Bump minimal supported kernel to 4.4 (Petr Vorel <pvorel@suse.cz>)
947393d25: syscalls: arch_prctl01.c fix compilation on old distros (Cyril Hrubis <chrubis@suse.cz>)
0d9dc994e: runtest: Move io content to ltp-aiodio.part4 (Petr Vorel <pvorel@suse.cz>)
071727828: runtest: Move capability related tests to new capability (Petr Vorel <pvorel@suse.cz>)
c5500841c: Add case about arch_prctl syscall. (lufei <lufei@uniontech.com>)
b3102e21c: doc: Improve TDEBUG docs (Petr Vorel <pvorel@suse.cz>)
7352ba023: hugemmap15: Support RISC-V to do __cache_flush (Hui Min Mina Chou <minachou@andestech.com>)
e59f1a917: doc: Use more common doc for gdb (Petr Vorel <pvorel@suse.cz>)
dc2c4f8bc: doc: Add links to git man pages (Petr Vorel <pvorel@suse.cz>)
095f00ec6: doc: Link modules to kernel doc website (Petr Vorel <pvorel@suse.cz>)
0364c2671: doc: Link kernel file names to git repo on kernel.org (Petr Vorel <pvorel@suse.cz>)
e4260eee6: doc: More link file/directory names to GitHub sources (Petr Vorel <pvorel@suse.cz>)
6052dca5d: ci: Specify only library devel packages (Petr Vorel <pvorel@suse.cz>)
349bab5f0: ci: Fix libaio package rename on Debian (Petr Vorel <pvorel@suse.cz>)
84155fae8: ci: Rename docker build config (Petr Vorel <pvorel@suse.cz>)
180bc2bb9: ci: Run sphinx test only when files changed (Petr Vorel <pvorel@suse.cz>)
3fe59efe4: Add utime07 test (Andrea Cervesato <andrea.cervesato@suse.com>)
b8a5974d3: statx04: Skip STATX_ATTR_COMPRESSED on Bcachefs (Petr Vorel <pvorel@suse.cz>)
67f155054: safe_mmap(): Fix compiler warning in tst_res() format (Martin Doucha <mdoucha@suse.cz>)
7841eed7c: ci: Add sphinx related job (Petr Vorel <pvorel@suse.cz>)
a835b0730: open_posix_testsuite: Avoid non portable GCC extensions without a guard (Detlef Riekenberg via ltp <ltp@lists.linux.it>)
ef286ba37: KVM: Move kvm_pagefault01 to the end of KVM runfile (Martin Doucha <mdoucha@suse.cz>)
27700e7c4: KVM: Add VMSAVE/VMLOAD functions to x86 SVM library (Martin Doucha <mdoucha@suse.cz>)
e93dc2146: KVM: Add system control MSR constants (Martin Doucha <mdoucha@suse.cz>)
320fc82e3: kvm_find_free_descriptor(): Skip descriptor 0 (Martin Doucha <mdoucha@suse.cz>)
29b76a954: kvm_svm02: Fix saved stack segment index value (Martin Doucha <mdoucha@suse.cz>)
90f80322a: Rewrite msgstress testing suite (Cyril Hrubis <chrubis@suse.cz>)
703406ba4: doc: libltpswap: Add kerneldoc (Petr Vorel <pvorel@suse.cz>)
b0343add6: mmap15: Enable in compat mode (Petr Vorel <pvorel@suse.cz>)
dd0e8ded2: tst_test.h: Turn 1 bit tst_test members to unsigned (Petr Vorel <pvorel@suse.cz>)
504bdede6: zram01.sh: Remove unneeded return (Petr Vorel <pvorel@suse.cz>)
96ef4b40a: zram01.sh: Increase timeout for check_read_mem_used_total (Wei Gao <wegao@suse.com>)
8cb61291f: doc: Update building docs section (Petr Vorel <pvorel@suse.cz>)
0a682f1af: sched_stress: Use time_t instead of long for type (Khem Raj <raj.khem@gmail.com>)
f62d2cbc1: kallsyms: Fix docparse formatting (Petr Vorel <pvorel@suse.cz>)
e29c89f6e: kallsyms: Utilize ksymbol table for unauthorized address access (Li Wang <liwang@redhat.com>)
9725496ca: lib: add SAFE_CALLOC macro (Li Wang <liwang@redhat.com>)
1ba882cf3: m4: Remove now unused ltp-nommu-linux.m4 (Cyril Hrubis <chrubis@suse.cz>)
b635fe826: doc: UCLINUX has been removed (Petr Vorel <pvorel@suse.cz>)
81fbc2937: Remove doc/old/nommu-notes.txt (Petr Vorel <pvorel@suse.cz>)
664c0d320: lib: Remove -C option and self_exec.c (Petr Vorel <pvorel@suse.cz>)
7cdb2bedb: syscalls/ustat02: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
be7e87d12: syscalls/sysinfo02: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
5f31b9cf3: syscalls/sigrelse01: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
b6b583098: syscalls/setsid01: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
070b10e84: syscalls/setgroups04: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
b36429dde: syscalls/read02: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
ebbb3c9ce: syscalls/sock*: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
9b02fceb9: syscalls/send*: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
e3e3d0217: syscalls/recv*: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
f3a290e1c: syscalls/pause: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
dba03bf22: syscalls/pipe: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
0dff3d5f7: syscalls/writev05: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
d4063d5fa: syscalls/munmap: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
90b735af7: syscalls/mlockall: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
ae0808881: syscalls/madvise02: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
883a911b3: syscalls/kill: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
aecdb74cb: syscalls/semctl06: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
7464f09b4: syscalls/fcntl: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
e3fc7c44a: syscalls/creat06: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
450309c5b: syscalls/connect01: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
00ca6ec8a: syscalls/clone02: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
ad8ed74aa: tlibio.c: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
e4d3f8551: lib/parse_opts.c: Remove UCLINUX (Petr Vorel <pvorel@suse.cz>)
fca021a2a: tree: Remove FORK_OR_VFORK and tst_vfork() (Petr Vorel <pvorel@suse.cz>)
ebff440f9: test.h: Remove MAP_PRIVATE_EXCEPT_UCLINUX (Petr Vorel <pvorel@suse.cz>)
b6a09758d: make: Remove UCLINUX (nommu detection) (Petr Vorel <pvorel@suse.cz>)
891fee45c: make: Remove WITH_POWER_MANAGEMENT_TESTSUITE (Petr Vorel <pvorel@suse.cz>)
2f13c1364: doc: Link file/directory names to GitHub sources (Petr Vorel <pvorel@suse.cz>)
c240726a6: libswap: Use {SAFE_,}MAKE_MINIMAL_SWAPFILE() (Petr Vorel <pvorel@suse.cz>)
c33f65c39: libswap: Add {SAFE_,}MAKE_SMALL_SWAPFILE() macros (Petr Vorel <pvorel@suse.cz>)
6b791b727: doc: Remove dead link to README.md (Petr Vorel <pvorel@suse.cz>)
ccb072923: doc: Fix link to github repo (Petr Vorel <petr.vorel@gmail.com>)
7248e5c5f: doc: update syscalls statistics (Andrea Cervesato <andrea.cervesato@suse.com>)
f8c922454: lapi: getrandom05: Add getrandom() fallback (Petr Vorel <pvorel@suse.cz>)
b4970ae94: lapi/fs: Replace loff_t with long long (Petr Vorel <pvorel@suse.cz>)
965d1fa3c: tst_safe_macros_inline.h: Add man page + more explicit doc (Petr Vorel <pvorel@suse.cz>)
2cf78f47a: unlink: Add error tests for EPERM and EROFS (Yang Xu <xuyang2018.jy@fujitsu.com>)
d9280782d: getrandom: Add negative tests for getrandom (Yang Xu <xuyang2018.jy@fujitsu.com>)
7c8997c06: gethostname: Add negative test for gethostname (Yang Xu <xuyang2018.jy@fujitsu.com>)
03333e6f8: doc: introduce sphinx extlinks (Andrea Cervesato <andrea.cervesato@suse.com>)
b150e3a21: doc: test_case_tutorial: Fix link (Petr Vorel <pvorel@suse.cz>)
b318e7822: tst_test: Merge needs_cgroup_ctrls C comment into sphinx doc (Petr Vorel <pvorel@suse.cz>)
04cca38b5: mincore02: refactor with new LTP API (Andrea Manzini <andrea.manzini@suse.com>)
c99c5a4be: swapoff0[12]: Remove unneeded tst_brk() (Petr Vorel <pvorel@suse.cz>)
f77ebacb7: libswap: Use tst_res_() instead of tst_res() (Petr Vorel <pvorel@suse.cz>)
2eec2625a: libswap: Move file & line macros to macros (Petr Vorel <pvorel@suse.cz>)
2bec70ce2: doc: documentation: Fix typos (Petr Vorel <pvorel@suse.cz>)
46f4aa523: doc: Add section for C API documentation (Andrea Cervesato <andrea.cervesato@suse.com>)
638934e8b: doc: Documentation usage and development (Andrea Cervesato <andrea.cervesato@suse.com>)
70d3ea085: controllers: remove use of LINE_MAX (Edward Liaw via ltp <ltp@lists.linux.it>)
4961781fd: mremap06: fallocate is not supported on nfsv4.1 or earlier (Samasth Norway Ananda <samasth.norway.ananda@ora...)
b592cdd0d: dnsmasq: Final fix of library inclusion (Petr Vorel <pvorel@suse.cz>)
8f3b7bb06: syscalls: Add test for splicing to /dev/zero and /dev/null (Cyril Hrubis <chrubis@suse.cz>)
a0bf6550e: syscalls: Add test for splicing from /dev/zero and /dev/full (Cyril Hrubis <chrubis@suse.cz>)
a49a7e9d7: dnsmasq: Proper fix of library inclusion (Petr Vorel <pvorel@suse.cz>)
1cb8e3153: dnsmasq: Fix variable initialization (Petr Vorel <pvorel@suse.cz>)
a8e3009e1: getsockopt01: refactor with new LTP API (Andrea Manzini <andrea.manzini@suse.com>)
cce93d3a3: Refactor with new API and merge fcntl27 + fcntl28 (Andrea Manzini <Andrea Manzini andrea.manzini@su...)
8fb231135: Refactor open09.c with new LTP API (Andrea Manzini <andrea.manzini@suse.com>)
0b6ca26f9: refactor fallocate03 with new LTP API (Andrea Manzini <andrea.manzini@suse.com>)
76ed92c1b: waitid10: Add .needs_tmpdir=1 to run test in temporary directory (Hui Min Mina Chou via ltp <ltp@lists.linux.it>)
91feb8458: unlink05: Convert docs to docparse (Petr Vorel <pvorel@suse.cz>)
73c196c24: unlink05: Add identifier name (Petr Vorel <pvorel@suse.cz>)
807ff91c1: getsockname01: refactor with new LTP API (Andrea Manzini <andrea.manzini@suse.com>)
6f97789ca: network/README: Document ping dependencies (Petr Vorel <pvorel@suse.cz>)
64b11656f: tst_net.sh: tst_ping(): check for ping -I support (Petr Vorel <pvorel@suse.cz>)
87d90a00e: doc: Remove make install (Petr Vorel <pvorel@suse.cz>)
0d688b956: .github: Remove GitHub wiki mirroring hook (Petr Vorel <pvorel@suse.cz>)
6cf992812: include: doc: Convert comments into linuxdoc (Cyril Hrubis <chrubis@suse.cz>)
175d91a74: doc: Add more to spelling_wordlist (Cyril Hrubis <chrubis@suse.cz>)
4a72aada8: New LTP documentation (Andrea Cervesato <andrea.cervesato@suse.com>)
0ac55a649: realpath01: Use TST_EXP_FAIL_PTR_NULL (Wei Gao <wegao@suse.com>)
3fef321cb: shmat02: Use TST_EXP_FAIL_PTR_VOID (Wei Gao <wegao@suse.com>)
8995610c3: lib: Add TST_EXP_FAIL_PTR_{NULL,VOID}{,_ARR} macros (Wei Gao <wegao@suse.com>)
4bba73929: test_macros02: Reduce duplicity (Petr Vorel <pvorel@suse.cz>)
ce7060d84: Refactor sigaltstack02.c with new API (Andrea Manzini <andrea.manzini@suse.com>)
42f2c155f: sctp/test_1_to_1_events: memset() struct sctp_event_subscribe (yangfeng <yangfeng@kylinos.cn>)
747fe069f: tree: Fix tst_clone_args initialisation (Petr Vorel <petr.vorel@gmail.com>)
f09c3b0db: Refactor mmap09 test with new LTP API (Andrea Manzini <andrea.manzini@suse.com>)
18ab64692: Refactor gethostbyname_r01 with new API (Andrea Manzini <Andrea Manzini andrea.manzini@su...)
b1f31f4f3: Refactor fcntl08 with new API (Andrea Manzini <andrea.manzini@suse.com>)
350f353d6: fanotify14: fix anonymous pipe testcases (Mete Durlu <meted@linux.ibm.com>)
634376ea6: tst_test_macros.h: Require to pass array size in TST_EXP_FAIL*_ARR() (Petr Vorel <pvorel@suse.cz>)
64bb39076: lib: Add tst_selinux_enforcing() (Petr Vorel <pvorel@suse.cz>)
23e3083b8: getpeername01: Refactor with new LTP API (Andrea Manzini <andrea.manzini@suse.com>)
df933e38b: setpgrp02: refactor with new LTP API (Andrea Manzini <andrea.manzini@suse.com>)
3f571da28: include: Move inline functions to special header (Petr Vorel <pvorel@suse.cz>)
3c3c36f02: tst_safe_macros: Move implementations into C file, rename (Petr Vorel <pvorel@suse.cz>)
67ab430a2: lib: Merge security related sources (Petr Vorel <pvorel@suse.cz>)
d1e742459: syscalls/timer_getoverrun01: use kernel_timer_t type (Jan Stancek <jstancek@redhat.com>)
8ea05b559: swapon01: create 128MB swapfile (Li Wang <liwang@redhat.com>)
f987ffff5: libswap: add two methods to create swapfile (Li Wang <liwang@redhat.com>)
aa33d2bb8: mknod09: Refactor with new API (Andrea Manzini <andrea.manzini@suse.com>)
e2fce8fc6: lib: Add SAFE_SSCANF() (Andrea Manzini <andrea.manzini@suse.com>)
77449d296: getxattr01: Convert to new API (Shiyang Ruan <ruansy.fnst@fujitsu.com>)
bc9b785a6: iopl02: Convert docs to docparse (Yang Xu (Fujitsu) <xuyang2018.jy@fujitsu.com>)
fd3f66831: iopl01: Convert docs to docparse (Yang Xu (Fujitsu) <xuyang2018.jy@fujitsu.com>)
a3dc45fcd: madvise06: set max_runtime to 60 (Li Wang <liwang@redhat.com>)
be4368630: fpathconf01: Fix SPDX license ID (Avinesh Kumar <akumar@suse.de>)
2282da7c4: github: Add issue template (Petr Vorel <pvorel@suse.cz>)
f99740db4: setreuid07: Add missing .needs_tmpdir = 1 (Hui Min Mina Chou via ltp <ltp@lists.linux.it>)
c3f8ace4a: tst_lockdown: Add copyright (Petr Vorel <pvorel@suse.cz>)
3e0648fc5: docparse: Correct spelling mistake (Sebastian Chlad <sebastianchlad@gmail.com>)
dbfe867b4: fpathconf01: Convert to new API (Yang Xu via ltp <ltp@lists.linux.it>)
fc1e87cb8: Add more check points for Review Checklist doc (Wei Gao via ltp <ltp@lists.linux.it>)
690d44d75: make: Delete gitignore.mk (Petr Vorel <pvorel@suse.cz>)
91cee3203: Makefile: Add doc target (Petr Vorel <pvorel@suse.cz>)
d06621fed: tests: Run test_kconfig03 in CI (Petr Vorel <pvorel@suse.cz>)
7ba556640: tst_safe_macros: Fix formatting (Petr Vorel <pvorel@suse.cz>)
6a582f415: doc: Document the oldest supported clang (Petr Vorel <pvorel@suse.cz>)
9b118fea5: lib/newlib_tests: add test_kconfig03 in .gitignore (Li Wang <liwang@redhat.com>)
bc8b87088: stack_clash: make use of tst_kcmdline_parse (Li Wang <liwang@redhat.com>)
3c0b6c7ab: init_module: To handle kernel module signature enforcement (Li Wang <liwang@redhat.com>)
180834982: kconfig: add funtion to parse /proc/cmdline (Li Wang <liwang@redhat.com>)
14c710cae: scenario_groups/default: remove connectors (Xiangyu Chen <xiangyu.chen@windriver.com>)
71f75ca07: tools: fix broken failure-detection when using individual dmesg logs (Li Wang <liwang@redhat.com>)
02109a38b: safe_mount: Temporary clear umask before mount() (Wei Gao <wegao@suse.com>)
ab1c8d16e: memcontrol03: Using clean page cache to avoid dependency on IO rate (Wei Gao <wegao@suse.com>)
f21f1e4ee: tst_fs_setup.c: Add tst_ prefix to new API functions (Petr Vorel <pvorel@suse.cz>)
b78078e90: include: Move new API only functions to new API header (Petr Vorel <pvorel@suse.cz>)
441dcca68: logrotate: Simplify log checking (Petr Vorel <pvorel@suse.cz>)
dd7aa665f: logrotate: Rewrite into new API (lufei <lufei@uniontech.com>)
20ea2221c: send02: Turn docs into docparse (Petr Vorel <pvorel@suse.cz>)
9856625b2: Add shmat04 SysV IPC bug reproducer (Andrea Cervesato <andrea.cervesato@suse.com>)
ff5f945e1: Print prot flag when SAFE_MMAP() fails (Andrea Cervesato <andrea.cervesato@suse.com>)
b366afb64: Add SAFE_MPROTECT() macro (Andrea Cervesato <andrea.cervesato@suse.com>)
9fa305fe3: send02: Fix typo in TINFO message (Petr Vorel <pvorel@suse.cz>)
cbc2d0568: mkdir03: Convert docs to docparse (Petr Vorel <pvorel@suse.cz>)
d824f59a2: Add more testcases in mkdir03 (Andrea Cervesato <andrea.cervesato@suse.com>)
754c518e5: munlockall: re-write test case (Dennis Brendel <dbrendel@redhat.com>)
d6e3d0c44: network: Remove clockdiff01.sh test (Petr Vorel <pvorel@suse.cz>)
37bc7f250: network: Remove telnet01.sh test (Petr Vorel <pvorel@suse.cz>)
4fb5e8e2e: network: remove xinetd_tests.sh (Petr Vorel <pvorel@suse.cz>)
f85a9df7a: network: Remove host01.sh (Petr Vorel <pvorel@suse.cz>)
0b38797a8: getxattr04, 05: Change to docparse comment and typo fixes (Avinesh Kumar <akumar@suse.de>)
dce8b26e2: syscalls/mmap13: Rewrite the test using new API (Avinesh Kumar <akumar@suse.de>)
6f82542fc: libswap.c: Improve calculate swap dev number (Wei Gao <wegao@suse.com>)
ee628efff: include/tst_fs.h: Fix missing header (Petr Vorel <pvorel@suse.cz>)
0f5d8c520: libswap.c: Check free space with correct mnt path (Wei Gao <wegao@suse.com>)
50626b4a1: cgroup_dir_mk: set the umask to '0' before creating the subdir (Li Wang <liwang@redhat.com>)
d95f453ac: statx07.c: set umask to 0 within setup (Wei Gao <wegao@suse.com>)
3c89830fc: pipe15: Adjust fd check for pipe creation (Wenjie Xu <xuwenjie04@baidu.com>)
fc6adb845: pipe15: Avoid SIGSEGV in cleanup (Petr Vorel <pvorel@suse.cz>)
ea1a7e8f1: tree: Relicense GPL-2.0 (v2 only) => GPL-2.0-or-later (Petr Vorel <pvorel@suse.cz>)
75744cf01: tree: Fix SPDX license GPL-2.0-only (Petr Vorel <pvorel@suse.cz>)
e8564a2bc: tree: Fix license GPL-2.0-or-later (Petr Vorel <pvorel@suse.cz>)
4ce197857: setxattr03: Convert docs to docparse (Yang Xu <xuyang2018.jy@fujitsu.com>)
1700062eb: setxattr02: Convert docs to docparse (Yang Xu <xuyang2018.jy@fujitsu.com>)
f487f3e29: setxattr01: Convert docs to docparse (Yang Xu <xuyang2018.jy@fujitsu.com>)
b85c7bca3: getxattr05: Add missing linux tag (Yang Xu <xuyang2018.jy@fujitsu.com>)
ca03a9b92: listxattr03: Convert docs to docparse (Yang Xu <xuyang2018.jy@fujitsu.com>)
f74b8b422: listxattr02: Convert docs to docparse (Yang Xu <xuyang2018.jy@fujitsu.com>)
f47428eee: listxattr01: Convert docs to docparse (Yang Xu <xuyang2018.jy@fujitsu.com>)
697a06a82: ioctl02: Use correct termios structure (Martin Doucha <mdoucha@suse.cz>)
dbd224078: Add fallback for RHEL9 (Yang Xu <xuyang2018.jy@fujitsu.com>)
8fd941649: syscalls/swapon03: Simply this case (Yang Xu <xuyang2018.jy@fujitsu.com>)
cf99f511d: swapon/Makefile: Remove useless section for MAX_SWAPFILES (Yang Xu <xuyang2018.jy@fujitsu.com>)
ee95bc7fc: swaponoff.h: Remove useless header (Yang Xu <xuyang2018.jy@fujitsu.com>)
fe1782ed6: syscalls/swapon03: use tst_max_swapfiles() and GET_USED_SWAPFILES() API (Yang Xu <xuyang2018.jy@fujitsu.com>)
319693d0b: libltpswap: alter tst_count_swaps API (Yang Xu <xuyang2018.jy@fujitsu.com>)
c1b8c011e: libltpswap: Add tst_max_swapfiles API (Yang Xu <xuyang2018.jy@fujitsu.com>)
a3b05b8c7: Use memset() to fill buffers in diotest (Sergey Ulanov via ltp <ltp@lists.linux.it>)
afb6277fb: swapo{n,ff}: Remove useless tag .needs_tmpdir (Petr Vorel <pvorel@suse.cz>)
386844083: include/tst_cmd.h: Improve programming doc (Petr Vorel <pvorel@suse.cz>)
2c89b2f78: include: Add SAFE_CMD() programming doc (Petr Vorel <pvorel@suse.cz>)
928c93ca2: doc/C-Test-API: Reword SAFE_CMD() (Petr Vorel <pvorel@suse.cz>)
7b1c5e0a2: tst_fd: Use raw syscall for fanotify_init() (Edward Liaw <edliaw@google.com>)
e97f41970: move_pages12: compacting memory before each test loop (Li Wang <liwang@redhat.com>)
631b5acd8: doc: Fix typo in constant name (Petr Vorel <pvorel@suse.cz>)
23ec4f144: link05: Use constant for number of links (Petr Vorel <pvorel@suse.cz>)
25ad0c50a: link05: Return on link() failure (Petr Vorel <pvorel@suse.cz>)
58952a874: net.nfs: Fix nfs06.sh runfile entries (Martin Doucha <mdoucha@suse.cz>)
f62beb00d: open07: Convert to new API (Martin Doucha <mdoucha@suse.cz>)
fba66012d: settimeofday02: Simplify test using TST_ macros (Yang Xu <xuyang2018.jy@fujitsu.com>)
512cf0e75: settimeofday01: Convert docs to docparse (Yang Xu <xuyang2018.jy@fujitsu.com>)
5f596e662: Refactor mount02 test using new LTP API (Andrea Cervesato <andrea.cervesato@suse.com>)
a43ab76d6: refactor fcntl29 with new API (Andrea Manzini <ilmanzo@gmail.com>)
82562d5cd: Add test for file truncation over NFS (Martin Doucha <mdoucha@suse.cz>)
1050f12f6: swapon03: swapon() file on mounted filesystem (Petr Vorel <pvorel@suse.cz>)
3f79bcb94: Refactor mount01 test using new LTP API (Andrea Cervesato <andrea.cervesato@suse.com>)
fe4068694: io_submit: Link against libaio only io_submit01 (Petr Vorel <pvorel@suse.cz>)
31b988058: Refactor timer_getoverrun test using new LTP API (Andrea Cervesato <andrea.cervesato@suse.com>)
ab803e8a9: futex_waitv: Convert 32bit timespec struct to 64bit for compatibility mo... (Wei Gao <wegao@suse.com>)
64f7e5604: nfsstat01.sh: Run on all NFS versions, TCP and UDP (Petr Vorel <pvorel@suse.cz>)
17568a518: nfsstat01.sh: Add support for NFSv4* (Petr Vorel <pvorel@suse.cz>)
ee00c2ebe: nfsstat01.sh: Validate parsing /proc/net/rpc/nfs{,d} (Petr Vorel <pvorel@suse.cz>)
36b2baa46: runtest/net.nfs: Rename test names (Petr Vorel <pvorel@suse.cz>)
34cc32bd6: process_state: Enhancement of process state detection (Li Wang <liwang@redhat.com>)
ee6cfd5d9: pwritev2: Convert docs to docparse (Petr Vorel <pvorel@suse.cz>)
15841bafa: waitpid01: Add subtests from waitpid05 (Martin Doucha <mdoucha@suse.cz>)
dcf371c4d: waitpid01: Fix signal value (Petr Vorel <pvorel@suse.cz>)
ef154a8df: swapon03: Fix formatting (Petr Vorel <pvorel@suse.cz>)
8bea380a0: lib: tst_buffers: Fix checkpatch.pl warnings (Petr Vorel <pvorel@suse.cz>)
767ae231b: waitpid04: Convert to new API (Martin Doucha <mdoucha@suse.cz>)
b07ef3bff: libswap: Refactor is_swap_supported function to return status (Li Wang <liwang@redhat.com>)
009a407a0: swapon/off: enable all_filesystem in swap test (Li Wang <liwang@redhat.com>)
6249e87b5: libswap: customize swapfile size (Li Wang <liwang@redhat.com>)
fb3f4c08c: libswap: Introduce file contiguity check (Li Wang <liwang@redhat.com>)
0d85fd1c7: libswap: add function to prealloc contiguous file (Li Wang <liwang@redhat.com>)
f1e2c3bce: swapon01: Improving test with memory limits and swap reporting (Li Wang <liwang@redhat.com>)
a0fb0c3f2: swapon01: Test on all filesystems (Petr Vorel <pvorel@suse.cz>)
9a18d9fbe: libswap: add known swap supported fs check (Li Wang <liwang@redhat.com>)
2a50d18cc: README: Mention -f param for strace (Petr Vorel <pvorel@suse.cz>)
ac69c8125: hugemmap24: Postpone free() (Petr Vorel <pvorel@suse.cz>)
ed5ccf6c1: waitpid01: Test all standard deadly signals (Martin Doucha <mdoucha@suse.cz>)
c6a51e024: inotify: Convert doc to docparse (Petr Vorel <pvorel@suse.cz>)
6bb15044f: ioctl: Convert doc to docparse (Petr Vorel <pvorel@suse.cz>)
2959a26d5: runtest/net.nfs: Restore running nfsstat01.sh on NFSv3 (Petr Vorel <pvorel@suse.cz>)
54fb751b2: nfsstat01.sh: Move local to the beginning of the function (Petr Vorel <pvorel@suse.cz>)
8137e4778: doc: Update C And Shell Test API Comparison table (Petr Vorel <pvorel@suse.cz>)
c5e71f9e2: Increase default appends operations in dio_append (Andrea Cervesato <andrea.cervesato@suse.com>)
3cc510997: Fix dio_append/aiodio_append tests (Andrea Cervesato <andrea.cervesato@suse.com>)
359047c97: fanotify01: Test setting two marks on different filesystems (Amir Goldstein <amir73il@gmail.com>)
711878673: Add test for ASLRn't bug (Martin Doucha <mdoucha@suse.cz>)
9eb8d2dc7: lib: Add tst_is_compat_mode() helper function (Martin Doucha <mdoucha@suse.cz>)
46eb69ffd: execl01.c: set stack to unlimited (Wei Gao <wegao@suse.com>)
222054d4c: lib: Add .ulimit (Wei Gao via ltp <ltp@lists.linux.it>)
491927d79: waitpid03: Convert to new API (Martin Doucha <mdoucha@suse.cz>)
```

