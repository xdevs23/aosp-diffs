```diff
diff --git a/modified/scsi/scsi_proto.h b/modified/scsi/scsi_proto.h
index 501749b..1adf4c0 100644
--- a/modified/scsi/scsi_proto.h
+++ b/modified/scsi/scsi_proto.h
@@ -122,6 +122,7 @@
 #define WRITE_SAME_16	      0x93
 #define ZBC_OUT		      0x94
 #define ZBC_IN		      0x95
+#define WRITE_ATOMIC_16	0x9c
 #define SERVICE_ACTION_BIDIRECTIONAL 0x9d
 #define SERVICE_ACTION_IN_16  0x9e
 #define SERVICE_ACTION_OUT_16 0x9f
diff --git a/original/scsi/scsi_proto.h b/original/scsi/scsi_proto.h
index 843106e..70e1262 100644
--- a/original/scsi/scsi_proto.h
+++ b/original/scsi/scsi_proto.h
@@ -120,6 +120,7 @@
 #define WRITE_SAME_16	      0x93
 #define ZBC_OUT		      0x94
 #define ZBC_IN		      0x95
+#define WRITE_ATOMIC_16	0x9c
 #define SERVICE_ACTION_BIDIRECTIONAL 0x9d
 #define SERVICE_ACTION_IN_16  0x9e
 #define SERVICE_ACTION_OUT_16 0x9f
diff --git a/original/uapi/asm-arm64/asm/unistd.h b/original/uapi/asm-arm64/asm/unistd.h
index ce2ee8f..df36f23 100644
--- a/original/uapi/asm-arm64/asm/unistd.h
+++ b/original/uapi/asm-arm64/asm/unistd.h
@@ -1,25 +1,2 @@
 /* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
-/*
- * Copyright (C) 2012 ARM Ltd.
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
- * GNU General Public License for more details.
- *
- * You should have received a copy of the GNU General Public License
- * along with this program.  If not, see <http://www.gnu.org/licenses/>.
- */
-
-#define __ARCH_WANT_RENAMEAT
-#define __ARCH_WANT_NEW_STAT
-#define __ARCH_WANT_SET_GET_RLIMIT
-#define __ARCH_WANT_TIME32_SYSCALLS
-#define __ARCH_WANT_SYS_CLONE3
-#define __ARCH_WANT_MEMFD_SECRET
-
-#include <asm-generic/unistd.h>
+#include <asm/unistd_64.h>
diff --git a/original/uapi/asm-arm64/asm/unistd_64.h b/original/uapi/asm-arm64/asm/unistd_64.h
new file mode 100644
index 0000000..efc29fc
--- /dev/null
+++ b/original/uapi/asm-arm64/asm/unistd_64.h
@@ -0,0 +1,327 @@
+#ifndef _UAPI_ASM_UNISTD_64_H
+#define _UAPI_ASM_UNISTD_64_H
+
+#define __NR_io_setup 0
+#define __NR_io_destroy 1
+#define __NR_io_submit 2
+#define __NR_io_cancel 3
+#define __NR_io_getevents 4
+#define __NR_setxattr 5
+#define __NR_lsetxattr 6
+#define __NR_fsetxattr 7
+#define __NR_getxattr 8
+#define __NR_lgetxattr 9
+#define __NR_fgetxattr 10
+#define __NR_listxattr 11
+#define __NR_llistxattr 12
+#define __NR_flistxattr 13
+#define __NR_removexattr 14
+#define __NR_lremovexattr 15
+#define __NR_fremovexattr 16
+#define __NR_getcwd 17
+#define __NR_lookup_dcookie 18
+#define __NR_eventfd2 19
+#define __NR_epoll_create1 20
+#define __NR_epoll_ctl 21
+#define __NR_epoll_pwait 22
+#define __NR_dup 23
+#define __NR_dup3 24
+#define __NR_fcntl 25
+#define __NR_inotify_init1 26
+#define __NR_inotify_add_watch 27
+#define __NR_inotify_rm_watch 28
+#define __NR_ioctl 29
+#define __NR_ioprio_set 30
+#define __NR_ioprio_get 31
+#define __NR_flock 32
+#define __NR_mknodat 33
+#define __NR_mkdirat 34
+#define __NR_unlinkat 35
+#define __NR_symlinkat 36
+#define __NR_linkat 37
+#define __NR_renameat 38
+#define __NR_umount2 39
+#define __NR_mount 40
+#define __NR_pivot_root 41
+#define __NR_nfsservctl 42
+#define __NR_statfs 43
+#define __NR_fstatfs 44
+#define __NR_truncate 45
+#define __NR_ftruncate 46
+#define __NR_fallocate 47
+#define __NR_faccessat 48
+#define __NR_chdir 49
+#define __NR_fchdir 50
+#define __NR_chroot 51
+#define __NR_fchmod 52
+#define __NR_fchmodat 53
+#define __NR_fchownat 54
+#define __NR_fchown 55
+#define __NR_openat 56
+#define __NR_close 57
+#define __NR_vhangup 58
+#define __NR_pipe2 59
+#define __NR_quotactl 60
+#define __NR_getdents64 61
+#define __NR_lseek 62
+#define __NR_read 63
+#define __NR_write 64
+#define __NR_readv 65
+#define __NR_writev 66
+#define __NR_pread64 67
+#define __NR_pwrite64 68
+#define __NR_preadv 69
+#define __NR_pwritev 70
+#define __NR_sendfile 71
+#define __NR_pselect6 72
+#define __NR_ppoll 73
+#define __NR_signalfd4 74
+#define __NR_vmsplice 75
+#define __NR_splice 76
+#define __NR_tee 77
+#define __NR_readlinkat 78
+#define __NR_newfstatat 79
+#define __NR_fstat 80
+#define __NR_sync 81
+#define __NR_fsync 82
+#define __NR_fdatasync 83
+#define __NR_sync_file_range 84
+#define __NR_timerfd_create 85
+#define __NR_timerfd_settime 86
+#define __NR_timerfd_gettime 87
+#define __NR_utimensat 88
+#define __NR_acct 89
+#define __NR_capget 90
+#define __NR_capset 91
+#define __NR_personality 92
+#define __NR_exit 93
+#define __NR_exit_group 94
+#define __NR_waitid 95
+#define __NR_set_tid_address 96
+#define __NR_unshare 97
+#define __NR_futex 98
+#define __NR_set_robust_list 99
+#define __NR_get_robust_list 100
+#define __NR_nanosleep 101
+#define __NR_getitimer 102
+#define __NR_setitimer 103
+#define __NR_kexec_load 104
+#define __NR_init_module 105
+#define __NR_delete_module 106
+#define __NR_timer_create 107
+#define __NR_timer_gettime 108
+#define __NR_timer_getoverrun 109
+#define __NR_timer_settime 110
+#define __NR_timer_delete 111
+#define __NR_clock_settime 112
+#define __NR_clock_gettime 113
+#define __NR_clock_getres 114
+#define __NR_clock_nanosleep 115
+#define __NR_syslog 116
+#define __NR_ptrace 117
+#define __NR_sched_setparam 118
+#define __NR_sched_setscheduler 119
+#define __NR_sched_getscheduler 120
+#define __NR_sched_getparam 121
+#define __NR_sched_setaffinity 122
+#define __NR_sched_getaffinity 123
+#define __NR_sched_yield 124
+#define __NR_sched_get_priority_max 125
+#define __NR_sched_get_priority_min 126
+#define __NR_sched_rr_get_interval 127
+#define __NR_restart_syscall 128
+#define __NR_kill 129
+#define __NR_tkill 130
+#define __NR_tgkill 131
+#define __NR_sigaltstack 132
+#define __NR_rt_sigsuspend 133
+#define __NR_rt_sigaction 134
+#define __NR_rt_sigprocmask 135
+#define __NR_rt_sigpending 136
+#define __NR_rt_sigtimedwait 137
+#define __NR_rt_sigqueueinfo 138
+#define __NR_rt_sigreturn 139
+#define __NR_setpriority 140
+#define __NR_getpriority 141
+#define __NR_reboot 142
+#define __NR_setregid 143
+#define __NR_setgid 144
+#define __NR_setreuid 145
+#define __NR_setuid 146
+#define __NR_setresuid 147
+#define __NR_getresuid 148
+#define __NR_setresgid 149
+#define __NR_getresgid 150
+#define __NR_setfsuid 151
+#define __NR_setfsgid 152
+#define __NR_times 153
+#define __NR_setpgid 154
+#define __NR_getpgid 155
+#define __NR_getsid 156
+#define __NR_setsid 157
+#define __NR_getgroups 158
+#define __NR_setgroups 159
+#define __NR_uname 160
+#define __NR_sethostname 161
+#define __NR_setdomainname 162
+#define __NR_getrlimit 163
+#define __NR_setrlimit 164
+#define __NR_getrusage 165
+#define __NR_umask 166
+#define __NR_prctl 167
+#define __NR_getcpu 168
+#define __NR_gettimeofday 169
+#define __NR_settimeofday 170
+#define __NR_adjtimex 171
+#define __NR_getpid 172
+#define __NR_getppid 173
+#define __NR_getuid 174
+#define __NR_geteuid 175
+#define __NR_getgid 176
+#define __NR_getegid 177
+#define __NR_gettid 178
+#define __NR_sysinfo 179
+#define __NR_mq_open 180
+#define __NR_mq_unlink 181
+#define __NR_mq_timedsend 182
+#define __NR_mq_timedreceive 183
+#define __NR_mq_notify 184
+#define __NR_mq_getsetattr 185
+#define __NR_msgget 186
+#define __NR_msgctl 187
+#define __NR_msgrcv 188
+#define __NR_msgsnd 189
+#define __NR_semget 190
+#define __NR_semctl 191
+#define __NR_semtimedop 192
+#define __NR_semop 193
+#define __NR_shmget 194
+#define __NR_shmctl 195
+#define __NR_shmat 196
+#define __NR_shmdt 197
+#define __NR_socket 198
+#define __NR_socketpair 199
+#define __NR_bind 200
+#define __NR_listen 201
+#define __NR_accept 202
+#define __NR_connect 203
+#define __NR_getsockname 204
+#define __NR_getpeername 205
+#define __NR_sendto 206
+#define __NR_recvfrom 207
+#define __NR_setsockopt 208
+#define __NR_getsockopt 209
+#define __NR_shutdown 210
+#define __NR_sendmsg 211
+#define __NR_recvmsg 212
+#define __NR_readahead 213
+#define __NR_brk 214
+#define __NR_munmap 215
+#define __NR_mremap 216
+#define __NR_add_key 217
+#define __NR_request_key 218
+#define __NR_keyctl 219
+#define __NR_clone 220
+#define __NR_execve 221
+#define __NR_mmap 222
+#define __NR_fadvise64 223
+#define __NR_swapon 224
+#define __NR_swapoff 225
+#define __NR_mprotect 226
+#define __NR_msync 227
+#define __NR_mlock 228
+#define __NR_munlock 229
+#define __NR_mlockall 230
+#define __NR_munlockall 231
+#define __NR_mincore 232
+#define __NR_madvise 233
+#define __NR_remap_file_pages 234
+#define __NR_mbind 235
+#define __NR_get_mempolicy 236
+#define __NR_set_mempolicy 237
+#define __NR_migrate_pages 238
+#define __NR_move_pages 239
+#define __NR_rt_tgsigqueueinfo 240
+#define __NR_perf_event_open 241
+#define __NR_accept4 242
+#define __NR_recvmmsg 243
+#define __NR_wait4 260
+#define __NR_prlimit64 261
+#define __NR_fanotify_init 262
+#define __NR_fanotify_mark 263
+#define __NR_name_to_handle_at 264
+#define __NR_open_by_handle_at 265
+#define __NR_clock_adjtime 266
+#define __NR_syncfs 267
+#define __NR_setns 268
+#define __NR_sendmmsg 269
+#define __NR_process_vm_readv 270
+#define __NR_process_vm_writev 271
+#define __NR_kcmp 272
+#define __NR_finit_module 273
+#define __NR_sched_setattr 274
+#define __NR_sched_getattr 275
+#define __NR_renameat2 276
+#define __NR_seccomp 277
+#define __NR_getrandom 278
+#define __NR_memfd_create 279
+#define __NR_bpf 280
+#define __NR_execveat 281
+#define __NR_userfaultfd 282
+#define __NR_membarrier 283
+#define __NR_mlock2 284
+#define __NR_copy_file_range 285
+#define __NR_preadv2 286
+#define __NR_pwritev2 287
+#define __NR_pkey_mprotect 288
+#define __NR_pkey_alloc 289
+#define __NR_pkey_free 290
+#define __NR_statx 291
+#define __NR_io_pgetevents 292
+#define __NR_rseq 293
+#define __NR_kexec_file_load 294
+#define __NR_pidfd_send_signal 424
+#define __NR_io_uring_setup 425
+#define __NR_io_uring_enter 426
+#define __NR_io_uring_register 427
+#define __NR_open_tree 428
+#define __NR_move_mount 429
+#define __NR_fsopen 430
+#define __NR_fsconfig 431
+#define __NR_fsmount 432
+#define __NR_fspick 433
+#define __NR_pidfd_open 434
+#define __NR_clone3 435
+#define __NR_close_range 436
+#define __NR_openat2 437
+#define __NR_pidfd_getfd 438
+#define __NR_faccessat2 439
+#define __NR_process_madvise 440
+#define __NR_epoll_pwait2 441
+#define __NR_mount_setattr 442
+#define __NR_quotactl_fd 443
+#define __NR_landlock_create_ruleset 444
+#define __NR_landlock_add_rule 445
+#define __NR_landlock_restrict_self 446
+#define __NR_memfd_secret 447
+#define __NR_process_mrelease 448
+#define __NR_futex_waitv 449
+#define __NR_set_mempolicy_home_node 450
+#define __NR_cachestat 451
+#define __NR_fchmodat2 452
+#define __NR_map_shadow_stack 453
+#define __NR_futex_wake 454
+#define __NR_futex_wait 455
+#define __NR_futex_requeue 456
+#define __NR_statmount 457
+#define __NR_listmount 458
+#define __NR_lsm_get_self_attr 459
+#define __NR_lsm_set_self_attr 460
+#define __NR_lsm_list_modules 461
+#define __NR_mseal 462
+
+#ifdef __KERNEL__
+#define __NR_syscalls 463
+#endif
+
+#endif /* _UAPI_ASM_UNISTD_64_H */
diff --git a/original/uapi/asm-generic/unistd.h b/original/uapi/asm-generic/unistd.h
index d4cc269..5bf6148 100644
--- a/original/uapi/asm-generic/unistd.h
+++ b/original/uapi/asm-generic/unistd.h
@@ -776,12 +776,8 @@ __SYSCALL(__NR_fsmount, sys_fsmount)
 __SYSCALL(__NR_fspick, sys_fspick)
 #define __NR_pidfd_open 434
 __SYSCALL(__NR_pidfd_open, sys_pidfd_open)
-
-#ifdef __ARCH_WANT_SYS_CLONE3
 #define __NR_clone3 435
 __SYSCALL(__NR_clone3, sys_clone3)
-#endif
-
 #define __NR_close_range 436
 __SYSCALL(__NR_close_range, sys_close_range)
 #define __NR_openat2 437
diff --git a/original/uapi/asm-riscv/asm/hwprobe.h b/original/uapi/asm-riscv/asm/hwprobe.h
index dda76a0..1e153cd 100644
--- a/original/uapi/asm-riscv/asm/hwprobe.h
+++ b/original/uapi/asm-riscv/asm/hwprobe.h
@@ -60,6 +60,18 @@ struct riscv_hwprobe {
 #define		RISCV_HWPROBE_EXT_ZACAS		(1ULL << 34)
 #define		RISCV_HWPROBE_EXT_ZICOND	(1ULL << 35)
 #define		RISCV_HWPROBE_EXT_ZIHINTPAUSE	(1ULL << 36)
+#define		RISCV_HWPROBE_EXT_ZVE32X	(1ULL << 37)
+#define		RISCV_HWPROBE_EXT_ZVE32F	(1ULL << 38)
+#define		RISCV_HWPROBE_EXT_ZVE64X	(1ULL << 39)
+#define		RISCV_HWPROBE_EXT_ZVE64F	(1ULL << 40)
+#define		RISCV_HWPROBE_EXT_ZVE64D	(1ULL << 41)
+#define		RISCV_HWPROBE_EXT_ZIMOP		(1ULL << 42)
+#define		RISCV_HWPROBE_EXT_ZCA		(1ULL << 43)
+#define		RISCV_HWPROBE_EXT_ZCB		(1ULL << 44)
+#define		RISCV_HWPROBE_EXT_ZCD		(1ULL << 45)
+#define		RISCV_HWPROBE_EXT_ZCF		(1ULL << 46)
+#define		RISCV_HWPROBE_EXT_ZCMOP		(1ULL << 47)
+#define		RISCV_HWPROBE_EXT_ZAWRS		(1ULL << 48)
 #define RISCV_HWPROBE_KEY_CPUPERF_0	5
 #define		RISCV_HWPROBE_MISALIGNED_UNKNOWN	(0 << 0)
 #define		RISCV_HWPROBE_MISALIGNED_EMULATED	(1 << 0)
@@ -68,6 +80,14 @@ struct riscv_hwprobe {
 #define		RISCV_HWPROBE_MISALIGNED_UNSUPPORTED	(4 << 0)
 #define		RISCV_HWPROBE_MISALIGNED_MASK		(7 << 0)
 #define RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE	6
+#define RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS	7
+#define RISCV_HWPROBE_KEY_TIME_CSR_FREQ	8
+#define RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF	9
+#define		RISCV_HWPROBE_MISALIGNED_SCALAR_UNKNOWN		0
+#define		RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED	1
+#define		RISCV_HWPROBE_MISALIGNED_SCALAR_SLOW		2
+#define		RISCV_HWPROBE_MISALIGNED_SCALAR_FAST		3
+#define		RISCV_HWPROBE_MISALIGNED_SCALAR_UNSUPPORTED	4
 /* Increase RISCV_HWPROBE_MAX_KEY when adding items. */
 
 /* Flags */
diff --git a/original/uapi/asm-riscv/asm/kvm.h b/original/uapi/asm-riscv/asm/kvm.h
index e878e7c..e97db32 100644
--- a/original/uapi/asm-riscv/asm/kvm.h
+++ b/original/uapi/asm-riscv/asm/kvm.h
@@ -168,6 +168,13 @@ enum KVM_RISCV_ISA_EXT_ID {
 	KVM_RISCV_ISA_EXT_ZTSO,
 	KVM_RISCV_ISA_EXT_ZACAS,
 	KVM_RISCV_ISA_EXT_SSCOFPMF,
+	KVM_RISCV_ISA_EXT_ZIMOP,
+	KVM_RISCV_ISA_EXT_ZCA,
+	KVM_RISCV_ISA_EXT_ZCB,
+	KVM_RISCV_ISA_EXT_ZCD,
+	KVM_RISCV_ISA_EXT_ZCF,
+	KVM_RISCV_ISA_EXT_ZCMOP,
+	KVM_RISCV_ISA_EXT_ZAWRS,
 	KVM_RISCV_ISA_EXT_MAX,
 };
 
diff --git a/original/uapi/asm-riscv/asm/unistd.h b/original/uapi/asm-riscv/asm/unistd.h
index 950ab3f..81896bb 100644
--- a/original/uapi/asm-riscv/asm/unistd.h
+++ b/original/uapi/asm-riscv/asm/unistd.h
@@ -14,41 +14,10 @@
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <https://www.gnu.org/licenses/>.
  */
+#include <asm/bitsperlong.h>
 
-#if defined(__LP64__) && !defined(__SYSCALL_COMPAT)
-#define __ARCH_WANT_NEW_STAT
-#define __ARCH_WANT_SET_GET_RLIMIT
-#endif /* __LP64__ */
-
-#define __ARCH_WANT_SYS_CLONE3
-#define __ARCH_WANT_MEMFD_SECRET
-
-#include <asm-generic/unistd.h>
-
-/*
- * Allows the instruction cache to be flushed from userspace.  Despite RISC-V
- * having a direct 'fence.i' instruction available to userspace (which we
- * can't trap!), that's not actually viable when running on Linux because the
- * kernel might schedule a process on another hart.  There is no way for
- * userspace to handle this without invoking the kernel (as it doesn't know the
- * thread->hart mappings), so we've defined a RISC-V specific system call to
- * flush the instruction cache.
- *
- * __NR_riscv_flush_icache is defined to flush the instruction cache over an
- * address range, with the flush applying to either all threads or just the
- * caller.  We don't currently do anything with the address range, that's just
- * in there for forwards compatibility.
- */
-#ifndef __NR_riscv_flush_icache
-#define __NR_riscv_flush_icache (__NR_arch_specific_syscall + 15)
-#endif
-__SYSCALL(__NR_riscv_flush_icache, sys_riscv_flush_icache)
-
-/*
- * Allows userspace to query the kernel for CPU architecture and
- * microarchitecture details across a given set of CPUs.
- */
-#ifndef __NR_riscv_hwprobe
-#define __NR_riscv_hwprobe (__NR_arch_specific_syscall + 14)
+#if __BITS_PER_LONG == 64
+#include <asm/unistd_64.h>
+#else
+#include <asm/unistd_32.h>
 #endif
-__SYSCALL(__NR_riscv_hwprobe, sys_riscv_hwprobe)
diff --git a/original/uapi/asm-riscv/asm/unistd_32.h b/original/uapi/asm-riscv/asm/unistd_32.h
new file mode 100644
index 0000000..1d67ed1
--- /dev/null
+++ b/original/uapi/asm-riscv/asm/unistd_32.h
@@ -0,0 +1,318 @@
+#ifndef _UAPI_ASM_UNISTD_32_H
+#define _UAPI_ASM_UNISTD_32_H
+
+#define __NR_io_setup 0
+#define __NR_io_destroy 1
+#define __NR_io_submit 2
+#define __NR_io_cancel 3
+#define __NR_setxattr 5
+#define __NR_lsetxattr 6
+#define __NR_fsetxattr 7
+#define __NR_getxattr 8
+#define __NR_lgetxattr 9
+#define __NR_fgetxattr 10
+#define __NR_listxattr 11
+#define __NR_llistxattr 12
+#define __NR_flistxattr 13
+#define __NR_removexattr 14
+#define __NR_lremovexattr 15
+#define __NR_fremovexattr 16
+#define __NR_getcwd 17
+#define __NR_lookup_dcookie 18
+#define __NR_eventfd2 19
+#define __NR_epoll_create1 20
+#define __NR_epoll_ctl 21
+#define __NR_epoll_pwait 22
+#define __NR_dup 23
+#define __NR_dup3 24
+#define __NR_fcntl64 25
+#define __NR_inotify_init1 26
+#define __NR_inotify_add_watch 27
+#define __NR_inotify_rm_watch 28
+#define __NR_ioctl 29
+#define __NR_ioprio_set 30
+#define __NR_ioprio_get 31
+#define __NR_flock 32
+#define __NR_mknodat 33
+#define __NR_mkdirat 34
+#define __NR_unlinkat 35
+#define __NR_symlinkat 36
+#define __NR_linkat 37
+#define __NR_umount2 39
+#define __NR_mount 40
+#define __NR_pivot_root 41
+#define __NR_nfsservctl 42
+#define __NR_statfs64 43
+#define __NR_fstatfs64 44
+#define __NR_truncate64 45
+#define __NR_ftruncate64 46
+#define __NR_fallocate 47
+#define __NR_faccessat 48
+#define __NR_chdir 49
+#define __NR_fchdir 50
+#define __NR_chroot 51
+#define __NR_fchmod 52
+#define __NR_fchmodat 53
+#define __NR_fchownat 54
+#define __NR_fchown 55
+#define __NR_openat 56
+#define __NR_close 57
+#define __NR_vhangup 58
+#define __NR_pipe2 59
+#define __NR_quotactl 60
+#define __NR_getdents64 61
+#define __NR_llseek 62
+#define __NR_read 63
+#define __NR_write 64
+#define __NR_readv 65
+#define __NR_writev 66
+#define __NR_pread64 67
+#define __NR_pwrite64 68
+#define __NR_preadv 69
+#define __NR_pwritev 70
+#define __NR_sendfile64 71
+#define __NR_signalfd4 74
+#define __NR_vmsplice 75
+#define __NR_splice 76
+#define __NR_tee 77
+#define __NR_readlinkat 78
+#define __NR_sync 81
+#define __NR_fsync 82
+#define __NR_fdatasync 83
+#define __NR_sync_file_range 84
+#define __NR_timerfd_create 85
+#define __NR_acct 89
+#define __NR_capget 90
+#define __NR_capset 91
+#define __NR_personality 92
+#define __NR_exit 93
+#define __NR_exit_group 94
+#define __NR_waitid 95
+#define __NR_set_tid_address 96
+#define __NR_unshare 97
+#define __NR_set_robust_list 99
+#define __NR_get_robust_list 100
+#define __NR_getitimer 102
+#define __NR_setitimer 103
+#define __NR_kexec_load 104
+#define __NR_init_module 105
+#define __NR_delete_module 106
+#define __NR_timer_create 107
+#define __NR_timer_getoverrun 109
+#define __NR_timer_delete 111
+#define __NR_syslog 116
+#define __NR_ptrace 117
+#define __NR_sched_setparam 118
+#define __NR_sched_setscheduler 119
+#define __NR_sched_getscheduler 120
+#define __NR_sched_getparam 121
+#define __NR_sched_setaffinity 122
+#define __NR_sched_getaffinity 123
+#define __NR_sched_yield 124
+#define __NR_sched_get_priority_max 125
+#define __NR_sched_get_priority_min 126
+#define __NR_restart_syscall 128
+#define __NR_kill 129
+#define __NR_tkill 130
+#define __NR_tgkill 131
+#define __NR_sigaltstack 132
+#define __NR_rt_sigsuspend 133
+#define __NR_rt_sigaction 134
+#define __NR_rt_sigprocmask 135
+#define __NR_rt_sigpending 136
+#define __NR_rt_sigqueueinfo 138
+#define __NR_rt_sigreturn 139
+#define __NR_setpriority 140
+#define __NR_getpriority 141
+#define __NR_reboot 142
+#define __NR_setregid 143
+#define __NR_setgid 144
+#define __NR_setreuid 145
+#define __NR_setuid 146
+#define __NR_setresuid 147
+#define __NR_getresuid 148
+#define __NR_setresgid 149
+#define __NR_getresgid 150
+#define __NR_setfsuid 151
+#define __NR_setfsgid 152
+#define __NR_times 153
+#define __NR_setpgid 154
+#define __NR_getpgid 155
+#define __NR_getsid 156
+#define __NR_setsid 157
+#define __NR_getgroups 158
+#define __NR_setgroups 159
+#define __NR_uname 160
+#define __NR_sethostname 161
+#define __NR_setdomainname 162
+#define __NR_getrusage 165
+#define __NR_umask 166
+#define __NR_prctl 167
+#define __NR_getcpu 168
+#define __NR_getpid 172
+#define __NR_getppid 173
+#define __NR_getuid 174
+#define __NR_geteuid 175
+#define __NR_getgid 176
+#define __NR_getegid 177
+#define __NR_gettid 178
+#define __NR_sysinfo 179
+#define __NR_mq_open 180
+#define __NR_mq_unlink 181
+#define __NR_mq_notify 184
+#define __NR_mq_getsetattr 185
+#define __NR_msgget 186
+#define __NR_msgctl 187
+#define __NR_msgrcv 188
+#define __NR_msgsnd 189
+#define __NR_semget 190
+#define __NR_semctl 191
+#define __NR_semop 193
+#define __NR_shmget 194
+#define __NR_shmctl 195
+#define __NR_shmat 196
+#define __NR_shmdt 197
+#define __NR_socket 198
+#define __NR_socketpair 199
+#define __NR_bind 200
+#define __NR_listen 201
+#define __NR_accept 202
+#define __NR_connect 203
+#define __NR_getsockname 204
+#define __NR_getpeername 205
+#define __NR_sendto 206
+#define __NR_recvfrom 207
+#define __NR_setsockopt 208
+#define __NR_getsockopt 209
+#define __NR_shutdown 210
+#define __NR_sendmsg 211
+#define __NR_recvmsg 212
+#define __NR_readahead 213
+#define __NR_brk 214
+#define __NR_munmap 215
+#define __NR_mremap 216
+#define __NR_add_key 217
+#define __NR_request_key 218
+#define __NR_keyctl 219
+#define __NR_clone 220
+#define __NR_execve 221
+#define __NR_mmap2 222
+#define __NR_fadvise64_64 223
+#define __NR_swapon 224
+#define __NR_swapoff 225
+#define __NR_mprotect 226
+#define __NR_msync 227
+#define __NR_mlock 228
+#define __NR_munlock 229
+#define __NR_mlockall 230
+#define __NR_munlockall 231
+#define __NR_mincore 232
+#define __NR_madvise 233
+#define __NR_remap_file_pages 234
+#define __NR_mbind 235
+#define __NR_get_mempolicy 236
+#define __NR_set_mempolicy 237
+#define __NR_migrate_pages 238
+#define __NR_move_pages 239
+#define __NR_rt_tgsigqueueinfo 240
+#define __NR_perf_event_open 241
+#define __NR_accept4 242
+#define __NR_riscv_hwprobe 258
+#define __NR_riscv_flush_icache 259
+#define __NR_prlimit64 261
+#define __NR_fanotify_init 262
+#define __NR_fanotify_mark 263
+#define __NR_name_to_handle_at 264
+#define __NR_open_by_handle_at 265
+#define __NR_syncfs 267
+#define __NR_setns 268
+#define __NR_sendmmsg 269
+#define __NR_process_vm_readv 270
+#define __NR_process_vm_writev 271
+#define __NR_kcmp 272
+#define __NR_finit_module 273
+#define __NR_sched_setattr 274
+#define __NR_sched_getattr 275
+#define __NR_renameat2 276
+#define __NR_seccomp 277
+#define __NR_getrandom 278
+#define __NR_memfd_create 279
+#define __NR_bpf 280
+#define __NR_execveat 281
+#define __NR_userfaultfd 282
+#define __NR_membarrier 283
+#define __NR_mlock2 284
+#define __NR_copy_file_range 285
+#define __NR_preadv2 286
+#define __NR_pwritev2 287
+#define __NR_pkey_mprotect 288
+#define __NR_pkey_alloc 289
+#define __NR_pkey_free 290
+#define __NR_statx 291
+#define __NR_rseq 293
+#define __NR_kexec_file_load 294
+#define __NR_clock_gettime64 403
+#define __NR_clock_settime64 404
+#define __NR_clock_adjtime64 405
+#define __NR_clock_getres_time64 406
+#define __NR_clock_nanosleep_time64 407
+#define __NR_timer_gettime64 408
+#define __NR_timer_settime64 409
+#define __NR_timerfd_gettime64 410
+#define __NR_timerfd_settime64 411
+#define __NR_utimensat_time64 412
+#define __NR_pselect6_time64 413
+#define __NR_ppoll_time64 414
+#define __NR_io_pgetevents_time64 416
+#define __NR_recvmmsg_time64 417
+#define __NR_mq_timedsend_time64 418
+#define __NR_mq_timedreceive_time64 419
+#define __NR_semtimedop_time64 420
+#define __NR_rt_sigtimedwait_time64 421
+#define __NR_futex_time64 422
+#define __NR_sched_rr_get_interval_time64 423
+#define __NR_pidfd_send_signal 424
+#define __NR_io_uring_setup 425
+#define __NR_io_uring_enter 426
+#define __NR_io_uring_register 427
+#define __NR_open_tree 428
+#define __NR_move_mount 429
+#define __NR_fsopen 430
+#define __NR_fsconfig 431
+#define __NR_fsmount 432
+#define __NR_fspick 433
+#define __NR_pidfd_open 434
+#define __NR_clone3 435
+#define __NR_close_range 436
+#define __NR_openat2 437
+#define __NR_pidfd_getfd 438
+#define __NR_faccessat2 439
+#define __NR_process_madvise 440
+#define __NR_epoll_pwait2 441
+#define __NR_mount_setattr 442
+#define __NR_quotactl_fd 443
+#define __NR_landlock_create_ruleset 444
+#define __NR_landlock_add_rule 445
+#define __NR_landlock_restrict_self 446
+#define __NR_memfd_secret 447
+#define __NR_process_mrelease 448
+#define __NR_futex_waitv 449
+#define __NR_set_mempolicy_home_node 450
+#define __NR_cachestat 451
+#define __NR_fchmodat2 452
+#define __NR_map_shadow_stack 453
+#define __NR_futex_wake 454
+#define __NR_futex_wait 455
+#define __NR_futex_requeue 456
+#define __NR_statmount 457
+#define __NR_listmount 458
+#define __NR_lsm_get_self_attr 459
+#define __NR_lsm_set_self_attr 460
+#define __NR_lsm_list_modules 461
+#define __NR_mseal 462
+
+#ifdef __KERNEL__
+#define __NR_syscalls 463
+#endif
+
+#endif /* _UAPI_ASM_UNISTD_32_H */
diff --git a/original/uapi/asm-riscv/asm/unistd_64.h b/original/uapi/asm-riscv/asm/unistd_64.h
new file mode 100644
index 0000000..b42cfbb
--- /dev/null
+++ b/original/uapi/asm-riscv/asm/unistd_64.h
@@ -0,0 +1,328 @@
+#ifndef _UAPI_ASM_UNISTD_64_H
+#define _UAPI_ASM_UNISTD_64_H
+
+#define __NR_io_setup 0
+#define __NR_io_destroy 1
+#define __NR_io_submit 2
+#define __NR_io_cancel 3
+#define __NR_io_getevents 4
+#define __NR_setxattr 5
+#define __NR_lsetxattr 6
+#define __NR_fsetxattr 7
+#define __NR_getxattr 8
+#define __NR_lgetxattr 9
+#define __NR_fgetxattr 10
+#define __NR_listxattr 11
+#define __NR_llistxattr 12
+#define __NR_flistxattr 13
+#define __NR_removexattr 14
+#define __NR_lremovexattr 15
+#define __NR_fremovexattr 16
+#define __NR_getcwd 17
+#define __NR_lookup_dcookie 18
+#define __NR_eventfd2 19
+#define __NR_epoll_create1 20
+#define __NR_epoll_ctl 21
+#define __NR_epoll_pwait 22
+#define __NR_dup 23
+#define __NR_dup3 24
+#define __NR_fcntl 25
+#define __NR_inotify_init1 26
+#define __NR_inotify_add_watch 27
+#define __NR_inotify_rm_watch 28
+#define __NR_ioctl 29
+#define __NR_ioprio_set 30
+#define __NR_ioprio_get 31
+#define __NR_flock 32
+#define __NR_mknodat 33
+#define __NR_mkdirat 34
+#define __NR_unlinkat 35
+#define __NR_symlinkat 36
+#define __NR_linkat 37
+#define __NR_umount2 39
+#define __NR_mount 40
+#define __NR_pivot_root 41
+#define __NR_nfsservctl 42
+#define __NR_statfs 43
+#define __NR_fstatfs 44
+#define __NR_truncate 45
+#define __NR_ftruncate 46
+#define __NR_fallocate 47
+#define __NR_faccessat 48
+#define __NR_chdir 49
+#define __NR_fchdir 50
+#define __NR_chroot 51
+#define __NR_fchmod 52
+#define __NR_fchmodat 53
+#define __NR_fchownat 54
+#define __NR_fchown 55
+#define __NR_openat 56
+#define __NR_close 57
+#define __NR_vhangup 58
+#define __NR_pipe2 59
+#define __NR_quotactl 60
+#define __NR_getdents64 61
+#define __NR_lseek 62
+#define __NR_read 63
+#define __NR_write 64
+#define __NR_readv 65
+#define __NR_writev 66
+#define __NR_pread64 67
+#define __NR_pwrite64 68
+#define __NR_preadv 69
+#define __NR_pwritev 70
+#define __NR_sendfile 71
+#define __NR_pselect6 72
+#define __NR_ppoll 73
+#define __NR_signalfd4 74
+#define __NR_vmsplice 75
+#define __NR_splice 76
+#define __NR_tee 77
+#define __NR_readlinkat 78
+#define __NR_newfstatat 79
+#define __NR_fstat 80
+#define __NR_sync 81
+#define __NR_fsync 82
+#define __NR_fdatasync 83
+#define __NR_sync_file_range 84
+#define __NR_timerfd_create 85
+#define __NR_timerfd_settime 86
+#define __NR_timerfd_gettime 87
+#define __NR_utimensat 88
+#define __NR_acct 89
+#define __NR_capget 90
+#define __NR_capset 91
+#define __NR_personality 92
+#define __NR_exit 93
+#define __NR_exit_group 94
+#define __NR_waitid 95
+#define __NR_set_tid_address 96
+#define __NR_unshare 97
+#define __NR_futex 98
+#define __NR_set_robust_list 99
+#define __NR_get_robust_list 100
+#define __NR_nanosleep 101
+#define __NR_getitimer 102
+#define __NR_setitimer 103
+#define __NR_kexec_load 104
+#define __NR_init_module 105
+#define __NR_delete_module 106
+#define __NR_timer_create 107
+#define __NR_timer_gettime 108
+#define __NR_timer_getoverrun 109
+#define __NR_timer_settime 110
+#define __NR_timer_delete 111
+#define __NR_clock_settime 112
+#define __NR_clock_gettime 113
+#define __NR_clock_getres 114
+#define __NR_clock_nanosleep 115
+#define __NR_syslog 116
+#define __NR_ptrace 117
+#define __NR_sched_setparam 118
+#define __NR_sched_setscheduler 119
+#define __NR_sched_getscheduler 120
+#define __NR_sched_getparam 121
+#define __NR_sched_setaffinity 122
+#define __NR_sched_getaffinity 123
+#define __NR_sched_yield 124
+#define __NR_sched_get_priority_max 125
+#define __NR_sched_get_priority_min 126
+#define __NR_sched_rr_get_interval 127
+#define __NR_restart_syscall 128
+#define __NR_kill 129
+#define __NR_tkill 130
+#define __NR_tgkill 131
+#define __NR_sigaltstack 132
+#define __NR_rt_sigsuspend 133
+#define __NR_rt_sigaction 134
+#define __NR_rt_sigprocmask 135
+#define __NR_rt_sigpending 136
+#define __NR_rt_sigtimedwait 137
+#define __NR_rt_sigqueueinfo 138
+#define __NR_rt_sigreturn 139
+#define __NR_setpriority 140
+#define __NR_getpriority 141
+#define __NR_reboot 142
+#define __NR_setregid 143
+#define __NR_setgid 144
+#define __NR_setreuid 145
+#define __NR_setuid 146
+#define __NR_setresuid 147
+#define __NR_getresuid 148
+#define __NR_setresgid 149
+#define __NR_getresgid 150
+#define __NR_setfsuid 151
+#define __NR_setfsgid 152
+#define __NR_times 153
+#define __NR_setpgid 154
+#define __NR_getpgid 155
+#define __NR_getsid 156
+#define __NR_setsid 157
+#define __NR_getgroups 158
+#define __NR_setgroups 159
+#define __NR_uname 160
+#define __NR_sethostname 161
+#define __NR_setdomainname 162
+#define __NR_getrlimit 163
+#define __NR_setrlimit 164
+#define __NR_getrusage 165
+#define __NR_umask 166
+#define __NR_prctl 167
+#define __NR_getcpu 168
+#define __NR_gettimeofday 169
+#define __NR_settimeofday 170
+#define __NR_adjtimex 171
+#define __NR_getpid 172
+#define __NR_getppid 173
+#define __NR_getuid 174
+#define __NR_geteuid 175
+#define __NR_getgid 176
+#define __NR_getegid 177
+#define __NR_gettid 178
+#define __NR_sysinfo 179
+#define __NR_mq_open 180
+#define __NR_mq_unlink 181
+#define __NR_mq_timedsend 182
+#define __NR_mq_timedreceive 183
+#define __NR_mq_notify 184
+#define __NR_mq_getsetattr 185
+#define __NR_msgget 186
+#define __NR_msgctl 187
+#define __NR_msgrcv 188
+#define __NR_msgsnd 189
+#define __NR_semget 190
+#define __NR_semctl 191
+#define __NR_semtimedop 192
+#define __NR_semop 193
+#define __NR_shmget 194
+#define __NR_shmctl 195
+#define __NR_shmat 196
+#define __NR_shmdt 197
+#define __NR_socket 198
+#define __NR_socketpair 199
+#define __NR_bind 200
+#define __NR_listen 201
+#define __NR_accept 202
+#define __NR_connect 203
+#define __NR_getsockname 204
+#define __NR_getpeername 205
+#define __NR_sendto 206
+#define __NR_recvfrom 207
+#define __NR_setsockopt 208
+#define __NR_getsockopt 209
+#define __NR_shutdown 210
+#define __NR_sendmsg 211
+#define __NR_recvmsg 212
+#define __NR_readahead 213
+#define __NR_brk 214
+#define __NR_munmap 215
+#define __NR_mremap 216
+#define __NR_add_key 217
+#define __NR_request_key 218
+#define __NR_keyctl 219
+#define __NR_clone 220
+#define __NR_execve 221
+#define __NR_mmap 222
+#define __NR_fadvise64 223
+#define __NR_swapon 224
+#define __NR_swapoff 225
+#define __NR_mprotect 226
+#define __NR_msync 227
+#define __NR_mlock 228
+#define __NR_munlock 229
+#define __NR_mlockall 230
+#define __NR_munlockall 231
+#define __NR_mincore 232
+#define __NR_madvise 233
+#define __NR_remap_file_pages 234
+#define __NR_mbind 235
+#define __NR_get_mempolicy 236
+#define __NR_set_mempolicy 237
+#define __NR_migrate_pages 238
+#define __NR_move_pages 239
+#define __NR_rt_tgsigqueueinfo 240
+#define __NR_perf_event_open 241
+#define __NR_accept4 242
+#define __NR_recvmmsg 243
+#define __NR_riscv_hwprobe 258
+#define __NR_riscv_flush_icache 259
+#define __NR_wait4 260
+#define __NR_prlimit64 261
+#define __NR_fanotify_init 262
+#define __NR_fanotify_mark 263
+#define __NR_name_to_handle_at 264
+#define __NR_open_by_handle_at 265
+#define __NR_clock_adjtime 266
+#define __NR_syncfs 267
+#define __NR_setns 268
+#define __NR_sendmmsg 269
+#define __NR_process_vm_readv 270
+#define __NR_process_vm_writev 271
+#define __NR_kcmp 272
+#define __NR_finit_module 273
+#define __NR_sched_setattr 274
+#define __NR_sched_getattr 275
+#define __NR_renameat2 276
+#define __NR_seccomp 277
+#define __NR_getrandom 278
+#define __NR_memfd_create 279
+#define __NR_bpf 280
+#define __NR_execveat 281
+#define __NR_userfaultfd 282
+#define __NR_membarrier 283
+#define __NR_mlock2 284
+#define __NR_copy_file_range 285
+#define __NR_preadv2 286
+#define __NR_pwritev2 287
+#define __NR_pkey_mprotect 288
+#define __NR_pkey_alloc 289
+#define __NR_pkey_free 290
+#define __NR_statx 291
+#define __NR_io_pgetevents 292
+#define __NR_rseq 293
+#define __NR_kexec_file_load 294
+#define __NR_pidfd_send_signal 424
+#define __NR_io_uring_setup 425
+#define __NR_io_uring_enter 426
+#define __NR_io_uring_register 427
+#define __NR_open_tree 428
+#define __NR_move_mount 429
+#define __NR_fsopen 430
+#define __NR_fsconfig 431
+#define __NR_fsmount 432
+#define __NR_fspick 433
+#define __NR_pidfd_open 434
+#define __NR_clone3 435
+#define __NR_close_range 436
+#define __NR_openat2 437
+#define __NR_pidfd_getfd 438
+#define __NR_faccessat2 439
+#define __NR_process_madvise 440
+#define __NR_epoll_pwait2 441
+#define __NR_mount_setattr 442
+#define __NR_quotactl_fd 443
+#define __NR_landlock_create_ruleset 444
+#define __NR_landlock_add_rule 445
+#define __NR_landlock_restrict_self 446
+#define __NR_memfd_secret 447
+#define __NR_process_mrelease 448
+#define __NR_futex_waitv 449
+#define __NR_set_mempolicy_home_node 450
+#define __NR_cachestat 451
+#define __NR_fchmodat2 452
+#define __NR_map_shadow_stack 453
+#define __NR_futex_wake 454
+#define __NR_futex_wait 455
+#define __NR_futex_requeue 456
+#define __NR_statmount 457
+#define __NR_listmount 458
+#define __NR_lsm_get_self_attr 459
+#define __NR_lsm_set_self_attr 460
+#define __NR_lsm_list_modules 461
+#define __NR_mseal 462
+
+#ifdef __KERNEL__
+#define __NR_syscalls 463
+#endif
+
+#endif /* _UAPI_ASM_UNISTD_64_H */
diff --git a/original/uapi/asm-x86/asm/kvm.h b/original/uapi/asm-x86/asm/kvm.h
index 9fae1b7..bf57a82 100644
--- a/original/uapi/asm-x86/asm/kvm.h
+++ b/original/uapi/asm-x86/asm/kvm.h
@@ -106,6 +106,7 @@ struct kvm_ioapic_state {
 
 #define KVM_RUN_X86_SMM		 (1 << 0)
 #define KVM_RUN_X86_BUS_LOCK     (1 << 1)
+#define KVM_RUN_X86_GUEST_MODE   (1 << 2)
 
 /* for KVM_GET_REGS and KVM_SET_REGS */
 struct kvm_regs {
@@ -697,6 +698,11 @@ enum sev_cmd_id {
 	/* Second time is the charm; improved versions of the above ioctls.  */
 	KVM_SEV_INIT2,
 
+	/* SNP-specific commands */
+	KVM_SEV_SNP_LAUNCH_START = 100,
+	KVM_SEV_SNP_LAUNCH_UPDATE,
+	KVM_SEV_SNP_LAUNCH_FINISH,
+
 	KVM_SEV_NR_MAX,
 };
 
@@ -824,6 +830,48 @@ struct kvm_sev_receive_update_data {
 	__u32 pad2;
 };
 
+struct kvm_sev_snp_launch_start {
+	__u64 policy;
+	__u8 gosvw[16];
+	__u16 flags;
+	__u8 pad0[6];
+	__u64 pad1[4];
+};
+
+/* Kept in sync with firmware values for simplicity. */
+#define KVM_SEV_SNP_PAGE_TYPE_NORMAL		0x1
+#define KVM_SEV_SNP_PAGE_TYPE_ZERO		0x3
+#define KVM_SEV_SNP_PAGE_TYPE_UNMEASURED	0x4
+#define KVM_SEV_SNP_PAGE_TYPE_SECRETS		0x5
+#define KVM_SEV_SNP_PAGE_TYPE_CPUID		0x6
+
+struct kvm_sev_snp_launch_update {
+	__u64 gfn_start;
+	__u64 uaddr;
+	__u64 len;
+	__u8 type;
+	__u8 pad0;
+	__u16 flags;
+	__u32 pad1;
+	__u64 pad2[4];
+};
+
+#define KVM_SEV_SNP_ID_BLOCK_SIZE	96
+#define KVM_SEV_SNP_ID_AUTH_SIZE	4096
+#define KVM_SEV_SNP_FINISH_DATA_SIZE	32
+
+struct kvm_sev_snp_launch_finish {
+	__u64 id_block_uaddr;
+	__u64 id_auth_uaddr;
+	__u8 id_block_en;
+	__u8 auth_key_en;
+	__u8 vcek_disabled;
+	__u8 host_data[KVM_SEV_SNP_FINISH_DATA_SIZE];
+	__u8 pad0[3];
+	__u16 flags;
+	__u64 pad1[4];
+};
+
 #define KVM_X2APIC_API_USE_32BIT_IDS            (1ULL << 0)
 #define KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK  (1ULL << 1)
 
@@ -874,5 +922,6 @@ struct kvm_hyperv_eventfd {
 #define KVM_X86_SW_PROTECTED_VM	1
 #define KVM_X86_SEV_VM		2
 #define KVM_X86_SEV_ES_VM	3
+#define KVM_X86_SNP_VM		4
 
 #endif /* _ASM_X86_KVM_H */
diff --git a/original/uapi/asm-x86/asm/svm.h b/original/uapi/asm-x86/asm/svm.h
index 80e1df4..1814b41 100644
--- a/original/uapi/asm-x86/asm/svm.h
+++ b/original/uapi/asm-x86/asm/svm.h
@@ -115,6 +115,7 @@
 #define SVM_VMGEXIT_AP_CREATE_ON_INIT		0
 #define SVM_VMGEXIT_AP_CREATE			1
 #define SVM_VMGEXIT_AP_DESTROY			2
+#define SVM_VMGEXIT_SNP_RUN_VMPL		0x80000018
 #define SVM_VMGEXIT_HV_FEATURES			0x8000fffd
 #define SVM_VMGEXIT_TERM_REQUEST		0x8000fffe
 #define SVM_VMGEXIT_TERM_REASON(reason_set, reason_code)	\
diff --git a/original/uapi/asm-x86/asm/unistd_64.h b/original/uapi/asm-x86/asm/unistd_64.h
index b9c5cd5..7fc8789 100644
--- a/original/uapi/asm-x86/asm/unistd_64.h
+++ b/original/uapi/asm-x86/asm/unistd_64.h
@@ -336,6 +336,7 @@
 #define __NR_statx 332
 #define __NR_io_pgetevents 333
 #define __NR_rseq 334
+#define __NR_uretprobe 335
 #define __NR_pidfd_send_signal 424
 #define __NR_io_uring_setup 425
 #define __NR_io_uring_enter 426
diff --git a/original/uapi/asm-x86/asm/unistd_x32.h b/original/uapi/asm-x86/asm/unistd_x32.h
index 1c632b6..644bcdb 100644
--- a/original/uapi/asm-x86/asm/unistd_x32.h
+++ b/original/uapi/asm-x86/asm/unistd_x32.h
@@ -289,6 +289,7 @@
 #define __NR_statx (__X32_SYSCALL_BIT + 332)
 #define __NR_io_pgetevents (__X32_SYSCALL_BIT + 333)
 #define __NR_rseq (__X32_SYSCALL_BIT + 334)
+#define __NR_uretprobe (__X32_SYSCALL_BIT + 335)
 #define __NR_pidfd_send_signal (__X32_SYSCALL_BIT + 424)
 #define __NR_io_uring_setup (__X32_SYSCALL_BIT + 425)
 #define __NR_io_uring_enter (__X32_SYSCALL_BIT + 426)
diff --git a/original/uapi/drm/amdgpu_drm.h b/original/uapi/drm/amdgpu_drm.h
index 96e32da..efe5de6 100644
--- a/original/uapi/drm/amdgpu_drm.h
+++ b/original/uapi/drm/amdgpu_drm.h
@@ -171,6 +171,8 @@ extern "C" {
  * may override the MTYPE selected in AMDGPU_VA_OP_MAP.
  */
 #define AMDGPU_GEM_CREATE_EXT_COHERENT		(1 << 15)
+/* Set PTE.D and recompress during GTT->VRAM moves according to TILING flags. */
+#define AMDGPU_GEM_CREATE_GFX12_DCC		(1 << 16)
 
 struct drm_amdgpu_gem_create_in  {
 	/** the requested memory size */
@@ -392,7 +394,7 @@ struct drm_amdgpu_gem_userptr {
 #define AMDGPU_TILING_NUM_BANKS_SHIFT			21
 #define AMDGPU_TILING_NUM_BANKS_MASK			0x3
 
-/* GFX9 and later: */
+/* GFX9 - GFX11: */
 #define AMDGPU_TILING_SWIZZLE_MODE_SHIFT		0
 #define AMDGPU_TILING_SWIZZLE_MODE_MASK			0x1f
 #define AMDGPU_TILING_DCC_OFFSET_256B_SHIFT		5
@@ -406,6 +408,17 @@ struct drm_amdgpu_gem_userptr {
 #define AMDGPU_TILING_SCANOUT_SHIFT			63
 #define AMDGPU_TILING_SCANOUT_MASK			0x1
 
+/* GFX12 and later: */
+#define AMDGPU_TILING_GFX12_SWIZZLE_MODE_SHIFT			0
+#define AMDGPU_TILING_GFX12_SWIZZLE_MODE_MASK			0x7
+/* These are DCC recompression setting for memory management: */
+#define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT	3
+#define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_MASK	0x3 /* 0:64B, 1:128B, 2:256B */
+#define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_SHIFT		5
+#define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_MASK		0x7 /* CB_COLOR0_INFO.NUMBER_TYPE */
+#define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_SHIFT		8
+#define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_MASK		0x3f /* [0:4]:CB_COLOR0_INFO.FORMAT, [5]:MM */
+
 /* Set/Get helpers for tiling flags. */
 #define AMDGPU_TILING_SET(field, value) \
 	(((__u64)(value) & AMDGPU_TILING_##field##_MASK) << AMDGPU_TILING_##field##_SHIFT)
@@ -1268,6 +1281,16 @@ struct drm_amdgpu_info_gpuvm_fault {
 #define AMDGPU_FAMILY_GC_10_3_6			149 /* GC 10.3.6 */
 #define AMDGPU_FAMILY_GC_10_3_7			151 /* GC 10.3.7 */
 #define AMDGPU_FAMILY_GC_11_5_0			150 /* GC 11.5.0 */
+#define AMDGPU_FAMILY_GC_12_0_0			152 /* GC 12.0.0 */
+
+/* FIXME wrong namespace! */
+struct drm_color_ctm_3x4 {
+	/*
+	 * Conversion matrix with 3x4 dimensions in S31.32 sign-magnitude
+	 * (not two's complement!) format.
+	 */
+	__u64 matrix[12];
+};
 
 #if defined(__cplusplus)
 }
diff --git a/original/uapi/drm/drm_fourcc.h b/original/uapi/drm/drm_fourcc.h
index 84d502e..2d84a80 100644
--- a/original/uapi/drm/drm_fourcc.h
+++ b/original/uapi/drm/drm_fourcc.h
@@ -1476,6 +1476,7 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
 #define AMD_FMT_MOD_TILE_VER_GFX10 2
 #define AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS 3
 #define AMD_FMT_MOD_TILE_VER_GFX11 4
+#define AMD_FMT_MOD_TILE_VER_GFX12 5
 
 /*
  * 64K_S is the same for GFX9/GFX10/GFX10_RBPLUS and hence has GFX9 as canonical
@@ -1486,6 +1487,8 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
 /*
  * 64K_D for non-32 bpp is the same for GFX9/GFX10/GFX10_RBPLUS and hence has
  * GFX9 as canonical version.
+ *
+ * 64K_D_2D on GFX12 is identical to 64K_D on GFX11.
  */
 #define AMD_FMT_MOD_TILE_GFX9_64K_D 10
 #define AMD_FMT_MOD_TILE_GFX9_64K_S_X 25
@@ -1493,6 +1496,21 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
 #define AMD_FMT_MOD_TILE_GFX9_64K_R_X 27
 #define AMD_FMT_MOD_TILE_GFX11_256K_R_X 31
 
+/* Gfx12 swizzle modes:
+ *    0 - LINEAR
+ *    1 - 256B_2D  - 2D block dimensions
+ *    2 - 4KB_2D
+ *    3 - 64KB_2D
+ *    4 - 256KB_2D
+ *    5 - 4KB_3D   - 3D block dimensions
+ *    6 - 64KB_3D
+ *    7 - 256KB_3D
+ */
+#define AMD_FMT_MOD_TILE_GFX12_256B_2D 1
+#define AMD_FMT_MOD_TILE_GFX12_4K_2D 2
+#define AMD_FMT_MOD_TILE_GFX12_64K_2D 3
+#define AMD_FMT_MOD_TILE_GFX12_256K_2D 4
+
 #define AMD_FMT_MOD_DCC_BLOCK_64B 0
 #define AMD_FMT_MOD_DCC_BLOCK_128B 1
 #define AMD_FMT_MOD_DCC_BLOCK_256B 2
diff --git a/original/uapi/drm/drm_mode.h b/original/uapi/drm/drm_mode.h
index 1ca5c7e..d390011 100644
--- a/original/uapi/drm/drm_mode.h
+++ b/original/uapi/drm/drm_mode.h
@@ -846,14 +846,6 @@ struct drm_color_ctm {
 	__u64 matrix[9];
 };
 
-struct drm_color_ctm_3x4 {
-	/*
-	 * Conversion matrix with 3x4 dimensions in S31.32 sign-magnitude
-	 * (not two's complement!) format.
-	 */
-	__u64 matrix[12];
-};
-
 struct drm_color_lut {
 	/*
 	 * Values are mapped linearly to 0.0 - 1.0 range, with 0x0 == 0.0 and
diff --git a/original/uapi/drm/i915_drm.h b/original/uapi/drm/i915_drm.h
index d4d86e5..535cb68 100644
--- a/original/uapi/drm/i915_drm.h
+++ b/original/uapi/drm/i915_drm.h
@@ -2163,6 +2163,15 @@ struct drm_i915_gem_context_param {
  * supports this per context flag.
  */
 #define I915_CONTEXT_PARAM_LOW_LATENCY		0xe
+
+/*
+ * I915_CONTEXT_PARAM_CONTEXT_IMAGE:
+ *
+ * Allows userspace to provide own context images.
+ *
+ * Note that this is a debug API not available on production kernel builds.
+ */
+#define I915_CONTEXT_PARAM_CONTEXT_IMAGE	0xf
 /* Must be kept compact -- no holes and well documented */
 
 	/** @value: Context parameter value to be set or queried */
@@ -2564,6 +2573,24 @@ struct i915_context_param_engines {
 	struct i915_engine_class_instance engines[N__]; \
 } __attribute__((packed)) name__
 
+struct i915_gem_context_param_context_image {
+	/** @engine: Engine class & instance to be configured. */
+	struct i915_engine_class_instance engine;
+
+	/** @flags: One of the supported flags or zero. */
+	__u32 flags;
+#define I915_CONTEXT_IMAGE_FLAG_ENGINE_INDEX (1u << 0)
+
+	/** @size: Size of the image blob pointed to by @image. */
+	__u32 size;
+
+	/** @mbz: Must be zero. */
+	__u32 mbz;
+
+	/** @image: Userspace memory containing the context image. */
+	__u64 image;
+} __attribute__((packed));
+
 /**
  * struct drm_i915_gem_context_create_ext_setparam - Context parameter
  * to set or query during context creation.
diff --git a/original/uapi/drm/ivpu_accel.h b/original/uapi/drm/ivpu_accel.h
index 19a1346..084fb52 100644
--- a/original/uapi/drm/ivpu_accel.h
+++ b/original/uapi/drm/ivpu_accel.h
@@ -1,6 +1,6 @@
 /* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
 /*
- * Copyright (C) 2020-2023 Intel Corporation
+ * Copyright (C) 2020-2024 Intel Corporation
  */
 
 #ifndef __UAPI_IVPU_DRM_H__
@@ -21,6 +21,10 @@ extern "C" {
 #define DRM_IVPU_BO_INFO		  0x03
 #define DRM_IVPU_SUBMIT			  0x05
 #define DRM_IVPU_BO_WAIT		  0x06
+#define DRM_IVPU_METRIC_STREAMER_START	  0x07
+#define DRM_IVPU_METRIC_STREAMER_STOP	  0x08
+#define DRM_IVPU_METRIC_STREAMER_GET_DATA 0x09
+#define DRM_IVPU_METRIC_STREAMER_GET_INFO 0x0a
 
 #define DRM_IOCTL_IVPU_GET_PARAM                                               \
 	DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_GET_PARAM, struct drm_ivpu_param)
@@ -40,6 +44,22 @@ extern "C" {
 #define DRM_IOCTL_IVPU_BO_WAIT                                                 \
 	DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_BO_WAIT, struct drm_ivpu_bo_wait)
 
+#define DRM_IOCTL_IVPU_METRIC_STREAMER_START                                   \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_START,            \
+		 struct drm_ivpu_metric_streamer_start)
+
+#define DRM_IOCTL_IVPU_METRIC_STREAMER_STOP                                    \
+	DRM_IOW(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_STOP,              \
+		struct drm_ivpu_metric_streamer_stop)
+
+#define DRM_IOCTL_IVPU_METRIC_STREAMER_GET_DATA                                \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_GET_DATA,         \
+		 struct drm_ivpu_metric_streamer_get_data)
+
+#define DRM_IOCTL_IVPU_METRIC_STREAMER_GET_INFO                                \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_GET_INFO,         \
+		 struct drm_ivpu_metric_streamer_get_data)
+
 /**
  * DOC: contexts
  *
@@ -336,6 +356,53 @@ struct drm_ivpu_bo_wait {
 	__u32 pad;
 };
 
+/**
+ * struct drm_ivpu_metric_streamer_start - Start collecting metric data
+ */
+struct drm_ivpu_metric_streamer_start {
+	/** @metric_group_mask: Indicates metric streamer instance */
+	__u64 metric_group_mask;
+	/** @sampling_period_ns: Sampling period in nanoseconds */
+	__u64 sampling_period_ns;
+	/**
+	 * @read_period_samples:
+	 *
+	 * Number of samples after which user space will try to read the data.
+	 * Reading the data after significantly longer period may cause data loss.
+	 */
+	__u32 read_period_samples;
+	/** @sample_size: Returned size of a single sample in bytes */
+	__u32 sample_size;
+	/** @max_data_size: Returned max @data_size from %DRM_IOCTL_IVPU_METRIC_STREAMER_GET_DATA */
+	__u32 max_data_size;
+};
+
+/**
+ * struct drm_ivpu_metric_streamer_get_data - Copy collected metric data
+ */
+struct drm_ivpu_metric_streamer_get_data {
+	/** @metric_group_mask: Indicates metric streamer instance */
+	__u64 metric_group_mask;
+	/** @buffer_ptr: A pointer to a destination for the copied data */
+	__u64 buffer_ptr;
+	/** @buffer_size: Size of the destination buffer */
+	__u64 buffer_size;
+	/**
+	 * @data_size: Returned size of copied metric data
+	 *
+	 * If the @buffer_size is zero, returns the amount of data ready to be copied.
+	 */
+	__u64 data_size;
+};
+
+/**
+ * struct drm_ivpu_metric_streamer_stop - Stop collecting metric data
+ */
+struct drm_ivpu_metric_streamer_stop {
+	/** @metric_group_mask: Indicates metric streamer instance */
+	__u64 metric_group_mask;
+};
+
 #if defined(__cplusplus)
 }
 #endif
diff --git a/original/uapi/drm/msm_drm.h b/original/uapi/drm/msm_drm.h
index d8a6b34..3fca72f 100644
--- a/original/uapi/drm/msm_drm.h
+++ b/original/uapi/drm/msm_drm.h
@@ -87,6 +87,7 @@ struct drm_msm_timespec {
 #define MSM_PARAM_VA_START   0x0e  /* RO: start of valid GPU iova range */
 #define MSM_PARAM_VA_SIZE    0x0f  /* RO: size of valid GPU iova range (bytes) */
 #define MSM_PARAM_HIGHEST_BANK_BIT 0x10 /* RO */
+#define MSM_PARAM_RAYTRACING 0x11 /* RO */
 
 /* For backwards compat.  The original support for preemption was based on
  * a single ring per priority level so # of priority levels equals the #
diff --git a/original/uapi/drm/panthor_drm.h b/original/uapi/drm/panthor_drm.h
index 926b1de..e23a7f9 100644
--- a/original/uapi/drm/panthor_drm.h
+++ b/original/uapi/drm/panthor_drm.h
@@ -692,7 +692,11 @@ enum drm_panthor_group_priority {
 	/** @PANTHOR_GROUP_PRIORITY_MEDIUM: Medium priority group. */
 	PANTHOR_GROUP_PRIORITY_MEDIUM,
 
-	/** @PANTHOR_GROUP_PRIORITY_HIGH: High priority group. */
+	/**
+	 * @PANTHOR_GROUP_PRIORITY_HIGH: High priority group.
+	 *
+	 * Requires CAP_SYS_NICE or DRM_MASTER.
+	 */
 	PANTHOR_GROUP_PRIORITY_HIGH,
 };
 
diff --git a/original/uapi/drm/v3d_drm.h b/original/uapi/drm/v3d_drm.h
index dce1835..87fc5bb 100644
--- a/original/uapi/drm/v3d_drm.h
+++ b/original/uapi/drm/v3d_drm.h
@@ -42,6 +42,7 @@ extern "C" {
 #define DRM_V3D_PERFMON_DESTROY                   0x09
 #define DRM_V3D_PERFMON_GET_VALUES                0x0a
 #define DRM_V3D_SUBMIT_CPU                        0x0b
+#define DRM_V3D_PERFMON_GET_COUNTER               0x0c
 
 #define DRM_IOCTL_V3D_SUBMIT_CL           DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_SUBMIT_CL, struct drm_v3d_submit_cl)
 #define DRM_IOCTL_V3D_WAIT_BO             DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_WAIT_BO, struct drm_v3d_wait_bo)
@@ -58,6 +59,8 @@ extern "C" {
 #define DRM_IOCTL_V3D_PERFMON_GET_VALUES  DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_PERFMON_GET_VALUES, \
 						   struct drm_v3d_perfmon_get_values)
 #define DRM_IOCTL_V3D_SUBMIT_CPU          DRM_IOW(DRM_COMMAND_BASE + DRM_V3D_SUBMIT_CPU, struct drm_v3d_submit_cpu)
+#define DRM_IOCTL_V3D_PERFMON_GET_COUNTER DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_PERFMON_GET_COUNTER, \
+						   struct drm_v3d_perfmon_get_counter)
 
 #define DRM_V3D_SUBMIT_CL_FLUSH_CACHE             0x01
 #define DRM_V3D_SUBMIT_EXTENSION		  0x02
@@ -286,6 +289,7 @@ enum drm_v3d_param {
 	DRM_V3D_PARAM_SUPPORTS_PERFMON,
 	DRM_V3D_PARAM_SUPPORTS_MULTISYNC_EXT,
 	DRM_V3D_PARAM_SUPPORTS_CPU_QUEUE,
+	DRM_V3D_PARAM_MAX_PERF_COUNTERS,
 };
 
 struct drm_v3d_get_param {
@@ -599,6 +603,16 @@ struct drm_v3d_submit_cpu {
 	__u64 extensions;
 };
 
+/* The performance counters index represented by this enum are deprecated and
+ * must no longer be used. These counters are only valid for V3D 4.2.
+ *
+ * In order to check for performance counter information,
+ * use DRM_IOCTL_V3D_PERFMON_GET_COUNTER.
+ *
+ * Don't use V3D_PERFCNT_NUM to retrieve the maximum number of performance
+ * counters. You should use DRM_IOCTL_V3D_GET_PARAM with the following
+ * parameter: DRM_V3D_PARAM_MAX_PERF_COUNTERS.
+ */
 enum {
 	V3D_PERFCNT_FEP_VALID_PRIMTS_NO_PIXELS,
 	V3D_PERFCNT_FEP_VALID_PRIMS,
@@ -717,6 +731,40 @@ struct drm_v3d_perfmon_get_values {
 	__u64 values_ptr;
 };
 
+#define DRM_V3D_PERFCNT_MAX_NAME 64
+#define DRM_V3D_PERFCNT_MAX_CATEGORY 32
+#define DRM_V3D_PERFCNT_MAX_DESCRIPTION 256
+
+/**
+ * struct drm_v3d_perfmon_get_counter - ioctl to get the description of a
+ * performance counter
+ *
+ * As userspace needs to retrieve information about the performance counters
+ * available, this IOCTL allows users to get information about a performance
+ * counter (name, category and description).
+ */
+struct drm_v3d_perfmon_get_counter {
+	/*
+	 * Counter ID
+	 *
+	 * Must be smaller than the maximum number of performance counters, which
+	 * can be retrieve through DRM_V3D_PARAM_MAX_PERF_COUNTERS.
+	 */
+	__u8 counter;
+
+	/* Name of the counter */
+	__u8 name[DRM_V3D_PERFCNT_MAX_NAME];
+
+	/* Category of the counter */
+	__u8 category[DRM_V3D_PERFCNT_MAX_CATEGORY];
+
+	/* Description of the counter */
+	__u8 description[DRM_V3D_PERFCNT_MAX_DESCRIPTION];
+
+	/* mbz */
+	__u8 reserved[7];
+};
+
 #if defined(__cplusplus)
 }
 #endif
diff --git a/original/uapi/drm/xe_drm.h b/original/uapi/drm/xe_drm.h
index 1446c3b..db232a2 100644
--- a/original/uapi/drm/xe_drm.h
+++ b/original/uapi/drm/xe_drm.h
@@ -80,6 +80,7 @@ extern "C" {
  *  - &DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY
  *  - &DRM_IOCTL_XE_EXEC
  *  - &DRM_IOCTL_XE_WAIT_USER_FENCE
+ *  - &DRM_IOCTL_XE_OBSERVATION
  */
 
 /*
@@ -100,6 +101,8 @@ extern "C" {
 #define DRM_XE_EXEC_QUEUE_GET_PROPERTY	0x08
 #define DRM_XE_EXEC			0x09
 #define DRM_XE_WAIT_USER_FENCE		0x0a
+#define DRM_XE_OBSERVATION		0x0b
+
 /* Must be kept compact -- no holes */
 
 #define DRM_IOCTL_XE_DEVICE_QUERY		DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_DEVICE_QUERY, struct drm_xe_device_query)
@@ -113,6 +116,7 @@ extern "C" {
 #define DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY	DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_GET_PROPERTY, struct drm_xe_exec_queue_get_property)
 #define DRM_IOCTL_XE_EXEC			DRM_IOW(DRM_COMMAND_BASE + DRM_XE_EXEC, struct drm_xe_exec)
 #define DRM_IOCTL_XE_WAIT_USER_FENCE		DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_WAIT_USER_FENCE, struct drm_xe_wait_user_fence)
+#define DRM_IOCTL_XE_OBSERVATION		DRM_IOW(DRM_COMMAND_BASE + DRM_XE_OBSERVATION, struct drm_xe_observation_param)
 
 /**
  * DOC: Xe IOCTL Extensions
@@ -508,6 +512,7 @@ struct drm_xe_query_gt_list {
  *    containing the following in mask:
  *    ``DSS_COMPUTE    ff ff ff ff 00 00 00 00``
  *    means 32 DSS are available for compute.
+ *  - %DRM_XE_TOPO_L3_BANK - To query the mask of enabled L3 banks
  *  - %DRM_XE_TOPO_EU_PER_DSS - To query the mask of Execution Units (EU)
  *    available per Dual Sub Slices (DSS). For example a query response
  *    containing the following in mask:
@@ -520,6 +525,7 @@ struct drm_xe_query_topology_mask {
 
 #define DRM_XE_TOPO_DSS_GEOMETRY	1
 #define DRM_XE_TOPO_DSS_COMPUTE		2
+#define DRM_XE_TOPO_L3_BANK		3
 #define DRM_XE_TOPO_EU_PER_DSS		4
 	/** @type: type of mask */
 	__u16 type;
@@ -683,6 +689,7 @@ struct drm_xe_device_query {
 #define DRM_XE_DEVICE_QUERY_GT_TOPOLOGY		5
 #define DRM_XE_DEVICE_QUERY_ENGINE_CYCLES	6
 #define DRM_XE_DEVICE_QUERY_UC_FW_VERSION	7
+#define DRM_XE_DEVICE_QUERY_OA_UNITS		8
 	/** @query: The type of data to query */
 	__u32 query;
 
@@ -776,7 +783,13 @@ struct drm_xe_gem_create {
 #define DRM_XE_GEM_CPU_CACHING_WC                      2
 	/**
 	 * @cpu_caching: The CPU caching mode to select for this object. If
-	 * mmaping the object the mode selected here will also be used.
+	 * mmaping the object the mode selected here will also be used. The
+	 * exception is when mapping system memory (including data evicted
+	 * to system) on discrete GPUs. The caching mode selected will
+	 * then be overridden to DRM_XE_GEM_CPU_CACHING_WB, and coherency
+	 * between GPU- and CPU is guaranteed. The caching mode of
+	 * existing CPU-mappings will be updated transparently to
+	 * user-space clients.
 	 */
 	__u16 cpu_caching;
 	/** @pad: MBZ */
@@ -1368,6 +1381,311 @@ struct drm_xe_wait_user_fence {
 	__u64 reserved[2];
 };
 
+/**
+ * enum drm_xe_observation_type - Observation stream types
+ */
+enum drm_xe_observation_type {
+	/** @DRM_XE_OBSERVATION_TYPE_OA: OA observation stream type */
+	DRM_XE_OBSERVATION_TYPE_OA,
+};
+
+/**
+ * enum drm_xe_observation_op - Observation stream ops
+ */
+enum drm_xe_observation_op {
+	/** @DRM_XE_OBSERVATION_OP_STREAM_OPEN: Open an observation stream */
+	DRM_XE_OBSERVATION_OP_STREAM_OPEN,
+
+	/** @DRM_XE_OBSERVATION_OP_ADD_CONFIG: Add observation stream config */
+	DRM_XE_OBSERVATION_OP_ADD_CONFIG,
+
+	/** @DRM_XE_OBSERVATION_OP_REMOVE_CONFIG: Remove observation stream config */
+	DRM_XE_OBSERVATION_OP_REMOVE_CONFIG,
+};
+
+/**
+ * struct drm_xe_observation_param - Input of &DRM_XE_OBSERVATION
+ *
+ * The observation layer enables multiplexing observation streams of
+ * multiple types. The actual params for a particular stream operation are
+ * supplied via the @param pointer (use __copy_from_user to get these
+ * params).
+ */
+struct drm_xe_observation_param {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+	/** @observation_type: observation stream type, of enum @drm_xe_observation_type */
+	__u64 observation_type;
+	/** @observation_op: observation stream op, of enum @drm_xe_observation_op */
+	__u64 observation_op;
+	/** @param: Pointer to actual stream params */
+	__u64 param;
+};
+
+/**
+ * enum drm_xe_observation_ioctls - Observation stream fd ioctl's
+ *
+ * Information exchanged between userspace and kernel for observation fd
+ * ioctl's is stream type specific
+ */
+enum drm_xe_observation_ioctls {
+	/** @DRM_XE_OBSERVATION_IOCTL_ENABLE: Enable data capture for an observation stream */
+	DRM_XE_OBSERVATION_IOCTL_ENABLE = _IO('i', 0x0),
+
+	/** @DRM_XE_OBSERVATION_IOCTL_DISABLE: Disable data capture for a observation stream */
+	DRM_XE_OBSERVATION_IOCTL_DISABLE = _IO('i', 0x1),
+
+	/** @DRM_XE_OBSERVATION_IOCTL_CONFIG: Change observation stream configuration */
+	DRM_XE_OBSERVATION_IOCTL_CONFIG = _IO('i', 0x2),
+
+	/** @DRM_XE_OBSERVATION_IOCTL_STATUS: Return observation stream status */
+	DRM_XE_OBSERVATION_IOCTL_STATUS = _IO('i', 0x3),
+
+	/** @DRM_XE_OBSERVATION_IOCTL_INFO: Return observation stream info */
+	DRM_XE_OBSERVATION_IOCTL_INFO = _IO('i', 0x4),
+};
+
+/**
+ * enum drm_xe_oa_unit_type - OA unit types
+ */
+enum drm_xe_oa_unit_type {
+	/**
+	 * @DRM_XE_OA_UNIT_TYPE_OAG: OAG OA unit. OAR/OAC are considered
+	 * sub-types of OAG. For OAR/OAC, use OAG.
+	 */
+	DRM_XE_OA_UNIT_TYPE_OAG,
+
+	/** @DRM_XE_OA_UNIT_TYPE_OAM: OAM OA unit */
+	DRM_XE_OA_UNIT_TYPE_OAM,
+};
+
+/**
+ * struct drm_xe_oa_unit - describe OA unit
+ */
+struct drm_xe_oa_unit {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @oa_unit_id: OA unit ID */
+	__u32 oa_unit_id;
+
+	/** @oa_unit_type: OA unit type of @drm_xe_oa_unit_type */
+	__u32 oa_unit_type;
+
+	/** @capabilities: OA capabilities bit-mask */
+	__u64 capabilities;
+#define DRM_XE_OA_CAPS_BASE		(1 << 0)
+
+	/** @oa_timestamp_freq: OA timestamp freq */
+	__u64 oa_timestamp_freq;
+
+	/** @reserved: MBZ */
+	__u64 reserved[4];
+
+	/** @num_engines: number of engines in @eci array */
+	__u64 num_engines;
+
+	/** @eci: engines attached to this OA unit */
+	struct drm_xe_engine_class_instance eci[];
+};
+
+/**
+ * struct drm_xe_query_oa_units - describe OA units
+ *
+ * If a query is made with a struct drm_xe_device_query where .query
+ * is equal to DRM_XE_DEVICE_QUERY_OA_UNITS, then the reply uses struct
+ * drm_xe_query_oa_units in .data.
+ *
+ * OA unit properties for all OA units can be accessed using a code block
+ * such as the one below:
+ *
+ * .. code-block:: C
+ *
+ *	struct drm_xe_query_oa_units *qoa;
+ *	struct drm_xe_oa_unit *oau;
+ *	u8 *poau;
+ *
+ *	// malloc qoa and issue DRM_XE_DEVICE_QUERY_OA_UNITS. Then:
+ *	poau = (u8 *)&qoa->oa_units[0];
+ *	for (int i = 0; i < qoa->num_oa_units; i++) {
+ *		oau = (struct drm_xe_oa_unit *)poau;
+ *		// Access 'struct drm_xe_oa_unit' fields here
+ *		poau += sizeof(*oau) + oau->num_engines * sizeof(oau->eci[0]);
+ *	}
+ */
+struct drm_xe_query_oa_units {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+	/** @num_oa_units: number of OA units returned in oau[] */
+	__u32 num_oa_units;
+	/** @pad: MBZ */
+	__u32 pad;
+	/**
+	 * @oa_units: struct @drm_xe_oa_unit array returned for this device.
+	 * Written below as a u64 array to avoid problems with nested flexible
+	 * arrays with some compilers
+	 */
+	__u64 oa_units[];
+};
+
+/**
+ * enum drm_xe_oa_format_type - OA format types as specified in PRM/Bspec
+ * 52198/60942
+ */
+enum drm_xe_oa_format_type {
+	/** @DRM_XE_OA_FMT_TYPE_OAG: OAG report format */
+	DRM_XE_OA_FMT_TYPE_OAG,
+	/** @DRM_XE_OA_FMT_TYPE_OAR: OAR report format */
+	DRM_XE_OA_FMT_TYPE_OAR,
+	/** @DRM_XE_OA_FMT_TYPE_OAM: OAM report format */
+	DRM_XE_OA_FMT_TYPE_OAM,
+	/** @DRM_XE_OA_FMT_TYPE_OAC: OAC report format */
+	DRM_XE_OA_FMT_TYPE_OAC,
+	/** @DRM_XE_OA_FMT_TYPE_OAM_MPEC: OAM SAMEDIA or OAM MPEC report format */
+	DRM_XE_OA_FMT_TYPE_OAM_MPEC,
+	/** @DRM_XE_OA_FMT_TYPE_PEC: PEC report format */
+	DRM_XE_OA_FMT_TYPE_PEC,
+};
+
+/**
+ * enum drm_xe_oa_property_id - OA stream property id's
+ *
+ * Stream params are specified as a chain of @drm_xe_ext_set_property
+ * struct's, with @property values from enum @drm_xe_oa_property_id and
+ * @drm_xe_user_extension base.name set to @DRM_XE_OA_EXTENSION_SET_PROPERTY.
+ * @param field in struct @drm_xe_observation_param points to the first
+ * @drm_xe_ext_set_property struct.
+ *
+ * Exactly the same mechanism is also used for stream reconfiguration using the
+ * @DRM_XE_OBSERVATION_IOCTL_CONFIG observation stream fd ioctl, though only a
+ * subset of properties below can be specified for stream reconfiguration.
+ */
+enum drm_xe_oa_property_id {
+#define DRM_XE_OA_EXTENSION_SET_PROPERTY	0
+	/**
+	 * @DRM_XE_OA_PROPERTY_OA_UNIT_ID: ID of the OA unit on which to open
+	 * the OA stream, see @oa_unit_id in 'struct
+	 * drm_xe_query_oa_units'. Defaults to 0 if not provided.
+	 */
+	DRM_XE_OA_PROPERTY_OA_UNIT_ID = 1,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_SAMPLE_OA: A value of 1 requests inclusion of raw
+	 * OA unit reports or stream samples in a global buffer attached to an
+	 * OA unit.
+	 */
+	DRM_XE_OA_PROPERTY_SAMPLE_OA,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_OA_METRIC_SET: OA metrics defining contents of OA
+	 * reports, previously added via @DRM_XE_OBSERVATION_OP_ADD_CONFIG.
+	 */
+	DRM_XE_OA_PROPERTY_OA_METRIC_SET,
+
+	/** @DRM_XE_OA_PROPERTY_OA_FORMAT: OA counter report format */
+	DRM_XE_OA_PROPERTY_OA_FORMAT,
+	/*
+	 * OA_FORMAT's are specified the same way as in PRM/Bspec 52198/60942,
+	 * in terms of the following quantities: a. enum @drm_xe_oa_format_type
+	 * b. Counter select c. Counter size and d. BC report. Also refer to the
+	 * oa_formats array in drivers/gpu/drm/xe/xe_oa.c.
+	 */
+#define DRM_XE_OA_FORMAT_MASK_FMT_TYPE		(0xffu << 0)
+#define DRM_XE_OA_FORMAT_MASK_COUNTER_SEL	(0xffu << 8)
+#define DRM_XE_OA_FORMAT_MASK_COUNTER_SIZE	(0xffu << 16)
+#define DRM_XE_OA_FORMAT_MASK_BC_REPORT		(0xffu << 24)
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_OA_PERIOD_EXPONENT: Requests periodic OA unit
+	 * sampling with sampling frequency proportional to 2^(period_exponent + 1)
+	 */
+	DRM_XE_OA_PROPERTY_OA_PERIOD_EXPONENT,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_OA_DISABLED: A value of 1 will open the OA
+	 * stream in a DISABLED state (see @DRM_XE_OBSERVATION_IOCTL_ENABLE).
+	 */
+	DRM_XE_OA_PROPERTY_OA_DISABLED,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_EXEC_QUEUE_ID: Open the stream for a specific
+	 * @exec_queue_id. OA queries can be executed on this exec queue.
+	 */
+	DRM_XE_OA_PROPERTY_EXEC_QUEUE_ID,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_OA_ENGINE_INSTANCE: Optional engine instance to
+	 * pass along with @DRM_XE_OA_PROPERTY_EXEC_QUEUE_ID or will default to 0.
+	 */
+	DRM_XE_OA_PROPERTY_OA_ENGINE_INSTANCE,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_NO_PREEMPT: Allow preemption and timeslicing
+	 * to be disabled for the stream exec queue.
+	 */
+	DRM_XE_OA_PROPERTY_NO_PREEMPT,
+};
+
+/**
+ * struct drm_xe_oa_config - OA metric configuration
+ *
+ * Multiple OA configs can be added using @DRM_XE_OBSERVATION_OP_ADD_CONFIG. A
+ * particular config can be specified when opening an OA stream using
+ * @DRM_XE_OA_PROPERTY_OA_METRIC_SET property.
+ */
+struct drm_xe_oa_config {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @uuid: String formatted like "%\08x-%\04x-%\04x-%\04x-%\012x" */
+	char uuid[36];
+
+	/** @n_regs: Number of regs in @regs_ptr */
+	__u32 n_regs;
+
+	/**
+	 * @regs_ptr: Pointer to (register address, value) pairs for OA config
+	 * registers. Expected length of buffer is: (2 * sizeof(u32) * @n_regs).
+	 */
+	__u64 regs_ptr;
+};
+
+/**
+ * struct drm_xe_oa_stream_status - OA stream status returned from
+ * @DRM_XE_OBSERVATION_IOCTL_STATUS observation stream fd ioctl. Userspace can
+ * call the ioctl to query stream status in response to EIO errno from
+ * observation fd read().
+ */
+struct drm_xe_oa_stream_status {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @oa_status: OA stream status (see Bspec 46717/61226) */
+	__u64 oa_status;
+#define DRM_XE_OASTATUS_MMIO_TRG_Q_FULL		(1 << 3)
+#define DRM_XE_OASTATUS_COUNTER_OVERFLOW	(1 << 2)
+#define DRM_XE_OASTATUS_BUFFER_OVERFLOW		(1 << 1)
+#define DRM_XE_OASTATUS_REPORT_LOST		(1 << 0)
+
+	/** @reserved: reserved for future use */
+	__u64 reserved[3];
+};
+
+/**
+ * struct drm_xe_oa_stream_info - OA stream info returned from
+ * @DRM_XE_OBSERVATION_IOCTL_INFO observation stream fd ioctl
+ */
+struct drm_xe_oa_stream_info {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @oa_buf_size: OA buffer size */
+	__u64 oa_buf_size;
+
+	/** @reserved: reserved for future use */
+	__u64 reserved[3];
+};
+
 #if defined(__cplusplus)
 }
 #endif
diff --git a/original/uapi/linux/bpf.h b/original/uapi/linux/bpf.h
index 90706a4..35bcf52 100644
--- a/original/uapi/linux/bpf.h
+++ b/original/uapi/linux/bpf.h
@@ -1425,6 +1425,8 @@ enum {
 #define BPF_F_TEST_RUN_ON_CPU	(1U << 0)
 /* If set, XDP frames will be transmitted after processing */
 #define BPF_F_TEST_XDP_LIVE_FRAMES	(1U << 1)
+/* If set, apply CHECKSUM_COMPLETE to skb and validate the checksum */
+#define BPF_F_TEST_SKB_CHECKSUM_COMPLETE	(1U << 2)
 
 /* type for BPF_ENABLE_STATS */
 enum bpf_stats_type {
@@ -6207,12 +6209,17 @@ union {					\
 	__u64 :64;			\
 } __attribute__((aligned(8)))
 
+/* The enum used in skb->tstamp_type. It specifies the clock type
+ * of the time stored in the skb->tstamp.
+ */
 enum {
-	BPF_SKB_TSTAMP_UNSPEC,
-	BPF_SKB_TSTAMP_DELIVERY_MONO,	/* tstamp has mono delivery time */
-	/* For any BPF_SKB_TSTAMP_* that the bpf prog cannot handle,
-	 * the bpf prog should handle it like BPF_SKB_TSTAMP_UNSPEC
-	 * and try to deduce it by ingress, egress or skb->sk->sk_clockid.
+	BPF_SKB_TSTAMP_UNSPEC = 0,		/* DEPRECATED */
+	BPF_SKB_TSTAMP_DELIVERY_MONO = 1,	/* DEPRECATED */
+	BPF_SKB_CLOCK_REALTIME = 0,
+	BPF_SKB_CLOCK_MONOTONIC = 1,
+	BPF_SKB_CLOCK_TAI = 2,
+	/* For any future BPF_SKB_CLOCK_* that the bpf prog cannot handle,
+	 * the bpf prog can try to deduce it by ingress/egress/skb->sk->sk_clockid.
 	 */
 };
 
diff --git a/original/uapi/linux/btrfs_tree.h b/original/uapi/linux/btrfs_tree.h
index d24e8e1..fc29d27 100644
--- a/original/uapi/linux/btrfs_tree.h
+++ b/original/uapi/linux/btrfs_tree.h
@@ -747,21 +747,9 @@ struct btrfs_raid_stride {
 	__le64 physical;
 } __attribute__ ((__packed__));
 
-/* The stripe_extent::encoding, 1:1 mapping of enum btrfs_raid_types. */
-#define BTRFS_STRIPE_RAID0	1
-#define BTRFS_STRIPE_RAID1	2
-#define BTRFS_STRIPE_DUP	3
-#define BTRFS_STRIPE_RAID10	4
-#define BTRFS_STRIPE_RAID5	5
-#define BTRFS_STRIPE_RAID6	6
-#define BTRFS_STRIPE_RAID1C3	7
-#define BTRFS_STRIPE_RAID1C4	8
-
 struct btrfs_stripe_extent {
-	__u8 encoding;
-	__u8 reserved[7];
 	/* An array of raid strides this stripe is composed of. */
-	struct btrfs_raid_stride strides[];
+	__DECLARE_FLEX_ARRAY(struct btrfs_raid_stride, strides);
 } __attribute__ ((__packed__));
 
 #define BTRFS_HEADER_FLAG_WRITTEN	(1ULL << 0)
@@ -777,6 +765,14 @@ struct btrfs_stripe_extent {
 #define BTRFS_SUPER_FLAG_CHANGING_FSID	(1ULL << 35)
 #define BTRFS_SUPER_FLAG_CHANGING_FSID_V2 (1ULL << 36)
 
+/*
+ * Those are temporaray flags utilized by btrfs-progs to do offline conversion.
+ * They are rejected by kernel.
+ * But still keep them all here to avoid conflicts.
+ */
+#define BTRFS_SUPER_FLAG_CHANGING_BG_TREE	(1ULL << 38)
+#define BTRFS_SUPER_FLAG_CHANGING_DATA_CSUM	(1ULL << 39)
+#define BTRFS_SUPER_FLAG_CHANGING_META_CSUM	(1ULL << 40)
 
 /*
  * items in the extent btree are used to record the objectid of the
diff --git a/original/uapi/linux/can/isotp.h b/original/uapi/linux/can/isotp.h
index 6cde623..bd99091 100644
--- a/original/uapi/linux/can/isotp.h
+++ b/original/uapi/linux/can/isotp.h
@@ -2,7 +2,7 @@
 /*
  * linux/can/isotp.h
  *
- * Definitions for isotp CAN sockets (ISO 15765-2:2016)
+ * Definitions for ISO 15765-2 CAN transport protocol sockets
  *
  * Copyright (c) 2020 Volkswagen Group Electronic Research
  * All rights reserved.
diff --git a/original/uapi/linux/dlm.h b/original/uapi/linux/dlm.h
index e7e905f..4eaf835 100644
--- a/original/uapi/linux/dlm.h
+++ b/original/uapi/linux/dlm.h
@@ -71,6 +71,8 @@ struct dlm_lksb {
 /* DLM_LSFL_TIMEWARN is deprecated and reserved. DO NOT USE! */
 #define DLM_LSFL_TIMEWARN	0x00000002
 #define DLM_LSFL_NEWEXCL     	0x00000008
+/* currently reserved due in-kernel use */
+#define __DLM_LSFL_RESERVED0	0x00000010
 
 
 #endif /* _UAPI__DLM_DOT_H__ */
diff --git a/original/uapi/linux/dma-heap.h b/original/uapi/linux/dma-heap.h
index 6f84fa0..a4cf716 100644
--- a/original/uapi/linux/dma-heap.h
+++ b/original/uapi/linux/dma-heap.h
@@ -19,7 +19,7 @@
 #define DMA_HEAP_VALID_FD_FLAGS (O_CLOEXEC | O_ACCMODE)
 
 /* Currently no heap flags */
-#define DMA_HEAP_VALID_HEAP_FLAGS (0)
+#define DMA_HEAP_VALID_HEAP_FLAGS (0ULL)
 
 /**
  * struct dma_heap_allocation_data - metadata passed from userspace for
diff --git a/original/uapi/linux/ethtool.h b/original/uapi/linux/ethtool.h
index 8733a31..4a0a6e7 100644
--- a/original/uapi/linux/ethtool.h
+++ b/original/uapi/linux/ethtool.h
@@ -752,6 +752,197 @@ enum ethtool_module_power_mode {
 	ETHTOOL_MODULE_POWER_MODE_HIGH,
 };
 
+/**
+ * enum ethtool_c33_pse_ext_state - groups of PSE extended states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION: Group of error_condition states
+ * @ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID: Group of mr_mps_valid states
+ * @ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE: Group of mr_pse_enable states
+ * @ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED: Group of option_detect_ted
+ *	states
+ * @ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM: Group of option_vport_lim states
+ * @ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED: Group of ovld_detected states
+ * @ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE: Group of pd_dll_power_type
+ *	states
+ * @ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE: Group of power_not_available
+ *	states
+ * @ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED: Group of short_detected states
+ */
+enum ethtool_c33_pse_ext_state {
+	ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION = 1,
+	ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID,
+	ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE,
+	ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED,
+	ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM,
+	ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED,
+	ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE,
+	ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE,
+	ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_mr_mps_valid - mr_mps_valid states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_DETECTED_UNDERLOAD: Underload
+ *	state
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_CONNECTION_OPEN: Port is not
+ *	connected
+ *
+ * The PSE monitors either the DC or AC Maintain Power Signature
+ * (MPS, see 33.2.9.1). This variable indicates the presence or absence of
+ * a valid MPS.
+ */
+enum ethtool_c33_pse_ext_substate_mr_mps_valid {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_DETECTED_UNDERLOAD = 1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_CONNECTION_OPEN,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_error_condition - error_condition states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT: Non-existing
+ *	port number
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT: Undefined port
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT: Internal
+ *	hardware fault
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON:
+ *	Communication error after force on
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS: Unknown
+ *	port status
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF: Host
+ *	crash turn off
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN:
+ *	Host crash force shutdown
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE: Configuration
+ *	change
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP: Over
+ *	temperature detected
+ *
+ * error_condition is a variable indicating the status of
+ * implementation-specific fault conditions or optionally other system faults
+ * that prevent the PSE from meeting the specifications in Table 33–11 and that
+ * require the PSE not to source power. These error conditions are different
+ * from those monitored by the state diagrams in Figure 33–10.
+ */
+enum ethtool_c33_pse_ext_substate_error_condition {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT = 1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_mr_pse_enable - mr_pse_enable states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE: Disable
+ *	pin active
+ *
+ * mr_pse_enable is control variable that selects PSE operation and test
+ * functions.
+ */
+enum ethtool_c33_pse_ext_substate_mr_pse_enable {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE = 1,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_option_detect_ted - option_detect_ted
+ *	states functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS: Detection
+ *	in process
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR:
+ *	Connection check error
+ *
+ * option_detect_ted is a variable indicating if detection can be performed
+ * by the PSE during the ted_timer interval.
+ */
+enum ethtool_c33_pse_ext_substate_option_detect_ted {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS = 1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_option_vport_lim - option_vport_lim states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE: Main supply
+ *	voltage is high
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE: Main supply
+ *	voltage is low
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION: Voltage
+ *	injection into the port
+ *
+ * option_vport_lim is an optional variable indicates if VPSE is out of the
+ * operating range during normal operating state.
+ */
+enum ethtool_c33_pse_ext_substate_option_vport_lim {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE = 1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_ovld_detected - ovld_detected states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD: Overload state
+ *
+ * ovld_detected is a variable indicating if the PSE output current has been
+ * in an overload condition (see 33.2.7.6) for at least TCUT of a one-second
+ * sliding time.
+ */
+enum ethtool_c33_pse_ext_substate_ovld_detected {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD = 1,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_power_not_available - power_not_available
+ *	states functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED: Power
+ *	budget exceeded for the controller
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET:
+ *	Configured port power limit exceeded controller power budget
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT:
+ *	Power request from PD exceeds port limit
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT: Power
+ *	denied due to Hardware power limit
+ *
+ * power_not_available is a variable that is asserted in an
+ * implementation-dependent manner when the PSE is no longer capable of
+ * sourcing sufficient power to support the attached PD. Sufficient power
+ * is defined by classification; see 33.2.6.
+ */
+enum ethtool_c33_pse_ext_substate_power_not_available {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED =  1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_short_detected - short_detected states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION: Short
+ *	condition was detected
+ *
+ * short_detected is a variable indicating if the PSE output current has been
+ * in a short circuit condition for TLIM within a sliding window (see 33.2.7.7).
+ */
+enum ethtool_c33_pse_ext_substate_short_detected {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION = 1,
+};
+
 /**
  * enum ethtool_pse_types - Types of PSE controller.
  * @ETHTOOL_PSE_UNKNOWN: Type of PSE controller is unknown
@@ -877,6 +1068,24 @@ enum ethtool_mm_verify_status {
 	ETHTOOL_MM_VERIFY_STATUS_DISABLED,
 };
 
+/**
+ * enum ethtool_module_fw_flash_status - plug-in module firmware flashing status
+ * @ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED: The firmware flashing process has
+ *	started.
+ * @ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS: The firmware flashing process
+ *	is in progress.
+ * @ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED: The firmware flashing process was
+ *	completed successfully.
+ * @ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR: The firmware flashing process was
+ *	stopped due to an error.
+ */
+enum ethtool_module_fw_flash_status {
+	ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED = 1,
+	ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS,
+	ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED,
+	ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR,
+};
+
 /**
  * struct ethtool_gstrings - string set for data tagging
  * @cmd: Command number = %ETHTOOL_GSTRINGS
@@ -1845,6 +2054,7 @@ enum ethtool_link_mode_bit_indices {
 	ETHTOOL_LINK_MODE_10baseT1S_Full_BIT		 = 99,
 	ETHTOOL_LINK_MODE_10baseT1S_Half_BIT		 = 100,
 	ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT	 = 101,
+	ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT		 = 102,
 
 	/* must be last entry */
 	__ETHTOOL_LINK_MODE_MASK_NBITS
diff --git a/original/uapi/linux/ethtool_netlink.h b/original/uapi/linux/ethtool_netlink.h
index b49b804..6d5bdcc 100644
--- a/original/uapi/linux/ethtool_netlink.h
+++ b/original/uapi/linux/ethtool_netlink.h
@@ -57,6 +57,7 @@ enum {
 	ETHTOOL_MSG_PLCA_GET_STATUS,
 	ETHTOOL_MSG_MM_GET,
 	ETHTOOL_MSG_MM_SET,
+	ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
 
 	/* add new constants above here */
 	__ETHTOOL_MSG_USER_CNT,
@@ -109,6 +110,7 @@ enum {
 	ETHTOOL_MSG_PLCA_NTF,
 	ETHTOOL_MSG_MM_GET_REPLY,
 	ETHTOOL_MSG_MM_NTF,
+	ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
 
 	/* add new constants above here */
 	__ETHTOOL_MSG_KERNEL_CNT,
@@ -415,12 +417,34 @@ enum {
 	ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES,		/* u32 */
 	ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES,		/* u32 */
 	ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS,		/* u32 */
+	/* nest - _A_PROFILE_IRQ_MODERATION */
+	ETHTOOL_A_COALESCE_RX_PROFILE,
+	/* nest - _A_PROFILE_IRQ_MODERATION */
+	ETHTOOL_A_COALESCE_TX_PROFILE,
 
 	/* add new constants above here */
 	__ETHTOOL_A_COALESCE_CNT,
 	ETHTOOL_A_COALESCE_MAX = (__ETHTOOL_A_COALESCE_CNT - 1)
 };
 
+enum {
+	ETHTOOL_A_PROFILE_UNSPEC,
+	/* nest, _A_IRQ_MODERATION_* */
+	ETHTOOL_A_PROFILE_IRQ_MODERATION,
+	__ETHTOOL_A_PROFILE_CNT,
+	ETHTOOL_A_PROFILE_MAX = (__ETHTOOL_A_PROFILE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_IRQ_MODERATION_UNSPEC,
+	ETHTOOL_A_IRQ_MODERATION_USEC,			/* u32 */
+	ETHTOOL_A_IRQ_MODERATION_PKTS,			/* u32 */
+	ETHTOOL_A_IRQ_MODERATION_COMPS,			/* u32 */
+
+	__ETHTOOL_A_IRQ_MODERATION_CNT,
+	ETHTOOL_A_IRQ_MODERATION_MAX = (__ETHTOOL_A_IRQ_MODERATION_CNT - 1)
+};
+
 /* PAUSE */
 
 enum {
@@ -906,6 +930,12 @@ enum {
 };
 
 /* Power Sourcing Equipment */
+enum {
+	ETHTOOL_A_C33_PSE_PW_LIMIT_UNSPEC,
+	ETHTOOL_A_C33_PSE_PW_LIMIT_MIN,	/* u32 */
+	ETHTOOL_A_C33_PSE_PW_LIMIT_MAX,	/* u32 */
+};
+
 enum {
 	ETHTOOL_A_PSE_UNSPEC,
 	ETHTOOL_A_PSE_HEADER,			/* nest - _A_HEADER_* */
@@ -915,6 +945,12 @@ enum {
 	ETHTOOL_A_C33_PSE_ADMIN_STATE,		/* u32 */
 	ETHTOOL_A_C33_PSE_ADMIN_CONTROL,	/* u32 */
 	ETHTOOL_A_C33_PSE_PW_D_STATUS,		/* u32 */
+	ETHTOOL_A_C33_PSE_PW_CLASS,		/* u32 */
+	ETHTOOL_A_C33_PSE_ACTUAL_PW,		/* u32 */
+	ETHTOOL_A_C33_PSE_EXT_STATE,		/* u32 */
+	ETHTOOL_A_C33_PSE_EXT_SUBSTATE,		/* u32 */
+	ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,	/* u32 */
+	ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES,	/* nest - _C33_PSE_PW_LIMIT_* */
 
 	/* add new constants above here */
 	__ETHTOOL_A_PSE_CNT,
@@ -996,6 +1032,23 @@ enum {
 	ETHTOOL_A_MM_MAX = (__ETHTOOL_A_MM_CNT - 1)
 };
 
+/* MODULE_FW_FLASH */
+
+enum {
+	ETHTOOL_A_MODULE_FW_FLASH_UNSPEC,
+	ETHTOOL_A_MODULE_FW_FLASH_HEADER,		/* nest - _A_HEADER_* */
+	ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,		/* string */
+	ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,		/* u32 */
+	ETHTOOL_A_MODULE_FW_FLASH_STATUS,		/* u32 */
+	ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG,		/* string */
+	ETHTOOL_A_MODULE_FW_FLASH_DONE,			/* uint */
+	ETHTOOL_A_MODULE_FW_FLASH_TOTAL,		/* uint */
+
+	/* add new constants above here */
+	__ETHTOOL_A_MODULE_FW_FLASH_CNT,
+	ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
+};
+
 /* generic netlink info */
 #define ETHTOOL_GENL_NAME "ethtool"
 #define ETHTOOL_GENL_VERSION 1
diff --git a/original/uapi/linux/fs.h b/original/uapi/linux/fs.h
index 45e4e64..7539717 100644
--- a/original/uapi/linux/fs.h
+++ b/original/uapi/linux/fs.h
@@ -329,12 +329,17 @@ typedef int __bitwise __kernel_rwf_t;
 /* per-IO negation of O_APPEND */
 #define RWF_NOAPPEND	((__force __kernel_rwf_t)0x00000020)
 
+/* Atomic Write */
+#define RWF_ATOMIC	((__force __kernel_rwf_t)0x00000040)
+
 /* mask of flags supported by the kernel */
 #define RWF_SUPPORTED	(RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT |\
-			 RWF_APPEND | RWF_NOAPPEND)
+			 RWF_APPEND | RWF_NOAPPEND | RWF_ATOMIC)
+
+#define PROCFS_IOCTL_MAGIC 'f'
 
 /* Pagemap ioctl */
-#define PAGEMAP_SCAN	_IOWR('f', 16, struct pm_scan_arg)
+#define PAGEMAP_SCAN	_IOWR(PROCFS_IOCTL_MAGIC, 16, struct pm_scan_arg)
 
 /* Bitmasks provided in pm_scan_args masks and reported in page_region.categories. */
 #define PAGE_IS_WPALLOWED	(1 << 0)
@@ -393,4 +398,158 @@ struct pm_scan_arg {
 	__u64 return_mask;
 };
 
+/* /proc/<pid>/maps ioctl */
+#define PROCMAP_QUERY	_IOWR(PROCFS_IOCTL_MAGIC, 17, struct procmap_query)
+
+enum procmap_query_flags {
+	/*
+	 * VMA permission flags.
+	 *
+	 * Can be used as part of procmap_query.query_flags field to look up
+	 * only VMAs satisfying specified subset of permissions. E.g., specifying
+	 * PROCMAP_QUERY_VMA_READABLE only will return both readable and read/write VMAs,
+	 * while having PROCMAP_QUERY_VMA_READABLE | PROCMAP_QUERY_VMA_WRITABLE will only
+	 * return read/write VMAs, though both executable/non-executable and
+	 * private/shared will be ignored.
+	 *
+	 * PROCMAP_QUERY_VMA_* flags are also returned in procmap_query.vma_flags
+	 * field to specify actual VMA permissions.
+	 */
+	PROCMAP_QUERY_VMA_READABLE		= 0x01,
+	PROCMAP_QUERY_VMA_WRITABLE		= 0x02,
+	PROCMAP_QUERY_VMA_EXECUTABLE		= 0x04,
+	PROCMAP_QUERY_VMA_SHARED		= 0x08,
+	/*
+	 * Query modifier flags.
+	 *
+	 * By default VMA that covers provided address is returned, or -ENOENT
+	 * is returned. With PROCMAP_QUERY_COVERING_OR_NEXT_VMA flag set, closest
+	 * VMA with vma_start > addr will be returned if no covering VMA is
+	 * found.
+	 *
+	 * PROCMAP_QUERY_FILE_BACKED_VMA instructs query to consider only VMAs that
+	 * have file backing. Can be combined with PROCMAP_QUERY_COVERING_OR_NEXT_VMA
+	 * to iterate all VMAs with file backing.
+	 */
+	PROCMAP_QUERY_COVERING_OR_NEXT_VMA	= 0x10,
+	PROCMAP_QUERY_FILE_BACKED_VMA		= 0x20,
+};
+
+/*
+ * Input/output argument structured passed into ioctl() call. It can be used
+ * to query a set of VMAs (Virtual Memory Areas) of a process.
+ *
+ * Each field can be one of three kinds, marked in a short comment to the
+ * right of the field:
+ *   - "in", input argument, user has to provide this value, kernel doesn't modify it;
+ *   - "out", output argument, kernel sets this field with VMA data;
+ *   - "in/out", input and output argument; user provides initial value (used
+ *     to specify maximum allowable buffer size), and kernel sets it to actual
+ *     amount of data written (or zero, if there is no data).
+ *
+ * If matching VMA is found (according to criterias specified by
+ * query_addr/query_flags, all the out fields are filled out, and ioctl()
+ * returns 0. If there is no matching VMA, -ENOENT will be returned.
+ * In case of any other error, negative error code other than -ENOENT is
+ * returned.
+ *
+ * Most of the data is similar to the one returned as text in /proc/<pid>/maps
+ * file, but procmap_query provides more querying flexibility. There are no
+ * consistency guarantees between subsequent ioctl() calls, but data returned
+ * for matched VMA is self-consistent.
+ */
+struct procmap_query {
+	/* Query struct size, for backwards/forward compatibility */
+	__u64 size;
+	/*
+	 * Query flags, a combination of enum procmap_query_flags values.
+	 * Defines query filtering and behavior, see enum procmap_query_flags.
+	 *
+	 * Input argument, provided by user. Kernel doesn't modify it.
+	 */
+	__u64 query_flags;		/* in */
+	/*
+	 * Query address. By default, VMA that covers this address will
+	 * be looked up. PROCMAP_QUERY_* flags above modify this default
+	 * behavior further.
+	 *
+	 * Input argument, provided by user. Kernel doesn't modify it.
+	 */
+	__u64 query_addr;		/* in */
+	/* VMA starting (inclusive) and ending (exclusive) address, if VMA is found. */
+	__u64 vma_start;		/* out */
+	__u64 vma_end;			/* out */
+	/* VMA permissions flags. A combination of PROCMAP_QUERY_VMA_* flags. */
+	__u64 vma_flags;		/* out */
+	/* VMA backing page size granularity. */
+	__u64 vma_page_size;		/* out */
+	/*
+	 * VMA file offset. If VMA has file backing, this specifies offset
+	 * within the file that VMA's start address corresponds to.
+	 * Is set to zero if VMA has no backing file.
+	 */
+	__u64 vma_offset;		/* out */
+	/* Backing file's inode number, or zero, if VMA has no backing file. */
+	__u64 inode;			/* out */
+	/* Backing file's device major/minor number, or zero, if VMA has no backing file. */
+	__u32 dev_major;		/* out */
+	__u32 dev_minor;		/* out */
+	/*
+	 * If set to non-zero value, signals the request to return VMA name
+	 * (i.e., VMA's backing file's absolute path, with " (deleted)" suffix
+	 * appended, if file was unlinked from FS) for matched VMA. VMA name
+	 * can also be some special name (e.g., "[heap]", "[stack]") or could
+	 * be even user-supplied with prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME).
+	 *
+	 * Kernel will set this field to zero, if VMA has no associated name.
+	 * Otherwise kernel will return actual amount of bytes filled in
+	 * user-supplied buffer (see vma_name_addr field below), including the
+	 * terminating zero.
+	 *
+	 * If VMA name is longer that user-supplied maximum buffer size,
+	 * -E2BIG error is returned.
+	 *
+	 * If this field is set to non-zero value, vma_name_addr should point
+	 * to valid user space memory buffer of at least vma_name_size bytes.
+	 * If set to zero, vma_name_addr should be set to zero as well
+	 */
+	__u32 vma_name_size;		/* in/out */
+	/*
+	 * If set to non-zero value, signals the request to extract and return
+	 * VMA's backing file's build ID, if the backing file is an ELF file
+	 * and it contains embedded build ID.
+	 *
+	 * Kernel will set this field to zero, if VMA has no backing file,
+	 * backing file is not an ELF file, or ELF file has no build ID
+	 * embedded.
+	 *
+	 * Build ID is a binary value (not a string). Kernel will set
+	 * build_id_size field to exact number of bytes used for build ID.
+	 * If build ID is requested and present, but needs more bytes than
+	 * user-supplied maximum buffer size (see build_id_addr field below),
+	 * -E2BIG error will be returned.
+	 *
+	 * If this field is set to non-zero value, build_id_addr should point
+	 * to valid user space memory buffer of at least build_id_size bytes.
+	 * If set to zero, build_id_addr should be set to zero as well
+	 */
+	__u32 build_id_size;		/* in/out */
+	/*
+	 * User-supplied address of a buffer of at least vma_name_size bytes
+	 * for kernel to fill with matched VMA's name (see vma_name_size field
+	 * description above for details).
+	 *
+	 * Should be set to zero if VMA name should not be returned.
+	 */
+	__u64 vma_name_addr;		/* in */
+	/*
+	 * User-supplied address of a buffer of at least build_id_size bytes
+	 * for kernel to fill with matched VMA's ELF build ID, if available
+	 * (see build_id_size field description above for details).
+	 *
+	 * Should be set to zero if build ID should not be returned.
+	 */
+	__u64 build_id_addr;		/* in */
+};
+
 #endif /* _UAPI_LINUX_FS_H */
diff --git a/original/uapi/linux/if_xdp.h b/original/uapi/linux/if_xdp.h
index d316984..42ec5dd 100644
--- a/original/uapi/linux/if_xdp.h
+++ b/original/uapi/linux/if_xdp.h
@@ -41,6 +41,10 @@
  */
 #define XDP_UMEM_TX_SW_CSUM		(1 << 1)
 
+/* Request to reserve tx_metadata_len bytes of per-chunk metadata.
+ */
+#define XDP_UMEM_TX_METADATA_LEN	(1 << 2)
+
 struct sockaddr_xdp {
 	__u16 sxdp_family;
 	__u16 sxdp_flags;
diff --git a/original/uapi/linux/iio/buffer.h b/original/uapi/linux/iio/buffer.h
index 1393903..c666aa9 100644
--- a/original/uapi/linux/iio/buffer.h
+++ b/original/uapi/linux/iio/buffer.h
@@ -5,6 +5,28 @@
 #ifndef _UAPI_IIO_BUFFER_H_
 #define _UAPI_IIO_BUFFER_H_
 
+#include <linux/types.h>
+
+/* Flags for iio_dmabuf.flags */
+#define IIO_BUFFER_DMABUF_CYCLIC		(1 << 0)
+#define IIO_BUFFER_DMABUF_SUPPORTED_FLAGS	0x00000001
+
+/**
+ * struct iio_dmabuf - Descriptor for a single IIO DMABUF object
+ * @fd:		file descriptor of the DMABUF object
+ * @flags:	one or more IIO_BUFFER_DMABUF_* flags
+ * @bytes_used:	number of bytes used in this DMABUF for the data transfer.
+ *		Should generally be set to the DMABUF's size.
+ */
+struct iio_dmabuf {
+	__u32 fd;
+	__u32 flags;
+	__u64 bytes_used;
+};
+
 #define IIO_BUFFER_GET_FD_IOCTL			_IOWR('i', 0x91, int)
+#define IIO_BUFFER_DMABUF_ATTACH_IOCTL		_IOW('i', 0x92, int)
+#define IIO_BUFFER_DMABUF_DETACH_IOCTL		_IOW('i', 0x93, int)
+#define IIO_BUFFER_DMABUF_ENQUEUE_IOCTL		_IOW('i', 0x94, struct iio_dmabuf)
 
 #endif /* _UAPI_IIO_BUFFER_H_ */
diff --git a/original/uapi/linux/in.h b/original/uapi/linux/in.h
index e682ab6..d358add 100644
--- a/original/uapi/linux/in.h
+++ b/original/uapi/linux/in.h
@@ -81,6 +81,8 @@ enum {
 #define IPPROTO_ETHERNET	IPPROTO_ETHERNET
   IPPROTO_RAW = 255,		/* Raw IP packets			*/
 #define IPPROTO_RAW		IPPROTO_RAW
+  IPPROTO_SMC = 256,		/* Shared Memory Communications		*/
+#define IPPROTO_SMC		IPPROTO_SMC
   IPPROTO_MPTCP = 262,		/* Multipath TCP connection		*/
 #define IPPROTO_MPTCP		IPPROTO_MPTCP
   IPPROTO_MAX
diff --git a/original/uapi/linux/io_uring.h b/original/uapi/linux/io_uring.h
index 994bf7a..adc2524 100644
--- a/original/uapi/linux/io_uring.h
+++ b/original/uapi/linux/io_uring.h
@@ -257,6 +257,8 @@ enum io_uring_op {
 	IORING_OP_FUTEX_WAITV,
 	IORING_OP_FIXED_FD_INSTALL,
 	IORING_OP_FTRUNCATE,
+	IORING_OP_BIND,
+	IORING_OP_LISTEN,
 
 	/* this goes last, obviously */
 	IORING_OP_LAST,
@@ -419,7 +421,7 @@ enum io_uring_msg_ring_flags {
  * IO completion data structure (Completion Queue Entry)
  */
 struct io_uring_cqe {
-	__u64	user_data;	/* sqe->data submission passed back */
+	__u64	user_data;	/* sqe->user_data value passed back */
 	__s32	res;		/* result code for this event */
 	__u32	flags;
 
diff --git a/original/uapi/linux/iommufd.h b/original/uapi/linux/iommufd.h
index 1dfeaa2..4dde745 100644
--- a/original/uapi/linux/iommufd.h
+++ b/original/uapi/linux/iommufd.h
@@ -37,19 +37,20 @@
 enum {
 	IOMMUFD_CMD_BASE = 0x80,
 	IOMMUFD_CMD_DESTROY = IOMMUFD_CMD_BASE,
-	IOMMUFD_CMD_IOAS_ALLOC,
-	IOMMUFD_CMD_IOAS_ALLOW_IOVAS,
-	IOMMUFD_CMD_IOAS_COPY,
-	IOMMUFD_CMD_IOAS_IOVA_RANGES,
-	IOMMUFD_CMD_IOAS_MAP,
-	IOMMUFD_CMD_IOAS_UNMAP,
-	IOMMUFD_CMD_OPTION,
-	IOMMUFD_CMD_VFIO_IOAS,
-	IOMMUFD_CMD_HWPT_ALLOC,
-	IOMMUFD_CMD_GET_HW_INFO,
-	IOMMUFD_CMD_HWPT_SET_DIRTY_TRACKING,
-	IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP,
-	IOMMUFD_CMD_HWPT_INVALIDATE,
+	IOMMUFD_CMD_IOAS_ALLOC = 0x81,
+	IOMMUFD_CMD_IOAS_ALLOW_IOVAS = 0x82,
+	IOMMUFD_CMD_IOAS_COPY = 0x83,
+	IOMMUFD_CMD_IOAS_IOVA_RANGES = 0x84,
+	IOMMUFD_CMD_IOAS_MAP = 0x85,
+	IOMMUFD_CMD_IOAS_UNMAP = 0x86,
+	IOMMUFD_CMD_OPTION = 0x87,
+	IOMMUFD_CMD_VFIO_IOAS = 0x88,
+	IOMMUFD_CMD_HWPT_ALLOC = 0x89,
+	IOMMUFD_CMD_GET_HW_INFO = 0x8a,
+	IOMMUFD_CMD_HWPT_SET_DIRTY_TRACKING = 0x8b,
+	IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP = 0x8c,
+	IOMMUFD_CMD_HWPT_INVALIDATE = 0x8d,
+	IOMMUFD_CMD_FAULT_QUEUE_ALLOC = 0x8e,
 };
 
 /**
@@ -356,10 +357,13 @@ struct iommu_vfio_ioas {
  *                                the parent HWPT in a nesting configuration.
  * @IOMMU_HWPT_ALLOC_DIRTY_TRACKING: Dirty tracking support for device IOMMU is
  *                                   enforced on device attachment
+ * @IOMMU_HWPT_FAULT_ID_VALID: The fault_id field of hwpt allocation data is
+ *                             valid.
  */
 enum iommufd_hwpt_alloc_flags {
 	IOMMU_HWPT_ALLOC_NEST_PARENT = 1 << 0,
 	IOMMU_HWPT_ALLOC_DIRTY_TRACKING = 1 << 1,
+	IOMMU_HWPT_FAULT_ID_VALID = 1 << 2,
 };
 
 /**
@@ -396,8 +400,8 @@ struct iommu_hwpt_vtd_s1 {
  * @IOMMU_HWPT_DATA_VTD_S1: Intel VT-d stage-1 page table
  */
 enum iommu_hwpt_data_type {
-	IOMMU_HWPT_DATA_NONE,
-	IOMMU_HWPT_DATA_VTD_S1,
+	IOMMU_HWPT_DATA_NONE = 0,
+	IOMMU_HWPT_DATA_VTD_S1 = 1,
 };
 
 /**
@@ -411,6 +415,9 @@ enum iommu_hwpt_data_type {
  * @data_type: One of enum iommu_hwpt_data_type
  * @data_len: Length of the type specific data
  * @data_uptr: User pointer to the type specific data
+ * @fault_id: The ID of IOMMUFD_FAULT object. Valid only if flags field of
+ *            IOMMU_HWPT_FAULT_ID_VALID is set.
+ * @__reserved2: Padding to 64-bit alignment. Must be 0.
  *
  * Explicitly allocate a hardware page table object. This is the same object
  * type that is returned by iommufd_device_attach() and represents the
@@ -441,6 +448,8 @@ struct iommu_hwpt_alloc {
 	__u32 data_type;
 	__u32 data_len;
 	__aligned_u64 data_uptr;
+	__u32 fault_id;
+	__u32 __reserved2;
 };
 #define IOMMU_HWPT_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_ALLOC)
 
@@ -482,8 +491,8 @@ struct iommu_hw_info_vtd {
  * @IOMMU_HW_INFO_TYPE_INTEL_VTD: Intel VT-d iommu info type
  */
 enum iommu_hw_info_type {
-	IOMMU_HW_INFO_TYPE_NONE,
-	IOMMU_HW_INFO_TYPE_INTEL_VTD,
+	IOMMU_HW_INFO_TYPE_NONE = 0,
+	IOMMU_HW_INFO_TYPE_INTEL_VTD = 1,
 };
 
 /**
@@ -620,7 +629,7 @@ struct iommu_hwpt_get_dirty_bitmap {
  * @IOMMU_HWPT_INVALIDATE_DATA_VTD_S1: Invalidation data for VTD_S1
  */
 enum iommu_hwpt_invalidate_data_type {
-	IOMMU_HWPT_INVALIDATE_DATA_VTD_S1,
+	IOMMU_HWPT_INVALIDATE_DATA_VTD_S1 = 0,
 };
 
 /**
@@ -692,4 +701,100 @@ struct iommu_hwpt_invalidate {
 	__u32 __reserved;
 };
 #define IOMMU_HWPT_INVALIDATE _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_INVALIDATE)
+
+/**
+ * enum iommu_hwpt_pgfault_flags - flags for struct iommu_hwpt_pgfault
+ * @IOMMU_PGFAULT_FLAGS_PASID_VALID: The pasid field of the fault data is
+ *                                   valid.
+ * @IOMMU_PGFAULT_FLAGS_LAST_PAGE: It's the last fault of a fault group.
+ */
+enum iommu_hwpt_pgfault_flags {
+	IOMMU_PGFAULT_FLAGS_PASID_VALID		= (1 << 0),
+	IOMMU_PGFAULT_FLAGS_LAST_PAGE		= (1 << 1),
+};
+
+/**
+ * enum iommu_hwpt_pgfault_perm - perm bits for struct iommu_hwpt_pgfault
+ * @IOMMU_PGFAULT_PERM_READ: request for read permission
+ * @IOMMU_PGFAULT_PERM_WRITE: request for write permission
+ * @IOMMU_PGFAULT_PERM_EXEC: (PCIE 10.4.1) request with a PASID that has the
+ *                           Execute Requested bit set in PASID TLP Prefix.
+ * @IOMMU_PGFAULT_PERM_PRIV: (PCIE 10.4.1) request with a PASID that has the
+ *                           Privileged Mode Requested bit set in PASID TLP
+ *                           Prefix.
+ */
+enum iommu_hwpt_pgfault_perm {
+	IOMMU_PGFAULT_PERM_READ			= (1 << 0),
+	IOMMU_PGFAULT_PERM_WRITE		= (1 << 1),
+	IOMMU_PGFAULT_PERM_EXEC			= (1 << 2),
+	IOMMU_PGFAULT_PERM_PRIV			= (1 << 3),
+};
+
+/**
+ * struct iommu_hwpt_pgfault - iommu page fault data
+ * @flags: Combination of enum iommu_hwpt_pgfault_flags
+ * @dev_id: id of the originated device
+ * @pasid: Process Address Space ID
+ * @grpid: Page Request Group Index
+ * @perm: Combination of enum iommu_hwpt_pgfault_perm
+ * @addr: Fault address
+ * @length: a hint of how much data the requestor is expecting to fetch. For
+ *          example, if the PRI initiator knows it is going to do a 10MB
+ *          transfer, it could fill in 10MB and the OS could pre-fault in
+ *          10MB of IOVA. It's default to 0 if there's no such hint.
+ * @cookie: kernel-managed cookie identifying a group of fault messages. The
+ *          cookie number encoded in the last page fault of the group should
+ *          be echoed back in the response message.
+ */
+struct iommu_hwpt_pgfault {
+	__u32 flags;
+	__u32 dev_id;
+	__u32 pasid;
+	__u32 grpid;
+	__u32 perm;
+	__u64 addr;
+	__u32 length;
+	__u32 cookie;
+};
+
+/**
+ * enum iommufd_page_response_code - Return status of fault handlers
+ * @IOMMUFD_PAGE_RESP_SUCCESS: Fault has been handled and the page tables
+ *                             populated, retry the access. This is the
+ *                             "Success" defined in PCI 10.4.2.1.
+ * @IOMMUFD_PAGE_RESP_INVALID: Could not handle this fault, don't retry the
+ *                             access. This is the "Invalid Request" in PCI
+ *                             10.4.2.1.
+ */
+enum iommufd_page_response_code {
+	IOMMUFD_PAGE_RESP_SUCCESS = 0,
+	IOMMUFD_PAGE_RESP_INVALID = 1,
+};
+
+/**
+ * struct iommu_hwpt_page_response - IOMMU page fault response
+ * @cookie: The kernel-managed cookie reported in the fault message.
+ * @code: One of response code in enum iommufd_page_response_code.
+ */
+struct iommu_hwpt_page_response {
+	__u32 cookie;
+	__u32 code;
+};
+
+/**
+ * struct iommu_fault_alloc - ioctl(IOMMU_FAULT_QUEUE_ALLOC)
+ * @size: sizeof(struct iommu_fault_alloc)
+ * @flags: Must be 0
+ * @out_fault_id: The ID of the new FAULT
+ * @out_fault_fd: The fd of the new FAULT
+ *
+ * Explicitly allocate a fault handling object.
+ */
+struct iommu_fault_alloc {
+	__u32 size;
+	__u32 flags;
+	__u32 out_fault_id;
+	__u32 out_fault_fd;
+};
+#define IOMMU_FAULT_QUEUE_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_FAULT_QUEUE_ALLOC)
 #endif
diff --git a/original/uapi/linux/kfd_ioctl.h b/original/uapi/linux/kfd_ioctl.h
index 2040a47..285a366 100644
--- a/original/uapi/linux/kfd_ioctl.h
+++ b/original/uapi/linux/kfd_ioctl.h
@@ -41,9 +41,10 @@
  * - 1.13 - Add debugger API
  * - 1.14 - Update kfd_event_data
  * - 1.15 - Enable managing mappings in compute VMs with GEM_VA ioctl
+ * - 1.16 - Add contiguous VRAM allocation flag
  */
 #define KFD_IOCTL_MAJOR_VERSION 1
-#define KFD_IOCTL_MINOR_VERSION 15
+#define KFD_IOCTL_MINOR_VERSION 16
 
 struct kfd_ioctl_get_version_args {
 	__u32 major_version;	/* from KFD */
@@ -407,6 +408,7 @@ struct kfd_ioctl_acquire_vm_args {
 #define KFD_IOC_ALLOC_MEM_FLAGS_COHERENT	(1 << 26)
 #define KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED	(1 << 25)
 #define KFD_IOC_ALLOC_MEM_FLAGS_EXT_COHERENT	(1 << 24)
+#define KFD_IOC_ALLOC_MEM_FLAGS_CONTIGUOUS	(1 << 23)
 
 /* Allocate memory for later SVM (shared virtual memory) mapping.
  *
@@ -852,6 +854,7 @@ enum kfd_dbg_trap_address_watch_mode {
 /* Additional wave settings */
 enum kfd_dbg_trap_flags {
 	KFD_DBG_TRAP_FLAG_SINGLE_MEM_OP = 1,
+	KFD_DBG_TRAP_FLAG_SINGLE_ALU_OP = 2,
 };
 
 /* Trap exceptions */
diff --git a/original/uapi/linux/kfd_sysfs.h b/original/uapi/linux/kfd_sysfs.h
index a51b733..5e8d286 100644
--- a/original/uapi/linux/kfd_sysfs.h
+++ b/original/uapi/linux/kfd_sysfs.h
@@ -51,15 +51,16 @@
 /* Old buggy user mode depends on this being 0 */
 #define HSA_CAP_RESERVED_WAS_SRAM_EDCSUPPORTED	0x00080000
 
-#define HSA_CAP_MEM_EDCSUPPORTED		0x00100000
-#define HSA_CAP_RASEVENTNOTIFY			0x00200000
-#define HSA_CAP_ASIC_REVISION_MASK		0x03c00000
-#define HSA_CAP_ASIC_REVISION_SHIFT		22
-#define HSA_CAP_SRAM_EDCSUPPORTED		0x04000000
-#define HSA_CAP_SVMAPI_SUPPORTED		0x08000000
-#define HSA_CAP_FLAGS_COHERENTHOSTACCESS	0x10000000
-#define HSA_CAP_TRAP_DEBUG_FIRMWARE_SUPPORTED   0x20000000
-#define HSA_CAP_RESERVED			0xe00f8000
+#define HSA_CAP_MEM_EDCSUPPORTED				0x00100000
+#define HSA_CAP_RASEVENTNOTIFY					0x00200000
+#define HSA_CAP_ASIC_REVISION_MASK				0x03c00000
+#define HSA_CAP_ASIC_REVISION_SHIFT				22
+#define HSA_CAP_SRAM_EDCSUPPORTED				0x04000000
+#define HSA_CAP_SVMAPI_SUPPORTED				0x08000000
+#define HSA_CAP_FLAGS_COHERENTHOSTACCESS			0x10000000
+#define HSA_CAP_TRAP_DEBUG_FIRMWARE_SUPPORTED			0x20000000
+#define HSA_CAP_TRAP_DEBUG_PRECISE_ALU_OPERATIONS_SUPPORTED	0x40000000
+#define HSA_CAP_RESERVED					0x800f8000
 
 /* debug_prop bits in node properties */
 #define HSA_DBG_WATCH_ADDR_MASK_LO_BIT_MASK     0x0000000f
diff --git a/original/uapi/linux/kvm.h b/original/uapi/linux/kvm.h
index d03842a..637efc0 100644
--- a/original/uapi/linux/kvm.h
+++ b/original/uapi/linux/kvm.h
@@ -192,11 +192,24 @@ struct kvm_xen_exit {
 /* Flags that describe what fields in emulation_failure hold valid data. */
 #define KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES (1ULL << 0)
 
+/*
+ * struct kvm_run can be modified by userspace at any time, so KVM must be
+ * careful to avoid TOCTOU bugs. In order to protect KVM, HINT_UNSAFE_IN_KVM()
+ * renames fields in struct kvm_run from <symbol> to <symbol>__unsafe when
+ * compiled into the kernel, ensuring that any use within KVM is obvious and
+ * gets extra scrutiny.
+ */
+#ifdef __KERNEL__
+#define HINT_UNSAFE_IN_KVM(_symbol) _symbol##__unsafe
+#else
+#define HINT_UNSAFE_IN_KVM(_symbol) _symbol
+#endif
+
 /* for KVM_RUN, returned by mmap(vcpu_fd, offset=0) */
 struct kvm_run {
 	/* in */
 	__u8 request_interrupt_window;
-	__u8 immediate_exit;
+	__u8 HINT_UNSAFE_IN_KVM(immediate_exit);
 	__u8 padding1[6];
 
 	/* out */
@@ -917,6 +930,9 @@ struct kvm_enable_cap {
 #define KVM_CAP_MEMORY_ATTRIBUTES 233
 #define KVM_CAP_GUEST_MEMFD 234
 #define KVM_CAP_VM_TYPES 235
+#define KVM_CAP_PRE_FAULT_MEMORY 236
+#define KVM_CAP_X86_APIC_BUS_CYCLES_NS 237
+#define KVM_CAP_X86_GUEST_MODE 238
 
 struct kvm_irq_routing_irqchip {
 	__u32 irqchip;
@@ -1548,4 +1564,13 @@ struct kvm_create_guest_memfd {
 	__u64 reserved[6];
 };
 
+#define KVM_PRE_FAULT_MEMORY	_IOWR(KVMIO, 0xd5, struct kvm_pre_fault_memory)
+
+struct kvm_pre_fault_memory {
+	__u64 gpa;
+	__u64 size;
+	__u64 flags;
+	__u64 padding[5];
+};
+
 #endif /* __LINUX_KVM_H */
diff --git a/original/uapi/linux/landlock.h b/original/uapi/linux/landlock.h
index 68625e7..2c8dbc7 100644
--- a/original/uapi/linux/landlock.h
+++ b/original/uapi/linux/landlock.h
@@ -12,29 +12,36 @@
 #include <linux/types.h>
 
 /**
- * struct landlock_ruleset_attr - Ruleset definition
+ * struct landlock_ruleset_attr - Ruleset definition.
  *
- * Argument of sys_landlock_create_ruleset().  This structure can grow in
- * future versions.
+ * Argument of sys_landlock_create_ruleset().
+ *
+ * This structure defines a set of *handled access rights*, a set of actions on
+ * different object types, which should be denied by default when the ruleset is
+ * enacted.  Vice versa, access rights that are not specifically listed here are
+ * not going to be denied by this ruleset when it is enacted.
+ *
+ * For historical reasons, the %LANDLOCK_ACCESS_FS_REFER right is always denied
+ * by default, even when its bit is not set in @handled_access_fs.  In order to
+ * add new rules with this access right, the bit must still be set explicitly
+ * (cf. `Filesystem flags`_).
+ *
+ * The explicit listing of *handled access rights* is required for backwards
+ * compatibility reasons.  In most use cases, processes that use Landlock will
+ * *handle* a wide range or all access rights that they know about at build time
+ * (and that they have tested with a kernel that supported them all).
+ *
+ * This structure can grow in future Landlock versions.
  */
 struct landlock_ruleset_attr {
 	/**
-	 * @handled_access_fs: Bitmask of actions (cf. `Filesystem flags`_)
-	 * that is handled by this ruleset and should then be forbidden if no
-	 * rule explicitly allow them: it is a deny-by-default list that should
-	 * contain as much Landlock access rights as possible. Indeed, all
-	 * Landlock filesystem access rights that are not part of
-	 * handled_access_fs are allowed.  This is needed for backward
-	 * compatibility reasons.  One exception is the
-	 * %LANDLOCK_ACCESS_FS_REFER access right, which is always implicitly
-	 * handled, but must still be explicitly handled to add new rules with
-	 * this access right.
+	 * @handled_access_fs: Bitmask of handled filesystem actions
+	 * (cf. `Filesystem flags`_).
 	 */
 	__u64 handled_access_fs;
 	/**
-	 * @handled_access_net: Bitmask of actions (cf. `Network flags`_)
-	 * that is handled by this ruleset and should then be forbidden if no
-	 * rule explicitly allow them.
+	 * @handled_access_net: Bitmask of handled network actions (cf. `Network
+	 * flags`_).
 	 */
 	__u64 handled_access_net;
 };
@@ -97,20 +104,21 @@ struct landlock_path_beneath_attr {
  */
 struct landlock_net_port_attr {
 	/**
-	 * @allowed_access: Bitmask of allowed access network for a port
+	 * @allowed_access: Bitmask of allowed network actions for a port
 	 * (cf. `Network flags`_).
 	 */
 	__u64 allowed_access;
 	/**
 	 * @port: Network port in host endianness.
 	 *
-	 * It should be noted that port 0 passed to :manpage:`bind(2)` will
-	 * bind to an available port from a specific port range. This can be
-	 * configured thanks to the ``/proc/sys/net/ipv4/ip_local_port_range``
-	 * sysctl (also used for IPv6). A Landlock rule with port 0 and the
-	 * ``LANDLOCK_ACCESS_NET_BIND_TCP`` right means that requesting to bind
-	 * on port 0 is allowed and it will automatically translate to binding
-	 * on the related port range.
+	 * It should be noted that port 0 passed to :manpage:`bind(2)` will bind
+	 * to an available port from the ephemeral port range.  This can be
+	 * configured with the ``/proc/sys/net/ipv4/ip_local_port_range`` sysctl
+	 * (also used for IPv6).
+	 *
+	 * A Landlock rule with port 0 and the ``LANDLOCK_ACCESS_NET_BIND_TCP``
+	 * right means that requesting to bind on port 0 is allowed and it will
+	 * automatically translate to binding on the related port range.
 	 */
 	__u64 port;
 };
@@ -131,10 +139,10 @@ struct landlock_net_port_attr {
  * The following access rights apply only to files:
  *
  * - %LANDLOCK_ACCESS_FS_EXECUTE: Execute a file.
- * - %LANDLOCK_ACCESS_FS_WRITE_FILE: Open a file with write access. Note that
- *   you might additionally need the %LANDLOCK_ACCESS_FS_TRUNCATE right in order
- *   to overwrite files with :manpage:`open(2)` using ``O_TRUNC`` or
- *   :manpage:`creat(2)`.
+ * - %LANDLOCK_ACCESS_FS_WRITE_FILE: Open a file with write access.  When
+ *   opening files for writing, you will often additionally need the
+ *   %LANDLOCK_ACCESS_FS_TRUNCATE right.  In many cases, these system calls
+ *   truncate existing files when overwriting them (e.g., :manpage:`creat(2)`).
  * - %LANDLOCK_ACCESS_FS_READ_FILE: Open a file with read access.
  * - %LANDLOCK_ACCESS_FS_TRUNCATE: Truncate a file with :manpage:`truncate(2)`,
  *   :manpage:`ftruncate(2)`, :manpage:`creat(2)`, or :manpage:`open(2)` with
@@ -256,7 +264,7 @@ struct landlock_net_port_attr {
  * These flags enable to restrict a sandboxed process to a set of network
  * actions. This is supported since the Landlock ABI version 4.
  *
- * TCP sockets with allowed actions:
+ * The following access rights apply to TCP port numbers:
  *
  * - %LANDLOCK_ACCESS_NET_BIND_TCP: Bind a TCP socket to a local port.
  * - %LANDLOCK_ACCESS_NET_CONNECT_TCP: Connect an active TCP socket to
diff --git a/original/uapi/linux/media/raspberrypi/pisp_be_config.h b/original/uapi/linux/media/raspberrypi/pisp_be_config.h
new file mode 100644
index 0000000..cbeb714
--- /dev/null
+++ b/original/uapi/linux/media/raspberrypi/pisp_be_config.h
@@ -0,0 +1,968 @@
+/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
+/*
+ * PiSP Back End configuration definitions.
+ *
+ * Copyright (C) 2021 - Raspberry Pi Ltd
+ *
+ */
+#ifndef _UAPI_PISP_BE_CONFIG_H_
+#define _UAPI_PISP_BE_CONFIG_H_
+
+#include <linux/types.h>
+
+#include "pisp_common.h"
+
+/* byte alignment for inputs */
+#define PISP_BACK_END_INPUT_ALIGN 4u
+/* alignment for compressed inputs */
+#define PISP_BACK_END_COMPRESSED_ALIGN 8u
+/* minimum required byte alignment for outputs */
+#define PISP_BACK_END_OUTPUT_MIN_ALIGN 16u
+/* preferred byte alignment for outputs */
+#define PISP_BACK_END_OUTPUT_MAX_ALIGN 64u
+
+/* minimum allowed tile width anywhere in the pipeline */
+#define PISP_BACK_END_MIN_TILE_WIDTH 16u
+/* minimum allowed tile width anywhere in the pipeline */
+#define PISP_BACK_END_MIN_TILE_HEIGHT 16u
+
+#define PISP_BACK_END_NUM_OUTPUTS 2
+#define PISP_BACK_END_HOG_OUTPUT 1
+
+#define PISP_BACK_END_NUM_TILES 64
+
+enum pisp_be_bayer_enable {
+	PISP_BE_BAYER_ENABLE_INPUT = 0x000001,
+	PISP_BE_BAYER_ENABLE_DECOMPRESS = 0x000002,
+	PISP_BE_BAYER_ENABLE_DPC = 0x000004,
+	PISP_BE_BAYER_ENABLE_GEQ = 0x000008,
+	PISP_BE_BAYER_ENABLE_TDN_INPUT = 0x000010,
+	PISP_BE_BAYER_ENABLE_TDN_DECOMPRESS = 0x000020,
+	PISP_BE_BAYER_ENABLE_TDN = 0x000040,
+	PISP_BE_BAYER_ENABLE_TDN_COMPRESS = 0x000080,
+	PISP_BE_BAYER_ENABLE_TDN_OUTPUT = 0x000100,
+	PISP_BE_BAYER_ENABLE_SDN = 0x000200,
+	PISP_BE_BAYER_ENABLE_BLC = 0x000400,
+	PISP_BE_BAYER_ENABLE_STITCH_INPUT = 0x000800,
+	PISP_BE_BAYER_ENABLE_STITCH_DECOMPRESS = 0x001000,
+	PISP_BE_BAYER_ENABLE_STITCH = 0x002000,
+	PISP_BE_BAYER_ENABLE_STITCH_COMPRESS = 0x004000,
+	PISP_BE_BAYER_ENABLE_STITCH_OUTPUT = 0x008000,
+	PISP_BE_BAYER_ENABLE_WBG = 0x010000,
+	PISP_BE_BAYER_ENABLE_CDN = 0x020000,
+	PISP_BE_BAYER_ENABLE_LSC = 0x040000,
+	PISP_BE_BAYER_ENABLE_TONEMAP = 0x080000,
+	PISP_BE_BAYER_ENABLE_CAC = 0x100000,
+	PISP_BE_BAYER_ENABLE_DEBIN = 0x200000,
+	PISP_BE_BAYER_ENABLE_DEMOSAIC = 0x400000,
+};
+
+enum pisp_be_rgb_enable {
+	PISP_BE_RGB_ENABLE_INPUT = 0x000001,
+	PISP_BE_RGB_ENABLE_CCM = 0x000002,
+	PISP_BE_RGB_ENABLE_SAT_CONTROL = 0x000004,
+	PISP_BE_RGB_ENABLE_YCBCR = 0x000008,
+	PISP_BE_RGB_ENABLE_FALSE_COLOUR = 0x000010,
+	PISP_BE_RGB_ENABLE_SHARPEN = 0x000020,
+	/* Preferred colours would occupy 0x000040 */
+	PISP_BE_RGB_ENABLE_YCBCR_INVERSE = 0x000080,
+	PISP_BE_RGB_ENABLE_GAMMA = 0x000100,
+	PISP_BE_RGB_ENABLE_CSC0 = 0x000200,
+	PISP_BE_RGB_ENABLE_CSC1 = 0x000400,
+	PISP_BE_RGB_ENABLE_DOWNSCALE0 = 0x001000,
+	PISP_BE_RGB_ENABLE_DOWNSCALE1 = 0x002000,
+	PISP_BE_RGB_ENABLE_RESAMPLE0 = 0x008000,
+	PISP_BE_RGB_ENABLE_RESAMPLE1 = 0x010000,
+	PISP_BE_RGB_ENABLE_OUTPUT0 = 0x040000,
+	PISP_BE_RGB_ENABLE_OUTPUT1 = 0x080000,
+	PISP_BE_RGB_ENABLE_HOG = 0x200000
+};
+
+#define PISP_BE_RGB_ENABLE_CSC(i) (PISP_BE_RGB_ENABLE_CSC0 << (i))
+#define PISP_BE_RGB_ENABLE_DOWNSCALE(i) (PISP_BE_RGB_ENABLE_DOWNSCALE0 << (i))
+#define PISP_BE_RGB_ENABLE_RESAMPLE(i) (PISP_BE_RGB_ENABLE_RESAMPLE0 << (i))
+#define PISP_BE_RGB_ENABLE_OUTPUT(i) (PISP_BE_RGB_ENABLE_OUTPUT0 << (i))
+
+/*
+ * We use the enable flags to show when blocks are "dirty", but we need some
+ * extra ones too.
+ */
+enum pisp_be_dirty {
+	PISP_BE_DIRTY_GLOBAL = 0x0001,
+	PISP_BE_DIRTY_SH_FC_COMBINE = 0x0002,
+	PISP_BE_DIRTY_CROP = 0x0004
+};
+
+/**
+ * struct pisp_be_global_config - PiSP global enable bitmaps
+ * @bayer_enables:	Bayer input enable flags
+ * @rgb_enables:	RGB output enable flags
+ * @bayer_order:	Bayer input format ordering
+ * @pad:		Padding bytes
+ */
+struct pisp_be_global_config {
+	__u32 bayer_enables;
+	__u32 rgb_enables;
+	__u8 bayer_order;
+	__u8 pad[3];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_input_buffer_config - PiSP Back End input buffer
+ * @addr:		Input buffer address
+ */
+struct pisp_be_input_buffer_config {
+	/* low 32 bits followed by high 32 bits (for each of up to 3 planes) */
+	__u32 addr[3][2];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_dpc_config - PiSP Back End DPC config
+ *
+ * Defective Pixel Correction configuration
+ *
+ * @coeff_level:	Coefficient for the darkest neighbouring pixel value
+ * @coeff_range:	Coefficient for the range of pixels for this Bayer channel
+ * @pad:		Padding byte
+ * @flags:		DPC configuration flags
+ */
+struct pisp_be_dpc_config {
+	__u8 coeff_level;
+	__u8 coeff_range;
+	__u8 pad;
+#define PISP_BE_DPC_FLAG_FOLDBACK 1
+	__u8 flags;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_geq_config - PiSP Back End GEQ config
+ *
+ * Green Equalisation configuration
+ *
+ * @offset:		Offset value for threshold calculation
+ * @slope_sharper:	Slope/Sharper configuration
+ * @min:		Minimum value the threshold may have
+ * @max:		Maximum value the threshold may have
+ */
+struct pisp_be_geq_config {
+	__u16 offset;
+#define PISP_BE_GEQ_SHARPER (1U << 15)
+#define PISP_BE_GEQ_SLOPE ((1 << 10) - 1)
+	/* top bit is the "sharper" flag, slope value is bottom 10 bits */
+	__u16 slope_sharper;
+	__u16 min;
+	__u16 max;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_tdn_input_buffer_config - PiSP Back End TDN input buffer
+ * @addr:		TDN input buffer address
+ */
+struct pisp_be_tdn_input_buffer_config {
+	/* low 32 bits followed by high 32 bits */
+	__u32 addr[2];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_tdn_config - PiSP Back End TDN config
+ *
+ * Temporal Denoise configuration
+ *
+ * @black_level:	Black level value subtracted from pixels
+ * @ratio:		Multiplier for the LTA input frame
+ * @noise_constant:	Constant offset value used in noise estimation
+ * @noise_slope:	Noise estimation multiplier
+ * @threshold:		Threshold for TDN operations
+ * @reset:		Disable TDN operations
+ * @pad:		Padding byte
+ */
+struct pisp_be_tdn_config {
+	__u16 black_level;
+	__u16 ratio;
+	__u16 noise_constant;
+	__u16 noise_slope;
+	__u16 threshold;
+	__u8 reset;
+	__u8 pad;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_tdn_output_buffer_config - PiSP Back End TDN output buffer
+ * @addr:		TDN output buffer address
+ */
+struct pisp_be_tdn_output_buffer_config {
+	/* low 32 bits followed by high 32 bits */
+	__u32 addr[2];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_sdn_config - PiSP Back End SDN config
+ *
+ * Spatial Denoise configuration
+ *
+ * @black_level:	Black level subtracted from pixel for noise estimation
+ * @leakage:		Proportion of the original undenoised value to mix in
+ *			denoised output
+ * @pad:		Padding byte
+ * @noise_constant:	Noise constant used for noise estimation
+ * @noise_slope:	Noise slope value used for noise estimation
+ * @noise_constant2:	Second noise constant used for noise estimation
+ * @noise_slope2:	Second slope value used for noise estimation
+ */
+struct pisp_be_sdn_config {
+	__u16 black_level;
+	__u8 leakage;
+	__u8 pad;
+	__u16 noise_constant;
+	__u16 noise_slope;
+	__u16 noise_constant2;
+	__u16 noise_slope2;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_stitch_input_buffer_config - PiSP Back End Stitch input
+ * @addr:		Stitch input buffer address
+ */
+struct pisp_be_stitch_input_buffer_config {
+	/* low 32 bits followed by high 32 bits */
+	__u32 addr[2];
+} __attribute__((packed));
+
+#define PISP_BE_STITCH_STREAMING_LONG 0x8000
+#define PISP_BE_STITCH_EXPOSURE_RATIO_MASK 0x7fff
+
+/**
+ * struct pisp_be_stitch_config - PiSP Back End Stitch config
+ *
+ * Stitch block configuration
+ *
+ * @threshold_lo:		Low threshold value
+ * @threshold_diff_power:	Low and high threshold difference
+ * @pad:			Padding bytes
+ * @exposure_ratio:		Multiplier to convert long exposure pixels into
+ *				short exposure pixels
+ * @motion_threshold_256:	Motion threshold above which short exposure
+ *				pixels are used
+ * @motion_threshold_recip:	Reciprocal of motion_threshold_256 value
+ */
+struct pisp_be_stitch_config {
+	__u16 threshold_lo;
+	__u8 threshold_diff_power;
+	__u8 pad;
+
+	/* top bit indicates whether streaming input is the long exposure */
+	__u16 exposure_ratio;
+
+	__u8 motion_threshold_256;
+	__u8 motion_threshold_recip;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_stitch_output_buffer_config - PiSP Back End Stitch output
+ * @addr:		Stitch input buffer address
+ */
+struct pisp_be_stitch_output_buffer_config {
+	/* low 32 bits followed by high 32 bits */
+	__u32 addr[2];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_cdn_config - PiSP Back End CDN config
+ *
+ * Colour Denoise configuration
+ *
+ * @thresh:		Constant for noise estimation
+ * @iir_strength:	Relative strength of the IIR part of the filter
+ * @g_adjust:		Proportion of the change assigned to the G channel
+ */
+struct pisp_be_cdn_config {
+	__u16 thresh;
+	__u8 iir_strength;
+	__u8 g_adjust;
+} __attribute__((packed));
+
+#define PISP_BE_LSC_LOG_GRID_SIZE 5
+#define PISP_BE_LSC_GRID_SIZE (1 << PISP_BE_LSC_LOG_GRID_SIZE)
+#define PISP_BE_LSC_STEP_PRECISION 18
+
+/**
+ * struct pisp_be_lsc_config - PiSP Back End LSC config
+ *
+ * Lens Shading Correction configuration
+ *
+ * @grid_step_x:	Reciprocal of cell size width
+ * @grid_step_y:	Reciprocal of cell size height
+ * @lut_packed:		Jointly-coded RGB gains for each LSC grid
+ */
+struct pisp_be_lsc_config {
+	/* (1<<18) / grid_cell_width */
+	__u16 grid_step_x;
+	/* (1<<18) / grid_cell_height */
+	__u16 grid_step_y;
+	/* RGB gains jointly encoded in 32 bits */
+#define PISP_BE_LSC_LUT_SIZE	(PISP_BE_LSC_GRID_SIZE + 1)
+	__u32 lut_packed[PISP_BE_LSC_LUT_SIZE][PISP_BE_LSC_LUT_SIZE];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_lsc_extra - PiSP Back End LSC Extra config
+ * @offset_x:		Horizontal offset into the LSC table of this tile
+ * @offset_y:		Vertical offset into the LSC table of this tile
+ */
+struct pisp_be_lsc_extra {
+	__u16 offset_x;
+	__u16 offset_y;
+} __attribute__((packed));
+
+#define PISP_BE_CAC_LOG_GRID_SIZE 3
+#define PISP_BE_CAC_GRID_SIZE (1 << PISP_BE_CAC_LOG_GRID_SIZE)
+#define PISP_BE_CAC_STEP_PRECISION 20
+
+/**
+ * struct pisp_be_cac_config - PiSP Back End CAC config
+ *
+ * Chromatic Aberration Correction config
+ *
+ * @grid_step_x:	Reciprocal of cell size width
+ * @grid_step_y:	Reciprocal of cell size height
+ * @lut:		Pixel shift for the CAC grid
+ */
+struct pisp_be_cac_config {
+	/* (1<<20) / grid_cell_width */
+	__u16 grid_step_x;
+	/* (1<<20) / grid_cell_height */
+	__u16 grid_step_y;
+	/* [gridy][gridx][rb][xy] */
+#define PISP_BE_CAC_LUT_SIZE		(PISP_BE_CAC_GRID_SIZE + 1)
+	__s8 lut[PISP_BE_CAC_LUT_SIZE][PISP_BE_CAC_LUT_SIZE][2][2];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_cac_extra - PiSP Back End CAC extra config
+ * @offset_x:		Horizontal offset into the CAC table of this tile
+ * @offset_y:		Horizontal offset into the CAC table of this tile
+ */
+struct pisp_be_cac_extra {
+	__u16 offset_x;
+	__u16 offset_y;
+} __attribute__((packed));
+
+#define PISP_BE_DEBIN_NUM_COEFFS 4
+
+/**
+ * struct pisp_be_debin_config - PiSP Back End Debin config
+ *
+ * Debinning configuration
+ *
+ * @coeffs:		Filter coefficients for debinning
+ * @h_enable:		Horizontal debinning enable
+ * @v_enable:		Vertical debinning enable
+ * @pad:		Padding bytes
+ */
+struct pisp_be_debin_config {
+	__s8 coeffs[PISP_BE_DEBIN_NUM_COEFFS];
+	__s8 h_enable;
+	__s8 v_enable;
+	__s8 pad[2];
+} __attribute__((packed));
+
+#define PISP_BE_TONEMAP_LUT_SIZE 64
+
+/**
+ * struct pisp_be_tonemap_config - PiSP Back End Tonemap config
+ *
+ * Tonemapping configuration
+ *
+ * @detail_constant:	Constant value for threshold calculation
+ * @detail_slope:	Slope value for threshold calculation
+ * @iir_strength:	Relative strength of the IIR fiter
+ * @strength:		Strength factor
+ * @lut:		Look-up table for tonemap curve
+ */
+struct pisp_be_tonemap_config {
+	__u16 detail_constant;
+	__u16 detail_slope;
+	__u16 iir_strength;
+	__u16 strength;
+	__u32 lut[PISP_BE_TONEMAP_LUT_SIZE];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_demosaic_config - PiSP Back End Demosaic config
+ *
+ * Demosaic configuration
+ *
+ * @sharper:		Use other Bayer channels to increase sharpness
+ * @fc_mode:		Built-in false colour suppression mode
+ * @pad:		Padding bytes
+ */
+struct pisp_be_demosaic_config {
+	__u8 sharper;
+	__u8 fc_mode;
+	__u8 pad[2];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_ccm_config - PiSP Back End CCM config
+ *
+ * Colour Correction Matrix configuration
+ *
+ * @coeffs:		Matrix coefficients
+ * @pad:		Padding bytes
+ * @offsets:		Offsets triplet
+ */
+struct pisp_be_ccm_config {
+	__s16 coeffs[9];
+	__u8 pad[2];
+	__s32 offsets[3];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_sat_control_config - PiSP Back End SAT config
+ *
+ * Saturation Control configuration
+ *
+ * @shift_r:		Left shift for Red colour channel
+ * @shift_g:		Left shift for Green colour channel
+ * @shift_b:		Left shift for Blue colour channel
+ * @pad:		Padding byte
+ */
+struct pisp_be_sat_control_config {
+	__u8 shift_r;
+	__u8 shift_g;
+	__u8 shift_b;
+	__u8 pad;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_false_colour_config - PiSP Back End False Colour config
+ *
+ * False Colour configuration
+ *
+ * @distance:		Distance of neighbouring pixels, either 1 or 2
+ * @pad:		Padding bytes
+ */
+struct pisp_be_false_colour_config {
+	__u8 distance;
+	__u8 pad[3];
+} __attribute__((packed));
+
+#define PISP_BE_SHARPEN_SIZE 5
+#define PISP_BE_SHARPEN_FUNC_NUM_POINTS 9
+
+/**
+ * struct pisp_be_sharpen_config - PiSP Back End Sharpening config
+ *
+ * Sharpening configuration
+ *
+ * @kernel0:		Coefficient for filter 0
+ * @pad0:		Padding byte
+ * @kernel1:		Coefficient for filter 1
+ * @pad1:		Padding byte
+ * @kernel2:		Coefficient for filter 2
+ * @pad2:		Padding byte
+ * @kernel3:		Coefficient for filter 3
+ * @pad3:		Padding byte
+ * @kernel4:		Coefficient for filter 4
+ * @pad4:		Padding byte
+ * @threshold_offset0:	Offset for filter 0 response calculation
+ * @threshold_slope0:	Slope multiplier for the filter 0 response calculation
+ * @scale0:		Scale factor for filter 0 response calculation
+ * @pad5:		Padding byte
+ * @threshold_offset1:	Offset for filter 0 response calculation
+ * @threshold_slope1:	Slope multiplier for the filter 0 response calculation
+ * @scale1:		Scale factor for filter 0 response calculation
+ * @pad6:		Padding byte
+ * @threshold_offset2:	Offset for filter 0 response calculation
+ * @threshold_slope2:	Slope multiplier for the filter 0 response calculation
+ * @scale2:		Scale factor for filter 0 response calculation
+ * @pad7:		Padding byte
+ * @threshold_offset3:	Offset for filter 0 response calculation
+ * @threshold_slope3:	Slope multiplier for the filter 0 response calculation
+ * @scale3:		Scale factor for filter 0 response calculation
+ * @pad8:		Padding byte
+ * @threshold_offset4:	Offset for filter 0 response calculation
+ * @threshold_slope4:	Slope multiplier for the filter 0 response calculation
+ * @scale4:		Scale factor for filter 0 response calculation
+ * @pad9:		Padding byte
+ * @positive_strength:	Factor to scale the positive sharpening strength
+ * @positive_pre_limit:	Maximum allowed possible positive sharpening value
+ * @positive_func:	Gain factor applied to positive sharpening response
+ * @positive_limit:	Final gain factor applied to positive sharpening
+ * @negative_strength:	Factor to scale the negative sharpening strength
+ * @negative_pre_limit:	Maximum allowed possible negative sharpening value
+ * @negative_func:	Gain factor applied to negative sharpening response
+ * @negative_limit:	Final gain factor applied to negative sharpening
+ * @enables:		Filter enable mask
+ * @white:		White output pixel filter mask
+ * @black:		Black output pixel filter mask
+ * @grey:		Grey output pixel filter mask
+ */
+struct pisp_be_sharpen_config {
+	__s8 kernel0[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+	__s8 pad0[3];
+	__s8 kernel1[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+	__s8 pad1[3];
+	__s8 kernel2[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+	__s8 pad2[3];
+	__s8 kernel3[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+	__s8 pad3[3];
+	__s8 kernel4[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+	__s8 pad4[3];
+	__u16 threshold_offset0;
+	__u16 threshold_slope0;
+	__u16 scale0;
+	__u16 pad5;
+	__u16 threshold_offset1;
+	__u16 threshold_slope1;
+	__u16 scale1;
+	__u16 pad6;
+	__u16 threshold_offset2;
+	__u16 threshold_slope2;
+	__u16 scale2;
+	__u16 pad7;
+	__u16 threshold_offset3;
+	__u16 threshold_slope3;
+	__u16 scale3;
+	__u16 pad8;
+	__u16 threshold_offset4;
+	__u16 threshold_slope4;
+	__u16 scale4;
+	__u16 pad9;
+	__u16 positive_strength;
+	__u16 positive_pre_limit;
+	__u16 positive_func[PISP_BE_SHARPEN_FUNC_NUM_POINTS];
+	__u16 positive_limit;
+	__u16 negative_strength;
+	__u16 negative_pre_limit;
+	__u16 negative_func[PISP_BE_SHARPEN_FUNC_NUM_POINTS];
+	__u16 negative_limit;
+	__u8 enables;
+	__u8 white;
+	__u8 black;
+	__u8 grey;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_sh_fc_combine_config - PiSP Back End Sharpening and
+ *					 False Colour config
+ *
+ * Sharpening and False Colour configuration
+ *
+ * @y_factor:		Control amount of desaturation of pixels being darkened
+ * @c1_factor:		Control amount of brightening of a pixel for the Cb
+ *			channel
+ * @c2_factor:		Control amount of brightening of a pixel for the Cr
+ *			channel
+ * @pad:		Padding byte
+ */
+struct pisp_be_sh_fc_combine_config {
+	__u8 y_factor;
+	__u8 c1_factor;
+	__u8 c2_factor;
+	__u8 pad;
+} __attribute__((packed));
+
+#define PISP_BE_GAMMA_LUT_SIZE 64
+
+/**
+ * struct pisp_be_gamma_config - PiSP Back End Gamma configuration
+ * @lut:		Gamma curve look-up table
+ */
+struct pisp_be_gamma_config {
+	__u32 lut[PISP_BE_GAMMA_LUT_SIZE];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_crop_config - PiSP Back End Crop config
+ *
+ * Crop configuration
+ *
+ * @offset_x:		Number of pixels cropped from the left of the tile
+ * @offset_y:		Number of pixels cropped from the top of the tile
+ * @width:		Width of the cropped tile output
+ * @height:		Height of the cropped tile output
+ */
+struct pisp_be_crop_config {
+	__u16 offset_x, offset_y;
+	__u16 width, height;
+} __attribute__((packed));
+
+#define PISP_BE_RESAMPLE_FILTER_SIZE 96
+
+/**
+ * struct pisp_be_resample_config - PiSP Back End Resampling config
+ *
+ * Resample configuration
+ *
+ * @scale_factor_h:	Horizontal scale factor
+ * @scale_factor_v:	Vertical scale factor
+ * @coef:		Resample coefficients
+ */
+struct pisp_be_resample_config {
+	__u16 scale_factor_h, scale_factor_v;
+	__s16 coef[PISP_BE_RESAMPLE_FILTER_SIZE];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_resample_extra - PiSP Back End Resample config
+ *
+ * Resample configuration
+ *
+ * @scaled_width:	Width in pixels of the scaled output
+ * @scaled_height:	Height in pixels of the scaled output
+ * @initial_phase_h:	Initial horizontal phase
+ * @initial_phase_v:	Initial vertical phase
+ */
+struct pisp_be_resample_extra {
+	__u16 scaled_width;
+	__u16 scaled_height;
+	__s16 initial_phase_h[3];
+	__s16 initial_phase_v[3];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_downscale_config - PiSP Back End Downscale config
+ *
+ * Downscale configuration
+ *
+ * @scale_factor_h:	Horizontal scale factor
+ * @scale_factor_v:	Vertical scale factor
+ * @scale_recip_h:	Horizontal reciprocal factor
+ * @scale_recip_v:	Vertical reciprocal factor
+ */
+struct pisp_be_downscale_config {
+	__u16 scale_factor_h;
+	__u16 scale_factor_v;
+	__u16 scale_recip_h;
+	__u16 scale_recip_v;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_downscale_extra - PiSP Back End Downscale Extra config
+ * @scaled_width:	Scaled image width
+ * @scaled_height:	Scaled image height
+ */
+struct pisp_be_downscale_extra {
+	__u16 scaled_width;
+	__u16 scaled_height;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_hog_config - PiSP Back End HOG config
+ *
+ * Histogram of Oriented Gradients configuration
+ *
+ * @compute_signed:	Set 0 for unsigned gradients, 1 for signed
+ * @channel_mix:	Channels proportions to use
+ * @stride:		Stride in bytes between blocks directly below
+ */
+struct pisp_be_hog_config {
+	__u8 compute_signed;
+	__u8 channel_mix[3];
+	__u32 stride;
+} __attribute__((packed));
+
+struct pisp_be_axi_config {
+	__u8 r_qos; /* Read QoS */
+	__u8 r_cache_prot; /* Read { prot[2:0], cache[3:0] } */
+	__u8 w_qos; /* Write QoS */
+	__u8 w_cache_prot; /* Write { prot[2:0], cache[3:0] } */
+} __attribute__((packed));
+
+/**
+ * enum pisp_be_transform - PiSP Back End Transform flags
+ * @PISP_BE_TRANSFORM_NONE:	No transform
+ * @PISP_BE_TRANSFORM_HFLIP:	Horizontal flip
+ * @PISP_BE_TRANSFORM_VFLIP:	Vertical flip
+ * @PISP_BE_TRANSFORM_ROT180:	180 degress rotation
+ */
+enum pisp_be_transform {
+	PISP_BE_TRANSFORM_NONE = 0x0,
+	PISP_BE_TRANSFORM_HFLIP = 0x1,
+	PISP_BE_TRANSFORM_VFLIP = 0x2,
+	PISP_BE_TRANSFORM_ROT180 =
+		(PISP_BE_TRANSFORM_HFLIP | PISP_BE_TRANSFORM_VFLIP)
+};
+
+struct pisp_be_output_format_config {
+	struct pisp_image_format_config image;
+	__u8 transform;
+	__u8 pad[3];
+	__u16 lo;
+	__u16 hi;
+	__u16 lo2;
+	__u16 hi2;
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_output_buffer_config - PiSP Back End Output buffer
+ * @addr:		Output buffer address
+ */
+struct pisp_be_output_buffer_config {
+	/* low 32 bits followed by high 32 bits (for each of 3 planes) */
+	__u32 addr[3][2];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_hog_buffer_config - PiSP Back End HOG buffer
+ * @addr:		HOG buffer address
+ */
+struct pisp_be_hog_buffer_config {
+	/* low 32 bits followed by high 32 bits */
+	__u32 addr[2];
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_config - RaspberryPi PiSP Back End Processing configuration
+ *
+ * @input_buffer:		Input buffer addresses
+ * @tdn_input_buffer:		TDN input buffer addresses
+ * @stitch_input_buffer:	Stitch input buffer addresses
+ * @tdn_output_buffer:		TDN output buffer addresses
+ * @stitch_output_buffer:	Stitch output buffer addresses
+ * @output_buffer:		Output buffers addresses
+ * @hog_buffer:			HOG buffer addresses
+ * @global:			Global PiSP configuration
+ * @input_format:		Input image format
+ * @decompress:			Decompress configuration
+ * @dpc:			Defective Pixel Correction configuration
+ * @geq:			Green Equalisation configuration
+ * @tdn_input_format:		Temporal Denoise input format
+ * @tdn_decompress:		Temporal Denoise decompress configuration
+ * @tdn:			Temporal Denoise configuration
+ * @tdn_compress:		Temporal Denoise compress configuration
+ * @tdn_output_format:		Temporal Denoise output format
+ * @sdn:			Spatial Denoise configuration
+ * @blc:			Black Level Correction configuration
+ * @stitch_compress:		Stitch compress configuration
+ * @stitch_output_format:	Stitch output format
+ * @stitch_input_format:	Stitch input format
+ * @stitch_decompress:		Stitch decompress configuration
+ * @stitch:			Stitch configuration
+ * @lsc:			Lens Shading Correction configuration
+ * @wbg:			White Balance Gain configuration
+ * @cdn:			Colour Denoise configuration
+ * @cac:			Colour Aberration Correction configuration
+ * @debin:			Debinning configuration
+ * @tonemap:			Tonemapping configuration
+ * @demosaic:			Demosaicing configuration
+ * @ccm:			Colour Correction Matrix configuration
+ * @sat_control:		Saturation Control configuration
+ * @ycbcr:			YCbCr colour correction configuration
+ * @sharpen:			Sharpening configuration
+ * @false_colour:		False colour correction
+ * @sh_fc_combine:		Sharpening and False Colour correction
+ * @ycbcr_inverse:		Inverse YCbCr colour correction
+ * @gamma:			Gamma curve configuration
+ * @csc:			Color Space Conversion configuration
+ * @downscale:			Downscale configuration
+ * @resample:			Resampling configuration
+ * @output_format:		Output format configuration
+ * @hog:			HOG configuration
+ * @axi:			AXI bus configuration
+ * @lsc_extra:			LSC extra info
+ * @cac_extra:			CAC extra info
+ * @downscale_extra:		Downscaler extra info
+ * @resample_extra:		Resample extra info
+ * @crop:			Crop configuration
+ * @hog_format:			HOG format info
+ * @dirty_flags_bayer:		Bayer enable dirty flags
+ *				(:c:type:`pisp_be_bayer_enable`)
+ * @dirty_flags_rgb:		RGB enable dirty flags
+ *				(:c:type:`pisp_be_rgb_enable`)
+ * @dirty_flags_extra:		Extra dirty flags
+ */
+struct pisp_be_config {
+	/* I/O configuration: */
+	struct pisp_be_input_buffer_config input_buffer;
+	struct pisp_be_tdn_input_buffer_config tdn_input_buffer;
+	struct pisp_be_stitch_input_buffer_config stitch_input_buffer;
+	struct pisp_be_tdn_output_buffer_config tdn_output_buffer;
+	struct pisp_be_stitch_output_buffer_config stitch_output_buffer;
+	struct pisp_be_output_buffer_config
+				output_buffer[PISP_BACK_END_NUM_OUTPUTS];
+	struct pisp_be_hog_buffer_config hog_buffer;
+	/* Processing configuration: */
+	struct pisp_be_global_config global;
+	struct pisp_image_format_config input_format;
+	struct pisp_decompress_config decompress;
+	struct pisp_be_dpc_config dpc;
+	struct pisp_be_geq_config geq;
+	struct pisp_image_format_config tdn_input_format;
+	struct pisp_decompress_config tdn_decompress;
+	struct pisp_be_tdn_config tdn;
+	struct pisp_compress_config tdn_compress;
+	struct pisp_image_format_config tdn_output_format;
+	struct pisp_be_sdn_config sdn;
+	struct pisp_bla_config blc;
+	struct pisp_compress_config stitch_compress;
+	struct pisp_image_format_config stitch_output_format;
+	struct pisp_image_format_config stitch_input_format;
+	struct pisp_decompress_config stitch_decompress;
+	struct pisp_be_stitch_config stitch;
+	struct pisp_be_lsc_config lsc;
+	struct pisp_wbg_config wbg;
+	struct pisp_be_cdn_config cdn;
+	struct pisp_be_cac_config cac;
+	struct pisp_be_debin_config debin;
+	struct pisp_be_tonemap_config tonemap;
+	struct pisp_be_demosaic_config demosaic;
+	struct pisp_be_ccm_config ccm;
+	struct pisp_be_sat_control_config sat_control;
+	struct pisp_be_ccm_config ycbcr;
+	struct pisp_be_sharpen_config sharpen;
+	struct pisp_be_false_colour_config false_colour;
+	struct pisp_be_sh_fc_combine_config sh_fc_combine;
+	struct pisp_be_ccm_config ycbcr_inverse;
+	struct pisp_be_gamma_config gamma;
+	struct pisp_be_ccm_config csc[PISP_BACK_END_NUM_OUTPUTS];
+	struct pisp_be_downscale_config downscale[PISP_BACK_END_NUM_OUTPUTS];
+	struct pisp_be_resample_config resample[PISP_BACK_END_NUM_OUTPUTS];
+	struct pisp_be_output_format_config
+				output_format[PISP_BACK_END_NUM_OUTPUTS];
+	struct pisp_be_hog_config hog;
+	struct pisp_be_axi_config axi;
+	/* Non-register fields: */
+	struct pisp_be_lsc_extra lsc_extra;
+	struct pisp_be_cac_extra cac_extra;
+	struct pisp_be_downscale_extra
+				downscale_extra[PISP_BACK_END_NUM_OUTPUTS];
+	struct pisp_be_resample_extra resample_extra[PISP_BACK_END_NUM_OUTPUTS];
+	struct pisp_be_crop_config crop;
+	struct pisp_image_format_config hog_format;
+	__u32 dirty_flags_bayer; /* these use pisp_be_bayer_enable */
+	__u32 dirty_flags_rgb; /* use pisp_be_rgb_enable */
+	__u32 dirty_flags_extra; /* these use pisp_be_dirty_t */
+} __attribute__((packed));
+
+/**
+ * enum pisp_tile_edge - PiSP Back End Tile position
+ * @PISP_LEFT_EDGE:		Left edge tile
+ * @PISP_RIGHT_EDGE:		Right edge tile
+ * @PISP_TOP_EDGE:		Top edge tile
+ * @PISP_BOTTOM_EDGE:		Bottom edge tile
+ */
+enum pisp_tile_edge {
+	PISP_LEFT_EDGE = (1 << 0),
+	PISP_RIGHT_EDGE = (1 << 1),
+	PISP_TOP_EDGE = (1 << 2),
+	PISP_BOTTOM_EDGE = (1 << 3)
+};
+
+/**
+ * struct pisp_tile - Raspberry Pi PiSP Back End tile configuration
+ *
+ * Tile parameters: each set of tile parameters is a 160-bytes block of data
+ * which contains the tile processing parameters.
+ *
+ * @edge:			Edge tile flag
+ * @pad0:			Padding bytes
+ * @input_addr_offset:		Top-left pixel offset, in bytes
+ * @input_addr_offset2:		Top-left pixel offset, in bytes for the second/
+ *				third image planes
+ * @input_offset_x:		Horizontal offset in pixels of this tile in the
+ *				input image
+ * @input_offset_y:		Vertical offset in pixels of this tile in the
+ *				input image
+ * @input_width:		Width in pixels of this tile
+ * @input_height:		Height in pixels of the this tile
+ * @tdn_input_addr_offset:	TDN input image offset, in bytes
+ * @tdn_output_addr_offset:	TDN output image offset, in bytes
+ * @stitch_input_addr_offset:	Stitch input image offset, in bytes
+ * @stitch_output_addr_offset:	Stitch output image offset, in bytes
+ * @lsc_grid_offset_x:		Horizontal offset in the LSC table for this tile
+ * @lsc_grid_offset_y:		Vertical offset in the LSC table for this tile
+ * @cac_grid_offset_x:		Horizontal offset in the CAC table for this tile
+ * @cac_grid_offset_y:		Horizontal offset in the CAC table for this tile
+ * @crop_x_start:		Number of pixels cropped from the left of the
+ *				tile
+ * @crop_x_end:			Number of pixels cropped from the right of the
+ *				tile
+ * @crop_y_start:		Number of pixels cropped from the top of the
+ *				tile
+ * @crop_y_end:			Number of pixels cropped from the bottom of the
+ *				tile
+ * @downscale_phase_x:		Initial horizontal phase in pixels
+ * @downscale_phase_y:		Initial vertical phase in pixels
+ * @resample_in_width:		Width in pixels of the tile entering the
+ *				Resample block
+ * @resample_in_height:		Height in pixels of the tile entering the
+ *				Resample block
+ * @resample_phase_x:		Initial horizontal phase for the Resample block
+ * @resample_phase_y:		Initial vertical phase for the Resample block
+ * @output_offset_x:		Horizontal offset in pixels where the tile will
+ *				be written into the output image
+ * @output_offset_y:		Vertical offset in pixels where the tile will be
+ *				written into the output image
+ * @output_width:		Width in pixels in the output image of this tile
+ * @output_height:		Height in pixels in the output image of this tile
+ * @output_addr_offset:		Offset in bytes into the output buffer
+ * @output_addr_offset2:	Offset in bytes into the output buffer for the
+ *				second and third plane
+ * @output_hog_addr_offset:	Offset in bytes into the HOG buffer where
+ *				results of this tile are to be written
+ */
+struct pisp_tile {
+	__u8 edge; /* enum pisp_tile_edge */
+	__u8 pad0[3];
+	/* 4 bytes */
+	__u32 input_addr_offset;
+	__u32 input_addr_offset2;
+	__u16 input_offset_x;
+	__u16 input_offset_y;
+	__u16 input_width;
+	__u16 input_height;
+	/* 20 bytes */
+	__u32 tdn_input_addr_offset;
+	__u32 tdn_output_addr_offset;
+	__u32 stitch_input_addr_offset;
+	__u32 stitch_output_addr_offset;
+	/* 36 bytes */
+	__u32 lsc_grid_offset_x;
+	__u32 lsc_grid_offset_y;
+	/* 44 bytes */
+	__u32 cac_grid_offset_x;
+	__u32 cac_grid_offset_y;
+	/* 52 bytes */
+	__u16 crop_x_start[PISP_BACK_END_NUM_OUTPUTS];
+	__u16 crop_x_end[PISP_BACK_END_NUM_OUTPUTS];
+	__u16 crop_y_start[PISP_BACK_END_NUM_OUTPUTS];
+	__u16 crop_y_end[PISP_BACK_END_NUM_OUTPUTS];
+	/* 68 bytes */
+	/* Ordering is planes then branches */
+	__u16 downscale_phase_x[3 * PISP_BACK_END_NUM_OUTPUTS];
+	__u16 downscale_phase_y[3 * PISP_BACK_END_NUM_OUTPUTS];
+	/* 92 bytes */
+	__u16 resample_in_width[PISP_BACK_END_NUM_OUTPUTS];
+	__u16 resample_in_height[PISP_BACK_END_NUM_OUTPUTS];
+	/* 100 bytes */
+	/* Ordering is planes then branches */
+	__u16 resample_phase_x[3 * PISP_BACK_END_NUM_OUTPUTS];
+	__u16 resample_phase_y[3 * PISP_BACK_END_NUM_OUTPUTS];
+	/* 124 bytes */
+	__u16 output_offset_x[PISP_BACK_END_NUM_OUTPUTS];
+	__u16 output_offset_y[PISP_BACK_END_NUM_OUTPUTS];
+	__u16 output_width[PISP_BACK_END_NUM_OUTPUTS];
+	__u16 output_height[PISP_BACK_END_NUM_OUTPUTS];
+	/* 140 bytes */
+	__u32 output_addr_offset[PISP_BACK_END_NUM_OUTPUTS];
+	__u32 output_addr_offset2[PISP_BACK_END_NUM_OUTPUTS];
+	/* 156 bytes */
+	__u32 output_hog_addr_offset;
+	/* 160 bytes */
+} __attribute__((packed));
+
+/**
+ * struct pisp_be_tiles_config - Raspberry Pi PiSP Back End configuration
+ * @tiles:	Tile descriptors
+ * @num_tiles:	Number of tiles
+ * @config:	PiSP Back End configuration
+ */
+struct pisp_be_tiles_config {
+	struct pisp_be_config config;
+	struct pisp_tile tiles[PISP_BACK_END_NUM_TILES];
+	__u32 num_tiles;
+} __attribute__((packed));
+
+#endif /* _UAPI_PISP_BE_CONFIG_H_ */
diff --git a/original/uapi/linux/media/raspberrypi/pisp_common.h b/original/uapi/linux/media/raspberrypi/pisp_common.h
new file mode 100644
index 0000000..cbdccfe
--- /dev/null
+++ b/original/uapi/linux/media/raspberrypi/pisp_common.h
@@ -0,0 +1,202 @@
+/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
+/*
+ * RP1 PiSP common definitions.
+ *
+ * Copyright (C) 2021 - Raspberry Pi Ltd.
+ *
+ */
+#ifndef _UAPI_PISP_COMMON_H_
+#define _UAPI_PISP_COMMON_H_
+
+#include <linux/types.h>
+
+struct pisp_image_format_config {
+	/* size in pixels */
+	__u16 width;
+	__u16 height;
+	/* must match struct pisp_image_format below */
+	__u32 format;
+	__s32 stride;
+	/* some planar image formats will need a second stride */
+	__s32 stride2;
+} __attribute__((packed));
+
+enum pisp_bayer_order {
+	/*
+	 * Note how bayer_order&1 tells you if G is on the even pixels of the
+	 * checkerboard or not, and bayer_order&2 tells you if R is on the even
+	 * rows or is swapped with B. Note that if the top (of the 8) bits is
+	 * set, this denotes a monochrome or greyscale image, and the lower bits
+	 * should all be ignored.
+	 */
+	PISP_BAYER_ORDER_RGGB = 0,
+	PISP_BAYER_ORDER_GBRG = 1,
+	PISP_BAYER_ORDER_BGGR = 2,
+	PISP_BAYER_ORDER_GRBG = 3,
+	PISP_BAYER_ORDER_GREYSCALE = 128
+};
+
+enum pisp_image_format {
+	/*
+	 * Precise values are mostly tbd. Generally these will be portmanteau
+	 * values comprising bit fields and flags. This format must be shared
+	 * throughout the PiSP.
+	 */
+	PISP_IMAGE_FORMAT_BPS_8 = 0x00000000,
+	PISP_IMAGE_FORMAT_BPS_10 = 0x00000001,
+	PISP_IMAGE_FORMAT_BPS_12 = 0x00000002,
+	PISP_IMAGE_FORMAT_BPS_16 = 0x00000003,
+	PISP_IMAGE_FORMAT_BPS_MASK = 0x00000003,
+
+	PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED = 0x00000000,
+	PISP_IMAGE_FORMAT_PLANARITY_SEMI_PLANAR = 0x00000010,
+	PISP_IMAGE_FORMAT_PLANARITY_PLANAR = 0x00000020,
+	PISP_IMAGE_FORMAT_PLANARITY_MASK = 0x00000030,
+
+	PISP_IMAGE_FORMAT_SAMPLING_444 = 0x00000000,
+	PISP_IMAGE_FORMAT_SAMPLING_422 = 0x00000100,
+	PISP_IMAGE_FORMAT_SAMPLING_420 = 0x00000200,
+	PISP_IMAGE_FORMAT_SAMPLING_MASK = 0x00000300,
+
+	PISP_IMAGE_FORMAT_ORDER_NORMAL = 0x00000000,
+	PISP_IMAGE_FORMAT_ORDER_SWAPPED = 0x00001000,
+
+	PISP_IMAGE_FORMAT_SHIFT_0 = 0x00000000,
+	PISP_IMAGE_FORMAT_SHIFT_1 = 0x00010000,
+	PISP_IMAGE_FORMAT_SHIFT_2 = 0x00020000,
+	PISP_IMAGE_FORMAT_SHIFT_3 = 0x00030000,
+	PISP_IMAGE_FORMAT_SHIFT_4 = 0x00040000,
+	PISP_IMAGE_FORMAT_SHIFT_5 = 0x00050000,
+	PISP_IMAGE_FORMAT_SHIFT_6 = 0x00060000,
+	PISP_IMAGE_FORMAT_SHIFT_7 = 0x00070000,
+	PISP_IMAGE_FORMAT_SHIFT_8 = 0x00080000,
+	PISP_IMAGE_FORMAT_SHIFT_MASK = 0x000f0000,
+
+	PISP_IMAGE_FORMAT_BPP_32 = 0x00100000,
+
+	PISP_IMAGE_FORMAT_UNCOMPRESSED = 0x00000000,
+	PISP_IMAGE_FORMAT_COMPRESSION_MODE_1 = 0x01000000,
+	PISP_IMAGE_FORMAT_COMPRESSION_MODE_2 = 0x02000000,
+	PISP_IMAGE_FORMAT_COMPRESSION_MODE_3 = 0x03000000,
+	PISP_IMAGE_FORMAT_COMPRESSION_MASK = 0x03000000,
+
+	PISP_IMAGE_FORMAT_HOG_SIGNED = 0x04000000,
+	PISP_IMAGE_FORMAT_HOG_UNSIGNED = 0x08000000,
+	PISP_IMAGE_FORMAT_INTEGRAL_IMAGE = 0x10000000,
+	PISP_IMAGE_FORMAT_WALLPAPER_ROLL = 0x20000000,
+	PISP_IMAGE_FORMAT_THREE_CHANNEL = 0x40000000,
+
+	/* Lastly a few specific instantiations of the above. */
+	PISP_IMAGE_FORMAT_SINGLE_16 = PISP_IMAGE_FORMAT_BPS_16,
+	PISP_IMAGE_FORMAT_THREE_16 = PISP_IMAGE_FORMAT_BPS_16 |
+				     PISP_IMAGE_FORMAT_THREE_CHANNEL
+};
+
+#define PISP_IMAGE_FORMAT_BPS_8(fmt)                                           \
+	(((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_8)
+#define PISP_IMAGE_FORMAT_BPS_10(fmt)                                          \
+	(((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_10)
+#define PISP_IMAGE_FORMAT_BPS_12(fmt)                                          \
+	(((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_12)
+#define PISP_IMAGE_FORMAT_BPS_16(fmt)                                          \
+	(((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_16)
+#define PISP_IMAGE_FORMAT_BPS(fmt)                                             \
+	(((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) ?                                \
+	       8 + (2 << (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) - 1)) : 8)
+#define PISP_IMAGE_FORMAT_SHIFT(fmt)                                           \
+	(((fmt) & PISP_IMAGE_FORMAT_SHIFT_MASK) / PISP_IMAGE_FORMAT_SHIFT_1)
+#define PISP_IMAGE_FORMAT_THREE_CHANNEL(fmt)                                   \
+	((fmt) & PISP_IMAGE_FORMAT_THREE_CHANNEL)
+#define PISP_IMAGE_FORMAT_SINGLE_CHANNEL(fmt)                                  \
+	(!((fmt) & PISP_IMAGE_FORMAT_THREE_CHANNEL))
+#define PISP_IMAGE_FORMAT_COMPRESSED(fmt)                                      \
+	(((fmt) & PISP_IMAGE_FORMAT_COMPRESSION_MASK) !=                       \
+	 PISP_IMAGE_FORMAT_UNCOMPRESSED)
+#define PISP_IMAGE_FORMAT_SAMPLING_444(fmt)                                    \
+	(((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) ==                          \
+	 PISP_IMAGE_FORMAT_SAMPLING_444)
+#define PISP_IMAGE_FORMAT_SAMPLING_422(fmt)                                    \
+	(((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) ==                          \
+	 PISP_IMAGE_FORMAT_SAMPLING_422)
+#define PISP_IMAGE_FORMAT_SAMPLING_420(fmt)                                    \
+	(((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) ==                          \
+	 PISP_IMAGE_FORMAT_SAMPLING_420)
+#define PISP_IMAGE_FORMAT_ORDER_NORMAL(fmt)                                    \
+	(!((fmt) & PISP_IMAGE_FORMAT_ORDER_SWAPPED))
+#define PISP_IMAGE_FORMAT_ORDER_SWAPPED(fmt)                                   \
+	((fmt) & PISP_IMAGE_FORMAT_ORDER_SWAPPED)
+#define PISP_IMAGE_FORMAT_INTERLEAVED(fmt)                                     \
+	(((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) ==                         \
+	 PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED)
+#define PISP_IMAGE_FORMAT_SEMIPLANAR(fmt)                                      \
+	(((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) ==                         \
+	 PISP_IMAGE_FORMAT_PLANARITY_SEMI_PLANAR)
+#define PISP_IMAGE_FORMAT_PLANAR(fmt)                                          \
+	(((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) ==                         \
+	 PISP_IMAGE_FORMAT_PLANARITY_PLANAR)
+#define PISP_IMAGE_FORMAT_WALLPAPER(fmt)                                       \
+	((fmt) & PISP_IMAGE_FORMAT_WALLPAPER_ROLL)
+#define PISP_IMAGE_FORMAT_BPP_32(fmt) ((fmt) & PISP_IMAGE_FORMAT_BPP_32)
+#define PISP_IMAGE_FORMAT_HOG(fmt)                                             \
+	((fmt) &                                                               \
+	 (PISP_IMAGE_FORMAT_HOG_SIGNED | PISP_IMAGE_FORMAT_HOG_UNSIGNED))
+
+#define PISP_WALLPAPER_WIDTH 128 /* in bytes */
+
+struct pisp_bla_config {
+	__u16 black_level_r;
+	__u16 black_level_gr;
+	__u16 black_level_gb;
+	__u16 black_level_b;
+	__u16 output_black_level;
+	__u8 pad[2];
+} __attribute__((packed));
+
+struct pisp_wbg_config {
+	__u16 gain_r;
+	__u16 gain_g;
+	__u16 gain_b;
+	__u8 pad[2];
+} __attribute__((packed));
+
+struct pisp_compress_config {
+	/* value subtracted from incoming data */
+	__u16 offset;
+	__u8 pad;
+	/* 1 => Companding; 2 => Delta (recommended); 3 => Combined (for HDR) */
+	__u8 mode;
+} __attribute__((packed));
+
+struct pisp_decompress_config {
+	/* value added to reconstructed data */
+	__u16 offset;
+	__u8 pad;
+	/* 1 => Companding; 2 => Delta (recommended); 3 => Combined (for HDR) */
+	__u8 mode;
+} __attribute__((packed));
+
+enum pisp_axi_flags {
+	/*
+	 * round down bursts to end at a 32-byte boundary, to align following
+	 * bursts
+	 */
+	PISP_AXI_FLAG_ALIGN = 128,
+	/* for FE writer: force WSTRB high, to pad output to 16-byte boundary */
+	PISP_AXI_FLAG_PAD = 64,
+	/* for FE writer: Use Output FIFO level to trigger "panic" */
+	PISP_AXI_FLAG_PANIC = 32,
+};
+
+struct pisp_axi_config {
+	/*
+	 * burst length minus one, which must be in the range 0:15; OR'd with
+	 * flags
+	 */
+	__u8 maxlen_flags;
+	/* { prot[2:0], cache[3:0] } fields, echoed on AXI bus */
+	__u8 cache_prot;
+	/* QoS field(s) (4x4 bits for FE writer; 4 bits for other masters) */
+	__u16 qos;
+} __attribute__((packed));
+
+#endif /* _UAPI_PISP_COMMON_H_ */
diff --git a/original/uapi/linux/mman.h b/original/uapi/linux/mman.h
index a246e11..e89d005 100644
--- a/original/uapi/linux/mman.h
+++ b/original/uapi/linux/mman.h
@@ -17,6 +17,7 @@
 #define MAP_SHARED	0x01		/* Share changes */
 #define MAP_PRIVATE	0x02		/* Changes are private */
 #define MAP_SHARED_VALIDATE 0x03	/* share + validate extension flags */
+#define MAP_DROPPABLE	0x08		/* Zero memory under memory pressure. */
 
 /*
  * Huge page size encoding when MAP_HUGETLB is specified, and a huge page
diff --git a/original/uapi/linux/mount.h b/original/uapi/linux/mount.h
index ad5478d..225bc36 100644
--- a/original/uapi/linux/mount.h
+++ b/original/uapi/linux/mount.h
@@ -154,7 +154,7 @@ struct mount_attr {
  */
 struct statmount {
 	__u32 size;		/* Total size, including strings */
-	__u32 __spare1;
+	__u32 mnt_opts;		/* [str] Mount options of the mount */
 	__u64 mask;		/* What results were written */
 	__u32 sb_dev_major;	/* Device ID */
 	__u32 sb_dev_minor;
@@ -172,7 +172,8 @@ struct statmount {
 	__u64 propagate_from;	/* Propagation from in current namespace */
 	__u32 mnt_root;		/* [str] Root of mount relative to root of fs */
 	__u32 mnt_point;	/* [str] Mountpoint relative to current root */
-	__u64 __spare2[50];
+	__u64 mnt_ns_id;	/* ID of the mount namespace */
+	__u64 __spare2[49];
 	char str[];		/* Variable size part containing strings */
 };
 
@@ -188,10 +189,12 @@ struct mnt_id_req {
 	__u32 spare;
 	__u64 mnt_id;
 	__u64 param;
+	__u64 mnt_ns_id;
 };
 
 /* List of all mnt_id_req versions. */
 #define MNT_ID_REQ_SIZE_VER0	24 /* sizeof first published struct */
+#define MNT_ID_REQ_SIZE_VER1	32 /* sizeof second published struct */
 
 /*
  * @mask bits for statmount(2)
@@ -202,10 +205,13 @@ struct mnt_id_req {
 #define STATMOUNT_MNT_ROOT		0x00000008U	/* Want/got mnt_root  */
 #define STATMOUNT_MNT_POINT		0x00000010U	/* Want/got mnt_point */
 #define STATMOUNT_FS_TYPE		0x00000020U	/* Want/got fs_type */
+#define STATMOUNT_MNT_NS_ID		0x00000040U	/* Want/got mnt_ns_id */
+#define STATMOUNT_MNT_OPTS		0x00000080U	/* Want/got mnt_opts */
 
 /*
  * Special @mnt_id values that can be passed to listmount
  */
 #define LSMT_ROOT		0xffffffffffffffff	/* root mount */
+#define LISTMOUNT_REVERSE	(1 << 0) /* List later mounts first */
 
 #endif /* _UAPI_LINUX_MOUNT_H */
diff --git a/original/uapi/linux/netfilter/nf_tables.h b/original/uapi/linux/netfilter/nf_tables.h
index aa4094c..639894e 100644
--- a/original/uapi/linux/netfilter/nf_tables.h
+++ b/original/uapi/linux/netfilter/nf_tables.h
@@ -1376,7 +1376,7 @@ enum nft_secmark_attributes {
 #define NFTA_SECMARK_MAX	(__NFTA_SECMARK_MAX - 1)
 
 /* Max security context length */
-#define NFT_SECMARK_CTX_MAXLEN		256
+#define NFT_SECMARK_CTX_MAXLEN		4096
 
 /**
  * enum nft_reject_types - nf_tables reject expression reject types
diff --git a/original/uapi/linux/nfs4.h b/original/uapi/linux/nfs4.h
index 1d20437..caf4db2 100644
--- a/original/uapi/linux/nfs4.h
+++ b/original/uapi/linux/nfs4.h
@@ -46,6 +46,7 @@
 #define NFS4_OPEN_RESULT_CONFIRM		0x0002
 #define NFS4_OPEN_RESULT_LOCKTYPE_POSIX		0x0004
 #define NFS4_OPEN_RESULT_PRESERVE_UNLINKED	0x0008
+#define NFS4_OPEN_RESULT_NO_OPEN_STATEID	0x0010
 #define NFS4_OPEN_RESULT_MAY_NOTIFY_LOCK	0x0020
 
 #define NFS4_SHARE_ACCESS_MASK	0x000F
@@ -69,6 +70,9 @@
 #define NFS4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL	0x10000
 #define NFS4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED		0x20000
 
+#define NFS4_SHARE_WANT_DELEG_TIMESTAMPS		0x100000
+#define NFS4_SHARE_WANT_OPEN_XOR_DELEGATION		0x200000
+
 #define NFS4_CDFC4_FORE	0x1
 #define NFS4_CDFC4_BACK 0x2
 #define NFS4_CDFC4_BOTH 0x3
diff --git a/original/uapi/linux/nfsd_netlink.h b/original/uapi/linux/nfsd_netlink.h
index 24c86db..887cbd1 100644
--- a/original/uapi/linux/nfsd_netlink.h
+++ b/original/uapi/linux/nfsd_netlink.h
@@ -70,6 +70,14 @@ enum {
 	NFSD_A_SERVER_SOCK_MAX = (__NFSD_A_SERVER_SOCK_MAX - 1)
 };
 
+enum {
+	NFSD_A_POOL_MODE_MODE = 1,
+	NFSD_A_POOL_MODE_NPOOLS,
+
+	__NFSD_A_POOL_MODE_MAX,
+	NFSD_A_POOL_MODE_MAX = (__NFSD_A_POOL_MODE_MAX - 1)
+};
+
 enum {
 	NFSD_CMD_RPC_STATUS_GET = 1,
 	NFSD_CMD_THREADS_SET,
@@ -78,6 +86,8 @@ enum {
 	NFSD_CMD_VERSION_GET,
 	NFSD_CMD_LISTENER_SET,
 	NFSD_CMD_LISTENER_GET,
+	NFSD_CMD_POOL_MODE_SET,
+	NFSD_CMD_POOL_MODE_GET,
 
 	__NFSD_CMD_MAX,
 	NFSD_CMD_MAX = (__NFSD_CMD_MAX - 1)
diff --git a/original/uapi/linux/nl80211.h b/original/uapi/linux/nl80211.h
index f917bc6..f97f5ad 100644
--- a/original/uapi/linux/nl80211.h
+++ b/original/uapi/linux/nl80211.h
@@ -2052,6 +2052,10 @@ enum nl80211_commands {
  * @NL80211_ATTR_INTERFACE_COMBINATIONS: Nested attribute listing the supported
  *	interface combinations. In each nested item, it contains attributes
  *	defined in &enum nl80211_if_combination_attrs.
+ *	If the wiphy uses multiple radios (@NL80211_ATTR_WIPHY_RADIOS is set),
+ *	this attribute contains the interface combinations of the first radio.
+ *	See @NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS for the global wiphy
+ *	combinations for the sum of all radios.
  * @NL80211_ATTR_SOFTWARE_IFTYPES: Nested attribute (just like
  *	%NL80211_ATTR_SUPPORTED_IFTYPES) containing the interface types that
  *	are managed in software: interfaces of these types aren't subject to
@@ -2856,6 +2860,14 @@ enum nl80211_commands {
  *	%NL80211_CMD_ASSOCIATE indicating the SPP A-MSDUs
  *	are used on this connection
  *
+ * @NL80211_ATTR_WIPHY_RADIOS: Nested attribute describing physical radios
+ *	belonging to this wiphy. See &enum nl80211_wiphy_radio_attrs.
+ *
+ * @NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS: Nested attribute listing the
+ *	supported interface combinations for all radios combined. In each
+ *	nested item, it contains attributes defined in
+ *	&enum nl80211_if_combination_attrs.
+ *
  * @NUM_NL80211_ATTR: total number of nl80211_attrs available
  * @NL80211_ATTR_MAX: highest attribute number currently defined
  * @__NL80211_ATTR_AFTER_LAST: internal use
@@ -3401,6 +3413,9 @@ enum nl80211_attrs {
 
 	NL80211_ATTR_ASSOC_SPP_AMSDU,
 
+	NL80211_ATTR_WIPHY_RADIOS,
+	NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS,
+
 	/* add attributes here, update the policy in nl80211.c */
 
 	__NL80211_ATTR_AFTER_LAST,
@@ -4277,6 +4292,8 @@ enum nl80211_wmm_rule {
  * @NL80211_FREQUENCY_ATTR_CAN_MONITOR: This channel can be used in monitor
  *	mode despite other (regulatory) restrictions, even if the channel is
  *	otherwise completely disabled.
+ * @NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP: This channel can be used for a
+ *	very low power (VLP) AP, despite being NO_IR.
  * @NL80211_FREQUENCY_ATTR_MAX: highest frequency attribute number
  *	currently defined
  * @__NL80211_FREQUENCY_ATTR_AFTER_LAST: internal use
@@ -4320,6 +4337,7 @@ enum nl80211_frequency_attr {
 	NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT,
 	NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT,
 	NL80211_FREQUENCY_ATTR_CAN_MONITOR,
+	NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP,
 
 	/* keep last */
 	__NL80211_FREQUENCY_ATTR_AFTER_LAST,
@@ -4529,6 +4547,8 @@ enum nl80211_sched_scan_match_attr {
  *	Should be used together with %NL80211_RRF_DFS only.
  * @NL80211_RRF_NO_6GHZ_VLP_CLIENT: Client connection to VLP AP not allowed
  * @NL80211_RRF_NO_6GHZ_AFC_CLIENT: Client connection to AFC AP not allowed
+ * @NL80211_RRF_ALLOW_6GHZ_VLP_AP: Very low power (VLP) AP can be permitted
+ *	despite NO_IR configuration.
  */
 enum nl80211_reg_rule_flags {
 	NL80211_RRF_NO_OFDM		= 1<<0,
@@ -4553,6 +4573,7 @@ enum nl80211_reg_rule_flags {
 	NL80211_RRF_DFS_CONCURRENT	= 1<<21,
 	NL80211_RRF_NO_6GHZ_VLP_CLIENT	= 1<<22,
 	NL80211_RRF_NO_6GHZ_AFC_CLIENT	= 1<<23,
+	NL80211_RRF_ALLOW_6GHZ_VLP_AP	= 1<<24,
 };
 
 #define NL80211_RRF_PASSIVE_SCAN	NL80211_RRF_NO_IR
@@ -7999,4 +8020,54 @@ enum nl80211_ap_settings_flags {
 	NL80211_AP_SETTINGS_SA_QUERY_OFFLOAD_SUPPORT	= 1 << 1,
 };
 
+/**
+ * enum nl80211_wiphy_radio_attrs - wiphy radio attributes
+ *
+ * @__NL80211_WIPHY_RADIO_ATTR_INVALID: Invalid
+ *
+ * @NL80211_WIPHY_RADIO_ATTR_INDEX: Index of this radio (u32)
+ * @NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE: Frequency range supported by this
+ *	radio. Attribute may be present multiple times.
+ * @NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION: Supported interface
+ *	combination for this radio. Attribute may be present multiple times
+ *	and contains attributes defined in &enum nl80211_if_combination_attrs.
+ *
+ * @__NL80211_WIPHY_RADIO_ATTR_LAST: Internal
+ * @NL80211_WIPHY_RADIO_ATTR_MAX: Highest attribute
+ */
+enum nl80211_wiphy_radio_attrs {
+	__NL80211_WIPHY_RADIO_ATTR_INVALID,
+
+	NL80211_WIPHY_RADIO_ATTR_INDEX,
+	NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE,
+	NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION,
+
+	/* keep last */
+	__NL80211_WIPHY_RADIO_ATTR_LAST,
+	NL80211_WIPHY_RADIO_ATTR_MAX = __NL80211_WIPHY_RADIO_ATTR_LAST - 1,
+};
+
+/**
+ * enum nl80211_wiphy_radio_freq_range - wiphy radio frequency range
+ *
+ * @__NL80211_WIPHY_RADIO_FREQ_ATTR_INVALID: Invalid
+ *
+ * @NL80211_WIPHY_RADIO_FREQ_ATTR_START: Frequency range start (u32).
+ *	The unit is kHz.
+ * @NL80211_WIPHY_RADIO_FREQ_ATTR_END: Frequency range end (u32).
+ *	The unit is kHz.
+ *
+ * @__NL80211_WIPHY_RADIO_FREQ_ATTR_LAST: Internal
+ * @NL80211_WIPHY_RADIO_FREQ_ATTR_MAX: Highest attribute
+ */
+enum nl80211_wiphy_radio_freq_range {
+	__NL80211_WIPHY_RADIO_FREQ_ATTR_INVALID,
+
+	NL80211_WIPHY_RADIO_FREQ_ATTR_START,
+	NL80211_WIPHY_RADIO_FREQ_ATTR_END,
+
+	__NL80211_WIPHY_RADIO_FREQ_ATTR_LAST,
+	NL80211_WIPHY_RADIO_FREQ_ATTR_MAX = __NL80211_WIPHY_RADIO_FREQ_ATTR_LAST - 1,
+};
+
 #endif /* __LINUX_NL80211_H */
diff --git a/original/uapi/linux/nsfs.h b/original/uapi/linux/nsfs.h
index a0c8552..5fad3d0 100644
--- a/original/uapi/linux/nsfs.h
+++ b/original/uapi/linux/nsfs.h
@@ -3,6 +3,7 @@
 #define __LINUX_NSFS_H
 
 #include <linux/ioctl.h>
+#include <linux/types.h>
 
 #define NSIO	0xb7
 
@@ -15,5 +16,15 @@
 #define NS_GET_NSTYPE		_IO(NSIO, 0x3)
 /* Get owner UID (in the caller's user namespace) for a user namespace */
 #define NS_GET_OWNER_UID	_IO(NSIO, 0x4)
+/* Get the id for a mount namespace */
+#define NS_GET_MNTNS_ID		_IOR(NSIO, 0x5, __u64)
+/* Translate pid from target pid namespace into the caller's pid namespace. */
+#define NS_GET_PID_FROM_PIDNS	_IOR(NSIO, 0x6, int)
+/* Return thread-group leader id of pid in the callers pid namespace. */
+#define NS_GET_TGID_FROM_PIDNS	_IOR(NSIO, 0x7, int)
+/* Translate pid from caller's pid namespace into a target pid namespace. */
+#define NS_GET_PID_IN_PIDNS	_IOR(NSIO, 0x8, int)
+/* Return thread-group leader id of pid in the target pid namespace. */
+#define NS_GET_TGID_IN_PIDNS	_IOR(NSIO, 0x9, int)
 
 #endif /* __LINUX_NSFS_H */
diff --git a/original/uapi/linux/openvswitch.h b/original/uapi/linux/openvswitch.h
index efc82c3..3a701bd 100644
--- a/original/uapi/linux/openvswitch.h
+++ b/original/uapi/linux/openvswitch.h
@@ -649,7 +649,8 @@ enum ovs_flow_attr {
  * Actions are passed as nested attributes.
  *
  * Executes the specified actions with the given probability on a per-packet
- * basis.
+ * basis. Nested actions will be able to access the probability value of the
+ * parent @OVS_ACTION_ATTR_SAMPLE.
  */
 enum ovs_sample_attr {
 	OVS_SAMPLE_ATTR_UNSPEC,
@@ -914,6 +915,31 @@ struct check_pkt_len_arg {
 };
 #endif
 
+#define OVS_PSAMPLE_COOKIE_MAX_SIZE 16
+/**
+ * enum ovs_psample_attr - Attributes for %OVS_ACTION_ATTR_PSAMPLE
+ * action.
+ *
+ * @OVS_PSAMPLE_ATTR_GROUP: 32-bit number to identify the source of the
+ * sample.
+ * @OVS_PSAMPLE_ATTR_COOKIE: An optional variable-length binary cookie that
+ * contains user-defined metadata. The maximum length is
+ * OVS_PSAMPLE_COOKIE_MAX_SIZE bytes.
+ *
+ * Sends the packet to the psample multicast group with the specified group and
+ * cookie. It is possible to combine this action with the
+ * %OVS_ACTION_ATTR_TRUNC action to limit the size of the sample.
+ */
+enum ovs_psample_attr {
+	OVS_PSAMPLE_ATTR_GROUP = 1,	/* u32 number. */
+	OVS_PSAMPLE_ATTR_COOKIE,	/* Optional, user specified cookie. */
+
+	/* private: */
+	__OVS_PSAMPLE_ATTR_MAX
+};
+
+#define OVS_PSAMPLE_ATTR_MAX (__OVS_PSAMPLE_ATTR_MAX - 1)
+
 /**
  * enum ovs_action_attr - Action types.
  *
@@ -966,6 +992,8 @@ struct check_pkt_len_arg {
  * of l3 tunnel flag in the tun_flags field of OVS_ACTION_ATTR_ADD_MPLS
  * argument.
  * @OVS_ACTION_ATTR_DROP: Explicit drop action.
+ * @OVS_ACTION_ATTR_PSAMPLE: Send a sample of the packet to external observers
+ * via psample.
  *
  * Only a single header can be set with a single %OVS_ACTION_ATTR_SET.  Not all
  * fields within a header are modifiable, e.g. the IPv4 protocol and fragment
@@ -1004,6 +1032,7 @@ enum ovs_action_attr {
 	OVS_ACTION_ATTR_ADD_MPLS,     /* struct ovs_action_add_mpls. */
 	OVS_ACTION_ATTR_DEC_TTL,      /* Nested OVS_DEC_TTL_ATTR_*. */
 	OVS_ACTION_ATTR_DROP,         /* u32 error code. */
+	OVS_ACTION_ATTR_PSAMPLE,      /* Nested OVS_PSAMPLE_ATTR_*. */
 
 	__OVS_ACTION_ATTR_MAX,	      /* Nothing past this will be accepted
 				       * from userspace. */
diff --git a/original/uapi/linux/perf_event.h b/original/uapi/linux/perf_event.h
index 3a64499..4842c36 100644
--- a/original/uapi/linux/perf_event.h
+++ b/original/uapi/linux/perf_event.h
@@ -1349,12 +1349,14 @@ union perf_mem_data_src {
 #define PERF_MEM_LVLNUM_L2	0x02 /* L2 */
 #define PERF_MEM_LVLNUM_L3	0x03 /* L3 */
 #define PERF_MEM_LVLNUM_L4	0x04 /* L4 */
-/* 5-0x7 available */
+#define PERF_MEM_LVLNUM_L2_MHB	0x05 /* L2 Miss Handling Buffer */
+#define PERF_MEM_LVLNUM_MSC	0x06 /* Memory-side Cache */
+/* 0x7 available */
 #define PERF_MEM_LVLNUM_UNC	0x08 /* Uncached */
 #define PERF_MEM_LVLNUM_CXL	0x09 /* CXL */
 #define PERF_MEM_LVLNUM_IO	0x0a /* I/O */
 #define PERF_MEM_LVLNUM_ANY_CACHE 0x0b /* Any cache */
-#define PERF_MEM_LVLNUM_LFB	0x0c /* LFB */
+#define PERF_MEM_LVLNUM_LFB	0x0c /* LFB / L1 Miss Handling Buffer */
 #define PERF_MEM_LVLNUM_RAM	0x0d /* RAM */
 #define PERF_MEM_LVLNUM_PMEM	0x0e /* PMEM */
 #define PERF_MEM_LVLNUM_NA	0x0f /* N/A */
diff --git a/original/uapi/linux/pidfd.h b/original/uapi/linux/pidfd.h
index 72ec000..565fc06 100644
--- a/original/uapi/linux/pidfd.h
+++ b/original/uapi/linux/pidfd.h
@@ -5,6 +5,7 @@
 
 #include <linux/types.h>
 #include <linux/fcntl.h>
+#include <linux/ioctl.h>
 
 /* Flags for pidfd_open().  */
 #define PIDFD_NONBLOCK	O_NONBLOCK
@@ -15,4 +16,17 @@
 #define PIDFD_SIGNAL_THREAD_GROUP	(1UL << 1)
 #define PIDFD_SIGNAL_PROCESS_GROUP	(1UL << 2)
 
+#define PIDFS_IOCTL_MAGIC 0xFF
+
+#define PIDFD_GET_CGROUP_NAMESPACE            _IO(PIDFS_IOCTL_MAGIC, 1)
+#define PIDFD_GET_IPC_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 2)
+#define PIDFD_GET_MNT_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 3)
+#define PIDFD_GET_NET_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 4)
+#define PIDFD_GET_PID_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 5)
+#define PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE  _IO(PIDFS_IOCTL_MAGIC, 6)
+#define PIDFD_GET_TIME_NAMESPACE              _IO(PIDFS_IOCTL_MAGIC, 7)
+#define PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 8)
+#define PIDFD_GET_USER_NAMESPACE              _IO(PIDFS_IOCTL_MAGIC, 9)
+#define PIDFD_GET_UTS_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 10)
+
 #endif /* _UAPI_LINUX_PIDFD_H */
diff --git a/original/uapi/linux/pkt_cls.h b/original/uapi/linux/pkt_cls.h
index 229fc92..d36d9cd 100644
--- a/original/uapi/linux/pkt_cls.h
+++ b/original/uapi/linux/pkt_cls.h
@@ -554,6 +554,9 @@ enum {
 	TCA_FLOWER_KEY_SPI,		/* be32 */
 	TCA_FLOWER_KEY_SPI_MASK,	/* be32 */
 
+	TCA_FLOWER_KEY_ENC_FLAGS,	/* be32 */
+	TCA_FLOWER_KEY_ENC_FLAGS_MASK,	/* be32 */
+
 	__TCA_FLOWER_MAX,
 };
 
@@ -674,8 +677,15 @@ enum {
 enum {
 	TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT = (1 << 0),
 	TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST = (1 << 1),
+	TCA_FLOWER_KEY_FLAGS_TUNNEL_CSUM = (1 << 2),
+	TCA_FLOWER_KEY_FLAGS_TUNNEL_DONT_FRAGMENT = (1 << 3),
+	TCA_FLOWER_KEY_FLAGS_TUNNEL_OAM = (1 << 4),
+	TCA_FLOWER_KEY_FLAGS_TUNNEL_CRIT_OPT = (1 << 5),
+	__TCA_FLOWER_KEY_FLAGS_MAX,
 };
 
+#define TCA_FLOWER_KEY_FLAGS_MAX (__TCA_FLOWER_KEY_FLAGS_MAX - 1)
+
 enum {
 	TCA_FLOWER_KEY_CFM_OPT_UNSPEC,
 	TCA_FLOWER_KEY_CFM_MD_LEVEL,
diff --git a/original/uapi/linux/psample.h b/original/uapi/linux/psample.h
index e585db5..b765f0e 100644
--- a/original/uapi/linux/psample.h
+++ b/original/uapi/linux/psample.h
@@ -8,7 +8,11 @@ enum {
 	PSAMPLE_ATTR_ORIGSIZE,
 	PSAMPLE_ATTR_SAMPLE_GROUP,
 	PSAMPLE_ATTR_GROUP_SEQ,
-	PSAMPLE_ATTR_SAMPLE_RATE,
+	PSAMPLE_ATTR_SAMPLE_RATE,	/* u32, ratio between observed and
+					 * sampled packets or scaled probability
+					 * if PSAMPLE_ATTR_SAMPLE_PROBABILITY
+					 * is set.
+					 */
 	PSAMPLE_ATTR_DATA,
 	PSAMPLE_ATTR_GROUP_REFCOUNT,
 	PSAMPLE_ATTR_TUNNEL,
@@ -19,6 +23,11 @@ enum {
 	PSAMPLE_ATTR_LATENCY,		/* u64, nanoseconds */
 	PSAMPLE_ATTR_TIMESTAMP,		/* u64, nanoseconds */
 	PSAMPLE_ATTR_PROTO,		/* u16 */
+	PSAMPLE_ATTR_USER_COOKIE,	/* binary, user provided data */
+	PSAMPLE_ATTR_SAMPLE_PROBABILITY,/* no argument, interpret rate in
+					 * PSAMPLE_ATTR_SAMPLE_RATE as a
+					 * probability scaled 0 - U32_MAX.
+					 */
 
 	__PSAMPLE_ATTR_MAX
 };
diff --git a/original/uapi/linux/psp-sev.h b/original/uapi/linux/psp-sev.h
index b7a2c2e..832c15d 100644
--- a/original/uapi/linux/psp-sev.h
+++ b/original/uapi/linux/psp-sev.h
@@ -31,6 +31,7 @@ enum {
 	SNP_PLATFORM_STATUS,
 	SNP_COMMIT,
 	SNP_SET_CONFIG,
+	SNP_VLEK_LOAD,
 
 	SEV_MAX,
 };
@@ -50,6 +51,7 @@ typedef enum {
 	SEV_RET_INVALID_PLATFORM_STATE,
 	SEV_RET_INVALID_GUEST_STATE,
 	SEV_RET_INAVLID_CONFIG,
+	SEV_RET_INVALID_CONFIG = SEV_RET_INAVLID_CONFIG,
 	SEV_RET_INVALID_LEN,
 	SEV_RET_ALREADY_OWNED,
 	SEV_RET_INVALID_CERTIFICATE,
@@ -214,6 +216,32 @@ struct sev_user_data_snp_config {
 	__u8 rsvd1[52];
 } __packed;
 
+/**
+ * struct sev_data_snp_vlek_load - SNP_VLEK_LOAD structure
+ *
+ * @len: length of the command buffer read by the PSP
+ * @vlek_wrapped_version: version of wrapped VLEK hashstick (Must be 0h)
+ * @rsvd: reserved
+ * @vlek_wrapped_address: address of a wrapped VLEK hashstick
+ *                        (struct sev_user_data_snp_wrapped_vlek_hashstick)
+ */
+struct sev_user_data_snp_vlek_load {
+	__u32 len;				/* In */
+	__u8 vlek_wrapped_version;		/* In */
+	__u8 rsvd[3];				/* In */
+	__u64 vlek_wrapped_address;		/* In */
+} __packed;
+
+/**
+ * struct sev_user_data_snp_vlek_wrapped_vlek_hashstick - Wrapped VLEK data
+ *
+ * @data: Opaque data provided by AMD KDS (as described in SEV-SNP Firmware ABI
+ *        1.54, SNP_VLEK_LOAD)
+ */
+struct sev_user_data_snp_wrapped_vlek_hashstick {
+	__u8 data[432];				/* In */
+} __packed;
+
 /**
  * struct sev_issue_cmd - SEV ioctl parameters
  *
diff --git a/original/uapi/linux/random.h b/original/uapi/linux/random.h
index e744c23..1dd047e 100644
--- a/original/uapi/linux/random.h
+++ b/original/uapi/linux/random.h
@@ -20,7 +20,7 @@
 /* Add to (or subtract from) the entropy count.  (Superuser only.) */
 #define RNDADDTOENTCNT	_IOW( 'R', 0x01, int )
 
-/* Get the contents of the entropy pool.  (Superuser only.) */
+/* Get the contents of the entropy pool.  (Superuser only.) (Removed in 2.6.9-rc2.) */
 #define RNDGETPOOL	_IOR( 'R', 0x02, int [2] )
 
 /* 
@@ -55,4 +55,19 @@ struct rand_pool_info {
 #define GRND_RANDOM	0x0002
 #define GRND_INSECURE	0x0004
 
+/**
+ * struct vgetrandom_opaque_params - arguments for allocating memory for vgetrandom
+ *
+ * @size_per_opaque_state:	Size of each state that is to be passed to vgetrandom().
+ * @mmap_prot:			Value of the prot argument in mmap(2).
+ * @mmap_flags:			Value of the flags argument in mmap(2).
+ * @reserved:			Reserved for future use.
+ */
+struct vgetrandom_opaque_params {
+	__u32 size_of_opaque_state;
+	__u32 mmap_prot;
+	__u32 mmap_flags;
+	__u32 reserved[13];
+};
+
 #endif /* _UAPI_LINUX_RANDOM_H */
diff --git a/original/uapi/linux/sev-guest.h b/original/uapi/linux/sev-guest.h
index 154a87a..fcdfea7 100644
--- a/original/uapi/linux/sev-guest.h
+++ b/original/uapi/linux/sev-guest.h
@@ -89,6 +89,9 @@ struct snp_ext_report_req {
 #define SNP_GUEST_FW_ERR_MASK		GENMASK_ULL(31, 0)
 #define SNP_GUEST_VMM_ERR_SHIFT		32
 #define SNP_GUEST_VMM_ERR(x)		(((u64)x) << SNP_GUEST_VMM_ERR_SHIFT)
+#define SNP_GUEST_FW_ERR(x)		((x) & SNP_GUEST_FW_ERR_MASK)
+#define SNP_GUEST_ERR(vmm_err, fw_err)	(SNP_GUEST_VMM_ERR(vmm_err) | \
+					 SNP_GUEST_FW_ERR(fw_err))
 
 #define SNP_GUEST_VMM_ERR_INVALID_LEN	1
 #define SNP_GUEST_VMM_ERR_BUSY		2
diff --git a/original/uapi/linux/stat.h b/original/uapi/linux/stat.h
index 9577094..887a252 100644
--- a/original/uapi/linux/stat.h
+++ b/original/uapi/linux/stat.h
@@ -128,7 +128,13 @@ struct statx {
 	__u32	stx_dio_offset_align;	/* File offset alignment for direct I/O */
 	/* 0xa0 */
 	__u64	stx_subvol;	/* Subvolume identifier */
-	__u64	__spare3[11];	/* Spare space for future expansion */
+	__u32	stx_atomic_write_unit_min;	/* Min atomic write unit in bytes */
+	__u32	stx_atomic_write_unit_max;	/* Max atomic write unit in bytes */
+	/* 0xb0 */
+	__u32   stx_atomic_write_segments_max;	/* Max atomic write segment count */
+	__u32   __spare1[1];
+	/* 0xb8 */
+	__u64	__spare3[9];	/* Spare space for future expansion */
 	/* 0x100 */
 };
 
@@ -157,6 +163,7 @@ struct statx {
 #define STATX_DIOALIGN		0x00002000U	/* Want/got direct I/O alignment info */
 #define STATX_MNT_ID_UNIQUE	0x00004000U	/* Want/got extended stx_mount_id */
 #define STATX_SUBVOL		0x00008000U	/* Want/got stx_subvol */
+#define STATX_WRITE_ATOMIC	0x00010000U	/* Want/got atomic_write_* fields */
 
 #define STATX__RESERVED		0x80000000U	/* Reserved for future struct statx expansion */
 
@@ -192,6 +199,7 @@ struct statx {
 #define STATX_ATTR_MOUNT_ROOT		0x00002000 /* Root of a mount */
 #define STATX_ATTR_VERITY		0x00100000 /* [I] Verity protected file */
 #define STATX_ATTR_DAX			0x00200000 /* File is currently in DAX state */
+#define STATX_ATTR_WRITE_ATOMIC		0x00400000 /* File supports atomic write operations */
 
 
 #endif /* _UAPI_LINUX_STAT_H */
diff --git a/original/uapi/linux/tcp_metrics.h b/original/uapi/linux/tcp_metrics.h
index 7cb4a17..927c735 100644
--- a/original/uapi/linux/tcp_metrics.h
+++ b/original/uapi/linux/tcp_metrics.h
@@ -1,8 +1,8 @@
 /* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
 /* tcp_metrics.h - TCP Metrics Interface */
 
-#ifndef _LINUX_TCP_METRICS_H
-#define _LINUX_TCP_METRICS_H
+#ifndef _UAPI_LINUX_TCP_METRICS_H
+#define _UAPI_LINUX_TCP_METRICS_H
 
 #include <linux/types.h>
 
@@ -27,6 +27,22 @@ enum tcp_metric_index {
 
 #define TCP_METRIC_MAX	(__TCP_METRIC_MAX - 1)
 
+/* Re-define enum tcp_metric_index, again, using the values carried
+ * as netlink attribute types.
+ */
+enum {
+	TCP_METRICS_A_METRICS_RTT = 1,
+	TCP_METRICS_A_METRICS_RTTVAR,
+	TCP_METRICS_A_METRICS_SSTHRESH,
+	TCP_METRICS_A_METRICS_CWND,
+	TCP_METRICS_A_METRICS_REODERING,
+	TCP_METRICS_A_METRICS_RTT_US,
+	TCP_METRICS_A_METRICS_RTTVAR_US,
+
+	__TCP_METRICS_A_METRICS_MAX
+};
+#define TCP_METRICS_A_METRICS_MAX (__TCP_METRICS_A_METRICS_MAX - 1)
+
 enum {
 	TCP_METRICS_ATTR_UNSPEC,
 	TCP_METRICS_ATTR_ADDR_IPV4,		/* u32 */
@@ -58,4 +74,4 @@ enum {
 
 #define TCP_METRICS_CMD_MAX	(__TCP_METRICS_CMD_MAX - 1)
 
-#endif /* _LINUX_TCP_METRICS_H */
+#endif /* _UAPI_LINUX_TCP_METRICS_H */
diff --git a/original/uapi/linux/um_timetravel.h b/original/uapi/linux/um_timetravel.h
index ca32382..546a690 100644
--- a/original/uapi/linux/um_timetravel.h
+++ b/original/uapi/linux/um_timetravel.h
@@ -1,17 +1,6 @@
+/* SPDX-License-Identifier: BSD-3-Clause */
 /*
- * Permission to use, copy, modify, and/or distribute this software for any
- * purpose with or without fee is hereby granted, provided that the above
- * copyright notice and this permission notice appear in all copies.
- *
- * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
- * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
- * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
- * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
- * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
- * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
- * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
- *
- * Copyright (C) 2019 Intel Corporation
+ * Copyright (C) 2019 - 2023 Intel Corporation
  */
 #ifndef _UAPI_LINUX_UM_TIMETRAVEL_H
 #define _UAPI_LINUX_UM_TIMETRAVEL_H
@@ -50,6 +39,36 @@ struct um_timetravel_msg {
 	__u64 time;
 };
 
+/* max number of file descriptors that can be sent/received in a message */
+#define UM_TIMETRAVEL_MAX_FDS 2
+
+/**
+ * enum um_timetravel_shared_mem_fds - fds sent in ACK message for START message
+ */
+enum um_timetravel_shared_mem_fds {
+	/**
+	 * @UM_TIMETRAVEL_SHARED_MEMFD: Index of the shared memory file
+	 *	descriptor in the control message
+	 */
+	UM_TIMETRAVEL_SHARED_MEMFD,
+	/**
+	 * @UM_TIMETRAVEL_SHARED_LOGFD: Index of the logging file descriptor
+	 *	in the control message
+	 */
+	UM_TIMETRAVEL_SHARED_LOGFD,
+	UM_TIMETRAVEL_SHARED_MAX_FDS,
+};
+
+/**
+ * enum um_timetravel_start_ack - ack-time mask for start message
+ */
+enum um_timetravel_start_ack {
+	/**
+	 * @UM_TIMETRAVEL_START_ACK_ID: client ID that controller allocated.
+	 */
+	UM_TIMETRAVEL_START_ACK_ID = 0xffff,
+};
+
 /**
  * enum um_timetravel_ops - Operation codes
  */
@@ -57,7 +76,9 @@ enum um_timetravel_ops {
 	/**
 	 * @UM_TIMETRAVEL_ACK: response (ACK) to any previous message,
 	 *	this usually doesn't carry any data in the 'time' field
-	 *	unless otherwise specified below
+	 *	unless otherwise specified below, note: while using shared
+	 *	memory no ACK for WAIT and RUN messages, for more info see
+	 *	&struct um_timetravel_schedshm.
 	 */
 	UM_TIMETRAVEL_ACK		= 0,
 
@@ -123,6 +144,147 @@ enum um_timetravel_ops {
 	 *	the simulation.
 	 */
 	UM_TIMETRAVEL_GET_TOD		= 8,
+
+	/**
+	 * @UM_TIMETRAVEL_BROADCAST: Send/Receive a broadcast message.
+	 *	This message can be used to sync all components in the system
+	 *	with a single message, if the calender gets the message, the
+	 *	calender broadcast the message to all components, and if a
+	 *	component receives it it should act based on it e.g print a
+	 *	message to it's log system.
+	 *	(calendar <-> host)
+	 */
+	UM_TIMETRAVEL_BROADCAST		= 9,
+};
+
+/* version of struct um_timetravel_schedshm */
+#define UM_TIMETRAVEL_SCHEDSHM_VERSION 2
+
+/**
+ * enum um_timetravel_schedshm_cap - time travel capabilities of every client
+ *
+ * These flags must be set immediately after processing the ACK to
+ * the START message, before sending any message to the controller.
+ */
+enum um_timetravel_schedshm_cap {
+	/**
+	 * @UM_TIMETRAVEL_SCHEDSHM_CAP_TIME_SHARE: client can read current time
+	 *	update internal time request to shared memory and read
+	 *	free until and send no Ack on RUN and doesn't expect ACK on
+	 *	WAIT.
+	 */
+	UM_TIMETRAVEL_SCHEDSHM_CAP_TIME_SHARE = 0x1,
+};
+
+/**
+ * enum um_timetravel_schedshm_flags - time travel flags of every client
+ */
+enum um_timetravel_schedshm_flags {
+	/**
+	 * @UM_TIMETRAVEL_SCHEDSHM_FLAGS_REQ_RUN: client has a request to run.
+	 *	It's set by client when it has a request to run, if (and only
+	 *	if) the @running_id points to a client that is able to use
+	 *	shared memory, i.e. has %UM_TIMETRAVEL_SCHEDSHM_CAP_TIME_SHARE
+	 *	(this includes the client itself). Otherwise, a message must
+	 *	be used.
+	 */
+	UM_TIMETRAVEL_SCHEDSHM_FLAGS_REQ_RUN = 0x1,
+};
+
+/**
+ * DOC: Time travel shared memory overview
+ *
+ * The main purpose of the shared memory is to avoid all time travel message
+ * that don't need any action, for example current time can be held in shared
+ * memory without the need of any client to send a message UM_TIMETRAVEL_GET
+ * in order to know what's the time.
+ *
+ * Since this is shared memory with all clients and controller and controller
+ * creates the shared memory space, all time values are absolute to controller
+ * time. So first time client connects to shared memory mode it should take the
+ * current_time value in shared memory and keep it internally as a diff to
+ * shared memory times, and once shared memory is initialized, any interaction
+ * with the controller must happen in the controller time domain, including any
+ * messages (for clients that are not using shared memory, the controller will
+ * handle an offset and make the clients think they start at time zero.)
+ *
+ * Along with the shared memory file descriptor is sent to the client a logging
+ * file descriptor, to have all logs related to shared memory,
+ * logged into one place. note: to have all logs synced into log file at write,
+ * file should be flushed (fflush) after writing to it.
+ *
+ * To avoid memory corruption, we define below for each field who can write to
+ * it at what time, defined in the structure fields.
+ *
+ * To avoid having to pack this struct, all fields in it must be naturally aligned
+ * (i.e. aligned to their size).
+ */
+
+/**
+ * union um_timetravel_schedshm_client - UM time travel client struct
+ *
+ * Every entity using the shared memory including the controller has a place in
+ * the um_timetravel_schedshm clients array, that holds info related to the client
+ * using the shared memory, and can be set only by the client after it gets the
+ * fd memory.
+ *
+ * @capa: bit fields with client capabilities see
+ *	&enum um_timetravel_schedshm_cap, set by client once after getting the
+ *	shared memory file descriptor.
+ * @flags: bit fields for flags see &enum um_timetravel_schedshm_flags for doc.
+ * @req_time: request time to run, set by client on every request it needs.
+ * @name: unique id sent to the controller by client with START message.
+ */
+union um_timetravel_schedshm_client {
+	struct {
+		__u32 capa;
+		__u32 flags;
+		__u64 req_time;
+		__u64 name;
+	};
+	char reserve[128]; /* reserved for future usage */
 };
 
+/**
+ * struct um_timetravel_schedshm - UM time travel shared memory struct
+ *
+ * @hdr: header fields:
+ * @version: Current version struct UM_TIMETRAVEL_SCHEDSHM_VERSION,
+ *	set by controller once at init, clients must check this after mapping
+ *	and work without shared memory if they cannot handle the indicated
+ *	version.
+ * @len: Length of all the memory including header (@hdr), clients should once
+ *	per connection first mmap the header and take the length (@len) to remap the entire size.
+ *	This is done in order to support dynamic struct size letting number of
+ *	clients be dynamic based on controller support.
+ * @free_until: Stores the next request to run by any client, in order for the
+ *	current client to know how long it can still run. A client needs to (at
+ *	least) reload this value immediately after communicating with any other
+ *	client, since the controller will update this field when a new request
+ *	is made by any client. Clients also must update this value when they
+ *	insert/update an own request into the shared memory while not running
+ *	themselves, and the new request is before than the current value.
+ * current_time: Current time, can only be set by the client in running state
+ *	(indicated by @running_id), though that client may only run until @free_until,
+ *	so it must remain smaller than @free_until.
+ * @running_id: The current client in state running, set before a client is
+ *	notified that it's now running.
+ * @max_clients: size of @clients array, set once at init by the controller.
+ * @clients: clients array see &union um_timetravel_schedshm_client for doc,
+ *	set only by client.
+ */
+struct um_timetravel_schedshm {
+	union {
+		struct {
+			__u32 version;
+			__u32 len;
+			__u64 free_until;
+			__u64 current_time;
+			__u16 running_id;
+			__u16 max_clients;
+		};
+		char hdr[4096]; /* align to 4K page size */
+	};
+	union um_timetravel_schedshm_client clients[];
+};
 #endif /* _UAPI_LINUX_UM_TIMETRAVEL_H */
diff --git a/original/uapi/linux/v4l2-controls.h b/original/uapi/linux/v4l2-controls.h
index 99c3f5e..974fd25 100644
--- a/original/uapi/linux/v4l2-controls.h
+++ b/original/uapi/linux/v4l2-controls.h
@@ -898,6 +898,8 @@ enum v4l2_mpeg_video_av1_level {
 	V4L2_MPEG_VIDEO_AV1_LEVEL_7_3 = 23
 };
 
+#define V4L2_CID_MPEG_VIDEO_AVERAGE_QP  (V4L2_CID_CODEC_BASE + 657)
+
 /*  MPEG-class control IDs specific to the CX2341x driver as defined by V4L2 */
 #define V4L2_CID_CODEC_CX2341X_BASE				(V4L2_CTRL_CLASS_CODEC | 0x1000)
 #define V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER_MODE		(V4L2_CID_CODEC_CX2341X_BASE+0)
diff --git a/original/uapi/linux/version.h b/original/uapi/linux/version.h
index 833a3ce..d051cab 100644
--- a/original/uapi/linux/version.h
+++ b/original/uapi/linux/version.h
@@ -1,5 +1,5 @@
-#define LINUX_VERSION_CODE 395776
+#define LINUX_VERSION_CODE 396032
 #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
 #define LINUX_VERSION_MAJOR 6
-#define LINUX_VERSION_PATCHLEVEL 10
+#define LINUX_VERSION_PATCHLEVEL 11
 #define LINUX_VERSION_SUBLEVEL 0
diff --git a/original/uapi/linux/videodev2.h b/original/uapi/linux/videodev2.h
index 4a6392f..bcc9d64 100644
--- a/original/uapi/linux/videodev2.h
+++ b/original/uapi/linux/videodev2.h
@@ -582,6 +582,8 @@ struct v4l2_pix_format {
 
 /* RGB formats (6 or 8 bytes per pixel) */
 #define V4L2_PIX_FMT_BGR48_12    v4l2_fourcc('B', '3', '1', '2') /* 48  BGR 12-bit per component */
+#define V4L2_PIX_FMT_BGR48       v4l2_fourcc('B', 'G', 'R', '6') /* 48  BGR 16-bit per component */
+#define V4L2_PIX_FMT_RGB48       v4l2_fourcc('R', 'G', 'B', '6') /* 48  RGB 16-bit per component */
 #define V4L2_PIX_FMT_ABGR64_12   v4l2_fourcc('B', '4', '1', '2') /* 64  BGRA 12-bit per component */
 
 /* Grey formats */
@@ -814,6 +816,18 @@ struct v4l2_pix_format {
 #define V4L2_PIX_FMT_IPU3_SGRBG10	v4l2_fourcc('i', 'p', '3', 'G') /* IPU3 packed 10-bit GRBG bayer */
 #define V4L2_PIX_FMT_IPU3_SRGGB10	v4l2_fourcc('i', 'p', '3', 'r') /* IPU3 packed 10-bit RGGB bayer */
 
+/* Raspberry Pi PiSP compressed formats. */
+#define V4L2_PIX_FMT_PISP_COMP1_RGGB	v4l2_fourcc('P', 'C', '1', 'R') /* PiSP 8-bit mode 1 compressed RGGB bayer */
+#define V4L2_PIX_FMT_PISP_COMP1_GRBG	v4l2_fourcc('P', 'C', '1', 'G') /* PiSP 8-bit mode 1 compressed GRBG bayer */
+#define V4L2_PIX_FMT_PISP_COMP1_GBRG	v4l2_fourcc('P', 'C', '1', 'g') /* PiSP 8-bit mode 1 compressed GBRG bayer */
+#define V4L2_PIX_FMT_PISP_COMP1_BGGR	v4l2_fourcc('P', 'C', '1', 'B') /* PiSP 8-bit mode 1 compressed BGGR bayer */
+#define V4L2_PIX_FMT_PISP_COMP1_MONO	v4l2_fourcc('P', 'C', '1', 'M') /* PiSP 8-bit mode 1 compressed monochrome */
+#define V4L2_PIX_FMT_PISP_COMP2_RGGB	v4l2_fourcc('P', 'C', '2', 'R') /* PiSP 8-bit mode 2 compressed RGGB bayer */
+#define V4L2_PIX_FMT_PISP_COMP2_GRBG	v4l2_fourcc('P', 'C', '2', 'G') /* PiSP 8-bit mode 2 compressed GRBG bayer */
+#define V4L2_PIX_FMT_PISP_COMP2_GBRG	v4l2_fourcc('P', 'C', '2', 'g') /* PiSP 8-bit mode 2 compressed GBRG bayer */
+#define V4L2_PIX_FMT_PISP_COMP2_BGGR	v4l2_fourcc('P', 'C', '2', 'B') /* PiSP 8-bit mode 2 compressed BGGR bayer */
+#define V4L2_PIX_FMT_PISP_COMP2_MONO	v4l2_fourcc('P', 'C', '2', 'M') /* PiSP 8-bit mode 2 compressed monochrome */
+
 /* SDR formats - used only for Software Defined Radio devices */
 #define V4L2_SDR_FMT_CU8          v4l2_fourcc('C', 'U', '0', '8') /* IQ u8 */
 #define V4L2_SDR_FMT_CU16LE       v4l2_fourcc('C', 'U', '1', '6') /* IQ u16le */
@@ -841,6 +855,9 @@ struct v4l2_pix_format {
 #define V4L2_META_FMT_RK_ISP1_PARAMS	v4l2_fourcc('R', 'K', '1', 'P') /* Rockchip ISP1 3A Parameters */
 #define V4L2_META_FMT_RK_ISP1_STAT_3A	v4l2_fourcc('R', 'K', '1', 'S') /* Rockchip ISP1 3A Statistics */
 
+/* Vendor specific - used for RaspberryPi PiSP */
+#define V4L2_META_FMT_RPI_BE_CFG	v4l2_fourcc('R', 'P', 'B', 'C') /* PiSP BE configuration */
+
 #ifdef __KERNEL__
 /*
  * Line-based metadata formats. Remember to update v4l_fill_fmtdesc() when
diff --git a/original/uapi/linux/xfrm.h b/original/uapi/linux/xfrm.h
index d950d02..f287015 100644
--- a/original/uapi/linux/xfrm.h
+++ b/original/uapi/linux/xfrm.h
@@ -321,6 +321,7 @@ enum xfrm_attr_type_t {
 	XFRMA_IF_ID,		/* __u32 */
 	XFRMA_MTIMER_THRESH,	/* __u32 in seconds for input SA */
 	XFRMA_SA_DIR,		/* __u8 */
+	XFRMA_NAT_KEEPALIVE_INTERVAL,	/* __u32 in seconds for NAT keepalive */
 	__XFRMA_MAX
 
 #define XFRMA_OUTPUT_MARK XFRMA_SET_MARK	/* Compatibility */
diff --git a/original/uapi/linux/zorro_ids.h b/original/uapi/linux/zorro_ids.h
index 6e574d7..393f2ee 100644
--- a/original/uapi/linux/zorro_ids.h
+++ b/original/uapi/linux/zorro_ids.h
@@ -449,6 +449,9 @@
 #define  ZORRO_PROD_VMC_ISDN_BLASTER_Z2				ZORRO_ID(VMC, 0x01, 0)
 #define  ZORRO_PROD_VMC_HYPERCOM_4				ZORRO_ID(VMC, 0x02, 0)
 
+#define ZORRO_MANUF_CSLAB					0x1400
+#define  ZORRO_PROD_CSLAB_WARP_1260				ZORRO_ID(CSLAB, 0x65, 0)
+
 #define ZORRO_MANUF_INFORMATION					0x157C
 #define  ZORRO_PROD_INFORMATION_ISDN_ENGINE_I			ZORRO_ID(INFORMATION, 0x64, 0)
 
diff --git a/original/uapi/misc/fastrpc.h b/original/uapi/misc/fastrpc.h
index 9158369..f33d914 100644
--- a/original/uapi/misc/fastrpc.h
+++ b/original/uapi/misc/fastrpc.h
@@ -8,14 +8,11 @@
 #define FASTRPC_IOCTL_ALLOC_DMA_BUFF	_IOWR('R', 1, struct fastrpc_alloc_dma_buf)
 #define FASTRPC_IOCTL_FREE_DMA_BUFF	_IOWR('R', 2, __u32)
 #define FASTRPC_IOCTL_INVOKE		_IOWR('R', 3, struct fastrpc_invoke)
-/* This ioctl is only supported with secure device nodes */
 #define FASTRPC_IOCTL_INIT_ATTACH	_IO('R', 4)
 #define FASTRPC_IOCTL_INIT_CREATE	_IOWR('R', 5, struct fastrpc_init_create)
 #define FASTRPC_IOCTL_MMAP		_IOWR('R', 6, struct fastrpc_req_mmap)
 #define FASTRPC_IOCTL_MUNMAP		_IOWR('R', 7, struct fastrpc_req_munmap)
-/* This ioctl is only supported with secure device nodes */
 #define FASTRPC_IOCTL_INIT_ATTACH_SNS	_IO('R', 8)
-/* This ioctl is only supported with secure device nodes */
 #define FASTRPC_IOCTL_INIT_CREATE_STATIC _IOWR('R', 9, struct fastrpc_init_create_static)
 #define FASTRPC_IOCTL_MEM_MAP		_IOWR('R', 10, struct fastrpc_mem_map)
 #define FASTRPC_IOCTL_MEM_UNMAP		_IOWR('R', 11, struct fastrpc_mem_unmap)
diff --git a/original/uapi/misc/mrvl_cn10k_dpi.h b/original/uapi/misc/mrvl_cn10k_dpi.h
new file mode 100644
index 0000000..8db902e
--- /dev/null
+++ b/original/uapi/misc/mrvl_cn10k_dpi.h
@@ -0,0 +1,39 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/*
+ * Marvell Octeon CN10K DPI driver
+ *
+ * Copyright (C) 2024 Marvell.
+ *
+ */
+
+#ifndef __MRVL_CN10K_DPI_H__
+#define __MRVL_CN10K_DPI_H__
+
+#include <linux/types.h>
+
+#define DPI_MAX_ENGINES 6
+
+struct dpi_mps_mrrs_cfg {
+	__u16 max_read_req_sz; /* Max read request size */
+	__u16 max_payload_sz;  /* Max payload size */
+	__u16 port; /* Ebus port */
+	__u16 reserved; /* Reserved */
+};
+
+struct dpi_engine_cfg {
+	__u64 fifo_mask; /* FIFO size mask in KBytes */
+	__u16 molr[DPI_MAX_ENGINES]; /* Max outstanding load requests */
+	__u16 update_molr; /* '1' to update engine MOLR */
+	__u16 reserved; /* Reserved */
+};
+
+/* DPI ioctl numbers */
+#define DPI_MAGIC_NUM	0xB8
+
+/* Set MPS & MRRS parameters */
+#define DPI_MPS_MRRS_CFG _IOW(DPI_MAGIC_NUM, 1, struct dpi_mps_mrrs_cfg)
+
+/* Set Engine FIFO configuration */
+#define DPI_ENGINE_CFG   _IOW(DPI_MAGIC_NUM, 2, struct dpi_engine_cfg)
+
+#endif /* __MRVL_CN10K_DPI_H__ */
diff --git a/original/uapi/rdma/bnxt_re-abi.h b/original/uapi/rdma/bnxt_re-abi.h
index c0c34ac..e61104f 100644
--- a/original/uapi/rdma/bnxt_re-abi.h
+++ b/original/uapi/rdma/bnxt_re-abi.h
@@ -55,7 +55,7 @@ enum {
 	BNXT_RE_UCNTX_CMASK_WC_DPI_ENABLED = 0x04ULL,
 	BNXT_RE_UCNTX_CMASK_DBR_PACING_ENABLED = 0x08ULL,
 	BNXT_RE_UCNTX_CMASK_POW2_DISABLED = 0x10ULL,
-	BNXT_RE_COMP_MASK_UCNTX_HW_RETX_ENABLED = 0x40,
+	BNXT_RE_UCNTX_CMASK_MSN_TABLE_ENABLED = 0x40,
 };
 
 enum bnxt_re_wqe_mode {
diff --git a/original/uapi/rdma/ib_user_ioctl_cmds.h b/original/uapi/rdma/ib_user_ioctl_cmds.h
index dafc7eb..ec71905 100644
--- a/original/uapi/rdma/ib_user_ioctl_cmds.h
+++ b/original/uapi/rdma/ib_user_ioctl_cmds.h
@@ -37,9 +37,6 @@
 #define UVERBS_ID_NS_MASK 0xF000
 #define UVERBS_ID_NS_SHIFT 12
 
-#define UVERBS_UDATA_DRIVER_DATA_NS	1
-#define UVERBS_UDATA_DRIVER_DATA_FLAG	(1UL << UVERBS_ID_NS_SHIFT)
-
 enum uverbs_default_objects {
 	UVERBS_OBJECT_DEVICE, /* No instances of DEVICE are allowed */
 	UVERBS_OBJECT_PD,
@@ -61,8 +58,10 @@ enum uverbs_default_objects {
 };
 
 enum {
-	UVERBS_ATTR_UHW_IN = UVERBS_UDATA_DRIVER_DATA_FLAG,
+	UVERBS_ID_DRIVER_NS = 1UL << UVERBS_ID_NS_SHIFT,
+	UVERBS_ATTR_UHW_IN = UVERBS_ID_DRIVER_NS,
 	UVERBS_ATTR_UHW_OUT,
+	UVERBS_ID_DRIVER_NS_WITH_UHW,
 };
 
 enum uverbs_methods_device {
diff --git a/original/uapi/rdma/mana-abi.h b/original/uapi/rdma/mana-abi.h
index 2c41cc3..45c2df6 100644
--- a/original/uapi/rdma/mana-abi.h
+++ b/original/uapi/rdma/mana-abi.h
@@ -45,6 +45,15 @@ struct mana_ib_create_qp_resp {
 	__u32 reserved;
 };
 
+struct mana_ib_create_rc_qp {
+	__aligned_u64 queue_buf[4];
+	__u32 queue_size[4];
+};
+
+struct mana_ib_create_rc_qp_resp {
+	__u32 queue_id[4];
+};
+
 struct mana_ib_create_wq {
 	__aligned_u64 wq_buf_addr;
 	__u32 wq_buf_size;
diff --git a/original/uapi/rdma/mlx5_user_ioctl_cmds.h b/original/uapi/rdma/mlx5_user_ioctl_cmds.h
index 595edad..5b74d65 100644
--- a/original/uapi/rdma/mlx5_user_ioctl_cmds.h
+++ b/original/uapi/rdma/mlx5_user_ioctl_cmds.h
@@ -270,6 +270,10 @@ enum mlx5_ib_device_query_context_attrs {
 	MLX5_IB_ATTR_QUERY_CONTEXT_RESP_UCTX = (1U << UVERBS_ID_NS_SHIFT),
 };
 
+enum mlx5_ib_create_cq_attrs {
+	MLX5_IB_ATTR_CREATE_CQ_UAR_INDEX = UVERBS_ID_DRIVER_NS_WITH_UHW,
+};
+
 #define MLX5_IB_DW_MATCH_PARAM 0xA0
 
 struct mlx5_ib_match_params {
diff --git a/original/uapi/rdma/rdma_netlink.h b/original/uapi/rdma/rdma_netlink.h
index a214fc2..2f37568 100644
--- a/original/uapi/rdma/rdma_netlink.h
+++ b/original/uapi/rdma/rdma_netlink.h
@@ -301,6 +301,10 @@ enum rdma_nldev_command {
 
 	RDMA_NLDEV_CMD_RES_SRQ_GET_RAW,
 
+	RDMA_NLDEV_CMD_NEWDEV,
+
+	RDMA_NLDEV_CMD_DELDEV,
+
 	RDMA_NLDEV_NUM_OPS
 };
 
@@ -564,6 +568,12 @@ enum rdma_nldev_attr {
 	 */
 	RDMA_NLDEV_ATTR_RES_SUBTYPE,		/* string */
 
+	RDMA_NLDEV_ATTR_DEV_TYPE,		/* u8 */
+
+	RDMA_NLDEV_ATTR_PARENT_NAME,		/* string */
+
+	RDMA_NLDEV_ATTR_NAME_ASSIGN_TYPE,	/* u8 */
+
 	/*
 	 * Always the end
 	 */
@@ -602,4 +612,16 @@ enum rdma_nl_counter_mask {
 	RDMA_COUNTER_MASK_QP_TYPE = 1,
 	RDMA_COUNTER_MASK_PID = 1 << 1,
 };
+
+/* Supported rdma device types. */
+enum rdma_nl_dev_type {
+	RDMA_DEVICE_TYPE_SMI = 1,
+};
+
+/* RDMA device name assignment types */
+enum rdma_nl_name_assign_type {
+	RDMA_NAME_ASSIGN_TYPE_UNKNOWN = 0,
+	RDMA_NAME_ASSIGN_TYPE_USER = 1, /* Provided by user-space */
+};
+
 #endif /* _UAPI_RDMA_NETLINK_H */
diff --git a/original/uapi/scsi/scsi_bsg_mpi3mr.h b/original/uapi/scsi/scsi_bsg_mpi3mr.h
index a3ba779..f5ea1db 100644
--- a/original/uapi/scsi/scsi_bsg_mpi3mr.h
+++ b/original/uapi/scsi/scsi_bsg_mpi3mr.h
@@ -296,6 +296,7 @@ struct mpi3mr_hdb_entry {
  * multiple hdb entries.
  *
  * @num_hdb_types: Number of host diag buffer types supported
+ * @element_trigger_format: Element trigger format
  * @rsvd1: Reserved
  * @rsvd2: Reserved
  * @rsvd3: Reserved
@@ -303,7 +304,7 @@ struct mpi3mr_hdb_entry {
  */
 struct mpi3mr_bsg_in_hdb_status {
 	__u8	num_hdb_types;
-	__u8	rsvd1;
+	__u8    element_trigger_format;
 	__u16	rsvd2;
 	__u32	rsvd3;
 	struct mpi3mr_hdb_entry entry[1];
diff --git a/original/uapi/sound/asequencer.h b/original/uapi/sound/asequencer.h
index c85fdd8..39b37ed 100644
--- a/original/uapi/sound/asequencer.h
+++ b/original/uapi/sound/asequencer.h
@@ -10,7 +10,7 @@
 #include <sound/asound.h>
 
 /** version of the sequencer */
-#define SNDRV_SEQ_VERSION SNDRV_PROTOCOL_VERSION(1, 0, 3)
+#define SNDRV_SEQ_VERSION SNDRV_PROTOCOL_VERSION(1, 0, 4)
 
 /**
  * definition of sequencer event types
@@ -523,11 +523,12 @@ struct snd_seq_queue_status {
 /* queue tempo */
 struct snd_seq_queue_tempo {
 	int queue;			/* sequencer queue */
-	unsigned int tempo;		/* current tempo, us/tick */
+	unsigned int tempo;		/* current tempo, us/tick (or different time-base below) */
 	int ppq;			/* time resolution, ticks/quarter */
 	unsigned int skew_value;	/* queue skew */
 	unsigned int skew_base;		/* queue skew base */
-	char reserved[24];		/* for the future */
+	unsigned short tempo_base;	/* tempo base in nsec unit; either 10 or 1000 */
+	char reserved[22];		/* for the future */
 };
 
 
diff --git a/original/uapi/sound/asound.h b/original/uapi/sound/asound.h
index 628d46a..8bf7e8a 100644
--- a/original/uapi/sound/asound.h
+++ b/original/uapi/sound/asound.h
@@ -142,7 +142,7 @@ struct snd_hwdep_dsp_image {
  *                                                                           *
  *****************************************************************************/
 
-#define SNDRV_PCM_VERSION		SNDRV_PROTOCOL_VERSION(2, 0, 17)
+#define SNDRV_PCM_VERSION		SNDRV_PROTOCOL_VERSION(2, 0, 18)
 
 typedef unsigned long snd_pcm_uframes_t;
 typedef signed long snd_pcm_sframes_t;
@@ -334,7 +334,7 @@ union snd_pcm_sync_id {
 	unsigned char id[16];
 	unsigned short id16[8];
 	unsigned int id32[4];
-};
+} __attribute__((deprecated));
 
 struct snd_pcm_info {
 	unsigned int device;		/* RO/WR (control): device number */
@@ -348,7 +348,7 @@ struct snd_pcm_info {
 	int dev_subclass;		/* SNDRV_PCM_SUBCLASS_* */
 	unsigned int subdevices_count;
 	unsigned int subdevices_avail;
-	union snd_pcm_sync_id sync;	/* hardware synchronization ID */
+	unsigned char pad1[16];		/* was: hardware synchronization ID */
 	unsigned char reserved[64];	/* reserved for future... */
 };
 
@@ -420,7 +420,8 @@ struct snd_pcm_hw_params {
 	unsigned int rate_num;		/* R: rate numerator */
 	unsigned int rate_den;		/* R: rate denominator */
 	snd_pcm_uframes_t fifo_size;	/* R: chip FIFO size in frames */
-	unsigned char reserved[64];	/* reserved for future */
+	unsigned char sync[16];		/* R: synchronization ID (perfect sync - one clock source) */
+	unsigned char reserved[48];	/* reserved for future */
 };
 
 enum {
diff --git a/original/uapi/sound/sof/abi.h b/original/uapi/sound/sof/abi.h
index 937ed94..c1b158e 100644
--- a/original/uapi/sound/sof/abi.h
+++ b/original/uapi/sound/sof/abi.h
@@ -29,7 +29,7 @@
 /* SOF ABI version major, minor and patch numbers */
 #define SOF_ABI_MAJOR 3
 #define SOF_ABI_MINOR 23
-#define SOF_ABI_PATCH 0
+#define SOF_ABI_PATCH 1
 
 /* SOF ABI version number. Format within 32bit word is MMmmmppp */
 #define SOF_ABI_MAJOR_SHIFT	24
```

