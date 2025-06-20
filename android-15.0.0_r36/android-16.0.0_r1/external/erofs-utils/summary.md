```
e06bfc9: ANDROID: erofs-utils: enable multithreading (Sandeep Dhavale <dhavale@google.com>)
4cba5d8: Add janitors to the OWNERS file (Sadaf Ebrahimi <sadafebrahimi@google.com>)
6a7ae58: erofs-utils: mkfs: make output stable (Jooyung Han <jooyung@google.com>)
8d6c5d4: erofs-utils: release 1.8.3 (Gao Xiang <xiang@kernel.org>)
cc99425: erofs-utils: lib: correct erofsfuse build script (ComixHe <heyuming@deepin.org>)
867adb0: ANDROID: remove make_erofs (Jooyung Han <jooyung@google.com>)
54e217b: erofs-utils: add --hard-dereference option (Paul Meyer <katexochen0@gmail.com>)
91e74ac: erofs-utils: mkfs: add `-U <clear|random>` support (Gao Xiang <hsiangkao@linux.alibaba.com>)
c4facdc: erofs-utils: lib: get rid of pthread_cancel() for workqueue (Gao Xiang <hsiangkao@linux.alibaba.com>)
485b317: erofs-utils: use pkg-config for lz4 configuration (Gao Xiang <hsiangkao@linux.alibaba.com>)
027c4af: erofs-utils: lib: add missing dependencies (Gao Xiang <hsiangkao@linux.alibaba.com>)
eec6f7a: erofs-utils: mkfs: make output stable (Jooyung Han <jooyung@google.com>)
a4a24fd: erofs-utils: lib: fix user-after-free in xattr.c (Hongzhen Luo <hongzhen@linux.alibaba.com>)
8015606: erofs-utils: rebuild: set the appropriate `dev` field for dirs (Hongzhen Luo <hongzhen@linux.alibaba.com>)
ee7d3dc: erofs-utils: avoid silent corruption caused by `c_root_xattr_isize` (Hongzhen Luo <hongzhen@linux.alibaba.com>)
889aa26: erofs-utils: lib: clean up z_erofs_load_full_lcluster() (Gao Xiang <hsiangkao@linux.alibaba.com>)
c8e6407: erofs-utils: lib: clean up zmap.c (Gao Xiang <hsiangkao@linux.alibaba.com>)
c15004f: erofs-utils: fix `Not a directory` error for incremental builds (Gao Xiang <hsiangkao@linux.alibaba.com>)
654e8b8: erofs-utils: lib: capture errors from {mkfs,rebuild}_handle_inode() (Hongzhen Luo <hongzhen@linux.alibaba.com>)
bc6a5d3: erofs-utils: lib: rearrange struct erofs_configure (Hongzhen Luo <hongzhen@linux.alibaba.com>)
539ad7d: erofs-utils: mkfs: Fix input offset counting in headerball mode (Mike Baynton <mike@mbaynton.com>)
f9c7233: erofs-utils: avoid allocating large arrays on the stack (Jianan Huang <huangjianan@xiaomi.com>)
7642e38: erofs-utils: lib: report leftovers for partially filled blocks (Gao Xiang <hsiangkao@linux.alibaba.com>)
a4b10b2: erofs-utils: mkfs: fix unexpected errors for chunk-based images (Gao Xiang <hsiangkao@linux.alibaba.com>)
882ad1c: erofs-utils: mkfs: fix `-Eall-fragments` for multi-threaded compression (Gao Xiang <hsiangkao@linux.alibaba.com>)
9f5bcf3: erofs-utils: lib: Explicitly include <pthread.h> where used (Satoshi Niwa <niwa@google.com>)
8bedd86: erofs-utils: release 1.8.2 (Gao Xiang <xiang@kernel.org>)
8b56d3f: erofs-utils: lib: fix compressed packed inodes (Danny Lin <danny@orbstack.dev>)
e975306: erofs-utils: mkfs: add `--sort=none` (Gao Xiang <hsiangkao@linux.alibaba.com>)
cb1742e: erofs-utils: mkfs: get rid of outdated subpage compression warning (Gao Xiang <hsiangkao@linux.alibaba.com>)
8e6138c: erofs-utils: mkfs: fix a regression where rebuild mode does not work (Gao Xiang <hsiangkao@linux.alibaba.com>)
8ef51b0: erofs-utils: lib: fix off-by-one issue with invalid device ID (Gao Xiang <hsiangkao@linux.alibaba.com>)
c9d13ce: erofs-utils: lib: fix sorting shared xattrs (Sheng Yong <shengyong@oppo.com>)
5c56672: erofs-utils: fsck: introduce exporting xattrs (Hongzhen Luo <hongzhen@linux.alibaba.com>)
1a54ae7: erofs-utils: lib: expose erofs_xattr_prefix_matches() (Hongzhen Luo <hongzhen@linux.alibaba.com>)
5375687: erofs-utils: lib: fix incorrect nblocks in block list for chunked inodes (Hongzhen Luo <hongzhen@linux.alibaba.com>)
85ea711: erofs-utils: lib: use another way to check power-of-2 (Gao Xiang <hsiangkao@linux.alibaba.com>)
c551dab: erofs-utils: mkfs: fix inaccurate assertion of hardlinks in rebuild mode (Gao Xiang <hsiangkao@linux.alibaba.com>)
4102c47: erofs-utils: lib: tar: allow pax headers with empty names (Gao Xiang <hsiangkao@linux.alibaba.com>)
ff1ca05: erofs-utils: mkfs: fix an undefined behavior of memcpy (Gao Xiang <hsiangkao@linux.alibaba.com>)
d18972d: erofs-utils: fix invalid argument type in erofs_err() (Hongzhen Luo <hongzhen@linux.alibaba.com>)
90b7844: erofs-utils: lib: don't include <lzma.h> and <zlib.h> in external header... (Gao Xiang <hsiangkao@linux.alibaba.com>)
bb8a0f3: erofs-utils: lib: actually skip the unidentified xattrs (Sandeep Dhavale <dhavale@google.com>)
93c46f5: erofs-utils: mkfs: fix an indefinite wait race (Gao Xiang <hsiangkao@linux.alibaba.com>)
74eecf7: erofs-utils: lib: fix potential overflow issue (Hongzhen Luo <hongzhen@linux.alibaba.com>)
6ad2be3: erofs-utils: adjust volume label maximum length to the kernel implementa... (Naoto Yamaguchi <wata2ki@gmail.com>)
c469131: erofs-utils: use $EROFS_UTILS_VERSION, if set, as the version (Ahelenia Ziemiańska <nabijaczleweli@nabijaczlewe...)
8305ee8: erofs-utils: lib: exclude: #include PATH_MAX workaround (Ahelenia Ziemiańska <nabijaczleweli@nabijaczlewe...)
```

