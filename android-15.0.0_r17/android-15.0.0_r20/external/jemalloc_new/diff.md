```diff
diff --git a/Android.bp b/Android.bp
index a8024b33..459ebe6c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -67,6 +67,9 @@ common_cflags = [
     "-Wno-missing-field-initializers",
 
     "-U_FORTIFY_SOURCE",
+
+    // Default enable the tcache.
+    "-DANDROID_ENABLE_TCACHE",
 ]
 
 common_c_local_includes = [
@@ -93,7 +96,6 @@ common_c_local_includes = [
 
 android_common_cflags = [
     // Default parameters for jemalloc config.
-    "-DANDROID_ENABLE_TCACHE",
     "-DANDROID_LG_TCACHE_MAXCLASS_DEFAULT=16",
     "-DANDROID_NUM_ARENAS=2",
     "-DANDROID_TCACHE_NSLOTS_SMALL_MAX=8",
@@ -116,6 +118,10 @@ android_product_variables = {
 
             "-UANDROID_TCACHE_NSLOTS_LARGE",
             "-DANDROID_TCACHE_NSLOTS_LARGE=1",
+
+            // Minimize the size of the internal data structures by removing
+            // unused stats and other data not used on Android.
+            "-DANDROID_MINIMIZE_STRUCTS",
         ],
     },
 }
@@ -250,7 +256,7 @@ cc_library_host_static {
     },
 
     visibility: [
-        "//external/rust/crates/tikv-jemalloc-sys:__subpackages__",
+        "//external/rust/android-crates-io/crates/tikv-jemalloc-sys:__subpackages__",
     ],
 }
 
diff --git a/include/jemalloc/internal/arena_inlines_a.h b/include/jemalloc/internal/arena_inlines_a.h
index 9abf7f6a..56528b99 100644
--- a/include/jemalloc/internal/arena_inlines_a.h
+++ b/include/jemalloc/internal/arena_inlines_a.h
@@ -8,21 +8,30 @@ arena_ind_get(const arena_t *arena) {
 
 static inline void
 arena_internal_add(arena_t *arena, size_t size) {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	atomic_fetch_add_zu(&arena->stats.internal, size, ATOMIC_RELAXED);
+#endif
 }
 
 static inline void
 arena_internal_sub(arena_t *arena, size_t size) {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	atomic_fetch_sub_zu(&arena->stats.internal, size, ATOMIC_RELAXED);
+#endif
 }
 
 static inline size_t
 arena_internal_get(arena_t *arena) {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	return atomic_load_zu(&arena->stats.internal, ATOMIC_RELAXED);
+#else
+	return 0;
+#endif
 }
 
 static inline bool
 arena_prof_accum(tsdn_t *tsdn, arena_t *arena, uint64_t accumbytes) {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	cassert(config_prof);
 
 	if (likely(prof_interval == 0 || !prof_active_get_unlocked())) {
@@ -30,6 +39,9 @@ arena_prof_accum(tsdn_t *tsdn, arena_t *arena, uint64_t accumbytes) {
 	}
 
 	return prof_accum_add(tsdn, &arena->prof_accum, accumbytes);
+#else
+  return false;
+#endif
 }
 
 static inline void
diff --git a/include/jemalloc/internal/arena_stats.h b/include/jemalloc/internal/arena_stats.h
index 5f3dca8b..45b246eb 100644
--- a/include/jemalloc/internal/arena_stats.h
+++ b/include/jemalloc/internal/arena_stats.h
@@ -27,6 +27,7 @@ struct arena_stats_large_s {
 	arena_stats_u64_t	nmalloc;
 	arena_stats_u64_t	ndalloc;
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	/*
 	 * Number of allocation requests that correspond to this size class.
 	 * This includes requests served by tcache, though tcache only
@@ -36,6 +37,7 @@ struct arena_stats_large_s {
 
 	/* Current number of allocations of this size class. */
 	size_t		curlextents; /* Derived. */
+#endif
 };
 
 typedef struct arena_stats_decay_s arena_stats_decay_t;
@@ -62,6 +64,7 @@ struct arena_stats_s {
 	/* Number of bytes currently mapped, excluding retained memory. */
 	atomic_zu_t		mapped; /* Partially derived. */
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	/*
 	 * Number of unused virtual memory bytes currently retained.  Retained
 	 * bytes are technically mapped (though always decommitted or purged),
@@ -86,6 +89,7 @@ struct arena_stats_s {
 	atomic_zu_t		tcache_bytes; /* Derived. */
 
 	mutex_prof_data_t mutex_prof_data[mutex_prof_num_arena_mutexes];
+#endif
 
 	/* One element for each large size class. */
 	arena_stats_large_t	lstats[NSIZES - NBINS];
@@ -220,10 +224,12 @@ arena_stats_accum_zu(atomic_zu_t *dst, size_t src) {
 static inline void
 arena_stats_large_nrequests_add(tsdn_t *tsdn, arena_stats_t *arena_stats,
     szind_t szind, uint64_t nrequests) {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	arena_stats_lock(tsdn, arena_stats);
 	arena_stats_add_u64(tsdn, arena_stats, &arena_stats->lstats[szind -
 	    NBINS].nrequests, nrequests);
 	arena_stats_unlock(tsdn, arena_stats);
+#endif
 }
 
 static inline void
diff --git a/include/jemalloc/internal/arena_structs_b.h b/include/jemalloc/internal/arena_structs_b.h
index 38bc9596..eb1271d8 100644
--- a/include/jemalloc/internal/arena_structs_b.h
+++ b/include/jemalloc/internal/arena_structs_b.h
@@ -63,6 +63,7 @@ struct arena_decay_s {
 	 */
 	size_t			backlog[SMOOTHSTEP_NSTEPS];
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	/*
 	 * Pointer to associated stats.  These stats are embedded directly in
 	 * the arena's stats due to how stats structures are shared between the
@@ -72,6 +73,7 @@ struct arena_decay_s {
 	arena_stats_decay_t	*stats;
 	/* Peak number of pages in associated extents.  Used for debug only. */
 	uint64_t		ceil_npages;
+#endif
 };
 
 struct arena_s {
@@ -100,6 +102,7 @@ struct arena_s {
 	/* Synchronization: internal. */
 	arena_stats_t		stats;
 
+#if defined(ANDROID_ENABLE_TCACHE)
 	/*
 	 * Lists of tcaches and cache_bin_array_descriptors for extant threads
 	 * associated with this arena.  Stats from these are merged
@@ -110,10 +113,13 @@ struct arena_s {
 	ql_head(tcache_t)			tcache_ql;
 	ql_head(cache_bin_array_descriptor_t)	cache_bin_array_descriptor_ql;
 	malloc_mutex_t				tcache_ql_mtx;
+#endif
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	/* Synchronization: internal. */
 	prof_accum_t		prof_accum;
 	uint64_t		prof_accumbytes;
+#endif
 
 	/*
 	 * PRNG state for cache index randomization of large allocation base
diff --git a/include/jemalloc/internal/bin.h b/include/jemalloc/internal/bin.h
index 9b416ada..8f2febf3 100644
--- a/include/jemalloc/internal/bin.h
+++ b/include/jemalloc/internal/bin.h
@@ -93,13 +93,17 @@ bin_stats_merge(tsdn_t *tsdn, bin_stats_t *dst_bin_stats, bin_t *bin) {
 	malloc_mutex_prof_read(tsdn, &dst_bin_stats->mutex_data, &bin->lock);
 	dst_bin_stats->nmalloc += bin->stats.nmalloc;
 	dst_bin_stats->ndalloc += bin->stats.ndalloc;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	dst_bin_stats->nrequests += bin->stats.nrequests;
+#endif
 	dst_bin_stats->curregs += bin->stats.curregs;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	dst_bin_stats->nfills += bin->stats.nfills;
 	dst_bin_stats->nflushes += bin->stats.nflushes;
 	dst_bin_stats->nslabs += bin->stats.nslabs;
 	dst_bin_stats->reslabs += bin->stats.reslabs;
 	dst_bin_stats->curslabs += bin->stats.curslabs;
+#endif
 	malloc_mutex_unlock(tsdn, &bin->lock);
 }
 
diff --git a/include/jemalloc/internal/bin_stats.h b/include/jemalloc/internal/bin_stats.h
index 86e673ec..d2ada6e1 100644
--- a/include/jemalloc/internal/bin_stats.h
+++ b/include/jemalloc/internal/bin_stats.h
@@ -14,12 +14,14 @@ struct bin_stats_s {
 	uint64_t	nmalloc;
 	uint64_t	ndalloc;
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	/*
 	 * Number of allocation requests that correspond to the size of this
 	 * bin.  This includes requests served by tcache, though tcache only
 	 * periodically merges into this counter.
 	 */
 	uint64_t	nrequests;
+#endif
 
 	/*
 	 * Current number of regions of this size class, including regions
@@ -27,6 +29,7 @@ struct bin_stats_s {
 	 */
 	size_t		curregs;
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	/* Number of tcache fills from this bin. */
 	uint64_t	nfills;
 
@@ -44,6 +47,7 @@ struct bin_stats_s {
 
 	/* Current number of slabs in this bin. */
 	size_t		curslabs;
+#endif
 
 	mutex_prof_data_t mutex_data;
 };
diff --git a/include/jemalloc/internal/extent_externs.h b/include/jemalloc/internal/extent_externs.h
index b8a4d026..3575d61e 100644
--- a/include/jemalloc/internal/extent_externs.h
+++ b/include/jemalloc/internal/extent_externs.h
@@ -69,5 +69,6 @@ bool extent_merge_wrapper(tsdn_t *tsdn, arena_t *arena,
     extent_hooks_t **r_extent_hooks, extent_t *a, extent_t *b);
 
 bool extent_boot(void);
+void extent_postfork_child(tsdn_t *tsdn);
 
 #endif /* JEMALLOC_INTERNAL_EXTENT_EXTERNS_H */
diff --git a/include/jemalloc/internal/private_namespace.h b/include/jemalloc/internal/private_namespace.h
index 8744f167..314f6f85 100644
--- a/include/jemalloc/internal/private_namespace.h
+++ b/include/jemalloc/internal/private_namespace.h
@@ -156,6 +156,7 @@
 #define extent_avail_remove_any JEMALLOC_N(extent_avail_remove_any)
 #define extent_avail_remove_first JEMALLOC_N(extent_avail_remove_first)
 #define extent_boot JEMALLOC_N(extent_boot)
+#define extent_postfork_child JEMALLOC_N(extent_postfork_child)
 #define extent_commit_wrapper JEMALLOC_N(extent_commit_wrapper)
 #define extent_dalloc JEMALLOC_N(extent_dalloc)
 #define extent_dalloc_gap JEMALLOC_N(extent_dalloc_gap)
diff --git a/include/jemalloc/internal/private_namespace_jet.h b/include/jemalloc/internal/private_namespace_jet.h
index c745f6ea..a2c14f7e 100644
--- a/include/jemalloc/internal/private_namespace_jet.h
+++ b/include/jemalloc/internal/private_namespace_jet.h
@@ -157,6 +157,7 @@
 #define extent_avail_remove_any JEMALLOC_N(extent_avail_remove_any)
 #define extent_avail_remove_first JEMALLOC_N(extent_avail_remove_first)
 #define extent_boot JEMALLOC_N(extent_boot)
+#define extent_postfork_child JEMALLOC_N(extent_postfork_child)
 #define extent_commit_wrapper JEMALLOC_N(extent_commit_wrapper)
 #define extent_dalloc JEMALLOC_N(extent_dalloc)
 #define extent_dalloc_gap JEMALLOC_N(extent_dalloc_gap)
diff --git a/include/jemalloc/internal/util.h b/include/jemalloc/internal/util.h
index 304cb545..c88daef5 100644
--- a/include/jemalloc/internal/util.h
+++ b/include/jemalloc/internal/util.h
@@ -36,12 +36,15 @@
 #  define unlikely(x) !!(x)
 #endif
 
-#if !defined(JEMALLOC_INTERNAL_UNREACHABLE)
-#  error JEMALLOC_INTERNAL_UNREACHABLE should have been defined by configure
+#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
+#  include <stddef.h> /* Use the C23 unreachable() macro. */
+#else
+#  if !defined(JEMALLOC_INTERNAL_UNREACHABLE)
+#    error JEMALLOC_INTERNAL_UNREACHABLE should have been defined by configure
+#  endif
+#  define unreachable() JEMALLOC_INTERNAL_UNREACHABLE()
 #endif
 
-#define unreachable() JEMALLOC_INTERNAL_UNREACHABLE()
-
 /* Set error code. */
 UTIL_INLINE void
 set_errno(int errnum) {
diff --git a/src/arena.c b/src/arena.c
index 61b8083f..7a85ca9c 100644
--- a/src/arena.c
+++ b/src/arena.c
@@ -91,6 +91,7 @@ arena_stats_merge(tsdn_t *tsdn, arena_t *arena, unsigned *nthreads,
 
 	arena_stats_accum_zu(&astats->mapped, base_mapped
 	    + arena_stats_read_zu(tsdn, &arena->stats, &arena->stats.mapped));
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	arena_stats_accum_zu(&astats->retained,
 	    extents_npages_get(&arena->extents_retained) << LG_PAGE);
 
@@ -121,35 +122,45 @@ arena_stats_merge(tsdn_t *tsdn, arena_t *arena, unsigned *nthreads,
 	    (((atomic_load_zu(&arena->nactive, ATOMIC_RELAXED) +
 	    extents_npages_get(&arena->extents_dirty) +
 	    extents_npages_get(&arena->extents_muzzy)) << LG_PAGE)));
+#endif
 
 	for (szind_t i = 0; i < NSIZES - NBINS; i++) {
 		uint64_t nmalloc = arena_stats_read_u64(tsdn, &arena->stats,
 		    &arena->stats.lstats[i].nmalloc);
 		arena_stats_accum_u64(&lstats[i].nmalloc, nmalloc);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		arena_stats_accum_u64(&astats->nmalloc_large, nmalloc);
+#endif
 
 		uint64_t ndalloc = arena_stats_read_u64(tsdn, &arena->stats,
 		    &arena->stats.lstats[i].ndalloc);
 		arena_stats_accum_u64(&lstats[i].ndalloc, ndalloc);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		arena_stats_accum_u64(&astats->ndalloc_large, ndalloc);
+#endif
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		uint64_t nrequests = arena_stats_read_u64(tsdn, &arena->stats,
 		    &arena->stats.lstats[i].nrequests);
 		arena_stats_accum_u64(&lstats[i].nrequests,
 		    nmalloc + nrequests);
 		arena_stats_accum_u64(&astats->nrequests_large,
 		    nmalloc + nrequests);
+#endif
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		assert(nmalloc >= ndalloc);
 		assert(nmalloc - ndalloc <= SIZE_T_MAX);
 		size_t curlextents = (size_t)(nmalloc - ndalloc);
 		lstats[i].curlextents += curlextents;
 		arena_stats_accum_zu(&astats->allocated_large,
 		    curlextents * sz_index2size(NBINS + i));
+#endif
 	}
 
 	arena_stats_unlock(tsdn, &arena->stats);
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS) && defined(ANDROID_ENABLE_TCACHE)
 	/* tcache_bytes counts currently cached bytes. */
 	atomic_store_zu(&astats->tcache_bytes, 0, ATOMIC_RELAXED);
 	malloc_mutex_lock(tsdn, &arena->tcache_ql_mtx);
@@ -171,7 +182,9 @@ arena_stats_merge(tsdn_t *tsdn, arena_t *arena, unsigned *nthreads,
 	    &astats->mutex_prof_data[arena_prof_mutex_tcache_list],
 	    &arena->tcache_ql_mtx);
 	malloc_mutex_unlock(tsdn, &arena->tcache_ql_mtx);
+#endif
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 #define READ_ARENA_MUTEX_PROF_DATA(mtx, ind)				\
     malloc_mutex_lock(tsdn, &arena->mtx);				\
     malloc_mutex_prof_read(tsdn, &astats->mutex_prof_data[ind],		\
@@ -195,6 +208,7 @@ arena_stats_merge(tsdn_t *tsdn, arena_t *arena, unsigned *nthreads,
 	READ_ARENA_MUTEX_PROF_DATA(base->mtx,
 	    arena_prof_mutex_base)
 #undef READ_ARENA_MUTEX_PROF_DATA
+#endif
 
 	nstime_copy(&astats->uptime, &arena->create_time);
 	nstime_update(&astats->uptime);
@@ -473,6 +487,7 @@ arena_decay_backlog_update_last(arena_decay_t *decay, size_t current_npages) {
 	    current_npages - decay->nunpurged : 0;
 	decay->backlog[SMOOTHSTEP_NSTEPS-1] = npages_delta;
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	if (config_debug) {
 		if (current_npages > decay->ceil_npages) {
 			decay->ceil_npages = current_npages;
@@ -483,6 +498,7 @@ arena_decay_backlog_update_last(arena_decay_t *decay, size_t current_npages) {
 			decay->ceil_npages = npages_limit;
 		}
 	}
+#endif
 }
 
 static void
@@ -579,22 +595,26 @@ arena_decay_reinit(arena_decay_t *decay, ssize_t decay_ms) {
 static bool
 arena_decay_init(arena_decay_t *decay, ssize_t decay_ms,
     arena_stats_decay_t *stats) {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	if (config_debug) {
 		for (size_t i = 0; i < sizeof(arena_decay_t); i++) {
 			assert(((char *)decay)[i] == 0);
 		}
 		decay->ceil_npages = 0;
 	}
+#endif
 	if (malloc_mutex_init(&decay->mtx, "decay", WITNESS_RANK_DECAY,
 	    malloc_mutex_rank_exclusive)) {
 		return true;
 	}
 	decay->purging = false;
 	arena_decay_reinit(decay, decay_ms);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	/* Memory is zeroed, so there is no need to clear stats. */
 	if (config_stats) {
 		decay->stats = stats;
 	}
+#endif
 	return false;
 }
 
@@ -791,12 +811,14 @@ arena_decay_stashed(tsdn_t *tsdn, arena_t *arena,
 
 	if (config_stats) {
 		arena_stats_lock(tsdn, &arena->stats);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		arena_stats_add_u64(tsdn, &arena->stats, &decay->stats->npurge,
 		    1);
 		arena_stats_add_u64(tsdn, &arena->stats,
 		    &decay->stats->nmadvise, nmadvise);
 		arena_stats_add_u64(tsdn, &arena->stats, &decay->stats->purged,
 		    npurged);
+#endif
 		arena_stats_sub_zu(tsdn, &arena->stats, &arena->stats.mapped,
 		    nunmapped << LG_PAGE);
 		arena_stats_unlock(tsdn, &arena->stats);
@@ -926,9 +948,11 @@ arena_bin_slabs_nonfull_tryget(bin_t *bin) {
 	if (slab == NULL) {
 		return NULL;
 	}
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	if (config_stats) {
 		bin->stats.reslabs++;
 	}
+#endif
 	return slab;
 }
 
@@ -1025,7 +1049,9 @@ arena_reset(tsd_t *tsd, arena_t *arena) {
 		}
 		if (config_stats) {
 			bin->stats.curregs = 0;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 			bin->stats.curslabs = 0;
+#endif
 		}
 		malloc_mutex_unlock(tsd_tsdn(tsd), &bin->lock);
 	}
@@ -1170,10 +1196,12 @@ arena_bin_nonfull_slab_get(tsdn_t *tsdn, arena_t *arena, bin_t *bin,
 	/********************************/
 	malloc_mutex_lock(tsdn, &bin->lock);
 	if (slab != NULL) {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		if (config_stats) {
 			bin->stats.nslabs++;
 			bin->stats.curslabs++;
 		}
+#endif
 		return slab;
 	}
 
@@ -1293,7 +1321,9 @@ arena_tcache_fill_small(tsdn_t *tsdn, arena_t *arena, tcache_t *tcache,
 		bin->stats.nrequests += tbin->tstats.nrequests;
 #endif
 		bin->stats.curregs += i;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		bin->stats.nfills++;
+#endif
 #if defined(ANDROID_ENABLE_TCACHE_STATS)
 		tbin->tstats.nrequests = 0;
 #endif
@@ -1342,7 +1372,9 @@ arena_malloc_small(tsdn_t *tsdn, arena_t *arena, szind_t binind, bool zero) {
 
 	if (config_stats) {
 		bin->stats.nmalloc++;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		bin->stats.nrequests++;
+#endif
 		bin->stats.curregs++;
 	}
 	malloc_mutex_unlock(tsdn, &bin->lock);
@@ -1428,7 +1460,9 @@ arena_prof_promote(tsdn_t *tsdn, const void *ptr, size_t usize) {
 	rtree_szind_slab_update(tsdn, &extents_rtree, rtree_ctx, (uintptr_t)ptr,
 	    szind, false);
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	prof_accum_cancel(tsdn, &arena->prof_accum, usize);
+#endif
 
 	assert(isalloc(tsdn, ptr) == usize);
 }
@@ -1497,9 +1531,11 @@ arena_dalloc_bin_slab(tsdn_t *tsdn, arena_t *arena, extent_t *slab,
 	arena_slab_dalloc(tsdn, arena, slab);
 	/****************************/
 	malloc_mutex_lock(tsdn, &bin->lock);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	if (config_stats) {
 		bin->stats.curslabs--;
 	}
+#endif
 }
 
 static void
@@ -1521,9 +1557,11 @@ arena_bin_lower_slab(UNUSED tsdn_t *tsdn, arena_t *arena, extent_t *slab,
 			arena_bin_slabs_full_insert(arena, bin, bin->slabcur);
 		}
 		bin->slabcur = slab;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		if (config_stats) {
 			bin->stats.reslabs++;
 		}
+#endif
 	} else {
 		arena_bin_slabs_nonfull_insert(bin, slab);
 	}
@@ -1791,19 +1829,23 @@ arena_new(tsdn_t *tsdn, unsigned ind, extent_hooks_t *extent_hooks) {
 			goto label_error;
 		}
 
+#if defined(ANDROID_ENABLE_TCACHE)
 		ql_new(&arena->tcache_ql);
 		ql_new(&arena->cache_bin_array_descriptor_ql);
 		if (malloc_mutex_init(&arena->tcache_ql_mtx, "tcache_ql",
 		    WITNESS_RANK_TCACHE_QL, malloc_mutex_rank_exclusive)) {
 			goto label_error;
 		}
+#endif
 	}
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	if (config_prof) {
 		if (prof_accum_init(tsdn, &arena->prof_accum)) {
 			goto label_error;
 		}
 	}
+#endif
 
 	if (config_cache_oblivious) {
 		/*
@@ -1859,6 +1901,7 @@ arena_new(tsdn_t *tsdn, unsigned ind, extent_hooks_t *extent_hooks) {
 		goto label_error;
 	}
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	if (arena_decay_init(&arena->decay_dirty,
 	    arena_dirty_decay_ms_default_get(), &arena->stats.decay_dirty)) {
 		goto label_error;
@@ -1867,6 +1910,16 @@ arena_new(tsdn_t *tsdn, unsigned ind, extent_hooks_t *extent_hooks) {
 	    arena_muzzy_decay_ms_default_get(), &arena->stats.decay_muzzy)) {
 		goto label_error;
 	}
+#else
+	if (arena_decay_init(&arena->decay_dirty,
+	    arena_dirty_decay_ms_default_get(), NULL)) {
+		goto label_error;
+	}
+	if (arena_decay_init(&arena->decay_muzzy,
+	    arena_muzzy_decay_ms_default_get(), NULL)) {
+		goto label_error;
+	}
+#endif
 
 	arena->extent_grow_next = sz_psz2ind(HUGEPAGE);
 	arena->retain_grow_limit = EXTENT_GROW_MAX_PIND;
@@ -1943,7 +1996,12 @@ arena_prefork0(tsdn_t *tsdn, arena_t *arena) {
 void
 arena_prefork1(tsdn_t *tsdn, arena_t *arena) {
 	if (config_stats) {
+#if defined(ANDROID_ENABLE_TCACHE)
 		malloc_mutex_prefork(tsdn, &arena->tcache_ql_mtx);
+#endif
+#ifndef JEMALLOC_ATOMIC_U64
+		malloc_mutex_prefork(tsdn, &arena->stats.mtx);
+#endif
 	}
 }
 
@@ -1991,14 +2049,19 @@ arena_postfork_parent(tsdn_t *tsdn, arena_t *arena) {
 	malloc_mutex_postfork_parent(tsdn, &arena->large_mtx);
 	base_postfork_parent(tsdn, arena->base);
 	malloc_mutex_postfork_parent(tsdn, &arena->extent_avail_mtx);
-	extents_postfork_parent(tsdn, &arena->extents_dirty);
-	extents_postfork_parent(tsdn, &arena->extents_muzzy);
 	extents_postfork_parent(tsdn, &arena->extents_retained);
+	extents_postfork_parent(tsdn, &arena->extents_muzzy);
+	extents_postfork_parent(tsdn, &arena->extents_dirty);
 	malloc_mutex_postfork_parent(tsdn, &arena->extent_grow_mtx);
 	malloc_mutex_postfork_parent(tsdn, &arena->decay_dirty.mtx);
 	malloc_mutex_postfork_parent(tsdn, &arena->decay_muzzy.mtx);
 	if (config_stats) {
+#ifndef JEMALLOC_ATOMIC_U64
+		malloc_mutex_postfork_parent(tsdn, &arena->stats.mtx);
+#endif
+#if defined(ANDROID_ENABLE_TCACHE)
 		malloc_mutex_postfork_parent(tsdn, &arena->tcache_ql_mtx);
+#endif
 	}
 }
 
@@ -2014,6 +2077,7 @@ arena_postfork_child(tsdn_t *tsdn, arena_t *arena) {
 	if (tsd_iarena_get(tsdn_tsd(tsdn)) == arena) {
 		arena_nthreads_inc(arena, true);
 	}
+#if defined(ANDROID_ENABLE_TCACHE)
 	if (config_stats) {
 		ql_new(&arena->tcache_ql);
 		ql_new(&arena->cache_bin_array_descriptor_ql);
@@ -2028,6 +2092,7 @@ arena_postfork_child(tsdn_t *tsdn, arena_t *arena) {
 			    &tcache->cache_bin_array_descriptor, link);
 		}
 	}
+#endif
 
 	for (i = 0; i < NBINS; i++) {
 		bin_postfork_child(tsdn, &arena->bins[i]);
@@ -2035,13 +2100,18 @@ arena_postfork_child(tsdn_t *tsdn, arena_t *arena) {
 	malloc_mutex_postfork_child(tsdn, &arena->large_mtx);
 	base_postfork_child(tsdn, arena->base);
 	malloc_mutex_postfork_child(tsdn, &arena->extent_avail_mtx);
-	extents_postfork_child(tsdn, &arena->extents_dirty);
-	extents_postfork_child(tsdn, &arena->extents_muzzy);
 	extents_postfork_child(tsdn, &arena->extents_retained);
+	extents_postfork_child(tsdn, &arena->extents_muzzy);
+	extents_postfork_child(tsdn, &arena->extents_dirty);
 	malloc_mutex_postfork_child(tsdn, &arena->extent_grow_mtx);
 	malloc_mutex_postfork_child(tsdn, &arena->decay_dirty.mtx);
 	malloc_mutex_postfork_child(tsdn, &arena->decay_muzzy.mtx);
 	if (config_stats) {
+#ifndef JEMALLOC_ATOMIC_U64
+		malloc_mutex_postfork_child(tsdn, &arena->stats.mtx);
+#endif
+#if defined(ANDROID_ENABLE_TCACHE)
 		malloc_mutex_postfork_child(tsdn, &arena->tcache_ql_mtx);
+#endif
 	}
 }
diff --git a/src/ctl.c b/src/ctl.c
index 1e713a3d..06791d0e 100644
--- a/src/ctl.c
+++ b/src/ctl.c
@@ -151,24 +151,32 @@ CTL_PROTO(stats_arenas_i_small_allocated)
 CTL_PROTO(stats_arenas_i_small_nmalloc)
 CTL_PROTO(stats_arenas_i_small_ndalloc)
 CTL_PROTO(stats_arenas_i_small_nrequests)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_PROTO(stats_arenas_i_large_allocated)
 CTL_PROTO(stats_arenas_i_large_nmalloc)
 CTL_PROTO(stats_arenas_i_large_ndalloc)
+#endif
 CTL_PROTO(stats_arenas_i_large_nrequests)
 CTL_PROTO(stats_arenas_i_bins_j_nmalloc)
 CTL_PROTO(stats_arenas_i_bins_j_ndalloc)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_PROTO(stats_arenas_i_bins_j_nrequests)
+#endif
 CTL_PROTO(stats_arenas_i_bins_j_curregs)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_PROTO(stats_arenas_i_bins_j_nfills)
 CTL_PROTO(stats_arenas_i_bins_j_nflushes)
 CTL_PROTO(stats_arenas_i_bins_j_nslabs)
 CTL_PROTO(stats_arenas_i_bins_j_nreslabs)
 CTL_PROTO(stats_arenas_i_bins_j_curslabs)
+#endif
 INDEX_PROTO(stats_arenas_i_bins_j)
 CTL_PROTO(stats_arenas_i_lextents_j_nmalloc)
 CTL_PROTO(stats_arenas_i_lextents_j_ndalloc)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_PROTO(stats_arenas_i_lextents_j_nrequests)
 CTL_PROTO(stats_arenas_i_lextents_j_curlextents)
+#endif
 INDEX_PROTO(stats_arenas_i_lextents_j)
 CTL_PROTO(stats_arenas_i_nthreads)
 CTL_PROTO(stats_arenas_i_uptime)
@@ -179,6 +187,7 @@ CTL_PROTO(stats_arenas_i_pactive)
 CTL_PROTO(stats_arenas_i_pdirty)
 CTL_PROTO(stats_arenas_i_pmuzzy)
 CTL_PROTO(stats_arenas_i_mapped)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_PROTO(stats_arenas_i_retained)
 CTL_PROTO(stats_arenas_i_dirty_npurge)
 CTL_PROTO(stats_arenas_i_dirty_nmadvise)
@@ -191,6 +200,7 @@ CTL_PROTO(stats_arenas_i_internal)
 CTL_PROTO(stats_arenas_i_metadata_thp)
 CTL_PROTO(stats_arenas_i_tcache_bytes)
 CTL_PROTO(stats_arenas_i_resident)
+#endif
 INDEX_PROTO(stats_arenas_i)
 CTL_PROTO(stats_allocated)
 CTL_PROTO(stats_active)
@@ -212,15 +222,19 @@ CTL_PROTO(stats_##n##_total_wait_time)					\
 CTL_PROTO(stats_##n##_max_wait_time)					\
 CTL_PROTO(stats_##n##_max_num_thds)
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 /* Global mutexes. */
 #define OP(mtx) MUTEX_STATS_CTL_PROTO_GEN(mutexes_##mtx)
 MUTEX_PROF_GLOBAL_MUTEXES
 #undef OP
+#endif
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 /* Per arena mutexes. */
 #define OP(mtx) MUTEX_STATS_CTL_PROTO_GEN(arenas_i_mutexes_##mtx)
 MUTEX_PROF_ARENA_MUTEXES
 #undef OP
+#endif
 
 /* Arena bin mutexes. */
 MUTEX_STATS_CTL_PROTO_GEN(arenas_i_bins_j_mutex)
@@ -392,14 +406,18 @@ static const ctl_named_node_t stats_arenas_i_small_node[] = {
 	{NAME("allocated"),	CTL(stats_arenas_i_small_allocated)},
 	{NAME("nmalloc"),	CTL(stats_arenas_i_small_nmalloc)},
 	{NAME("ndalloc"),	CTL(stats_arenas_i_small_ndalloc)},
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	{NAME("nrequests"),	CTL(stats_arenas_i_small_nrequests)}
+#endif
 };
 
 static const ctl_named_node_t stats_arenas_i_large_node[] = {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	{NAME("allocated"),	CTL(stats_arenas_i_large_allocated)},
 	{NAME("nmalloc"),	CTL(stats_arenas_i_large_nmalloc)},
 	{NAME("ndalloc"),	CTL(stats_arenas_i_large_ndalloc)},
 	{NAME("nrequests"),	CTL(stats_arenas_i_large_nrequests)}
+#endif
 };
 
 #define MUTEX_PROF_DATA_NODE(prefix)					\
@@ -426,13 +444,17 @@ MUTEX_PROF_DATA_NODE(arenas_i_bins_j_mutex)
 static const ctl_named_node_t stats_arenas_i_bins_j_node[] = {
 	{NAME("nmalloc"),	CTL(stats_arenas_i_bins_j_nmalloc)},
 	{NAME("ndalloc"),	CTL(stats_arenas_i_bins_j_ndalloc)},
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	{NAME("nrequests"),	CTL(stats_arenas_i_bins_j_nrequests)},
+#endif
 	{NAME("curregs"),	CTL(stats_arenas_i_bins_j_curregs)},
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	{NAME("nfills"),	CTL(stats_arenas_i_bins_j_nfills)},
 	{NAME("nflushes"),	CTL(stats_arenas_i_bins_j_nflushes)},
 	{NAME("nslabs"),	CTL(stats_arenas_i_bins_j_nslabs)},
 	{NAME("nreslabs"),	CTL(stats_arenas_i_bins_j_nreslabs)},
 	{NAME("curslabs"),	CTL(stats_arenas_i_bins_j_curslabs)},
+#endif
 	{NAME("mutex"),		CHILD(named, stats_arenas_i_bins_j_mutex)}
 };
 
@@ -447,8 +469,10 @@ static const ctl_indexed_node_t stats_arenas_i_bins_node[] = {
 static const ctl_named_node_t stats_arenas_i_lextents_j_node[] = {
 	{NAME("nmalloc"),	CTL(stats_arenas_i_lextents_j_nmalloc)},
 	{NAME("ndalloc"),	CTL(stats_arenas_i_lextents_j_ndalloc)},
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	{NAME("nrequests"),	CTL(stats_arenas_i_lextents_j_nrequests)},
 	{NAME("curlextents"),	CTL(stats_arenas_i_lextents_j_curlextents)}
+#endif
 };
 static const ctl_named_node_t super_stats_arenas_i_lextents_j_node[] = {
 	{NAME(""),		CHILD(named, stats_arenas_i_lextents_j)}
@@ -458,15 +482,19 @@ static const ctl_indexed_node_t stats_arenas_i_lextents_node[] = {
 	{INDEX(stats_arenas_i_lextents_j)}
 };
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 #define OP(mtx)  MUTEX_PROF_DATA_NODE(arenas_i_mutexes_##mtx)
 MUTEX_PROF_ARENA_MUTEXES
 #undef OP
+#endif
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 static const ctl_named_node_t stats_arenas_i_mutexes_node[] = {
 #define OP(mtx) {NAME(#mtx), CHILD(named, stats_arenas_i_mutexes_##mtx)},
 MUTEX_PROF_ARENA_MUTEXES
 #undef OP
 };
+#endif
 
 static const ctl_named_node_t stats_arenas_i_node[] = {
 	{NAME("nthreads"),	CTL(stats_arenas_i_nthreads)},
@@ -478,6 +506,7 @@ static const ctl_named_node_t stats_arenas_i_node[] = {
 	{NAME("pdirty"),	CTL(stats_arenas_i_pdirty)},
 	{NAME("pmuzzy"),	CTL(stats_arenas_i_pmuzzy)},
 	{NAME("mapped"),	CTL(stats_arenas_i_mapped)},
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	{NAME("retained"),	CTL(stats_arenas_i_retained)},
 	{NAME("dirty_npurge"),	CTL(stats_arenas_i_dirty_npurge)},
 	{NAME("dirty_nmadvise"), CTL(stats_arenas_i_dirty_nmadvise)},
@@ -490,11 +519,14 @@ static const ctl_named_node_t stats_arenas_i_node[] = {
 	{NAME("metadata_thp"),	CTL(stats_arenas_i_metadata_thp)},
 	{NAME("tcache_bytes"),	CTL(stats_arenas_i_tcache_bytes)},
 	{NAME("resident"),	CTL(stats_arenas_i_resident)},
+#endif
 	{NAME("small"),		CHILD(named, stats_arenas_i_small)},
 	{NAME("large"),		CHILD(named, stats_arenas_i_large)},
 	{NAME("bins"),		CHILD(indexed, stats_arenas_i_bins)},
 	{NAME("lextents"),	CHILD(indexed, stats_arenas_i_lextents)},
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	{NAME("mutexes"),	CHILD(named, stats_arenas_i_mutexes)}
+#endif
 };
 static const ctl_named_node_t super_stats_arenas_i_node[] = {
 	{NAME(""),		CHILD(named, stats_arenas_i)}
@@ -510,10 +542,13 @@ static const ctl_named_node_t stats_background_thread_node[] = {
 	{NAME("run_interval"),	CTL(stats_background_thread_run_interval)}
 };
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 #define OP(mtx) MUTEX_PROF_DATA_NODE(mutexes_##mtx)
 MUTEX_PROF_GLOBAL_MUTEXES
 #undef OP
+#endif
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 static const ctl_named_node_t stats_mutexes_node[] = {
 #define OP(mtx) {NAME(#mtx), CHILD(named, stats_mutexes_##mtx)},
 MUTEX_PROF_GLOBAL_MUTEXES
@@ -521,6 +556,7 @@ MUTEX_PROF_GLOBAL_MUTEXES
 	{NAME("reset"),		CTL(stats_mutexes_reset)}
 };
 #undef MUTEX_PROF_DATA_NODE
+#endif
 
 static const ctl_named_node_t stats_node[] = {
 	{NAME("allocated"),	CTL(stats_allocated)},
@@ -532,7 +568,9 @@ static const ctl_named_node_t stats_node[] = {
 	{NAME("retained"),	CTL(stats_retained)},
 	{NAME("background_thread"),
 	 CHILD(named, stats_background_thread)},
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 	{NAME("mutexes"),	CHILD(named, stats_mutexes)},
+#endif
 	{NAME("arenas"),	CHILD(indexed, stats_arenas)}
 };
 
@@ -723,8 +761,10 @@ ctl_arena_stats_amerge(tsdn_t *tsdn, ctl_arena_t *ctl_arena, arena_t *arena) {
 			    ctl_arena->astats->bstats[i].nmalloc;
 			ctl_arena->astats->ndalloc_small +=
 			    ctl_arena->astats->bstats[i].ndalloc;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 			ctl_arena->astats->nrequests_small +=
 			    ctl_arena->astats->bstats[i].nrequests;
+#endif
 		}
 	} else {
 		arena_basic_stats_merge(tsdn, arena, &ctl_arena->nthreads,
@@ -758,10 +798,13 @@ ctl_arena_stats_sdmerge(ctl_arena_t *ctl_sdarena, ctl_arena_t *ctl_arena,
 		if (!destroyed) {
 			accum_atomic_zu(&sdstats->astats.mapped,
 			    &astats->astats.mapped);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 			accum_atomic_zu(&sdstats->astats.retained,
 			    &astats->astats.retained);
+#endif
 		}
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		ctl_accum_arena_stats_u64(&sdstats->astats.decay_dirty.npurge,
 		    &astats->astats.decay_dirty.npurge);
 		ctl_accum_arena_stats_u64(&sdstats->astats.decay_dirty.nmadvise,
@@ -775,7 +818,9 @@ ctl_arena_stats_sdmerge(ctl_arena_t *ctl_sdarena, ctl_arena_t *ctl_arena,
 		    &astats->astats.decay_muzzy.nmadvise);
 		ctl_accum_arena_stats_u64(&sdstats->astats.decay_muzzy.purged,
 		    &astats->astats.decay_muzzy.purged);
+#endif
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 #define OP(mtx) malloc_mutex_prof_merge(				\
 		    &(sdstats->astats.mutex_prof_data[			\
 		        arena_prof_mutex_##mtx]),			\
@@ -796,6 +841,7 @@ MUTEX_PROF_ARENA_MUTEXES
 			assert(atomic_load_zu(
 			    &astats->astats.internal, ATOMIC_RELAXED) == 0);
 		}
+#endif
 
 		if (!destroyed) {
 			sdstats->allocated_small += astats->allocated_small;
@@ -806,6 +852,7 @@ MUTEX_PROF_ARENA_MUTEXES
 		sdstats->ndalloc_small += astats->ndalloc_small;
 		sdstats->nrequests_small += astats->nrequests_small;
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		if (!destroyed) {
 			accum_atomic_zu(&sdstats->astats.allocated_large,
 			    &astats->astats.allocated_large);
@@ -822,6 +869,7 @@ MUTEX_PROF_ARENA_MUTEXES
 
 		accum_atomic_zu(&sdstats->astats.tcache_bytes,
 		    &astats->astats.tcache_bytes);
+#endif
 
 		if (ctl_arena->arena_ind == 0) {
 			sdstats->astats.uptime = astats->astats.uptime;
@@ -830,14 +878,17 @@ MUTEX_PROF_ARENA_MUTEXES
 		for (i = 0; i < NBINS; i++) {
 			sdstats->bstats[i].nmalloc += astats->bstats[i].nmalloc;
 			sdstats->bstats[i].ndalloc += astats->bstats[i].ndalloc;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 			sdstats->bstats[i].nrequests +=
 			    astats->bstats[i].nrequests;
+#endif
 			if (!destroyed) {
 				sdstats->bstats[i].curregs +=
 				    astats->bstats[i].curregs;
 			} else {
 				assert(astats->bstats[i].curregs == 0);
 			}
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 			sdstats->bstats[i].nfills += astats->bstats[i].nfills;
 			sdstats->bstats[i].nflushes +=
 			    astats->bstats[i].nflushes;
@@ -849,6 +900,7 @@ MUTEX_PROF_ARENA_MUTEXES
 			} else {
 				assert(astats->bstats[i].curslabs == 0);
 			}
+#endif
 			malloc_mutex_prof_merge(&sdstats->bstats[i].mutex_data,
 			    &astats->bstats[i].mutex_data);
 		}
@@ -858,6 +910,7 @@ MUTEX_PROF_ARENA_MUTEXES
 			    &astats->lstats[i].nmalloc);
 			ctl_accum_arena_stats_u64(&sdstats->lstats[i].ndalloc,
 			    &astats->lstats[i].ndalloc);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 			ctl_accum_arena_stats_u64(&sdstats->lstats[i].nrequests,
 			    &astats->lstats[i].nrequests);
 			if (!destroyed) {
@@ -866,6 +919,7 @@ MUTEX_PROF_ARENA_MUTEXES
 			} else {
 				assert(astats->lstats[i].curlextents == 0);
 			}
+#endif
 		}
 	}
 }
@@ -949,6 +1003,7 @@ ctl_refresh(tsdn_t *tsdn) {
 	}
 
 	if (config_stats) {
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		ctl_stats->allocated = ctl_sarena->astats->allocated_small +
 		    atomic_load_zu(&ctl_sarena->astats->astats.allocated_large,
 			ATOMIC_RELAXED);
@@ -961,10 +1016,13 @@ ctl_refresh(tsdn_t *tsdn) {
 		    &ctl_sarena->astats->astats.metadata_thp, ATOMIC_RELAXED);
 		ctl_stats->resident = atomic_load_zu(
 		    &ctl_sarena->astats->astats.resident, ATOMIC_RELAXED);
+#endif
 		ctl_stats->mapped = atomic_load_zu(
 		    &ctl_sarena->astats->astats.mapped, ATOMIC_RELAXED);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		ctl_stats->retained = atomic_load_zu(
 		    &ctl_sarena->astats->astats.retained, ATOMIC_RELAXED);
+#endif
 
 		ctl_background_thread_stats_read(tsdn);
 
@@ -2664,6 +2722,7 @@ CTL_RO_GEN(stats_arenas_i_pmuzzy, arenas_i(mib[2])->pmuzzy, size_t)
 CTL_RO_CGEN(config_stats, stats_arenas_i_mapped,
     atomic_load_zu(&arenas_i(mib[2])->astats->astats.mapped, ATOMIC_RELAXED),
     size_t)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_RO_CGEN(config_stats, stats_arenas_i_retained,
     atomic_load_zu(&arenas_i(mib[2])->astats->astats.retained, ATOMIC_RELAXED),
     size_t)
@@ -2703,6 +2762,7 @@ CTL_RO_CGEN(config_stats, stats_arenas_i_tcache_bytes,
 CTL_RO_CGEN(config_stats, stats_arenas_i_resident,
     atomic_load_zu(&arenas_i(mib[2])->astats->astats.resident, ATOMIC_RELAXED),
     size_t)
+#endif
 
 CTL_RO_CGEN(config_stats, stats_arenas_i_small_allocated,
     arenas_i(mib[2])->astats->allocated_small, size_t)
@@ -2712,6 +2772,7 @@ CTL_RO_CGEN(config_stats, stats_arenas_i_small_ndalloc,
     arenas_i(mib[2])->astats->ndalloc_small, uint64_t)
 CTL_RO_CGEN(config_stats, stats_arenas_i_small_nrequests,
     arenas_i(mib[2])->astats->nrequests_small, uint64_t)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_RO_CGEN(config_stats, stats_arenas_i_large_allocated,
     atomic_load_zu(&arenas_i(mib[2])->astats->astats.allocated_large,
     ATOMIC_RELAXED), size_t)
@@ -2727,6 +2788,7 @@ CTL_RO_CGEN(config_stats, stats_arenas_i_large_ndalloc,
 CTL_RO_CGEN(config_stats, stats_arenas_i_large_nrequests,
     ctl_arena_stats_read_u64(
     &arenas_i(mib[2])->astats->astats.nmalloc_large), uint64_t) /* Intentional. */
+#endif
 
 /* Lock profiling related APIs below. */
 #define RO_MUTEX_CTL_GEN(n, l)						\
@@ -2752,11 +2814,13 @@ CTL_RO_CGEN(config_stats, stats_##n##_max_num_thds,			\
 MUTEX_PROF_GLOBAL_MUTEXES
 #undef OP
 
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 /* Per arena mutexes */
 #define OP(mtx) RO_MUTEX_CTL_GEN(arenas_i_mutexes_##mtx,		\
     arenas_i(mib[2])->astats->astats.mutex_prof_data[arena_prof_mutex_##mtx])
 MUTEX_PROF_ARENA_MUTEXES
 #undef OP
+#endif
 
 /* tcache bin mutex */
 RO_MUTEX_CTL_GEN(arenas_i_bins_j_mutex,
@@ -2803,7 +2867,9 @@ stats_mutexes_reset_ctl(tsd_t *tsd, const size_t *mib, size_t miblen,
 		MUTEX_PROF_RESET(arena->extents_retained.mtx);
 		MUTEX_PROF_RESET(arena->decay_dirty.mtx);
 		MUTEX_PROF_RESET(arena->decay_muzzy.mtx);
+#if defined(ANDROID_ENABLE_TCACHE)
 		MUTEX_PROF_RESET(arena->tcache_ql_mtx);
+#endif
 		MUTEX_PROF_RESET(arena->base->mtx);
 
 		for (szind_t i = 0; i < NBINS; i++) {
@@ -2819,10 +2885,13 @@ CTL_RO_CGEN(config_stats, stats_arenas_i_bins_j_nmalloc,
     arenas_i(mib[2])->astats->bstats[mib[4]].nmalloc, uint64_t)
 CTL_RO_CGEN(config_stats, stats_arenas_i_bins_j_ndalloc,
     arenas_i(mib[2])->astats->bstats[mib[4]].ndalloc, uint64_t)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_RO_CGEN(config_stats, stats_arenas_i_bins_j_nrequests,
     arenas_i(mib[2])->astats->bstats[mib[4]].nrequests, uint64_t)
+#endif
 CTL_RO_CGEN(config_stats, stats_arenas_i_bins_j_curregs,
     arenas_i(mib[2])->astats->bstats[mib[4]].curregs, size_t)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_RO_CGEN(config_stats, stats_arenas_i_bins_j_nfills,
     arenas_i(mib[2])->astats->bstats[mib[4]].nfills, uint64_t)
 CTL_RO_CGEN(config_stats, stats_arenas_i_bins_j_nflushes,
@@ -2833,6 +2902,7 @@ CTL_RO_CGEN(config_stats, stats_arenas_i_bins_j_nreslabs,
     arenas_i(mib[2])->astats->bstats[mib[4]].reslabs, uint64_t)
 CTL_RO_CGEN(config_stats, stats_arenas_i_bins_j_curslabs,
     arenas_i(mib[2])->astats->bstats[mib[4]].curslabs, size_t)
+#endif
 
 static const ctl_named_node_t *
 stats_arenas_i_bins_j_index(tsdn_t *tsdn, const size_t *mib, size_t miblen,
@@ -2849,11 +2919,13 @@ CTL_RO_CGEN(config_stats, stats_arenas_i_lextents_j_nmalloc,
 CTL_RO_CGEN(config_stats, stats_arenas_i_lextents_j_ndalloc,
     ctl_arena_stats_read_u64(
     &arenas_i(mib[2])->astats->lstats[mib[4]].ndalloc), uint64_t)
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 CTL_RO_CGEN(config_stats, stats_arenas_i_lextents_j_nrequests,
     ctl_arena_stats_read_u64(
     &arenas_i(mib[2])->astats->lstats[mib[4]].nrequests), uint64_t)
 CTL_RO_CGEN(config_stats, stats_arenas_i_lextents_j_curlextents,
     arenas_i(mib[2])->astats->lstats[mib[4]].curlextents, size_t)
+#endif
 
 static const ctl_named_node_t *
 stats_arenas_i_lextents_j_index(tsdn_t *tsdn, const size_t *mib, size_t miblen,
diff --git a/src/extent.c b/src/extent.c
index da66a8e0..1e94cf34 100644
--- a/src/extent.c
+++ b/src/extent.c
@@ -2191,3 +2191,14 @@ extent_boot(void) {
 
 	return false;
 }
+
+void
+extent_postfork_child(tsdn_t *tsdn) {
+	// There is the possibility that a thread is holding one of these locks
+	// when forking, but all of the other locks acquired during the prefork
+	// should prevent any corruption if this code resets the locks.
+	mutex_pool_init(&extent_mutex_pool, "extent_mutex_pool",
+	    WITNESS_RANK_EXTENT_POOL);
+
+	malloc_mutex_init(&extents_rtree.init_lock, "rtree", WITNESS_RANK_RTREE, malloc_mutex_rank_exclusive);
+}
diff --git a/src/jemalloc.c b/src/jemalloc.c
index c2efa767..e438cd66 100644
--- a/src/jemalloc.c
+++ b/src/jemalloc.c
@@ -631,6 +631,7 @@ arenas_tdata_cleanup(tsd_t *tsd) {
 
 static void
 stats_print_atexit(void) {
+#if defined(ANDROID_ENABLE_TCACHE)
 	if (config_stats) {
 		tsdn_t *tsdn;
 		unsigned narenas, i;
@@ -658,6 +659,7 @@ stats_print_atexit(void) {
 			}
 		}
 	}
+#endif
 	je_malloc_stats_print(NULL, NULL, opt_stats_print_opts);
 }
 
@@ -3322,6 +3324,7 @@ jemalloc_postfork_child(void) {
 	tsd = tsd_fetch();
 
 	witness_postfork_child(tsd_witness_tsdp_get(tsd));
+	extent_postfork_child(tsd_tsdn(tsd));
 	/* Release all mutexes, now that fork() has completed. */
 	for (i = 0, narenas = narenas_total_get(); i < narenas; i++) {
 		arena_t *arena;
diff --git a/src/tcache.c b/src/tcache.c
index b2557c15..bb505d79 100644
--- a/src/tcache.c
+++ b/src/tcache.c
@@ -139,7 +139,9 @@ tcache_bin_flush_small(tsd_t *tsd, tcache_t *tcache, cache_bin_t *tbin,
 		if (config_stats && bin_arena == arena) {
 			assert(!merged_stats);
 			merged_stats = true;
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 			bin->stats.nflushes++;
+#endif
 #if defined(ANDROID_ENABLE_TCACHE_STATS)
 			bin->stats.nrequests += tbin->tstats.nrequests;
 			tbin->tstats.nrequests = 0;
@@ -177,7 +179,9 @@ tcache_bin_flush_small(tsd_t *tsd, tcache_t *tcache, cache_bin_t *tbin,
 		 */
 		bin_t *bin = &arena->bins[binind];
 		malloc_mutex_lock(tsd_tsdn(tsd), &bin->lock);
+#if !defined(ANDROID_MINIMIZE_STRUCTS)
 		bin->stats.nflushes++;
+#endif
 #if defined(ANDROID_ENABLE_TCACHE_STATS)
 		bin->stats.nrequests += tbin->tstats.nrequests;
 		tbin->tstats.nrequests = 0;
@@ -299,6 +303,7 @@ tcache_bin_flush_large(tsd_t *tsd, cache_bin_t *tbin, szind_t binind,
 
 void
 tcache_arena_associate(tsdn_t *tsdn, tcache_t *tcache, arena_t *arena) {
+#if defined(ANDROID_ENABLE_TCACHE)
 	assert(tcache->arena == NULL);
 	tcache->arena = arena;
 
@@ -316,10 +321,12 @@ tcache_arena_associate(tsdn_t *tsdn, tcache_t *tcache, arena_t *arena) {
 
 		malloc_mutex_unlock(tsdn, &arena->tcache_ql_mtx);
 	}
+#endif
 }
 
 static void
 tcache_arena_dissociate(tsdn_t *tsdn, tcache_t *tcache) {
+#if defined(ANDROID_ENABLE_TCACHE)
 	arena_t *arena = tcache->arena;
 	assert(arena != NULL);
 	if (config_stats) {
@@ -343,6 +350,7 @@ tcache_arena_dissociate(tsdn_t *tsdn, tcache_t *tcache) {
 		malloc_mutex_unlock(tsdn, &arena->tcache_ql_mtx);
 	}
 	tcache->arena = NULL;
+#endif
 }
 
 void
```

