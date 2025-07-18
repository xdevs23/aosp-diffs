```
9f2a00e: Don't run the math tests for routines we're not using. (Elliott Hughes <enh@google.com>)
3752b98: v25.01 release (Pierre Blanchard <pierre.blanchard@arm.com>)
75e6215: networking: Fix make install. (Pierre Blanchard <pierre.blanchard@arm.com>)
79decc2: Update README (Pierre Blanchard <pierre.blanchard@arm.com>)
080801d: math/aarch64/sve: more updates in exps. (Pierre Blanchard <pierre.blanchard@arm.com>)
2238b31: math/aarch64/sve: Corrected comment in sv_expf_inline.h (Claudio Martino <Claudio.Martino@arm.com>)
60ffae2: math/aarch64/sve: Improve codegen for pow (Yat Long Poon <YatLong.Poon@arm.com>)
28ec061: math/aarch64/sve: Improve codegen for powf (Yat Long Poon <YatLong.Poon@arm.com>)
40974f7: math/aarch64/sve: Improve codegen in exp and users. (Luna Lamb <Luna.Lamb@arm.com>)
3e3d392: math/aarch64/sve: Improve codegen for asinh. (Luna Lamb <Luna.Lamb@arm.com>)
fa4654d: math/aarch64/sve: Improve codegen for sincospif (Joana Cruz <Joana.Cruz@arm.com>)
a365caa: string: Improve SVE memset (Wilco Dijkstra <wilco.dijkstra@arm.com>)
21c5784: bench: Avoid indirect calls in memcpy (Wilco Dijkstra <wilco.dijkstra@arm.com>)
fc1c316: bench: Avoid indirect calls in strlen (Wilco Dijkstra <wilco.dijkstra@arm.com>)
9540bf7: math: Remove sve-math-cflags variable (Joe Ramsay <joe.ramsay@arm.com>)
e2785b1: math: Remove WANT_SIMD_TESTS (Joe Ramsay <joe.ramsay@arm.com>)
6c74650: math: Add vector annotations to mathlib.h (Joe Ramsay <joe.ramsay@arm.com>)
1017271: math/aarch64: Improve codegen for SVE erfcf (Yat Long Poon <YatLong.Poon@arm.com>)
71e3640: string: Cleanup defines (Wilco Dijkstra <wilco.dijkstra@arm.com>)
316ccb3: string: move SVE functions into experimental directory (Wilco Dijkstra <wilco.dijkstra@arm.com>)
f6fd56b: bench: Avoid indirect calls in benchmarks (Wilco Dijkstra <wilco.dijkstra@arm.com>)
10de479: string: Fix 32-bit Arm build (Wilco Dijkstra <wilco.dijkstra@arm.com>)
bb0538d: Update list of maintainers. (Pierre Blanchard <pierre.blanchard@arm.com>)
4e6c2da: math: Add unmangled names for trigpis if experimental math enabled (Joe Ramsay <joe.ramsay@arm.com>)
991f5ea: math: Raise minimum GCC version (Joe Ramsay <joe.ramsay@arm.com>)
937d32d: Add janitors to the OWNERS file (Sadaf Ebrahimi <sadafebrahimi@google.com>)
9a2e719: math: Do not copy math-tools headers (Joe Ramsay <Joe.Ramsay@arm.com>)
81ac58f: math: Fix powi test line (Joe Ramsay <Joe.Ramsay@arm.com>)
78cd003: math/aarch64/sve: Improve codegen expm1f and users. (Luna Lamb <Luna.Lamb@arm.com>)
98f48ed: math, pl/math: Remove PL completely (Joe Ramsay <joe.ramsay@arm.com>)
aed553c: math, pl/math: Move all experimental scalar routines to math (Joe Ramsay <joe.ramsay@arm.com>)
95cd10b: math, pl/math: Move low-accuracy scalar erfs to math (Joe Ramsay <joe.ramsay@arm.com>)
d77ed82: math, pl/math: Add erfinv and powi in math (Joe Ramsay <joe.ramsay@arm.com>)
ec48195: math, pl/math: Move funcs with non-standard signature to math (Joe Ramsay <joe.ramsay@arm.com>)
a386525: math/aarch64/sve: Improve codegen for log1pf and users (Yat Long Poon <YatLong.Poon@arm.com>)
e4a99aa: math/aarch64/sve: Update log max ULP error (Yat Long Poon <YatLong.Poon@arm.com>)
41e5ae5: string: Remove ILP32 defines (Wilco Dijkstra <wilco.dijkstra@arm.com>)
f6c190e: math: Improve exp10 data layout (Wilco Dijkstra <wilco.dijkstra@arm.com>)
ce53bb5: math/aarch64/sve: Improve codegen in tans. (Luna Lamb <Luna.Lamb@arm.com>)
6ed9529: math, pl/math: Move tanpi to math (Joe Ramsay <joe.ramsay@arm.com>)
c3114f1: math, pl/math: Move sinpi, cospi, sincospi to math (Joe Ramsay <joe.ramsay@arm.com>)
747e0e1: math/aarch64/advsimd: Improve codegen for coshf (Joana Cruz <joana.cruz@arm.com>)
7668501: math/aarch64/advsimd: Improve codegen for exp10f (Joana Cruz <joana.cruz@arm.com>)
6c6e552: math/aarch64/advsimd: Improve codegen for exp2f and exp2f_1u (Joana Cruz <joana.cruz@arm.com>)
c154f23: math/aarch64/advsimd: Improve codegen for expf and expf_1u (Joana Cruz <joana.cruz@arm.com>)
d99d93f: math/aarch64/sve: Improve codegen for logs (Yat Long Poon <YatLong.Poon@arm.com>)
ec4e493: math: fix mathbench on Windows. (Pierre Blanchard <pierre.blanchard@arm.com>)
81f7270: math/aarch64/advsimd: Improve codegen of asinh. (Luna Lamb <Luna.Lamb@arm.com>)
6d27564: math/aarch64/advsimd: update tanh ulp threshold and max error. (Pierre Blanchard <pierre.blanchard@arm.com>)
733739c: math/aarch64/advsimd: optimize pow (Pierre Blanchard <pierre.blanchard@arm.com>)
3902778: math/aarch64/advsimd: Improve codegen for atan2f (Joana Cruz <joana.cruz@arm.com>)
cae99f1: math/aarch64/advsimd: Improve codegen for atan2 (Joana Cruz <joana.cruz@arm.com>)
a135ce2: string: Fix SVE build (Wilco Dijkstra <wilco.dijkstra@arm.com>)
8c08642: pl/math/aarch64/sve: port AdvSIMD tanpi to SVE (Luna Lamb <Luna.Lamb@arm.com>)
24d7d8a: math: Replace $(S) with $(math-src-dir) (Joe Ramsay <Joe.Ramsay@arm.com>)
eeeb22a: pl/math/aarch64/advsimd: implement tanpi (Pierre Blanchard <pierre.blanchard@arm.com>)
df9ec2e: math/aarch64/advsimd: Improve codegen for log2f (Joana Cruz <joana.cruz@arm.com>)
44be610: math/aarch64/advsimd: Improve codegen for log10f (Joana Cruz <joana.cruz@arm.com>)
675ea95: math/aarch64/advsimd: Improve codegen for logf (Joana Cruz <joana.cruz@arm.com>)
e8860f8: math/aarch64: Adjust error threshold for expm1 and log. (Pierre Blanchard <pierre.blanchard@arm.com>)
098d998: pl/math/aarch64/sve: port tanpif AdvSIMD to SVE. (Luna Lamb <Luna.Lamb@arm.com>)
bb745e2: math/aarch64/advsimd: Adjust error threshold for sinh (Pierre Blanchard <pierre.blanchard@arm.com>)
02f8a9d: math/aarch64/advsimd: optimize logs (Pierre Blanchard <pierre.blanchard@arm.com>)
53145b5: pl/math: Improve codegen for  Neon asin (Joana Cruz <Joana.Cruz@arm.com>)
c507e7a: pl/math: Improve codegen for Neon atan (Joana Cruz <Joana.Cruz@arm.com>)
0a6ab6d: math, pl/math: Reorganise vector routines (Joe Ramsay <Joe.Ramsay@arm.com>)
23ab6e3: math, pl/math: Move vector cbrts to math (Joe Ramsay <Joe.Ramsay@arm.com>)
e9c20fb: math, pl/math: Rename data symbols to avoid conflicts with libc (Joe Ramsay <Joe.Ramsay@arm.com>)
ca0bfe5: math, pl/math: Move vector erf/erfc variants to math (Joe Ramsay <joe.ramsay@arm.com>)
c0136f1: math, pl/math: Move scalar log10f to math (Joe Ramsay <joe.ramsay@arm.com>)
2623409: math, pl/math: Move vector cosh to math/ (Joe Ramsay <joe.ramsay@arm.com>)
3dfd4d2: math, pl/math: Move remaining log and exp variants to math (Joe Ramsay <joe.ramsay@arm.com>)
34cc402: math, pl/math: Move log-related routines to math (Joe Ramsay <joe.ramsay@arm.com>)
c866cfc: math: Fix warning in tgamma128 (Joe Ramsay <Joe.Ramsay@arm.com>)
f6619fa: math, pl/math: Move vector pows to math (Joe Ramsay <joe.ramsay@arm.com>)
be89a4c: math, pl/math: Move all self-contained vector routines to math/ (Joe Ramsay <joe.ramsay@arm.com>)
84aa900: pl/math: Remove WANT_VMATH completely (Joe Ramsay <joe.ramsay@arm.com>)
8f73027: math, pl/math: Build tools for AdvSIMD routines based on WANT_SIMD_TESTS... (Joe Ramsay <joe.ramsay@arm.com>)
0ebccbe: pl/math: Improve codegen in Neon log1p and users (Pierre Blanchard <pierre.blanchard@arm.com>)
8e0d0da: pl/math: Improve codegen in Neon expm1 and users (Pierre Blanchard <pierre.blanchard@arm.com>)
0f80f1c: pl/math: Reduce register pressure slightly in AdvSIMD erfc (Joe Ramsay <Joe.Ramsay@arm.com>)
62add02: pl/math: Prevent spill in AdvSIMD erf (Joe Ramsay <Joe.Ramsay@arm.com>)
932dc00: pl/math: Align TEST_SIG decls with ones in math/ (Joe Ramsay <joe.ramsay@arm.com>)
aec783d: math: Add auto-generation of ulp & bench maps (Joe Ramsay <joe.ramsay@arm.com>)
545d2a9: pl/math: Rename PL_SIG make variables (Joe Ramsay <joe.ramsay@arm.com>)
426db36: pl/math: Correct name mangling in PL_DECL macro (Joe Ramsay <joe.ramsay@arm.com>)
a8d315e: Add func argument to math/test/runulp.sh (Joe Ramsay <joe.ramsay@arm.com>)
ba682eb: Rename PL_TEST directives to TEST (Joe Ramsay <joe.ramsay@arm.com>)
b4c19c4: math, pl/math: Small simplification in test directives (Joe Ramsay <joe.ramsay@arm.com>)
3bb85af: pl/math: Add separate test macro for control values (Joe Ramsay <joe.ramsay@arm.com>)
af29d39: math: Move test intervals to source files (Joe Ramsay <joe.ramsay@arm.com>)
714339b: math: Move max ULP and fenv spec to routine sources (Joe Ramsay <joe.ramsay@arm.com>)
1f89b65: pl/math: Fix fenv handling in test macros (Joe Ramsay <Joe.Ramsay@arm.com>)
140d9e9: math, pl/math: Improve trigpi tests (Pierre Blanchard <pierre.blanchard@arm.com>)
3389879: pl/math: Implement AdvSIMD tanpif. (Joana Cruz <Joana.Cruz@arm.com>)
0fbc16a: math, pl/math:  Build tools for WoA (Pierre Blanchard <pierre.blanchard@arm.com>)
5e9ea23: pl/math: Add scalar tanpi/f implementation. (Gabriel Harrison <Gabriel.Harrison@arm.com>)
e00681d: math, pl/math: Redefine INFINITY to work on Windows (Pierre Blanchard <pierre.blanchard@arm.com>)
a4c1309: math, pl/math: Compile math for WoA. (Pierre Blanchard <pierre.blanchard@arm.com>)
92f94cd: pl/math: Improve codegen in users of Neon expm1f helper (Joe Ramsay <Joe.Ramsay@arm.com>)
141faef: pl/math: Improve codegen in users of Neon log1pf helper (Joe Ramsay <Joe.Ramsay@arm.com>)
3114bef: math/aarch64: Optimise several shift-based reductions (Joe Ramsay <Joe.Ramsay@arm.com>)
44a79ce: pl/math: Fix sincospi sign handling. (Pierre Blanchard <pierre.blanchard@arm.com>)
983003e: pl/math: Improve codegen in SVE expf and inline helper (Joe Ramsay <Joe.Ramsay@arm.com>)
7342bc6: pl/math: Improve codegen for SVE F32 logs (Joe Ramsay <Joe.Ramsay@arm.com>)
35c749c: pl/math: fix scalar erfc. (Pierre Blanchard <pierre.blanchard@arm.com>)
30c5a93: math, pl/math: Fix up use of mpfr in runulp.sh. (Pierre Blanchard <pierre.blanchard@arm.com>)
be60062: math, pl/math: Disable vector symbols unless on Linux (Joe Ramsay <Joe.Ramsay@arm.com>)
e34c521: pl/math: Reformat tests for sincospi functions. (Gabriel Harrison <Gabriel.Harrison@arm.com>)
3d382c4: pl/math: Implement SVE sincospi (Gabriel Harrison <Gabriel.Harrison@arm.com>)
8720965: pl/math: Implement SVE sincospif (Gabriel Harrison <Gabriel.Harrison@arm.com>)
700776a: string: Minor memset tweaks (Wilco Dijkstra <wilco.dijkstra@arm.com>)
53fba1d: pl/math, math: Fix handling of x0 around return value (Joe Ramsay <Joe.Ramsay@arm.com>)
986e1de: pl/math: Fix return-value trick for Neon tanh (Joe Ramsay <Joe.Ramsay@arm.com>)
5eaca81: pl/math: Implement Neon sincospi (Joana Cruz <joana.cruz@arm.com>)
7aab9c5: pl/math: Add double precision scalar sincospi implementation (Joana Cruz <joana.cruz@arm.com>)
ea3d1f2: pl/math: Implement sve double precision modf (Gabriel Harrison <Gabriel.Harrison@arm.com>)
bc78e9a: pl/math: Implement sve single precision modf (Gabriel Harrison <Gabriel.Harrison@arm.com>)
55b326c: pl/math: Rename private exp table (Joe Ramsay <Joe.Ramsay@arm.com>)
dc07724: pl/math: Implement neon double precision modf (Gabriel Harrison <Gabriel.Harrison@arm.com>)
43b916e: pl/math, math: Remove global __exp_dd symbol (Joe Ramsay <Joe.Ramsay@arm.com>)
9190f2f: string: Optimize __memset_aarch64 (Wilco Dijkstra <wilco.dijkstra@arm.com>)
655044e: pl/math: implement Neon sincospif (Joana Cruz <joana.cruz@arm.com>)
1da312c: pl/math: add scalar sincospif (Joana Cruz <joana.cruz@arm.com>)
2793c52: pl/math: Pass WANT_TRIGPI_TESTS to autogenerated map entries (Joe Ramsay <Joe.Ramsay@arm.com>)
11ccc85: Add config for building math and pl/math on MacOS (Joe Ramsay <Joe.Ramsay@arm.com>)
2082e0e: math, pl/math: Deal with absence of exp10 on non-GNU systems (Joe Ramsay <Joe.Ramsay@arm.com>)
45d5f2d: pl/math: Deal with absence of sincos on non-GNU systems (Joe Ramsay <Joe.Ramsay@arm.com>)
ca6e298: pl/math: Deal with absence of M_PIl on non-GNU systems (Joe Ramsay <Joe.Ramsay@arm.com>)
5c8f809: pl/math: Implement neon single precision modf (Gabriel Harrison <Gabriel.Harrison@arm.com>)
9b45a50: math: Improve layout of exp/expf data (Wilco Dijkstra <wdijkstr@arm.com>)
0046982: Fix MPFR build for math and pl/math (Joe Ramsay <Joe.Ramsay@arm.com>)
17feb82: pl/math: Fix sign of zero in sinpi & sinpif (Joe Ramsay <Joe.Ramsay@arm.com>)
f0d6b48: string: Add SVE memset (Wilco Dijkstra <wilco.dijkstra@arm.com>)
f8af395: string: Improve strlen-mte performance (Wilco Dijkstra <wilco.dijkstra@arm.com>)
e3bfc4a: string: Improve string benchmarks (Wilco Dijkstra <wilco.dijkstra@arm.com>)
```

