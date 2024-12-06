```diff
diff --git a/FIXES b/FIXES
index 33a36fc..ad8bce2 100644
--- a/FIXES
+++ b/FIXES
@@ -25,9 +25,36 @@ THIS SOFTWARE.
 This file lists all bug fixes, changes, etc., made since the 
 second edition of the AWK book was published in September 2023.
 
+Jul 28, 2024
+	Fixed readcsvrec resize segfault when reading csv records longer
+	than 8k. Thanks to Ozan Yigit.
+	mktime() added to bsd-features branch. Thanks to Todd Miller.
+
+Jun 23, 2024
+	Fix signal for system-status test. Thanks to Tim van der Molen.
+	Rewrite if-else chain as switch. Thanks to Andrew Sukach.
+
+May 27, 2024
+	Spelling fixes and removal of unneeded prototypes and extern.
+	Thanks to Jonathan Gray.
+
+May 4, 2024
+	Fixed a use-after-free bug with ARGV for "delete ARGV".
+	Also ENVtab is no longer global. Thanks to Benjamin Sturz
+	for spotting the ARGV issue and	Todd Miller for the fix. 
+
+May 3, 2024:
+	Remove warnings when compiling with g++. Thanks to Arnold Robbins.
+
+Apr 22, 2024:
+	Fixed regex engine gototab reallocation issue that was
+	Introduced during the Nov 24 rewrite. Thanks to Arnold Robbins.
+	Fixed a scan bug in split in the case the separator is a single
+	character. Thanks to Oguz Ismail for spotting the issue.
+
 Mar 10, 2024:
-	fixed use-after-free bug in fnematch due to adjbuf invalidating
-	the pointers to buf. thanks to github user caffe3 for spotting
+	Fixed use-after-free bug in fnematch due to adjbuf invalidating
+	the pointers to buf. Thanks to github user caffe3 for spotting
 	the issue and providing a fix, and to Miguel Pineiro Jr.
 	for the alternative fix.
 	MAX_UTF_BYTES in fnematch has been replaced with awk_mb_cur_max.
diff --git a/FIXES.1e b/FIXES.1e
index 8cbd6ac..880226d 100644
--- a/FIXES.1e
+++ b/FIXES.1e
@@ -224,7 +224,7 @@ January 9, 2020:
 	mere warnings. Thanks to Martijn Dekker <martijn@inlv.org>.
 
 January 5, 2020:
-	Fix a bug in the concatentation of two string constants into
+	Fix a bug in the concatenation of two string constants into
 	one done in the grammar.  Fixes GitHub issue #61.  Thanks
 	to GitHub user awkfan77 for pointing out the direction for
 	the fix.  New test T.concat added to the test suite.
@@ -866,7 +866,7 @@ Jan 13, 1999:
 	added a few (int) casts to silence useless compiler warnings.
 	e.g., errorflag= in run.c jump().
 
-	added proctab.c to the bundle outout; one less thing
+	added proctab.c to the bundle output; one less thing
 	to have to compile out of the box.
 
 	added calls to _popen and _pclose to the win95 stub for
diff --git a/METADATA b/METADATA
index 2c9a96a..80b43ef 100644
--- a/METADATA
+++ b/METADATA
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 4
-    day: 9
+    month: 8
+    day: 5
   }
   identifier {
     type: "Git"
     value: "https://github.com/onetrueawk/awk.git"
-    version: "20240311"
+    version: "20240728"
   }
 }
diff --git a/README.md b/README.md
index a41fb3c..aba0572 100644
--- a/README.md
+++ b/README.md
@@ -16,7 +16,7 @@ this affects `length`, `substr`, `index`, `match`, `split`,
 points are not necessarily characters.
 
 UTF-8 sequences may appear in literal strings and regular expressions.
-Aribtrary characters may be included with `\u` followed by 1 to 8 hexadecimal digits.
+Arbitrary characters may be included with `\u` followed by 1 to 8 hexadecimal digits.
 
 ### Regular expressions ###
 
diff --git a/TODO b/TODO
index 13f2925..151cb88 100644
--- a/TODO
+++ b/TODO
@@ -14,6 +14,6 @@ and see exactly which tests fail:
    The beebe.tar file appears to be from sometime in the 1990s.
 
 3. Make the One True Awk valgrind clean. In particular add a
-   a test suite target that runs valgrind on all the tests and
+   test suite target that runs valgrind on all the tests and
    reports if there are any definite losses or any invalid reads
    or writes (similar to gawk's test of this nature).
diff --git a/awk.h b/awk.h
index 76180e4..b92faa3 100644
--- a/awk.h
+++ b/awk.h
@@ -168,7 +168,6 @@ typedef struct Node {
 #define	NIL	((Node *) 0)
 
 extern Node	*winner;
-extern Node	*nullstat;
 extern Node	*nullnode;
 
 /* ctypes */
diff --git a/b.c b/b.c
index 870eecf..a8f6778 100644
--- a/b.c
+++ b/b.c
@@ -369,36 +369,49 @@ int quoted(const uschar **pp)	/* pick up next thing after a \\ */
 
 /* BUG: should advance by utf-8 char even if makes no sense */
 
-	if ((c = *p++) == 't') {
+	switch ((c = *p++)) {
+	case 't':
 		c = '\t';
-	} else if (c == 'n') {
+		break;
+	case 'n':
 		c = '\n';
-	} else if (c == 'f') {
+		break;
+	case 'f':
 		c = '\f';
-	} else if (c == 'r') {
+		break;
+	case 'r':
 		c = '\r';
-	} else if (c == 'b') {
+		break;
+	case 'b':
 		c = '\b';
-	} else if (c == 'v') {
+		break;
+	case 'v':
 		c = '\v';
-	} else if (c == 'a') {
+		break;
+	case 'a':
 		c = '\a';
-	} else if (c == '\\') {
+		break;
+	case '\\':
 		c = '\\';
-	} else if (c == 'x') {	/* 2 hex digits follow */
-		c = hexstr(&p, 2);	/* this adds a null if number is invalid */
-	} else if (c == 'u') {	/* unicode char number up to 8 hex digits */
+		break;
+	case 'x': /* 2 hex digits follow */
+		c = hexstr(&p, 2); /* this adds a null if number is invalid */
+		break;
+	case 'u': /* unicode char number up to 8 hex digits */
 		c = hexstr(&p, 8);
-	} else if (isoctdigit(c)) {	/* \d \dd \ddd */
-		int n = c - '0';
-		if (isoctdigit(*p)) {
-			n = 8 * n + *p++ - '0';
-			if (isoctdigit(*p))
+		break;
+	default:
+		if (isoctdigit(c)) { /* \d \dd \ddd */
+			int n = c - '0';
+			if (isoctdigit(*p)) {
 				n = 8 * n + *p++ - '0';
+				if (isoctdigit(*p))
+					n = 8 * n + *p++ - '0';
+			}
+			c = n;
 		}
-		c = n;
-	} /* else */
-		/* c = c; */
+	}
+
 	*pp = p;
 	return c;
 }
@@ -645,14 +658,14 @@ static int set_gototab(fa *f, int state, int ch, int val) /* hide gototab implem
 		f->gototab[state].entries[0].state = val;
 		f->gototab[state].inuse++;
 		return val;
-	} else if (ch > f->gototab[state].entries[f->gototab[state].inuse-1].ch) {
+	} else if ((unsigned)ch > f->gototab[state].entries[f->gototab[state].inuse-1].ch) {
 		// not seen yet, insert and return
 		gtt *tab = & f->gototab[state];
 		if (tab->inuse + 1 >= tab->allocated)
 			resize_gototab(f, state);
 
-		f->gototab[state].entries[f->gototab[state].inuse-1].ch = ch;
-		f->gototab[state].entries[f->gototab[state].inuse-1].state = val;
+		f->gototab[state].entries[f->gototab[state].inuse].ch = ch;
+		f->gototab[state].entries[f->gototab[state].inuse].state = val;
 		f->gototab[state].inuse++;
 		return val;
 	} else {
@@ -677,9 +690,9 @@ static int set_gototab(fa *f, int state, int ch, int val) /* hide gototab implem
 	gtt *tab = & f->gototab[state];
 	if (tab->inuse + 1 >= tab->allocated)
 		resize_gototab(f, state);
-	++tab->inuse;
 	f->gototab[state].entries[tab->inuse].ch = ch;
 	f->gototab[state].entries[tab->inuse].state = val;
+	++tab->inuse;
 
 	qsort(f->gototab[state].entries,
 		f->gototab[state].inuse, sizeof(gtte), entry_cmp);
@@ -869,7 +882,7 @@ bool fnematch(fa *pfa, FILE *f, char **pbuf, int *pbufsize, int quantum)
 		 * Call u8_rune with at least awk_mb_cur_max ahead in
 		 * the buffer until EOF interferes.
 		 */
-		if (k - j < awk_mb_cur_max) {
+		if (k - j < (int)awk_mb_cur_max) {
 			if (k + awk_mb_cur_max > buf + bufsize) {
 				char *obuf = buf;
 				adjbuf((char **) &buf, &bufsize,
diff --git a/bugs-fixed/ofs-rebuild.awk b/bugs-fixed/ofs-rebuild.awk
index dd27000..7c5e5ee 100644
--- a/bugs-fixed/ofs-rebuild.awk
+++ b/bugs-fixed/ofs-rebuild.awk
@@ -10,7 +10,7 @@ BEGIN {
 	# Change OFS after (conceptually) rebuilding the record
 	OFS = "<>"
 
-	# Unmodifed nawk prints "a<>b<>3333<>d<>e<>f<>g" because
+	# Unmodified nawk prints "a<>b<>3333<>d<>e<>f<>g" because
 	# it delays rebuilding $0 until it's needed, and then it uses
 	# the current value of OFS. Oops.
 	print
diff --git a/bugs-fixed/system-status.awk b/bugs-fixed/system-status.awk
index 8daf563..a369637 100644
--- a/bugs-fixed/system-status.awk
+++ b/bugs-fixed/system-status.awk
@@ -9,7 +9,7 @@ BEGIN {
 	status = system("exit 42")
 	print "normal status", status
 
-	status = system("kill -HUP $$")
+	status = system("kill -KILL $$")
 	print "death by signal status", status
 
 	status = system("kill -ABRT $$")
diff --git a/bugs-fixed/system-status.ok b/bugs-fixed/system-status.ok
index 737828f..afc0788 100644
--- a/bugs-fixed/system-status.ok
+++ b/bugs-fixed/system-status.ok
@@ -1,3 +1,3 @@
 normal status 42
-death by signal status 257
+death by signal status 265
 death by signal with core dump status 518
diff --git a/bugs-fixed/system-status.ok2 b/bugs-fixed/system-status.ok2
index f1f631e..c8f39fc 100644
--- a/bugs-fixed/system-status.ok2
+++ b/bugs-fixed/system-status.ok2
@@ -1,3 +1,3 @@
 normal status 42
-death by signal status 257
+death by signal status 265
 death by signal with core dump status 262
diff --git a/lex.c b/lex.c
index 0473a33..add5bfb 100644
--- a/lex.c
+++ b/lex.c
@@ -216,7 +216,7 @@ int yylex(void)
 				;
 			unput(c);
 			/*
-			 * Next line is a hack, itcompensates for
+			 * Next line is a hack, it compensates for
 			 * unput's treatment of \n.
 			 */
 			lineno++;
diff --git a/lib.c b/lib.c
index 0dac1f9..a2731d6 100644
--- a/lib.c
+++ b/lib.c
@@ -231,7 +231,7 @@ int readrec(char **pbuf, int *pbufsize, FILE *inf, bool newflag)	/* read one rec
 	char *rs = getsval(rsloc);
 
 	if (CSV) {
-		c = readcsvrec(pbuf, pbufsize, inf, newflag);
+		c = readcsvrec(&buf, &bufsize, inf, newflag);
 		isrec = (c == EOF && rr == buf) ? false : true;
 	} else if (*rs && rs[1]) {
 		bool found;
@@ -335,14 +335,16 @@ int readcsvrec(char **pbuf, int *pbufsize, FILE *inf, bool newflag) /* csv can h
 
 char *getargv(int n)	/* get ARGV[n] */
 {
+	Array *ap;
 	Cell *x;
 	char *s, temp[50];
-	extern Array *ARGVtab;
+	extern Cell *ARGVcell;
 
+	ap = (Array *)ARGVcell->sval;
 	snprintf(temp, sizeof(temp), "%d", n);
-	if (lookup(temp, ARGVtab) == NULL)
+	if (lookup(temp, ap) == NULL)
 		return NULL;
-	x = setsymtab(temp, "", 0.0, STR, ARGVtab);
+	x = setsymtab(temp, "", 0.0, STR, ap);
 	s = getsval(x);
 	DPRINTF("getargv(%d) returns |%s|\n", n, s);
 	return s;
diff --git a/main.c b/main.c
index 5bc1272..7d3ef84 100644
--- a/main.c
+++ b/main.c
@@ -22,7 +22,7 @@ ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 THIS SOFTWARE.
 ****************************************************************/
 
-const char	*version = "version 20240311";
+const char	*version = "version 20240728";
 
 #define DEBUG
 #include <stdio.h>
@@ -62,22 +62,42 @@ static noreturn void fpecatch(int n
 )
 {
 #ifdef SA_SIGINFO
-	static const char *emsg[] = {
-		[0] = "Unknown error",
-		[FPE_INTDIV] = "Integer divide by zero",
-		[FPE_INTOVF] = "Integer overflow",
-		[FPE_FLTDIV] = "Floating point divide by zero",
-		[FPE_FLTOVF] = "Floating point overflow",
-		[FPE_FLTUND] = "Floating point underflow",
-		[FPE_FLTRES] = "Floating point inexact result",
-		[FPE_FLTINV] = "Invalid Floating point operation",
-		[FPE_FLTSUB] = "Subscript out of range",
-	};
+	const char *mesg = NULL;
+
+	switch (si->si_code) {
+	case FPE_INTDIV:
+		mesg = "Integer divide by zero";
+		break;
+	case FPE_INTOVF:
+		mesg = "Integer overflow";
+		break;
+	case FPE_FLTDIV:
+		mesg = "Floating point divide by zero";
+		break;
+	case FPE_FLTOVF:
+		mesg = "Floating point overflow";
+		break;
+	case FPE_FLTUND:
+		mesg = "Floating point underflow";
+		break;
+	case FPE_FLTRES:
+		mesg = "Floating point inexact result";
+		break;
+	case FPE_FLTINV:
+		mesg = "Invalid Floating point operation";
+		break;
+	case FPE_FLTSUB:
+		mesg = "Subscript out of range";
+		break;
+	case 0:
+	default:
+		mesg = "Unknown error";
+		break;
+	}
 #endif
 	FATAL("floating point exception"
 #ifdef SA_SIGINFO
-		": %s", (size_t)si->si_code < sizeof(emsg) / sizeof(emsg[0]) &&
-		emsg[si->si_code] ? emsg[si->si_code] : emsg[0]
+		": %s", mesg
 #endif
 	    );
 }
diff --git a/makefile b/makefile
index b47a8af..0240e5e 100644
--- a/makefile
+++ b/makefile
@@ -32,6 +32,7 @@ CFLAGS = -O2
 #CC = cc -O4 -Wall -pedantic -fno-strict-aliasing
 #CC = cc -fprofile-arcs -ftest-coverage # then gcov f1.c; cat f1.c.gcov
 HOSTCC = cc -g -Wall -pedantic -Wcast-qual
+# HOSTCC = g++ -g -Wall -pedantic -Wcast-qual
 CC = $(HOSTCC)  # change this is cross-compiling.
 
 # By fiat, to make our lives easier, yacc is now defined to be bison.
diff --git a/proto.h b/proto.h
index ed63e78..cfd4b7c 100644
--- a/proto.h
+++ b/proto.h
@@ -34,9 +34,6 @@ extern	void	startreg(void);
 extern	int	input(void);
 extern	void	unput(int);
 extern	void	unputstr(const char *);
-extern	int	yylook(void);
-extern	int	yyback(int *, int);
-extern	int	yyinput(void);
 
 extern	fa	*makedfa(const char *, bool);
 extern	fa	*mkdfa(const char *, bool);
@@ -167,7 +164,6 @@ extern	Cell	*boolop(Node **, int);
 extern	Cell	*relop(Node **, int);
 extern	void	tfree(Cell *);
 extern	Cell	*gettemp(void);
-extern	Cell	*field(Node **, int);
 extern	Cell	*indirect(Node **, int);
 extern	Cell	*substr(Node **, int);
 extern	Cell	*sindex(Node **, int);
diff --git a/run.c b/run.c
index 799e998..44c0f41 100644
--- a/run.c
+++ b/run.c
@@ -724,7 +724,7 @@ int u8_byte2char(const char *s, int bytenum)
 	return charnum;
 }
 
-/* runetochar() adapted from rune.c in the Plan 9 distributione */
+/* runetochar() adapted from rune.c in the Plan 9 distribution */
 
 enum
 {
@@ -1827,7 +1827,7 @@ Cell *split(Node **a, int nnn)	/* split(a[0], a[1], a[2]); a[3] is type */
 		for (;;) {
 			n++;
 			t = s;
-			while (*s != sep && *s != '\n' && *s != '\0')
+			while (*s != sep && *s != '\0')
 				s++;
 			temp = *s;
 			setptr(s, '\0');
@@ -2061,7 +2061,7 @@ static char *nawk_tolower(const char *s)
 Cell *bltin(Node **a, int n)	/* builtin functions. a[0] is type, a[1] is arg list */
 {
 	Cell *x, *y;
-	Awkfloat u;
+	Awkfloat u = 0;
 	int t;
 	Awkfloat tmp;
 	char *buf;
@@ -2406,7 +2406,7 @@ void backsub(char **pb_ptr, const char **sptr_ptr);
 Cell *dosub(Node **a, int subop)        /* sub and gsub */
 {
 	fa *pfa;
-	int tempstat;
+	int tempstat = 0;
 	char *repl;
 	Cell *x;
 
@@ -2418,7 +2418,7 @@ Cell *dosub(Node **a, int subop)        /* sub and gsub */
 	const char *start;
 	const char *noempty = NULL;      /* empty match disallowed here */
 	size_t m = 0;                    /* match count */
-	size_t whichm;                   /* which match to select, 0 = global */
+	size_t whichm = 0;               /* which match to select, 0 = global */
 	int mtype;                       /* match type */
 
 	if (a[0] == NULL) {	/* 0 => a[1] is already-compiled regexpr */
diff --git a/testdir/T.argv b/testdir/T.argv
index 55e2754..2002d3c 100755
--- a/testdir/T.argv
+++ b/testdir/T.argv
@@ -148,3 +148,26 @@ END {
                 printf("ARGV[%d] is %s\n", i, ARGV[i])
 }' >foo2
 diff foo1 foo2 || echo 'BAD: T.argv delete ARGV[2]'
+
+# deleting ARGV used to trigger a use-after-free crash when awk
+# iterates over it to read files.
+echo >foo1
+echo >foo2
+echo >foo3
+
+$awk 'BEGIN {
+	delete ARGV
+	ARGV[0] = "awk"
+	ARGV[1] = "/dev/null"
+	ARGC = 2
+} {
+	# this should not be executed
+	print "FILENAME: " FILENAME
+	fflush()
+}' foo1 foo2 foo3 >foo4
+
+awkstatus=$?
+diff /dev/null foo4
+if [ $? -ne 0 ] || [ $awkstatus -ne 0 ]; then
+	echo 'BAD: T.argv delete ARGV'
+fi
diff --git a/testdir/T.csconcat b/testdir/T.csconcat
index 5199600..a877543 100755
--- a/testdir/T.csconcat
+++ b/testdir/T.csconcat
@@ -1,4 +1,4 @@
-echo T.csconcat: test constant string concatentation
+echo T.csconcat: test constant string concatenation
 
 awk=${awk-../a.out}
 
diff --git a/tran.c b/tran.c
index 482eede..ad8234a 100644
--- a/tran.c
+++ b/tran.c
@@ -57,8 +57,7 @@ Cell	*fnrloc;	/* FNR */
 Cell	*ofsloc;	/* OFS */
 Cell	*orsloc;	/* ORS */
 Cell	*rsloc;		/* RS */
-Array	*ARGVtab;	/* symbol table containing ARGV[...] */
-Array	*ENVtab;	/* symbol table containing ENVIRON[...] */
+Cell	*ARGVcell;	/* cell with symbol table containing ARGV[...] */
 Cell	*rstartloc;	/* RSTART */
 Cell	*rlengthloc;	/* RLENGTH */
 Cell	*subseploc;	/* SUBSEP */
@@ -107,36 +106,39 @@ void syminit(void)	/* initialize symbol table with builtin vars */
 
 void arginit(int ac, char **av)	/* set up ARGV and ARGC */
 {
+	Array *ap;
 	Cell *cp;
 	int i;
 	char temp[50];
 
 	ARGC = &setsymtab("ARGC", "", (Awkfloat) ac, NUM, symtab)->fval;
 	cp = setsymtab("ARGV", "", 0.0, ARR, symtab);
-	ARGVtab = makesymtab(NSYMTAB);	/* could be (int) ARGC as well */
+	ap = makesymtab(NSYMTAB);	/* could be (int) ARGC as well */
 	free(cp->sval);
-	cp->sval = (char *) ARGVtab;
+	cp->sval = (char *) ap;
 	for (i = 0; i < ac; i++) {
 		double result;
 
 		sprintf(temp, "%d", i);
 		if (is_number(*av, & result))
-			setsymtab(temp, *av, result, STR|NUM, ARGVtab);
+			setsymtab(temp, *av, result, STR|NUM, ap);
 		else
-			setsymtab(temp, *av, 0.0, STR, ARGVtab);
+			setsymtab(temp, *av, 0.0, STR, ap);
 		av++;
 	}
+	ARGVcell = cp;
 }
 
 void envinit(char **envp)	/* set up ENVIRON variable */
 {
+	Array *ap;
 	Cell *cp;
 	char *p;
 
 	cp = setsymtab("ENVIRON", "", 0.0, ARR, symtab);
-	ENVtab = makesymtab(NSYMTAB);
+	ap = makesymtab(NSYMTAB);
 	free(cp->sval);
-	cp->sval = (char *) ENVtab;
+	cp->sval = (char *) ap;
 	for ( ; *envp; envp++) {
 		double result;
 
@@ -146,9 +148,9 @@ void envinit(char **envp)	/* set up ENVIRON variable */
 			continue;
 		*p++ = 0;	/* split into two strings at = */
 		if (is_number(p, & result))
-			setsymtab(*envp, p, result, STR|NUM, ENVtab);
+			setsymtab(*envp, p, result, STR|NUM, ap);
 		else
-			setsymtab(*envp, p, 0.0, STR, ENVtab);
+			setsymtab(*envp, p, 0.0, STR, ap);
 		p[-1] = '=';	/* restore in case env is passed down to a shell */
 	}
 }
```

