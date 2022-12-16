/* misc.h - miscellaneous interfaces */

/* SimpleScalar(TM) Tool Suite
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 * All Rights Reserved. 
 * 
 * THIS IS A LEGAL DOCUMENT, BY USING SIMPLESCALAR,
 * YOU ARE AGREEING TO THESE TERMS AND CONDITIONS.
 * 
 * No portion of this work may be used by any commercial entity, or for any
 * commercial purpose, without the prior, written permission of SimpleScalar,
 * LLC (info@simplescalar.com). Nonprofit and noncommercial use is permitted
 * as described below.
 * 
 * 1. SimpleScalar is provided AS IS, with no warranty of any kind, express
 * or implied. The user of the program accepts full responsibility for the
 * application of the program and the use of any results.
 * 
 * 2. Nonprofit and noncommercial use is encouraged. SimpleScalar may be
 * downloaded, compiled, executed, copied, and modified solely for nonprofit,
 * educational, noncommercial research, and noncommercial scholarship
 * purposes provided that this notice in its entirety accompanies all copies.
 * Copies of the modified software can be delivered to persons who use it
 * solely for nonprofit, educational, noncommercial research, and
 * noncommercial scholarship purposes provided that this notice in its
 * entirety accompanies all copies.
 * 
 * 3. ALL COMMERCIAL USE, AND ALL USE BY FOR PROFIT ENTITIES, IS EXPRESSLY
 * PROHIBITED WITHOUT A LICENSE FROM SIMPLESCALAR, LLC (info@simplescalar.com).
 * 
 * 4. No nonprofit user may place any restrictions on the use of this software,
 * including as modified by the user, by any other authorized user.
 * 
 * 5. Noncommercial and nonprofit users may distribute copies of SimpleScalar
 * in compiled or executable form as set forth in Section 2, provided that
 * either: (A) it is accompanied by the corresponding machine-readable source
 * code, or (B) it is accompanied by a written offer, with no time limit, to
 * give anyone a machine-readable copy of the corresponding source code in
 * return for reimbursement of the cost of distribution. This written offer
 * must permit verbatim duplication by anyone, or (C) it is distributed by
 * someone who received only the executable form, and is accompanied by a
 * copy of the written offer of source code.
 * 
 * 6. SimpleScalar was developed by Todd M. Austin, Ph.D. The tool suite is
 * currently maintained by SimpleScalar LLC (info@simplescalar.com). US Mail:
 * 2395 Timbercrest Court, Ann Arbor, MI 48105.
 * 
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 */


#ifndef MISC_H
#define MISC_H

#include <cstdio>
#include <cstdlib>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

//boolean value defs
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

//various useful macros
#ifndef MAX
#define MAX(a, b)		(((a) < (b)) ? (b) : (a))
#endif
#ifndef MIN
#define MIN(a, b)		(((a) < (b)) ? (a) : (b))
#endif

//for printing out "long long" vars
#define LLHIGH(L)		((int)(((L)>>32) & 0xffffffff))
#define LLLOW(L)		((int)((L) & 0xffffffff))

//size of an array, in elements
#define N_ELT(ARR)		(sizeof(ARR)/sizeof((ARR)[0]))

//rounding macros, assumes ALIGN is a power of two
#define ROUND_UP(N,ALIGN)	(((N) + ((ALIGN)-1)) & ~((ALIGN)-1))
#define ROUND_DOWN(N,ALIGN)	((N) & ~((ALIGN)-1))

//verbose output flag
extern int verbose;

#ifdef DEBUG
//active debug flag
extern int debugging;
#endif

//register a fatal hook function to be called when an error is detected
void fatal_hook(void (*hook_fn)(FILE *stream));

#ifdef __GNUC__
//declare a fatal run-time error, calls fatal hook function
#define fatal(fmt, args...)	_fatal(__FILE__, __FUNCTION__, __LINE__, fmt, ## args)

void _fatal(const char *file, const char *func, int line, const char *fmt, ...)
	__attribute__ ((noreturn));
#else
void fatal(const char *fmt, ...);
#endif

#ifdef __GNUC__
//declare a panic situation, dumps core
#define panic(fmt, args...)	_panic(__FILE__, (char *)__FUNCTION__, __LINE__, fmt, ## args)

void _panic(const char *file, const char *func, int line, const char *fmt, ...)
	__attribute__ ((noreturn));
#else
void panic(const char *fmt, ...);
#endif

#ifdef __GNUC__
//declare a warning
#define warn(fmt, args...)	_warn(__FILE__, __FUNCTION__, __LINE__, fmt, ## args)

void _warn(const char *file, const char *func, int line, const char *fmt, ...);
#else
void warn(const char *fmt, ...);
#endif

#ifdef __GNUC__
//print general information
#define info(fmt, args...)	_info(__FILE__, __FUNCTION__, __LINE__, fmt, ## args)

void _info(char *file, const char *func, int line, char *fmt, ...);
#else
void info(char *fmt, ...);
#endif

#ifdef DEBUG

#ifdef __GNUC__
//print a debugging message
#define debug(fmt, args...)							\
	do{									\
		if(debugging)							\
		{								\
			_debug(__FILE__, __FUNCTION__, __LINE__, fmt, ## args);	\
		}								\
	} while(0)								\

void _debug(const char *file, const char *func, int line, const char *fmt, ...);
#else
void debug(const char *fmt, ...);
#endif

#else /* !DEBUG */

#ifdef __GNUC__
#define debug(fmt, args...)
#else
//the optimizer should eliminate this call!
static void debug(char *fmt, ...) {}
#endif

#endif /* !DEBUG */

//seed the random number generator
void mysrand(unsigned int seed);

//get a random number (int)
int myrand(void);

//case insensitive string compare (NOTE: many machines are missing this trivial function, so I funcdup() it here...)
//Returns result of compare (see strcmp())
int mystricmp(const char *s1, const char *s2);

//return log of a number to the base 2
int log_base2(int n);

//return string describing elapsed time, passed in SEC in seconds
const char *elapsed_time(long sec);

//assume bit positions numbered 31 to 0 (31 high order bit), extract num bits from word starting at position pos
//(with pos as the high order bit of those to be extracted), result is right justified and zero filled to high
//order bit, for example, extractl(word, 6, 3) w/ 8 bit word = 01101011 returns 00000110
unsigned int extractl(int word,		//the word from which to extract
	int pos,			//bit positions 31 to 0
	int num);			//number of bits to extract

#if defined(sparc) && !defined(__svr4__)
#define strtoul strtol
#endif

//portable 64-bit I/O package

//portable vsprintf with qword support, returns end pointer
char *myvsprintf(char *obuf, const char *format, va_list v);

//portable sprintf with qword support, returns end pointer
char *mysprintf(char *obuf, const char *format, ...);

//portable vfprintf with qword support, returns end pointer
void myvfprintf(FILE *stream, const char *format, va_list v);

//portable fprintf with qword support, returns end pointer
void myfprintf(FILE *stream, const char *format, ...);

//convert a string to a signed result
sqword_t myatosq(char *nptr, char **endp, int base);

//convert a string to a unsigned result
qword_t myatoq(char *nptr, char **endp, int base);

//same semantics as fopen() except that filenames ending with a ".gz" or ".Z" will be automatically compressed
FILE *gzopen(const char *fname, const char *type);

//close compressed stream
void gzclose(FILE *fd);

//update the CRC on the data block one byte at a time
word_t crc(word_t crc_accum, word_t data);

#endif /* MISC_H */
