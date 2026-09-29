#ifndef SPX_BUILTIN_PROFILE_H
#define SPX_BUILTIN_PROFILE_H
#if defined(_WIN32) && !defined(WIN32)
#define WIN32 1
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
/* Match the pinned PE32 feature selection, including unavailable math calls. */
#define USE_DECNUM 1
#define HAVE_LIBONIG 1
#define HAVE_STRFTIME 1
#define HAVE_GMTIME 1
#define HAVE_LOCALTIME 1
#define HAVE_GETTIMEOFDAY 1
#ifndef _WIN32
#define HAVE_TIMEGM 1
#endif
#define HAVE_ACOS 1
#define HAVE_ACOSH 1
#define HAVE_ASIN 1
#define HAVE_ASINH 1
#define HAVE_ATAN 1
#define HAVE_ATAN2 1
#define HAVE_ATANH 1
#define HAVE_CBRT 1
#define HAVE_CEIL 1
#define HAVE_COPYSIGN 1
#define HAVE_COS 1
#define HAVE_COSH 1
#define HAVE_ERF 1
#define HAVE_ERFC 1
#define HAVE_EXP 1
#define HAVE_EXP2 1
#define HAVE_EXPM1 1
#define HAVE_FABS 1
#define HAVE_FDIM 1
#define HAVE_FLOOR 1
#define HAVE_FMA 1
#define HAVE_FMAX 1
#define HAVE_FMIN 1
#define HAVE_FMOD 1
#define HAVE_FREXP 1
#define HAVE_HYPOT 1
#define HAVE_J0 1
#define HAVE_J1 1
#define HAVE_JN 1
#define HAVE_LDEXP 1
#define HAVE_LGAMMA 1
#define HAVE_LOG 1
#define HAVE_LOG10 1
#define HAVE_LOG1P 1
#define HAVE_LOG2 1
#define HAVE_LOGB 1
#define HAVE_MODF 1
#define HAVE_NEARBYINT 1
#define HAVE_NEXTAFTER 1
#define HAVE_NEXTTOWARD 1
#define HAVE_POW 1
#define HAVE_REMAINDER 1
#define HAVE_RINT 1
#define HAVE_ROUND 1
#define HAVE_SCALBLN 1
#define HAVE_SIN 1
#define HAVE_SINH 1
#define HAVE_SQRT 1
#define HAVE_TAN 1
#define HAVE_TANH 1
#define HAVE_TGAMMA 1
#define HAVE_TRUNC 1
#define HAVE_Y0 1
#define HAVE_Y1 1
#define HAVE_YN 1
#endif
