/*

This module exposes runtime checks for cpu flags. Works only with GCC.

 */


# define GCC_VERSION (__GNUC__ * 10 + __GNUC_MINOR__)

/* Check an x86_64 feature */

# ifdef ARCH_X86_64
#     define X86_64_SUPPORTS(x) { __builtin_cpu_init(); return __builtin_cpu_supports((x)); }
# else
#     define X86_64_SUPPORTS(x) { return 0; }
# endif

# if GCC_VERSION >= 48 && !defined(__clang__)
# pragma GCC push_options
# pragma GCC optimize ("O0")

int raaz_supports_sse()   { X86_64_SUPPORTS("sse");     }
int raaz_supports_sse2()  { X86_64_SUPPORTS("sse2");    }
int raaz_supports_sse3()  { X86_64_SUPPORTS("sse3");    }
int raaz_supports_sse4_1(){ X86_64_SUPPORTS("sse4.1");  }
int raaz_supports_sse4_2(){ X86_64_SUPPORTS("sse4.2");  }
int raaz_supports_avx()   { X86_64_SUPPORTS("avx");     }
int raaz_supports_avx2()  { X86_64_SUPPORTS("avx2");    }

# pragma GCC pop_options

# else

int raaz_supports_sse()   { return 0;}
int raaz_supports_sse2()  { return 0;}
int raaz_supports_sse3()  { return 0;}
int raaz_supports_sse4_1(){ return 0;}
int raaz_supports_sse4_2(){ return 0;}
int raaz_supports_avx()   { return 0;}
int raaz_supports_avx2()  { return 0;}

#endif
