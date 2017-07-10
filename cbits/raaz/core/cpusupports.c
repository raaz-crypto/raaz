/*

This module exposes runtime checks for cpu flags. Works only with GCC.

 */

# ifdef __GNUC__
# define SUPPORTS(x) { __builtin_cpu_init(); return __builtin_cpu_supports((x)); }
# else
# define SUPPORTS(x) { return 0; }
# endif


# pragma GCC push_options
# pragma GCC optimize ("O0")

int raaz_supports_sse(){ SUPPORTS("sse");}
int raaz_supports_sse2(){ SUPPORTS("sse2");}
int raaz_supports_sse3(){ SUPPORTS("sse3");}
int raaz_supports_sse4_1(){ SUPPORTS("sse4.1");}
int raaz_supports_sse4_2(){ SUPPORTS("sse4.2");}
int raaz_supports_avx()   { SUPPORTS("avx");}
int raaz_supports_avx2(){ SUPPORTS("avx2");}

# pragma GCC pop_options
