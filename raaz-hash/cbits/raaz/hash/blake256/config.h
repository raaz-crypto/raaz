/* Auto generated stuff (do not edit) */
# ifndef __RAAZ_PRIMITIVES_CONF_H__
# define __RAAZ_PRIMITIVES_CONF_H__ 

/* System parameters guessed by Config.hs */
/* Cache parameters */
# define RAAZ_L1_CACHE 32768
# define RAAZ_L2_CACHE 262144
/* End of Cache parameters */

/* Page Size parameters */
# define RAAZ_PAGE_SIZE 4096
/* End of Page Size parameters */

/* Mark all FFI functions unavailable */
# undef RAAZ_HAVE_htole32
# undef RAAZ_HAVE_htole64
# undef RAAZ_HAVE_htobe32
# undef RAAZ_HAVE_htobe64
# undef RAAZ_HAVE_mlock
# undef RAAZ_HAVE_mlockall
# undef RAAZ_HAVE_memalign
/* End of Mark all FFI functions unavailable */

/* Selectively enable the available ones. */
# define RAAZ_HAVE_htole32 
# define RAAZ_HAVE_htole64 
# define RAAZ_HAVE_htobe32 
# define RAAZ_HAVE_htobe64 
# define RAAZ_HAVE_mlock 
# define RAAZ_HAVE_memalign 
/* End of Selectively enable the available ones. */


# endif /* __RAAZ_PRIMITIVES_CONF_H__ */
