
# ifdef PLATFORM_WINDOWS
# include <windows.h>

   typedef BOOL WINAPI (*VirtualFunction)(LPVOID, SIZE_T);

#else /* we assume posix system */

#  include <sys/mman.h>

#endif

/* Locks and Unlocks Memory */
int raazMemorylock(void* ptr, size_t size){
#ifdef PLATFORM_WINDOWS
  VirtualFunction func =
     (VirtualFunction)GetProcAddress(GetModuleHandle(TEXT("kernel32")),
				     "VirtualLock");
  return !func(ptr, size);
#else
    return mlock(ptr,size);
#endif

}

void raazMemoryunlock(void* ptr, size_t size){
#ifdef PLATFORM_WINDOWS
  VirtualFunction func =
     (VirtualFunction)GetProcAddress(GetModuleHandle (TEXT("kernel32")),
				     "VirtualUnlock");
  func(ptr, size);
#else  /* posix */
    munlock(ptr,size);
#endif
}

#if defined(HAVE_EXPLICIT_BZERO) || defined(HAVE_EXPLICIT_MEMSET)
#include <strings.h>
#endif

void raazWipeMemory(void * ptr, size_t size)
{
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(ptr,size);
#elif  HAVE_EXPLICIT_MEMSET
    explicit_memset(ptr,0,size);
#elif HAVE_SECURE_ZERO_MEMORY
    VirtualFunction func =
	(VirtualFunction)GetProcAddress(GetModuleHandle(TEXT("kernel32")),
					"SecureZeroMemory");
    func(ptr, size);
#else
#waring "Using memset for wiping memory, the compiler might optimise it away"
    memset(ptr,0,size);
#endif
}
