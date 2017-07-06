# ifdef PLATFORM_WINDOWS
# include <windows.h>

   typedef BOOL WINAPI (*VirtualFunction)(LPVOID, SIZE_T);

#else /* we assume posix system */

#  include <sys/mman.h>

#endif

/* Locks and Unlocks Memory */
int memorylock(void* ptr, size_t size){
#ifdef PLATFORM_WINDOWS
  VirtualFunction func =
     (VirtualFunction)GetProcAddress(GetModuleHandle(TEXT("kernel32")),
				     "VirtualLock");
  return !func(ptr, size);
#else
    return mlock(ptr,size);
#endif

}

void memoryunlock(void* ptr, size_t size){
#ifdef PLATFORM_WINDOWS
  VirtualFunction func =
     (VirtualFunction)GetProcAddress(GetModuleHandle (TEXT("kernel32")),
				     "VirtualUnlock");
  func(ptr, size);
#else  /* posix */
    munlock(ptr,size);
#endif
}
