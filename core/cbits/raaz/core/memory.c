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

#ifdef PLATFORM_WINDOWS
void raazWindowsSecureZeroMemory(void * ptr, size_t size)
{
    VirtualFunction func =
	(VirtualFunction)GetProcAddress(GetModuleHandle(TEXT("kernel32")),
					"SecureZeroMemory");
    func(ptr, size);
}
#endif
