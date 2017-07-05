#include <raaz/core/memory.h>
#ifdef PLATFORM_WINDOWS
#  include <windows.h>
#endif

#ifdef PLATFORM_WINDOWS
typedef BOOL WINAPI (*VirtualFunction)(LPVOID, SIZE_T);
#endif

/* Wipes the entire memory with 0. */
void wipememory ( volatile void* mem, /* volatile is used to keep the
                                      ** compiler from optimising
                                      ** stuff.
                                      ** BIG QUESTION: Is this
                                      ** sufficient?
				      */
		  size_t size
                )
{
    /* WARNING: Potentially dangerous code. Please audit all changes
    ** carefully.
    */
    memset((void *)mem, 0, size);
}

/* Locks and Unlocks Memory */
int memorylock(void* ptr, size_t size){
#ifdef RAAZ_HAVE_mlock
  return mlock(ptr,size);
#endif
#ifdef PLATFORM_WINDOWS
  VirtualFunction func =
     (VirtualFunction)GetProcAddress(GetModuleHandle(TEXT("kernel32")),
				     "VirtualLock");
  return !func(ptr, size);
#endif
}

void memoryunlock(void* ptr, size_t size){
#ifdef RAAZ_HAVE_mlock
  munlock(ptr,size);
#endif
#ifdef PLATFORM_WINDOWS
  VirtualFunction func =
     (VirtualFunction)GetProcAddress(GetModuleHandle (TEXT("kernel32")),
				     "VirtualUnlock");
  func(ptr, size);
#endif
}
