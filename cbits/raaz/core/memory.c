#include <raaz/core/memory.h>

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
}

void memoryunlock(void* ptr, size_t size){
#ifdef RAAZ_HAVE_mlock
  munlock(ptr,size);
#endif
}
