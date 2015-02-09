#include <raaz/core/memory.h>


/* Make this unbuffered and handle case when line is more that len */
char * getLine(char* line, size_t len){
  getline(&line, &len, stdin);
  return line;
}

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

/* Creates the page aligned memory */
void * createpool(size_t size){
#ifdef RAAZ_HAVE_memalign
  void *o;
  posix_memalign(&o,getpagesize(),size);
  return o;
#endif
}

void freepool (void* ptr, size_t size){
#ifdef RAAZ_HAVE_memalign
  free(ptr);
#endif
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
