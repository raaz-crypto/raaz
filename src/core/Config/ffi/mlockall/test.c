#include <sys/mman.h>

int lockall()
{
    return mlockall(MCL_CURRENT);
}

int lockallfuture()
{
    return mlockall(MCL_FUTURE);
}

int unlockall()
{
    return munlockall();
}
