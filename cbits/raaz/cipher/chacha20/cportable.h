#pragma once
#include "common.h"
extern void raazChaCha20Block(Block *msg, int nblocks, Key key, IV iv, Counter *ctr);
