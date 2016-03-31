#pragma once

extern void raazAESCBCEncryptCPortable(
    Block *inp, int nBlocks,
    int nRounds, RMatrix *eKey,
    RMatrix iv);

extern void raazAESCBCDecryptCPortable(
    Block *inp, int nBlocks,
    int nRounds, RMatrix *eKey,
    RMatrix iv);
