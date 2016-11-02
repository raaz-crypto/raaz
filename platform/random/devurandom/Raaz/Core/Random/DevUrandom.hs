
-- | This module exposes the system wide prng available through the file `/dev/urandom`.
module Raaz.Core.Random.DevUrandom
       ( DevUrandomPRG, newDevUrandomPRG
       ) where

import Control.Monad   (void)
import System.IO       ( openBinaryFile, Handle, IOMode(ReadMode)
                       , BufferMode(NoBuffering), hSetBuffering
                       )

import Raaz.Core.Types
import Raaz.Core.Random.PRG

-- | The psrg works on posix systems which often come with a `/dev/urandom`.
-- Filling the buffer is done by reading from the file
-- `/dev/urandom`. Although the quality of random bytes generated is
-- the best that you can get, there are some inherent problems
-- associated with reading from `/dev/urandom` which we list below.
--
-- 1. It uses up one extra file descriptor for each opening of the source.
--    This can be bad.

-- 2. The read call might get interrupted in which case we cannot
--    expect that the buffer will be fully overwritten. This can lead to
--    some predictability in the source.
--
-- 3. The prg might be slow because of system call overhead associated with read.
--
-- For this reason, raaz prefers using other system sources like
-- `arc4random` on OpenBSD if it is available.
newtype DevUrandomPRG = DevUrandomPRG Handle deriving Show

-- | Get a new instance of the system PRG.
newDevUrandomPRG :: IO DevUrandomPRG
newDevUrandomPRG = do h <- openBinaryFile "/dev/urandom" ReadMode
                      hSetBuffering h NoBuffering
                      return $ DevUrandomPRG h

instance PRG DevUrandomPRG where
  fillRandomBytes sz ptr (DevUrandomPRG hand) = void $ hFillBuf hand ptr sz
