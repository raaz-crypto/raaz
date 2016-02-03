{-|

This module exposes the high quality cryptographic pseudo-random
generator exposed by the system.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
module Raaz.System.Random
       ( SystemPRG
       ) where

import System.IO (openBinaryFile, Handle, IOMode(ReadMode)
                 , BufferMode(NoBuffering), hSetBuffering
                 )

import Raaz.Core.ByteSource (ByteSource)
import Raaz.Core.Random     (PRG(..))


-- | The system wide pseudo-random generator. Many systems provide
-- high quality pseudo-random generator within the system like for
-- example the @\/dev\/urandom@ file on a posix system. This type
-- captures such a pseudo-random generator. The source is expected to
-- be of high quality, albeit a bit slow due to system call overheads.
-- You do not need to seed this PRG and hence the associated type
-- @`Seed` `SystemPRG`@ is the unit type @()@.
newtype SystemPRG = SystemPRG Handle

instance InfiniteSource SystemPRG where
  slurpBytes sz sprg@(SystemPRG hand) cptr = hFillBuf hand cptr sz >> return sprg


instance PRG SystemPRG where
  type Seed SystemPRG = ()

  newPRG _ = do h <- openBinaryFile "/dev/urandom" ReadMode
                hSetBuffering h NoBuffering
                return $ SystemPRG h
  reseed _ _ = return ()
