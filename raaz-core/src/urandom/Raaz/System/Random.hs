{-|

This module exposes the @/dev/urandom@ device as a PRG for the raaz
libraries.

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
-- example the @/dev/random@ file on a posix system. This type
-- captures such a pseudo-random generator. The source is expected to
-- be of high quality, albeit a bit slow due to system call overheads.
newtype SystemPRG = SystemPRG Handle deriving ByteSource

instance PRG SystemPRG where
  type Seed SystemPRG = ()

  newPRG _ = do h <- openBinaryFile "/dev/urandom" ReadMode
                hSetBuffering h NoBuffering
                return $ SystemPRG h
  reseed _ _ = return ()
