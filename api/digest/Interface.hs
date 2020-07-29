-- |
--
-- Module      : digest-api: Interface
-- Description : Generic interface to message digest.
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Interface ( Digest
                 , digest
                 , digestFile
                 , digestSource
                 , name
                 , description
                 ) where

import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           System.IO.Unsafe     (unsafePerformIO)


import           Raaz.Core
import qualified Implementation
import           Utils

type Digest = Implementation.Prim

-- | Compute the digest of a pure byte source like, `B.ByteString`.
digest :: PureByteSource src
       => src  -- ^ Message
       -> Digest
digest = unsafePerformIO . digestSource
{-# INLINEABLE digest #-}
{-# SPECIALIZE digest :: B.ByteString -> Digest #-}
{-# SPECIALIZE digest :: L.ByteString -> Digest #-}

-- | Compute the digest of file.
digestFile :: FilePath  -- ^ File to be digested
           -> IO Digest
digestFile fileName = withBinaryFile fileName ReadMode digestSource
{-# INLINEABLE digestFile #-}

-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src
             -> IO Digest
{-# SPECIALIZE digestSource :: B.ByteString -> IO Digest #-}
{-# SPECIALIZE digestSource :: L.ByteString -> IO Digest #-}
{-# SPECIALIZE digestSource :: Handle       -> IO Digest #-}

digestSource src = withMemory $ \ mem -> do
  initialise () mem
  processByteSource src mem
  extract mem

-- | Textual name of the digest implementation.
name :: String
name = Implementation.name

-- | Description of the implementation
description :: String
description = Implementation.description
