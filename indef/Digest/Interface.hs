module Digest.Interface ( Digest
                        , digest
                        , digestFile
                        , digestSource
                        ) where

import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           System.IO
import           System.IO.Unsafe     (unsafePerformIO)


import           Raaz.Core
import           Digest.Implementation
import           Digest.Utils

-- | The message digest.
type Digest = Prim

-- | Compute the digest of a pure byte source like, `B.ByteString`.
digest :: PureByteSource src
       => src  -- ^ Message
       -> Prim
digest = unsafePerformIO . digestSource
{-# INLINEABLE digest #-}
{-# SPECIALIZE digest :: B.ByteString -> Prim #-}
{-# SPECIALIZE digest :: L.ByteString -> Prim #-}

-- | Compute the digest of file.
digestFile :: FilePath  -- ^ File to be digested
           -> IO Prim
digestFile fileName = withBinaryFile fileName ReadMode digestSource
{-# INLINEABLE digestFile #-}

-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src
             -> IO Prim
{-# SPECIALIZE digestSource :: B.ByteString -> IO Prim #-}
{-# SPECIALIZE digestSource :: L.ByteString -> IO Prim #-}
{-# SPECIALIZE digestSource :: Handle       -> IO Prim #-}

digestSource src = insecurely $ do
  initialise ()
  processByteSource src
  extract
