{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Version 1 of the interface.
module Raaz.V1 ( Digest
               , digest, digestFile, digestSource
               ) where

import           Data.String      ( IsString (..) )
import           Foreign.Storable ( Storable )

import           Raaz.Core
import qualified Raaz.Blake2b    as B2b


newtype Digest = Digest B2b.Blake2b deriving ( Equality
                                             , Eq
                                             , Storable
                                             , EndianStore
                                             , Encodable
                                             )

instance Show Digest where
  show (Digest dst) = show dst

instance IsString Digest where
  fromString = Digest . fromString



-- | Compute the digest of a pure byte source like, `B.ByteString`.
digest :: PureByteSource src
       => src              -- ^ Message
       -> Digest
digest = Digest . B2b.digest

-- | Compute the digest of file.
digestFile :: FilePath     -- ^ File to be digested
           -> IO Digest
digestFile = fmap Digest . B2b.digestFile

-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src        -- ^ The source whose digest needs to be
                           -- computed.
             -> IO Digest
digestSource = fmap Digest . B2b.digestSource
