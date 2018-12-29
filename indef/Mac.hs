{-|

This module exposes all the cryptographic hash functions available
under the raaz library.

-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances    #-}

module Mac
       (
         -- * Cryptographic Message Authentication codes.
         -- $computingHash$

         -- ** Encoding and displaying.
         -- $encoding$
         --
         Mac, mac, macFile, macSource
       , Poly1305
       ) where


import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           System.IO
import           System.IO.Unsafe     (unsafePerformIO)


import           Raaz.Core
import           Raaz.Primitive.Poly1305.Internal (Poly1305)
import           Poly1305.Implementation          ( clamp  )
import qualified Poly1305.Utils        as Poly1305U


-- $computingHash$
--
--
-- The cryptographic message authenticators (MAC) provided by raaz
-- give the following guarantees:
--
-- 1. Distinct macs are represented distinct types and hence it is a compiler
--    error to compare two different macs.
--
-- 2. The `Eq` instance for macs use a constant time equality test
--    and hence it is safe to check equality using the operator `==`.
--
-- 3. For certain macs (like Poly1305 for example), the integrity is
--    compromised if the key is reused. It is therefore necessary to
--    make sure that distinct messages have distinct keys. Also do not
--    use this interface directly. Mac's like Poly1305 are generally
--    used in conjunction with other protocol dependent encrypting or
--    AEAD modes. 
--
-- The functions `mac`, `macFile`, and `macSource` provide a rather
-- high level interface for computing macs.

-- $encoding$
--
-- When interfacing with other applications or when printing output to
-- users, it is often necessary to encode macs as
-- strings. Applications usually present macs encoded in base16. The
-- `Show` and `Data.String.IsString` instances for the macs exposed
-- here follow this convention.
--
-- More generally macs are instances of type class
-- `Raaz.Core.Encode.Encodable` and can hence can be encoded in any of
-- the formats supported in raaz.


-- | The class that captures all cryptographic hashes.
class (Primitive mac, Digest mac ~ mac, Equality mac, Eq mac) => Mac mac where
  -- | Computes the cryptographic hash of a given byte source.
  macSource  :: ByteSource src => Key mac -> src -> IO mac


-- | Compute the hash of a pure byte source like, `B.ByteString`.
mac :: ( Mac mac, PureByteSource src )
     => Key mac
     -> src  -- ^ Message
     -> mac
mac key = unsafePerformIO . macSource key
{-# INLINEABLE mac #-}
{-# SPECIALIZE mac :: Mac mac => Key mac -> B.ByteString -> mac #-}
{-# SPECIALIZE mac :: Mac mac => Key mac -> L.ByteString -> mac #-}

-- | Compute the mac of file.
macFile :: Mac mac
        => Key mac
        -> FilePath  -- ^ File to be maced
        -> IO mac
macFile key fileName = withBinaryFile fileName ReadMode $ macSource key
{-# INLINEABLE macFile #-}

instance Mac Poly1305 where
  macSource key src = insecurely $ do initialise key
                                      clamp
                                      Poly1305U.processByteSource src
                                      extract
