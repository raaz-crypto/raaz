-- | This module exposes the types required to implement the the
-- poly1305 message authenticator. The poly1305 is a function that
-- takes two parameters `r` and `s` and for an input message `m`
-- computes the function.
--
-- Poly1305(m, r,s) = (M(r) mod 2^130 - 5) + s mod 2^128
--
--  In the original publication, `r` is selected pseudo-randomly and
-- `s` is generated by encrypting (using AES) a nonce `n` with a
-- secret key k, i.e. r = random; s = AES(k,n).  The secret that needs
-- to be shared by the two parties is `r` and the key `k`. Actual
-- protocols should never repeat the nonce `n` for otherwise there
-- will be compromise in the security.  The RFC7539 uses a variant
-- that uses the chacha20 cipher instead of AES.

-- As can be seen from the above discussion the actual mechanism for
-- selecting the `r` and `s` differs depending on the
-- situation. Hence, this module only provide the "raw" Poly1305
-- implementation leaving out the details of the selection of `r` and
-- `s` for some latter stage. Thus this module is not of direct use
-- but is used by actual protocols to implement message
-- authentication.

{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
module Raaz.Primitive.Poly1305.Internal
       ( Poly1305(..), R(..), S(..)
       ) where

import Data.String
import Data.Word
import Foreign.Storable( Storable )
import Raaz.Core


type WORD = Tuple 2 (LE Word64)

-- | The datatype that captures the Poly1305 authenticator tag.
newtype Poly1305 = Poly1305 WORD deriving (Storable, EndianStore, Equality, Eq)

-- | The `r` component of the secret.
newtype R        = R WORD deriving (Storable, EndianStore, Equality, Eq)

-- | The `s` component of the secret.
newtype S        = S WORD deriving (Storable, EndianStore, Equality, Eq)

instance Encodable Poly1305
instance Encodable R
instance Encodable S

instance IsString Poly1305 where
  fromString = fromBase16

instance IsString R where
  fromString = fromBase16

instance IsString S where
  fromString = fromBase16

instance Show Poly1305 where
  show = showBase16

instance Show R where
  show = showBase16

instance Show S where
  show = showBase16

instance Primitive Poly1305 where
  type BlockSize Poly1305      = 16
  type Key Poly1305            = (R, S)
  type Digest Poly1305         = Poly1305