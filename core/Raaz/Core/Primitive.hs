{-|

Generic cryptographic block primtives and their implementations. This
module exposes low-level generic code used in the raaz system. Most
likely, one would not need to stoop so low and it might be better to
use a more high level interface.

-}

{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE FlexibleContexts            #-}
{-# LANGUAGE DataKinds                   #-}

module Raaz.Core.Primitive
       ( -- * Cryptographic Primtives
         Primitive(..), Key
       ) where

import GHC.TypeLits

----------------------- A primitive ------------------------------------


-- | The type class that captures an abstract block cryptographic
-- primitive.
class KnownNat (BlockSize p) => Primitive p where

  -- | Bulk cryptographic primitives like hashes, ciphers etc often
  -- acts on blocks of data. The size of the block is captured by the
  -- associated type `BlockSize`.
  type BlockSize p :: Nat

  -- | The key associated with primitive. In the setting of the raaz
  -- library keys are "inputs" that are required to start processing.
  -- Often primitives like ciphers have a /secret key/ together with
  -- an additional nounce/IV. This type denotes not just the secret
  -- key par but the nounce too.
  --

-- The type family that captures the key of a keyed primitive.
type family Key p :: *

