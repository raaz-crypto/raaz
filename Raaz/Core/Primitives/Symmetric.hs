{- |

This module abstracts basic cryptographic primitive operations.

-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE CPP              #-}
module Raaz.Core.Primitives.Symmetric
       ( Auth, authTag', verifyTag', authTag, verifyTag
       , Cipher
       , AuthEncrypt
       ) where

import System.IO.Unsafe    (unsafePerformIO)

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.ByteSource

-- | This class captures symmetric primitives which support generation
-- of authentication tags. The verification is done by generating the
-- authentication tag using the underlying gadget and then comparing
class Auth prim

-- | Generate authentication tag.
authTag' :: ( PureByteSource src
            , Auth prim
            , FinalizableMemory g
            , PaddableGadget g
            , FV g ~ prim, prim ~ PrimitiveOf g
            )
         => g             -- ^ Type of Gadget
         -> Key prim      -- ^ Key
         -> src           -- ^ Message
         -> prim
authTag' g key src = unsafePerformIO $ withGadget key $ go g
  where go :: ( Auth (PrimitiveOf g1)
              , PaddableGadget g1
              , FinalizableMemory g1
              )
           => g1 -> g1 -> IO (FV g1)
        go _ gad = transformGadget gad src >> finalizeMemory gad

-- | Verify generated tag
verifyTag' :: ( PureByteSource src
              , FinalizableMemory g
              , FV g ~ prim
              , PaddableGadget g
              , Auth prim
              , prim ~ PrimitiveOf g
              , Eq prim
              )
           => g             -- ^ Type of Gadget
           -> Key prim      -- ^ Key
           -> src           -- ^ Message
           -> prim
           -> Bool
verifyTag' g key src tag = authTag' g key src == tag

-- | Generate Authentication tag using recommended gadget.
authTag :: ( PureByteSource src
           , g ~ Recommended prim
           , FinalizableMemory g
           , FV g ~ prim
           , Auth prim
           , PaddableGadget g
           , CryptoPrimitive prim
           )
        => Key prim      -- ^ Key
        -> src           -- ^ Message
        -> prim
authTag key src = tag
  where
    tag = authTag' (recommended tag) key src

-- | Verify tag using recommended gadget.
verifyTag :: ( PureByteSource src
             , g ~ Recommended prim
             , FinalizableMemory g
             , FV g ~ prim
             , Auth prim
             , PaddableGadget g
             , CryptoPrimitive prim
             , Eq prim
             )
          => Key prim      -- ^ Key
          -> src           -- ^ Message
          -> prim
          -> Bool
verifyTag key src prim = verifyTag' (recommended prim) key src prim

-- | This class captures symmetric primitives which support
-- encryption (also called ciphers).
class Cipher prim

-- | This class captures symmetric primitives which support
-- authenticated encryption.
class AuthEncrypt prim

-- | Helpers for the type checker.
recommended :: prim -> Recommended prim
recommended _ = undefined
