{- |

This module abstracts basic cryptographic primitive operations.

-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE CPP              #-}
module Raaz.Primitives.Symmetric
       ( Auth(..), authTag', verifyTag', authTag, verifyTag
       , Cipher(..)
       , AuthEncrypt(..)
       ) where

import Control.Applicative
import System.IO.Unsafe    (unsafePerformIO)

import Raaz.Primitives
import Raaz.Core.ByteSource
import Raaz.Serialize

-- | This class captures symmetric primitives which support generation
-- of authentication tags. The verification is done by generating the
-- authentication tag using the underlying gadget and then comparing
-- it with the given tag.
class ( Digestible prim
      , CryptoSerialize (Key prim)
      , Digest prim ~ prim
      ) => Auth prim where
  -- | Get context from the Key.
  authCxt :: Key prim  -- ^ Auth Key
          -> Cxt prim  -- ^ Context


-- | Generate authentication tag.
authTag' :: ( PureByteSource src
            , Auth prim
            , PaddableGadget g
            , prim ~ PrimitiveOf g
            )
         => g             -- ^ Type of Gadget
         -> Key prim      -- ^ Key
         -> src           -- ^ Message
         -> prim
authTag' g key src = unsafePerformIO $ withGadget (authCxt key) $ go g
  where go :: (Auth (PrimitiveOf g1), PaddableGadget g1)
            => g1 -> g1 -> IO (Digest (PrimitiveOf g1))
        go _ gad =  do
          transformGadget gad src
          toDigest <$> finalize gad

-- | Verify generated tag
verifyTag' :: ( PureByteSource src
              , Auth prim
              , PaddableGadget g
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
           , Auth prim
           , PaddableGadget (Recommended prim)
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
             , Auth prim
             , PaddableGadget (Recommended prim)
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
class CryptoSerialize (Key prim) => Cipher prim where
  -- | Get context from encryption key.
  cipherCxt :: Key prim -> Cxt prim

-- | This class captures symmetric primitives which support
-- authenticated encryption.
class ( Digestible prim
      , Digest prim ~ prim
      , CryptoSerialize (Key prim)
      ) => AuthEncrypt prim where
  -- | Get context from key.
  authEncryptCxt :: Key prim -> Cxt prim

-- | Helpers for the type checker.
recommended :: prim -> Recommended prim
recommended _ = undefined
