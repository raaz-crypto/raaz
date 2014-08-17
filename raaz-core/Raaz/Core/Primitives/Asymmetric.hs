{- |

This module abstracts basic cryptographic primitive operations.

-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE CPP              #-}
module Raaz.Core.Primitives.Asymmetric
       ( Sign(..)
       , sign, sign', verify, verify'
       ) where

import Control.Applicative
import System.IO.Unsafe

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.ByteSource
import Raaz.Core.Serialize

-- | This class captures primitives which support generation of
-- authenticated signatures and its verification. This is assymetric
-- version of `Auth`.
class Sign prim where
  -- | Get `SignMode` context from the Key.
  signCxt :: prim SignMode       -- ^ To satisfy types
          -> Key (prim SignMode) -- ^ Auth Key
          -> Cxt (prim SignMode) -- ^ Context

  -- | Get `VerifyMode` context from Key and signature.
  verifyCxt :: Key (prim VerifyMode)  -- ^ Verify key
            -> prim SignMode          -- ^ Signature
            -> Cxt (prim VerifyMode)  -- ^ Context


-- | Generate Signature.
sign' :: ( PureByteSource src
         , Sign p
         , FinalizableMemory (MemoryOf g)
         , FV (MemoryOf g) ~ prim
         , prim ~ p SignMode
         , PaddableGadget g
         , prim ~ PrimitiveOf g
         )
      => g             -- ^ Type of Gadget
      -> Key prim      -- ^ Key
      -> src           -- ^ Message
      -> prim
sign' g key src = unsafePerformIO $ withGadget (signCxt p key) $ go g
  where go :: ( Sign prim
              , PaddableGadget g1
              , FinalizableMemory (MemoryOf g1)
              , prim SignMode ~ PrimitiveOf g1
              )
           => g1 -> g1 -> IO (FV (MemoryOf g1))
        go _ gad =  do
          transformGadget gad src
          finalize gad

        p = primitiveOf g

-- | Generate signature using recommended gadget.
sign :: ( PureByteSource src
        , Sign p
        , g ~ Recommended prim
        , FinalizableMemory (MemoryOf g)
        , FV (MemoryOf g) ~ prim
        , prim ~ p SignMode
        , PaddableGadget g
        , CryptoPrimitive prim
        )
        => Key prim      -- ^ Key
        -> src           -- ^ Message
        -> prim
sign key src = sig
  where
    sig = sign' (recommended sig) key src
    recommended :: prim -> Recommended prim
    recommended _ = undefined

-- | Verify Signature.
verify' :: ( PureByteSource src
           , Sign p
           , FinalizableMemory (MemoryOf g)
           , FV (MemoryOf g) ~ Bool
           , prim ~ p VerifyMode
           , PaddableGadget g
           , prim ~ PrimitiveOf g
           )
           => g             -- ^ Type of Gadget
           -> Key prim      -- ^ Key
           -> src           -- ^ Message
           -> p SignMode
           -> Bool
verify' g key src p  = unsafePerformIO $ withGadget (verifyCxt key p) $ go g
  where go :: ( Sign prim
              , PaddableGadget g1
              , FinalizableMemory (MemoryOf g1)
              , prim VerifyMode ~ PrimitiveOf g1
              )
           => g1 -> g1 -> IO (FV (MemoryOf g1))
        go _ gad =  do
          transformGadget gad src
          finalize gad

-- | Verify tag using recommended gadget.
verify :: ( PureByteSource src
          , Sign p
          , g ~ Recommended prim
          , FinalizableMemory (MemoryOf g)
          , FV (MemoryOf g) ~ Bool
          , prim ~ p VerifyMode
          , PaddableGadget g
          , CryptoPrimitive prim
          , prim ~ PrimitiveOf g
          )
          => Key prim      -- ^ Key
          -> src           -- ^ Message
          -> p SignMode
          -> Bool
verify key src prim = verify' (recommended prim) key src prim
  where
    recommended :: p SignMode -> Recommended (p VerifyMode)
    recommended _ = undefined
