{- |

This module abstracts basic cryptographic primitive operations.

-}
{-# LANGUAGE DataKinds                 #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE CPP                       #-}
{-# LANGUAGE RankNTypes #-}
module Raaz.Core.Primitives.Asymmetric
       ( Sign
       , sign, sign', verify, verify'
       ) where

import System.IO.Unsafe

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.ByteSource

-- | This class captures primitives which support generation of
-- authenticated signatures and its verification. This is assymetric
-- version of `Auth`.
class ( Primitive (prim SignMode)
      , Primitive (prim VerifyMode)
      ) => Sign prim

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
sign' g key src = unsafePerformIO $ withGadget key $ go g
  where go :: ( Sign prim
              , PaddableGadget g1
              , FinalizableMemory (MemoryOf g1)
              , prim SignMode ~ PrimitiveOf g1
              )
           => g1 -> g1 -> IO (FV (MemoryOf g1))
        go _ gad =  do
          transformGadget gad src
          finalize gad

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
           , Key prim ~ (k, p SignMode)
           )
           => g             -- ^ Type of Gadget
           -> k             -- ^ Key
           -> p SignMode
           -> src           -- ^ Message
           -> Bool
verify' g key sig src = unsafePerformIO $ withGadget (key,sig) $ go g
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
          , Key prim ~ (k, p SignMode)
          )
          => k
          -> p SignMode
          -> src           -- ^ Message
          -> Bool
verify k sig = verify' (recommended sig) k sig
  where
    recommended :: p SignMode -> Recommended (p VerifyMode)
    recommended _ = undefined
