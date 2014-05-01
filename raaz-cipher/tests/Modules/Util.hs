{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies      #-}

module Modules.Util where

import Data.ByteString  (ByteString)
import Test.Framework   (Test, testGroup)

import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Serialize
import Raaz.Test.Gadget

cportableVsReference :: ( HasName g1
                        , HasName (Inverse g1)
                        , HasName g2
                        , HasName (Inverse g2)
                        , CryptoInverse g1
                        , CryptoInverse g2
                        , PrimitiveOf g1 ~ PrimitiveOf g2
                        , PrimitiveOf (Inverse g1) ~ PrimitiveOf (Inverse g2)
                        , Cipher p
                        , p ~ PrimitiveOf g1
                        , p ~ PrimitiveOf (Inverse g1)
                        , Eq (Cxt p)
                        )
                     => g1 -> g2 -> ByteString -> Test
cportableVsReference g1 g2 iv = testGroup ""
  [ testGadget g1 g2 cxt
  , testGadget (inverse g1) (inverse g2) cxt ]
  where
    cxt = cipherCxt $ fromByteString iv
