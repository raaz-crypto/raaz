{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies      #-}

module Modules.Util where

import Test.Framework              ( Test, testGroup )

import Raaz.Core
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Test.Gadget

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
                        , Eq (Key p)
                        )
                     => g1 -> g2 -> Key p -> Test
cportableVsReference g1 g2 iv = testGroup ""
  [ testGadget g1 g2 iv
  , testGadget (inverse g1) (inverse g2) iv ]
