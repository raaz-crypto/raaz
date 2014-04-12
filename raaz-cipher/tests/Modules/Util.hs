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
                        , HasName g1'
                        , HasName g2
                        , HasName g2'
                        , Gadget g1, Gadget g1'
                        , Gadget g2, Gadget g2'
                        , PrimitiveOf g1 ~ PrimitiveOf g2
                        , PrimitiveOf g1' ~ PrimitiveOf g2'
                        , Encrypt p
                        , p EncryptMode ~ PrimitiveOf g1
                        , p DecryptMode ~ PrimitiveOf g1'
                        , Eq (Cxt (PrimitiveOf g1))
                        , Eq (Cxt (PrimitiveOf g1'))
                        )
                     => g1 -> g1' -> g2 -> g2' -> ByteString -> Test
cportableVsReference g1 g1' g2 g2' iv = testGroup ""
  [ testGadget g1 g2 (encryptCxt $ fromByteString iv)
  , testGadget g1' g2' (decryptCxt $ fromByteString iv) ]
