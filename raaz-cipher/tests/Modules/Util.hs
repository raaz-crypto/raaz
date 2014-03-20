{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies      #-}

module Modules.Util where

import           Data.ByteString  (ByteString)
import qualified Data.ByteString  as BS
import           Test.Framework   (Test)

import           Raaz.Primitives
import           Raaz.Test.Gadget

cportableVsReference :: ( HasInverse g1
                        , HasInverse g2
                        , (PrimitiveOf g1 ~ PrimitiveOf g2)
                        , (PrimitiveOf (Inverse g1) ~ PrimitiveOf (Inverse g2))
                        , Initializable (PrimitiveOf g1)
                        , Initializable (PrimitiveOf (Inverse g1))
                        , Eq (Cxt (PrimitiveOf g1))
                        , Eq (Cxt (PrimitiveOf (Inverse g1))))
                     => g1 -> g2 -> ByteString -> [Test]
cportableVsReference ge1 ge2 iv' =
  [ testGadget ge1 ge2 (getCxt iv) "CPortable vs Reference Encryption"
  , testGadget (inverseGadget ge1) (inverseGadget ge2) (getCxt iv) "CPortable vs Reference Decryption"]
  where
    iv = BS.take (fromIntegral $ cxtSize $ primitiveOf ge1) iv'
