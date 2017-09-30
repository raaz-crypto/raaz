{-# LANGUAGE FlexibleContexts #-}
module Common.Cipher where

import Raaz.Core.Transfer
import Common.Imports
import Common.Utils


encryptVsDecrypt :: ( Arbitrary (Key c)
                    , Show (Key c)
                    , Cipher c, Recommendation c
                    )
                 => Proxy c -> Spec
encryptVsDecrypt cProxy = encryptVsDecrypt' cProxy $ recommended cProxy

encryptVsDecrypt' :: ( Arbitrary (Key c)
                     , Show (Key c)
                     , Cipher c
                     )
                     => Proxy c -> Implementation c -> Spec

encryptVsDecrypt' cProxy imp = describe "decrypt . encrypt" $ do
  it "trivial on strings of a length that is a multiple of the block size"
    $ property $ forAll genKeyStr prop_EvsD
  where genKeyStr = (,) <$> arbitrary <*> blocks cProxy
        prop_EvsD (k,bs) = unsafeDecrypt' cProxy imp k (unsafeEncrypt' cProxy imp k bs) == bs

encryptsTo :: (Cipher c, Recommendation c, Format fmt1, Format fmt2)
           => Proxy c
           -> fmt1
           -> fmt2
           -> Key c
           -> Spec

crossCheck :: ( Arbitrary (Key c)
              , Show (Key c)
              , Cipher c
              , Recommendation c
              )
              => Proxy c -> Implementation c -> Spec
crossCheck cProxy impl = describe mesg $ do
  it "encryption" $ property $ forAll genKeyStr prop_Enc
  it "decryption" $ property $ forAll genKeyStr prop_Dec
  where mesg      = unwords ["cross check with ", name reco , "(recommended implementation)" ]
        reco      = recommended cProxy
        genKeyStr = (,) <$> arbitrary <*> blocks cProxy
        prop_Enc (k,bs) = unsafeEncrypt' cProxy reco k bs == unsafeEncrypt' cProxy impl k bs
        prop_Dec (k,bs) = unsafeDecrypt' cProxy reco k bs == unsafeDecrypt' cProxy impl k bs


encryptsTo cProxy = encryptsTo' cProxy $ recommended cProxy

encryptsTo' :: (Cipher c, Format fmt1, Format fmt2)
            => Proxy c
            -> Implementation c
            -> fmt1
            -> fmt2
            -> Key c
            -> Spec
encryptsTo' cProxy imp inp expected key
  = it msg $ result `shouldBe` (decodeFormat expected)
  where result = unsafeEncrypt' cProxy imp key $ decodeFormat inp
        msg   = unwords [ "encrypts"
                        , shortened $ show inp
                        , "to"
                        , shortened $ show expected
                        ]

transformsTo :: (StreamCipher c, Recommendation c, Format fmt1, Format fmt2)
              => Proxy c
              -> fmt1
              -> fmt2
              -> Key c
              -> Spec
transformsTo cProxy = transformsTo' cProxy $ recommended cProxy


keyStreamIs' :: (StreamCipher c, Format fmt)
             => Proxy c
             -> Implementation c
             -> fmt
             -> Key c
             -> Spec
keyStreamIs' cProxy impl expected key = it msg $ result `shouldBe` decodeFormat expected
  where result = transform' cProxy impl key $ zeros $ 1 `blocksOf` cProxy
        msg    = unwords ["with key"
                         , "key stream is"
                         , shortened $ show expected
                         ]

zeros :: Primitive prim => BLOCKS prim -> ByteString
zeros = toByteString . writeZero
  where writeZero :: LengthUnit u => u -> WriteIO
        writeZero = writeBytes 0

transformsTo' :: (StreamCipher c, Format fmt1, Format fmt2)
              => Proxy c
              -> Implementation c
              -> fmt1
              -> fmt2
              -> Key c
              -> Spec

transformsTo' cProxy impl inp expected key
  = it msg $ result `shouldBe` (decodeFormat expected)
  where result = transform' cProxy impl key $ decodeFormat inp
        msg   = unwords [ "encrypts"
                        , shortened $ show inp
                        , "to"
                        , shortened $ show expected
                        ]
