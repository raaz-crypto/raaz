{-# LANGUAGE FlexibleContexts #-}
module Common.Cipher where

import Raaz.Core.Transfer
import Common.Imports
import Common.Utils


encryptVsDecrypt :: ( Arbitrary (Key c)
                    , Show (Key c)
                    , Cipher c, Recommendation c
                    )
                 => c -> Spec
encryptVsDecrypt c = encryptVsDecrypt' c $ recommended c

encryptVsDecrypt' :: ( Arbitrary (Key c)
                     , Show (Key c)
                     , Cipher c
                     )
                     => c -> Implementation c -> Spec

encryptVsDecrypt' c imp = describe "decrypt . encrypt" $ do
  it "trivial on strings of a length that is a multiple of the block size"
    $ property $ forAll genKeyStr prop_EvsD
  where genKeyStr = (,) <$> arbitrary <*> blocks c
        prop_EvsD (k,bs) = unsafeDecrypt' c imp k (unsafeEncrypt' c imp k bs) == bs

encryptsTo :: (Cipher c, Recommendation c, Format fmt1, Format fmt2)
           => c
           -> fmt1
           -> fmt2
           -> Key c
           -> Spec

crossCheck :: ( Arbitrary (Key c)
              , Show (Key c)
              , Cipher c
              , Recommendation c
              )
              => c -> Implementation c -> Spec
crossCheck c impl = describe mesg $ do
  it "encryption" $ property $ forAll genKeyStr prop_Enc
  it "decryption" $ property $ forAll genKeyStr prop_Dec
  where mesg      = unwords ["cross check with ", name reco , "(recommended implementation)" ]
        reco      = recommended c
        genKeyStr = (,) <$> arbitrary <*> blocks c
        prop_Enc (k,bs) = unsafeEncrypt' c reco k bs == unsafeEncrypt' c impl k bs
        prop_Dec (k,bs) = unsafeDecrypt' c reco k bs == unsafeDecrypt' c impl k bs


encryptsTo c = encryptsTo' c $ recommended c

encryptsTo' :: (Cipher c, Format fmt1, Format fmt2)
            => c
            -> Implementation c
            -> fmt1
            -> fmt2
            -> Key c
            -> Spec
encryptsTo' c imp inp expected key
  = it msg $ result `shouldBe` (decodeFormat expected)
  where result = unsafeEncrypt' c imp key $ decodeFormat inp
        msg   = unwords [ "encrypts"
                        , shortened $ show inp
                        , "to"
                        , shortened $ show expected
                        ]

transformsTo :: (StreamCipher c, Recommendation c, Format fmt1, Format fmt2)
              => c
              -> fmt1
              -> fmt2
              -> Key c
              -> Spec
transformsTo c = transformsTo' c $ recommended c


keyStreamIs' :: (StreamCipher c, Format fmt)
             => c
             -> Implementation c
             -> fmt
             -> Key c
             -> Spec
keyStreamIs' c impl expected key = it msg $ result `shouldBe` decodeFormat expected
  where result = transform' c impl key $ zeros $ 1 `blocksOf` c
        msg    = unwords ["with key"
                         , "key stream is"
                         , shortened $ show expected
                         ]

zeros :: Primitive prim => BLOCKS prim -> ByteString
zeros = toByteString . writeZero
  where writeZero :: LengthUnit u => u -> WriteIO
        writeZero = writeBytes 0

transformsTo' :: (StreamCipher c, Format fmt1, Format fmt2)
              => c
              -> Implementation c
              -> fmt1
              -> fmt2
              -> Key c
              -> Spec

transformsTo' c impl inp expected key
  = it msg $ result `shouldBe` (decodeFormat expected)
  where result = transform' c impl key $ decodeFormat inp
        msg   = unwords [ "encrypts"
                        , shortened $ show inp
                        , "to"
                        , shortened $ show expected
                        ]
