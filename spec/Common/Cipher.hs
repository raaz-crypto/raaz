{-# LANGUAGE FlexibleContexts #-}
module Common.Cipher where

import Common.Imports
import Common.Utils


encryptVsDecrypt :: ( Arbitrary (Key c)
                    , Show (Key c)
                    , Cipher c, Recommendation c
                    )
                 => c -> Spec
encryptVsDecrypt c = describe "decrypt . encrypt" $ do
  it "trivial on strings of a length that is a multiple of the block size"
    $ property $ forAll genKeyStr prop_EvsD
  where genKeyStr = (,) <$> arbitrary <*> blocks c
        prop_EvsD (k,bs) = unsafeDecrypt c k (unsafeEncrypt c k bs) == bs


encryptsTo :: (Cipher c, Recommendation c, Format fmt1, Format fmt2)
           => c
           -> fmt1
           -> fmt2
           -> Key c
           -> Spec
encryptsTo c inp expected key
  = it msg $ result `shouldBe` (decodeFormat expected)
  where result = unsafeEncrypt c key $ decodeFormat inp
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
transformsTo c inp expected key
  = it msg $ result `shouldBe` (decodeFormat expected)
  where result = transform c key $ decodeFormat inp
        msg   = unwords [ "encrypts"
                        , shortened $ show inp
                        , "to"
                        , shortened $ show expected
                        ]
