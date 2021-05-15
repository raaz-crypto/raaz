module Encrypt( encryptSpec
              , decryptSpec
              , module Compare
              ) where
import Compare

encryptSpec :: ( Eq a
               , Show k, Show n
               , Arbitrary k , Arbitrary n
               )
            => [(String, k -> n -> ByteString -> a)]
            -> Spec

encryptSpec fs = prop mesg $ \ k n bs -> checkSame $ map (encryptIt k n bs) fs
  where encryptIt k n bs (nm,f) = (nm, f k n bs)
        mesg = message $ map fst fs


decryptSpec :: ( Eq a
               , Show k, Show n
               , Arbitrary k , Arbitrary n
               )
            => [(String, k -> n -> ByteString -> a)]
            -> Spec

decryptSpec fs = prop mesg $ \ k n bs -> checkSame $ map (decryptIt k n bs) fs
  where decryptIt k n bs (nm,f) = (nm, f k n bs)
        mesg = message $ map fst fs
