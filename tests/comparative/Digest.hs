module Digest( digestSpec
             , module Compare
             ) where
import Compare

digestSpec :: Eq a
           => [(String, ByteString -> a)]
           -> Spec
digestSpec fs = prop mesg $ \ bs -> checkSame $ map (digestIt bs) fs
  where digestIt bs (nm,f) = (nm, f bs)
        mesg = message $ map fst fs
