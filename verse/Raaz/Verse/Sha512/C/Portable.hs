{-# LANGUAGE 
                DataKinds,
                ForeignFunctionInterface #-}
module Raaz.Verse.Sha512.C.Portable where
import Raaz.Core
foreign import ccall unsafe
    verse_sha512_c_portable :: Ptr (Tuple 16 Word64)
                            -> Word64
                            -> Ptr (Tuple 8 Word64)
                            -> IO ()
