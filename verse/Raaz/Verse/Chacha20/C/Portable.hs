{-# LANGUAGE 
                DataKinds,
                ForeignFunctionInterface #-}
module Raaz.Verse.Chacha20.C.Portable where
import Raaz.Core
import Foreign.Ptr
foreign import ccall unsafe
    verse_chacha20_c_portable :: Ptr (Tuple 16 Word32)
                              -> Word64
                              -> Ptr (Tuple 8 Word32)
                              -> Ptr (Tuple 3 Word32)
                              -> Ptr Word32
                              -> IO ()
foreign import ccall unsafe
    verse_chacha20csprg_c_portable :: Ptr (Tuple 16 Word32)
                                   -> Word64
                                   -> Ptr (Tuple 8 Word32)
                                   -> Ptr (Tuple 3 Word32)
                                   -> Ptr Word32
                                   -> IO ()
foreign import ccall unsafe
    verse_hchacha20_c_portable :: Ptr (Tuple 8 Word32)
                               -> Word32
                               -> Word32
                               -> Word32
                               -> Word32
                               -> IO ()
