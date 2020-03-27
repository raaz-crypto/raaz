{-# LANGUAGE 
                DataKinds,
                ForeignFunctionInterface #-}
module Raaz.Verse.Blake2s.C.Portable where
import Raaz.Core
import Foreign.Ptr
foreign import ccall unsafe
    verse_blake2s_c_portable_iter :: Ptr (Tuple 16 Word32)
                                  -> Word64
                                  -> Ptr Word32
                                  -> Ptr Word32
                                  -> Ptr (Tuple 8 Word32)
                                  -> IO ()
foreign import ccall unsafe
    verse_blake2s_c_portable_last :: Ptr (Tuple 16 Word32)
                                  -> Word32
                                  -> Word32
                                  -> Word32
                                  -> Word32
                                  -> Word32
                                  -> Ptr (Tuple 8 Word32)
                                  -> IO ()
