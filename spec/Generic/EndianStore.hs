{-|

Generic tests for instances of endian store.

-}

module Generic.EndianStore
       ( storeAndThenLoad
       ) where
import Raaz.Core


storeAndThenLoad :: EndianStore a
                 => a -> IO a
storeAndThenLoad a = allocaBuffer (byteSize a) runStoreLoad
  where runStoreLoad ptr = store ptr a >> load ptr
