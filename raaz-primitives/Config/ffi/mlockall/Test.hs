{-# LANGUAGE ForeignFunctionInterface #-}

import Control.Monad
import Data.Word
import Foreign.Marshal.Alloc
import Foreign.Ptr
import System.Exit

foreign import ccall "lockall"         c_mlockall       :: IO Int
foreign import ccall "lockallfuture"   c_mlockallfuture :: IO Int
foreign import ccall "munlockall"      c_munlockall :: IO Int

checkStatus :: String -> IO Int -> IO ()
checkStatus name action = do
  stat <- action
  when (stat /= 0) $ do
    putStr $ unwords [name, "failed"]
    exitFailure
  when (stat == 0) $ do
    putStr $ unwords [name, "succcess"]

main :: IO ()
main = do checkStatus "mlockall"   c_mlockall
          checkStatus "munlockall" c_munlockall
          checkStatus "mlockall future" c_mlockallfuture
          checkStatus "munlockall future" c_munlockall
