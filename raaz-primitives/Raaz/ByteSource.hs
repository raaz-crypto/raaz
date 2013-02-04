{-# LANGUAGE FlexibleContexts #-}
{-|

-}
module Raaz.ByteSource
       ( FillResult(..)
       , withFillResult
       , ByteSource(..)
       , fill
       ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Prelude hiding(length)
import           System.IO(Handle)

import           Raaz.Types(BYTES, CryptoPtr, CryptoCoerce(..))
import           Raaz.Util.ByteString( unsafeCopyToCryptoPtr
                                     , unsafeNCopyToCryptoPtr
                                     , length
                                     )
import           Raaz.Util.Ptr(movePtr, hFillBuf)


-- | This type captures the result of a fill operation.
data FillResult a = Remaining a           -- ^ only partially filled
                                          -- the buffer.
                  | Exhausted (BYTES Int) -- ^ source exhausted and
                                          -- there is still so much of
                                          -- bytes left in the buffer
instance Functor FillResult where
  fmap f (Remaining a ) = Remaining $ f a
  fmap _ (Exhausted sz) = Exhausted sz

-- | Combinator to handle a fill result.
withFillResult :: (a -> b)          -- ^ stuff to do when filled
               -> (BYTES Int -> b)  -- ^ stuff to do when exhausted
               -> FillResult a      -- ^ the fill result to process
               -> b
withFillResult continueWith _     (Remaining a)  = continueWith a
withFillResult _            endBy (Exhausted sz) = endBy sz

class ByteSource src where
  fillBytes :: BYTES Int  -- ^ Buffer size
            -> src        -- ^ The source to fill.
            -> CryptoPtr  -- ^ Buffer pointer
            -> IO (FillResult src)

instance ByteSource Handle where
  fillBytes sz hand cptr = do
            count <- hFillBuf hand cptr sz
            if count < sz then return $ Exhausted $ sz - count
               else return $ Remaining hand

instance ByteSource B.ByteString where
  fillBytes sz bs cptr | l < sz    = do unsafeCopyToCryptoPtr bs cptr
                                        return $ Exhausted $ sz - l
                       | otherwise = do unsafeNCopyToCryptoPtr sz bs cptr
                                        return $ Remaining rest
       where l    = length bs
             rest = B.drop (fromIntegral sz) bs

instance ByteSource L.ByteString where
  fillBytes sz bs cptr =   fillBytes sz (L.toChunks bs) cptr
                       >>= return . fmap L.fromChunks

instance ByteSource src => ByteSource (Maybe src) where
  fillBytes sz ma cptr = maybe exhausted fillIt ma
          where exhausted = return $ Exhausted sz
                fillIt a  =  fillBytes sz a cptr
                          >>= return . fmap Just


instance ByteSource src => ByteSource [src] where
  fillBytes sz []     _    = return $ Exhausted sz
  fillBytes sz (x:xs) cptr = do
            result <- fillBytes sz x cptr
            case result of
                 Exhausted nSz -> fillBytes nSz xs $ movePtr cptr $ sz - nSz
                 Remaining nx  -> return $ Remaining $ nx:xs

-- | A version of fillBytes that takes type safe lengths as input.
fill :: ( CryptoCoerce len (BYTES Int)
        , ByteSource src
        )
     => len
     -> src
     -> CryptoPtr
     -> IO (FillResult src)
fill = fillBytes . cryptoCoerce
