{-# LANGUAGE FlexibleContexts #-}

-- | Module define byte sources.
module Raaz.ByteSource
       ( ByteSource(..), fill
       , PureByteSource
       , FillResult(..)
       , withFillResult
       ) where

import           Control.Monad        (liftM)
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           Prelude hiding(length)
import           System.IO            (Handle)

import           Raaz.Types           (BYTES, CryptoPtr, Rounding(..))
import           Raaz.Util.ByteString( unsafeCopyToCryptoPtr
                                     , unsafeNCopyToCryptoPtr
                                     , length
                                     )
import           Raaz.Util.Ptr        (movePtr, hFillBuf)


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

------------------------ Byte sources ----------------------------------

-- | Abstract byte sources. A bytesource is something that you can use
-- to fill a buffer.
class ByteSource src where
  -- | Fills a buffer from the source.
  fillBytes :: BYTES Int  -- ^ Buffer size
            -> src        -- ^ The source to fill.
            -> CryptoPtr  -- ^ Buffer pointer
            -> IO (FillResult src)



-- | A version of fillBytes that takes type safe lengths as input.
fill :: ( Rounding len (BYTES Int)
        , ByteSource src
        )
     => len
     -> src
     -> CryptoPtr
     -> IO (FillResult src)
fill = fillBytes . roundFloor
{-# INLINE fill #-}

-- | A byte source src is pure if filling from it does not have any
-- other side effect on the state of the byte source. Formally, two
-- different fills form the same source should fill the buffer with
-- the same bytes.  This additional constraint on the source helps to
-- /purify/ certain crypto computations like computing the hash or mac
-- of the source. Usualy sources like `B.ByteString` etc are pure byte
-- sources. A file handle is a byte source that /not/ a pure source.
class ByteSource src => PureByteSource src where

----------------------- Instances of byte source -----------------------

instance ByteSource Handle where
  {-# INLINE fillBytes #-}
  fillBytes sz hand cptr = do
            count <- hFillBuf hand cptr sz
            if count < sz then return $ Exhausted $ sz - count
               else return $ Remaining hand

instance ByteSource B.ByteString where
  {-# INLINE fillBytes #-}
  fillBytes sz bs cptr | l < sz    = do unsafeCopyToCryptoPtr bs cptr
                                        return $ Exhausted $ sz - l
                       | otherwise = do unsafeNCopyToCryptoPtr sz bs cptr
                                        return $ Remaining rest
       where l    = length bs
             rest = B.drop (fromIntegral sz) bs

instance ByteSource L.ByteString where
  {-# INLINE fillBytes #-}
  fillBytes sz bs = liftM (fmap L.fromChunks)
                    . fillBytes sz (L.toChunks bs)


instance ByteSource src => ByteSource (Maybe src) where
  {-# INLINE fillBytes #-}
  fillBytes sz ma cptr = maybe exhausted fillIt ma
          where exhausted = return $ Exhausted sz
                fillIt a  = liftM (fmap Just) $ fillBytes sz a cptr

instance ByteSource src => ByteSource [src] where
  fillBytes sz []     _    = return $ Exhausted sz
  fillBytes sz (x:xs) cptr = do
    result <- fillBytes sz x cptr
    case result of
      Exhausted nSz -> fillBytes nSz xs $ movePtr cptr $ sz - nSz
      Remaining nx  -> return $ Remaining $ nx:xs

--------------------- Instances of pure byte source --------------------

instance PureByteSource B.ByteString where
instance PureByteSource L.ByteString where
instance PureByteSource src => PureByteSource [src]
