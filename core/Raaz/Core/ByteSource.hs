{-# LANGUAGE FlexibleContexts  #-}
-- | Module define byte sources.
module Raaz.Core.ByteSource
       ( -- * Byte sources.
         -- $bytesource$

         ByteSource(..), PureByteSource
       --    InfiniteSource(..)
       , FillResult(..)
       , fill, processChunks
       , withFillResult
       ) where

import           Control.Applicative
import           Control.Monad.IO.Class
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           Prelude hiding(length)
import           System.IO            (Handle, hIsEOF)

import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types      (BYTES, Pointer, LengthUnit (..))
import           Raaz.Core.Util.ByteString( unsafeCopyToPointer
                                          , unsafeNCopyToPointer
                                          , length
                                          )
import           Raaz.Core.Types.Pointer  (hFillBuf)

-- $bytesource$
--
-- Cryptographic input come from various sources; they can come from
-- network sockets or might be just a string in the Haskell. To give a
-- uniform interfaces for all such inputs, we define the abstract
-- concept of a /byte source/. Essentially a byte source is one from
-- which we can fill a buffer with bytes.
--
-- Among instances of `ByteSource`, some like for example
-- `B.ByteString` are /pure/ in the sense filling a buffer with bytes
-- from such a source has no other side-effects. This is in contrast
-- to a source like a sockets. The type class `PureByteSource`
-- captures such byte sources.
--

-- | This type captures the result of a fill operation.
data FillResult a = Remaining a           -- ^ There is still bytes left.
                  | Exhausted (BYTES Int) -- ^ source exhausted with so much
                                          -- bytes read.
                    deriving (Show, Eq)

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
--
--  __WARNING:__ The source is required to return `Exhausted` in the
-- boundary case where it has exactly the number of bytes
-- requested. In other words, if the source returns @Remaining@ on any
-- particular request, there should be at least 1 additional byte left
-- on the source for the next request. Cryptographic block primitives
-- perform certain special processing, like padding for example, for
-- the last block and it is required to know whether the last block
-- has been read or not.
class ByteSource src where
  -- | Fills a buffer from the source.
  fillBytes :: BYTES Int  -- ^ Buffer size
            -> src        -- ^ The source to fill.
            -> Pointer    -- ^ Buffer pointer
            -> IO (FillResult src)

-- | A version of fillBytes that takes type safe lengths as input.
fill :: ( LengthUnit len
        , ByteSource src
        )
     => len
     -> src
     -> Pointer
     -> IO (FillResult src)
fill = fillBytes . inBytes
{-# INLINE fill #-}

-- | Process data from a source in chunks of a particular size.
processChunks :: ( MonadIO m, LengthUnit chunkSize, ByteSource src)
              => m a                 -- action on a complete chunk,
              -> (BYTES Int -> m b)  -- action on the last partial chunk,
              -> src                 -- the source
              -> chunkSize           -- size of the chunksize
              -> Pointer             -- buffer to fill the chunk in
              -> m b
processChunks mid end source csz ptr = go source
  where fillChunk src = liftIO $ fill csz src ptr
        step src      = mid >> go src
        go src        = fillChunk src >>= withFillResult step end


-- | A byte source src is pure if filling from it does not have any
-- other side effect on the state of the byte source. Formally, two
-- different fills form the same source should fill the buffer with
-- the same bytes.  This additional constraint on the source helps to
-- /purify/ certain crypto computations like computing the hash or mac
-- of the source. Usualy sources like `B.ByteString` etc are pure byte
-- sources. A file handle is a byte source that is /not/ a pure
-- source.
class ByteSource src => PureByteSource src where

----------------------- Instances of byte source -----------------------

-- | __WARNING:_ The `fillBytes` may block.
instance ByteSource Handle where
  {-# INLINE fillBytes #-}
  fillBytes sz hand cptr = do
    count <- hFillBuf hand cptr sz
    eof   <- hIsEOF hand
    if eof then return $ Exhausted count
      else return $ Remaining hand

instance ByteSource B.ByteString where
  {-# INLINE fillBytes #-}
  fillBytes sz bs cptr | l <= sz    = do unsafeCopyToPointer bs cptr
                                         return $ Exhausted l
                       | otherwise = do unsafeNCopyToPointer sz bs cptr
                                        return $ Remaining rest
       where l    = length bs
             rest = B.drop (fromIntegral sz) bs

instance ByteSource L.ByteString where
  {-# INLINE fillBytes #-}
  fillBytes sz bs = fmap (fmap L.fromChunks) . fillBytes sz (L.toChunks bs)

instance ByteSource src => ByteSource (Maybe src) where
  {-# INLINE fillBytes #-}
  fillBytes sz ma cptr = maybe exhausted fillIt ma
          where exhausted = return $ Exhausted 0
                fillIt a  = fmap Just <$> fillBytes sz a cptr

instance ByteSource src => ByteSource [src] where
  fillBytes _  []     _    = return $ Exhausted 0
  fillBytes sz (x:xs) cptr = do
    result <- fillBytes sz x cptr
    case result of
      Remaining nx     -> return $ Remaining $ nx:xs
      Exhausted bytesX -> let nptr              = bytesX <.> cptr
                              whenXSExhausted bytesXS = return $ Exhausted $ bytesX + bytesXS
                              whenXSRemains           = return . Remaining
                           in fillBytes (sz - bytesX) xs nptr
                              >>= withFillResult whenXSRemains whenXSExhausted


--------------------- Instances of pure byte source --------------------

instance PureByteSource B.ByteString where
instance PureByteSource L.ByteString where
instance PureByteSource src => PureByteSource [src]
instance PureByteSource src => PureByteSource (Maybe src)
