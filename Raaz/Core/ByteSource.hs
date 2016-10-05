{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE DefaultSignatures #-}
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
import           Control.Monad        (liftM)
import           Control.Monad.IO.Class
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           Prelude hiding(length)
import           System.IO            (Handle)

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
-- which we can fill a buffer with bytes. Depending on the nature of
-- the source we have two classes: `ByteSource` which captures bounded
-- sources and `InfiniteSource` that captures never ending source of
-- bytes.
--
-- Among instances of `ByteSource`, some like for example
-- `B.ByteString` are /pure/ in the sense filling a buffer with bytes
-- from such a source has no other side-effects. This is in contrast
-- to a source like a sockets. The type class `PureByteSource`
-- captures such byte sources.
--

-- | This type captures the result of a fill operation.
data FillResult a = Remaining a           -- ^ the buffer is filled completely
                  | Exhausted (BYTES Int) -- ^ source exhausted with so much
                                          -- bytes read.

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
            -> Pointer  -- ^ Buffer pointer
            -> IO (FillResult src)

--  default fillBytes :: InfiniteSource src => BYTES Int ->  src -> Pointer -> IO (FillResult src)
--  fillBytes sz src pointer = Remaining <$> slurp sz src pointer

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

{--

-- | Never ending stream of bytes. The reads to the stream might get
-- delayed but it will always return the number of bytes that were
-- asked for.
class InfiniteSource src where
  slurpBytes :: BYTES Int -- ^ bytes to read,
             -> src       -- ^ the source to fill from,
             -> Pointer   -- ^ the buffer source to fill.
             -> IO src


-- | A version of slurp that takes type safe lengths as input.
slurp :: ( LengthUnit len
         , InfiniteSource src
         )
       => len
       -> src
       -> Pointer
       -> IO src
slurp = slurpBytes . inBytes

--}

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

instance ByteSource Handle where
  {-# INLINE fillBytes #-}
  fillBytes sz hand cptr = do
            count <- hFillBuf hand cptr sz
            return
              (if count < sz then Exhausted count
                             else Remaining hand)

instance ByteSource B.ByteString where
  {-# INLINE fillBytes #-}
  fillBytes sz bs cptr | l < sz    = do unsafeCopyToPointer bs cptr
                                        return $ Exhausted l
                       | otherwise = do unsafeNCopyToPointer sz bs cptr
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
          where exhausted = return $ Exhausted 0
                fillIt a  = fmap Just <$> fillBytes sz a cptr

instance ByteSource src => ByteSource [src] where
  fillBytes _  []     _    = return $ Exhausted 0
  fillBytes sz (x:xs) cptr = do
    result <- fillBytes sz x cptr
    case result of
      Exhausted rbytes -> let nptr = rbytes <.> cptr
                          in  fillBytes (sz - rbytes) xs nptr
      Remaining nx     -> return $ Remaining $ nx:xs

--------------------- Instances of pure byte source --------------------

instance PureByteSource B.ByteString where
instance PureByteSource L.ByteString where
instance PureByteSource src => PureByteSource [src]
instance PureByteSource src => PureByteSource (Maybe src)
