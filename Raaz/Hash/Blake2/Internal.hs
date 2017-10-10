{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

-- | Internal types and function for blake2 hashes.
module Raaz.Hash.Blake2.Internal
       ( -- * The blake2 types
         BLAKE2, BLAKE2b, BLAKE2s
       , Blake2bMem, Blake2sMem
       , blake2Pad, blake2bImplementation
       , blake2sImplementation
       ) where

import           Control.Applicative
import           Control.Monad.IO.Class
import           Data.Bits           ( xor, complement )
import           Data.Monoid
import           Data.Proxy
import           Data.String
import           Data.Word
import           Foreign.Ptr         ( Ptr          )
import           Foreign.Storable    ( Storable(..) )
import           Prelude      hiding ( zipWith      )

import           Raaz.Core
import           Raaz.Core.Transfer
import           Raaz.Hash.Internal

----------------------------- The blake2 type ---------------------------------

-- | The BLAKE2 type.
newtype BLAKE2 w = BLAKE2 (Tuple 8 w)
               deriving (Eq, Equality, Storable, EndianStore)

-- | Word type for Blake2b
type Word2b = LE Word64

-- | Word type for Blake2s
type Word2s = LE Word32

-- | The BLAKE2b hash type.
type BLAKE2b = BLAKE2 Word2b

-- | The BLAKE2s hash type.
type BLAKE2s = BLAKE2 Word2s

instance Encodable BLAKE2b
instance Encodable BLAKE2s


instance IsString BLAKE2b where
  fromString = fromBase16

instance IsString BLAKE2s where
  fromString = fromBase16

instance Show BLAKE2b where
  show =  showBase16

instance Show BLAKE2s where
  show =  showBase16

instance Primitive BLAKE2b where
  type BlockSize BLAKE2b      = 128
  type Implementation BLAKE2b = SomeHashI BLAKE2b

instance Hash BLAKE2b where
  additionalPadBlocks _ = toEnum 1

instance Primitive BLAKE2s where
  type BlockSize BLAKE2s      = 64
  type Implementation BLAKE2s = SomeHashI BLAKE2s

instance Hash BLAKE2s where
  additionalPadBlocks _ = toEnum 1

-- | The initial value to start the blake2b hashing. This is equal to
-- the iv `xor` the parameter block.
hash2b0 :: BLAKE2b
hash2b0 = BLAKE2 $ unsafeFromList [ 0x6a09e667f3bcc908 `xor` 0x01010040
                                  , 0xbb67ae8584caa73b
                                  , 0x3c6ef372fe94f82b
                                  , 0xa54ff53a5f1d36f1
                                  , 0x510e527fade682d1
                                  , 0x9b05688c2b3e6c1f
                                  , 0x1f83d9abfb41bd6b
                                  , 0x5be0cd19137e2179
                                  ]

-- | The initial value to start the blake2b hashing. This is equal to
-- the iv `xor` the parameter block.
hash2s0 :: BLAKE2s
hash2s0 = BLAKE2 $ unsafeFromList [ 0x6a09e667 `xor` 0x01010020
                                  , 0xbb67ae85
                                  , 0x3c6ef372
                                  , 0xa54ff53a
                                  , 0x510e527f
                                  , 0x9b05688c
                                  , 0x1f83d9ab
                                  , 0x5be0cd19
                                  ]

---------------------------------- Memory element for BLAKE2b -----------------------

-- | Memory element for BLAKE2b implementations.
data Blake2bMem = Blake2bMem { blake2bCell :: MemoryCell BLAKE2b
                             , uLengthCell :: MemoryCell (BYTES Word64)
                             , lLengthCell :: MemoryCell (BYTES Word64)
                             }


instance Memory Blake2bMem where
  memoryAlloc     = Blake2bMem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . blake2bCell

instance Initialisable Blake2bMem () where
  initialise _ = do onSubMemory blake2bCell  $ initialise hash2b0
                    onSubMemory uLengthCell  $ initialise (0 :: BYTES Word64)
                    onSubMemory lLengthCell  $ initialise (0 :: BYTES Word64)

instance Extractable Blake2bMem BLAKE2b where
  extract = onSubMemory blake2bCell extract

---------------------------------- Memory element for BLAKE2b -----------------------

-- | Memory element for BLAKE2s implementations.
data Blake2sMem = Blake2sMem { blake2sCell :: MemoryCell BLAKE2s
                             , lengthCell  :: MemoryCell (BYTES Word64)
                             }

instance Memory Blake2sMem where
  memoryAlloc     = Blake2sMem <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . blake2sCell

instance Initialisable Blake2sMem () where
  initialise _ = do onSubMemory blake2sCell $ initialise hash2s0
                    onSubMemory lengthCell  $ initialise (0 :: BYTES Word64)

instance Extractable Blake2sMem BLAKE2s where
  extract = onSubMemory blake2sCell extract

----------------------- Padding for Blake code ------------------------------

-- | The generic blake2 padding algorithm.
blake2Pad :: (Primitive prim, MonadIO m)
          => Proxy prim  -- ^ the primitive (BLAKE2b or BLAKE2s).
          -> BYTES Int   -- ^ length of the message
          -> WriteM m
blake2Pad primProxy = padWrite 0 (blocksOf 1 primProxy) . skipWrite



----------------------- Create a blake2b implementation ---------------------
type Compress2b =  Pointer            -- ^ Buffer
                -> BLOCKS BLAKE2b     -- ^ number of blocks
                -> Ptr (BYTES Word64) -- ^ Upper count
                -> Ptr (BYTES Word64) -- ^ Lower
                -> Ptr BLAKE2b
                -> IO ()

type Last2b =  Pointer
            -> BYTES Int
            -> BYTES Word64 -- Upper
            -> BYTES Word64 -- Lower
            -> Word64       -- f0
            -> Word64       -- f1
            -> Ptr BLAKE2b
            -> IO ()


-- | Create a hash implementation form BLAKE2b given a compression
-- function and the last block function.
blake2bImplementation :: String  -- ^ Name
                      -> String  -- ^ Description
                      -> Compress2b
                      -> Last2b
                      -> HashI BLAKE2b Blake2bMem
blake2bImplementation nm descr compress2b last2b
  = HashI { hashIName              = nm
          , hashIDescription       = descr
          , compress               = comp
          , compressFinal          = final
          , compressStartAlignment = 32  --  Allow gcc to use vector instructions
          }
  where comp buf blks = do uPtr   <- onSubMemory uLengthCell getCellPointer
                           lPtr   <- onSubMemory lLengthCell getCellPointer
                           hshPtr <- onSubMemory blake2bCell getCellPointer
                           liftIO $ compress2b buf blks uPtr lPtr hshPtr

        lastBlock buf r = do u      <- onSubMemory uLengthCell extract
                             l      <- onSubMemory lLengthCell extract
                             hshPtr <- onSubMemory blake2bCell getCellPointer
                             let f0 = complement 0
                                 f1 = 0
                               in  liftIO $ last2b buf r u l f0 f1 hshPtr

        final buf nbytes = unsafeWrite blake2bPad buf >> finalPadded buf nbytes
          where blake2bPad = blake2Pad (Proxy :: Proxy BLAKE2b) nbytes

        finalPadded buf nbytes
          | nbytes == 0 = lastBlock buf 0  -- only when actual input is empty.
          | otherwise   = let
              (blks,r)       =  bytesQuotRem nbytes
              blksToCompress = if r == 0 then blks <> toEnum (-1) else blks
              remBytes       = if r > 0 then r else inBytes $ blocksOf 1 (Proxy :: Proxy BLAKE2b)
              lastBlockPtr   = buf `movePtr` blksToCompress
              in do comp buf blksToCompress
                    lastBlock lastBlockPtr remBytes

------------------------- Implementations of blake2s ---------------------------------------------

type Compress2s =  Pointer            -- ^ Buffer
                -> BLOCKS BLAKE2s     -- ^ number of blocks
                -> BYTES Word64       -- ^ length of the message so far
                -> Ptr BLAKE2s        -- ^ Hash pointer
                -> IO ()

type Last2s =  Pointer
            -> BYTES Int
            -> BYTES Word64
            -> Word32       -- f0
            -> Word32       -- f1
            -> Ptr BLAKE2s
            -> IO ()

-- | Create a hash implementation form BLAKE2s given a compression
-- function and the last block function.
blake2sImplementation :: String  -- ^ Name
                      -> String  -- ^ Description
                      -> Compress2s
                      -> Last2s
                      -> HashI BLAKE2s Blake2sMem
blake2sImplementation nm descr compress2s last2s
  = HashI { hashIName              = nm
          , hashIDescription       = descr
          , compress               = comp
          , compressFinal          = final
          , compressStartAlignment = 32  --  Allow gcc to use vector instructions
          }
  where comp buf blks = do len    <- onSubMemory lengthCell  extract    -- extract current length

                           hshPtr <- onSubMemory blake2sCell getCellPointer
                           liftIO $ compress2s buf blks len hshPtr

                           let increment :: BYTES Word64
                               increment = fromIntegral $ inBytes blks -- update the length by blks
                               in onSubMemory lengthCell $ modify (+increment)


        lastBlock buf r = do len    <- onSubMemory lengthCell extract
                             hshPtr <- onSubMemory blake2sCell getCellPointer
                             let f0 = complement 0
                                 f1 = 0
                               in liftIO $ last2s buf r len f0 f1 hshPtr

        final buf nbytes = unsafeWrite blake2sPad buf >> finalPadded buf nbytes
          where blake2sPad = blake2Pad (Proxy :: Proxy BLAKE2s) nbytes

        finalPadded buf nbytes
          | nbytes == 0 = lastBlock buf 0  -- only when actual input is empty.
          | otherwise   = let
              (blks,r)       =  bytesQuotRem nbytes
              blksToCompress = if r == 0 then blks <> toEnum (-1) else blks
              remBytes       = if r > 0 then r else inBytes $ blocksOf 1 (Proxy :: Proxy BLAKE2s)
              lastBlockPtr   = buf `movePtr` blksToCompress
              in do comp buf blksToCompress
                    lastBlock lastBlockPtr remBytes
