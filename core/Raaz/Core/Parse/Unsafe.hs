-- |
--
-- Module      : Raaz.Core.Parse.Unsafe
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--

module Raaz.Core.Parse.Unsafe
       ( Parser, parseWidth
       , unsafeMakeParser
       , unsafeRunParser
       , unsafeParseVector, unsafeParseStorableVector
       ) where

import           Data.Vector.Generic       (Vector, generateM)
import           Foreign.Storable          (Storable, peekElemOff)
import           Raaz.Core.Prelude
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types.Endian
import           Raaz.Core.Types.Pointer


type BytesMonoid   = BYTES Int
type ParseAction   = FieldM IO (Ptr Word8)

-- | An applicative parser type for reading data from a pointer.
type Parser = TwistRF ParseAction BytesMonoid

-- | Run the parser without checking the length constraints.
unsafeRunParser :: Pointer ptr
                => Parser a
                -> ptr b
                -> IO a
unsafeRunParser prsr = unsafeWithPointerCast $ runIt prsr
  where runIt = runFieldM . twistFunctorValue

-- | Return the bytes that this parser will read.
parseWidth :: Parser a -> BYTES Int
parseWidth =  twistMonoidValue

-- | Make an parser out of its action and the length of the buffer
-- that it acts on.
unsafeMakeParser :: LengthUnit l => l -> (Ptr Word8 -> IO a) -> Parser a
unsafeMakeParser l action = TwistRF (liftToFieldM action) $ inBytes l

-- | Similar to @unsafeParseVector@ but assumes the elements are
-- encoded in host endian
unsafeParseStorableVector :: (Storable a, Vector v a) => Int -> Parser (v a)
unsafeParseStorableVector n = pvec
  where pvec      = unsafeMakeParser  width $ \ cptr -> generateM n (getA cptr)
        width     = fromIntegral n * sizeOf (thisProxy pvec)
        getA      = peekElemOff . castPointer
        thisProxy    :: Storable a => Parser (v a) -> Proxy a
        thisProxy _ = Proxy

-- | Parse a vector of elements making sure the proper endian
-- conversion is done. It does not check whether the length parameter
-- is non-negative and hence is unsafe. Use it only if you can prove
-- that the length parameter is non-negative.
unsafeParseVector :: (EndianStore a, Vector v a) => Int -> Parser (v a)
unsafeParseVector n = pvec
  where pvec     = unsafeMakeParser  width $ \ cptr -> generateM n (loadFromIndex (castPointer cptr))
        width    = fromIntegral n * sizeOf (thisProxy pvec)
        thisProxy    :: Storable a => Parser (v a) -> Proxy a
        thisProxy _ = Proxy
