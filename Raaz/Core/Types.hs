-- | This module exposes some core types used through out the Raaz
-- library. One of the major goals of the raaz cryptographic library
-- use the type safety of Haskell to catch some common bugs at compile
-- time. As of now we address three kinds of errors
--

module Raaz.Core.Types
       ( -- * Timing safe equality checking.
         -- $timingSafeEquality$
         module Raaz.Core.Types.Equality
         -- * Endianess aware types.
         -- $endianness$
       , module Raaz.Core.Types.Endian
         -- * The pointer type and Length offsets.
         -- $typesafeLength$
       , module Raaz.Core.Types.Pointer
         -- * Tuples with length encoded in their types.
       , module Raaz.Core.Types.Tuple
       , Describable(..)
       ) where

import Raaz.Core.Types.Describe
import Raaz.Core.Types.Equality
import Raaz.Core.Types.Endian
import Raaz.Core.Types.Pointer
import Raaz.Core.Types.Tuple

-- $timingSafeEquality$
--
-- We need a consistent way to build timing safe equality
-- comparisons. The type class `Equality` plays the role of `Eq` for
-- us. The comparison result is of type `Result` and not `Bool` so as
-- to avoid timing attacks due to short-circuting of the
-- AND-operation.
--
-- The `Result` type is an opaque type to avoid the user from
-- compromising the equality comparisons by pattern matching on it. To
-- combine the results of two comparisons one can use the monoid
-- instance of `Result`, i.e. if @r1@ and @r2@ are the results of two
-- comparisons then @r1 `mappend` r2@ essentially takes the AND of
-- these results but this and is not short-circuited and is timing
-- independent.
--
-- Instance for basic word types are provided by the library and users
-- are expected to build the `Equality` instances of compound types by
-- combine the results of comparisons using the monoid instance of
-- `Result`. We also give timing safe equality comparisons for
-- `Vector` types using the `eqVector` and `oftenCorrectEqVector`
-- functions.  Once an instance for `Equality` is defined for a
-- cryptographically sensitive data type, we define the `Eq` for it
-- indirectly using the `Equality` instance and the operation `===`.


-- $endianness$
--
-- Cryptographic primitives often consider their input as an array of
-- words of a particular endianness. Endianness is only relevant when
-- the data is being read or written to. It makes sense therefore to
-- keep track of the endianness in the type and perform necessary
-- transformations depending on the endianness of the
-- machine. Such types are captured by the type class `EndianStore`. They
-- support the `load` and `store` combinators that automatically compensates
-- for the endianness of the machine.
--
-- This libraray exposes endian aware variants of `Word32` and
-- `Word64` here and expect other cryptographic types to use such
-- endian explicit types in their definition.


-- $typesafeLength$
--
-- We have the generic pointer type `Pointer` and distinguish between
-- different length units at the type level. This helps in to avoid a
-- lot of length conversion errors.


{-# ANN module "HLint: ignore Use import/export shortcut" #-}
