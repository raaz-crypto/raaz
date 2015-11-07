-- | This module exposes some core types used through out the Raaz
-- library. One of the major goals of the raaz cryptographic library
-- use the type safety of Haskell to catch some common bugs at compile
-- time. As of now we address three kinds of errors
--
-- [Timing safe equality:] We need a consistent way to build timing
--     safe equality comparisons. The type class `Equality` plays the
--     role of `Eq` for us. The comparison result is of type `Result`
--     and not `Bool` so as to avoid timing attacks due to
--     short-circuting of the AND-operation. Instance for basic word
--     types are given here and users are expected to build the
--     `Equality` instances of compound types by combine the results
--     of comparisons using the monoid instance of `Result`. We also
--     give timing safe equality comparisons for `Vector` types using
--     the `eqVector` and `oftenCorrectEqVector` functions.  Once an
--     instance for `Equality` is defined for a cryptographically
--     sensitive data type, we define the `Eq` for it indirectly using
--     the `Equality` instance and the operation `===`.
--
-- [Endianness aware types:] When serialising data, we need to be
--     careful about the endianness of the machine. Instance of the
--     `EndianStore` type class correctly stores and loads data from
--     memory, irrespective of the endianness of the machine. We
--     define endian aware variants of `Word32` and `Word64` here and
--     expect other cryptographic types to use such endian explicit
--     types in their definition.
--
-- [Pointer and Length units:] We have the generic pointer type
--     `Pointer` and distinguish between different length units at the
--     type level. This helps in to avoid a lot of length conversion
--     errors.
module Raaz.Core.Types
       ( -- * Timing safe equality checking.
         module Raaz.Core.Types.Equality
         -- * Endianess aware types.
       , module Raaz.Core.Types.Endian
         -- * The pointer type and Length offsets.
       , module Raaz.Core.Types.Pointer
       ) where


import Raaz.Core.Types.Pointer
import Raaz.Core.Types.Equality
import Raaz.Core.Types.Endian

{-# ANN module "HLint: ignore Use import/export shortcut" #-}
