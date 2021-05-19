{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
-- |
--
-- Module      : Raaz.Primitive.AEAD.Internal
-- Description : Generic interface to authenticated encryption.
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental

module Raaz.Primitive.AEAD.Internal
       ( AEAD(..), unsafeAEAD
       ) where


import           Data.ByteString
import           Raaz.Core

-- | An authenticated encrypted packet containing a payload of type
-- @plain@ and additional authenticated data of type @aad@.
data AEAD c t = AEAD
     { unsafeToNounce      :: Nounce c
                           -- ^ The nounce use to compute this packet.

     , unsafeToCipherText  :: ByteString
                           -- ^ The associated cipher text.

     , unsafeToAuthTag     :: t
                           -- ^ The associated authentication tag.

     }

-- | Create an AEAD packet from the underlying authentication tag and
-- cipher text.
unsafeAEAD :: Nounce c
           -> ByteString
           -> t             -- ^ the authentication tag
           -> AEAD c t
unsafeAEAD = AEAD
