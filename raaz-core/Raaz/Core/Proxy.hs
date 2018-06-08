module Raaz.Core.Proxy
       ( proxyUnwrap
       ) where

import Data.Proxy


-- | Sometimes we require a proxy of an element of type 'a' while all
-- that we have is a proxy of what we `F a`. In such cases, we can use
-- proxyUnwrap.
{-# INLINE proxyUnwrap #-}
proxyUnwrap :: Proxy (t a) -> Proxy a
proxyUnwrap _ = Proxy
