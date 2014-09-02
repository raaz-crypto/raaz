{-|

The SSH Transport layer (RFC-4253). This module implements the
transport layer of ssh.

-}

{-# LANGUAGE OverloadedStrings #-}
module Raaz.Network.SSH.Transport
       ( idString
       , idString'
       ) where

import qualified Data.ByteString.Char8 as C8
import           Data.Version          (showVersion)

import           Paths_raaz_ssh        (version)


-- | The prefix of the identification string.
idPrefix = C8.concat [ "SSH-2.0-"
                     , "RaazSSH_"
                     , C8.pack $ showVersion version
                     ]

-- | The identification string sent by the library.
idString :: C8.ByteString
idString = idPrefix `C8.append` "\r\n"

-- | The identification string with an extra comment field.
idString' :: C8.ByteString -> C8.ByteString
idString' comment = C8.concat [ idPrefix, " ", comment, "\r\n"]
