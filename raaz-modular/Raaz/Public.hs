module Raaz.Public
       ( DEREncoding(..)
       ) where

import qualified Data.ByteString as BS

import           Raaz.Hash

-- | Required DER encoding for Hashes
class DEREncoding x where
  derEncode :: x -> BS.ByteString

instance DEREncoding SHA1 where
  derEncode sha = BS.append (BS.pack [ 0x30, 0x21, 0x30, 0x09, 0x06
                                     , 0x05, 0x2b, 0x0e, 0x03, 0x02
                                     , 0x1a, 0x05, 0x00, 0x04, 0x14])
                            (toByteString sha)

instance DEREncoding SHA256 where
  derEncode sha = BS.append (BS.pack [ 0x30, 0x31, 0x30, 0x0d, 0x06
                                     , 0x09, 0x60, 0x86, 0x48, 0x01
                                     , 0x65, 0x03, 0x04, 0x02, 0x01
                                     , 0x05, 0x00, 0x04, 0x20])
                            (toByteString sha)

instance DEREncoding SHA384 where
  derEncode sha = BS.append (BS.pack [ 0x30, 0x41, 0x30, 0x0d, 0x06
                                     , 0x09, 0x60, 0x86, 0x48, 0x01
                                     , 0x65, 0x03, 0x04, 0x02, 0x02
                                     , 0x05, 0x00, 0x04, 0x30])
                            (toByteString sha)

instance DEREncoding SHA512 where
  derEncode sha = BS.append (BS.pack [ 0x30, 0x51, 0x30, 0x0d, 0x06
                                     , 0x09, 0x60, 0x86, 0x48, 0x01
                                     , 0x65, 0x03, 0x04, 0x02, 0x03
                                     , 0x05, 0x00, 0x04, 0x40])
                            (toByteString sha)
