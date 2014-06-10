module Modules.Number.Modular ( benchExponentiation
                                , ParamList(..)
                              ) where

import Criterion.Main
import Data.Bits
import System.Random

import Raaz.Number

data ParamList = ParamList [Integer] [Integer] [Integer] [Integer] [Integer] [Integer]

benchExponentiation :: ParamList -> [ Benchmark ]
benchExponentiation p = [ bench "powModuloSlow" $ nf powModuloSlow' p
                        , bench "powModuloSlowSafe" $ nf powModuloSlowSafe' p
                        , bench "powModuloSlowSafe-timing" $ nf powModuloSlowSafeTiming' p
                        ]
  where powModuloSlow' (ParamList glist klist mlist glist' klist' mlist') = powModuloSlow'' glist klist mlist
        powModuloSlow'' [g] [k] [m] = [(powModuloSlow g k m)]
        powModuloSlow'' (g:gs) (k:ks) (m:ms) = (powModuloSlow g k m) : (powModuloSlow'' gs ks ms)
        powModuloSlowSafe' (ParamList glist klist mlist glist' klist' mlist') = powModuloSlowSafe'' glist klist mlist
        powModuloSlowSafe'' [g] [k] [m] = [(powModuloSlowSafe g k m)]
        powModuloSlowSafe'' (g:gs) (k:ks) (m:ms) = (powModuloSlowSafe g k m) : (powModuloSlowSafeTiming'' gs ks ms)
        powModuloSlowSafeTiming' (ParamList glist klist mlist glist' klist' mlist') = powModuloSlowSafeTiming'' glist' klist' mlist'
        powModuloSlowSafeTiming'' [g] [k] [m] = [(powModuloSlowSafe g k m)]
        powModuloSlowSafeTiming'' (g:gs) (k:ks) (m:ms) = (powModuloSlowSafe g k m) : (powModuloSlowSafeTiming'' gs ks ms)

