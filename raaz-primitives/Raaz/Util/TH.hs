{-|

Some template haskell helper functions. For speed considerations we
often need to unroll computations. Typing such unrolled definitions
are repeatitive and error prone. This module provides Template Haskell
based functions to eliminate some of these. For function definitions,
also consider using the INLINE pragma.

-}

module Raaz.Util.TH
       ( constants
       , matrix
       , variable
       , signature
       , permute
       , sub, subE, subP
       ) where

import Control.Monad
import Data.List(intercalate)
import Language.Haskell.TH
import Language.Haskell.TH.Syntax(Lift(..))

-- | Declare a list of constants. For example the expression
-- @constants "k" ''Int [1, 1 ,2, 3]@ will lead to the following
-- declarations.
--
-- > k_0 :: Int
-- > k_0 = 1
-- > k_1 :: Int
-- > k_1 = 1
-- > k_2 :: Int
-- > k_2 = 2
-- > k_3 :: Int
-- > k_3 = 3
--
-- This combinator gives an easy way of declaring round constants in a
-- cryptographic algorithm.
constants :: Lift val
          => String  -- ^ variable name.
          -> Name    -- ^ the type of the variable
          -> [val]   -- ^ the values
          -> DecsQ
constants = constantP []


-- | A matrix variant of `constants`: @matrix "k" ''Int [[0,1],[2,3]]@ gives
-- the declaration
--
-- > k_0_0 :: Int
-- > k_0_0 = 0
-- > ...
-- > ...
-- > k_1_1 :: Int
-- > k_1_1 = 3
matrix :: Lift val
       => String    -- ^ the base name of the variable
       -> Name      -- ^ the type of the variable
       -> [[val]]   -- ^ the value matrix
       -> DecsQ
matrix k ty = fmap concat . zipWithM outer [0..]
  where outer i = constantP [i] k ty


-- | Worker function to define constants.
constantP :: Lift v
          => [Int]
          -> String
          -> Name
          -> [v]
          -> DecsQ
constantP is k ty = fmap concat . zipWithM inner [0..]
   where inner i v = sequence [ signature k ty index
                              , variable  k (const $ lift v) index
                              ]
               where index = is ++ [i]

-- | The expression @signature "x" ''Int [1,2]@ declares the following
-- type signature.
--
-- > x_5 :: Int
--
signature :: String -> Name -> [Int] -> DecQ
signature k ty is = sigD (k `sub` is) $ conT ty


-- | Generate a variable definition. The expression @variable "x" exp [1,2]@
-- will result in a declaration that looks like
--
-- > x_1_2 = [| $(exp [1,2]) |]
--
--
variable :: String          -- ^ Variable name
         -> ([Int] -> ExpQ) -- ^ the rhs of the variable
         -> [Int]           -- ^ subscript
         -> DecQ
variable k rhs is = valD (k `subP` is)
                         (normalB $ rhs is)
                         []


-- | The TH expression @permute [("x", "y"), ("u","v")] 5@ declares
-- the following variables
--
-- > x_5 = y_4
-- > u_5 = v_4
--
-- Often the definition of round variables are just permutations of
-- the previous round variables. In such a case the permute
-- declaration is useful.
--

permute :: [(String,String)] -> Int -> DecsQ
permute vars i   = sequence $ map f vars
  where f :: (String,String) -> DecQ
        f (x,y)  = variable x (const $ subE y [i-1]) [i]


-- | The expression @sub "k" [i,j]@ gives the name @"k_i_j"@.
sub :: String -> [Int] -> Name
sub x is = mkName $ intercalate "_" $ x : map show is

-- | The `ExpQ` variant of @sub@.
subE :: String -> [Int] -> ExpQ
subE x is = varE $ sub x is

-- | The `PatQ` variabt of @sub@.
subP :: String -> [Int] -> PatQ
subP x is = varP $ sub x is
