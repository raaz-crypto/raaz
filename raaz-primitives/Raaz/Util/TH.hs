{-# LANGUAGE FlexibleInstances #-}
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
       , variable, variable', variableGen
       , signature, signatureGen
       , declarations
       , permute
       -- * Subscripting variables.
       -- $subscripting
       , Subscript
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
-- > x_1_2 :: Int
--
signature :: Subscript s
          => String      -- ^ Variable name
          -> Name        -- ^ The type name
          -> s           -- ^ The subscript
          -> DecQ
signature k ty = signatureGen k $ conT ty

-- | A more general version of `signature`.
signatureGen :: Subscript s
             => String      -- ^ The variable
             -> TypeQ       -- ^ The type
             -> s           -- ^ The subscript
             -> DecQ
signatureGen k ty is = sigD (k `sub` is) ty


-- | Generate a variable definition. The expression @variable "x" exp [1,2]@
-- will result in a declaration that looks like
--
-- > x_1_2 = [| $(exp [1,2]) |]
--
--
variable :: Subscript s
         => String      -- ^ Variable name
         -> (s -> ExpQ) -- ^ the rhs of the variable
         -> s           -- ^ subscript
         -> DecQ
variable k rhs is = valD (k `subP` is)
                         (normalB $ rhs is)
                         []

-- | Genrates a variable definition and type signature.
variable' :: Subscript s
          => String          -- ^ Variable name
          -> Name            -- ^ Type
          -> (s -> ExpQ)     -- ^ The rhs of the variable definition
          -> s               -- ^ The subscript
          -> DecsQ
variable' k ty = variableGen k $ conT ty


-- | The most general type of variable declaration.
variableGen :: Subscript s
            => String      -- ^ Variable name
            -> TypeQ       -- ^ Type signature
            -> (s -> ExpQ) -- ^ The rhs of the variable definition
            -> s           -- ^ The subscript
            -> DecsQ
variableGen k ty rhs is = sequence [ signatureGen k ty is
                                   , variable k rhs is
                                   ]

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
permute vars i   = mapM f vars
  where f :: (String,String) -> DecQ
        f (x,y)  = variable x (const $ subE y [i-1]) [i]

-- | The TH code @declarations [w,a] [1..100]@ generates the following
-- declarations
--
-- > w 1
-- > w 2
-- > ...
-- > w 100
-- > a 1
-- > ...
-- > w 100
--
-- This function can be used for example to unroll a set of mutually
-- recursive definitions of variables.

declarations :: Subscript s
             => [s -> DecsQ] -- ^ Declaration generators
             -> [s]          -- ^ Subscripts
             -> DecsQ
declarations gens is  = fmap concat $ forM gens singleGen
  where singleGen gen = fmap concat $ forM is gen

-- $subscripting
--
-- While unrolling loops we need to generate a sequence of
-- variables. Typically the subscript would just be an
-- integer. However, we some times require matrix variables. The
-- convention followed in this: A variable can have a list of integers
-- as its subscript. Infact our class Subscript captures those types
-- which can be used as subscripts. Currently we support only @`Int`@
-- and @[`Int`]@.

-- The variable @k@ with subscript @[2,3]@ correspondes to the
-- variable @k_2_3@ in the generated Haskell code. However, while
-- using the library make use of the exported functions `sub`, `subE`
-- and `subP` to generate the variable names instead of explicitly
-- coding it up.

-- | An class that capture subscripts.
class Subscript a where
  toSub :: a -> String

instance Subscript Int where
  toSub x | x >= 0    = show x
          | otherwise = '_' : show (abs x)

instance Subscript [Int] where
  toSub = intercalate "_" . map toSub

-- | The expression @sub "k" [i,j]@ gives the name @"k_i_j"@.
sub :: Subscript s => String -> s -> Name
sub x s = mkName $ x ++ "_" ++ toSub s

-- | The `ExpQ` variant of @sub@.
subE :: Subscript s => String -> s -> ExpQ
subE x = varE . sub x

-- | The `PatQ` variant of @sub@.
subP :: Subscript s => String -> s -> PatQ
subP x = varP . sub x
