{-|
Module:      Crypto.Cipher.Vigenere
Copyright:   (C) 2015 Ryan Scott
License:     GPL-3 (see the file LICENSE)
Maintainer:  Ryan Scott
Stability:   Provisional
Portability: GHC

Encrypt or decrypt a message using the Vigenère cipher.

/Since: 0.1/
-}
module Crypto.Cipher.Vigenere (
      Plaintext
    , Key
    , Ciphertext
    , encrypt
    , decrypt
    , keyFrom
    ) where

import           Data.Char (chr, ord)
import           Data.Int (Int64)
import           Data.Text.Lazy (Text)
import qualified Data.Text.Lazy as TL (append, filter, null, take, toUpper, zipWith)

-- | A human-readable message.
type Plaintext  = Text

-- | A secret word the can encrypt plaintext and decrypt ciphertext.
type Key        = Text

-- | An incomprehensible message that must be decoded.
type Ciphertext = Text

-- | Encrypt a plaintext with the given key, using the Vigenère cipher.
-- 
-- /Since: 0.1/
encrypt :: Key -> Plaintext -> Ciphertext
encrypt k p = crypt (+) k p
{-# INLINE encrypt #-}

-- | Decrypt a ciphertext with the given key, using the Vigenère cipher.
-- 
-- /Since: 0.1/
decrypt :: Key -> Ciphertext -> Plaintext
decrypt k c = crypt (-) k c
{-# INLINE decrypt #-}

-- | Determines the 'Key' that would encrypt the 'Plaintext' argument into the
-- 'Ciphertext' argument with a Vigenère cipher.
keyFrom :: Plaintext -> Ciphertext -> Int64 -> Key
keyFrom ptxt ctxt len = TL.zipWith shiftDiff
                                   (TL.take len (sanitize ptxt))
                                   (TL.take len (sanitize ctxt))
{-# INLINE keyFrom #-}

-- | Transform a 'Text' using the given 'Key' and a function that combines the
-- integer representations of two letters in the English alphabet.
crypt :: (Int -> Int -> Int) -> Key -> Text -> Text
crypt f k t = TL.zipWith (shift f) -- Combine the integer representatins
                         (cycleText (sanitize k)) -- An infinite stream of key characters
                         (sanitize t) -- The transformed 'Text', cleaned up
{-# INLINE crypt #-}

-- | Remove any spaces from a 'Text', and convert all characters to uppercase.
sanitize :: Text -> Text
sanitize t = TL.filter (/= ' ') (TL.toUpper t)
{-# INLINE sanitize #-}

-- | Creates an infinite 'Text' consisting of the argument repeated forever.
cycleText :: Text -> Text
cycleText t | TL.null t = error "empty text"
            | otherwise = t' where t' = TL.append t t'
{-# INLINE cycleText #-}

-- | Shifts an English-letter 'Char' by an amount equal to the Vigenère cipher
-- representation of a key's 'Char'. The shifting is performed by the higher-
-- order function argument.
shift :: (Int -> Int -> Int) -> Char -> Char -> Char
shift f delta letter = chr $ ((f (ord letter - ord 'A') (fromTableau delta)) `mod` range) + ord 'A'
{-# INLINE shift #-}

-- | The modulus for the 'shift' operation, or, the number of letters in the 
-- English alphabet.
range :: Int
range = 26
{-# INLINE range #-}

-- The 'Char' that would shift @c1@ to @c2@ in a Vigenère cipher.
shiftDiff :: Char -> Char -> Char
shiftDiff c1 c2 = chr $ ((ord c2 - ord c1 - 1) `mod` range) + ord 'A'
{-# INLINE shiftDiff #-}

-- | Determines the Vigenère cipher representation of a 'Char'.
fromTableau :: Char -> Int
fromTableau c = ord c - ord 'A' + 1 `mod` range
{-# INLINE fromTableau #-}