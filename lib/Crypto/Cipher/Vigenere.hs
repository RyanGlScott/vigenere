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
module Crypto.Cipher.Vigenere (encrypt, decrypt) where

import           Data.Char (chr, ord)
import qualified Data.Text.Lazy as TL (Text, append, filter, null, toUpper, zipWith)

type Plaintext  = TL.Text
type Key        = TL.Text
type Ciphertext = TL.Text

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

crypt :: (Int -> Int -> Int) -> Key -> TL.Text -> TL.Text
crypt f k t = TL.zipWith (shift f) (cycleText (sanitize k)) (sanitize t)
{-# INLINE crypt #-}

sanitize :: TL.Text -> TL.Text
sanitize t = TL.filter (/= ' ') (TL.toUpper t)
{-# INLINE sanitize #-}

cycleText :: TL.Text -> TL.Text
cycleText t | TL.null t = error "empty text"
            | otherwise = t' where t' = TL.append t t'
{-# INLINE cycleText #-}

shift :: (Int -> Int -> Int) -> Char -> Char -> Char
shift f delta letter = chr $ ((f (ord letter - ord 'a') (convert delta)) `mod` range) + ord 'a'
{-# INLINE shift #-}

range :: Int
range = 26
{-# INLINE range #-}

convert :: Char -> Int
convert c = ord c - ord 'a' + 1 `mod` range
{-# INLINE convert #-}
