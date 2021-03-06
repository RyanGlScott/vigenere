{-# LANGUAGE OverloadedStrings #-}
{-|
Module:      PasswordCracker.hs
Copyright:   (C) 2015 Ryan Scott
License:     GPL-3
Maintainer:  Ryan Scott
Stability:   Provisional
Portability: GHC

A "password cracker" for passwords encoded with a Vigenère cipher.

/Since: 0.1/
-}
module Main (main) where

import           Control.Monad (guard)

import           Data.Char (chr, ord)
import           Data.Foldable (for_)
import           Data.HashSet (HashSet, fromList, member, size, toList)
import qualified Data.HashSet as HS (filter)
import           Data.Int (Int64)
import           Data.Monoid ((<>))
import           Data.Text.Lazy (Text, cons, empty, pack)
import qualified Data.Text.Lazy as TL (append, filter, length, null,
                                       take, toUpper, zipWith)
import qualified Data.Text.Lazy.IO as TL (putStrLn)

import           System.Environment (getArgs)

type Dictionary = HashSet Plaintext
type PasswordCracker = Ciphertext -> Int64 -> Int64 -> Dictionary -> [(Key, Plaintext)]

main :: IO ()
main = getArgs >>= \args -> case args of
    ctxt:kl:fwl:_ -> do
        dict <- dictionary
        let ctxt' :: Text
            ctxt' = pack ctxt
            
            kl' :: Int64
            kl' = read kl
            
            fwl' :: Int64
            fwl' = read fwl
            
            dict' :: Dictionary
            dict' = HS.filter ((== fwl') . TL.length) dict
            
            -- Determine if the keyspace or dictionary-space is smaller
            naive :: Bool
            naive = 26^kl' < size dict'
            
            cpass :: PasswordCracker
            cpass = if naive then crackPasswordNaive else crackPasswordClever
            
            kps :: [(Key, Plaintext)]
            kps = cpass ctxt' kl' fwl' dict'
        for_ kps $ \(key, ptxt) ->
            TL.putStrLn $ "Key: " <> key <> ", plaintext: " <> ptxt
    _ -> putStrLn "usage: ./password-cracker <ciphertext> <keyLength> <firstWordLength>"

-- | The brute-force algorithm, in which every possible key is considered.
crackPasswordNaive :: PasswordCracker
crackPasswordNaive ctxt kl fwl dict = do
    key <- lowercaseCombos kl
    let ptxt = decrypt key ctxt
    guard $ TL.take fwl ptxt `member` dict
    return (key, ptxt)

-- | A modified algorithm in which every dictionary word of the given length is
-- considered, using the word and the ciphertext to reverse-engineer a key.
crackPasswordClever :: PasswordCracker
crackPasswordClever ctxt kl fwl dict = do
    pDictWord <- toList dict
    let key       = keyFrom pDictWord ctxt kl
        cDictWord = encrypt key pDictWord -- A partially encrypted ciphertext, used as a litmus test
    -- Since the Vigenère cipher cycles after the length of the key, we need only
    -- test the ciphertext up to the length of the key
    guard $ cDictWord == (TL.take fwl ctxt)
    return (key, decrypt key ctxt)

dictionary :: IO Dictionary
dictionary = fmap (fromList . map pack . splitLines) $ readFile "dict.txt"

-- | Breaks a string on newlines (including Windows-style \r\n newlines, which are
-- annoyingly common).
splitLines :: String -> [String]
splitLines [] = []
splitLines cs =
    let (pre, suf) = break isLineTerminator cs
    in  pre : case suf of 
                ('\r':'\n':rest) -> splitLines rest
                ('\r':rest)      -> splitLines rest
                ('\n':rest)      -> splitLines rest
                _                -> []

isLineTerminator :: Char -> Bool
isLineTerminator c = c == '\r' || c == '\n'

-- | Generates all possible keys of a given length.
lowercaseCombos :: Int64 -> [Text]
lowercaseCombos = combos empty
  where
    combos :: Text -> Int64 -> [Text]
    combos q n | n <= 0    = [q]
               | otherwise = ['a'..'z'] >>= \c -> combos (cons c q) (n-1)

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