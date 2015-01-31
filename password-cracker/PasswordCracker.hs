{-# LANGUAGE OverloadedStrings #-}
{-|
Module:      PasswordCracker.hs
Copyright:   (C) 2015 Ryan Scott
License:     GPL-3 (see the file LICENSE)
Maintainer:  Ryan Scott
Stability:   Provisional
Portability: GHC

A "password cracker" for passwords encoded with a Vigenère cipher.

/Since: 0.1/
-}
module Main (main) where

import           Control.Monad (guard)

import           Crypto.Cipher.Vigenere (Ciphertext, Key, Plaintext, decrypt)

import           Data.Foldable (for_)
import           Data.HashSet (HashSet, fromList, member)
import           Data.Int (Int64)
import           Data.Monoid ((<>))
import           Data.Text.Lazy (Text, cons, empty, pack)
import qualified Data.Text.Lazy    as TL (take)
import qualified Data.Text.Lazy.IO as TL (putStrLn)

import           Paths_vigenere (getDataDir)

import           System.Environment (getArgs)

main :: IO ()
main = getArgs >>= \args -> case args of
    ctxt:kl:fwl:_ -> do
        dict <- dictionary
        let kps = crackPassword (pack ctxt) (read kl) (read fwl) dict
        for_ kps $ \(key, ptxt) ->
            TL.putStrLn $ "Key: " <> key <> ", plaintext: " <> ptxt
    _ -> putStrLn "usage: ./password-cracker <ciphertext> <keyLength> <firstWordLength>"

crackPassword :: Ciphertext -> Int -> Int64 -> Dictionary -> [(Key, Plaintext)]
crackPassword ctxt kl fwl dict = do
    key <- lowercaseCombos kl
    let ptxt = decrypt key ctxt
    guard $ TL.take fwl ptxt `member` dict
    return (key, ptxt)

type Dictionary = HashSet Plaintext

dictionary :: IO Dictionary
dictionary = do
    dir  <- getDataDir
    dict <- readFile $ dir ++ "/dict/dict.txt"
    return . fromList . map pack $ splitLines dict

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

lowercaseCombos :: Int -> [Text]
lowercaseCombos = combos empty
  where
    combos :: Text -> Int -> [Text]
    combos q n | n <= 0    = [q]
               | otherwise = ['a'..'z'] >>= \c -> combos (cons c q) (n-1)