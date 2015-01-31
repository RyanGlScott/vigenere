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

import           Crypto.Cipher.Vigenere (Ciphertext, Key, Plaintext,
                                         encrypt, decrypt, keyFrom)

import           Data.Foldable (for_)
import           Data.HashSet (HashSet, fromList, member, size, toList)
import qualified Data.HashSet as HS (filter)
import           Data.Int (Int64)
import           Data.Monoid ((<>))
import           Data.Text.Lazy (Text, cons, empty, pack)
import qualified Data.Text.Lazy    as TL (length, take)
import qualified Data.Text.Lazy.IO as TL (putStrLn)

import           Paths_vigenere (getDataDir)

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
            
            naive :: Bool
            naive = 26^kl' < size dict'
            
            cpass :: PasswordCracker
            cpass = if naive then crackPasswordNaive else crackPasswordClever
            
            kps :: [(Key, Plaintext)]
            kps = cpass ctxt' kl' fwl' dict'
        for_ kps $ \(key, ptxt) ->
            TL.putStrLn $ "Key: " <> key <> ", plaintext: " <> ptxt
    _ -> putStrLn "usage: ./password-cracker <ciphertext> <keyLength> <firstWordLength>"

crackPasswordNaive :: PasswordCracker
crackPasswordNaive ctxt kl fwl dict = do
    key <- lowercaseCombos kl
    let ptxt = decrypt key ctxt
    guard $ TL.take fwl ptxt `member` dict
    return (key, ptxt)

crackPasswordClever :: PasswordCracker
crackPasswordClever ctxt kl fwl dict = do
    pDictWord <- toList dict
    let key       = keyFrom pDictWord ctxt kl
        cDictWord = encrypt key pDictWord
    guard $ cDictWord == (TL.take fwl ctxt)
    return (key, decrypt key ctxt)

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

lowercaseCombos :: Int64 -> [Text]
lowercaseCombos = combos empty
  where
    combos :: Text -> Int64 -> [Text]
    combos q n | n <= 0    = [q]
               | otherwise = ['a'..'z'] >>= \c -> combos (cons c q) (n-1)