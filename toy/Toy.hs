{-# LANGUAGE OverloadedStrings #-}
{-|
Module:      Toy.hs
Copyright:   (C) 2015 Ryan Scott
License:     GPL-3 (see the file LICENSE)
Maintainer:  Ryan Scott
Stability:   Provisional
Portability: GHC

A simple demonstration of Vigenère cipher encryption/decryption.

/Since: 0.1/
-}
module Main (main) where

import           Crypto.Cipher.Vigenere (encrypt, decrypt)

import           Data.Text.Lazy (pack)
import qualified Data.Text.Lazy.IO as TL (putStrLn)

import           System.Environment (getArgs)

main :: IO ()
main = getArgs >>= \args -> TL.putStrLn $ case args of
    "encrypt":m:k:_ -> encrypt (pack k) (pack m)
    "decrypt":c:k:_ -> decrypt (pack k) (pack c)
    _               -> "usage: ./toy {encrypt, decrypt} <text> <key>"
