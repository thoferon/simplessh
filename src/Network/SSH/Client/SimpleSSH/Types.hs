module Network.SSH.Client.SimpleSSH.Types
  ( Result(..)
  , ResultExit(..)
  , SimpleSSH
  , SimpleSSHError(..)
  , runSimpleSSH
  , readError
  ) where

import           Control.Monad.Error

import qualified Data.ByteString.Char8 as BS

import           Foreign.C.Types

-- | Exit code or signal of a process.
data ResultExit
  = ExitSuccess
  | ExitFailure Integer
  | ExitSignal BS.ByteString
  deriving (Show, Eq)

-- | The result of a command execution.
data Result = Result
  { resultOut  :: BS.ByteString -- ^ The process' stdout
  , resultErr  :: BS.ByteString -- ^ The process' stderr
  , resultExit :: ResultExit    -- ^ The process' exit code or signal
  } deriving (Show, Eq)

type SimpleSSH a = ErrorT SimpleSSHError IO a

runSimpleSSH :: SimpleSSH a -> IO (Either SimpleSSHError a)
runSimpleSSH = runErrorT

data SimpleSSHError
  = Connect
  | Init
  | Handshake
  | KnownhostsInit
  | KnownhostsHostkey
  | KnownhostsCheck
  | Authentication
  | ChannelOpen
  | ChannelExec
  | Read
  | FileOpen
  | Write
  | Unknown
  deriving (Show, Eq)

instance Error SimpleSSHError where
  strMsg _ = Unknown

readError :: CInt -> SimpleSSHError
readError errNum = case errNum of
  1  -> Connect
  2  -> Init
  3  -> Handshake
  4  -> KnownhostsInit
  5  -> KnownhostsHostkey
  6  -> KnownhostsCheck
  7  -> Authentication
  8  -> ChannelOpen
  9  -> ChannelExec
  10 -> Read
  11 -> FileOpen
  12 -> Write
  _  -> Unknown
