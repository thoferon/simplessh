{-# LANGUAGE ForeignFunctionInterface #-}

module Network.SSH.Client.SimpleSSH
  ( SimpleSSHError(..)
  , openSessionWithPassword
  , execCommand
  , closeSession
  , withSessionPassword
  ) where

import Control.Applicative
import Control.Monad.Trans
import Control.Monad.Error

import Foreign.C.Types
import Foreign.C.String
import Foreign.Marshal.Alloc
import Foreign.Ptr

type CEither a  = Ptr a
newtype Session = Session (Ptr ())
newtype Result  = Result  (Ptr CChar)

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
  | Unknown
  deriving (Show, Eq)

instance Error SimpleSSHError where
  strMsg _ = Unknown

foreign import ccall "simplessh_is_left"
  isLeftC :: CEither a
          -> IO CInt

foreign import ccall "simplessh_get_error"
  getErrorC :: CEither a
            -> IO CInt

foreign import ccall "simplessh_get_value"
  getValueC :: CEither a
            -> IO (Ptr a)

foreign import ccall "simplessh_open_session_password"
  openSessionWithPasswordC :: CString
                           -> CUShort
                           -> CString
                           -> CString
                           -> CString
                           -> IO (CEither ())

foreign import ccall "simplessh_exec_command"
  execCommandC :: Session
               -> CString
               -> IO (CEither CChar)

foreign import ccall "simplessh_close_session"
  closeSessionC :: Session
                -> IO ()

readError :: CInt -> SimpleSSHError
readError err = case err of
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
  _  -> Unknown

getValue :: CEither a
         -> (Ptr a -> b)
         -> IO b
getValue eitherC build = do
  ptr <- getValueC eitherC
  return $ build ptr

getError :: CEither a -> IO SimpleSSHError
getError eitherC = readError <$> getErrorC eitherC

openSessionWithPassword :: String  -- ^ Hostname.
                        -> Integer -- ^ Port.
                        -> String  -- ^ Username.
                        -> String  -- ^ Password.
                        -> String  -- ^ Path to known_hosts.
                        -> SimpleSSH Session
openSessionWithPassword hostname port username password knownhostsPath = do
  eRes <- liftIO $ do
    (hostnameC, usernameC, passwordC, knownhostsPathC) <-
      (,,,) <$> newCString hostname
            <*> newCString username
            <*> newCString password
            <*> newCString knownhostsPath
    let portC = fromInteger port

    eitherC   <- openSessionWithPasswordC hostnameC portC usernameC passwordC knownhostsPathC
    checkLeft <- isLeftC eitherC
    mapM_ free [hostnameC, usernameC, passwordC, knownhostsPathC]

    if checkLeft == 0
      then Right <$> getValue eitherC Session
      else Left  <$> getError eitherC

  case eRes of
    Left err  -> throwError err
    Right res -> return res

execCommand :: Session -- ^ The session to use, see 'openSessionWithPassword'.
            -> String  -- ^ Command.
            -> SimpleSSH String
execCommand session command = do
  eRes <- liftIO $ do
    commandC <- newCString command
    eitherC  <- execCommandC session commandC
    free commandC

    checkLeft <- isLeftC eitherC
    if checkLeft == 0
      then Right <$> getValue eitherC Result
      else Left  <$> getError eitherC

  case eRes of
    Left err  -> throwError err
    Right res -> liftIO $ readResult res

readResult :: Result -> IO String
readResult (Result ptr) = do
  res <- peekCString ptr
  free ptr
  return res

closeSession :: Session -> SimpleSSH ()
closeSession = lift . closeSessionC

withSessionPassword :: String
                    -> Integer
                    -> String
                    -> String
                    -> String
                    -> (Session -> SimpleSSH a)
                    -> SimpleSSH a
withSessionPassword hostname port username password knownhostsPath action = do
  session <- openSessionWithPassword hostname port username password knownhostsPath
  res     <- action session
  closeSession session
  return res
