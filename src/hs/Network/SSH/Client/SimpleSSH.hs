{-# LANGUAGE ForeignFunctionInterface #-}

module Network.SSH.Client.SimpleSSH
  ( SimpleSSHError(..)
  , Session
  , Result
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

type CEither    = Ptr ()
newtype Session = Session (Ptr ())
newtype CResult = CResult (Ptr ())
data Result = Result
  { content  :: String
  , exitCode :: Integer
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
  | Unknown
  deriving (Show, Eq)

instance Error SimpleSSHError where
  strMsg _ = Unknown

foreign import ccall "simplessh_is_left"
  isLeftC :: CEither
          -> IO CInt

foreign import ccall "simplessh_get_error"
  getErrorC :: CEither
            -> IO CInt

foreign import ccall "simplessh_get_value"
  getValueC :: CEither
            -> IO (Ptr a)

foreign import ccall "simplessh_get_content"
  getContentC :: CResult
              -> IO CString

foreign import ccall "simplessh_get_exit_code"
  getExitCodeC :: CResult
               -> IO CInt

foreign import ccall "simplessh_free_either_result"
  freeEitherResultC :: CEither
                    -> IO ()

foreign import ccall "simplessh_open_session_password"
  openSessionWithPasswordC :: CString
                           -> CUShort
                           -> CString
                           -> CString
                           -> CString
                           -> IO CEither

foreign import ccall "simplessh_exec_command"
  execCommandC :: Session
               -> CString
               -> IO CEither

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

getValue :: CEither
         -> (Ptr () -> b)
         -> IO b
getValue eitherC build = do
  ptr <- getValueC eitherC
  return $ build ptr

getError :: CEither -> IO SimpleSSHError
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

    res <- if checkLeft == 0
      then Right <$> getValue eitherC Session
      else Left  <$> getError eitherC
    free eitherC
    return res

  case eRes of
    Left err  -> throwError err
    Right res -> return res

execCommand :: Session -- ^ The session to use, see 'openSessionWithPassword'.
            -> String  -- ^ Command.
            -> SimpleSSH Result
execCommand session command = do
  eRes <- liftIO $ do
    commandC <- newCString command
    eitherC  <- execCommandC session commandC
    free commandC

    checkLeft <- isLeftC eitherC
    res <- if checkLeft == 0
      then Right <$> (getValue eitherC CResult >>= readResult)
      else Left  <$> getError eitherC

    freeEitherResultC eitherC
    return res

  finalRes <- case eRes of
    Left err  -> throwError err
    Right res -> return res

  return finalRes

getContent :: CResult -> IO String
getContent ptr = do
  contentPtr <- getContentC ptr
  peekCString contentPtr

getExitCode :: CResult -> IO Integer
getExitCode ptr = toInteger <$> getExitCodeC ptr

readResult :: CResult -> IO Result
readResult resultC =  Result
                  <$> getContent  resultC
                  <*> getExitCode resultC

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
