{-# LANGUAGE ForeignFunctionInterface #-}

module Network.SSH.Client.SimpleSSH
  ( SimpleSSHError(..)
  , Session
  , Result
  , openSession
  , authenticateWithPassword
  , authenticateWithKey
  , execCommand
  , closeSession
  , withSessionPassword
  , withSessionKey
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

foreign import ccall "simplessh_open_session"
  openSessionC :: CString
                           -> CUShort
                           -> CString
                           -> IO CEither

foreign import ccall "simplessh_authenticate_password"
  authenticatePasswordC :: Session
                        -> CString
                        -> CString
                        -> IO CEither

foreign import ccall "simplessh_authenticate_key"
  authenticateKeyC :: Session
                   -> CString
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

openSession :: String  -- ^ Hostname.
            -> Integer -- ^ Port.
            -> String  -- ^ Path to known_hosts.
            -> SimpleSSH Session
openSession hostname port knownhostsPath = do
  eRes <- liftIO $ do
    hostnameC       <- newCString hostname
    knownhostsPathC <- newCString knownhostsPath
    let portC = fromInteger port

    eitherC   <- openSessionC hostnameC portC knownhostsPathC
    checkLeft <- isLeftC eitherC

    free hostnameC
    free knownhostsPathC

    res <- if checkLeft == 0
      then Right <$> getValue eitherC Session
      else Left  <$> getError eitherC
    free eitherC
    return res

  case eRes of
    Left err  -> throwError err
    Right res -> return res

authenticateWithPassword :: Session
                         -> String
                         -> String
                         -> SimpleSSH Session
authenticateWithPassword session username password = do
  eRes <- liftIO $ do
    usernameC <- newCString username
    passwordC <- newCString password

    eitherC   <- authenticatePasswordC session usernameC passwordC
    checkLeft <- isLeftC eitherC

    free usernameC
    free passwordC

    res <- if checkLeft == 0
      then Right <$> getValue eitherC Session
      else Left  <$> getError eitherC
    free eitherC
    return res

  case eRes of
    Left err  -> throwError err
    Right res -> return res

authenticateWithKey :: Session
                    -> String
                    -> FilePath
                    -> FilePath
                    -> String
                    -> SimpleSSH Session
authenticateWithKey session username publicKeyPath privateKeyPath passphrase = do
  eRes <- liftIO $ do
    (usernameC, publicKeyPathC, privateKeyPathC, passphraseC) <-
      (,,,) <$> newCString username
            <*> newCString publicKeyPath
            <*> newCString privateKeyPath
            <*> newCString passphrase

    eitherC   <- authenticateKeyC session usernameC publicKeyPathC privateKeyPathC passphraseC
    checkLeft <- isLeftC eitherC

    mapM_ free [usernameC, publicKeyPathC, privateKeyPathC, passphraseC]

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

withSessionPassword :: String                   -- ^ Hostname
                    -> Integer                  -- ^ Port
                    -> String                   -- ^ Path to known_hosts
                    -> String                   -- ^ Username
                    -> String                   -- ^ Password
                    -> (Session -> SimpleSSH a) -- ^ Monadic action on the session
                    -> SimpleSSH a
withSessionPassword hostname port knownhostsPath username password action = do
  session              <- openSession hostname port knownhostsPath
  authenticatedSession <- authenticateWithPassword session username password
  res                  <- action authenticatedSession
  closeSession authenticatedSession
  return res

withSessionKey :: String                   -- ^ Hostname
               -> Integer                  -- ^ port
               -> String                   -- ^ Path to known_hosts
               -> String                   -- ^ Username
               -> String                   -- ^ Path to public key
               -> String                   -- ^ Path to private key
               -> String                   -- ^ Passphrase
               -> (Session -> SimpleSSH a) -- ^ Monadic action on the session
               -> SimpleSSH a
withSessionKey hostname port knownhostsPath username publicKeyPath privateKeyPath passphrase action = do
  session              <- openSession hostname port knownhostsPath
  authenticatedSession <- authenticateWithKey session username publicKeyPath privateKeyPath passphrase
  res                  <- action authenticatedSession
  closeSession authenticatedSession
  return res
