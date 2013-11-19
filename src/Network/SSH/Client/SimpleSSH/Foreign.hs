{-# LANGUAGE ForeignFunctionInterface #-}

module Network.SSH.Client.SimpleSSH.Foreign where

import           Foreign.C.String
import           Foreign.C.Types
import           Foreign.Ptr

type CEither    = Ptr ()
newtype Session = Session (Ptr ())
type CResult    = Ptr ()
type CCount     = Ptr ()

foreign import ccall "simplessh_is_left"
  isLeftC :: CEither
          -> IO CInt

foreign import ccall "simplessh_get_error"
  getErrorC :: CEither
            -> IO CInt

foreign import ccall "simplessh_get_value"
  getValueC :: CEither
            -> IO (Ptr a)

foreign import ccall "simplessh_get_out"
  getOutC :: CResult
          -> IO CString

foreign import ccall "simplessh_get_err"
  getErrC :: CResult
          -> IO CString

foreign import ccall "simplessh_get_exit_code"
  getExitCodeC :: CResult
               -> IO CInt

foreign import ccall "simplessh_get_exit_signal"
  getExitSignalC :: CResult
                 -> IO CString

foreign import ccall "simplessh_get_count"
  getCountC :: CCount
            -> IO CInt

foreign import ccall "simplessh_free_either_result"
  freeEitherResultC :: CEither
                    -> IO ()

foreign import ccall "simplessh_free_either_count"
  freeEitherCountC :: CEither
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

foreign import ccall "simplessh_send_file"
  sendFileC :: Session
            -> CInt
            -> CString
            -> CString
            -> IO CEither

foreign import ccall "simplessh_close_session"
  closeSessionC :: Session
                -> IO ()
