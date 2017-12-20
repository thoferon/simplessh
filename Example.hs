import Control.Monad.Trans

import System.Environment
import System.Exit
import System.IO

import Network.SSH.Client.SimpleSSH

action :: FilePath -> String -> String -> SimpleSSH ()
action home username host = do
  withSessionKey host 22 (home ++ "/.ssh/known_hosts") username
                 (home ++ "/.ssh/id_rsa.pub") (home ++ "/.ssh/id_rsa")
                 "" $ \session -> do
    res <- execCommand session "uname -a"
    liftIO $ print res

main :: IO ()
main = do
  username : host : _ <- getArgs
  Just home <- lookup "HOME" <$> getEnvironment
  eRes <- runSimpleSSH $ action home username host
  case eRes of
    Left err -> do
      hPutStrLn stderr $ "Error: " ++ show err
      exitFailure
    Right () -> return ()
