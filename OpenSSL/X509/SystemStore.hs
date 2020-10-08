{-# LANGUAGE CPP #-}

module OpenSSL.X509.SystemStore
    ( contextLoadSystemCerts
    ) where

import OpenSSL.Session (SSLContext)
#ifdef CABAL_OS_WINDOWS
import qualified OpenSSL.X509.SystemStore.Win32 as S
#elif defined(CABAL_OS_MACOSX)
import qualified OpenSSL.X509.SystemStore.MacOSX as S
#else
import qualified OpenSSL.X509.SystemStore.Unix as S
#endif

-- | Add the certificates from the system-wide certificate store to the
-- given 'SSLContext'.
--
-- Note that you also need to call 'OpenSSL.Session.contextSetVerificationMode'
-- and 'OpenSSL.Session.enableHostnameValidation' to enable proper
-- certificate validation.
contextLoadSystemCerts :: SSLContext -> IO () 
contextLoadSystemCerts = S.contextLoadSystemCerts
{-# INLINE contextLoadSystemCerts #-}
