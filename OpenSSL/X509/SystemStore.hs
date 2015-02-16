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
-- given @openssl@ context. Note that this does not automatically enable
-- peer certificate verification. You need to also call
-- 'OpenSSL.Session.contextSetVerificationMode' for that.
contextLoadSystemCerts :: SSLContext -> IO () 
contextLoadSystemCerts = S.contextLoadSystemCerts
{-# INLINE contextLoadSystemCerts #-}
