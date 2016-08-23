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
-- given @openssl@ context. Note that
-- __this does not automatically enable peer certificate verification__.
-- You also need to call 'OpenSSL.Session.contextSetVerificationMode' and
-- __check manually if the hostname matches__ the one specified in the
-- certificate. You can find information about how to do the latter
-- <https://github.com/iSECPartners/ssl-conservatory/blob/master/openssl/everything-you-wanted-to-know-about-openssl.pdf here>.
contextLoadSystemCerts :: SSLContext -> IO () 
contextLoadSystemCerts = S.contextLoadSystemCerts
{-# INLINE contextLoadSystemCerts #-}
