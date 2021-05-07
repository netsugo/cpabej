package cpabe;

import java.security.GeneralSecurityException;

public class DecryptException extends GeneralSecurityException {
    public DecryptException(String msg) {
        super(msg);
    }

    public DecryptException(String msg, Throwable t) {
        super(msg, t);
    }
}
