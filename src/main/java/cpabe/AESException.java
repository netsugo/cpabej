package cpabe;

import java.security.GeneralSecurityException;

public class AESException extends GeneralSecurityException {
    public AESException(String msg) {
        super(msg);
    }

    public AESException(String msg, Throwable t) {
        super(msg, t);
    }
}
