package com.github.netsugo.cpabej;

import java.security.GeneralSecurityException;

public class EncryptException extends GeneralSecurityException {
    public EncryptException(String msg) {
        super(msg);
    }

    public EncryptException(String msg, Throwable t) {
        super(msg, t);
    }
}
