package bswabe;

import java.security.GeneralSecurityException;

public class ParseException extends GeneralSecurityException {
    public ParseException(String msg) {
        super(msg);
    }

    public ParseException(String msg, Throwable t) {
        super(msg, t);
    }

    public static ParseException create(String policy, String reason, String tok) {
        return new ParseException(String.format("Error parsing %s: %s %s", policy, reason, tok));
    }

    public static ParseException create(String policy, String reason) {
        return new ParseException(String.format("Error parsing '%s': %s", policy, reason));
    }
}
