import cpabe.Cpabe;
import cpabe.EncryptException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class InvalidPolicyTest {
    private static void assertThrowsEncryptException(String policy) {
        byte[][] byteArrays = Cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> Cpabe.encrypt(pubkey, policy, plain));
    }

    @Test
    public void empty() {
        String policy = "";
        assertThrowsEncryptException(policy);
    }

    @Test
    public void space() {
        String policy = " ";
        assertThrowsEncryptException(policy);
    }

    @Test
    public void noOp() {
        String policy = "alice bob";
        assertThrowsEncryptException(policy);
    }

    @Test
    public void tooFew() {
        String policy = "alice bob david eve 2of5";
        assertThrowsEncryptException(policy);
    }

    @Test
    public void tooMany() {
        String policy = "alice bob david eve 2of3";
        assertThrowsEncryptException(policy);
    }

    @Test
    public void invalidSingle() {
        String policy = "alice 1of1";
        assertThrowsEncryptException(policy);
    }

    @Test
    public void unsatisfiableOp() {
        String policy = "alice bob david 3of2";
        assertThrowsEncryptException(policy);
    }

    @Test
    public void triviallySatisfiedOp() {
        String policy = "alice bob 0of2";
        assertThrowsEncryptException(policy);
    }
}
