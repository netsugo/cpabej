import cpabe.Cpabe;
import cpabe.EncryptException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class InvalidPolicyTest {
    @Test
    public void empty() {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];

        String policy = "";
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> cpabe.encrypt(pubkey, policy, plain));
    }

    @Test
    public void space() {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];

        String policy = " ";
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> cpabe.encrypt(pubkey, policy, plain));
    }

    @Test
    public void noOp() {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];

        String policy = "alice bob";
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> cpabe.encrypt(pubkey, policy, plain));
    }

    @Test
    public void tooFew() {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];

        String policy = "alice bob david eve 2of5";
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> cpabe.encrypt(pubkey, policy, plain));
    }

    @Test
    public void tooMany() {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];

        String policy = "alice bob david eve 2of3";
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> cpabe.encrypt(pubkey, policy, plain));
    }

    @Test
    public void invalidSingle() {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];

        String policy = "alice 1of1";
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> cpabe.encrypt(pubkey, policy, plain));
    }

    @Test
    public void unsatisfiableOp() {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];

        String policy = "alice bob david 3of2";
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> cpabe.encrypt(pubkey, policy, plain));
    }

    @Test
    public void triviallySatisfiedOp() {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];

        String policy = "alice bob 0of2";
        byte[] plain = "hello".getBytes();

        Assertions.assertThrows(EncryptException.class, () -> cpabe.encrypt(pubkey, policy, plain));
    }
}
