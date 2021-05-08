import cpabe.Cpabe;
import cpabe.DecryptException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class IntegrationTest {
    @Test
    public void singlePolicy() throws Exception {
        byte[][] byteArrays = Cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];
        byte[] master = byteArrays[Cpabe.SETUP_MASTER];

        String attrAlice = "alice";
        String attrBob = "bob";
        String policy = "alice";
        byte[] plain = "hello".getBytes();

        byte[] secretAlice = Cpabe.keygen(pubkey, master, attrAlice);
        byte[] secretBob = Cpabe.keygen(pubkey, master, attrBob);

        byte[] encrypted = Cpabe.encrypt(pubkey, policy, plain);

        Assertions.assertArrayEquals(plain, Cpabe.decrypt(pubkey, secretAlice, encrypted));
        Assertions.assertThrows(DecryptException.class, () -> Cpabe.decrypt(pubkey, secretBob, encrypted));
    }

    @Test
    public void multipleOrPolicy() throws Exception {
        byte[][] byteArrays = Cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];
        byte[] master = byteArrays[Cpabe.SETUP_MASTER];

        String attrAlice = "alice";
        String attrBob = "bob";
        String attrDavid = "david";
        String policy = "alice bob 1of2";
        byte[] plain = "hello".getBytes();

        byte[] secretAlice = Cpabe.keygen(pubkey, master, attrAlice);
        byte[] secretBob = Cpabe.keygen(pubkey, master, attrBob);
        byte[] secretDavid = Cpabe.keygen(pubkey, master, attrDavid);

        byte[] encrypted = Cpabe.encrypt(pubkey, policy, plain);

        Assertions.assertArrayEquals(plain, Cpabe.decrypt(pubkey, secretAlice, encrypted));
        Assertions.assertArrayEquals(plain, Cpabe.decrypt(pubkey, secretBob, encrypted));
        Assertions.assertThrows(DecryptException.class, () -> Cpabe.decrypt(pubkey, secretDavid, encrypted));
    }
}
