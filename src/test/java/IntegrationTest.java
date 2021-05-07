import cpabe.Cpabe;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class IntegrationTest {
    @Test
    public void singlePolicy() throws Exception {
        Cpabe cpabe = new Cpabe();
        byte[][] byteArrays = cpabe.setup();
        byte[] pubkey = byteArrays[Cpabe.SETUP_PUBLIC];
        byte[] master = byteArrays[Cpabe.SETUP_MASTER];

        String attrAlice = "alice";
        String attrBob = "bob";
        String policy = "alice";
        byte[] plain = "hello".getBytes();

        byte[] secretAlice = cpabe.keygen(pubkey, master, attrAlice);
        byte[] secretBob = cpabe.keygen(pubkey, master, attrBob);

        byte[] encrypted = cpabe.encrypt(pubkey, policy, plain);

        Assertions.assertArrayEquals(plain, cpabe.decrypt(pubkey, secretAlice, encrypted));
        Assertions.assertThrows(Exception.class, () -> cpabe.decrypt(pubkey, secretBob, encrypted));
    }
}
