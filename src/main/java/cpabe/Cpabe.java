package cpabe;

import bswabe.*;
import it.unisa.dia.gas.jpbc.Element;

import java.security.NoSuchAlgorithmException;

public class Cpabe {

    /**
     * @param
     * @author Junwei Wang(wakemecn@gmail.com)
     */

    public static final int SETUP_PUBLIC = 0;
    public static final int SETUP_MASTER = 1;

    public static byte[][] setup() {
        BswabePub pub = new BswabePub();
        BswabeMsk msk = new BswabeMsk();
        Bswabe.setup(pub, msk);

        byte[] publicKey = SerializeUtils.serializeBswabePub(pub);
        byte[] masterKey = SerializeUtils.serializeBswabeMsk(msk);

        return new byte[][]{publicKey, masterKey};
    }

    public static byte[] keygen(byte[] publicKey, byte[] masterKey, String attribute) throws NoSuchAlgorithmException {
        BswabePub pub = SerializeUtils.unserializeBswabePub(publicKey);
        BswabeMsk msk = SerializeUtils.unserializeBswabeMsk(pub, masterKey);
        String[] parsedAttribute = LangPolicy.parseAttribute(attribute);
        BswabePrv prv = Bswabe.keygen(pub, msk, parsedAttribute);
        return SerializeUtils.serializeBswabePrv(prv);
    }

    public static byte[] encrypt(byte[] publicKey, String policy, byte[] plain) throws EncryptException {
        BswabePub pub = SerializeUtils.unserializeBswabePub(publicKey);

        try {
            BswabeCphKey keyCph = Bswabe.encrypt(pub, policy);
            BswabeCph cph = keyCph.cph;
            Element element = keyCph.key;

            byte[] cphBuf = SerializeUtils.serializeBswabeCph(cph);
            byte[] aesBuf = AESCoder.encrypt(element.toBytes(), plain);

            return Common.packCpabe(cphBuf, aesBuf);
        } catch (Exception e) {
            throw new EncryptException(e.getMessage(), e.getCause());
        }
    }

    public static byte[] decrypt(byte[] publicKey, byte[] privateKey, byte[] encrypted) throws DecryptException {
        int BUF_AES = 0;
        int BUF_CPH = 1;

        try {
            byte[][] tmp = Common.UnpackCpabe(encrypted);
            byte[] aesBuf = tmp[BUF_AES];
            byte[] cphBuf = tmp[BUF_CPH];
            BswabePub pub = SerializeUtils.unserializeBswabePub(publicKey);
            BswabeCph cph = SerializeUtils.unserializeBswabeCph(pub, cphBuf);
            BswabePrv prv = SerializeUtils.unserializeBswabePrv(pub, privateKey);

            Element e = Bswabe.decrypt(pub, prv, cph);
            return AESCoder.decrypt(e.toBytes(), aesBuf);
        } catch (Exception e) {
            throw new DecryptException(e.getMessage(), e.getCause());
        }
    }

    public static byte[] delegate(byte[] pubKey, byte[] oldSecret, String subAttributes) throws NoSuchAlgorithmException {
        BswabePub pub = SerializeUtils.unserializeBswabePub(pubKey);
        BswabePrv oldKey = SerializeUtils.unserializeBswabePrv(pub, oldSecret);
        String[] parsedAttribute = LangPolicy.parseAttribute(subAttributes);
        BswabePrv newKey = Bswabe.delegate(pub, oldKey, parsedAttribute);
        return SerializeUtils.serializeBswabePrv(newKey);
    }
}
