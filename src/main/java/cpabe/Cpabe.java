package cpabe;

import bswabe.*;
import it.unisa.dia.gas.jpbc.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class Cpabe {

    /**
     * @param
     * @author Junwei Wang(wakemecn@gmail.com)
     */

    public static final int SETUP_PUBLIC = 0;
    public static final int SETUP_MASTER = 1;

    public byte[][] setup() {
        BswabePub pub = new BswabePub();
        BswabeMsk msk = new BswabeMsk();
        Bswabe.setup(pub, msk);

        byte[] publicKey = SerializeUtils.serializeBswabePub(pub);
        byte[] masterKey = SerializeUtils.serializeBswabeMsk(msk);

        return new byte[][]{publicKey, masterKey};
    }

    public byte[] keygen(byte[] publicKey, byte[] masterKey, String attribute) throws NoSuchAlgorithmException {
        BswabePub pub = SerializeUtils.unserializeBswabePub(publicKey);
        BswabeMsk msk = SerializeUtils.unserializeBswabeMsk(pub, masterKey);
        String[] parsedAttribute = LangPolicy.parseAttribute(attribute);
        BswabePrv prv = Bswabe.keygen(pub, msk, parsedAttribute);
        return SerializeUtils.serializeBswabePrv(prv);
    }

    private static byte[] packCpabe(byte[] cphBuf, byte[] aesBuf) throws IOException {
        // store data
        // mlen(4byte:int),mbuf,cphlen(4byte),cphbuf,aeslen(4byte),aesBuf
        byte[] mBuf = new byte[0];
        try (ByteArrayOutputStream stream = Common.writeCpabeData(mBuf, cphBuf, aesBuf)) {
            return stream.toByteArray();
        }
    }

    public byte[] encrypt(byte[] publicKey, String policy, byte[] plain) throws EncryptException {
        BswabePub pub = SerializeUtils.unserializeBswabePub(publicKey);

        try {
            BswabeCphKey keyCph = Bswabe.encrypt(pub, policy);
            BswabeCph cph = keyCph.cph;
            Element element = keyCph.key;

            byte[] cphBuf = SerializeUtils.bswabeCphSerialize(cph);
            byte[] aesBuf = AESCoder.encrypt(element.toBytes(), plain);

            return packCpabe(cphBuf, aesBuf);
        } catch (Exception e) {
            throw new EncryptException(e.getMessage(), e.getCause());
        }
    }

    private static byte[][] UnpackCpabe(byte[] packed) throws IOException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(packed)) {
            return Common.readCpabeData(inputStream);
        }
    }

    public byte[] decrypt(byte[] publicKey, byte[] privateKey, byte[] encrypted) throws DecryptException {
        int BUF_AES = 0;
        int BUF_CPH = 1;

        try {
            byte[][] tmp = UnpackCpabe(encrypted);
            byte[] aesBuf = tmp[BUF_AES];
            byte[] cphBuf = tmp[BUF_CPH];
            BswabePub pub = SerializeUtils.unserializeBswabePub(publicKey);
            BswabeCph cph = SerializeUtils.bswabeCphUnserialize(pub, cphBuf);
            BswabePrv prv = SerializeUtils.unserializeBswabePrv(pub, privateKey);

            Element e = Bswabe.decrypt(pub, prv, cph);
            return AESCoder.decrypt(e.toBytes(), aesBuf);
        } catch (Exception e) {
            throw new DecryptException(e.getMessage(), e.getCause());
        }
    }

    public byte[] delegate(byte[] pubKey, byte[] oldSecret, String subAttributes) throws NoSuchAlgorithmException {
        BswabePub pub = SerializeUtils.unserializeBswabePub(pubKey);
        BswabePrv oldKey = SerializeUtils.unserializeBswabePrv(pub, oldSecret);
        String[] parsedAttribute = LangPolicy.parseAttribute(subAttributes);
        BswabePrv newKey = Bswabe.delegate(pub, oldKey, parsedAttribute);
        return SerializeUtils.serializeBswabePrv(newKey);
    }
}
