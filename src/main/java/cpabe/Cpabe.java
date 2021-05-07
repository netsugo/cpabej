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

    public byte[] encrypt(byte[] publicKey, String policy, byte[] plain) throws Exception {
        BswabePub pub = SerializeUtils.unserializeBswabePub(publicKey);
        BswabeCphKey keyCph = Bswabe.enc(pub, policy);
        BswabeCph cph = keyCph.cph;
        Element element = keyCph.key;
        if (cph == null) {
            throw new RuntimeException("Error happened while encrypting");
        } else {
            byte[] cphBuf = SerializeUtils.bswabeCphSerialize(cph);
            byte[] aesBuf = AESCoder.encrypt(element.toBytes(), plain);
            return packCpabe(cphBuf, aesBuf);
        }
    }

    private static byte[][] UnpackCpabe(byte[] packed) throws IOException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(packed)) {
            return Common.readCpabeData(inputStream);
        }
    }

    public byte[] decrypt(byte[] publicKey, byte[] privateKey, byte[] encrypted) throws Exception {
        int BUF_AES = 0;
        int BUF_CPH = 1;
        byte[][] tmp = UnpackCpabe(encrypted);
        byte[] aesBuf = tmp[BUF_AES];
        byte[] cphBuf = tmp[BUF_CPH];
        BswabePub pub = SerializeUtils.unserializeBswabePub(publicKey);
        BswabeCph cph = SerializeUtils.bswabeCphUnserialize(pub, cphBuf);
        BswabePrv prv = SerializeUtils.unserializeBswabePrv(pub, privateKey);

        BswabeElementBoolean beb = Bswabe.dec(pub, prv, cph);

        if (beb.b) {
            return AESCoder.decrypt(beb.e.toBytes(), aesBuf);
        } else {
            throw new RuntimeException("Decrypt error: " + beb.e.toString());
        }
    }
}
