package cpabe;

import bswabe.SerializeUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class Common {
    public static ByteArrayOutputStream writeCpabeData(byte[] mBuf, byte[] cphBuf, byte[] aesBuf) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        SerializeUtils.writeBytes(os, mBuf);
        SerializeUtils.writeBytes(os, aesBuf);
        SerializeUtils.writeBytes(os, cphBuf);
        return os;
    }

    public static byte[][] readCpabeData(InputStream is) throws IOException {
        byte[][] res = new byte[3][];
        byte[] mBuf = SerializeUtils.readBytes(is);
        byte[] aesBuf = SerializeUtils.readBytes(is);
        byte[] cphBuf = SerializeUtils.readBytes(is);

        res[0] = aesBuf;
        res[1] = cphBuf;
        res[2] = mBuf;
        return res;
    }


    public static byte[] packCpabe(byte[] cphBuf, byte[] aesBuf) throws IOException {
        // store data
        // mlen(4byte:int),mbuf,cphlen(4byte),cphbuf,aeslen(4byte),aesBuf
        byte[] mBuf = new byte[0];
        try (ByteArrayOutputStream stream = Common.writeCpabeData(mBuf, cphBuf, aesBuf)) {
            return stream.toByteArray();
        }
    }

    public static byte[][] UnpackCpabe(byte[] packed) throws IOException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(packed)) {
            return Common.readCpabeData(inputStream);
        }
    }
}
