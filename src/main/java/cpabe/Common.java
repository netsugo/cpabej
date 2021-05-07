package cpabe;

import java.io.*;

public class Common {
    /**
     * Return a ByteArrayOutputStream instead of writing to a file
     */
    public static ByteArrayOutputStream writeCpabeData(byte[] mBuf, byte[] cphBuf, byte[] aesBuf) throws IOException {
        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            /* write m_buf */
            for (int i = 3; i >= 0; i--)
                os.write(((mBuf.length & (0xff << 8 * i)) >> 8 * i));
            os.write(mBuf);

            /* write aes_buf */
            for (int i = 3; i >= 0; i--)
                os.write(((aesBuf.length & (0xff << 8 * i)) >> 8 * i));
            os.write(aesBuf);

            /* write cph_buf */
            for (int i = 3; i >= 0; i--)
                os.write(((cphBuf.length & (0xff << 8 * i)) >> 8 * i));
            os.write(cphBuf);

            return os;
        }
    }

    /**
     * Read data from an InputStream instead of taking it from a file.
     */
    public static byte[][] readCpabeData(InputStream is) throws IOException {
        int len;

        byte[][] res = new byte[3][];
        byte[] mBuf, aesBuf, cphBuf;

        /* read m buf */
        len = 0;
        for (int i = 3; i >= 0; i--)
            len |= is.read() << (i * 8);
        mBuf = new byte[len];
        is.read(mBuf);
        /* read aes buf */
        len = 0;
        for (int i = 3; i >= 0; i--)
            len |= is.read() << (i * 8);
        aesBuf = new byte[len];
        is.read(aesBuf);

        /* read cph buf */
        len = 0;
        for (int i = 3; i >= 0; i--)
            len |= is.read() << (i * 8);
        cphBuf = new byte[len];
        is.read(cphBuf);

        res[0] = aesBuf;
        res[1] = cphBuf;
        res[2] = mBuf;
        return res;
    }
}
