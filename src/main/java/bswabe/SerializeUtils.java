package bswabe;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;

public class SerializeUtils {

    /* Method has been test okay */
    public static void serializeElement(ArrayList<Byte> list, Element e) {
        byte[] arr_e = e.toBytes();
        serializeUint32(list, arr_e.length);
        byteArrListAppend(list, arr_e);
    }

    /* Method has been test okay */
    public static int unserializeElement(byte[] arr, int offset, Element e) {
        int len = unserializeUint32(arr, offset);
        byte[] e_byte = new byte[(int) len];
        offset += 4;
        System.arraycopy(arr, offset, e_byte, 0, len);
        e.setFromBytes(e_byte);

        return offset + len;
    }

    public static void serializeString(ArrayList<Byte> list, String s) {
        byte[] b = s.getBytes();
        serializeUint32(list, b.length);
        byteArrListAppend(list, b);
    }

    /*
     * Usage:
     *
     * StringBuffer sb = new StringBuffer("");
     *
     * offset = unserializeString(arr, offset, sb);
     *
     * String str = sb.substring(0);
     */
    public static int unserializeString(byte[] arr, int offset, StringBuffer sb) {
        int len = unserializeUint32(arr, offset);
        offset += 4;
        byte[] str_byte = new byte[len];
        System.arraycopy(arr, offset, str_byte, 0, len);

        sb.append(new String(str_byte));
        return offset + len;
    }

    public static byte[] serializeBswabePub(BswabePub pub) {
        ArrayList<Byte> list = new ArrayList<>();

        serializeString(list, pub.pairingDesc);
        serializeElement(list, pub.g);
        serializeElement(list, pub.h);
        serializeElement(list, pub.gp);
        serializeElement(list, pub.g_hat_alpha);

        return Byte_arr2byte_arr(list);
    }

    public static BswabePub unserializeBswabePub(byte[] b) {
        BswabePub pub = new BswabePub();
        int offset = 0;

        StringBuffer sb = new StringBuffer("");
        offset = unserializeString(b, offset, sb);
        pub.pairingDesc = sb.substring(0);

        CurveParameters params = new DefaultCurveParameters()
                .load(new ByteArrayInputStream(pub.pairingDesc.getBytes()));
        pub.p = PairingFactory.getPairing(params);
        Pairing pairing = pub.p;

        pub.g = pairing.getG1().newElement();
        pub.h = pairing.getG1().newElement();
        pub.gp = pairing.getG2().newElement();
        pub.g_hat_alpha = pairing.getGT().newElement();

        offset = unserializeElement(b, offset, pub.g);
        offset = unserializeElement(b, offset, pub.h);
        offset = unserializeElement(b, offset, pub.gp);
        offset = unserializeElement(b, offset, pub.g_hat_alpha);

        return pub;
    }

    /* Method has been test okay */
    public static byte[] serializeBswabeMsk(BswabeMsk msk) {
        ArrayList<Byte> list = new ArrayList<>();

        serializeElement(list, msk.beta);
        serializeElement(list, msk.g_alpha);

        return Byte_arr2byte_arr(list);
    }

    /* Method has been test okay */
    public static BswabeMsk unserializeBswabeMsk(BswabePub pub, byte[] b) {
        int offset = 0;
        BswabeMsk msk = new BswabeMsk();

        msk.beta = pub.p.getZr().newElement();
        msk.g_alpha = pub.p.getG2().newElement();

        offset = unserializeElement(b, offset, msk.beta);
        offset = unserializeElement(b, offset, msk.g_alpha);

        return msk;
    }

    /* Method has been test okay */
    public static byte[] serializeBswabePrv(BswabePrv prv) {
        ArrayList<Byte> list = new ArrayList<>();
        int prvCompsLen = prv.comps.size();
        serializeElement(list, prv.d);
        serializeUint32(list, prvCompsLen);

        for (int i = 0; i < prvCompsLen; i++) {
            serializeString(list, prv.comps.get(i).attr);
            serializeElement(list, prv.comps.get(i).d);
            serializeElement(list, prv.comps.get(i).dp);
        }

        return Byte_arr2byte_arr(list);
    }

    /* Method has been test okay */
    public static BswabePrv unserializeBswabePrv(BswabePub pub, byte[] b) {
        BswabePrv prv = new BswabePrv();
        int offset = 0;

        prv.d = pub.p.getG2().newElement();
        offset = unserializeElement(b, offset, prv.d);

        prv.comps = new ArrayList<>();
        int len = unserializeUint32(b, offset);
        offset += 4;

        for (int i = 0; i < len; i++) {
            BswabePrvComp c = new BswabePrvComp();

            StringBuffer sb = new StringBuffer("");
            offset = unserializeString(b, offset, sb);
            c.attr = sb.substring(0);

            c.d = pub.p.getG2().newElement();
            c.dp = pub.p.getG2().newElement();

            offset = unserializeElement(b, offset, c.d);
            offset = unserializeElement(b, offset, c.dp);

            prv.comps.add(c);
        }

        return prv;
    }

    public static byte[] bswabeCphSerialize(BswabeCph cph) {
        ArrayList<Byte> list = new ArrayList<>();
        SerializeUtils.serializeElement(list, cph.cs);
        SerializeUtils.serializeElement(list, cph.c);
        SerializeUtils.serializePolicy(list, cph.p);

        return Byte_arr2byte_arr(list);
    }

    public static BswabeCph bswabeCphUnserialize(BswabePub pub, byte[] cphBuf) {
        BswabeCph cph = new BswabeCph();
        int offset = 0;
        int[] offset_arr = new int[1];

        cph.cs = pub.p.getGT().newElement();
        cph.c = pub.p.getG1().newElement();

        offset = SerializeUtils.unserializeElement(cphBuf, offset, cph.cs);
        offset = SerializeUtils.unserializeElement(cphBuf, offset, cph.c);

        offset_arr[0] = offset;
        cph.p = SerializeUtils.unserializePolicy(pub, cphBuf, offset_arr);
        offset = offset_arr[0];

        return cph;
    }

    /* Method has been test okay */
    /* potential problem: the number to be serialize is less than 2^31 */
    private static void serializeUint32(ArrayList<Byte> list, int k) {
        for (int i = 3; i >= 0; i--) {
            byte b = (byte) ((k & (0x000000ff << (i * 8))) >> (i * 8));
            list.add(b);
        }
    }

    /*
     * Usage:
     *
     * You have to do offset+=4 after call this method
     */
    /* Method has been test okay */
    private static int unserializeUint32(byte[] arr, int offset) {
        int r = 0;

        for (int i = 3; i >= 0; i--)
            r |= (byte2int(arr[offset++])) << (i * 8);
        return r;
    }

    private static void serializePolicy(ArrayList<Byte> list, BswabePolicy p) {
        serializeUint32(list, p.k);

        if (p.children == null || p.children.length == 0) {
            serializeUint32(list, 0);
            serializeString(list, p.attr);
            serializeElement(list, p.c);
            serializeElement(list, p.cp);
        } else {
            serializeUint32(list, p.children.length);
            for (int i = 0; i < p.children.length; i++)
                serializePolicy(list, p.children[i]);
        }
    }

    private static BswabePolicy unserializePolicy(BswabePub pub, byte[] arr,
                                                  int[] offset) {
        BswabePolicy p = new BswabePolicy();
        p.k = unserializeUint32(arr, offset[0]);
        offset[0] += 4;
        p.attr = null;

        /* children */
        int n = unserializeUint32(arr, offset[0]);
        offset[0] += 4;
        if (n == 0) {
            p.children = null;

            StringBuffer sb = new StringBuffer("");
            offset[0] = unserializeString(arr, offset[0], sb);
            p.attr = sb.substring(0);

            p.c = pub.p.getG1().newElement();
            p.cp = pub.p.getG1().newElement();

            offset[0] = unserializeElement(arr, offset[0], p.c);
            offset[0] = unserializeElement(arr, offset[0], p.cp);
        } else {
            p.children = new BswabePolicy[n];
            for (int i = 0; i < n; i++)
                p.children[i] = unserializePolicy(pub, arr, offset);
        }

        return p;
    }

    private static int byte2int(byte b) {
        if (b >= 0)
            return b;
        return (256 + b);
    }

    private static void byteArrListAppend(ArrayList<Byte> list, byte[] b) {
        for (byte value : b) list.add(value);
    }

    private static byte[] Byte_arr2byte_arr(ArrayList<Byte> B) {
        int len = B.size();
        byte[] b = new byte[len];

        for (int i = 0; i < len; i++)
            b[i] = B.get(i);

        return b;
    }

}
