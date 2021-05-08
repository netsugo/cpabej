package bswabe;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class SerializeUtils {
    private static void writeInt(OutputStream stream, int i) throws IOException {
        byte[] data = ByteBuffer.allocate(4).putInt(i).array();
        stream.write(data);
    }

    private static int readInt(InputStream stream) throws IOException {
        byte[] lenInfo = new byte[4];
        stream.read(lenInfo);
        return ByteBuffer.wrap(lenInfo).getInt();
    }

    private static void writeBytes(OutputStream stream, byte[] data) throws IOException {
        writeInt(stream, data.length);
        stream.write(data);
    }

    private static byte[] readBytes(InputStream stream) throws IOException {
        int len = readInt(stream);
        byte[] data = new byte[len];
        stream.read(data);

        return data;
    }

    private static void serializeElement(OutputStream stream, Element e) throws IOException {
        writeBytes(stream, e.toBytes());
    }

    private static Element unserializeElement(InputStream stream, Field field) throws IOException {
        byte[] data = readBytes(stream);
        Element e = field.newElement();
        e.setFromBytes(data);
        return e;
    }

    private static void serializeString(OutputStream stream, String s) throws IOException {
        byte[] data = s.getBytes();
        writeBytes(stream, data);
    }

    private static String unserializeString(InputStream stream) throws IOException {
        byte[] data = readBytes(stream);
        return new String(data);
    }

    public static byte[] serializeBswabePub(BswabePub pub) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try {
            serializeString(stream, pub.pairingDesc);
            serializeElement(stream, pub.g);
            serializeElement(stream, pub.h);
            serializeElement(stream, pub.gp);
            serializeElement(stream, pub.g_hat_alpha);

            return stream.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    public static BswabePub unserializeBswabePub(byte[] b) {
        ByteArrayInputStream stream = new ByteArrayInputStream(b);

        try {
            String paringDesc = unserializeString(stream);

            CurveParameters params = new DefaultCurveParameters()
                    .load(new ByteArrayInputStream(paringDesc.getBytes()));
            Pairing pairing = PairingFactory.getPairing(params);

            Element g = unserializeElement(stream, pairing.getG1());
            Element h = unserializeElement(stream, pairing.getG1());
            Element gp = unserializeElement(stream, pairing.getG2());
            Element g_hat_alpha = unserializeElement(stream, pairing.getGT());

            BswabePub pub = new BswabePub();
            pub.pairingDesc = paringDesc;
            pub.p = pairing;
            pub.g = g;
            pub.h = h;
            pub.gp = gp;
            pub.g_hat_alpha = g_hat_alpha;

            return pub;
        } catch (IOException e) {
            return null;
        }
    }

    /* Method has been test okay */
    public static byte[] serializeBswabeMsk(BswabeMsk msk) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try {
            serializeElement(stream, msk.beta);
            serializeElement(stream, msk.g_alpha);

            return stream.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    /* Method has been test okay */
    public static BswabeMsk unserializeBswabeMsk(BswabePub pub, byte[] b) {
        ByteArrayInputStream stream = new ByteArrayInputStream(b);

        try {
            Pairing pairing = pub.p;
            Element beta = unserializeElement(stream, pairing.getZr());
            Element g_alpha = unserializeElement(stream, pub.p.getG2());

            BswabeMsk msk = new BswabeMsk();
            msk.beta = beta;
            msk.g_alpha = g_alpha;
            return msk;
        } catch (IOException e) {
            return null;
        }
    }

    /* Method has been test okay */
    public static byte[] serializeBswabePrv(BswabePrv prv) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try {
            serializeElement(stream, prv.d);
            writeInt(stream, prv.comps.size());

            for (BswabePrvComp comp : prv.comps) {
                serializeString(stream, comp.attr);
                serializeElement(stream, comp.d);
                serializeElement(stream, comp.dp);
            }

            return stream.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    /* Method has been test okay */
    public static BswabePrv unserializeBswabePrv(BswabePub pub, byte[] b) {
        ByteArrayInputStream stream = new ByteArrayInputStream(b);

        try {
            Pairing pairing = pub.p;
            Element prv_d = unserializeElement(stream, pairing.getG2());
            int len = readInt(stream);
            ArrayList<BswabePrvComp> components = new ArrayList<>();

            for (int i = 0; i < len; i++) {
                String attr = unserializeString(stream);
                Element d = unserializeElement(stream, pairing.getG2());
                Element dp = unserializeElement(stream, pairing.getG2());

                BswabePrvComp c = new BswabePrvComp();
                c.attr = attr;
                c.d = d;
                c.dp = dp;
                components.add(c);
            }

            BswabePrv prv = new BswabePrv();
            prv.d = prv_d;
            prv.comps = components;
            return prv;
        } catch (IOException e) {
            return null;
        }
    }


    private static void serializePolicy(OutputStream stream, BswabePolicy policy) throws IOException {
        writeInt(stream, policy.k);

        BswabePolicy[] policies = policy.children;
        if (policies == null || policies.length == 0) {
            writeInt(stream, 0);
            serializeString(stream, policy.attr);
            serializeElement(stream, policy.c);
            serializeElement(stream, policy.cp);
        } else {
            writeInt(stream, policies.length);
            for (BswabePolicy p : policies) {
                serializePolicy(stream, p);
            }
        }
    }

    private static BswabePolicy unserializePolicy(InputStream stream, BswabePub pub) throws IOException {
        BswabePolicy p = new BswabePolicy();
        p.k = readInt(stream);

        /* children */
        int n = readInt(stream);
        if (n > 0) {
            BswabePolicy[] array = new BswabePolicy[n];
            for (int i = 0; i < n; i++) {
                array[i] = unserializePolicy(stream, pub);
            }
            p.children = array;
        } else {
            Pairing paring = pub.p;
            p.children = null;
            p.attr = unserializeString(stream);
            p.c = unserializeElement(stream, paring.getG1());
            p.cp = unserializeElement(stream, paring.getG1());
        }

        return p;
    }

    public static byte[] serializeBswabeCph(BswabeCph cph) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try {
            serializeElement(stream, cph.cs);
            serializeElement(stream, cph.c);
            serializePolicy(stream, cph.p);
            return stream.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    public static BswabeCph unserializeBswabeCph(BswabePub pub, byte[] cphBuf) {
        ByteArrayInputStream stream = new ByteArrayInputStream(cphBuf);

        try {
            Pairing pairing = pub.p;
            Element cs = unserializeElement(stream, pairing.getGT());
            Element c = unserializeElement(stream, pairing.getG1());
            BswabePolicy policy = unserializePolicy(stream, pub);

            BswabeCph cph = new BswabeCph();
            cph.cs = cs;
            cph.c = c;
            cph.p = policy;
            return cph;
        } catch (IOException e) {
            return null;
        }
    }
}
