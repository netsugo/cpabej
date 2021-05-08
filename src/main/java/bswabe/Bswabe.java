package bswabe;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Bswabe {
    private static final String curveParams = "type a\n"
            + "q 87807107996633125224377819847540498158068831994142082"
            + "1102865339926647563088022295707862517942266222142315585"
            + "8769582317459277713367317481324925129998224791\n"
            + "h 12016012264891146079388821366740534204802954401251311"
            + "822919615131047207289359704531102844802183906537786776\n"
            + "r 730750818665451621361119245571504901405976559617\n"
            + "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";

    private static Pairing createPairing() {
        CurveParameters params = new DefaultCurveParameters()
                .load(new ByteArrayInputStream(curveParams.getBytes()));
        return PairingFactory.getPairing(params);
    }

    /*
     * Generate a public key and corresponding master secret key.
     */
    public static void setup(BswabePub pub, BswabeMsk msk) {
        Pairing pairing = createPairing();

        Element g = pairing.getG1().newRandomElement();
        Element gp = pairing.getG2().newRandomElement();
        Element alpha = pairing.getZr().newRandomElement();
        Element beta = pairing.getZr().newRandomElement();
        Element beta_inv = beta.duplicate().invert();

        Element g_alpha = gp.duplicate().powZn(alpha);
        Element f = g.duplicate().powZn(beta_inv);
        Element h = g.duplicate().powZn(beta);
        Element g_hat_alpha = pairing.pairing(g, g_alpha);

        pub.h = h;
        pub.f = f;
        pub.g = g;
        pub.gp = gp;
        pub.p = pairing;
        pub.pairingDesc = curveParams;
        pub.g_hat_alpha = g_hat_alpha;

        msk.beta = beta;
        msk.g_alpha = g_alpha;
    }

    /*
     * Generate a private key with the given set of attributes.
     */
    public static BswabePrv keygen(BswabePub pub, BswabeMsk msk, String[] attrs) throws NoSuchAlgorithmException {
        Pairing pairing = pub.p;

        Element r = pairing.getZr().newRandomElement();
        Element g_r = pub.g.duplicate().powZn(r);
        Element beta_inv = msk.beta.duplicate().invert();
        Element prv_d = msk.g_alpha.duplicate().mul(g_r).powZn(beta_inv);

        ArrayList<BswabePrvComp> components = new ArrayList<>();
        for (String attr : attrs) {
            Element h_rp = pairing.getG2().newElement();
            elementFromString(h_rp, attr);
            Element rp = pairing.getZr().newRandomElement();
            h_rp.powZn(rp);
            Element d = g_r.duplicate().mul(h_rp);
            Element dp = pub.g.duplicate().powZn(rp);

            BswabePrvComp comp = new BswabePrvComp();

            comp.attr = attr;
            comp.d = d;
            comp.dp = dp;

            components.add(comp);
        }

        BswabePrv prv = new BswabePrv();
        prv.comps = components;
        prv.d = prv_d;
        return prv;
    }

    /*
     * Delegate a subset of attribute of an existing private key.
     */
    public static BswabePrv delegate(BswabePub pub, BswabePrv prv_src, String[] attrs_subset) throws NoSuchAlgorithmException, IllegalArgumentException {
        BswabePrv prv = new BswabePrv();

        /* initialize */
        Pairing pairing = pub.p;
        prv.d = pairing.getG2().newElement();

        Element g_rt = pairing.getG2().newElement();
        Element rt = pairing.getZr().newElement();
        Element f_at_rt = pairing.getZr().newElement();

        /* compute */
        rt.setToRandom();
        f_at_rt = pub.f.duplicate();
        f_at_rt.powZn(rt);
        prv.d = prv_src.d.duplicate();
        prv.d.mul(f_at_rt);

        g_rt = pub.g.duplicate();
        g_rt.powZn(rt);

        prv.comps = new ArrayList<>();

        for (String s : attrs_subset) {
            BswabePrvComp comp = new BswabePrvComp();
            comp.attr = s;

            BswabePrvComp comp_src = new BswabePrvComp();
            boolean comp_src_init = false;

            for (BswabePrvComp bswabePrvComp : prv_src.comps) {
                if (bswabePrvComp.attr.equals(comp.attr)) {
                    comp_src = bswabePrvComp;
                    comp_src_init = true;
                }
            }

            if (!comp_src_init) throw new IllegalArgumentException("comp_src_init == false");

            comp.d = pairing.getG2().newElement();
            comp.dp = pairing.getG1().newElement();
            Element h_rtp = pairing.getG2().newElement();
            Element rtp = pairing.getZr().newElement();

            elementFromString(h_rtp, comp.attr);
            rtp.setToRandom();

            h_rtp.powZn(rtp);

            comp.d = g_rt.duplicate();
            comp.d.mul(h_rtp);
            comp.d.mul(comp_src.d);

            comp.dp = pub.g.duplicate();
            comp.dp.powZn(rtp);
            comp.dp.mul(comp_src.dp);


            prv.comps.add(comp);
        }

        return prv;
    }

    /*
     * Pick a random group element and encrypt it under the specified access
     * policy. The resulting ciphertext is returned and the Element given as an
     * argument (which need not be initialized) is set to the random group
     * element.
     *
     * After using this function, it is normal to extract the random data in m
     * using the pbc functions element_length_in_bytes and element_to_bytes and
     * use it as a key for hybrid encryption.
     *
     * The policy is specified as a simple string which encodes a postorder
     * traversal of threshold tree defining the access policy. As an example,
     *
     * "foo bar fim 2of3 baf 1of2"
     *
     * specifies a policy with two threshold gates and four leaves. It is not
     * possible to specify an attribute with whitespace in it (although "_" is
     * allowed).
     *
     * Numerical attributes and any other fancy stuff are not supported.
     *
     * Returns null if an error occured, in which case a description can be
     * retrieved by calling bswabe_error().
     */
    public static BswabeCphKey encrypt(BswabePub pub, String policy) throws ParseException, NoSuchAlgorithmException {
        BswabeCphKey keyCph = new BswabeCphKey();
        BswabeCph cph = new BswabeCph();

        /* initialize */

        Pairing pairing = pub.p;
        Element s = pairing.getZr().newElement();
        Element m = pairing.getGT().newElement();
        cph.cs = pairing.getGT().newElement();
        cph.c = pairing.getG1().newElement();
        cph.p = parsePolicyPostfix(policy);

        /* compute */
        m.setToRandom();
        s.setToRandom();
        cph.cs = pub.g_hat_alpha.duplicate();
        cph.cs.powZn(s); /* num_exps++; */
        cph.cs.mul(m); /* num_muls++; */

        cph.c = pub.h.duplicate();
        cph.c.powZn(s); /* num_exps++; */

        fillPolicy(cph.p, pub, s);

        keyCph.cph = cph;
        keyCph.key = m;

        return keyCph;
    }

    /*
     * Decrypt the specified ciphertext using the given private key, filling in
     * the provided element m (which need not be initialized) with the result.
     */
    public static Element decrypt(BswabePub pub, BswabePrv prv, BswabeCph cph) {
        Element m = pub.p.getGT().newElement();
        Element t = pub.p.getGT().newElement();

        checkSatisfy(cph.p, prv);
        if (!cph.p.satisfiable) {
            throw new RuntimeException("Attributes in key do not satisfy policy");
        }

        pickSatisfyMinLeaves(cph.p);

        decFlatten(t, cph.p, prv, pub);

        m = cph.cs.duplicate();
        m.mul(t); /* num_muls++; */

        t = pub.p.pairing(cph.c, prv.d);
        t.invert();
        m.mul(t); /* num_muls++; */

        return m;
    }

    private static void decFlatten(Element r, BswabePolicy p, BswabePrv prv, BswabePub pub) {
        Element one = pub.p.getZr().newElement();
        one.setToOne();
        r.setToOne();

        decNodeFlatten(r, one, p, prv, pub);
    }

    private static void decNodeFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
        if (p.children == null || p.children.length == 0)
            decLeafFlatten(r, exp, p, prv, pub);
        else
            decInternalFlatten(r, exp, p, prv, pub);
    }

    private static void decLeafFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
        BswabePrvComp c = prv.comps.get(p.attri);

        Element s = pub.p.getGT().newElement();
        Element t = pub.p.getGT().newElement();

        s = pub.p.pairing(p.c, c.d); /* num_pairings++; */
        t = pub.p.pairing(p.cp, c.dp); /* num_pairings++; */
        t.invert();
        s.mul(t); /* num_muls++; */
        s.powZn(exp); /* num_exps++; */

        r.mul(s); /* num_muls++; */
    }

    private static void decInternalFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
        Element t = pub.p.getZr().newElement();
        Element expnew = pub.p.getZr().newElement();
        ArrayList<Integer> satl = p.satl;

        for (Integer sat : satl) {
            lagrangeCoef(t, satl, sat);
            expnew = exp.duplicate();
            expnew.mul(t);
            decNodeFlatten(r, expnew, p.children[sat - 1], prv, pub);
        }
    }

    private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
        // int j, k;
        Element t = r.duplicate();

        r.setToOne();
        s.stream().filter(j -> j != i).forEach(j -> {
            t.set(-j);
            r.mul(t); /* num_muls++; */
            t.set(i - j);
            t.invert();
            r.mul(t); /* num_muls++; */
        });
    }

    private static void pickSatisfyMinLeaves(BswabePolicy p) {
        if (p.children == null || p.children.length == 0)
            p.min_leaves = 1;
        else {
            int len = p.children.length;

            Arrays.stream(p.children)
                    .filter(policy -> policy.satisfiable)
                    .forEach(Bswabe::pickSatisfyMinLeaves);

            List<Integer> c = IntStream.range(0, len).boxed()
                    .sorted(new IntegerComparator(p))
                    .collect(Collectors.toList());

            p.satl = new ArrayList<>();
            p.min_leaves = 0;
            int l = 0;

            for (int i = 0; i < len && l < p.k; i++) {
                int c_i = c.get(i); /* c[i] */
                if (p.children[c_i].satisfiable) {
                    l++;
                    p.min_leaves += p.children[c_i].min_leaves;
                    int k = c_i + 1;
                    p.satl.add(k);
                }
            }
        }
    }

    private static void checkSatisfy(BswabePolicy p, BswabePrv prv) {
        p.satisfiable = false;
        if (p.children == null || p.children.length == 0) {
            for (int i = 0; i < prv.comps.size(); i++) {
                String prvAttr = prv.comps.get(i).attr;
                if (prvAttr.compareTo(p.attr) == 0) {
                    p.satisfiable = true;
                    p.attri = i;
                    break;
                }
            }
        } else {
            Arrays.stream(p.children)
                    .forEach(policy -> checkSatisfy(policy, prv));

            int l = (int) Arrays.stream(p.children)
                    .filter(policy -> policy.satisfiable)
                    .count();

            if (l >= p.k)
                p.satisfiable = true;
        }
    }

    private static void fillPolicy(BswabePolicy p, BswabePub pub, Element e)
            throws NoSuchAlgorithmException {
        Pairing pairing = pub.p;
        Element r = pairing.getZr().newElement();
        Element t = pairing.getZr().newElement();
        Element h = pairing.getG2().newElement();

        p.q = randPoly(p.k - 1, e);

        if (p.children == null || p.children.length == 0) {
            p.c = pairing.getG1().newElement();
            p.cp = pairing.getG2().newElement();

            elementFromString(h, p.attr);
            p.c = pub.g.duplicate();
            p.c.powZn(p.q.coef[0]);
            p.cp = h.duplicate();
            p.cp.powZn(p.q.coef[0]);
        } else {
            for (int i = 0; i < p.children.length; i++) {
                r.set(i + 1);
                evalPoly(t, p.q, r);
                fillPolicy(p.children[i], pub, t);
            }
        }

    }

    private static void evalPoly(Element r, BswabePolynomial q, Element x) {
        Element s = r.duplicate();
        Element t = r.duplicate();

        r.setToZero();
        t.setToOne();

        for (int i = 0; i < q.deg + 1; i++) {
            /* r += q->coef[i] * t */
            s = q.coef[i].duplicate();
            s.mul(t);
            r.add(s);

            /* t *= x */
            t.mul(x);
        }

    }

    private static BswabePolynomial randPoly(int deg, Element zeroVal) {
        BswabePolynomial q = new BswabePolynomial();
        q.deg = deg;
        q.coef = new Element[deg + 1];

        for (int i = 0; i < deg + 1; i++)
            q.coef[i] = zeroVal.duplicate();

        q.coef[0].set(zeroVal);

        for (int i = 1; i < deg + 1; i++)
            q.coef[i].setToRandom();

        return q;
    }

    private static BswabePolicy parsePolicyPostfix(String s) throws ParseException {
        ArrayList<BswabePolicy> stack = new ArrayList<>();
        List<String> splitPolicy = Arrays.stream(s.split("\\s+"))
                .filter(tok -> !tok.isEmpty())
                .collect(Collectors.toList());
        for (String tok : splitPolicy) {
            if (!tok.contains("of")) {
                stack.add(baseNode(1, tok));
            } else {
                /* parse kof n node */
                String[] k_n = tok.split("of");
                int k = Integer.parseInt(k_n[0]);
                int n = Integer.parseInt(k_n[1]);

                if (k < 1) {
                    throw ParseException.create(s, "trivially satisfied operator", tok);
                } else if (k > n) {
                    throw ParseException.create(s, "unsatisfiable operator", tok);
                } else if (n == 1) {
                    throw ParseException.create(s, "indentity operator", tok);
                } else if (n > stack.size()) {
                    throw ParseException.create(s, "stack underflow at");
                }

                /* pop n things and fill in children */
                BswabePolicy node = baseNode(k, null);
                node.children = new BswabePolicy[n];

                for (int i = n - 1; i >= 0; i--)
                    node.children[i] = stack.remove(stack.size() - 1);

                /* push result */
                stack.add(node);
            }
        }

        if (stack.size() > 1) {
            throw ParseException.create(s, "extra node left on the stack");
        } else if (stack.size() < 1) {
            throw ParseException.create(s, "empty policy");
        }

        return stack.get(0);
    }

    private static BswabePolicy baseNode(int k, String s) {
        BswabePolicy p = new BswabePolicy();

        p.k = k;
        p.attr = s;
        p.q = null;

        return p;
    }

    private static void elementFromString(Element h, String s) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

    private static class IntegerComparator implements Comparator<Integer> {
        public final BswabePolicy policy;

        public IntegerComparator(BswabePolicy p) {
            this.policy = p;
        }

        @Override
        public int compare(Integer o1, Integer o2) {
            int k = policy.children[o1].min_leaves;
            int l = policy.children[o2].min_leaves;

            return Integer.compare(k, l);
        }
    }
}
