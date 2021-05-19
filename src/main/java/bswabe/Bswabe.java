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
        Pairing pairing = pub.p;

        Element rt = pairing.getZr().newRandomElement();
        Element f_at_rt = pub.f.duplicate().powZn(rt);
        Element g_rt = pub.g.duplicate().powZn(rt);

        Element prv_d = prv_src.d.duplicate().mul(f_at_rt);
        ArrayList<BswabePrvComp> prv_comps = new ArrayList<>();

        for (String s : attrs_subset) {
            BswabePrvComp comp_src = searchBswabePrvComp(s, prv_src);
            if (comp_src == null) throw new IllegalArgumentException("comp_src == null");

            Element h_rtp = pairing.getG2().newElement();
            elementFromString(h_rtp, s);
            Element rtp = pairing.getZr().newRandomElement();
            h_rtp.powZn(rtp);

            BswabePrvComp comp = new BswabePrvComp();
            comp.attr = s;
            comp.d = g_rt.duplicate().mul(h_rtp).mul(comp_src.d);
            comp.dp = pub.g.duplicate().powZn(rtp).mul(comp_src.dp);

            prv_comps.add(comp);
        }

        BswabePrv prv = new BswabePrv();
        prv.d = prv_d;
        prv.comps = prv_comps;

        return prv;
    }

    private static BswabePrvComp searchBswabePrvComp(String attr, BswabePrv prv_src) {
        for (BswabePrvComp bswabePrvComp : prv_src.comps) {
            if (bswabePrvComp.attr.equals(attr)) {
                return bswabePrvComp;
            }
        }
        return null;
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
        Pairing pairing = pub.p;
        Element s = pairing.getZr().newRandomElement();
        Element m = pairing.getGT().newRandomElement();
        Element cs = pub.g_hat_alpha.duplicate().powZn(s).mul(m);
        Element c = pub.h.duplicate().powZn(s);
        BswabePolicy parsedPolicy = parsePolicyPostfix(policy);

        fillPolicy(parsedPolicy, pub, s);

        BswabeCph cph = new BswabeCph();
        cph.c = c;
        cph.cs = cs;
        cph.p = parsedPolicy;

        BswabeCphKey keyCph = new BswabeCphKey();
        keyCph.cph = cph;
        keyCph.key = m;

        return keyCph;
    }

    /*
     * Decrypt the specified ciphertext using the given private key, filling in
     * the provided element m (which need not be initialized) with the result.
     */
    public static Element decrypt(BswabePub pub, BswabePrv prv, BswabeCph cph) {
        checkSatisfy(cph.p, prv);
        if (!cph.p.satisfiable) {
            throw new RuntimeException("Attributes in key do not satisfy policy");
        }

        pickSatisfyMinLeaves(cph.p);

        Element r = decFlatten(cph.p, prv, pub);
        Element t = pub.p.pairing(cph.c, prv.d).invert();
        Element m = cph.cs.duplicate().mul(r).mul(t);

        return m;
    }

    private static Element decFlatten(BswabePolicy p, BswabePrv prv, BswabePub pub) {
        Element r = pub.p.getGT().newElement().setToOne();
        Element one = pub.p.getZr().newElement().setToOne();
        decNodeFlatten(r, one, p, prv, pub);
        return r;
    }

    private static void decNodeFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
        if (p.children == null || p.children.length == 0)
            decLeafFlatten(r, exp, p, prv, pub);
        else
            decInternalFlatten(r, exp, p, prv, pub);
    }

    private static void decLeafFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
        BswabePrvComp c = prv.comps.get(p.attri);

        Element t = pub.p.pairing(p.cp, c.dp).invert();
        Element s = pub.p.pairing(p.c, c.d).mul(t).powZn(exp);

        r.mul(s);
    }

    private static void decInternalFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
        Element t = pub.p.getZr().newElement();
        ArrayList<Integer> satl = p.satl;

        for (Integer sat : satl) {
            lagrangeCoef(t, satl, sat);
            Element expnew = exp.duplicate().mul(t);
            decNodeFlatten(r, expnew, p.children[sat - 1], prv, pub);
        }
    }

    private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
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

    private static int searchAttri(String attr, BswabePrv prv) {
        int i = 0;
        for (BswabePrvComp comp : prv.comps) {
            if (comp.attr.compareTo(attr) == 0) {
                return i;
            } else {
                i++;
            }
        }
        return -1;
    }

    private static void checkSatisfy(BswabePolicy p, BswabePrv prv) {
        if (p.children == null || p.children.length == 0) {
            int attri = searchAttri(p.attr, prv);
            if (attri >= 0) {
                p.satisfiable = true;
                p.attri = attri;
            } else {
                p.satisfiable = false;
                p.attri = 0;
            }
        } else {
            Arrays.stream(p.children)
                    .forEach(policy -> checkSatisfy(policy, prv));

            int l = (int) Arrays.stream(p.children)
                    .filter(policy -> policy.satisfiable)
                    .count();

            p.satisfiable = l >= p.k;
        }
    }

    private static void fillPolicy(BswabePolicy p, BswabePub pub, Element e) throws NoSuchAlgorithmException {
        Pairing pairing = pub.p;
        p.q = randPoly(p.k - 1, e);

        if (p.children == null || p.children.length == 0) {
            Element h = pairing.getG2().newElement();
            Element coe = p.q.coefficients.get(0);
            p.c = pub.g.duplicate().powZn(coe);
            p.cp = elementFromString(h, p.attr).powZn(coe);
        } else {
            int i = 0;
            for (BswabePolicy policy : p.children) {
                Element r = pairing.getZr().newElement(i + 1);
                Element t = evalPoly(p.q, r);
                fillPolicy(policy, pub, t);
                i++;
            }
        }

    }

    private static Element evalPoly(BswabePolynomial q, Element x) {
        Element t = x.duplicate().setToOne();
        Element r = x.duplicate().setToZero();

        for (Element coe : q.coefficients) {
            Element s = coe.duplicate().mul(t);
            r.add(s);
            t.mul(x);
        }

        return r;
    }

    private static BswabePolynomial randPoly(int deg, Element zeroVal) {
        ArrayList<Element> coefficients = new ArrayList<>();
        coefficients.add(zeroVal);
        IntStream.range(0, deg).forEach(i -> coefficients.add(zeroVal.duplicate().setToRandom()));

        BswabePolynomial q = new BswabePolynomial();
        q.coefficients = coefficients;
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
                    throw ParseException.create(s, "redundant operator", tok);
                } else if (n > stack.size()) {
                    throw ParseException.create(s, "stack underflow at", tok);
                }

                /* pop n things and fill in children */
                BswabePolicy node = baseNode(k, null);
                List<BswabePolicy> headList = stack.subList(0, n);
                node.children = headList.toArray(new BswabePolicy[n]);
                stack.removeAll(headList);

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

    private static Element elementFromString(Element h, String s) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(s.getBytes());
        return h.setFromHash(digest, 0, digest.length);
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
