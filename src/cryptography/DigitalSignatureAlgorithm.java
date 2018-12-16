package cryptography;

import javafx.util.Pair;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;
////////////////////////////////////////////////////////////////////////////////////////////////////
public class DigitalSignatureAlgorithm
{
    //-------------------------------------------------------------------------------- Local classes
    public static class DSAParameters
    {
        public DSAParameters(BigInteger p, BigInteger q, BigInteger g)
        {
            this.p = p;
            this.q = q;
            this.g = g;
        }

        public BigInteger getP()
        {
            return p;
        }
        public BigInteger getQ()
        {
            return q;
        }
        public BigInteger getG()
        {
            return g;
        }

        private BigInteger p, q, g;
    }
    public static class PublicKey
    {
        public PublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y)
        {
            this.dsaParameters = new DSAParameters(p, q, g);
            this.y = y;
        }
        public PublicKey(DSAParameters dsaParameters, BigInteger y)
        {
            this(dsaParameters.getP(), dsaParameters.getQ(), dsaParameters.getG(), y);
        }

        public DSAParameters getDSAParameters()
        {
            return new DSAParameters(getP(), getQ(), getG());
        }
        public BigInteger getP()
        {
            return dsaParameters.getP();
        }
        public BigInteger getQ()
        {
            return dsaParameters.getQ();
        }
        public BigInteger getG()
        {
            return dsaParameters.getG();
        }
        public BigInteger getY()
        {
            return y;
        }

        private DSAParameters dsaParameters;
        private BigInteger y;
    }
    public static class PrivateKey
    {
        public PrivateKey(BigInteger p, BigInteger q, BigInteger g, BigInteger x)
        {
            this.dsaParameters = new DSAParameters(p, q, g);
            this.x = x;
        }
        public PrivateKey(DSAParameters dsaParameters, BigInteger x)
        {
            this(dsaParameters.getP(), dsaParameters.getQ(), dsaParameters.getG(), x);
        }

        public DSAParameters getDSAParameters()
        {
            return new DSAParameters(getP(), getQ(), getG());
        }
        public BigInteger getP()
        {
            return dsaParameters.getP();
        }
        public BigInteger getQ()
        {
            return dsaParameters.getQ();
        }
        public BigInteger getG()
        {
            return dsaParameters.getG();
        }
        public BigInteger getX()
        {
            return x;
        }

        private DSAParameters dsaParameters;
        private BigInteger x;
    }
    public static class DigitalSignature
    {
        public DigitalSignature(BigInteger r, BigInteger s)
        {
            this.r = r;
            this.s = s;
        }

        public BigInteger getR()
        {
            return r;
        }
        public BigInteger getS()
        {
            return s;
        }

        private BigInteger r, s;
    }

    //---------------------------------------------------------------------------- DSA functionality
    public Pair<PublicKey, PrivateKey> generateKeys()
    {
        BigInteger p, q, h, g, x, y;
        int pBitLength;
        PublicKey publicKey;
        PrivateKey privateKey;

        // Choose a prime number q, which is called the prime divisor
        q = BigInteger.probablePrime(160, random);

        // Generate random key length: [512, 1024] (divisible by 64)
        pBitLength = 512 + random.nextInt(9) * 64;

        // Choose another primer number p, such that p-1 mod q = 0. p is called the prime modulus
        do
        {
            p = BigInteger.probablePrime(pBitLength, random);
            p = p.subtract(p.subtract(BigInteger.ONE).remainder(q));
        }
        while (!(p.isProbablePrime(4)));

        // Choose an integer g, such that 1 < g < p, g^q mod p = 1 and g = h^((p–1)/q) mod p.
        // q is also called g's multiplicative order modulo p.
        // h is arbitrary (1 < h < p-1)
        BigInteger pMinusOneDivQ = p.subtract(BigInteger.ONE).divide(q);
        do
        {
            h = new BigInteger(pBitLength, random).mod(p.subtract(BigInteger.valueOf(3))).add(BigInteger.TWO);
            g = h.mod(p).modPow(pMinusOneDivQ, p);
        }
        while (!(g.compareTo(BigInteger.ONE) == 1 && g.compareTo(p) == -1 && g.mod(p).modPow(q, p).compareTo(BigInteger.ONE) == 0));

        // Choose an integer, such that 0 < x < q.
        x = new BigInteger(160, random).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);

        // Compute y as g^x mod p.
        y = g.mod(p).modPow(x, p);

        // Package the public key as {p,q,g,y}.
        publicKey = new PublicKey(p, q, g, y);

        // Package the private key as {p,q,g,x}.
        privateKey = new PrivateKey(p, q, g, x);

        return new Pair<>(publicKey, privateKey);
    }
    public DigitalSignature generateDigitalSignature(byte[] data, PrivateKey privateKey)
    {
        BigInteger p, q, g, x;
        BigInteger h, k, r, i, s;

        p = privateKey.getP();
        q = privateKey.getQ();
        g = privateKey.getG();
        x = privateKey.getX();

        // Generate the message digest h, using a hash algorithm like SHA1, etc.
        h = new BigInteger(1, messageDigest.digest(data));

        // Generate a random number k, such that 0 < k < q
        // Compute r as (g^k mod p) mod q. If r = 0, select a different k
        // Compute i, such that k*i mod q = 1. i is called the modular multiplicative inverse of k modulo q
        // Compute s = i*(h+r*x) mod q. If s = 0, select a different k
        do
        {
            k = new BigInteger(160, random).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);

            r = g.modPow(k, p).mod(q);

            if (r.compareTo(BigInteger.ZERO) == 0)
                continue;

            i = k.modInverse(q);
            s = i.multiply(h.add(r.multiply(x))).mod(q);

            if (s.compareTo(BigInteger.ZERO) == 0)
                continue;

            break;
        }
        while (true);

        // Package the digital signature as {r,s}
        return new DigitalSignature(r, s);
    }
    public boolean verifyDigitalSignature(byte[] data, PublicKey publicKey, DigitalSignature digitalSignature)
    {
        BigInteger p, q, g, y;
        BigInteger h, w, u1, u2, v;

        p = publicKey.getP();
        q = publicKey.getQ();
        g = publicKey.getG();
        y = publicKey.getY();

        // Generate the message digest h, using the same hash algorithm
        h = new BigInteger(1, messageDigest.digest(data));

        // Compute w, such that s*w mod q = 1. w is called the modular multiplicative inverse of s modulo q
        w = digitalSignature.getS().modInverse(q);

        // Compute u1 = h*w mod q
        u1 = h.multiply(w).mod(q);

        // Compute u2 = r*w mod q
        u2 = digitalSignature.getR().multiply(w).mod(q);

        // Compute v = (((g^u1)*(y^u2)) mod p) mod q
        v = g.mod(p).modPow(u1, p).multiply(y.mod(p).modPow(u2, p)).mod(p).mod(q);

        // If v == r, the digital signature is valid
        if(v.compareTo(digitalSignature.getR()) == 0)
            return true;
        else
            return false;
    }

    //---------------------------------------------------------------------------------- Constructor
    public DigitalSignatureAlgorithm()
        throws Exception
    {
    }

    //--------------------------------------------------------------------------------------- Fields
    Random random = new Random();
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
}
////////////////////////////////////////////////////////////////////////////////////////////////////