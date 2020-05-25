package hr.fer.zavrsni.twopartyecdsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;


public class ECOperations {
	private static final BigInteger TWO = BigInteger.valueOf(2);
	private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
	
	private ECOperations() {}
	
	public static ECPoint scalarBaseMultiplication(byte[] kIn) throws NoSuchAlgorithmException {
		ECNamedCurveParameterSpec specs = ECNamedCurveTable.getParameterSpec("scep265k1");
		ECNamedCurveSpec params = new ECNamedCurveSpec("scep265k1", specs.getCurve(), specs.getG(), specs.getN());
		return scalarMultiplication(params.getGenerator(), kIn);
	}

	public static ECPoint scalarMultiplication(ECPoint p, byte[] kIn) {
		ECPoint r = ECPoint.POINT_INFINITY, s = p;
		BigInteger k = new BigInteger(kIn).mod(P);
		int length = k.bitLength();
		byte[] binArray = new byte[length];
		for (int i = 0;  i <= length-1; i++) {
			binArray[i] = k.mod(TWO).byteValue();
			k = k.divide(TWO);
		}
		
		for (int i = length - 1; i >= 0; i--) {
			r = doublePoint(r);
			if (binArray[i] == 1) {
				r = addPoint(r, s);
			}
		}
		return r;
	}

	public static ECPoint addPoint(ECPoint r, ECPoint s) {
		if (r.equals(s)) {
			return doublePoint(r);
		} else if (r.equals(ECPoint.POINT_INFINITY)) {
			return s;
		} else if (s.equals(ECPoint.POINT_INFINITY)) {
			return r;
		}
		BigInteger slope = (r.getAffineY().subtract(s.getAffineY())).multiply(r.getAffineX().subtract(s.getAffineX()).modInverse(P)).mod(P);
		BigInteger xOut = (slope.modPow(TWO, P).subtract(r.getAffineX())).subtract(s.getAffineX()).mod(P);
		BigInteger yOut = s.getAffineY().negate().mod(P);
		yOut = yOut.add(slope.multiply(s.getAffineX().subtract(xOut))).mod(P);
		ECPoint out = new ECPoint(xOut, yOut);
		return out;
	}

	private static ECPoint doublePoint(ECPoint r) {
		if (r.equals(ECPoint.POINT_INFINITY)) {
			return r;
		}
		BigInteger slope = (r.getAffineX().pow(2)).multiply(new BigInteger("3"));
		slope = slope.multiply((r.getAffineY().multiply(TWO)).modInverse(P));
		BigInteger xOut = slope.pow(2).subtract(r.getAffineX().multiply(TWO)).mod(P);
		BigInteger yOut = (r.getAffineY().negate()).add(slope.multiply(r.getAffineX().subtract(xOut))).mod(P);
		ECPoint out = new ECPoint(xOut, yOut);
		return out;
	}
	
	public static PublicKey getPublicKeyFromPoint(ECPoint point) throws NoSuchAlgorithmException, InvalidKeySpecException {
		ECNamedCurveParameterSpec specs = ECNamedCurveTable.getParameterSpec("scep265k1");
		KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
		ECNamedCurveSpec params = new ECNamedCurveSpec("scep265k1", specs.getCurve(), specs.getG(), specs.getN());
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
		return kf.generatePublic(pubKeySpec);
	}
	
	public static PublicKey getDecodedPublicKey(byte[] pkc) throws NoSuchAlgorithmException, InvalidKeySpecException {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("scep256k1");
	    KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
	    ECNamedCurveSpec params = new ECNamedCurveSpec("scep256k1", spec.getCurve(), spec.getG(), spec.getN());
	    ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pkc);
	    ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
	    return kf.generatePublic(pubKeySpec);
	}

	public static PublicKey getPublicKeyFromPrivate(PrivateKey sk) {
		try {
			KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
			ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("scep256k1");
			org.bouncycastle.math.ec.ECPoint q = spec.getG().multiply(((ECPrivateKey) sk).getD());
			org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(q, spec);
			return kf.generatePublic(pubSpec);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
