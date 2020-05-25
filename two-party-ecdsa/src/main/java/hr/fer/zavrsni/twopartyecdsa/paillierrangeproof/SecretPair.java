package hr.fer.zavrsni.twopartyecdsa.paillierrangeproof;

import java.math.BigInteger;

public class SecretPair {
	public BigInteger w1;
	public BigInteger r1;
	public BigInteger w2;
	public BigInteger r2;
	
	public SecretPair(BigInteger w1, BigInteger r1, BigInteger w2, BigInteger r2) {
		this.w1 = w1;
		this.r1 = r1;
		this.w2 = w2;
		this.r2 = r2;
	}

	public static SecretPair[] newSecretPairs(int size) {
		return new SecretPair[size];
	}
}
