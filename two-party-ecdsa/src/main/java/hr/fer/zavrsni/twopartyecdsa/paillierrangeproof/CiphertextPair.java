package hr.fer.zavrsni.twopartyecdsa.paillierrangeproof;

import java.math.BigInteger;

public class CiphertextPair {
	public BigInteger c1;
	public BigInteger c2;
	
	public CiphertextPair(BigInteger c1, BigInteger c2) {
		this.c1 = c1;
		this.c2 = c2;
	}
	
	public static CiphertextPair[] newCiphertextPairs(int size) {
		return new CiphertextPair[size];
	}

}
