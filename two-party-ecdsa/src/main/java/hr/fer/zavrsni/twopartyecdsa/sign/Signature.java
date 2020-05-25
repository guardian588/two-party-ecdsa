package hr.fer.zavrsni.twopartyecdsa.sign;

import java.math.BigInteger;

public class Signature {
	public Signature(BigInteger r, BigInteger s) {
		this.r = r;
		this.s = s;
	}
	public BigInteger r;
	public BigInteger s;

}
