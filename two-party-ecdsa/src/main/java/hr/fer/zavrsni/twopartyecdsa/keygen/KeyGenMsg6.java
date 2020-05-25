package hr.fer.zavrsni.twopartyecdsa.keygen;

import java.math.BigInteger;

import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;

public class KeyGenMsg6 {
	public KeyGenMsg6(BigInteger a, BigInteger b, Nonce abNonce) {
		this.a = a;
		this.b = b;
		this.abNonce = abNonce;
	}
	public BigInteger a;
	public BigInteger b;
	public Nonce abNonce;

}
