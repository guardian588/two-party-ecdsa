package hr.fer.zavrsni.twopartyecdsa.keygen;

import java.math.BigInteger;

import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;

public class KeyGenMsg7 {
	public KeyGenMsg7(byte[] alphaPK, Nonce alphaNonce) {
		this.alphaPK = new BigInteger(alphaPK);
		this.alphaNonce = alphaNonce;
	}
	public BigInteger alphaPK;
	public Nonce alphaNonce;

}
