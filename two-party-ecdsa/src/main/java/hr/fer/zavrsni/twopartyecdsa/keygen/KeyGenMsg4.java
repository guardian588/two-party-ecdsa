package hr.fer.zavrsni.twopartyecdsa.keygen;

import java.math.BigInteger;

import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;

public class KeyGenMsg4 {
	public KeyGenMsg4(byte[] rpChallenge, Nonce rpChalNonce, BigInteger cPrime, Comm abComm) {
		this.rpChallenge = rpChallenge;
		this.rpChalNonce = rpChalNonce;
		this.cPrime = cPrime;
		this.abComm = abComm;
	}
	public byte[] rpChallenge;
	public Nonce rpChalNonce;
	public BigInteger cPrime;
	public Comm abComm;
}
