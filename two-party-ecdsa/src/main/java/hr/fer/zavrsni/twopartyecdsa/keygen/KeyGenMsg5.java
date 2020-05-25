package hr.fer.zavrsni.twopartyecdsa.keygen;

import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.paillierrangeproof.ProofPair;

public class KeyGenMsg5 {
	public KeyGenMsg5(ProofPair[] rpProofPairs, Comm alphaComm) {
		this.rpProofPairs = rpProofPairs;
		this.alphaComm = alphaComm;
	}
	public ProofPair[] rpProofPairs;
	public Comm alphaComm;
}
