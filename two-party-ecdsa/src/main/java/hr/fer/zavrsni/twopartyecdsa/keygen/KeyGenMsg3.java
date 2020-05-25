package hr.fer.zavrsni.twopartyecdsa.keygen;

import java.math.BigInteger;

import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;
import hr.fer.zavrsni.twopartyecdsa.discretelogpok.DiscreteLogProofOfKnowledge;
import hr.fer.zavrsni.twopartyecdsa.pailliernthrootproof.PaillierNthRootProof;
import hr.fer.zavrsni.twopartyecdsa.paillierrangeproof.CiphertextPair;

public class KeyGenMsg3 {
	public KeyGenMsg3(DiscreteLogProofOfKnowledge x1PoK, Nonce x1PoKNonce, PaillierNthRootProof pProof, byte[] cKey,
			CiphertextPair[] rpctxtPairs) {
		this.x1PoK = x1PoK;
		this.x1PoKNonce = x1PoKNonce;
		this.pProof = pProof;
		this.setcKey(cKey);
		this.rpctxtPairs = rpctxtPairs;
		
	}
	public byte[] getcKey() {
		return cKey;
	}
	public void setcKey(byte[] cKey) {
		this.cKey = cKey;
	}
	public DiscreteLogProofOfKnowledge x1PoK;
	public Nonce x1PoKNonce;
	public PaillierNthRootProof pProof;
	private byte[] cKey;
	public CiphertextPair[] rpctxtPairs; 
}
