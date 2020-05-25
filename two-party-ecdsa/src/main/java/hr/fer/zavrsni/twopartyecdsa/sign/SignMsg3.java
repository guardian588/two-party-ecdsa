package hr.fer.zavrsni.twopartyecdsa.sign;

import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;
import hr.fer.zavrsni.twopartyecdsa.discretelogpok.DiscreteLogProofOfKnowledge;

public class SignMsg3 {
	public SignMsg3(DiscreteLogProofOfKnowledge r1PoK, Nonce r1PoKNonce) {
		this.r1PoK = r1PoK;
		this.r1PoKNonce = r1PoKNonce;
	}
	public DiscreteLogProofOfKnowledge r1PoK;
	public Nonce r1PoKNonce;
}
