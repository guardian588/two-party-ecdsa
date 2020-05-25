package hr.fer.zavrsni.twopartyecdsa.sign;

import hr.fer.zavrsni.twopartyecdsa.discretelogpok.DiscreteLogProofOfKnowledge;

public class SignMsg2 {
	public SignMsg2(DiscreteLogProofOfKnowledge r2PoK) {
		this.r2PoK = r2PoK;
	}

	public DiscreteLogProofOfKnowledge r2PoK;
}
