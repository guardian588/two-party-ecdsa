package hr.fer.zavrsni.twopartyecdsa.keygen;

import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.discretelogpok.DiscreteLogProofOfKnowledge;

public class KeyGenMsg2 {
	public KeyGenMsg2(DiscreteLogProofOfKnowledge x2PoK2, Comm comm) {
		this.x2PoK = x2PoK2;
		this.rpChalComm = comm;
	}
	public DiscreteLogProofOfKnowledge x2PoK;
	public Comm rpChalComm;
}
