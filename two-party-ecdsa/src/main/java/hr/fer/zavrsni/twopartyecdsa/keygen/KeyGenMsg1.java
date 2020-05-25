package hr.fer.zavrsni.twopartyecdsa.keygen;

import hr.fer.zavrsni.twopartyecdsa.commit.Comm;

public class KeyGenMsg1 {
	public Comm x1PoKComm;
	
	public KeyGenMsg1(Comm x1PoKComm) {
		this.x1PoKComm = x1PoKComm;
	}
}
