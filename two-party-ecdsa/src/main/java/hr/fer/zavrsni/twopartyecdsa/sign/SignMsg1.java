package hr.fer.zavrsni.twopartyecdsa.sign;

import hr.fer.zavrsni.twopartyecdsa.commit.Comm;

public class SignMsg1 {
	public SignMsg1(Comm r1PoKComm) {
		this.r1PoKComm = r1PoKComm;
	}

	public Comm r1PoKComm;

}
