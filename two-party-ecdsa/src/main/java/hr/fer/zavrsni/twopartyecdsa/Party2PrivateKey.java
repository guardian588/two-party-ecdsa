package hr.fer.zavrsni.twopartyecdsa;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;

import de.henku.jpaillier.PublicKey;
import hr.fer.zavrsni.twopartyecdsa.sign.Party2SignCtx;

public class Party2PrivateKey {
	public Party2PrivateKey(Config cfg2, PublicKey ppk2, BigInteger cKey2, PrivateKey private1, ECPublicKey q) {
		cfg = cfg2;
		ppk = ppk2;
		cKey = cKey2;
		x2sk = private1;
		publicKey = q;
	}
	private Config cfg;
	public PublicKey ppk;
	public BigInteger cKey;
	public PrivateKey x2sk;
	public ECPublicKey publicKey;
	
	public Party2SignCtx newSignCtx(byte[] msg) {
		return new Party2SignCtx(msg, this);
	}

	public Config getCfg() {
		return cfg;
	}
}
