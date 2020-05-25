package hr.fer.zavrsni.twopartyecdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import de.henku.jpaillier.KeyPair;
import hr.fer.zavrsni.twopartyecdsa.sign.Party1SignCtx;
import hr.fer.zavrsni.twopartyecdsa.sign.Party2SignCtx;
import hr.fer.zavrsni.twopartyecdsa.sign.SignMsg1;
import hr.fer.zavrsni.twopartyecdsa.sign.SignMsg2;
import hr.fer.zavrsni.twopartyecdsa.sign.SignMsg3;
import hr.fer.zavrsni.twopartyecdsa.sign.SignMsg4;
import hr.fer.zavrsni.twopartyecdsa.sign.Signature;

public class Party1PrivateKey {
	public Party1PrivateKey(Config cfg, KeyPair psk, PrivateKey x1Sk, PublicKey publicKey) {
		this.cfg = cfg;
		this.psk = psk;
		this.x1Sk = x1Sk;
		this.publicKey = publicKey;
	}
	private Config cfg;
	public KeyPair psk;
	public PrivateKey x1Sk;
	public PublicKey publicKey;
	
	public Party1SignCtx newSignCtx(byte[] msg) {
		return new Party1SignCtx(msg, this);
	}
	
	public Signature sign(byte[] msg, Party2PrivateKey sk2) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		Party1SignCtx p1Ctx = this.newSignCtx(msg);
		SignMsg1 sm1 = p1Ctx.signMsgPhase1(0);
		
		Party2SignCtx p2Ctx = sk2.newSignCtx(msg);
		
		SignMsg2 sm2 = p2Ctx.signMsgPhase2(0, sm1);
		
		SignMsg3 sm3 = p1Ctx.signMsgPhase3(0, sm2);
		
		SignMsg4 sm4 = p2Ctx.signMsgPhase4(0, sm3);
		
		Signature sig = p1Ctx.signMsgPhase5(0, sm4);
		
		p2Ctx.zero();
		p1Ctx.zero();
		
		return sig;
	}

	public Config getCfg() {
		return cfg;
	}
}
