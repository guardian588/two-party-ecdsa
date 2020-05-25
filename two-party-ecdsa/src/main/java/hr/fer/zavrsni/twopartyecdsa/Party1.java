package hr.fer.zavrsni.twopartyecdsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedList;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;

import de.henku.jpaillier.KeyPairBuilder;
import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;
import hr.fer.zavrsni.twopartyecdsa.discretelogpok.DiscreteLogProofOfKnowledge;
import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidPrimalityProofException;
import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidProofPairException;
import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidRangeProofException;
//import java.security.KeyPair;
//
//import de.henku.jpaillier.KeyPair;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg1;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg2;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg3;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg4;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg5;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg6;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg7;
import hr.fer.zavrsni.twopartyecdsa.pailliernthrootproof.PaillierNthRootProof;
import hr.fer.zavrsni.twopartyecdsa.paillierrangeproof.BitSlice;
import hr.fer.zavrsni.twopartyecdsa.paillierrangeproof.ProofPair;
import hr.fer.zavrsni.twopartyecdsa.paillierrangeproof.RangeProofProver;

public class Party1 {
	private Config cfg;
	private java.security.KeyPair x1;
//	public PrivateKey X1;
	public DiscreteLogProofOfKnowledge x1PoK;
	public Nonce x1Nonce;
	
	public PublicKey x2;
	public de.henku.jpaillier.KeyPair psk;
	public BigInteger cKey;
	public BigInteger cKeyNonce;
	public RangeProofProver rpProver;
	
	public Comm abComm;
	public BigInteger alpha;
	public byte[] alphaPK;
	public Nonce alphaNonce;
	
	public PublicKey q;
	
	public Party1(Config cfg) {
		this.cfg = cfg;
	}
	
	public Party1PrivateKey genKey(Party2 p2, java.security.KeyPair x1, java.security.KeyPair x2) throws SecurityException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, InvalidPrimalityProofException, InvalidRangeProofException, InvalidProofPairException {
		this.x1 = x1;
		p2.setX2(x2);
		
		KeyGenMsg1 m1 = this.keyGenPhase1(0);
		KeyGenMsg2 m2 = p2.keyGenPhase2(0, m1);
		KeyGenMsg3 m3 = this.keyGenPhase3(0, m2);
		KeyGenMsg4 m4 = p2.keyGenPhase4(0, m3);
		KeyGenMsg5 m5 = this.keyGenPhase5(0, m4);
		KeyGenMsg6 m6 = p2.KeyGenPhase6(0, m5);
		KeyGenMsg7 m7 = this.keyGenPhase7(0, m6);
		p2.KeyGenPhase8(0, m7);
		
		return new Party1PrivateKey(this.cfg, this.psk, this.x1.getPrivate(), this.q);
	}

	public KeyGenMsg1 keyGenPhase1(long sid) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
		java.security.KeyPair x1;
		
		if (this.x1 != null) {
			x1 = this.x1;
		} else {
			x1 = TwoPartyECDSA.newPrivKey();
		}
		
		DiscreteLogProofOfKnowledge x1PoK = new DiscreteLogProofOfKnowledge(TwoPartyECDSA.getKeyGen1Msg(), x1);
		
		Nonce x1Nonce = new Nonce();
		Comm x1Comm = Comm.commit(x1PoK.bytes(), x1Nonce);
		
		this.x1 = x1;
		this.x1PoK = x1PoK;
		this.x1Nonce = x1Nonce;
		
		return new KeyGenMsg1(x1Comm);
	}
	
	public KeyGenMsg3 keyGenPhase3(long sid, KeyGenMsg2 m2) throws InvalidKeySpecException, NoSuchAlgorithmException {
		m2.x2PoK.verify(TwoPartyECDSA.getKeyGen2Msg());
		de.henku.jpaillier.KeyPair psk = new de.henku.jpaillier.KeyPairBuilder().bits(this.cfg.nPaillierBits).generateKeyPair();
		BigInteger cKey = psk.getPublicKey().encrypt(new BigInteger(this.x1.getPrivate().getEncoded()));
		PaillierNthRootProof proof = PaillierNthRootProof.provePaillierNthRoot(psk.getPublicKey(), this.cfg.nthRootSecBits);

		PublicKey x2 = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(m2.x2PoK.pk));
		BigInteger x1 = new BigInteger(this.x1.getPrivate().getEncoded());
		RangeProofProver rpProver = new RangeProofProver(x1, this.cfg.q, this.cfg.q3, psk, m2.rpChalComm, this.cfg.rangeSecBits);
		
		this.x2 = x2;
		this.psk = psk;
		this.cKey = new BigInteger(cKey.toByteArray());
		this.cKeyNonce = BigInteger.ZERO;
		this.rpProver = rpProver;
		return new KeyGenMsg3(this.x1PoK, this.x1Nonce, proof, cKey.toByteArray(), this.rpProver.ctxtPairs);
	}
	
	public KeyGenMsg5 keyGenPhase5(long sid, KeyGenMsg4 m4) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidProofPairException {
		ProofPair[] proofPairs = this.rpProver.prove(new BitSlice(m4.rpChallenge), m4.rpChalNonce);
		
		BigInteger alphaSk = this.psk.decrypt(m4.cPrime);
		alphaSk = alphaSk.mod(this.cfg.q);
		
			
		PrivateKey alpha = KeyFactory.getInstance("EC").generatePrivate(new X509EncodedKeySpec(alphaSk.toByteArray()));
		// TODO
		PublicKey alphaPK = KeyFactory.getInstance("EC").generatePublic(
				new org.bouncycastle.jce.spec.ECPublicKeySpec(
						ECNamedCurveTable.getParameterSpec("secp256k1").getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) alpha).getD()),
						ECNamedCurveTable.getParameterSpec("secp256k1")));
		
		Nonce alphaNonce = new Nonce();
		Comm alphaComm = Comm.commit(alphaPK.getEncoded(), alphaNonce);
		
		this.alpha = this.psk.decrypt(m4.cPrime);
		this.alphaPK = alphaPK.getEncoded();
		this.alphaNonce = alphaNonce;
		this.abComm = m4.abComm;
		return new KeyGenMsg5(proofPairs, alphaComm);
	}
	
	public KeyGenMsg7 keyGenPhase7(long sid, KeyGenMsg6 m6) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(m6.a.toByteArray());
		baos.write(m6.b.toByteArray());
		byte[] data = baos.toByteArray();
		
		this.abComm.verify(data, m6.abNonce);
		
		BigInteger x1Int = new BigInteger(this.x1.getPrivate().getEncoded());
		BigInteger alphaPrime = m6.a.multiply(x1Int);
		alphaPrime = alphaPrime.add(m6.b);
		if (alphaPrime.compareTo(this.alpha) != 0) {
			// TODO
			throw new Exception();
		}
		
		ECPoint x1 = ((ECPublicKey) this.x2).getW();
		
		ECPoint product = ECOperations.scalarMultiplication(x1, this.x1.getPrivate().getEncoded());
		ECNamedCurveParameterSpec specs = ECNamedCurveTable.getParameterSpec("scep265k1");
		KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
		ECNamedCurveSpec params = new ECNamedCurveSpec("scep265k1", specs.getCurve(), specs.getG(), specs.getN());
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(product, params);
		this.q = kf.generatePublic(pubKeySpec);
		
		return new KeyGenMsg7(this.alphaPK, this.alphaNonce);
	}
}
