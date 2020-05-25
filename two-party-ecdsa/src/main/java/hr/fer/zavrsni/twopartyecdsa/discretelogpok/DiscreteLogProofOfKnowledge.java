package hr.fer.zavrsni.twopartyecdsa.discretelogpok;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;


import hr.fer.zavrsni.twopartyecdsa.ECOperations;
import hr.fer.zavrsni.twopartyecdsa.schnorr.Schnorr;
import hr.fer.zavrsni.twopartyecdsa.schnorr.Signature;

public class DiscreteLogProofOfKnowledge {
	public byte[] pk;
	public Signature schnorrSignature;
	
	public DiscreteLogProofOfKnowledge(byte[] plaintext, KeyPair sk) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
		this.pk = sk.getPublic().getEncoded();
		byte[] msg = dLogPokMsg(plaintext, pk);
		this.schnorrSignature = Schnorr.sign(sk.getPrivate(), msg); 
		
	}

	private byte[] dLogPokMsg(byte[] plaintext, byte[] pk) {
		try {
			MessageDigest h = MessageDigest.getInstance("SHA256");
			h.update(pk);
			h.update(plaintext);
			return h.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] bytes() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			baos.write(this.pk);
			baos.write(this.schnorrSignature.getSignature());
		} catch (IOException e) {
			e.printStackTrace();
		}
		return baos.toByteArray();
	}

	public void verify(byte[] plaintext) throws InvalidKeySpecException, NoSuchAlgorithmException {
	    PublicKey pk = ECOperations.getDecodedPublicKey(this.pk);	    
		
	    byte[] msg = dLogPokMsg(plaintext, this.pk);
	    Schnorr.verify(this.schnorrSignature, pk, msg);
	}

}
