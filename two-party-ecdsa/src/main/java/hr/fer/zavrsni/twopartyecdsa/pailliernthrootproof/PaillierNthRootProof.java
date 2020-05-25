package hr.fer.zavrsni.twopartyecdsa.pailliernthrootproof;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import de.henku.jpaillier.PublicKey;
import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidPrimalityProofException;

public class PaillierNthRootProof {
	public PublicKey pk;
	public BigInteger u;
	public BigInteger a;
	public BigInteger z;
	public int secBits;

	private PaillierNthRootProof(PublicKey pk, int secbits) {
		this.pk = pk;
		this.secBits = secbits;
	}

	public static PaillierNthRootProof provePaillierNthRoot(de.henku.jpaillier.PublicKey pk, int secbits) {
		PaillierNthRootProof proof = new PaillierNthRootProof(pk, secbits);
		
		SecureRandom rand = new SecureRandom();
		byte[] vb = new byte[pk.getnSquared().toByteArray().length];
		BigInteger v;
		do {
			rand.nextBytes(vb);
			v = new BigInteger(vb);
		} while (v.compareTo(pk.getnSquared()) >= 0);
		
		proof.u = v.modPow(pk.getN(), pk.getnSquared());
		
		proof.proveInstance(v);
		return proof;
		
	}

	private void proveInstance(BigInteger v) {
		SecureRandom rand = new SecureRandom();
		byte[] rb = new byte[this.pk.getnSquared().toByteArray().length];
		BigInteger r;
		do {
			rand.nextBytes(rb);
			r = new BigInteger(rb);
		} while (r.compareTo(this.pk.getnSquared()) >= 0);
		
		this.a = r.modPow(this.pk.getN(), this.pk.getnSquared());
		
		BigInteger e = this.deriveChallenge(this.a.toByteArray());
		
		this.z = v.modPow(e, this.pk.getnSquared());
		this.z = this.z.multiply(r);
		this.z = this.z.mod(this.pk.getnSquared());
	}

	private BigInteger deriveChallenge(byte[] a) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA256");
			byte[] seed = md.digest(a);
			SecretKeySpec secretKey = new SecretKeySpec(seed, "AES");
			byte[] eBytes = new byte[(this.secBits+7)/8];
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			ByteArrayOutputStream baos = new ByteArrayOutputStream(16);
			CipherOutputStream cos = new CipherOutputStream(baos, cipher);
			cos.write(eBytes);
			eBytes = cos.toString().getBytes();
			long mask = (1 << (this.secBits % 8)) - 1;
			if (mask > 0) {
				eBytes[0] &= mask;
			}
			return new BigInteger(eBytes);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public void verify() throws InvalidPrimalityProofException {
		this.verifyInstance();
	}

	private void verifyInstance() throws InvalidPrimalityProofException {
		BigInteger zn = this.z.modPow(this.pk.getN(), this.pk.getnSquared());
		
		BigInteger e = this.deriveChallenge(this.a.toByteArray());
		
		BigInteger aue = this.u.modPow(e, this.pk.getnSquared());
		aue = aue.multiply(this.a);
		aue = aue.mod(this.pk.getnSquared());
		
		if (zn.compareTo(aue) != 0) {
			throw new InvalidPrimalityProofException();
		}	
	}
}
