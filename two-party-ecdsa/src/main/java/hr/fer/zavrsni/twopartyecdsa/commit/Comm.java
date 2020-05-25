package hr.fer.zavrsni.twopartyecdsa.commit;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidCommitmentException;

public class Comm {
	public Uint256 val;
	
	public Comm(byte[] val) {
		this.val = val;
	}

	public static Comm commit(byte[] data, Nonce nonce) {
		SecureRandom sr = new SecureRandom();
		nonce.setVal(new BigInteger(256, sr));
		return _commit(data, nonce);
		
	}

	public void verify(byte[] data, Nonce nonce) {
		if (this.equals(_commit(data, nonce))) {
			return;
		}
		throw new InvalidCommitmentException();
	}
	
	public static Comm _commit(byte[] data, Nonce nonce) {
		MessageDigest h = MessageDigest.getInstance("SHA-256");
		h.update(data);
		h.update(nonce.getVal().toByteArray());
		
		Comm comm = new Comm(h.digest());
		return comm;
	}
}
