/*
 * MIT License
 *
 * Copyright (c) 2020 Christophe Munilla
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package cmssi.jwa;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author cmunilla@cmssi.fr
 * @version 0.1
 */
public class Rs256 implements JsonWebAlgorithm {

	private static Logger LOG = Logger.getLogger(Rs256.class.getName());

	@Override
	public boolean checkValid(String usefulload, String signature, String key) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			Signature sig = Signature.getInstance("SHA256withRSA");	
						
			int index = key.indexOf('.');
		    String modulusBase64 =  Base64URL.base64UrlDecoding(key.substring(0,index));					
			String exponentBase64 = Base64URL.base64UrlDecoding(key.substring(index+1));
				         		        
			BigInteger modulus = new BigInteger(1, modulusBase64.getBytes());
			BigInteger publicExponent = new BigInteger(1, exponentBase64.getBytes());
	
			PublicKey pubKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));					
			sig.initVerify(pubKey);
			sig.update(usefulload.getBytes());
			return sig.verify(signature.getBytes());
		
		} catch (GeneralSecurityException e) {
			if(LOG.isLoggable(Level.SEVERE)) {
				LOG.log(Level.SEVERE, e.getMessage(),e);
			}
		}
		return false;
	}
	
}