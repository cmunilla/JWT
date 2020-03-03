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


/**
 * JWS uses cryptographic algorithms to digitally sign or create a MAC of the 
 * contents of the JWS Protected Header and the JWS Payload. The table below 
 * is the set of possible "alg" (algorithm) Header Parameter values:
 * <br>
 * +--------+--------------------------------------+<br>
 * | "alg"  | Digital Signature or MAC Algorithm   |<br>
 * +--------+--------------------------------------+<br>
 * | HS256  | HMAC using SHA-256                   |<br>
 * | HS384  | HMAC using SHA-384                   |<br>
 * | HS512  | HMAC using SHA-512                   |<br>
 * | RS256  | RSASSA-PKCS1-v1_5 using SHA-256      |<br>
 * | RS384  | RSASSA-PKCS1-v1_5 using SHA-384      |<br>
 * | RS512  | RSASSA-PKCS1-v1_5 using SHA-512      |<br>
 * | ES256  | ECDSA using P-256 and SHA-256        |<br>
 * | ES384  | ECDSA using P-384 and SHA-384        |<br>
 * | ES512  | ECDSA using P-521 and SHA-512        |<br>
 * | PS256  | RSASSA-PSS and MGF1 using SHA-256    |<br>
 * | PS384  | RSASSA-PSS and MGF1 using SHA-384    |<br>
 * | PS512  | RSASSA-PSS MGF1 and using SHA-512    |<br>
 * | none   | No digital signature or MAC performed|<br>
 * +--------+--------------------------------------+<br>
 *  
 * @author cmunilla@cmssi.fr
 * @version 0.1
 */
public interface JsonWebAlgorithm {
	
	/**
	 * Processes the String key passed as parameter to validate the useful load 
	 * String argument, according to the specified signature
	 * 
	 * @param usefulload the useful load String to be validated
	 * @param signature the encrypted signature allowing to evaluate the specified 
	 * useful load validity 
	 * @param key the String key allowing to validate or invalidate the useful load 
	 * according to the specified signature
	 * 
	 * @return 
	 * <ul>
	 * 	<li>true if the specified useful load is valid according to the defined 
	 *  signature and key</li>
	 * 	<li>false otherwise</li>
	 * </ul>
	 */
	boolean checkValid(String usefulload, String signature, String key);
}
