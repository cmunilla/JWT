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

import java.util.Base64;

/**
 * Base64URL encoding and decoding helper - Base64URL is a modification of the main Base64 
 * standard offering the ability to use the encoding result as filename or URL address. 
 *  
 * @author cmunilla@cmssi.fr
 * @version 0.1
 */
public abstract class Base64URL {

	/**
	 * Provides a Base64URL decoding process for the encoded String passed as parameter.
	 * 
	 * @param encoded the Base64URL encoded String to be decoded
	 * 
	 * @return the decoded Base64URL String
	 */
	public static String base64UrlDecoding(String encoded) {
		String decoded = encoded;
		while(((4 - decoded.length() % 4) % 4)!=0) {
			decoded = decoded.concat("=");
		}
		decoded = decoded.replace("-", "+");
		decoded = decoded.replace("_", "/");	
		decoded = new String(Base64.getDecoder().decode(decoded));
		return decoded;
	}

	/**
	 * Provides a Base64URL encoding process for the String passed as parameter.
	 * 
	 * @param decoded the String to be encoded using the Base64URL format
	 * 
	 * @return the Base64URL encoded String
	 */
	public static String base64UrlEncoding(String decoded) {
		return base64UrlEncoding(decoded.getBytes());
	}

	/**
	 * Provides a Base64URL encoding process for the bytes array passed as parameter.
	 * 
	 * @param decoded the array of bytes to be encoded using the Base64URL format
	 * 
	 * @return the Base64URL encoded String
	 */
	public static String base64UrlEncoding(byte[] decoded) {
		String encoded = new String(Base64.getEncoder().encode(decoded));
		encoded = encoded.split("=")[0]; // Remove any trailing '='s
		encoded = encoded.replace('+', '-'); // 62nd char of encoding
		encoded = encoded.replace('/', '_'); // 63rd char of encoding	
		return encoded;
	}
}