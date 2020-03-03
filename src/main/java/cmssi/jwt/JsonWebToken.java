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
package cmssi.jwt;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import cmssi.jwa.Base64URL;
import cmssi.jwa.Hs256;
import cmssi.jwa.Rs256;
import cmssi.lyson.LysonParser;
import cmssi.lyson.handler.MappingHandler;

/**
 * Implementation of the JSON Web Token (JWT) data structure, that is a compact and 
 * URL-safe means of representing claims to be transferred between two parties. The 
 * claims in a JWT are encoded as a JSON object that is used as the payload of a JSON 
 * Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) 
 * structure, enabling the claims to be digitally signed or integrity protected with 
 * a Message Authentication Code (MAC) and/or encrypted. 
 * 
 * @author cmunilla@cmssi.fr
 * @version 0.1
 */
public class JsonWebToken {
	
	private static Logger LOG = Logger.getLogger(JsonWebToken.class.getName());
	
	private String data;
	private String name;
	private boolean valid;
	
	private Map<String,Object> claims;
	
	/**
	 * Constructor
	 */
	public JsonWebToken() {
		this.claims = new HashMap<>();
		this.valid = false;
	}
	
	/**
	 * Constructor 
	 * 
	 * @param data the String raw representation of the JsonWebToken
	 * to be instantiated
	 */
	public JsonWebToken(String data) {
		this();
		this.data = data;
		int part1 = data.indexOf(".");
		int part2 = data.lastIndexOf(".");
		
		//JWT header to a Map to identify the encoding algorithm in use
		LysonParser parser = new LysonParser(Base64URL.base64UrlDecoding(data.substring(0, part1)));
		MappingHandler handler = new MappingHandler();
		parser.parse(handler);		
		Map<String,Object> jose = (Map<String, Object>) handler.getMapped();		
		String algorithm = (String) jose.get("alg");
		this.claims.put("algorithm",algorithm);
		
		parser = new LysonParser(Base64URL.base64UrlDecoding(data.substring(part1 + 1, part2)));
		handler = new MappingHandler();
		parser.parse(handler);
		
		Map<String,Object> payload = (Map<String, Object>) handler.getMapped();
		this.claims.putAll(payload);
		
		String[] str = new String[] {"name","preferred_name","sub"};
		for(int i=0;i<str.length;i++) {
			String value = (String) this.claims.get(str[i]);
			if(value!=null) {
				this.name = value;
				break;
			}
		}
	}

	/**
	 * Process the String key passed as parameter to validate this 
	 * JsonWebToken
	 * 
	 * @param key the String key allowing to validate or invalidate this
	 * JsonWebToken
	 */
	protected void checkValid(String key) {
		int part2 = data.lastIndexOf(".");		
		try {
			String signature = Base64URL.base64UrlDecoding(data.substring(part2 + 1));				
			String usefulload = data.substring(0, part2);
			String algorithm = String.valueOf(this.claims.get("algorithm"));
			this.valid = false;
			switch(algorithm) {		
				case "RS256":					
					this.valid = new Rs256().checkValid(usefulload, signature, key);
					break;
				case "HS256":							
					this.valid = new Hs256().checkValid(usefulload, signature, key);
					break;
				case "none":							
					this.valid = true;
					break;
			    default:
				     break;
			}
		} catch (RuntimeException e) {
			if(LOG.isLoggable(Level.SEVERE)) {
				LOG.log(Level.SEVERE, e.getMessage(),e);
			}
		}		
	}
	
	/**
	 * Returns true if this JsonWebToken is valid - If this JsonWebToken has not 
	 * been validated or is not valid, returns false
	 * 
	 * @return
	 * <ul>
	 *     <li>true if this token has been validated</li>
	 *     <li>false if this token is not valid or has not been validated</li>
	 * </ul>
	 */
	public boolean isValid() {
		return this.valid;
	}

	/**
	 * Return the String name attribute of this JsonWebToken
	 * 
	 * @return this JsonWebToken String name
	 */
	public String getName() {
		return this.name;
	}
	
	/**
	 * Returns the Object value of the claim of this JsonWebToken whose name 
	 * is passed as parameter
	 * 
	 * @param claimName the name of the claim to retrieve the value of
	 * 
	 * @return the Object value of the specified claim
	 */
	public Object getClaim(String claimName) {
		Object claim =  this.claims.get(claimName);
		return claim;
	}

	@Override
	public String toString() {		
		return data;
	}
}
