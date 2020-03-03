/**
 * @author cmunilla@cmssi.fr
 * @version 0.1
 */
module cmssi.jwt {
	
	requires cmssi.lyson;
	requires java.logging;

	exports cmssi.jwt;
	exports cmssi.jwa;
	
	opens cmssi.jwt to cmssi.lyson;
}