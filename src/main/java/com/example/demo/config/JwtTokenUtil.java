package com.example.demo.config;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -2550185165626007488L;

	public static final long JWT_TOKEN_VALIDITY = 1 * 60 * 60;

	@Value("test")
	private String secret;

	//retrieve username from jwt token
	public String getUsernameFromToken(String token) {
		System.out.println(" token string is " + token);
		String getUsernameFromTokenString = getClaimFromToken(token, Claims::getSubject);
		System.out.println(" getUsernameFromTokenString based on getSubject is " + getUsernameFromTokenString);

		return getClaimFromToken(token, Claims::getSubject);
	}

	//retrieve expiration date from jwt token
	public Date getExpirationDateFromToken(String token) {

		Date getExpirationDateFromTokenDate = getClaimFromToken(token, Claims::getExpiration);
		System.out.println(" getExpirationDateFromTokenDate based on getExpiration is " + getExpirationDateFromTokenDate);

		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);

		System.out.println(" claims string inside getClaimFromToken is " + claims.toString());

		return claimsResolver.apply(claims);
	}


    //for retrieveing any information from token we will need the secret key
	private Claims getAllClaimsFromToken(String token) {


		System.out.println(" claims string inside getAllClaimsFromToken is " + Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody());

		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	//check if the token has expired
	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	//generate token for user
  //generate token for user
	public String generateToken(MyUserDetails myUserDetails) {
		Map<String, Object> claims = new HashMap<>();
		// Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();
		if (myUserDetails.getAuthorities().contains("Manager")) {
            claims.put("role", "manager");
        }
		if (myUserDetails.getAuthorities().contains("Staff")) {
            claims.put("role", "staff");
        }
		// if (userDetails instanceof MyUserDetails) {
		// 	String fullName = ((MyUserDetails) userDetails).getFullname();
		// 	claims.put("fullname", fullName);
		// }
		return Jwts.builder().setClaims(claims).setSubject(myUserDetails.getUsername()).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
		
	}
	//while creating the token -
	//1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
	//2. Sign the JWT using the HS512 algorithm and secret key.
	//3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
	//   compaction of the JWT to a URL-safe string

	//validate token
	public Boolean validateToken(String token, MyUserDetails myUserDetails) {
		final String username = getUsernameFromToken(token);

		return (username.equals(myUserDetails.getUsername()) && !isTokenExpired(token));
	}
}