package com.example.demo.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.repository.EmployeeRepository;

@Component
public class JwtTokenFilter extends OncePerRequestFilter{

	@Autowired
    private MyUserDetails myUserDetails;

    @Autowired
	private JwtTokenUtil jwtTokenUtil;

    @Override
	protected void doFilterInternal(HttpServletRequest request, 
									HttpServletResponse response, 
									FilterChain chain) throws ServletException, IOException {

		final String requestTokenHeader = request.getHeader("Authorization");
		final String username;
		final String jwtToken;

		if (requestTokenHeader == null || !requestTokenHeader.startsWith("Bearer ")) {
			chain.doFilter(request, response);
			return;
		}

		jwtToken = requestTokenHeader.substring(7);
		username = jwtTokenUtil.getUsernameFromToken(jwtToken);
	
		// Once we get the token validate it.
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			UserDetails userDetails = this.myUserDetails.loadUserByUsername(username);
			// myUserDetails = (MyUserDetails) myUserDetails.loadUserByUsername(username);
			// System.out.println(myUserDetails.getAuthorities());
			// authentication
			// var role = myUserDetails.getAuthorities(); 
			// String auth = null;
			// role.stream()
			// 	.map(GrantedAuthority::getAuthority)
			// 	.forEach(authRole -> {auth = authRole;});
			
			if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {

				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		
		chain.doFilter(request, response);
	}
}
