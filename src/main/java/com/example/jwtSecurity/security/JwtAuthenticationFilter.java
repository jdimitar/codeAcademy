package com.example.jwtSecurity.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.jwtSecurity.entity.UserPrincipal;

import io.jsonwebtoken.JwtException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	JwtTokenService tokenProvider;

	@Autowired
	CustomUserDetailsService customUserDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {

			String jwt = getJwtFromRequest(request);
			
			 if (StringUtils.hasText(jwt) && tokenProvider.validate(jwt)) {
				UserPrincipal userPrincipal = tokenProvider.getPrincipalFromAccessToken(jwt);
				UserDetails userDetails = customUserDetailsService.loadUserByUserId(userPrincipal.getId());
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userPrincipal, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		        SecurityContextHolder.getContext()
		            .setAuthentication(authentication);
			}

		} catch (Exception e) {
			System.out.println("Authorization problems ");
		}
		
		filterChain.doFilter(request, response);

	}

	private String getJwtFromRequest(HttpServletRequest request) {

		// Example: Authorization Bearer 1234sdfghfkld.sgfdhgffjgj
		String bearerToken = request.getHeader("Authorization");
		return bearerToken.substring(7, bearerToken.length());

	}

}
