package com.example.jwtSecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
		  prePostEnabled = true, 
		  securedEnabled = true, 
		  jsr250Enabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
    CustomUserDetailsService customUserDetailsService;
	
	@Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
	
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
//    	PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    	
    	authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }
	
	@Bean(BeanIds.AUTHENTICATION_MANAGER)
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		
		http
			.cors()
			.disable()
			.csrf()
			.disable()
//			.formLogin()
//	        .loginPage("/login.html")
//	        .permitAll()
//	        .successForwardUrl("/index")
//	        .and()
			.exceptionHandling()
            .authenticationEntryPoint(unauthorizedHandler)
            .and()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authorizeRequests()
			.antMatchers("/**",
				    "/index",
				    "/favicon.ico",
				    "/**/*.png",
				    "/**/*.gif",
				    "/**/*.svg",
				    "/**/*.jpg",
				    "/**/*.html",
				    "/**/*.css",
				    "/**/*.js")
			.permitAll()
			.antMatchers("/auth/signUpAdmin", "/auth/signUpUser", "/auth/signIn", "/signup", "/login")
			.permitAll()
			.anyRequest()
			.authenticated();
		
		http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception{
		web.ignoring()
		.antMatchers("/swagger-ui.html")
		.antMatchers("/swagger-documents/**")
		.antMatchers("/**", "/resources/**", "index.html","signup", "login", "signup.html", "login.html")
        .antMatchers("/resources/**","/templates/**", "/static/**", "/css/**", "/js/**", "/img/**", "/icon/**");
		;
	}

}
