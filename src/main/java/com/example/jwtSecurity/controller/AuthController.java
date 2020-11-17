package com.example.jwtSecurity.controller;

import java.util.Collections;

import javax.annotation.security.RolesAllowed;

import org.hibernate.mapping.Collection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.jwtSecurity.entity.LoginRequest;
import com.example.jwtSecurity.entity.Roles;
import com.example.jwtSecurity.entity.RoleName;
import com.example.jwtSecurity.entity.SignUpRequest;
import com.example.jwtSecurity.entity.User;
import com.example.jwtSecurity.entity.UserPrincipal;
import com.example.jwtSecurity.repository.RoleRepository;
import com.example.jwtSecurity.repository.UserRepository;
import com.example.jwtSecurity.security.JwtTokenService;

import lombok.EqualsAndHashCode;

@RestController
public class AuthController {

	@Autowired
	UserRepository userRepo;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	RoleRepository roleRepo;
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	JwtTokenService tokenProvider;

	@PostMapping("/auth/signUpAdmin")
	public ResponseEntity signUpAdministrator(@RequestBody SignUpRequest request) {

		if (userRepo.existsByUsername(request.getUsername())) {

			return ResponseEntity.badRequest().body("Administrator with same username already exists");

		}

		if (userRepo.existsByEmail(request.getEmail())) {

			return ResponseEntity.badRequest().body("Administrator with same email already exists");

		}

		User user = new User();
		user.setEmail(request.getEmail());
		user.setName(request.getName());
		user.setUsername(request.getUsername());
		user.setPassword(passwordEncoder.encode(request.getPassword()));

		Roles role = roleRepo.findByRole(RoleName.ROLE_ADMINISTRATOR);

		user.setRoles(Collections.singleton(role));

		userRepo.save(user);

		return ResponseEntity.ok("Administrator has been created");

	}

	@PostMapping("/auth/signUpUser")
	public ResponseEntity signUpUser(@RequestBody SignUpRequest request) {
		
		if (userRepo.existsByUsername(request.getUsername())) {

			return ResponseEntity.badRequest().body("User with same username already exists");

		}

		if (userRepo.existsByEmail(request.getEmail())) {

			return ResponseEntity.badRequest().body("User with same email already exists");

		}

		User user = new User();
		user.setEmail(request.getEmail());
		user.setName(request.getName());
		user.setUsername(request.getUsername());
		user.setPassword(passwordEncoder.encode(request.getPassword()));

		Roles role = roleRepo.findByRole(RoleName.ROLE_USER);

		user.setRoles(Collections.singleton(role));

		userRepo.save(user);

		return ResponseEntity.ok("User has been created");

	}

	@PostMapping("/auth/signIn")
	public ResponseEntity signIn(@RequestBody LoginRequest request) {
		
		 Authentication authentication = authenticationManager
			        .authenticate(new UsernamePasswordAuthenticationToken(request.getUsernameOrEmail(), request.getPassword()));
			    SecurityContextHolder.getContext()
			        .setAuthentication(authentication);
			    UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
			    String accessJwt = tokenProvider.generate(userPrincipal.getId(), userPrincipal.getUsername(), userPrincipal.getRole());
		
		return ResponseEntity.ok(accessJwt);

	}
	
	@GetMapping("/auth/user")
	@PreAuthorize("hasRole('USER')")
	public String getCurrentUser() {
		return "Hello user";
	}

	@GetMapping("/auth/admin")
	@PreAuthorize("hasRole('ADMINISTRATOR')")
	public String getCurrentAdmin() {
		return "Hello admin";
	}

}
