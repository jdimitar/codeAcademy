package com.example.jwtSecurity.controller;

import java.security.Principal;
import java.util.Collections;

import javax.annotation.security.RolesAllowed;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hibernate.mapping.Collection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.thymeleaf.extras.springsecurity5.auth.Authorization;

import com.example.jwtSecurity.entity.CurrentUser;
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

@Controller
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

	@GetMapping("/login")
	public String login(Model model) {
		LoginRequest request = new LoginRequest();
		model.addAttribute("request", request);
		return "login";
	}

	@GetMapping("/signup")
	public String home(Model model) {
		SignUpRequest request = new SignUpRequest();
		model.addAttribute("request", request);
		return "signup";
	}

	@GetMapping("/index")
	public String index(Model model, HttpServletRequest request, @CurrentUser UserPrincipal principal) {
		model.addAttribute("principal", principal);
		return "index";
	}

	@PostMapping("/auth/signUpAdmin")
	public String signUpAdministrator(@ModelAttribute("request") SignUpRequest request) {

		if (userRepo.existsByUsername(request.getUsername())) {

//			return ResponseEntity.badRequest().body("Administrator with same username already exists");
			return "error";
		}

		if (userRepo.existsByEmail(request.getEmail())) {

//			return ResponseEntity.badRequest().body("Administrator with same email already exists");
			return "error";
		}

		User user = new User();
		user.setEmail(request.getEmail());
		user.setName(request.getName());
		user.setUsername(request.getUsername());
		user.setPassword(passwordEncoder.encode(request.getPassword()));

		Roles role = roleRepo.findByRole(RoleName.ROLE_ADMINISTRATOR);

		user.setRoles(Collections.singleton(role));

		userRepo.save(user);

//		return ResponseEntity.ok("Administrator has been created");
		return "redirect:/login";

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
	public String signIn(@ModelAttribute("request") LoginRequest request, HttpServletResponse response) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getUsernameOrEmail(), request.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
		String accessJwt = tokenProvider.generate(userPrincipal.getId(), userPrincipal.getUsername(),
				userPrincipal.getRole());

		// header
		response.setHeader("Authorization", "Bearer " + accessJwt);


//		return ResponseEntity.ok(accessJwt);
		return "redirect:/index";

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
