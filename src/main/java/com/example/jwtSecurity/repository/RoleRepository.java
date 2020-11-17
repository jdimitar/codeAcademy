package com.example.jwtSecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.jwtSecurity.entity.Roles;
import com.example.jwtSecurity.entity.RoleName;

@Repository
public interface RoleRepository extends JpaRepository<Roles, Integer>{
	
	Roles findByRole(RoleName role);
}
