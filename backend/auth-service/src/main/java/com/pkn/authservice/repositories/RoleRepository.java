package com.pkn.authservice.repositories;

import com.pkn.authservice.enums.ERole;
import com.pkn.authservice.modals.Role;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
    boolean existsByName(ERole name);
}