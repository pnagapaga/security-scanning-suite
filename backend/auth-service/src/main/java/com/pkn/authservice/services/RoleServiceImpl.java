package com.pkn.authservice.services;

import com.pkn.authservice.enums.ERole;
import com.pkn.authservice.modals.Role;
import com.pkn.authservice.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class RoleServiceImpl implements RoleService {

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public Role findByName(ERole eRole) {
        return roleRepository.findByName(eRole)
                .orElseThrow(() -> new RuntimeException("Role is not found."));
    }
}
