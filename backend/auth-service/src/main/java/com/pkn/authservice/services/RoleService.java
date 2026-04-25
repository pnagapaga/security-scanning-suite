package com.pkn.authservice.services;

import com.pkn.authservice.enums.ERole;
import com.pkn.authservice.modals.Role;
import org.springframework.stereotype.Service;

@Service
public interface RoleService {
    Role findByName(ERole eRole);
}