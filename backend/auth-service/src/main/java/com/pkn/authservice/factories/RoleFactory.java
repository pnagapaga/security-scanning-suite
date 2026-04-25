package com.pkn.authservice.factories;

import com.pkn.authservice.enums.ERole;
import com.pkn.authservice.exceptions.RoleNotFoundException;
import com.pkn.authservice.modals.Role;
import com.pkn.authservice.services.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class RoleFactory {
    @Autowired
    RoleService roleService;

    public Role getInstance(String role) throws RoleNotFoundException {
        if (role.equals("admin")) {
            return roleService.findByName(ERole.ROLE_ADMIN);
        }
        else if (role.equals("user")){
            return roleService.findByName(ERole.ROLE_USER);
        }
        throw new RoleNotFoundException("Invalid role name: " + role);
    }

}
