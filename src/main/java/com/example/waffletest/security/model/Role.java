package com.example.waffletest.security.model;

import org.springframework.security.core.GrantedAuthority;

public class Role implements GrantedAuthority {
    private String authority;

    public Role() {
        this.authority = "ROLE_ADMIN";
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}
