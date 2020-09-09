package com.course.security.course.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    public abstract Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
