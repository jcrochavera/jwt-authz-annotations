package com.jcrochavera.jwt.authz.utils;

import org.hamcrest.core.IsEqual;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by julio.rocha on 21/6/19.
 *
 * @author julio.rocha
 */
public class BasicRolesTest {
    @Test
    public void verificationTest() {
        BasicRoles roles = new BasicRoles();
        assertThat(roles.USER, is(IsEqual.equalTo("User")));
        assertThat(roles.ADMIN, is(IsEqual.equalTo("Admin")));
    }
}