package com.github.jcrochavera.jwt.authz.utils;

import org.hamcrest.core.IsEqual;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by julio.rocha on 21/6/19.
 *
 * @author julio.rocha
 */
public class PermissionTest {
    @Test
    public void verificationTest() {
        Permission permission = new Permission();
        assertThat(permission.READ, is(IsEqual.equalTo("r")));
        assertThat(permission.INSERT, is(IsEqual.equalTo("i")));
        assertThat(permission.UPDATE, is(IsEqual.equalTo("u")));
        assertThat(permission.DELETE, is(IsEqual.equalTo("d")));
        assertThat(permission.ARCHIVE, is(IsEqual.equalTo("a")));
        assertThat(permission.EXECUTE, is(IsEqual.equalTo("x")));
        assertThat(permission.PRINT, is(IsEqual.equalTo("p")));
    }
}