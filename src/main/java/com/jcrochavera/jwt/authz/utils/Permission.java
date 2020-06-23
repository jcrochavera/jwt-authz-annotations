package com.jcrochavera.jwt.authz.utils;

/**
 * Created by julio.rocha on 21/6/19.
 *
 * @author julio.rocha
 * @since 1.0.0
 */
public class Permission {
    Permission() {
    }

    public static final String READ = "r";
    public static final String INSERT = "i";
    public static final String UPDATE = "u";
    public static final String DELETE = "d";
    public static final String ARCHIVE = "a";
    public static final String EXECUTE = "x";
    public static final String PRINT = "p";
}
