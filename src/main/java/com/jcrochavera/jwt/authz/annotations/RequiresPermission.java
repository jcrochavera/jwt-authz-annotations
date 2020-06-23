package com.jcrochavera.jwt.authz.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Created by julio.rocha on 21/6/19.
 * <p>
 * Requires that {@link com.jcrochavera.jwt.authz.control.UserSession} has certain permissions
 * in a resource or a resource with instance in order to executed a method.
 * </p>
 * <p>
 * For example, this declaration:
 * </p>
 * <pre>
 *     &#64;RequiresPermission(resource = "MY_RESOURCE", instance = "targetPathParamName",
 *             value = {Permission.READ, Permission.EXECUTE},
 *             operation = Operation.AND)
 * </pre>
 *
 * @author julio.rocha
 * @since 1.0.0
 */
@Target({ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermission {
    /**
     * <p>The defined resource under test</p>
     * <ul>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermission(String, String)}</li>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermissions(String, String...)}</li>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermissions(String, Operation, String...)}</li>
     * </ul>
     * <p>
     * In order to check resources permissions
     * </p>
     *
     * @return the defined resource under test
     */
    String resource();

    /**
     * <p>The defined instance under test</p>
     * <ul>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermission(String, String)}</li>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermissions(String, String...)}</li>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermissions(String, Operation, String...)}</li>
     * </ul>
     * <p>
     * In order to check instances permissions
     * </p>
     *
     * @return the defined instance under test
     */
    String instance() default "";

    /**
     * <p>The permission values under test</p>
     * <ul>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermission(String, String)}</li>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermissions(String, String...)}</li>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermissions(String, Operation, String...)}</li>
     * </ul>
     * <p>
     * In order to check resources permissions
     * </p>
     * Or
     * <ul>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermission(String, String)}</li>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermissions(String, String...)}</li>
     * <li>{@link com.jcrochavera.jwt.authz.control.UserSession#hasPermissions(String, Operation, String...)}</li>
     * </ul>
     * <p>
     * In order to check instances permissions
     * </p>
     *
     * @return defined permissions in annotation
     */
    String[] value();

    /**
     * The logical operation for the permission checks in case multiple permissions are specified. AND is the default
     *
     * @return the defined operation in annotation
     */
    Operation operation() default Operation.AND;
}
