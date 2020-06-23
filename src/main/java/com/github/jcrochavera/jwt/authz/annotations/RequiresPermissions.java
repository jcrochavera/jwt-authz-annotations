package com.github.jcrochavera.jwt.authz.annotations;

import com.github.jcrochavera.jwt.authz.control.UserSession;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Created by julio.rocha on 21/6/19.
 * <p>
 * Requires that {@link UserSession} has {@link RequiresPermission}
 * in a resource or a resource with instance in order to executed a method
 * </p>
 * <p>
 * For example, this declaration:
 * </p>
 * <pre>
 *     &#64;RequiresPermissions(permissions = {
 *             &#64;RequiresPermission(resource = "MY_RESOURCE", instance = "idPathParam1",
 *                     value = {Permission.READ, Permission.EXECUTE},
 *                     operation = Operation.OR
 *             ),
 *             &#64;RequiresPermission(resource = "MY_OTHER_RESOURCE", instance = "idPathParam2",
 *                     value = {Permission.INSERT, Permission.UPDATE, Permission.DELETE},
 *                     operation = Operation.AND
 *             )
 *     })
 *     public String hello(@PathParam("idPathParam2") String idReports, @PathParam("idPathParam1") String idPathParam1)
 * </pre>
 *
 * @author julio.rocha
 * @since 1.0.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermissions {
    /**
     * @return the defined permission annotations
     */
    RequiresPermission[] permissions();
}
