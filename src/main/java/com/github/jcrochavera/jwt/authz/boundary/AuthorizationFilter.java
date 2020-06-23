package com.github.jcrochavera.jwt.authz.boundary;

import com.github.jcrochavera.jwt.authz.annotations.RequiresPermission;
import com.github.jcrochavera.jwt.authz.annotations.RequiresPermissions;
import com.github.jcrochavera.jwt.authz.annotations.Operation;
import com.github.jcrochavera.jwt.authz.control.UserSession;
import com.github.jcrochavera.jwt.authz.utils.AnnotationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Objects;

/**
 * Created by julio.rocha on 21/6/19.
 * <p>Checks annotated methods with {@link RequiresPermissions} in endpoints,
 * it returns {@link javax.ws.rs.core.Response.Status#FORBIDDEN} when: </p>
 * <ul>
 *     <li>Session does not have resource permission for the defined annotation</li>
 *     <li>Session does not have resource and instance permission for the defined annotation</li>
 *     <li>Request does not contain an expected instance name with no null value for the defined annotation</li>
 * </ul>
 *
 * @author julio.rocha
 * @since 1.0.0
 */
@Provider
@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {
    static Logger LOG = LoggerFactory.getLogger(AuthorizationFilter.class);
    @Context
    ResourceInfo resourceInfo;
    @Inject
    ClientAuthz clientAuth;

    /**
     * Executes algorithm when a method inside resource is annotated with {@link RequiresPermissions}
     *
     * @param requestContext incoming request
     * @throws IOException if something wrong in the request happens i.e request canceled
     */
    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        AnnotationUtils au = new AnnotationUtils(resourceInfo.getResourceMethod().getAnnotations());
        if (au.isAnnotationPresent(RequiresPermissions.class)) {
            LOG.debug("'{}' requires permission evaluation", resourceInfo.getResourceClass());
            RequiresPermissions requiresPermissions = au.getAnnotation(RequiresPermissions.class);
            RequiresPermission[] permissions = requiresPermissions.permissions();
            for (RequiresPermission permission : permissions) {
                String resource = permission.resource();
                String[] value = permission.value();
                Operation operation = permission.operation();
                String instanceName = permission.instance();
                evaluateOne(requestContext, resource, value, operation, instanceName);
            }
        } else {
            LOG.debug("'{}' Just requires role evaluation", resourceInfo.getResourceClass());
        }
    }

    private void evaluateOne(ContainerRequestContext containerRequestContext, String resource, String[] value, Operation operation, String instanceName) {
        UserSession session = clientAuth.getSession();
        if (Objects.isNull(session)) {
            throw new NotAuthorizedException("");
        }
        if (!instanceName.isEmpty()) {
            String instance = getInstanceFromParameter(containerRequestContext, instanceName);
            if (!session.hasInstancePermissions(resource, instance, operation, value)) {
                throw new ForbiddenException();
            }
        } else {
            if (!session.hasPermissions(resource, operation, value)) {
                throw new ForbiddenException();
            }
        }
    }

    private String getInstanceFromParameter(ContainerRequestContext containerRequestContext, String instanceName) {
        MultivaluedMap<String, String> pathParameters = containerRequestContext.getUriInfo().getPathParameters();
        String instance = pathParameters.getFirst(instanceName);
        if (Objects.isNull(instance)) {
            LOG.warn("Value for parameter '{}' was not provided", instanceName);
            throw new ForbiddenException();
        }
        return instance;
    }
}
