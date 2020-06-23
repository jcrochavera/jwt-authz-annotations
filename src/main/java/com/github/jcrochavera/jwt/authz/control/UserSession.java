package com.github.jcrochavera.jwt.authz.control;

import com.github.jcrochavera.jwt.authz.annotations.Operation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by julio.rocha on 21/6/19.
 * <p>
 * Represents the grouping of related information of a user session
 * </p>
 * Example of extension:
 * <pre>
 * &#47;&#42;&#42;
 *  &#42; Created by julio.rocha on 21&#47;6&#47;19.
 *  &#42; &lt;p&gt;
 *  &#42; Represents the grouping of related information of a user session
 *  &#42; &lt;&#47;p&gt;
 *  &#42;
 *  &#42; @author julio.rocha
 *  &#42; @since 1.0.0
 *  &#42;&#47;
 * public class UserSessionExtended extends UserSession {
 *     final String user;
 *     final String email;
 *     final String tenant;
 *     final Long groupId;
 *
 *     &#47;&#42;&#42;
 *      &#42; {@literal @}param user          user's name  (mandatory)
 *      &#42; {@literal @}param email         user's email
 *      &#42; {@literal @}param tenant        user's tenant  (mandatory)
 *      &#42; {@literal @}param groupId       user's group (mandatory)
 *      &#42; {@literal @}param authorization user's authorization (not mandatory)
 *      &#42;&#47;
 *     public UserSessionExtended(String user, String email, String tenant, Long groupId, JsonObject authorization) {
 *         super(user, authorization);
 *         Objects.requireNonNull(tenant, "Claim 'tenant' is mandatory");
 *         Objects.requireNonNull(groupId, "Claim 'groupId' is mandatory");
 *         this.user = user;
 *         this.email = email;
 *         this.tenant = tenant;
 *         this.groupId = groupId;
 *     }
 *
 *     &#47;&#42;&#42;
 *      &#42; {@literal @}return user's email
 *      &#42;&#47;
 *     public String getEmail() {
 *         return email;
 *     }
 *
 *     &#47;&#42;&#42;
 *      &#42; {@literal @}return user's tenant
 *      &#42;&#47;
 *     public String getTenant() {
 *         return tenant;
 *     }
 *
 *     &#47;&#42;&#42;
 *      &#42; {@literal @}return user's group id
 *      &#42;&#47;
 *     public Long getGroupId() {
 *         return groupId;
 *     }
 * }
 * </pre>
 *
 * @author julio.rocha
 * @since 1.0.0
 */
public class UserSession {
    static Logger LOG = LoggerFactory.getLogger(UserSession.class);
    final String user;
    final Map<String, Set<String>> resourcePermissions;
    final Map<String, Set<String>> instancePermissions;

    /**
     * @param user          user's name  (mandatory)
     * @param authorization user's authorization (not mandatory)
     */
    public UserSession(String user, JsonObject authorization) {
        Objects.requireNonNull(user, "Claim 'user' is mandatory");
        this.user = user;
        this.resourcePermissions = new HashMap<>();
        this.instancePermissions = new HashMap<>();
        this.initialize(authorization);
    }

    private void initialize(JsonObject authorization) {
        if (Objects.nonNull(authorization)) {
            JsonArray permissions = authorization.getJsonArray("permissions");
            processPermissions(permissions);
        } else {
            LOG.debug("No authorization has been provided");
        }
    }

    private void processPermissions(JsonArray permissions) {
        if (isValidArray(permissions)) {
            for (JsonValue p : permissions) {
                processResourceScopes(p);
            }
        } else {
            LOG.warn("No permissions has been provided");
        }
    }

    private void processResourceScopes(JsonValue p) {
        JsonObject resource = p.asJsonObject();
        String resourceFullName = resource.getString("rsname");
        String[] resourceUser = resourceFullName.split(":");
        if (!isValidFormat(resourceUser)) {
            LOG.warn("Resource '{}' is not compatible with RESOURCE:USER or " +
                    "RESOURCE:USER:INSTANCE, it will be ignored.", resourceFullName);
            return;
        }
        String resourceName = resourceUser[0];
        String instanceName = (resourceUser.length == 3) ? resourceUser[2] : null;
        String instanceKey = resourceName + instanceName;
        LOG.debug("Resource Name: {}", resourceName);
        LOG.debug("Resource User: {}", resourceUser[1]);
        LOG.debug("Resource Inst: {}", instanceName);
        JsonArray scopes = resource.getJsonArray("scopes");
        if (Objects.nonNull(scopes)) {
            Set<String> resourcesScopes = resourcesLazyInitialization(resourceName);
            Set<String> instanceScopes = instancesLazyInitialization(instanceName, instanceKey);
            for (JsonValue s : scopes) {
                String value = ((JsonString) s).getString();
                addScope(instanceName, resourcesScopes, instanceScopes, value);
            }
        } else {
            LOG.warn("No scopes has been provided for resource '{}'", resourceFullName);
        }
    }

    private boolean isValidArray(JsonArray permissions) {
        return Objects.nonNull(permissions) && !permissions.isEmpty();
    }

    private boolean isValidFormat(String[] resourceUser) {
        return resourceUser.length >= 2 && resourceUser.length <= 3;
    }

    private Set<String> resourcesLazyInitialization(String resourceName) {
        Set<String> resourcesScopes = resourcePermissions.get(resourceName);
        if (Objects.isNull(resourcesScopes)) {
            resourcesScopes = new HashSet<>();
            resourcePermissions.put(resourceName, resourcesScopes);
        }
        return resourcesScopes;
    }

    private Set<String> instancesLazyInitialization(String instanceName, String instanceKey) {
        Set<String> instanceScopes = instancePermissions.get(instanceKey);
        if (Objects.nonNull(instanceName) && Objects.isNull(instanceScopes)) {
            instanceScopes = new HashSet<>();
            instancePermissions.put(instanceKey, instanceScopes);
        }
        return instanceScopes;
    }

    private void addScope(String instanceName, Set<String> resourcesScopes, Set<String> instanceScopes, String value) {
        resourcesScopes.add(value);
        if (Objects.nonNull(instanceName)) {
            instanceScopes.add(value);
        }
    }

    /**
     * @return user's name
     */
    public String getUser() {
        return user;
    }

    /**
     * <p>true if user has the specific permission to the provided resource, false in other case.</p>
     *
     * @param resource   the resource under test
     * @param permission the permission under test
     * @return evaluation's result
     */
    public boolean hasPermission(String resource, String permission) {
        Set<String> permissions = resourcePermissions.get(resource);
        return Objects.nonNull(permissions) && permissions.contains(permission);
    }

    /**
     * <p>true if user has the specific permission to the provided resource, false in other case.</p>
     * {@link Operation#AND} is used by default
     *
     * @param resource    the resource under test
     * @param permissions the permissions under test
     * @return evaluation's result
     */
    public boolean hasPermissions(String resource, String... permissions) {
        return hasPermissions(resource, Operation.AND, permissions);
    }

    /**
     * <p>true if user has the specific permission to the provided resource, false in other case.</p>
     *
     * @param resource    the resource under test
     * @param operation   the operation to be applied on permission's evaluation
     * @param permissions the permissions under test
     * @return evaluation's result
     */
    public boolean hasPermissions(String resource, Operation operation, String... permissions) {
        boolean permitted = Operation.AND == operation;
        for (String p : permissions) {
            if (Operation.AND == operation) {
                permitted &= hasPermission(resource, p);
            } else {
                permitted = hasPermission(resource, p);
                if (permitted) {
                    break;
                }
            }
        }
        return permitted;
    }

    /**
     * <p>true if user has the specific permission to the provided resource and instance, false in other case.</p>
     *
     * @param resource   the resource under test
     * @param instance   the instance under test
     * @param permission the permission under test
     * @return evaluation's result
     */
    public boolean hasInstancePermission(String resource, String instance, String permission) {
        Set<String> permissions = instancePermissions.get(resource + instance);
        return Objects.nonNull(permissions) && permissions.contains(permission);
    }

    /**
     * <p>true if user has the specific permission to the provided resource and instance, false in other case.</p>
     * {@link Operation#AND} is used by default
     *
     * @param resource    the resource under test
     * @param instance    the instance under test
     * @param permissions the permissions under test
     * @return evaluation's result
     */
    public boolean hasInstancePermissions(String resource, String instance, String... permissions) {
        return hasInstancePermissions(resource, instance, Operation.AND, permissions);
    }

    /**
     * <p>true if user has the specific permission to the provided resource and instance, false in other case.</p>
     *
     * @param resource    the resource under test
     * @param instance    the instance under test
     * @param operation   the operation to be applied on permission's evaluation
     * @param permissions the permissions under test
     * @return evaluation's result
     */
    public boolean hasInstancePermissions(String resource, String instance, Operation operation, String... permissions) {
        boolean permitted = Operation.AND == operation;
        for (String p : permissions) {
            if (Operation.AND == operation) {
                permitted &= hasInstancePermission(resource, instance, p);
            } else {
                permitted = hasInstancePermission(resource, instance, p);
                if (permitted) {
                    break;
                }
            }
        }
        return permitted;
    }

    /**
     * @return a set of resources for the current session
     */
    public Set<String> getResources() {
        return resourcePermissions.keySet();
    }

    /**
     * @param resource the instances' resource
     * @return a set of instances for the provided resource in the current session
     */
    public Set<String> getInstances(String resource) {
        return instancePermissions.keySet().stream()
                .filter(k -> k.startsWith(resource))
                .map(k -> k.replace(resource, ""))
                .collect(Collectors.toSet());
    }
}
