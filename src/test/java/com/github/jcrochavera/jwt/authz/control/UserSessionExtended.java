package com.github.jcrochavera.jwt.authz.control;

import javax.json.JsonObject;
import java.util.Objects;

/**
 * Created by julio.rocha on 21/6/19.
 * <p>
 * Represents the grouping of related information of a user session
 * </p>
 *
 * @author julio.rocha
 * @since 1.0.0
 */
public class UserSessionExtended extends UserSession {
    final String user;
    final String email;
    final String tenant;
    final Long groupId;

    /**
     * @param user          user's name  (mandatory)
     * @param email         user's email
     * @param tenant        user's tenant  (mandatory)
     * @param groupId       user's group (mandatory)
     * @param authorization user's authorization (not mandatory)
     */
    public UserSessionExtended(String user, String email, String tenant, Long groupId, JsonObject authorization) {
        super(user, authorization);
        Objects.requireNonNull(tenant, "Claim 'tenant' is mandatory");
        Objects.requireNonNull(groupId, "Claim 'groupId' is mandatory");
        this.user = user;
        this.email = email;
        this.tenant = tenant;
        this.groupId = groupId;
    }

    /**
     * @return user's email
     */
    public String getEmail() {
        return email;
    }

    /**
     * @return user's tenant
     */
    public String getTenant() {
        return tenant;
    }

    /**
     * @return user's group id
     */
    public Long getGroupId() {
        return groupId;
    }
}
