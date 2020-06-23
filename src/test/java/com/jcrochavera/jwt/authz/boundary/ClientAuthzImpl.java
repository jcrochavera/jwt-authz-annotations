package com.jcrochavera.jwt.authz.boundary;

import com.jcrochavera.jwt.authz.control.UserSession;
import com.jcrochavera.jwt.authz.control.UserSessionExtended;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.json.JsonObject;
import java.util.Objects;

/**
 * Created by julio.rocha on 21/6/19.
 * <p>
 * It's the service boundary to be injected by CDI. It contains {@link UserSession} and {@link JsonWebToken} principal
 * </p>
 * <p>
 * The next claims are mandatory inside  {@link JsonWebToken}
 * </p>
 * <ul>
 *     <li>preferred_username</li>
 *     <li>email</li>
 *     <li>tenant</li>
 *     <li>groupId</li>
 * </ul>
 * <p>
 *     And optional claim is authorization inside {@link JsonWebToken},
 *     this should be provided when the resource required permission's evaluation
 * </p>
 *
 * @author julio.rocha
 * @since 1.0.0
 */
@RequestScoped
public class ClientAuthzImpl implements ClientAuthz {
    @Inject
    JsonWebToken principal;
    @Inject
    @Claim("preferred_username")
    String userName;
    @Inject
    @Claim("email")
    String email;
    @Inject
    @Claim("tenant")
    String tenant;
    @Inject
    @Claim("groupId")
    Long groupId;
    @Inject
    @Claim("authorization")
    JsonObject authorization;

    UserSession userSession;


    @PostConstruct
    void init() {
        if (Objects.nonNull(principal) && Objects.nonNull(principal.getName())) {
            this.userSession = new UserSessionExtended(userName, email, tenant, groupId, authorization);
        }
    }

    @Override
    public UserSession getSession() {
        return this.userSession;
    }

    @Override
    public JsonWebToken getPrincipal() {
        return this.principal;
    }
}
