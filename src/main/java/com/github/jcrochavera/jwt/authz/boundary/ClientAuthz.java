package com.github.jcrochavera.jwt.authz.boundary;

import com.github.jcrochavera.jwt.authz.control.UserSession;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * Created by julio.rocha on 21/6/19.
 * <p>
 * It's the interface for service boundary base to be injected by CDI.
 * It returns {@link UserSession} and {@link JsonWebToken} principal.
 * Example:
 *
 * <pre>
 * import com.jcrochavera.jwt.authz.control.UserSession;
 * import com.jcrochavera.jwt.authz.control.UserSessionExtended;
 * import org.eclipse.microprofile.jwt.Claim;
 * import org.eclipse.microprofile.jwt.JsonWebToken;
 *
 * import jakarta.annotation.PostConstruct;
 * import jakarta.enterprise.context.RequestScoped;
 * import jakarta.inject.Inject;
 * import jakarta.json.JsonObject;
 * import java.util.Objects;
 * &#47;&#42;&#42;
 *  &#42; Created by julio.rocha on 21/6/19.
 *  &#42; &lt;p&gt;
 *  &#42; It's the service boundary to be injected by CDI. It contains {@link UserSession} and {@link JsonWebToken} principal
 *  &#42; &lt;/p&gt;
 *  &#42; &lt;p&gt;
 *  &#42; The next claims are mandatory inside  {@link JsonWebToken}
 *  &#42; &lt;/p&gt;
 *  &#42; &lt;ul&gt;
 *  &#42;     &lt;li&gt;preferred_username&lt;/li&gt;
 *  &#42;     &lt;li&gt;email&lt;/li&gt;
 *  &#42;     &lt;li&gt;tenant&lt;/li&gt;
 *  &#42;     &lt;li&gt;groupId&lt;/li&gt;
 *  &#42; &lt;/ul&gt;
 *  &#42; &lt;p&gt;
 *  &#42;     And optional claim is authorization inside {@link JsonWebToken},
 *  &#42;     this should be provided when the resource required permission's evaluation
 *  &#42; &lt;/p&gt;
 *  &#42;
 *  &#42; @author julio.rocha
 *  &#42; @since 1.0.0
 *  &#42;&#47;
 * {@literal @}RequestScoped
 * public class ClientAuthzImpl implements ClientAuthz {
 *     {@literal @}Inject
 *     JsonWebToken principal;
 *     {@literal @}Inject
 *     {@literal @}Claim("preferred_username")
 *     String userName;
 *     {@literal @}Inject
 *     {@literal @}Claim("email")
 *     String email;
 *     {@literal @}Inject
 *     {@literal @}Claim("tenant")
 *     String tenant;
 *     {@literal @}Inject
 *     {@literal @}Claim("groupId")
 *     Long groupId;
 *     {@literal @}Inject
 *     {@literal @}Claim("authorization")
 *     JsonObject authorization;
 *
 *     UserSession userSession;
 *
 *
 *     {@literal @}PostConstruct
 *     void init() {
 *         if (Objects.nonNull(principal) &amp;&amp; Objects.nonNull(principal.getName())) {
 *             this.userSession = new UserSessionExtended(userName, email, tenant, groupId, authorization);
 *         }
 *     }
 *
 *     {@literal @}Override
 *     public UserSession getSession() {
 *         return this.userSession;
 *     }
 *
 *     {@literal @}Override
 *     public JsonWebToken getPrincipal() {
 *         return this.principal;
 *     }
 * }
 * </pre>
 *
 * @author julio.rocha
 * @since 1.0.0
 */
public interface ClientAuthz {
    /**
     * @return the instance of {@link UserSession} for the current session
     */
    UserSession getSession();

    /**
     * @return the instance of {@link JsonWebToken} for the current session
     */
    JsonWebToken getPrincipal();
}
