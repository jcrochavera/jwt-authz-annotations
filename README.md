# jwt-authz-annotations

The main purpose of this library is to extend the MP-JWT specification using resource based tokens provided by Keycloak in the RPT token.

### AuthorizationFilter
AuthorizationFilter must be called in a filter providing ResourceInfo and ClientAuthz implementations. Example:
```
@Provider
@Priority(Priorities.AUTHORIZATION)
public class MyAuthorizationFilter implements ContainerRequestFilter {
    @Context
    ResourceInfo resourceInfo;
    @Inject
    ClientAuthzImpl clientAuth;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        AuthorizationFilter af = new AuthorizationFilter(resourceInfo, clientAuth);
        af.filter(requestContext);
    }
}
```

### ClientAuthz
ClientAuthz must be implemented with your required information. Example:
```
import UserSession;
import UserSessionExtended;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.JsonWebToken;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
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
```
Notice that also UserSession has been extended for this implementation:
```
import jakarta.json.JsonObject;
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

```
### Resource Format
There are two formats for the resource:
```
1. RESOURCE:OWNER
   - Name of the resource follow of the owner 
2. RESOURCE:OWNER:INSTANCE
   - Name of the resource follow of the owner and the instance to be evaluated in annotations
```
Once you have your custom ClientAuth implementation (also your resources in the right format), you can use roles and authorization resource annotations
```
import Operation;
import RequiresPermission;
import RequiresPermissions;
import BasicRoles;
import Permission;

import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * Created by julio.rocha on 21/6/19.
 *
 * @author julio.rocha
 */
@Path("/test")
public class ResourceTest {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String openEndpoint() {
        return "Hello " + System.currentTimeMillis();
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed(BasicRoles.USER)
    public String helloTest() {
        return "Hello " + System.currentTimeMillis();
    }

    @GET
    @Path("/{id}")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed(BasicRoles.USER)
    @RequiresPermissions(permissions = {
            @RequiresPermission(resource = "REPORTS", instance = "id",
                    value = {Permission.READ, Permission.EXECUTE, Permission.PRINT, Permission.UPDATE},
                    operation = Operation.AND
            )
    })
    public String helloTest1(@PathParam("id") String id) {
        return "Hello " + System.currentTimeMillis();
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed(BasicRoles.USER)
    @RequiresPermissions(permissions = {
            @RequiresPermission(resource = "GROUPS",
                    value = {Permission.INSERT, Permission.UPDATE, Permission.DELETE, Permission.ARCHIVE},
                    operation = Operation.AND
            )
    })
    public String helloTest2() {
        return "Hello " + System.currentTimeMillis();
    }

    @GET
    @Path("/groups/{idGroups}/reports/{idReports}")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed(BasicRoles.USER)
    @RequiresPermissions(permissions = {
            @RequiresPermission(resource = "REPORTS", instance = "idReports",
                    value = {Permission.READ, Permission.EXECUTE, Permission.PRINT, Permission.UPDATE},
                    operation = Operation.AND
            ),
            @RequiresPermission(resource = "GROUPS", instance = "idGroups",
                    value = {Permission.INSERT, Permission.UPDATE, Permission.DELETE, Permission.ARCHIVE},
                    operation = Operation.AND
            )
    })
    public String helloTest3(@PathParam("idReports") String idReports, @PathParam("idGroups") String idGroups) {
        return "Hello " + System.currentTimeMillis();
    }
}
```
