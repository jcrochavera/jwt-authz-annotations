package com.github.jcrochavera.jwt.authz.boundary;

import com.github.jcrochavera.jwt.authz.annotations.Operation;
import com.github.jcrochavera.jwt.authz.annotations.RequiresPermission;
import com.github.jcrochavera.jwt.authz.annotations.RequiresPermissions;
import com.github.jcrochavera.jwt.authz.utils.BasicRoles;
import com.github.jcrochavera.jwt.authz.utils.Permission;
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
@SuppressWarnings("unused")
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
