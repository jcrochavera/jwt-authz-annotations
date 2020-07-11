package com.github.jcrochavera.jwt.authz.boundary;

import com.github.jcrochavera.jwt.authz.annotations.RequiresPermissions;
import com.github.jcrochavera.jwt.authz.utils.AnnotationUtils;
import com.github.jcrochavera.jwt.authz.utils.Permission;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.hamcrest.MatcherAssert;
import org.hamcrest.core.IsEqual;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import javax.annotation.security.RolesAllowed;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;
import java.lang.reflect.Method;

import static com.github.jcrochavera.jwt.authz.control.UserSessionTest.addResource;
import static com.github.jcrochavera.jwt.authz.control.UserSessionTest.addScopes;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by julio.rocha on 21/6/19.
 *
 * @author julio.rocha
 */
public class AuthorizationFilterTest {
    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void nullResourceMethod() {
        exceptionRule.expect(IllegalStateException.class);
        exceptionRule.expectMessage("resourceMethod is null, filter will not be executed");

        ContainerRequestContext containerRequestContext = Mockito.mock(ContainerRequestContext.class);
        ResourceInfo resourceInfo = Mockito.mock(ResourceInfo.class);
        ClientAuthzImpl clientAuth = new ClientAuthzImpl();
        AuthorizationFilter af = new AuthorizationFilter(resourceInfo, clientAuth);
        Mockito.when(af.resourceInfo.getResourceMethod()).thenReturn(null);
        af.filter(containerRequestContext);
    }

    @Test
    public void endpointWithoutProtection() throws Exception {
        ContainerRequestContext containerRequestContext = Mockito.mock(ContainerRequestContext.class);
        ResourceInfo resourceInfo = Mockito.mock(ResourceInfo.class);
        ClientAuthzImpl clientAuth = new ClientAuthzImpl();
        clientAuth.principal = null;
        clientAuth.userName = null;
        clientAuth.email = null;
        clientAuth.tenant = null;
        clientAuth.groupId = null;
        clientAuth.authorization = null;

        clientAuth.init();

        AuthorizationFilter af = new AuthorizationFilter(resourceInfo, clientAuth);

        ResourceTest rt = new ResourceTest();
        Method openEndpoint = rt.getClass().getMethod("openEndpoint");
        Mockito.when(af.resourceInfo.getResourceMethod()).thenReturn(openEndpoint);
        Mockito.doReturn(ResourceTest.class).when(af.resourceInfo).getResourceClass();
        af.filter(containerRequestContext);

        AnnotationUtils an = new AnnotationUtils(openEndpoint.getAnnotations());
        MatcherAssert.assertThat(an.getAnnotation(RequiresPermissions.class), nullValue());
        assertThat(an.getAnnotation(RolesAllowed.class), nullValue());

        assertThat(af.clientAuth.getPrincipal(), nullValue());
        assertThat(af.clientAuth.getSession(), nullValue());
    }

    @Test
    public void endpointWithoutSession() throws Exception {
        ContainerRequestContext containerRequestContext = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        ResourceInfo resourceInfo = Mockito.mock(ResourceInfo.class);
        ClientAuthzImpl clientAuth = new ClientAuthzImpl();
        clientAuth.principal = Mockito.mock(JsonWebToken.class);
        Mockito.when(clientAuth.principal.getName()).thenReturn(null);

        clientAuth.init();

        AuthorizationFilter af = Mockito.spy(new AuthorizationFilter(resourceInfo, clientAuth));

        ResourceTest rt = new ResourceTest();
        Method helloTest1 = rt.getClass().getMethod("helloTest1", String.class);
        Mockito.when(af.resourceInfo.getResourceMethod()).thenReturn(helloTest1);
        Mockito.doReturn(ResourceTest.class).when(af.resourceInfo).getResourceClass();


        Mockito.when(containerRequestContext.getUriInfo()).thenReturn(uriInfo);

        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.add("id", "2");
        Mockito.when(uriInfo.getPathParameters()).thenReturn(params);
        try {
            af.filter(containerRequestContext);
        } catch (NotAuthorizedException e) {
            //expected, because principal is not null and name is null
            assertThat(e.getMessage(), is(IsEqual.equalTo("HTTP 401 Unauthorized")));
        }
        assertThat(af.clientAuth.getPrincipal(), notNullValue());
        assertThat(af.clientAuth.getSession(), nullValue());
    }

    @Test
    public void userWithRolesOnly() throws Exception {
        ContainerRequestContext containerRequestContext = Mockito.mock(ContainerRequestContext.class);
        ResourceInfo resourceInfo = Mockito.mock(ResourceInfo.class);
        ClientAuthzImpl clientAuth = new ClientAuthzImpl();
        clientAuth.principal = Mockito.mock(JsonWebToken.class);
        Mockito.when(clientAuth.principal.getName()).thenReturn("dummyPrincipal");
        clientAuth.userName = "dummy";
        clientAuth.email = "dummy@dummy.com";
        clientAuth.tenant = "DUMMY";
        clientAuth.groupId = 3L;
        clientAuth.authorization = null;

        clientAuth.init();

        AuthorizationFilter af = new AuthorizationFilter(resourceInfo, clientAuth);

        ResourceTest rt = new ResourceTest();
        Method helloTest = rt.getClass().getMethod("helloTest");
        Mockito.when(af.resourceInfo.getResourceMethod()).thenReturn(helloTest);
        Mockito.doReturn(ResourceTest.class).when(af.resourceInfo).getResourceClass();
        af.filter(containerRequestContext);

        AnnotationUtils an = new AnnotationUtils(helloTest.getAnnotations());
        assertThat(an.getAnnotation(RequiresPermissions.class), nullValue());
        assertThat(an.getAnnotation(RolesAllowed.class), notNullValue());

        assertThat(af.clientAuth.getPrincipal(), notNullValue());
        assertThat(af.clientAuth.getSession(), notNullValue());
        MatcherAssert.assertThat(af.clientAuth.getSession().getResources().size(), is(IsEqual.equalTo(0)));
        MatcherAssert.assertThat(af.clientAuth.getSession().getInstances("dummy").size(), is(IsEqual.equalTo(0)));
    }

    @Test(expected = ForbiddenException.class)
    public void userWithRolesAndWrongResource() throws Exception {
        ContainerRequestContext containerRequestContext = Mockito.mock(ContainerRequestContext.class);
        ResourceInfo resourceInfo = Mockito.mock(ResourceInfo.class);
        ClientAuthzImpl clientAuth = new ClientAuthzImpl();
        clientAuth.principal = Mockito.mock(JsonWebToken.class);
        Mockito.when(clientAuth.principal.getName()).thenReturn("dummyPrincipal");
        clientAuth.userName = "dummy";
        clientAuth.email = "dummy@dummy.com";
        clientAuth.tenant = "DUMMY";
        clientAuth.groupId = 3L;

        String resourceName = "REPORTS";
        JsonObjectBuilder resource = addResource(resourceName + ":dummy");
        JsonArray permissions = Json.createArrayBuilder()
                .add(addScopes(resource, Permission.UPDATE))
                .build();
        clientAuth.authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        clientAuth.init();

        AuthorizationFilter af = new AuthorizationFilter(resourceInfo, clientAuth);

        ResourceTest rt = new ResourceTest();
        Method helloTest2 = rt.getClass().getMethod("helloTest2");
        Mockito.when(af.resourceInfo.getResourceMethod()).thenReturn(helloTest2);
        Mockito.doReturn(ResourceTest.class).when(af.resourceInfo).getResourceClass();
        af.filter(containerRequestContext);
    }


    @Test
    public void userWithRolesResourcesAndInstances() throws Exception {
        ContainerRequestContext containerRequestContext = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        ResourceInfo resourceInfo = Mockito.mock(ResourceInfo.class);
        ClientAuthzImpl clientAuth = new ClientAuthzImpl();
        clientAuth.principal = Mockito.mock(JsonWebToken.class);
        Mockito.when(clientAuth.principal.getName()).thenReturn("dummyPrincipal");
        clientAuth.userName = "dummy";
        clientAuth.email = "dummy@dummy.com";
        clientAuth.tenant = "DUMMY";
        clientAuth.groupId = 3L;

        String resourceName = "REPORTS";
        JsonObjectBuilder resource1 = addResource(resourceName + ":dummy:2");
        JsonArray permissions = Json.createArrayBuilder()
                .add(addScopes(resource1, Permission.READ, Permission.EXECUTE, Permission.PRINT, Permission.UPDATE))
                .build();
        clientAuth.authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        clientAuth.init();

        AuthorizationFilter af = Mockito.spy(new AuthorizationFilter(resourceInfo, clientAuth));

        ResourceTest rt = new ResourceTest();
        Method helloTest1 = rt.getClass().getMethod("helloTest1", String.class);
        Mockito.when(af.resourceInfo.getResourceMethod()).thenReturn(helloTest1);
        Mockito.doReturn(ResourceTest.class).when(af.resourceInfo).getResourceClass();


        Mockito.when(containerRequestContext.getUriInfo()).thenReturn(uriInfo);

        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.add("id", "2");
        Mockito.when(uriInfo.getPathParameters()).thenReturn(params);
        af.filter(containerRequestContext);

        assertThat(af.clientAuth.getPrincipal(), notNullValue());
        assertThat(af.clientAuth.getSession(), notNullValue());
        MatcherAssert.assertThat(af.clientAuth.getSession()
                .hasInstancePermissions(resourceName, "2", Permission.READ, Permission.EXECUTE,
                        Permission.PRINT, Permission.UPDATE), is(IsEqual.equalTo(true)));


        //check with no valid instances
        params = new MultivaluedHashMap<>();
        params.add("id", "25");
        Mockito.when(uriInfo.getPathParameters()).thenReturn(params);
        try {
            af.filter(containerRequestContext);
        } catch (ForbiddenException e) {
            assertThat(e.getMessage(), is(IsEqual.equalTo("HTTP 403 Forbidden")));
        }

        params = new MultivaluedHashMap<>();
        params.add("noValidParamName", "2");
        Mockito.when(uriInfo.getPathParameters()).thenReturn(params);
        try {
            af.filter(containerRequestContext);
        } catch (ForbiddenException e) {
            assertThat(e.getMessage(), is(IsEqual.equalTo("HTTP 403 Forbidden")));
        }
    }

    @Test
    public void userWithOneResource() throws Exception {
        ContainerRequestContext containerRequestContext = Mockito.mock(ContainerRequestContext.class);
        ResourceInfo resourceInfo = Mockito.mock(ResourceInfo.class);
        ClientAuthzImpl clientAuth = new ClientAuthzImpl();
        clientAuth.principal = Mockito.mock(JsonWebToken.class);
        Mockito.when(clientAuth.principal.getName()).thenReturn("dummyPrincipal");
        clientAuth.userName = "dummy";
        clientAuth.email = "dummy@dummy.com";
        clientAuth.tenant = "DUMMY";
        clientAuth.groupId = 3L;

        String resourceName = "GROUPS";
        JsonObjectBuilder resource = addResource(resourceName + ":dummy:2");
        JsonArray permissions = Json.createArrayBuilder()
                .add(addScopes(resource, Permission.INSERT, Permission.UPDATE, Permission.DELETE, Permission.ARCHIVE))
                .build();
        clientAuth.authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        clientAuth.init();

        AuthorizationFilter af = new AuthorizationFilter(resourceInfo, clientAuth);

        ResourceTest rt = new ResourceTest();
        Method helloTest2 = rt.getClass().getMethod("helloTest2");
        Mockito.when(af.resourceInfo.getResourceMethod()).thenReturn(helloTest2);
        Mockito.doReturn(ResourceTest.class).when(af.resourceInfo).getResourceClass();

        af.filter(containerRequestContext);

        assertThat(af.clientAuth.getPrincipal(), notNullValue());
        assertThat(af.clientAuth.getSession(), notNullValue());
        MatcherAssert.assertThat(af.clientAuth.getSession()
                .hasPermissions(resourceName, Permission.INSERT, Permission.UPDATE,
                        Permission.DELETE, Permission.ARCHIVE), is(IsEqual.equalTo(true)));
    }

    @Test
    public void userWithRolesMultipleResourcesAndInstances() throws Exception {
        ContainerRequestContext containerRequestContext = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        ResourceInfo resourceInfo = Mockito.mock(ResourceInfo.class);
        ClientAuthzImpl clientAuth = new ClientAuthzImpl();
        clientAuth.principal = Mockito.mock(JsonWebToken.class);
        Mockito.when(clientAuth.principal.getName()).thenReturn("dummyPrincipal");
        clientAuth.userName = "dummy";
        clientAuth.email = "dummy@dummy.com";
        clientAuth.tenant = "DUMMY";
        clientAuth.groupId = 3L;

        String resourceName1 = "REPORTS";
        String resourceName2 = "GROUPS";
        JsonObjectBuilder resource1 = addResource(resourceName1 + ":dummy:2");
        JsonObjectBuilder resource2 = addResource(resourceName2 + ":dummy:5");
        JsonArray permissions = Json.createArrayBuilder()
                .add(addScopes(resource1, Permission.READ, Permission.EXECUTE, Permission.PRINT, Permission.UPDATE))
                .add(addScopes(resource2, Permission.INSERT, Permission.UPDATE, Permission.DELETE, Permission.ARCHIVE))
                .build();
        clientAuth.authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        clientAuth.init();

        AuthorizationFilter af = new AuthorizationFilter(resourceInfo, clientAuth);

        ResourceTest rt = new ResourceTest();
        Method helloTest3 = rt.getClass().getMethod("helloTest3", String.class, String.class);
        Mockito.when(af.resourceInfo.getResourceMethod()).thenReturn(helloTest3);
        Mockito.doReturn(ResourceTest.class).when(af.resourceInfo).getResourceClass();


        Mockito.when(containerRequestContext.getUriInfo()).thenReturn(uriInfo);

        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.add("idReports", "2");
        params.add("idGroups", "5");
        Mockito.when(uriInfo.getPathParameters()).thenReturn(params);
        af.filter(containerRequestContext);

        assertThat(af.clientAuth.getPrincipal(), notNullValue());
        assertThat(af.clientAuth.getSession(), notNullValue());
        MatcherAssert.assertThat(af.clientAuth.getSession()
                .hasInstancePermissions(resourceName1, "2", Permission.READ, Permission.EXECUTE,
                        Permission.PRINT, Permission.UPDATE), is(IsEqual.equalTo(true)));
        MatcherAssert.assertThat(af.clientAuth.getSession()
                .hasInstancePermissions(resourceName1, "3", Permission.INSERT, Permission.UPDATE,
                        Permission.DELETE, Permission.ARCHIVE), is(IsEqual.equalTo(false)));
    }
}