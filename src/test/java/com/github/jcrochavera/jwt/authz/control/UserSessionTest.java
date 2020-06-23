package com.github.jcrochavera.jwt.authz.control;

import com.github.jcrochavera.jwt.authz.annotations.Operation;
import org.hamcrest.MatcherAssert;
import org.hamcrest.core.IsEqual;
import org.junit.Test;

import javax.json.*;
import java.util.Arrays;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by julio.rocha on 21/6/19.
 *
 * @author julio.rocha
 */
public class UserSessionTest {

    @Test
    public void userWithoutJsonAuthorization() {
        String user = "dummy";
        String email = "dummy@dummy.com";
        String tenant = "DUMMY";
        Long groupId = 3L;
        UserSessionExtended session = new UserSessionExtended(user, email, tenant, groupId, null);

        assertThat(session.getUser(), is(IsEqual.equalTo(user)));
        assertThat(session.getEmail(), is(IsEqual.equalTo(email)));
        assertThat(session.getTenant(), is(IsEqual.equalTo(tenant)));
        assertThat(session.getGroupId(), is(IsEqual.equalTo(groupId)));

        assertThat(session.resourcePermissions.size(), is(IsEqual.equalTo(0)));
        assertThat(session.instancePermissions.size(), is(IsEqual.equalTo(0)));

        assertThat(session.getResources(), notNullValue());
        assertThat(session.getInstances("Dummy"), notNullValue());

        assertThat(session.getResources().size(), is(IsEqual.equalTo(0)));
        assertThat(session.getInstances("Dummy").size(), is(IsEqual.equalTo(0)));

        assertThat(session.hasPermission("Dummy", "r"), is(IsEqual.equalTo(false)));
        assertThat(session.hasPermissions("Dummy", "r"), is(IsEqual.equalTo(false)));
        assertThat(session.hasInstancePermission("Dummy", "34", "r"), is(IsEqual.equalTo(false)));
    }


    @Test
    public void userWithoutPermissionsArray() {
        String user = "dummy";
        String email = "dummy@dummy.com";
        String tenant = "DUMMY";
        Long groupId = 3L;
        JsonObject authorization = Json.createObjectBuilder().build();
        UserSessionExtended session = new UserSessionExtended(user, email, tenant, groupId, authorization);
        assertThat(session.resourcePermissions.size(), is(IsEqual.equalTo(0)));
        assertThat(session.instancePermissions.size(), is(IsEqual.equalTo(0)));
    }

    @Test
    public void userWithEmptyPermissionsArray() {
        String user = "dummy";
        String email = "dummy@dummy.com";
        String tenant = "DUMMY";
        Long groupId = 3L;
        JsonObject authorization = Json.createObjectBuilder()
                .add("permissions", Json.createArrayBuilder())
                .build();
        UserSessionExtended session = new UserSessionExtended(user, email, tenant, groupId, authorization);
        assertThat(session.resourcePermissions.size(), is(IsEqual.equalTo(0)));
        assertThat(session.instancePermissions.size(), is(IsEqual.equalTo(0)));
    }

    @Test
    public void userWithoutValidResources() {
        String user = "dummy";
        String email = "dummy@dummy.com";
        String tenant = "DUMMY";
        Long groupId = 3L;
        JsonArray permissions = Json.createArrayBuilder()
                .add(addResource("no valid"))
                .add(addResource("is:not:valid:format"))
                .build();
        JsonObject authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        UserSessionExtended session = new UserSessionExtended(user, email, tenant, groupId, authorization);
        assertThat(session.resourcePermissions.size(), is(IsEqual.equalTo(0)));
        assertThat(session.instancePermissions.size(), is(IsEqual.equalTo(0)));
    }

    @Test
    public void userWithValidResourceAndNoValidScope() {
        String user = "dummy";
        String email = "dummy@dummy.com";
        String tenant = "DUMMY";
        Long groupId = 3L;
        JsonArray permissions = Json.createArrayBuilder()
                .add(addResource("REPORTS:dummy"))
                .build();
        JsonObject authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        UserSessionExtended session = new UserSessionExtended(user, email, tenant, groupId, authorization);
        assertThat(session.resourcePermissions.size(), is(IsEqual.equalTo(0)));
        assertThat(session.instancePermissions.size(), is(IsEqual.equalTo(0)));
    }

    @Test
    public void userWithValidResourcesAndScopes() {
        String user = "dummy";
        String email = "dummy@dummy.com";
        String tenant = "DUMMY";
        Long groupId = 3L;
        String resourceName1 = "REPORTS";
        String resourceName2 = "GROUPS";
        JsonObjectBuilder resource1 = addResource(resourceName1 + ":dummy");
        JsonObjectBuilder resource2 = addResource(resourceName2 + ":dummy");
        JsonArray permissions = Json.createArrayBuilder()
                .add(addScopes(resource1, "r", "x"))
                .add(addScopes(resource2, "r", "p"))
                .build();
        JsonObject authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        UserSessionExtended session = new UserSessionExtended(user, email, tenant, groupId, authorization);
        assertThat(session.resourcePermissions.size(), is(IsEqual.equalTo(2)));
        assertThat(session.instancePermissions.size(), is(IsEqual.equalTo(0)));
        assertThat(session.hasPermissions(resourceName1, "r", "x"), is(IsEqual.equalTo(true)));
        MatcherAssert.assertThat(session.hasPermissions(resourceName2, Operation.OR, "i", "u", "p"), is(IsEqual.equalTo(true)));

        assertThat(session.getResources().size(), is(IsEqual.equalTo(2)));
        assertThat(session.getInstances(resourceName1).size(), is(IsEqual.equalTo(0)));
        assertThat(session.getInstances(resourceName2).size(), is(IsEqual.equalTo(0)));
    }

    @Test
    public void userWithValidResourcesInstancesAndScopes() {
        String user = "dummy";
        String email = "dummy@dummy.com";
        String tenant = "DUMMY";
        Long groupId = 3L;
        String resourceName1 = "REPORTS";
        String resourceName2 = "GROUPS";
        String instanceValue1 = "34";
        String instanceValue2 = "35";
        JsonObjectBuilder resource1 = addResource(resourceName1 + ":dummy:" + instanceValue1);
        JsonObjectBuilder resource2 = addResource(resourceName2 + ":dummy:" + instanceValue2);
        JsonArray permissions = Json.createArrayBuilder()
                .add(addScopes(resource1, "r", "x"))
                .add(addScopes(resource2, "r", "p"))
                .build();
        JsonObject authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        UserSessionExtended session = new UserSessionExtended(user, email, tenant, groupId, authorization);
        assertThat(session.resourcePermissions.size(), is(IsEqual.equalTo(2)));
        assertThat(session.instancePermissions.size(), is(IsEqual.equalTo(2)));
        assertThat(session.hasPermissions(resourceName1, "r", "x"), is(IsEqual.equalTo(true)));
        MatcherAssert.assertThat(session.hasPermissions(resourceName2, Operation.OR, "i", "u", "p"), is(IsEqual.equalTo(true)));

        assertThat(session.getResources().size(), is(IsEqual.equalTo(2)));
        assertThat(session.getInstances(resourceName1).size(), is(IsEqual.equalTo(1)));
        assertThat(session.getInstances(resourceName2).size(), is(IsEqual.equalTo(1)));

        assertThat(session.hasInstancePermissions(resourceName1, instanceValue1, "r", "x"), is(IsEqual.equalTo(true)));
        MatcherAssert.assertThat(session.hasInstancePermissions(resourceName2, instanceValue2, Operation.OR, "i", "u", "p"), is(IsEqual.equalTo(true)));
        MatcherAssert.assertThat(session.hasInstancePermissions(resourceName2, instanceValue2, Operation.OR, "d"), is(IsEqual.equalTo(false)));
    }

    @Test
    public void userWithValidSharedResourcesInstancesAndScopes() {
        String user = "dummy";
        String email = "dummy@dummy.com";
        String tenant = "DUMMY";
        Long groupId = 3L;
        String resourceName1 = "REPORTS";
        String resourceSharedName1 = "REPORTS";
        String resourceName2 = "GROUPS";
        String instanceValue1 = "34";
        String instanceSharedValue1 = "38";
        String instanceValue2 = "35";
        JsonObjectBuilder resource1 = addResource(resourceName1 + ":dummy:" + instanceValue1);
        JsonObjectBuilder resource2 = addResource(resourceName2 + ":dummy:" + instanceValue2);
        JsonObjectBuilder resourceShared1 = addResource(resourceSharedName1 + ":dummy:" + instanceSharedValue1);
        JsonObjectBuilder resourceShared2 = addResource(resourceSharedName1 + ":dummy:" + instanceValue1);
        JsonArray permissions = Json.createArrayBuilder()
                .add(addScopes(resource1, "r", "x"))
                .add(addScopes(resource2, "r", "p"))
                .add(addScopes(resourceShared1, "a"))
                .add(addScopes(resourceShared2, "i"))
                .build();
        JsonObject authorization = Json.createObjectBuilder().add("permissions", permissions).build();
        UserSessionExtended session = new UserSessionExtended(user, email, tenant, groupId, authorization);
        assertThat(session.resourcePermissions.size(), is(IsEqual.equalTo(2)));
        assertThat(session.instancePermissions.size(), is(IsEqual.equalTo(3)));
        assertThat(session.hasPermissions(resourceName1, "r", "x"), is(IsEqual.equalTo(true)));
        MatcherAssert.assertThat(session.hasPermissions(resourceName2, Operation.OR, "i", "u", "p"), is(IsEqual.equalTo(true)));

        assertThat(session.getResources().size(), is(IsEqual.equalTo(2)));
        assertThat(session.getInstances(resourceName1).size(), is(IsEqual.equalTo(2)));
        assertThat(session.getInstances(resourceName2).size(), is(IsEqual.equalTo(1)));

        assertThat(session.hasInstancePermissions(resourceName1, instanceValue1, "r", "x"), is(IsEqual.equalTo(true)));
        MatcherAssert.assertThat(session.hasInstancePermissions(resourceName2, instanceValue2, Operation.OR, "i", "u", "p"), is(IsEqual.equalTo(true)));
        MatcherAssert.assertThat(session.hasInstancePermissions(resourceName2, instanceValue2, Operation.OR, "d"), is(IsEqual.equalTo(false)));

        assertThat(session.hasInstancePermissions(resourceSharedName1, instanceSharedValue1, "a"), is(IsEqual.equalTo(true)));
        assertThat(session.hasInstancePermissions(resourceName1, instanceSharedValue1, "a"), is(IsEqual.equalTo(true)));
        assertThat(session.hasInstancePermissions(resourceName1, instanceValue1, "i"), is(IsEqual.equalTo(true)));
    }

    public static JsonObjectBuilder addResource(String value) {
        return Json.createObjectBuilder().add("rsname", value);
    }

    public static JsonObjectBuilder addScopes(JsonObjectBuilder resource, String... scopes) {
        JsonArrayBuilder scopesArray = Json.createArrayBuilder(Arrays.asList(scopes));
        return resource.add("scopes", scopesArray);
    }
}