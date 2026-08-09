// JAX-RS / Jakarta REST test fixture for framework extractor tests.

package com.example.api;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.annotation.security.RolesAllowed;
import javax.annotation.security.PermitAll;
import javax.annotation.security.DenyAll;

@Path("/api")
@Produces(MediaType.APPLICATION_JSON)
public class UserResource {

    @GET
    @Path("/users")
    public Response listUsers(@QueryParam("page") int page,
                              @QueryParam("size") @DefaultValue("20") int size) {
        return Response.ok().build();
    }

    @GET
    @Path("/users/{id}")
    @RolesAllowed("USER")
    public Response getUser(@PathParam("id") long id) {
        return Response.ok().build();
    }

    @POST
    @Path("/users")
    @PermitAll
    public Response createUser(@FormParam("name") String name,
                               @FormParam("email") String email) {
        return Response.status(201).build();
    }

    @PUT
    @Path("/users/{id}")
    @RolesAllowed({"USER", "ADMIN"})
    public Response updateUser(@PathParam("id") long id,
                               @HeaderParam("Authorization") String token) {
        return Response.ok().build();
    }

    @DELETE
    @Path("/users/{id}")
    @DenyAll
    public Response deleteUser(@PathParam("id") long id) {
        return Response.noContent().build();
    }

    @GET
    @Path("/admin/stats")
    public Response adminStats(@CookieParam("session") String session) {
        return Response.ok().build();
    }

    @GET
    @Path("/search")
    public Response search(@MatrixParam("filter") String filter) {
        return Response.ok().build();
    }

    @POST
    @Path("/upload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response upload(@BeanParam UploadForm form) {
        return Response.ok().build();
    }

    // Helper form class
    public static class UploadForm {
        @FormParam("file")
        private String file;
    }
}
