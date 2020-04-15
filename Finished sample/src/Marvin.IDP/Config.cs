// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace Marvin.IDP
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> Ids =>
            new IdentityResource[]
            {
                // These will show up in the "scopes_supported" section of the discovery document.
                // support OpenID Connect
                new IdentityResources.OpenId(),
                // Profile maps to things like given name and family name claims
                new IdentityResources.Profile(),
                new IdentityResources.Address(),
                new IdentityResource(
                    "roles",
                    "Your role(s)",
                    new List<string>() { "role" }),
                new IdentityResource(
                    "country",
                    "The country you're living in",
                    new List<string>() { "country" }),
                new IdentityResource(
                    "subscriptionlevel",
                    "Your subscription level",
                    new List<string>() { "subscriptionlevel" })
            };

        // A.K.A. Resource Scopes
        public static IEnumerable<ApiResource> Apis =>
            new ApiResource[]
            {
                new ApiResource(
                    "imagegalleryapi",
                    "Image Gallery API",
                    new List<string>() { "role" }) // Include roles in the Access Token
                {
                    ApiSecrets = { new Secret("apisecret".Sha256()) } // Secret shared between client and IDP for validating Access tokens via a Reference / Token Introspection Endpoint.
                }
            };

        public static IEnumerable<Client> Clients =>
            new Client[]
            {

                // This is the client application we are connecting to the Identity Server
                new Client
                {
                    AccessTokenType = AccessTokenType.Reference,
                    AccessTokenLifetime = 120, // In seconds.
                    AllowOfflineAccess = true, // Allow access to client app even when the user is not currently logged into the IDP.
                    UpdateAccessTokenClaimsOnRefresh = true, // Upon refresh, and updates to a user's claims in the IDP are propagated to the client.
                    // The ClientName text appears in the UI for user to choose to consent
                    // to letting the application to access your identity tokens

                    ClientName = "Image Gallery",
                    ClientId = "imagegalleryclient",
                    // Our type is code-flow
                    AllowedGrantTypes = GrantTypes.Code,
                    RequirePkce = true,
                    RedirectUris = new List<string>()
                    {
                        "http://localhost:44389/signin-oidc"
                    },
                    // URL that IDP should use to redirect logged users,
                    PostLogoutRedirectUris = new List<string>()
                    {
                        "http://localhost:44389/signout-callback-oidc"
                    },
                    // The scopes the client is allowed to access as given out by the Identity Server
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Address,
                        "roles", // This and the below are our custom-defined scopes.
                        "imagegalleryapi",
                        "country",
                        "subscriptionlevel"
                    },
                    // Shared secret between client app and Identity server
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    }
                } };
    }
}