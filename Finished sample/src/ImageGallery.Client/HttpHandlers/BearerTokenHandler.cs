using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ImageGallery.Client.HttpHandlers
{
    /**
     * An alternative to managing our Ac

     *   https://identitymodel.readthedocs.io/en/latest/aspnetcore/web.html
     *   services.AddAccessTokenManagement();
     *
     * or various versions of the above, in the Startup.cs
     */
    public class BearerTokenHandler : DelegatingHandler
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IHttpClientFactory _httpClientFactory;

        public BearerTokenHandler(IHttpContextAccessor httpContextAccessor,
                   IHttpClientFactory httpClientFactory)
        {
            _httpContextAccessor = httpContextAccessor ??
                throw new ArgumentNullException(nameof(httpContextAccessor));
            // Inject the Client Factory that we will use for refreshing our Access Tokens.
            _httpClientFactory = httpClientFactory ??
                 throw new ArgumentNullException(nameof(httpClientFactory));
        }
        

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, 
            CancellationToken cancellationToken)
        {
            var accessToken = await GetAccessTokenAsync();

            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                // Use the IdentityServer4 Client Library method
                request.SetBearerToken(accessToken);
            }

            return await base.SendAsync(request, cancellationToken);
        }

        /**
         * Make sure we have a non-expired Access Token.
         */
        public async Task<string> GetAccessTokenAsync()
        {
            // get the expires_at value & parse it
            var expiresAt = await _httpContextAccessor
                .HttpContext.GetTokenAsync("expires_at");

            var expiresAtAsDateTimeOffset = 
                DateTimeOffset.Parse(expiresAt, CultureInfo.InvariantCulture);

            if ((expiresAtAsDateTimeOffset.AddSeconds(-60)).ToUniversalTime() > DateTime.UtcNow)
            {
                // no need to refresh, return the access token
                return await _httpContextAccessor
                       .HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            }

            // ELSE, let's go Refresh our Access Token as we are near or past the expiration time.
            // First create an HTTP Client.
            var idpClient = _httpClientFactory.CreateClient("IDPClient");

            // get the discovery document
            var discoveryReponse = await idpClient.GetDiscoveryDocumentAsync();

            // refresh the tokens
            // Get the refresh token the IDP gave us earlier.
            var refreshToken = await _httpContextAccessor
                       .HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);
            // TODO
            // Newer version of MS library returns blank refresh token.
            // What's the workaround for this?

            var refreshResponse = await idpClient.RequestRefreshTokenAsync(
                new RefreshTokenRequest
                {
                    Address = discoveryReponse.TokenEndpoint,
                    ClientId = "imagegalleryclient",
                    ClientSecret = "secret",
                    RefreshToken = refreshToken
                });

            // store the tokens from the Refresh response.            
            var updatedTokens = new List<AuthenticationToken>();
            updatedTokens.Add(new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.IdToken,
                Value = refreshResponse.IdentityToken
            });
            updatedTokens.Add(new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.AccessToken,
                Value = refreshResponse.AccessToken
            });
            updatedTokens.Add(new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.RefreshToken,
                Value = refreshResponse.RefreshToken
            });
            updatedTokens.Add(new AuthenticationToken
            {
                Name = "expires_at",
                Value = (DateTime.UtcNow + TimeSpan.FromSeconds(refreshResponse.ExpiresIn)).
                        ToString("o", CultureInfo.InvariantCulture) // Format of how time is stored.
            });

            // get authenticate result, containing the current principal & 
            // properties
            var currentAuthenticateResult = await _httpContextAccessor
                .HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // store the updated tokens in the cookie.
            currentAuthenticateResult.Properties.StoreTokens(updatedTokens);

            // sign in .. really puts the values into the cookie ... so we can retrieve them from 
            // other places in our code to use them.
            // This is Microsoft's recommendation for "Session Management".
            await _httpContextAccessor.HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                currentAuthenticateResult.Principal,
                currentAuthenticateResult.Properties);
            // Finally, return the valid access token.
            return refreshResponse.AccessToken;
        }
    }
}
