using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;
using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using IdentityModel;
using ImageGallery.Client.HttpHandlers;

namespace ImageGallery.Client
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            // Don't use the Default Mapper of Inbound Claim Types to the Claim Types available for the application.
            // Clear it OUT! Let's keep the raw claims as delivered.
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                 .AddJsonOptions(opts => opts.JsonSerializerOptions.PropertyNamingPolicy = null);

            services.AddAuthorization(authorizationOptions =>
                {
                    // Define a new Policy using MS' Auth libraries.
                   authorizationOptions.AddPolicy(
                       "CanOrderFrame",
                       policyBuilder =>
                       {
                           policyBuilder.RequireAuthenticatedUser();
                           policyBuilder.RequireClaim("country", "be");
                           policyBuilder.RequireClaim("subscriptionlevel", "PayingUser");
                           // Could add "role" as an additional required claim if desired.
                       });
                });

            services.AddHttpContextAccessor();
            // D.Inject our custom BearerTokenHandler so it's available for use in this class.
            services.AddTransient<BearerTokenHandler>();

            // create an HttpClient used for accessing the API
            services.AddHttpClient("APIClient", client =>
            {
                client.BaseAddress = new Uri("http://localhost:44366/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            }).AddHttpMessageHandler<BearerTokenHandler>(); // Add in our AccessToken so we are authorized to use API.
            // Create an HttpClient used for accessing the IDP
            // Is this defining a HTTP Client "Factory" used for creating an instance in other locations in our app
            // like GalleryController.OrderFrame() ?
            services.AddHttpClient("IDPClient", client =>
            {
                client.BaseAddress = new Uri("http://localhost:44318/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            });

            // IMPORTANT WORK HERE TO CONFIGURE OUR AUTHENTICATION
            // Notice the chaining of handlers.
            // Setup to use Open ID Connect
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
               
                // options.RequireAuthenticatedSignIn = false;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {   // Set in our cookie which controller path to use to render the proper page when access is denied.
                options.AccessDeniedPath = "/Authorization/AccessDenied";
            })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                // Many of these values must match what we set up in IDP for this client.
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                // Who is validating our tokens? Our IDP.
                options.Authority = "http://localhost:44318/";
                options.ClientId = "imagegalleryclient";
                // code flow + PKCE is turned on by default.
                options.ResponseType = "code";               
                options.Scope.Add("address");
                options.Scope.Add("roles");
                options.Scope.Add("imagegalleryapi"); // Make API access requests available
                options.Scope.Add("subscriptionlevel");
                options.Scope.Add("country");
                options.Scope.Add("offline_access");
                // You can add back a claim that is being removed by the "default filter" via .Remove("xyz").
                // options.ClaimActions.Remove("nbf");
                // Get rid of claims that we don't need from the Claims Identity.
                options.ClaimActions.DeleteClaim("sid");
                options.ClaimActions.DeleteClaim("idp");
                options.ClaimActions.DeleteClaim("s_hash");
                options.ClaimActions.DeleteClaim("auth_time");
                // Have to use the below mappings in order to add our custom claims - returned by IDP - to the
                // claims made available to the app.
                options.ClaimActions.MapUniqueJsonKey("role", "role");
                options.ClaimActions.MapUniqueJsonKey("subscriptionlevel", "subscriptionlevel");
                options.ClaimActions.MapUniqueJsonKey("country", "country");
                options.SaveTokens = true; // Asp.Net Core will save tokens for us in the Cookie.
                options.ClientSecret = "secret";
                // Get the user's claims from the UserInfoEndpoint ... rather than getting them 
                // from theIdentity Token directly, so that we don't run into any URI-length
                // restrictions in browsers like IE. Keeps the id_token small.
                options.GetClaimsFromUserInfoEndpoint = true;
                // Make these claim types available to MVC? Maybe ...
                // Says that these particular claim names returned by IDP will get mapped to the built-in
                // types provided by Microsoft's .AspNetCore.Authentication libraries. Maybe?
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtClaimTypes.GivenName,
                    RoleClaimType = JwtClaimTypes.Role
                };
                options.RequireHttpsMetadata = false; // Do not require HTTPS.
            });


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseStaticFiles();
 
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Shared/Error");
                // The default HSTS value is 30 days. You may want to change this for
                // production scenarios, see https://aka.ms/aspnetcore-hsts.
                // Disable in attempt to run using HTTP.
                // app.UseHsts();
            }
            // Disable in attempt to run using HTTP.
            // app.UseHttpsRedirection();
            app.UseStaticFiles();

            // IDP needs to know how to route to the client app endpoints.
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            // Below must come after authentication and authorization so that user's don't get access
            // to our controllers unless they pass the authentication & authorization steps.
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Gallery}/{action=Index}/{id?}");
            });
            // As of ASP.Net 3, you can add policy authorization requirements to endpoints above
            // using methods like the above instead of annotations, if your app isn't MVC controller-based.
            // Can be useful if you want to add global authorization configs, in case your developers
            // forget to add authorization annotations for each method.
        }
    }
}
