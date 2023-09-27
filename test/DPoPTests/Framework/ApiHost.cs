// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using ApiHost;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace DPoPTests;

public class ApiHost : GenericHost
{
    private readonly IdentityServerHost _identityServerHost;

    public bool ValidateNonce { get; set; }

    public event Action<Microsoft.AspNetCore.Http.HttpContext> ApiInvoked = ctx => { };
        
    public ApiHost(IdentityServerHost identityServerHost, string baseAddress = "https://api") 
        : base(baseAddress)
    {
        _identityServerHost = identityServerHost;

        OnConfigureServices += ConfigureServices;
        OnConfigure += Configure;
    }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
        services.AddAuthorization();

        services.AddAuthentication("token")
            .AddJwtBearer("token", options =>
            {
                options.Authority = _identityServerHost.Url();
                options.Audience = _identityServerHost.Url("/resources");
                options.MapInboundClaims = false;
                options.BackchannelHttpHandler = _identityServerHost.Server.CreateHandler();
            });
        services.ConfigureDPoPTokensForScheme("token", options =>
        {
            options.ClientClockSkew = TimeSpan.FromMinutes(1);
            options.ValidateNonce = ValidateNonce;
        });
    }

    private void Configure(IApplicationBuilder app)
    {
        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(ep => {
            ep.MapGet("/api", ctx =>
            {
                ApiInvoked.Invoke(ctx);
                ctx.Response.StatusCode = 200;
                return Task.CompletedTask;
            })
            .RequireAuthorization();
        });
    }
}