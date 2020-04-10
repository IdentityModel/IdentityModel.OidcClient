// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityModel.Jwk;
using IdentityModel.OidcClient.Tests.Infrastructure;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class ConfigurationTests
    {
        [Fact]
        public void Null_options_should_throw_exception()
        {
            OidcClientOptions options = null;

            Action act = () => new OidcClient(options);

            act.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void No_authority_and_no_static_config_should_throw_exception()
        {
            var options = new OidcClientOptions();

            Action act = () => new OidcClient(options);

            act.Should().Throw<ArgumentException>().Where(e => e.Message.StartsWith("No authority specified"));
        }

        [Fact]
        public void Providing_required_provider_information_should_not_throw()
        {
            var options = new OidcClientOptions
            {
                ProviderInformation = new ProviderInformation
                {
                    IssuerName = "issuer",
                    AuthorizeEndpoint = "authorize",
                    TokenEndpoint = "token",
                    KeySet = new JsonWebKeySet()
                }
            };

            var client = new OidcClient(options);

            Func<Task> act = async () => { await client.EnsureProviderInformationAsync(CancellationToken.None); };

            act.Should().NotThrow();
        }

        [Fact]
        public void Missing_issuer_should_throw()
        {
            var options = new OidcClientOptions
            {
                ProviderInformation = new ProviderInformation
                {
                    IssuerName = null,
                    AuthorizeEndpoint = "authorize",
                    TokenEndpoint = "token",
                    KeySet = new JsonWebKeySet()
                }
            };

            var client = new OidcClient(options);

            Func<Task> act = async () => { await client.EnsureProviderInformationAsync(CancellationToken.None); };

            act.Should().Throw<InvalidOperationException>().Where(e => e.Message.Equals("Issuer name is missing in provider information"));
        }

        [Fact]
        public void Missing_authorize_endpoint_should_throw()
        {
            var options = new OidcClientOptions
            {
                ProviderInformation = new ProviderInformation
                {
                    IssuerName = "issuer",
                    AuthorizeEndpoint = null,
                    TokenEndpoint = "token",
                    KeySet = new JsonWebKeySet()
                }
            };

            var client = new OidcClient(options);

            Func<Task> act = async () => { await client.EnsureProviderInformationAsync(CancellationToken.None); };

            act.Should().Throw<InvalidOperationException>().Where(e => e.Message.Equals("Authorize endpoint is missing in provider information"));
        }

        [Fact]
        public void Missing_token_endpoint_should_throw()
        {
            var options = new OidcClientOptions
            {
                ProviderInformation = new ProviderInformation
                {
                    IssuerName = "issuer",
                    AuthorizeEndpoint = "authorize",
                    TokenEndpoint = null,
                    KeySet = new JsonWebKeySet()
                }
            };

            var client = new OidcClient(options);

            Func<Task> act = async () => { await client.EnsureProviderInformationAsync(CancellationToken.None); };

            act.Should().Throw<InvalidOperationException>().Where(e => e.Message.Equals("Token endpoint is missing in provider information"));
        }

        [Fact]
        public void Missing_keyset_should_throw()
        {
            var options = new OidcClientOptions
            {
                ProviderInformation = new ProviderInformation
                {
                    IssuerName = "issuer",
                    AuthorizeEndpoint = "authorize",
                    TokenEndpoint = "token",
                    KeySet = null
                }
            };

            var client = new OidcClient(options);

            Func<Task> act = async () => { await client.EnsureProviderInformationAsync(CancellationToken.None); };

            act.Should().Throw<InvalidOperationException>().Where(e => e.Message.Equals("Key set is missing in provider information"));
        }

        [Fact]
        public void Exception_while_loading_discovery_document_should_throw()
        {
            var options = new OidcClientOptions
            {
                Authority = "https://authority",

                BackchannelHandler = new NetworkHandler(new Exception("error"))
            };

            var client = new OidcClient(options);

            Func<Task> act = async () => { await client.EnsureProviderInformationAsync(CancellationToken.None); };

            act.Should().Throw<InvalidOperationException>().Where(e => e.Message.Equals("Error loading discovery document: Error connecting to https://authority/.well-known/openid-configuration. error."));
        }

        [Fact]
        public void Error401_while_loading_discovery_document_should_throw()
        {
            var options = new OidcClientOptions
            {
                Authority = "https://authority",

                BackchannelHandler = new NetworkHandler(HttpStatusCode.NotFound, "not found")
            };

            var client = new OidcClient(options);

            Func<Task> act = async () => { await client.EnsureProviderInformationAsync(CancellationToken.None); };

            act.Should().Throw<InvalidOperationException>().Where(e => e.Message.Equals("Error loading discovery document: Error connecting to https://authority/.well-known/openid-configuration: not found"));
        }
    }
}