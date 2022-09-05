using BlazorWasmOpenIdADFS.Client;
using BlazorWasmOpenIdADFS.Client.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.Services.AddOptions();
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<HostAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<HostAuthenticationStateProvider>());

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddHttpClient("BlazorWasmOpenIdADFS.ServerAPI", client => client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress))
    .AddHttpMessageHandler<BaseAddressAuthorizationMessageHandler>();

// Supply HttpClient instances that include access tokens when making requests to the server project
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("BlazorWasmOpenIdADFS.ServerAPI"));

builder.Services.AddTransient(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

//builder.Services.AddMsalAuthentication(options =>
//{
//    builder.Configuration.Bind("AzureAd", options.ProviderOptions.Authentication);
//    options.ProviderOptions.DefaultAccessTokenScopes.Add("api://api.id.uri/access_as_user");
//});

await builder.Build().RunAsync();
