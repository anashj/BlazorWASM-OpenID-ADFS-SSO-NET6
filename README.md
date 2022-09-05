# BlazorWasmOpenIdADFS

Create new project using template: Blazor WebAssembly.
	
## A- Server side
1- In Server project, add following nuget packages:
 -  IdentityModel
 - IdentityModel.AspNetCore
2- Open Program.cs, and add the following code parts:
	
```
	JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
	builder.Services.AddAuthentication(options =>
	{
	    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
	})
	.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
	{
	    options.Cookie.SameSite = SameSiteMode.None;
	    options.Events.OnSigningOut = async e =>
	    {
	        await e.HttpContext.RevokeUserRefreshTokenAsync();
	    };
	})
	.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
	{
	    builder.Configuration.GetSection("ADFS").Bind(options);
	    options.SaveTokens = true;
	    options.UsePkce = true;
	    options.GetClaimsFromUserInfoEndpoint = true;
	    options.TokenValidationParameters = new TokenValidationParameters
	    {
	        NameClaimType = JwtClaimTypes.Name,
	        RoleClaimType = JwtClaimTypes.Role,
	    };
	    options.Scope.Add("openid");
	    options.Scope.Add("profile");
	    options.Scope.Add("email");
	    options.Events = new OpenIdConnectEvents
	    {
	        OnAccessDenied = context =>
	        {
	            context.HandleResponse();
	            context.Response.Redirect("/");
	            return Task.CompletedTask;
	        }
	    };
	});
	
	builder.Services.AddMvc();
	…
	
	builder.Services.AddAccessTokenManagement();
```
3- In appsettings.json, add the openid configuration metadata and ClientId for your ADFS identity provider (on prem in this case):
```
	"ADFS": {
	    "ClientId": "{client id}",
	    "MetadataAddress": "https://fs.cfl.lu/adfs/.well-known/openid-configuration",
	    "PostLogoutRedirectUri": "{logout_redirect_uri}"
	  }
```
4- We will need now to implement Login and Logout, to do this: create a new controller AccountController, and add the following code:
	
```
	[Route("[controller]")]
	public class AccountController : ControllerBase
	{
	   [HttpGet("Login")]
	   public ActionResult Login(string returnUrl = "/")
	   {
	      if (!Url.IsLocalUrl(returnUrl))
	      {
	         ModelState.AddModelError(nameof(returnUrl), "Value must be a local URL");
	         return BadRequest(ModelState);
	      }
	      return Challenge(new AuthenticationProperties { RedirectUri = returnUrl });
	   }
	
	   [HttpGet("Logout")]
	   public IActionResult Logout() => SignOut(
	      new AuthenticationProperties { RedirectUri = "/" },
	      CookieAuthenticationDefaults.AuthenticationScheme,
	      OpenIdConnectDefaults.AuthenticationScheme);
	 }
```
5- The second thing that we'll need, is getting user claims when he's authenticated. In order to do this, we'll need first to:
   
   5-1-  Add 2 models in Shared project:
   
   • ClaimValue
```
	public class ClaimValue
	{
	   public ClaimValue()
	   {
	   }
	   public ClaimValue(string type, string value)
	   {
	      Type = type;
	      Value = value;
	   }
	   public string Type { get; set; }
	   public string Value { get; set; }
	}
```
   • UserInfo
```
	public class UserInfo
	{
	    public static readonly UserInfo Anonymous = new UserInfo();
	    public bool IsAuthenticated { get; set; }
	    public string NameClaimType { get; set; }
	    public string RoleClaimType { get; set; }
	    public ICollection<ClaimValue> Claims { get; set; }
	}
```
   5-2-  Create UserController that will be responsible for getting current user info:
```
	[Route("[controller]")]
	[ApiController]
	public class UserController : ControllerBase
	{
	   [HttpGet("currentuserinfo")]
	   [Authorize]
	   [AllowAnonymous]
	   public IActionResult GetCurrentUser() =>
	      Ok(User.Identity != null && User.Identity.IsAuthenticated ? CreateUserInfo(User) : UserInfo.Anonymous);
	   private UserInfo CreateUserInfo(ClaimsPrincipal claimsPrincipal)
	   {
	      if (claimsPrincipal.Identity != null && !claimsPrincipal.Identity.IsAuthenticated)
	      {
	          return UserInfo.Anonymous;
	      }
	      var userInfo = new UserInfo
	      {
	          IsAuthenticated = true
	      };
	      if (claimsPrincipal.Identity is ClaimsIdentity claimsIdentity)
	      {
	          userInfo.NameClaimType = "{claim name}";
	          userInfo.RoleClaimType = claimsIdentity.RoleClaimType;
	      }
	      else
	      {
	          userInfo.NameClaimType = JwtClaimTypes.Name;
	          userInfo.RoleClaimType = JwtClaimTypes.Role;
	      }
	      if (claimsPrincipal.Claims.Any())
	      {
	         var claims = new List<ClaimValue>();
	         var nameClaims = claimsPrincipal.FindAll(userInfo.NameClaimType);
	         foreach (var claim in nameClaims)
	         {
	             claims.Add(new ClaimValue(userInfo.NameClaimType, claim.Value));
	         }
	         // Uncomment this code if you want to send additional claims to the client.
	         //foreach (var claim in claimsPrincipal.Claims.Except(nameClaims))
	         //{
	           //    claims.Add(new ClaimValue(claim.Type, claim.Value));
	         //}
	         userInfo.Claims = claims;
	      }
	      return userInfo;
	    }
	 }
```
## B- Client side
1- In order to connect via OpenId Connect for Blazor WASM , we need to create a custom authentication state provider (it's mandatory). To do this, create a Services folder , and add a new class that inherits from AuthenticationStateProvider, the goal here is to override GetAuthenticationStateAsync.
```
	public class HostAuthenticationStateProvider : AuthenticationStateProvider
	{
	   private static readonly TimeSpan _userCacheRefreshInterval = TimeSpan.FromSeconds(60);
	   private readonly NavigationManager _navigation;
	   private readonly HttpClient _client;
	   private readonly ILogger<HostAuthenticationStateProvider> _logger;
	   private DateTimeOffset _userLastCheck = DateTimeOffset.FromUnixTimeSeconds(0);
	   private ClaimsPrincipal _cachedUser = new ClaimsPrincipal(new ClaimsIdentity());
	   private const string LogInPath = "Account/Login";
	   private const string LogOutPath = "Account/Logout";
	   public HostAuthenticationStateProvider(NavigationManager navigation, HttpClient client, ILogger<HostAuthenticationStateProvider> logger)
	   {
	       _navigation = navigation;
	       _client = client;
	       _logger = logger;
	   }
	   public override async Task<AuthenticationState> GetAuthenticationStateAsync() => new AuthenticationState(await GetUser(useCache: true));
	   public void SignIn(string? customReturnUrl = null)
	   {
	       var returnUrl = customReturnUrl != null ? _navigation.ToAbsoluteUri(customReturnUrl).ToString() : null;
	       var encodedReturnUrl = Uri.EscapeDataString(returnUrl ?? _navigation.Uri);
	       var logInUrl = _navigation.ToAbsoluteUri($"{LogInPath}?returnUrl={encodedReturnUrl}");
	            _navigation.NavigateTo(logInUrl.ToString(), true);
	   }
	   public void SignOut()
	   {
	      _navigation.NavigateTo(_navigation.ToAbsoluteUri(LogOutPath).ToString(), true);
	   }
	   private async ValueTask<ClaimsPrincipal> GetUser(bool useCache = false)
	   {
	      var now = DateTimeOffset.Now;
	      if (useCache && now < _userLastCheck + _userCacheRefreshInterval)
	      {
	          return _cachedUser;
	      }
	      _logger.LogDebug("Fetching user");
	      _cachedUser = await FetchUser();
	      _userLastCheck = now;
	      return _cachedUser;
	   }
	   private async Task<ClaimsPrincipal> FetchUser()
	   {
	      UserInfo? user = null;
	      try
	      {
	         user = await _client.GetFromJsonAsync<UserInfo>("user/currentuserinfo");
	      }
	      catch (Exception exc)
	      {
	          _logger.LogWarning(exc, "Fetching user failed.");
	      }
	      if (user == null || !user.IsAuthenticated)
	      {
	          return new ClaimsPrincipal(new ClaimsIdentity());
	      }
	      var identity = new ClaimsIdentity(
	           nameof(HostAuthenticationStateProvider),
	           user.NameClaimType,
	           user.RoleClaimType);
	      if (user.Claims != null)
	      {
	          foreach (var claim in user.Claims)
	          {
	              identity.AddClaim(new Claim(claim.Type, claim.Value));
	          }
	      }
	      return new ClaimsPrincipal(identity);
	    }
	 }
```
	
2- Add a new service called AuthorizedHandler (not mandatory), the benefit of this service is to delegating requests on whether user is authenticated or not:
```
	public class AuthorizedHandler : DelegatingHandler
	{
	    private readonly HostAuthenticationStateProvider _authenticationStateProvider;
	    public AuthorizedHandler(HostAuthenticationStateProvider authenticationStateProvider)
	    {
	        _authenticationStateProvider = authenticationStateProvider;
	    }
	    protected override async Task<HttpResponseMessage> SendAsync(
	        HttpRequestMessage request,
	        CancellationToken cancellationToken)
	    {
	        var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
	        HttpResponseMessage responseMessage;
	        if (authState.User.Identity?.IsAuthenticated == false)
	        {
	            // if user is not authenticated, immediately set response status to 401 Unauthorized
	            responseMessage = new HttpResponseMessage(HttpStatusCode.Unauthorized);
	        }
	        else
	        {
	            responseMessage = await base.SendAsync(request, cancellationToken);
	        }
	        if (responseMessage.StatusCode == HttpStatusCode.Unauthorized)
	        {
	            // if server returned 401 Unauthorized, redirect to login page
	            _authenticationStateProvider.SignIn();
	        }
	            return responseMessage;
	    }
	}
```
	
3- Open Program.cs, and register all required services as shown below:
```
	builder.Services.AddOptions();
	builder.Services.AddAuthorizationCore();
	builder.Services.AddScoped<HostAuthenticationStateProvider>();
	builder.Services.AddScoped<AuthenticationStateProvider>(sp =>  sp.GetRequiredService<HostAuthenticationStateProvider>());
	builder.Services.AddTransient<AuthorizedHandler>();
```
	
4- In the LoginDisplay.razor, change the binding to use the Login, Logout of Accountcontroller, and comment the SignOutManager since it's already implemented in Logout:
```
	<AuthorizeView>
	    <Authorized>
	        Hello, @context.User.Identity?.Name!
	        <a class="nav-link btn btn-link" href="Account/Logout">Log out</a>
	    </Authorized>
	    <NotAuthorized>
	        <a href="Account/Login">Log in</a>
	    </NotAuthorized>
	</AuthorizeView>
```
	
5- Open RedirectToLogin.razor and change the Navigate to by this line:
```
	Navigation.NavigateTo($"Account/Login?", true);
```
	
The parameter true, is to force loading.
		
6- Finally since we want to implement authentication using OpenId connect, we need to reference the right AuthenticationService js file. To do this, open index.html, and add this line:
```
	<script src="_content/Microsoft.AspNetCore.Components.WebAssembly.Authentication/AuthenticationService.js"></script>
```
	
To avoid all sort of problems, you can comment the line just above that references Msal AuthenticationService.
