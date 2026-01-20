# Blazor Authentication Solution

## How It Works - The Key Insight

### The Problem You Had:
- Login worked but NavMenu didn't update
- Auth state was lost on navigation  
- ProtectedLocalStorage errors during prerender

### The Solution:

```
┌─────────────────────────────────────────────────────────────────────┐
│                           BROWSER                                    │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ NavMenu (WebAssembly) ← Can work offline                       │  │
│  │    └─ Reads auth from PersistentComponentState                 │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ Pages (InteractiveAuto)                                        │  │
│  │    └─ First visit: Server mode (reads cookie)                  │  │
│  │    └─ Later visits: WASM mode (reads persisted state)          │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ Auth Cookie ← Set by Login page                                │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│   BlazorApp1 (Server)   │     │    WebApi (port 5100)   │
│      port 7157/5161     │────▶│  ASP.NET Identity + JWT │
│                         │     │  SQL Server Database    │
│  - Cookie auth          │     └─────────────────────────┘
│  - Calls WebApi         │
│  - Persists auth state  │
└─────────────────────────┘
```

## Auth Flow

1. **User visits Login page** (Static SSR)
2. **User submits credentials** → Blazor Server calls WebApi
3. **WebApi validates** → Returns JWT with claims
4. **Blazor Server sets cookie** with claims from JWT
5. **Page reloads** → Cookie is sent, user is authenticated
6. **PersistingAuthStateProvider** serializes auth state
7. **NavMenu (WASM)** reads persisted state → Shows correct menu
8. **Other pages (InteractiveAuto)** work in both modes:
   - Server mode: Reads cookie
   - WASM mode: Reads persisted state

## Setup Instructions

### Step 1: Database Setup (SSMS)

1. Open SQL Server Management Studio
2. Connect to `(localdb)\mssqllocaldb`
3. The database will be created automatically on first run

### Step 2: Run Migrations

Open Package Manager Console in Visual Studio:
```
cd WebApi
dotnet ef database update
```

Or if using Visual Studio:
1. Set WebApi as startup project
2. Open Package Manager Console
3. Select WebApi as default project
4. Run: `Update-Database`

### Step 3: Download Bootstrap (Optional)

The solution includes a minimal CSS fallback. For full Bootstrap:

Option A - CDN (edit App.razor):
```html
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
```

Option B - Download:
1. Go to https://getbootstrap.com
2. Download compiled CSS
3. Copy `bootstrap.min.css` to `BlazorApp1/wwwroot/bootstrap/`

### Step 4: Run Both Projects

**In Visual Studio:**
1. Right-click solution → Properties
2. Select "Multiple startup projects"
3. Set WebApi and BlazorApp1 to "Start"
4. Press F5

**Or from command line:**
```bash
# Terminal 1
cd WebApi
dotnet run

# Terminal 2
cd BlazorApp1
dotnet run
```

### Step 5: Test

1. Open https://localhost:7157
2. Open browser DevTools (F12) → Console
3. Watch for `>>> ` log messages
4. Click Register → Create account
5. Click Login → Enter credentials
6. NavMenu should update immediately
7. Visit Profile page (protected)
8. Visit Admin page (requires Admin role)

### Step 6: Add Admin Role (SSMS)

```sql
-- Find your user
SELECT Id FROM AspNetUsers WHERE Email = 'your@email.com';

-- Find Admin role
SELECT Id FROM AspNetRoles WHERE Name = 'Admin';

-- Add user to Admin role
INSERT INTO AspNetUserRoles (UserId, RoleId)
VALUES ('user-id-here', 'admin-role-id-here');
```

Then logout and login again to get the new role in your cookie.

## Render Modes Explained

| Component | Render Mode | Why |
|-----------|-------------|-----|
| **NavMenu** | InteractiveWebAssembly | Works offline, no SignalR needed |
| **Login/Register/Logout** | Static SSR | Simple form POST, sets cookie |
| **Counter, Weather** | InteractiveAuto | Fast first load (Server), then WASM |
| **Profile, Admin** | InteractiveAuto + [Authorize] | Protected, works in both modes |

## Console Log Prefixes

All debug logs are prefixed for easy filtering:
- `>>> [SERVER]` - Server-side code
- `>>> [WASM]` - WebAssembly code

## Offline Behavior

| Scenario | Behavior |
|----------|----------|
| On Counter page, lose internet | Page keeps working (if in WASM mode) |
| NavMenu | Still shows correct auth state (reads persisted data) |
| Click Login | Will fail (needs server) |
| Navigate to Profile | Works if WASM cached, fails if needs Server |

## Key Files

| File | Purpose |
|------|---------|
| `BlazorApp1/Services/PersistingAuthStateProvider.cs` | Server: Persists auth to WASM |
| `BlazorApp1.Client/Services/PersistentAuthStateProvider.cs` | WASM: Reads persisted auth |
| `BlazorApp1/Components/Account/Login.razor` | Sets cookie after WebApi validation |
| `BlazorApp1.Client/Layout/NavMenu.razor` | WASM menu with AuthorizeView |

## Troubleshooting

### NavMenu doesn't update after login
- Check Console for errors
- Ensure `forceLoad: true` in Navigation.NavigateTo
- Cookie might not be set (check DevTools → Application → Cookies)

### "Not authorized" on protected pages
- Check if cookie exists
- Check Console for auth state logs
- Ensure roles are in the cookie claims

### WASM doesn't have auth state
- Check Console for `>>> [WASM] PersistentAuthStateProvider`
- Auth state is only persisted on full page load
- After login, page must reload (`forceLoad: true`)

### WebApi connection refused
- Ensure WebApi is running on port 5100
- Check CORS configuration in WebApi Program.cs
