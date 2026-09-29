# TasksApp – Backend (ASP.NET Core WebAPI)

REST-API för TasksApp, byggt med **ASP.NET Core (.NET 10)**, **Entity Framework Core** och **PostgreSQL**. Samma backend används av både webbappen och mobilappen.

- **Webbapp-repo:** https://github.com/fexell/tasks-web-app-frontend
- **Mobilapp-repo:** https://github.com/fexell/tasks-react-native

## 📋 Funktioner

- Inloggning med JWT (access-token 15 min, refresh-token 30 dagar med rotation)
- Två inloggningsflöden: cookies + CSRF för webbappen, Bearer-token för mobilappen
- Registrering, e-postverifiering, lösenordsåterställning och tvåfaktorsautentisering
- CRUD för uppgifter – varje användare ser bara sina egna
- Filuppladdning till uppgifter (max 10 MB, vitlista av filtyper)
- Rate limiting och brute force-skydd på inloggning
- Demokonto med exempeluppgifter skapas automatiskt vid start

## ✅ Förutsättningar

- **[.NET SDK 10](https://dotnet.microsoft.com/download)**
- **[PostgreSQL](https://www.postgresql.org/download/)** (lokalt installerat, eller i Docker)
- **EF Core-verktyget** för att skapa databasen:

  ```bash
  dotnet tool install --global dotnet-ef
  ```

## 🚀 Installation

### 1. Klona repot

```bash
git clone https://github.com/fexell/tasks-backend.git
cd tasks-backend
```

### 2. Skapa `appsettings.json`

`appsettings.json` innehåller hemligheter och finns därför **inte** i repot. Kopiera mallen:

```bash
# Windows (PowerShell)
Copy-Item appsettings.example.json appsettings.json

# macOS / Linux
cp appsettings.example.json appsettings.json
```

Fyll sedan i:

| Inställning | Vad | Krävs |
|---|---|---|
| `ConnectionStrings:Default` | Anslutning till PostgreSQL – byt lösenord (och ev. användare/databasnamn) | ✅ |
| `Jwt:Key` | Hemlig nyckel för att signera tokens, **minst 32 tecken**. Generera en med kommandot nedan | ✅ |
| `Resend:ApiKey` | API-nyckel för e-post via [Resend](https://resend.com). Måste finnas, men värdet `not-configured` räcker för att logga in med demokontot. E-post (t.ex. vid registrering) skickas då inte | ✅ |
| `AppUrls:FrontendBaseUrl` | Webbappens adress – styr CORS och länkar i e-post. Låt stå `http://localhost:3000` | ✅ |
| `IpInfo:Token` | Token från [ipinfo.io](https://ipinfo.io) för att se inloggningens land. Kan lämnas tom | ❌ |

Generera en JWT-nyckel:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
```

### 3. Skapa databasen

Skapa databasen och alla tabeller med migrationerna:

```bash
dotnet ef database update
```

Databasen (t.ex. `tasksapp`) skapas automatiskt om den inte finns, så länge PostgreSQL körs och användaren i `ConnectionStrings:Default` har rätt att skapa databaser.

## ▶️ Starta backend

Backend kan startas på två sätt, beroende på vilken app den ska användas med.

### För webbappen

```bash
dotnet run
```

- Backend körs på **http://localhost:5277** och nås bara från den egna datorn.
- Webbappen körs på `http://localhost:3000` och anropar `http://localhost:5277/api` – se [tasks-web-app-frontend](https://github.com/fexell/tasks-web-app-frontend).

### För mobilappen (och webbappen samtidigt)

```bash
dotnet run --launch-profile mobile
```

- Backend lyssnar på **http://0.0.0.0:5277**, alltså på hela det lokala nätverket, så att en telefon kan nå den via datorns IP-adress.
- Webbappen fungerar som vanligt samtidigt, via `http://localhost:5277`.
- Första gången frågar Windows-brandväggen om åtkomst – tillåt **privata nätverk**.
- Telefonen måste vara på **samma Wi-Fi** som datorn. Mobilappen hittar backend automatiskt – se [tasks-react-native](https://github.com/fexell/tasks-react-native).

**Testa att telefonen når backend:** öppna `http://<datorns-ip>:5277/swagger` i telefonens webbläsare. Datorns IP-adress visas med `ipconfig` (Windows) eller `ifconfig` (macOS/Linux).

> En vanlig `dotnet run` fungerar **inte** för mobilappen, eftersom backend då bara lyssnar på `localhost`.

### Startprofiler

| Kommando | Adress | Används för |
|---|---|---|
| `dotnet run` | `http://localhost:5277` | Webbappen |
| `dotnet run --launch-profile mobile` | `http://0.0.0.0:5277` | Mobilappen + webbappen |
| `dotnet watch run` | `http://localhost:5277` | Webbappen, startar om vid kodändringar |
| `dotnet watch run --launch-profile mobile` | `http://0.0.0.0:5277` | Mobilappen, startar om vid kodändringar |

### Demokonto

Skapas automatiskt första gången backend startar:

- **E-post:** `demo@example.com`
- **Lösenord:** `DemoPassword123!`

### Swagger

Med backend igång finns API-dokumentation och testverktyg på **http://localhost:5277/swagger**.

## 📡 API-översikt

Alla endpoints börjar med `/api`. Uppgifter kräver inloggning.

| Metod | Endpoint | Beskrivning |
|---|---|---|
| `POST` | `/api/auth/login` | Logga in |
| `POST` | `/api/auth/refresh` | Förnya access-token |
| `POST` | `/api/auth/logout` | Logga ut |
| `POST` | `/api/auth/register` | Registrera konto |
| `GET` | `/api/auth/csrf-token` | Hämta CSRF-token (webbappen) |
| `GET` | `/api/user/me` | Inloggad användare |
| `GET` | `/api/tasks` | Lista uppgifter |
| `GET` | `/api/tasks/{id}` | Hämta en uppgift |
| `POST` | `/api/tasks` | Skapa uppgift |
| `PUT` | `/api/tasks/{id}` | Uppdatera uppgift |
| `DELETE` | `/api/tasks/{id}` | Ta bort uppgift |
| `POST` | `/api/tasks/{id}/upload` | Ladda upp fil till uppgift |
| `DELETE` | `/api/tasks/{id}/upload` | Ta bort fil från uppgift |

Se Swagger för alla endpoints (konto, sessioner, tvåfaktor m.m.).

## 🔐 Autentisering: webbapp vs mobilapp

| | Webbapp | Mobilapp |
|---|---|---|
| Tokens skickas som | `HttpOnly`/`Secure`-cookies | `Authorization: Bearer <token>` |
| CSRF-skydd | `X-CSRF-TOKEN`-header krävs på anrop som ändrar data | Behövs inte |
| Förnya token | Cookie till `/api/auth/refresh` | `{ "refreshToken": "..." }` i body |
| Känns igen på | – | Headern `X-Client-Type: mobile` |

`Secure`-cookies skickas aldrig över vanlig http till en IP-adress, vilket är hur telefonen når backend under utveckling. Därför returnerar backend tokens i svaret i stället för som cookies när en klient skickar `X-Client-Type: mobile`. CSRF-kontrollen hoppas över för anrop med en Bearer-token och utan inloggnings-cookie, eftersom en webbläsare aldrig bifogar en `Authorization`-header automatiskt. Tokens returneras bara i body om de också skickades i body, så ett skript i webbläsaren kan inte byta ut en `HttpOnly`-cookie mot en läsbar token.

## 📁 Projektstruktur

```
├── Configuration/        # Identity- och CSRF-inställningar
├── Controllers/
│   ├── Auth/             # Inloggning, konto, tvåfaktor
│   ├── Tasks/            # Uppgifter och filuppladdning
│   └── Users/            # Användarprofil
├── Data/                 # AppDbContext (EF Core)
├── DTOs/                 # Objekt som skickas till/från API:t
├── Extensions/           # Registrering av tjänster (JWT, databas, CSRF)
├── Filters/              # Validering och CSRF-kontroll
├── Middlewares/          # Brute force-skydd, sessionskontroll
├── Migrations/           # Databasmigrationer
├── Models/               # Databasmodeller (AppUser, Task, ...)
├── Services/             # Affärslogik (auth, e-post, seeding)
├── Utils/                # Hjälpfunktioner (cookies, tokens)
├── wwwroot/uploads/      # Uppladdade filer
├── Program.cs            # Startkonfiguration
└── appsettings.example.json
```

## 🧯 Felsökning

| Problem | Lösning |
|---|---|
| `Missing required configuration value 'Jwt:Key'` | `appsettings.json` saknas eller saknar `Jwt:Key` – se steg 2 |
| `No CORS origins configured` | `AppUrls:FrontendBaseUrl` saknas i `appsettings.json` |
| `IDX10720` / nyckeln är för kort | `Jwt:Key` måste vara minst 32 tecken |
| Inloggning ger fel 500, loggen säger `Missing Resend API key` | Lägg till `"Resend": { "ApiKey": "not-configured" }` |
| `relation "AspNetUsers" does not exist` | Databasen saknar tabeller – kör `dotnet ef database update` |
| `Failed to connect to 127.0.0.1:5432` | PostgreSQL körs inte, eller fel lösenord i `ConnectionStrings:Default` |
| Webbappen får CORS-fel | Webbappen måste köras på `http://localhost:3000` (samma som `AppUrls:FrontendBaseUrl`) |
| Mobilappen når inte backend | Starta med `--launch-profile mobile`, samma Wi-Fi, tillåt port 5277 i brandväggen. Skolans Wi-Fi kan blockera trafik mellan enheter |
| Port 5277 är upptagen | Stäng den andra processen (t.ex. en tidigare `dotnet run`) |
