# PRISEC IV — Prototype


```
prototype/
├── backend/     FastAPI + SQLAlchemy + MySQL
└── frontend/    Next.js 16 / React 19
```

## Requirements

| Tool | Version |
|---|---|
| Python | 3.11+ |
| Node.js | 20.x LTS or newer |
| MySQL Server | 8.0+ |
| Git | any recent version |

## 1. Install prerequisites

### Linux / WSL

```bash
sudo apt update
sudo apt install -y nodejs npm
sudo apt update && sudo apt install -y mysql-server
```

### Windows

Install each of the following. The official installers (linked below)
handle PATH setup automatically; Chocolatey is a faster
command-line alternative if you prefer scripting the whole setup.

| Tool | Official installer | Chocolatey (elevated PowerShell) |
|---|---|---|
| Node.js | https://nodejs.org (LTS button) | `choco install nodejs-lts -y` |
| MySQL | https://dev.mysql.com/downloads/installer/ | `choco install mysql -y` |

> **Chocolatey needs an elevated (Administrator) shell** for every command
> above — see the note under "Set up MySQL" below for exactly how to open
> one. This applies regardless of which tool you're installing.

After installing, **verify each one from a brand-new terminal window**:
```powershell
node --version
npm --version
mysql --version
```
If any command isn't recognized, it's almost always the close/reopen IDE.

## 2. Set up MySQL

The backend expects a MySQL database. `backend/init.sql` creates the
database and app user in one step.

### Linux / WSL

```bash
sudo apt update && sudo apt install -y mysql-server(IF NOT DONE YET)
sudo systemctl start mysql
sudo mysql -u root < backend/init.sql
```

### Windows

```powershell
# Chocolatey (run PowerShell as Administrator)
choco install mysql -y (IF NOT DONE YET)
```
Then run the init script:
```powershell
cd prototype\backend
Get-Content .\init.sql | mysql -u root -p
```


`init.sql` creates the database `prisec_iv` and a user
`prisec_user` with a placeholder password (`123`). Edit that password
in `init.sql` before running it, or change it after:
```sql
ALTER USER 'prisec_user'@'%' IDENTIFIED BY 'your_real_password';
FLUSH PRIVILEGES;
```

This is a **one-time** step per machine — the database persists across
reboots and app restarts. You only repeat it if MySQL is reinstalled or the
database is intentionally dropped.

## 3. Set up the backend

```bash
# from the repo root
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Copy the env template in .env.example and fill in your real DB password:
```bash
cd prototype/backend
cp .env.example .env            # Windows: copy .env.example .env
```
```dotenv
DB_USER=prisec_user
DB_PASSWORD=your_real_password
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=prisec_iv
```

Start the backend:
```bash
uvicorn main:app --reload
```

On first run, SQLAlchemy creates the `profiles` and `decisions` tables
automatically — no manual table creation needed. Check
http://127.0.0.1:8000/docs to confirm it's up (interactive Swagger UI).

## 4. Set up the frontend

```bash
cd prototype/frontend
npm install
npm run dev
```

Open http://localhost:3000. The backend's CORS config already allows
requests from this origin, so no extra configuration is needed for local
development.
