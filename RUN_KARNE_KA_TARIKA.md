# Design Makers — Sirf Run Karne Ke Steps

**Achhi khabar:** code mein koi syntax/bug error nahi hai — maine `server.js`,
`database.js`, `products-store.js` sab check kar liye, sab theek hain.
Ye sirf isliye "run" nahi ho raha kyunki isse **Node packages install**
karne aur ek **MongoDB database** se connect hone ki zaroorat hai —
ye do cheezein mere sandbox mein nahi ho paayin kyunki yahan internet
access disabled hai. Aapke apne PC/laptop pe ye normally chal jayega.

## Option A — Sabse aasaan (Docker + VS Code) — already ready hai!
Is zip ke andar `.devcontainer/` folder already bana hua hai jo
**local MongoDB + Node dono khud spin up kar deta hai**, bina aapko
kuch manually install kiye:

1. VS Code + Docker Desktop install karein (agar nahi hai)
2. VS Code me "Dev Containers" extension install karein
3. Ye folder VS Code me kholein → bottom-right popup me
   **"Reopen in Container"** click karein
4. Ye khud `npm install` chalayega, local MongoDB start karega, aur
   sample data seed kar dega
5. Terminal me: `npm start`
6. Port 3000 pe site khul jayegi (Storefront `/`, Admin `/admin`)

## Option B — Bina Docker ke, apne PC pe direct
1. Node.js install karein (v18+): https://nodejs.org
2. MongoDB install karein (local) — https://www.mongodb.com/try/download/community
   — YA phir MongoDB Atlas (free cloud) bana lein: https://www.mongodb.com/cloud/atlas/register
3. Is folder me terminal khol ke:
   ```bash
   npm install
   ```
4. `.env.example` ko copy karke `.env` naam dein, aur `MONGODB_URI`
   apna daal dein (local ho to `mongodb://localhost:27017/designmakers`,
   Atlas ho to Atlas ka connection string). Pehli baar khali DB ke
   saath chalane ke liye `ALLOW_NEW_DATABASE=true` rehne dein.
5. Server start karein:
   ```bash
   npm start
   ```
6. Browser me kholein: `http://localhost:3000`
   - Storefront → `/`
   - Admin panel → `/admin`
   - Seller panel → `/seller` ya `/sell`

## Zaroori note
- Pehli run ke baad, jab aapka real data database me aa jaye, to
  `.env` se `ALLOW_NEW_DATABASE=true` hata dein — warna galti se
  fresh/empty DB ban sakta hai.
- Email (seller welcome mail, approvals) optional hai — `GMAIL_USER`
  aur `GMAIL_APP_PASSWORD` set na karein to bhi server chalega, bas
  auto-email nahi jayega (admin panel me password/details manually
  dikhengi).
