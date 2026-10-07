# Design Makers — Google SEO (ek baar set, phir sab automatic)

## Automatic kaise hota hai
Admin/seller panel se naya product add hote hi (aur seller product approve hote hi) server uske liye khud bana deta hai:
- product page `/product/<id>/<naam>` (title, description, price, stock, rating, schema)
- `sitemap.xml` me entry (photos ke saath)
- Google Shopping feed (`/feed/google-merchant.xml`) me entry
- category page (nayi category ho to wo bhi)
Product edit/hide/delete karne par sab apne aap update/hata hota hai. Aapko code ya sitemap dobara upload nahi karna.

## Sirf ek baar ke steps
1. Ye zip deploy karein. `npm install` phir `npm start`.
2. Server pe `SITE_URL` asli domain pe set karein (e.g. `https://designmakers.shop`).
3. Google Search Console: domain verify -> Sitemaps me `https://designmakers.shop/sitemap.xml` submit.
4. (Optional) Merchant Center: free listings -> Products -> Feed -> `https://designmakers.shop/feed/google-merchant.xml` (scheduled fetch). Shipping/returns details bharna zaroori.
5. (Optional) Google Business Profile.

## Chhoti baatein jo har naye product me dhyan rakhein
- **Stock daalna zaroori hai**: naya product jab tak stock nahi dalte, Google ko "Out of stock" dikhega (wahi jo site pe dikhta hai).
- Naam keywords wala ho ("Personalized Photo Coffee Mug"), description likhein, photo daalein — warna SEO kamzor rahega.
- Indexing me kuch din se hafte lagte hain; #1 rank guaranteed nahi hota.

## Domain: designmakers.shop (permanent)
- Code me default `SITE_URL` ab `https://designmakers.shop` hai (env me bhi yahi set karein).
- `designmakers.site` (aur www versions) pe koi bhi page kholne par automatic 301 redirect `.shop` pe hota hai (same path ke saath).
- Dono domains hosting me **same server/app** se connected rehne chahiye, tabhi redirect chalega.
- Google Sign-In use karte hain to Google Cloud Console me `https://designmakers.shop` ko "Authorized JavaScript origins" me add karein.
