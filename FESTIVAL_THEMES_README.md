# Festival themes — Deepawali, Dushera, Dhanteras, Chhath

Built on top of the Update 1 codebase. Admin-only switching; no customer-side theme switcher.

## Changed files
- index.html — shared festival theme engine (CSS block `#dmFestivalThemes`, JS `DM_FESTIVAL_THEMES` + `dmApplyFestivalTheme`)
- admin.html — new separate "Themes" tab in the sidebar (after Inventory) holding all 6 theme cards (Normal, Rakshabandhan + 4 festival); sidebar re-ordered; tabs renamed: Seller Applications, Sellers, Support Desk
- server.js — PUT /api/admin/settings/theme accepts the 4 new themes
- database.js — startup whitelist extended (otherwise a saved festival theme reset to "normal" on every restart)

## Use
Admin > Themes tab > pick a theme > Apply Selected Theme.

## Notes
- One engine, four palettes. Normal and Rakshabandhan are untouched.
- Uses the existing dark glass mode as base; dark/light toggle hidden while a festival theme is active.
- No external image assets needed (CSS + inline SVG environments).

## Themes (8) — updated
Normal, Rakshabandhan, Deepawali, Dushera, Dhanteras, Chhath, **Liquid Glass**, **xx**.

### New homepage (xx/ folder)
- `xx/homepage.html` — the new homepage layout (header, hero, categories, Gift for Her/Him, how it works, offers, best sellers, footer).
- `xx/xx.js` — wires it to the live store (products, cart, wishlist, popups).
- `xx/glass.css` — colour skin only. **Liquid Glass** uses the same homepage layout, recoloured with this file.
- **xx** theme = the layout in its own rose/gold colours. **Liquid Glass** = same layout + glass colours.
- Deploy: the whole `xx/` folder must sit next to `server.js`.


---
## Update: one homepage layout for ALL themes
Every theme now uses the new homepage layout (`xx/homepage.html` + `xx/xx.js`). Themes only change the colours:

| Theme | Colours come from |
|---|---|
| Normal | `xx/skin-normal.css` |
| Rakshabandhan | `xx/skin-rakshabandhan.css` |
| Deepawali, Dushera, Dhanteras, Chhath | `xx/skin-festival.css` (reads each theme's own colours from the page) |
| Liquid Glass | `xx/glass.css` |
| xx | built-in rose/gold |

- The phone bottom bar (Home, Search, Wishlist, Categories, Cart) shows in every theme.
- If the new page ever fails to load, the old homepage is shown automatically. Add `?old=1` to the site URL to see the old homepage.
