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
