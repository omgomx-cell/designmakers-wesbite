/**
 * seo.js — Search-engine visibility for Design Makers
 * ----------------------------------------------------
 * Makes every product findable on Google (Search, Images, Shopping):
 *
 *   /                          home page   (Organization + WebSite schema, crawlable links)
 *   /product/:id/:slug         product page (title, description, Product + Breadcrumb schema,
 *                                            real price/stock/rating, crawlable content)
 *   /category/:slug            category page (ItemList schema, crawlable product links)
 *   /sitemap.xml               all products + categories, with images and lastmod
 *   /robots.txt                crawl rules
 *   /feed/google-merchant.xml  free Google Shopping (Merchant Center) product feed
 *
 * The visual storefront (index.html) is unchanged. These routes serve the same
 * index.html, but with real per-page <head> tags and a visually-hidden block of
 * real content so crawlers see the product without having to run the JavaScript.
 *
 * Registered from server.js BEFORE the old routes, so these win.
 */

const fs = require("fs");
const path = require("path");

module.exports = function registerSeo(app, deps) {
  const {
    readDatabase,
    SITE_URL,
    slugifyProductName,
    escapeHtml,
    escapeJsonForHtml,
    isSaleActive,
    getStockForVariant,
    sameAs = [],
    rootDir,
  } = deps;

  const BRAND = "Design Makers";
  const DEFAULT_DESC =
    "Design Makers — personalized photo mugs, cushions, keychains, frames and gifts, customized just for you and delivered. Order easily via WhatsApp, Cash on Delivery.";

  // ---------------------------------------------------------------- helpers

  let templateCache = null;
  function getTemplate() {
    if (templateCache === null) {
      templateCache = fs.readFileSync(path.join(rootDir, "index.html"), "utf8");
    }
    return templateCache;
  }

  function visibleProducts(database) {
    const banned = new Set((database.sellers || []).filter((s) => s.banned).map((s) => s.id));
    return (database.products || []).filter(
      (p) =>
        p.active &&
        p.approved !== false &&
        !p.hidden &&
        !p.isGiftAddon &&
        !(p.sellerId && banned.has(p.sellerId)),
    );
  }

  // plain text only: strips any HTML tags a seller typed into a description
const clean = (s) => String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
  const clip = (s, n) => {
    const t = clean(s);
    return t.length <= n ? t : t.slice(0, n - 1).replace(/\s+\S*$/, "") + "…";
  };

  const productPath = (p) => `/product/${p.id}/${slugifyProductName(p.name)}`;
  const productUrl = (p) => `${SITE_URL}${productPath(p)}`;
  const categoryUrl = (name) => `${SITE_URL}/category/${slugifyProductName(name)}`;

  function absUrl(src) {
    if (!src) return "";
    if (/^https?:\/\//i.test(src)) return src;
    return `${SITE_URL}/${String(src).replace(/^\/+/, "")}`;
  }

  function imageUrls(p) {
    const stored = Array.isArray(p.images) && p.images.length ? p.images : p.image ? [p.image] : [];
    return stored
      .map((src, i) =>
        typeof src === "string" && src.startsWith("data:image/")
          ? `${SITE_URL}/product-image/${p.id}/${i}`
          : absUrl(src),
      )
      .filter(Boolean);
  }

  function priceInfo(p) {
    const price = Number(p.price) || 0;
    if (typeof isSaleActive === "function" && isSaleActive(p)) {
      const sale = Math.round(price * (1 - Number(p.salePercent) / 100) * 100) / 100;
      return { price, sale, final: sale, saleEndsAt: p.saleEndsAt ? Number(p.saleEndsAt) : null };
    }
    return { price, sale: null, final: price, saleEndsAt: null };
  }

  function inStock(p) {
    try {
      if (Array.isArray(p.sizes) && p.sizes.length) {
        return p.sizes.some((size) => getStockForVariant(p, size) > 0);
      }
      return getStockForVariant(p, null) > 0;
    } catch (e) {
      return true;
    }
  }

  function reviewStats(database, productId) {
    const rows = (database.reviews || []).filter(
      (r) => r.productId === productId && Number(r.rating) >= 1 && Number(r.rating) <= 5,
    );
    if (!rows.length) return null;
    const avg = rows.reduce((s, r) => s + Number(r.rating), 0) / rows.length;
    return { count: rows.length, avg: Math.round(avg * 10) / 10, rows };
  }

  const inr = (n) => `₹${Number(n).toLocaleString("en-IN", { maximumFractionDigits: 2 })}`;
  const isoDate = (ms) => new Date(ms).toISOString().slice(0, 10);

  // Fills the real per-page <head> tags + crawlable body block into index.html
  function renderPage({ title, description, canonical, ogType = "website", ogImage, jsonLd = [], bodyHtml = "", noindex = false }) {
    let html = getTemplate();
    const t = escapeHtml(title);
    const d = escapeHtml(description);
    const c = escapeHtml(canonical);
    const img = escapeHtml(ogImage || `${SITE_URL}/Logo.png`);

    // Relative asset paths in index.html (Logo.png, banners…) must resolve from
    // the site root, otherwise they break on /product/12/name and /category/x.
    html = html.replace(/<head>/i, `<head>\n    <base href="/" />`);

    html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${t}</title>`);
    html = html.replace(/<meta name="description" content="[^"]*" \/>/, `<meta name="description" content="${d}" />`);
    html = html.replace(/<link rel="canonical" href="[^"]*" \/>/, `<link rel="canonical" href="${c}" />`);
    html = html.replace(/<meta property="og:type" content="[^"]*" \/>/, `<meta property="og:type" content="${ogType}" />`);
    html = html.replace(/<meta property="og:title" content="[^"]*" \/>/, `<meta property="og:title" content="${t}" />`);
    html = html.replace(/<meta property="og:description" content="[^"]*" \/>/, `<meta property="og:description" content="${d}" />`);
    html = html.replace(/<meta property="og:image" content="[^"]*" \/>/, `<meta property="og:image" content="${img}" />`);
    html = html.replace(/<meta property="og:url" content="[^"]*" \/>/, `<meta property="og:url" content="${c}" />`);
    html = html.replace(
      /<meta name="twitter:card" content="[^"]*" \/>/,
      `<meta name="twitter:card" content="summary_large_image" />\n` +
        `    <meta name="twitter:title" content="${t}" />\n` +
        `    <meta name="twitter:description" content="${d}" />\n` +
        `    <meta name="twitter:image" content="${img}" />\n` +
        `    <meta property="og:locale" content="en_IN" />\n` +
        `    <meta name="robots" content="${noindex ? "noindex, follow" : "index, follow, max-image-preview:large, max-snippet:-1"}" />`,
    );

    const ld = jsonLd.map((o) => `<script type="application/ld+json">${escapeJsonForHtml(o)}</script>`).join("\n    ");
    html = html.replace("<!--SEO_JSONLD-->", ld);

    if (bodyHtml) {
      // Visually hidden (screen-reader style), but real text/links for crawlers.
      const block =
        `<section id="seo-content" aria-label="Product details" ` +
        `style="position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;">` +
        `${bodyHtml}</section>`;
      html = html.replace(/<body>/i, `<body>\n    ${block}`);
    }
    return html;
  }

  function sendPage(res, status, page) {
    res.status(status).set("Content-Type", "text/html; charset=utf-8").send(renderPage(page));
  }

  function breadcrumb(items) {
    return {
      "@context": "https://schema.org",
      "@type": "BreadcrumbList",
      itemListElement: items.map((it, i) => ({
        "@type": "ListItem",
        position: i + 1,
        name: it.name,
        item: it.url,
      })),
    };
  }

  function categoriesOf(products) {
    const map = new Map();
    products.forEach((p) => {
      const c = clean(p.category);
      if (!c) return;
      if (!map.has(c)) map.set(c, []);
      map.get(c).push(p);
    });
    return map;
  }

  // ------------------------------------------------------------------- home

  app.get("/", (req, res) => {
    try {
      const database = readDatabase();
      const products = visibleProducts(database);
      const cats = categoriesOf(products);

      const org = {
        "@context": "https://schema.org",
        "@type": "Organization",
        name: BRAND,
        url: `${SITE_URL}/`,
        logo: `${SITE_URL}/Logo.png`,
        sameAs: sameAs.filter(Boolean),
      };
      const site = {
        "@context": "https://schema.org",
        "@type": "WebSite",
        name: BRAND,
        url: `${SITE_URL}/`,
        inLanguage: "en-IN",
      };

      const catLinks = [...cats.keys()]
        .map((c) => `<li><a href="${escapeHtml(`/category/${slugifyProductName(c)}`)}">${escapeHtml(c)}</a></li>`)
        .join("");
      const prodLinks = products
        .slice(0, 60)
        .map((p) => `<li><a href="${escapeHtml(productPath(p))}">${escapeHtml(p.name)}</a> — ${escapeHtml(inr(priceInfo(p).final))}</li>`)
        .join("");

      sendPage(res, 200, {
        title: `Personalized Gifts Online — Photo Mugs, Cushions, Frames | ${BRAND}`,
        description: DEFAULT_DESC,
        canonical: `${SITE_URL}/`,
        jsonLd: [org, site],
        bodyHtml: `<nav><h2>Shop by category</h2><ul>${catLinks}</ul><h2>Popular personalized gifts</h2><ul>${prodLinks}</ul></nav>`,
      });
    } catch (err) {
      console.error("SEO home render failed:", err.message);
      res.sendFile(path.join(rootDir, "index.html"));
    }
  });

  // Old direct file URL → one canonical home URL
  app.get("/index.html", (req, res) => res.redirect(301, "/"));

  // ---------------------------------------------------------------- product

  app.get("/product/:id{/:slug}", (req, res) => {
    try {
      const database = readDatabase();
      const id = Number(req.params.id);
      const product = Number.isFinite(id) ? visibleProducts(database).find((p) => p.id === id) : null;

      if (!product) {
        // Real 404 status (not a "soft 404") so Google drops dead/hidden products.
        return sendPage(res, 404, {
          title: `Product not found | ${BRAND}`,
          description: DEFAULT_DESC,
          canonical: `${SITE_URL}/`,
          noindex: true,
        });
      }

      // One URL per product: wrong/missing slug → 301 to the canonical one.
      const wanted = productPath(product);
      const current = decodeURIComponent(req.path).replace(/\/+$/, "");
      if (current !== wanted) {
        const qs = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
        return res.redirect(301, wanted + qs);
      }

      const url = productUrl(product);
      const imgs = imageUrls(product);
      const pi = priceInfo(product);
      const stock = inStock(product);
      const stats = reviewStats(database, product.id);
      const category = clean(product.category);

      const description =
        clip(product.description, 158) ||
        `Buy ${product.name} online — personalized ${category ? category.toLowerCase() + " " : ""}gift by ${BRAND}, ${inr(pi.final)}. Order via WhatsApp, Cash on Delivery.`;
      const title = `${clip(product.name, 42)} — Buy Online ${inr(pi.final)} | ${BRAND}`;

      const priceValidUntil = pi.saleEndsAt ? isoDate(pi.saleEndsAt) : isoDate(Date.now() + 90 * 864e5);

      const productLd = {
        "@context": "https://schema.org",
        "@type": "Product",
        "@id": `${url}#product`,
        name: product.name,
        description: clean(product.description) || description,
        sku: `DM-${product.id}`,
        image: imgs.length ? imgs.slice(0, 6) : [`${SITE_URL}/Logo.png`],
        category: category || undefined,
        brand: { "@type": "Brand", name: BRAND },
        offers: {
          "@type": "Offer",
          url,
          priceCurrency: "INR",
          price: pi.final.toFixed(2),
          priceValidUntil,
          availability: stock ? "https://schema.org/InStock" : "https://schema.org/OutOfStock",
          itemCondition: "https://schema.org/NewCondition",
          seller: { "@type": "Organization", name: BRAND },
        },
      };
      if (stats) {
        productLd.aggregateRating = {
          "@type": "AggregateRating",
          ratingValue: stats.avg,
          reviewCount: stats.count,
        };
        productLd.review = stats.rows.slice(0, 5).map((r) => ({
          "@type": "Review",
          reviewRating: { "@type": "Rating", ratingValue: Number(r.rating), bestRating: 5 },
          author: { "@type": "Person", name: clean(r.customerName).split(" ")[0] || "Customer" },
          reviewBody: clip(r.text, 400) || undefined,
        }));
      }

      const crumbs = [{ name: "Home", url: `${SITE_URL}/` }];
      if (category) crumbs.push({ name: category, url: categoryUrl(category) });
      crumbs.push({ name: product.name, url });

      const related = visibleProducts(database)
        .filter((p) => p.id !== product.id && clean(p.category) === category)
        .slice(0, 8)
        .map((p) => `<li><a href="${escapeHtml(productPath(p))}">${escapeHtml(p.name)}</a></li>`)
        .join("");

      const bodyHtml =
        `<article>` +
        `<h1>${escapeHtml(product.name)}</h1>` +
        (imgs[0] ? `<img src="${escapeHtml(imgs[0])}" alt="${escapeHtml(product.name)}" width="400" height="400">` : "") +
        `<p>${escapeHtml(clean(product.description) || description)}</p>` +
        `<p>Price: ${escapeHtml(inr(pi.final))}${pi.sale ? ` (was ${escapeHtml(inr(pi.price))})` : ""} — ${stock ? "In stock" : "Out of stock"}</p>` +
        (category ? `<p>Category: <a href="${escapeHtml(`/category/${slugifyProductName(category)}`)}">${escapeHtml(category)}</a></p>` : "") +
        (related ? `<h2>More ${escapeHtml(category)}</h2><ul>${related}</ul>` : "") +
        `</article>`;

      sendPage(res, 200, {
        title,
        description,
        canonical: url,
        ogType: "product",
        ogImage: imgs[0],
        jsonLd: [productLd, breadcrumb(crumbs)],
        bodyHtml,
      });
    } catch (err) {
      console.error("SEO product render failed:", err.message);
      res.sendFile(path.join(rootDir, "index.html"));
    }
  });

  // --------------------------------------------------------------- category

  app.get("/category/:slug", (req, res) => {
    try {
      const database = readDatabase();
      const products = visibleProducts(database);
      const cats = categoriesOf(products);
      const name = [...cats.keys()].find((c) => slugifyProductName(c) === req.params.slug);

      if (!name) {
        return sendPage(res, 404, {
          title: `Category not found | ${BRAND}`,
          description: DEFAULT_DESC,
          canonical: `${SITE_URL}/`,
          noindex: true,
        });
      }

      const list = cats.get(name);
      const url = categoryUrl(name);
      const itemList = {
        "@context": "https://schema.org",
        "@type": "ItemList",
        name: `${name} — ${BRAND}`,
        itemListElement: list.slice(0, 50).map((p, i) => ({
          "@type": "ListItem",
          position: i + 1,
          url: productUrl(p),
          name: p.name,
        })),
      };
      const links = list
        .map((p) => `<li><a href="${escapeHtml(productPath(p))}">${escapeHtml(p.name)}</a> — ${escapeHtml(inr(priceInfo(p).final))}</li>`)
        .join("");

      sendPage(res, 200, {
        title: `${name} — Personalized ${name} Online | ${BRAND}`,
        description: `Shop personalized ${name.toLowerCase()} online at ${BRAND}. ${list.length} custom ${list.length === 1 ? "design" : "designs"} starting at ${inr(Math.min(...list.map((p) => priceInfo(p).final)))}. Order via WhatsApp, Cash on Delivery.`,
        canonical: url,
        ogImage: imageUrls(list[0])[0],
        jsonLd: [itemList, breadcrumb([{ name: "Home", url: `${SITE_URL}/` }, { name, url }])],
        bodyHtml: `<h1>${escapeHtml(name)}</h1><ul>${links}</ul>`,
      });
    } catch (err) {
      console.error("SEO category render failed:", err.message);
      res.sendFile(path.join(rootDir, "index.html"));
    }
  });

  // ------------------------------------------------------ robots + sitemap

  app.get("/robots.txt", (req, res) => {
    res.type("text/plain").send(
      [
        "User-agent: *",
        "Allow: /",
        "Disallow: /admin",
        "Disallow: /seller",
        "Disallow: /sellerapplication",
        "Disallow: /api/",
        "",
        `Sitemap: ${SITE_URL}/sitemap.xml`,
        "",
      ].join("\n"),
    );
  });

  app.get("/sitemap.xml", (req, res) => {
    try {
      const database = readDatabase();
      const products = visibleProducts(database);
      const cats = categoriesOf(products);
      const today = isoDate(Date.now());

      const rows = [`  <url><loc>${escapeHtml(SITE_URL + "/")}</loc><lastmod>${today}</lastmod><changefreq>daily</changefreq><priority>1.0</priority></url>`];

      cats.forEach((_, name) => {
        rows.push(
          `  <url><loc>${escapeHtml(categoryUrl(name))}</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>`,
        );
      });

      products.forEach((p) => {
        const stamp = Date.parse(p.updatedAt || p.createdAt || "");
        const imgXml = imageUrls(p)
          .slice(0, 5)
          .map((u) => `<image:image><image:loc>${escapeHtml(u)}</image:loc><image:title>${escapeHtml(clip(p.name, 100))}</image:title></image:image>`)
          .join("");
        rows.push(
          `  <url><loc>${escapeHtml(productUrl(p))}</loc>` +
            (Number.isFinite(stamp) ? `<lastmod>${isoDate(stamp)}</lastmod>` : "") +
            `<changefreq>weekly</changefreq><priority>0.8</priority>${imgXml}</url>`,
        );
      });

      const xml =
        `<?xml version="1.0" encoding="UTF-8"?>\n` +
        `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">\n` +
        rows.join("\n") +
        `\n</urlset>`;

      res.set("Content-Type", "application/xml; charset=utf-8");
      res.set("Cache-Control", "public, max-age=3600");
      res.send(xml);
    } catch (err) {
      console.error("sitemap failed:", err.message);
      res.status(500).type("text/plain").send("");
    }
  });

  // ------------------------------------------- Google Merchant Center feed

  app.get("/feed/google-merchant.xml", (req, res) => {
    try {
      const database = readDatabase();
      const items = visibleProducts(database)
        .map((p) => {
          const imgs = imageUrls(p);
          if (!imgs.length) return ""; // Merchant Center rejects items without an image
          const pi = priceInfo(p);
          const desc = clip(p.description, 4500) || `${p.name} — personalized gift by ${BRAND}`;
          return (
            `    <item>\n` +
            `      <g:id>DM-${p.id}</g:id>\n` +
            `      <g:title>${escapeHtml(clip(p.name, 150))}</g:title>\n` +
            `      <g:description>${escapeHtml(desc)}</g:description>\n` +
            `      <g:link>${escapeHtml(productUrl(p))}</g:link>\n` +
            `      <g:image_link>${escapeHtml(imgs[0])}</g:image_link>\n` +
            imgs.slice(1, 10).map((u) => `      <g:additional_image_link>${escapeHtml(u)}</g:additional_image_link>\n`).join("") +
            `      <g:availability>${inStock(p) ? "in_stock" : "out_of_stock"}</g:availability>\n` +
            `      <g:price>${pi.price.toFixed(2)} INR</g:price>\n` +
            (pi.sale ? `      <g:sale_price>${pi.sale.toFixed(2)} INR</g:sale_price>\n` : "") +
            `      <g:condition>new</g:condition>\n` +
            `      <g:brand>${BRAND}</g:brand>\n` +
            `      <g:identifier_exists>no</g:identifier_exists>\n` +
            (clean(p.category) ? `      <g:product_type>${escapeHtml(clean(p.category))}</g:product_type>\n` : "") +
            `    </item>`
          );
        })
        .filter(Boolean)
        .join("\n");

      const xml =
        `<?xml version="1.0" encoding="UTF-8"?>\n` +
        `<rss version="2.0" xmlns:g="http://base.google.com/ns/1.0">\n  <channel>\n` +
        `    <title>${BRAND}</title>\n    <link>${escapeHtml(SITE_URL)}</link>\n    <description>${BRAND} product feed</description>\n` +
        items +
        `\n  </channel>\n</rss>`;

      res.set("Content-Type", "application/xml; charset=utf-8");
      res.set("Cache-Control", "public, max-age=3600");
      res.send(xml);
    } catch (err) {
      console.error("merchant feed failed:", err.message);
      res.status(500).type("text/plain").send("");
    }
  });
};
