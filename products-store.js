/**
 * products-store.js
 * ------------------
 * Dedicated persistence layer for products, ONE Mongo document per product
 * (collection: "products").
 *
 * WHY THIS FILE EXISTS:
 * Previously every product (including its base64 product photos) lived
 * inside a single giant array on the one-and-only `app_data` document.
 * As products piled up that single document grew past MongoDB's 16MB
 * per-document limit, and saves/uploads started failing silently.
 *
 * This file gives products their own home: each product is its own
 * small document, so there is effectively no size ceiling on how many
 * products you can have — the 16MB limit now applies per PRODUCT, not
 * to your whole catalog at once.
 *
 * database.js still exposes `readDatabase().products` as a plain
 * in-memory array (nothing else in server.js has to change) — this
 * file is only the "save it properly" layer underneath that.
 */

const COLLECTION_NAME = "products";

let productsCollection = null;

// Called once from database.js's connectDB(), after the Mongo client
// is connected.
function init(db) {
  productsCollection = db.collection(COLLECTION_NAME);
}

function assertReady() {
  if (!productsCollection) {
    throw new Error("products-store not initialized — call init(db) first.");
  }
}

// Load every product back into a plain array (used to populate the
// in-memory cache at startup).
async function loadAllProducts() {
  assertReady();
  const docs = await productsCollection.find({}).toArray();
  return docs.map((doc) => {
    const { _id, ...product } = doc;
    return product;
  });
}

// Persist the CURRENT full products array:
//   - every product present gets upserted (created or overwritten)
//   - any product no longer in the array gets deleted from the collection
//     (covers admin/seller deletes)
// Uses each product's own `id` field as the unique key, matching how
// the rest of the app already identifies products.
async function saveAllProducts(products) {
  assertReady();
  const list = Array.isArray(products) ? products : [];

  if (list.length > 0) {
    const ops = list.map((product) => ({
      replaceOne: {
        filter: { id: product.id },
        replacement: product,
        upsert: true,
      },
    }));
    await productsCollection.bulkWrite(ops, { ordered: false });
  }

  const keepIds = list.map((p) => p.id);
  // If the list is empty, delete everything; otherwise delete anything
  // whose id isn't in the current list.
  await productsCollection.deleteMany(
    keepIds.length ? { id: { $nin: keepIds } } : {}
  );
}

// One-time migration helper: takes a legacy embedded products array
// (found on an old app_data document) and moves it into the products
// collection. Safe to call even if some/all of it is already there —
// it just upserts.
async function migrateLegacyProducts(legacyProducts) {
  assertReady();
  if (!Array.isArray(legacyProducts) || legacyProducts.length === 0) {
    return 0;
  }
  const ops = legacyProducts.map((product) => ({
    replaceOne: {
      filter: { id: product.id },
      replacement: product,
      upsert: true,
    },
  }));
  await productsCollection.bulkWrite(ops, { ordered: false });
  return legacyProducts.length;
}

async function count() {
  assertReady();
  return productsCollection.countDocuments();
}

module.exports = {
  init,
  loadAllProducts,
  saveAllProducts,
  migrateLegacyProducts,
  count,
};
