
      const TOKEN_KEY = "dm_seller_token";

      function getToken() { return localStorage.getItem(TOKEN_KEY); }
      function setToken(t) { localStorage.setItem(TOKEN_KEY, t); }
      function clearToken() { localStorage.removeItem(TOKEN_KEY); }

      async function api(path, options = {}) {
        const token = getToken();
        const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
        if (token) headers.Authorization = "Bearer " + token;
        const res = await fetch(path, Object.assign({}, options, { headers }));
        const data = await res.json().catch(() => ({ success: false, message: "Server error." }));

        // GLOBAL 401 HANDLER — every seller tab (Dashboard, My Products,
        // Orders, Profile) calls this same api() helper. Before this fix,
        // if the token went stale mid-session, every one of those calls
        // just quietly failed and each tab's own catch block left it on
        // an empty/loading state forever — "dashboard loads but data/tabs
        // broken", with no way for the seller to tell it was an auth
        // problem. Now a 401 on any authenticated call kicks them straight
        // back to a visible, working login screen instead.
        if (res.status === 401 && token && !path.includes("/login") && !path.includes("/forgot-password")) {
          clearToken();
          const dashboardEl = document.getElementById("dashboard");
          const loginScreenEl = document.getElementById("loginScreen");
          if (dashboardEl) dashboardEl.style.display = "none";
          if (loginScreenEl) loginScreenEl.style.display = "flex";
          showLoginForm();
          const errorEl = document.getElementById("loginError");
          if (errorEl) {
            errorEl.textContent = "Your session ended. Please log in again.";
            errorEl.style.display = "block";
          }
        }

        return { ok: res.ok, data };
      }

      // ---------- Login screen ----------
      function showForgotPassword() {
        document.getElementById("loginFormBlock").style.display = "none";
        document.getElementById("forgotBlock").style.display = "block";
      }
      function showLoginForm() {
        document.getElementById("forgotBlock").style.display = "none";
        document.getElementById("loginFormBlock").style.display = "block";
      }

      // ================================
      // GOOGLE SIGN-IN (seller)
      // ================================
      // Paste your Google OAuth Client ID here — same one used on index.html
      // and set as GOOGLE_CLIENT_ID on the server.
      const GOOGLE_CLIENT_ID = "982773085262-n04rje1hcha9om6h2qe7fshhirmi9j6t.apps.googleusercontent.com";

      function initGoogleSignIn() {
        if (!window.google || !window.google.accounts || GOOGLE_CLIENT_ID.startsWith("YOUR_")) return;
        google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleSellerLogin,
        });
        const btnEl = document.getElementById("googleSignInBtn");
        if (btnEl) {
          google.accounts.id.renderButton(btnEl, { theme: "outline", size: "large", width: 280, text: "continue_with" });
        }
      }

      async function handleGoogleSellerLogin(response) {
        const errorEl = document.getElementById("googleLoginError");
        errorEl.style.display = "none";
        const { data } = await api("/api/seller/google-login", {
          method: "POST",
          body: JSON.stringify({ idToken: response.credential }),
        });
        if (!data.success) {
          errorEl.textContent = data.message || "Google sign-in failed.";
          errorEl.style.display = "block";
          return;
        }
        setToken(data.token);
        enterDashboard(data.seller);
      }

      window.addEventListener("load", initGoogleSignIn);

      async function doLogin() {
        const errorEl = document.getElementById("loginError");
        errorEl.style.display = "none";
        const sellerId = document.getElementById("loginSellerId").value.trim();
        const password = document.getElementById("loginPassword").value;
        if (!sellerId || !password) {
          errorEl.textContent = "Enter your Seller ID and password.";
          errorEl.style.display = "block";
          return;
        }
        const btn = document.getElementById("loginBtn");
        btn.disabled = true;
        btn.textContent = "Logging in...";
        const { data } = await api("/api/seller/login", {
          method: "POST",
          body: JSON.stringify({ sellerId, password }),
        });
        btn.disabled = false;
        btn.textContent = "Log in";
        if (!data.success) {
          errorEl.textContent = data.message || "Could not log in.";
          errorEl.style.display = "block";
          return;
        }
        setToken(data.token);
        window.__dmSeller = data.seller;
        if (data.mustChangePassword) {
          showMustChangeScreen(password);
          return;
        }
        enterDashboard(data.seller);
      }

      // ---------- Forced password change (first login after an OTP) ----------
      function showMustChangeScreen(otpUsed) { return; /* seller passwords are admin-controlled */

        document.getElementById("loginScreen").style.display = "none";
        document.getElementById("dashboard").style.display = "none";
        document.getElementById("mustChangeScreen").style.display = "block";
        document.getElementById("mcCurrentPassword").value = otpUsed || "";
        document.getElementById("mcNewPassword").value = "";
        document.getElementById("mcConfirmPassword").value = "";
        document.getElementById("mcError").style.display = "none";
      }

      async function submitMustChangePassword() {
        const errorEl = document.getElementById("mcError");
        errorEl.style.display = "none";
        const currentPassword = document.getElementById("mcCurrentPassword").value;
        const newPassword = document.getElementById("mcNewPassword").value;
        const confirmPassword = document.getElementById("mcConfirmPassword").value;

        if (!currentPassword || !newPassword || !confirmPassword) {
          errorEl.textContent = "Fill in all three fields.";
          errorEl.style.display = "block";
          return;
        }
        if (newPassword.length < 6) {
          errorEl.textContent = "New password must be at least 6 characters.";
          errorEl.style.display = "block";
          return;
        }
        if (newPassword !== confirmPassword) {
          errorEl.textContent = "New password and confirmation don't match.";
          errorEl.style.display = "block";
          return;
        }

        const btn = document.getElementById("mcSubmitBtn");
        btn.disabled = true;
        btn.textContent = "Saving...";
        const { data } = await api("/api/seller/change-password", {
          method: "POST",
          body: JSON.stringify({ currentPassword, newPassword }),
        });
        btn.disabled = false;
        btn.textContent = "Save new password";
        if (!data.success) {
          errorEl.textContent = data.message || "Could not update password.";
          errorEl.style.display = "block";
          return;
        }
        document.getElementById("mustChangeScreen").style.display = "none";
        enterDashboard(window.__dmSeller || {});
      }

      async function submitForgotPassword() {
        const errorEl = document.getElementById("forgotError");
        const successEl = document.getElementById("forgotSuccess");
        errorEl.style.display = "none";
        successEl.style.display = "none";
        const sellerId = document.getElementById("forgotSellerId").value.trim();
        if (!sellerId) {
          errorEl.textContent = "Enter your Seller ID.";
          errorEl.style.display = "block";
          return;
        }
        const btn = document.getElementById("forgotBtn");
        btn.disabled = true;
        btn.textContent = "Sending...";
        const { data } = await api("/api/seller/forgot-password", {
          method: "POST",
          body: JSON.stringify({ sellerId }),
        });
        btn.disabled = false;
        btn.textContent = "Send request";
        if (!data.success) {
          errorEl.textContent = data.message || "Could not send request.";
          errorEl.style.display = "block";
          return;
        }
        successEl.textContent = data.message;
        successEl.style.display = "block";
      }

      function doLogout() {
        clearToken();
        document.getElementById("dashboard").style.display = "none";
        document.getElementById("loginScreen").style.display = "flex";
        showLoginForm();
      }

      // ---------- Dashboard shell ----------
      const DM_SELLER_TAB_TITLES = {
        dashboard: ["Dashboard", "Your business overview"],
        products: ["My Products", "Everything you've listed"],
        add: ["Add Product", "Submit a new product for approval"],
        orders: ["Orders", "Track orders containing your products"],
        profile: ["Profile", "Your shop details"],
      };
      function dmToggleSidebar() {
        const shell = document.getElementById("dmShell");
        if (shell) shell.classList.toggle("dm-sidebar-open");
      }
      function enterDashboard(seller) {
        document.getElementById("loginScreen").style.display = "none";
        document.getElementById("dashboard").style.display = "block";
        document.getElementById("dashShopTitle").textContent = seller.shopTitle || "Seller Dashboard";
        document.getElementById("dashSellerId").textContent = seller.sellerId + " · " + seller.name;
        const avatarEl = document.getElementById("sidebarAvatar");
        if (avatarEl) {
          const initials = (seller.shopTitle || seller.name || "SL").trim().split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase();
          avatarEl.textContent = initials || "SL";
        }
        window.__dmSeller = seller;
        switchTab("dashboard");
        // Preload live categories right away (in the background) so the
        // "Add Product" dropdown is already filled the instant the seller
        // opens that tab — no "Loading categories…" wait.
        loadLiveCategories();
      }

      function switchTab(tab) {
        document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
        document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
        document.getElementById("panel-" + tab).classList.add("active");
        const titleInfo = DM_SELLER_TAB_TITLES[tab];
        if (titleInfo) {
          const titleEl = document.getElementById("dmTopbarTitle");
          const subEl = document.getElementById("dmTopbarSub");
          if (titleEl) titleEl.textContent = titleInfo[0];
          if (subEl) subEl.textContent = titleInfo[1];
        }
        const shell = document.getElementById("dmShell");
        if (shell) shell.classList.remove("dm-sidebar-open");
        if (tab === "dashboard") loadSellerOverview();
        if (tab === "products") loadProducts();
        if (tab === "add") loadLiveCategories();
        if (tab === "orders") loadOrders();
        if (tab === "profile") loadProfile();
      }

      // ---------- SELLER EXECUTIVE OVERVIEW ----------
      async function loadSellerOverview() {
        const authName = (window.__dmSeller && window.__dmSeller.name) || "Seller";
        const nameEl = document.getElementById("sellerOverviewName");
        const greetingEl = document.getElementById("sellerOverviewGreeting");
        if (greetingEl) { const h = new Date().getHours(); greetingEl.textContent = h >= 5 && h < 12 ? "Good morning" : (h >= 12 && h < 17 ? "Good afternoon" : "Good evening"); }
        if (nameEl) nameEl.textContent = authName;
        ["svSales","svOrders","svProducts","svPending","svAov","svRecent","svHealth"].forEach(id => { const el=document.getElementById(id); if(el) el.innerHTML = ["svRecent","svHealth"].includes(id) ? '<div class="empty-state">Loading…</div>' : '—'; });
        try {
          const [pRes,oRes] = await Promise.all([api("/api/seller/products"), api("/api/seller/orders")]);
          const pData=pRes.data, oData=oRes.data;
          if(!pData.success || !oData.success) throw new Error("Unable to load seller data");
          const ps=pData.products||[], os=oData.orders||[];
          const valid=os.filter(o=>o.status!=="Cancelled");
          const sales=valid.reduce((sum,o)=>sum+(Number(o.sellerTotal)||0),0);
          const pending=os.filter(o=>["New","Processing"].includes(o.status)).length;
          const aov=valid.length ? sales/valid.length : 0;
          const live=ps.filter(p=>p.approved!==false).length;
          const pendingProducts=ps.filter(p=>p.approved===false).length;
          document.getElementById("svSales").textContent="₹"+Math.round(sales).toLocaleString("en-IN");
          document.getElementById("svOrders").textContent=os.length.toLocaleString("en-IN");
          document.getElementById("svProducts").textContent=live.toLocaleString("en-IN");
          document.getElementById("svPending").textContent=pending.toLocaleString("en-IN");
          document.getElementById("svAov").textContent=aov ? "₹"+Math.round(aov).toLocaleString("en-IN") : "₹0";
          const recent=os.slice(0,6);
          document.getElementById("svRecent").innerHTML = recent.length ? recent.map(o => `<div class="seller-recent-row"><div><strong>${escapeHtml(o.orderNumber || "")}</strong><span>${escapeHtml((o.items || []).map(i => i.name + " × " + i.qty).join(", "))}</span></div><div style="text-align:right"><strong>₹${(Number(o.sellerTotal) || 0).toLocaleString("en-IN")}</strong><span>${escapeHtml(o.status || "")}</span></div></div>`).join("") : '<div class="empty-state">No orders with your products yet.</div>';
          document.getElementById("svHealth").innerHTML='<div class="seller-recent-row"><div><strong>Live products</strong><span>Currently approved</span></div><span class="seller-pill">'+live+'</span></div><div class="seller-recent-row"><div><strong>Pending approval</strong><span>Waiting for admin review</span></div><span class="seller-pill">'+pendingProducts+'</span></div><div class="seller-recent-row"><div><strong>Total products</strong><span>All products in your account</span></div><span class="seller-pill">'+ps.length+'</span></div>';
        } catch(err) {
          document.getElementById("svRecent").innerHTML='<div class="empty-state">Could not load orders. <button class="link-btn" onclick="loadSellerOverview()">Retry</button></div>';
          document.getElementById("svHealth").innerHTML='<div class="empty-state">Could not load product data.</div>';
        }
      }

      // ---------- My Products ----------
      // The <select> already ships with the 10 known categories hardcoded
      // in the HTML, so the seller NEVER sees a "Loading…" or empty state —
      // it works instantly even if this fetch is slow or fails. This
      // function only runs quietly in the background to pull in any NEW
      // category the admin adds later (or drop one that's been removed),
      // updating the same dropdown in place without disturbing what's
      // already there if the fetch doesn't succeed.
      let liveCategoriesLoaded = false;
      async function loadLiveCategories() {
        // Both the "Add Product" form and the "Edit Product" modal have
        // their own category <select> — keep them in sync.
        const selects = [document.getElementById("pCategory"), document.getElementById("eCategory")].filter(Boolean);
        const currentValues = selects.map((s) => s.value);
        try {
          const res = await fetch("/api/categories");
          if (!res.ok) {
            throw new Error("HTTP " + res.status);
          }
          const data = await res.json();
          const categories = data.success ? (data.categories || []) : [];
          liveCategoriesLoaded = true;
          if (!categories.length) {
            // No live categories from the server for some reason — leave the
            // hardcoded fallback list in the dropdown as-is rather than
            // wiping it out to an empty/error state.
            return;
          }
          const optionsHtml =
            '<option value="">Select a category</option>' +
            categories.map((c) => '<option value="' + escapeHtml(c) + '">' + escapeHtml(c) + '</option>').join("");
          selects.forEach((select, i) => {
            select.innerHTML = optionsHtml;
            // Keep whatever the seller had picked (e.g. while editing) if
            // it's still a valid category; otherwise leave it on the
            // placeholder.
            if (currentValues[i] && categories.includes(currentValues[i])) {
              select.value = currentValues[i];
            }
          });
        } catch (err) {
          // Fetch failed entirely — no problem, the hardcoded 10 categories
          // already in the dropdown keep working; just log it and move on.
          console.error("Failed to load live categories, keeping fallback list:", err);
        }
      }

      // Cached so the Edit modal can look a product up by id without an
      // extra round-trip when the seller clicks "Edit".
      let sellerProductsCache = [];

      async function loadProducts() {
        const { data } = await api("/api/seller/products");
        if (!data.success) return;
        sellerProductsCache = data.products;
        const grid = document.getElementById("productsGrid");
        const empty = document.getElementById("productsEmpty");
        grid.innerHTML = "";
        if (!data.products.length) {
          empty.style.display = "block";
          return;
        }
        empty.style.display = "none";
        data.products.forEach((p) => {
          const img = (Array.isArray(p.images) && p.images[0]) || p.image || "";
          const card = document.createElement("div");
          card.className = "p-card";
          card.innerHTML =
            (img ? `<img src="${img}" alt="${escapeHtml(p.name)}" />` : `<div style="height:130px;background:var(--blush);"></div>`) +
            `<div class="body">
              <div class="name">${escapeHtml(p.name)}</div>
              <div class="meta">₹${p.price} · ${escapeHtml(p.category || "Uncategorized")}</div>
              <span class="badge ${p.approved !== false ? "live" : "pending"}">${p.approved !== false ? "Live" : "Pending approval"}</span>
            </div>
            <div class="actions"><button class="btn small secondary" onclick="openEditModal(${p.id})">Edit</button></div>`;
          grid.appendChild(card);
        });
      }

      // ---------- Edit Product ----------
      let editingProductId = null;
      let editCurrentImages = [];

      function parseSellerSizes(inputId) {
        return (document.getElementById(inputId).value || "").split(",").map(s => s.trim()).filter(Boolean);
      }

      function renderStockInputs(containerId, inputId, stock = {}) {
        const wrap = document.getElementById(containerId);
        if (!wrap) return;
        if (!Object.keys(stock).length) {
          wrap.querySelectorAll(".seller-stock-input").forEach(input => { stock[input.dataset.size || "__default"] = Math.max(0, Math.floor(Number(input.value) || 0)); });
        }
        const sizes = parseSellerSizes(inputId);
        if (!sizes.length) {
          const value = Number(stock.__default ?? stock.default ?? stock.stockQty ?? 0);
          wrap.innerHTML = '<div class="seller-stock-item"><label>Default Stock</label><input type="number" min="0" step="1" class="seller-stock-input" data-size="" value="' + (Number.isInteger(value) && value >= 0 ? value : 0) + '" /></div>';
          return;
        }
        wrap.innerHTML = sizes.map(size => {
          const value = Number(stock[size] ?? 0);
          return '<div class="seller-stock-item"><label>' + escapeHtml(size) + ' Stock</label><input type="number" min="0" step="1" class="seller-stock-input" data-size="' + escapeHtml(size) + '" value="' + (Number.isInteger(value) && value >= 0 ? value : 0) + '" /></div>';
        }).join("");
      }

      function renderNewProductStockEditor(stock = {}) { renderStockInputs("newProductStockEditor", "pSizes", stock); }
      function renderEditProductStockEditor(stock = {}) { renderStockInputs("editProductStockEditor", "eSizes", stock); }

      function collectSellerStock(containerId) {
        const variantStock = {};
        let stockQty = 0;
        document.querySelectorAll("#" + containerId + " .seller-stock-input").forEach(input => {
          const value = Math.max(0, Math.floor(Number(input.value) || 0));
          const size = input.dataset.size || "";
          if (size) variantStock[size] = value; else stockQty = value;
        });
        return { stockQty, variantStock };
      }

      function openEditModal(id) {
        const p = sellerProductsCache.find((x) => x.id === id);
        if (!p) return;

        editingProductId = id;
        editCurrentImages = (Array.isArray(p.images) && p.images.length) ? p.images.slice() : (p.image ? [p.image] : []);

        document.getElementById("eName").value = p.name || "";
        document.getElementById("ePrice").value = p.price || "";
        document.getElementById("eMoq").value = p.moq || 1;
        document.getElementById("eSizes").value = (p.sizes || []).join(", ");
        document.getElementById("eLowStockThreshold").value = Number(p.lowStockThreshold ?? 5);
        renderEditProductStockEditor((p.sizes || []).length ? (p.variantStock || {}) : { stockQty: p.stockQty || 0 });
        document.getElementById("eDescription").value = p.description || "";
        document.getElementById("eImage").value = "";

        const catSelect = document.getElementById("eCategory");
        if (p.category && !Array.from(catSelect.options).some((o) => o.value === p.category)) {
          const opt = document.createElement("option");
          opt.value = p.category;
          opt.textContent = p.category;
          catSelect.appendChild(opt);
        }
        catSelect.value = p.category || "";

        document.getElementById("editProductError").style.display = "none";
        document.getElementById("editProductSuccess").style.display = "none";
        renderEditImagePreview();

        document.getElementById("editModalOverlay").classList.add("open");
      }

      function closeEditModal() {
        document.getElementById("editModalOverlay").classList.remove("open");
      }

      function renderEditImagePreview() {
        const row = document.getElementById("eImagePreview");
        row.innerHTML = editCurrentImages
          .map((src) => `<img src="${src}" style="width:56px;height:56px;object-fit:cover;border-radius:8px;border:1px solid var(--border);margin:0 6px 6px 0;" />`)
          .join("");
      }

      document.getElementById("eImage").addEventListener("change", async (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;
        try {
          const dataUrl = await downscaleImage(file, 1000, 0.82);
          editCurrentImages = [dataUrl];
          renderEditImagePreview();
        } catch (err) {
          document.getElementById("editProductError").textContent = "Could not process the photo. Try a different image.";
          document.getElementById("editProductError").style.display = "block";
        }
      });

      async function submitEditProduct() {
        const errorEl = document.getElementById("editProductError");
        const successEl = document.getElementById("editProductSuccess");
        errorEl.style.display = "none";
        successEl.style.display = "none";

        const name = document.getElementById("eName").value.trim();
        const price = document.getElementById("ePrice").value.trim();
        const moq = document.getElementById("eMoq").value.trim();
        const category = document.getElementById("eCategory").value.trim();
        const sizes = document.getElementById("eSizes").value.trim();
        const description = document.getElementById("eDescription").value.trim();

        if (!name || !price) {
          errorEl.textContent = "Product name and price are required.";
          errorEl.style.display = "block";
          return;
        }
        if (!category) {
          errorEl.textContent = "Please select a category.";
          errorEl.style.display = "block";
          return;
        }

        const editStock = collectSellerStock("editProductStockEditor");
        const editLowStockThreshold = Math.max(0, Math.floor(Number(document.getElementById("eLowStockThreshold").value) || 0));

        const btn = document.getElementById("editProductBtn");
        btn.disabled = true;
        btn.textContent = "Saving...";

        const { data } = await api("/api/seller/products/" + editingProductId, {
          method: "PUT",
          body: JSON.stringify({
            name,
            price,
            moq: moq || 1,
            category,
            sizes,
            stockQty: editStock.stockQty,
            variantStock: editStock.variantStock,
            lowStockThreshold: editLowStockThreshold,
            description,
            images: editCurrentImages,
          }),
        });

        btn.disabled = false;
        btn.textContent = "Save changes";

        if (!data.success) {
          errorEl.textContent = data.message || "Could not update product.";
          errorEl.style.display = "block";
          return;
        }

        successEl.textContent = data.message || "Product updated.";
        successEl.style.display = "block";
        loadProducts();
        setTimeout(closeEditModal, 900);
      }

      // ---------- Add Product ----------
      function downscaleImage(file, maxDimension, quality) {
        return new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onerror = () => reject(new Error("read failed"));
          reader.onload = () => {
            const img = new Image();
            img.onerror = () => reject(new Error("decode failed"));
            img.onload = () => {
              let { width, height } = img;
              if (width > maxDimension || height > maxDimension) {
                if (width >= height) {
                  height = Math.round((height / width) * maxDimension);
                  width = maxDimension;
                } else {
                  width = Math.round((width / height) * maxDimension);
                  height = maxDimension;
                }
              }
              const canvas = document.createElement("canvas");
              canvas.width = width;
              canvas.height = height;
              const ctx = canvas.getContext("2d");
              ctx.drawImage(img, 0, 0, width, height);
              resolve(canvas.toDataURL("image/jpeg", quality));
            };
            img.src = reader.result;
          };
          reader.readAsDataURL(file);
        });
      }

      async function submitNewProduct() {
        const errorEl = document.getElementById("addProductError");
        const successEl = document.getElementById("addProductSuccess");
        errorEl.style.display = "none";
        successEl.style.display = "none";

        const name = document.getElementById("pName").value.trim();
        const price = document.getElementById("pPrice").value.trim();
        const moq = document.getElementById("pMoq").value.trim();
        const category = document.getElementById("pCategory").value.trim();
        const sizes = document.getElementById("pSizes").value.trim();
        const description = document.getElementById("pDescription").value.trim();
        const fileInput = document.getElementById("pImage");

        if (!name || !price) {
          errorEl.textContent = "Product name and price are required.";
          errorEl.style.display = "block";
          return;
        }
        if (!category) {
          errorEl.textContent = "Please select a category.";
          errorEl.style.display = "block";
          return;
        }

        const btn = document.getElementById("addProductBtn");
        btn.disabled = true;
        btn.textContent = "Submitting...";

        let image = "";
        if (fileInput.files && fileInput.files[0]) {
          try {
            image = await downscaleImage(fileInput.files[0], 1000, 0.82);
          } catch (e) {
            errorEl.textContent = "Could not process the photo. Try a different image.";
            errorEl.style.display = "block";
            btn.disabled = false;
            btn.textContent = "Submit for approval";
            return;
          }
        }

        const newStock = collectSellerStock("newProductStockEditor");
        const lowStockThreshold = Math.max(0, Math.floor(Number(document.getElementById("pLowStockThreshold").value) || 0));

        const { data } = await api("/api/seller/products", {
          method: "POST",
          body: JSON.stringify({
            name,
            price,
            moq: moq || 1,
            category,
            sizes,
            stockQty: newStock.stockQty,
            variantStock: newStock.variantStock,
            lowStockThreshold,
            description,
            images: image ? [image] : [],
          }),
        });

        btn.disabled = false;
        btn.textContent = "Submit for approval";

        if (!data.success) {
          errorEl.textContent = data.message || "Could not submit product.";
          errorEl.style.display = "block";
          return;
        }

        successEl.textContent = data.message || "Product submitted for approval.";
        successEl.style.display = "block";
        document.getElementById("pName").value = "";
        document.getElementById("pPrice").value = "";
        document.getElementById("pMoq").value = "";
        document.getElementById("pCategory").value = "";
        document.getElementById("pSizes").value = "";
        document.getElementById("pLowStockThreshold").value = 5;
        renderNewProductStockEditor();
        document.getElementById("pDescription").value = "";
        fileInput.value = "";
      }

      // ---------- Orders ----------
      async function loadOrders() {
        const { data } = await api("/api/seller/orders");
        if (!data.success) return;
        const list = document.getElementById("ordersList");
        const empty = document.getElementById("ordersEmpty");
        list.innerHTML = "";
        if (!data.orders.length) {
          empty.style.display = "block";
          return;
        }
        empty.style.display = "none";
        data.orders.forEach((o) => {
          const row = document.createElement("div");
          row.className = "order-row";
          const itemsText = (o.items || [])
            .map((it) => `${escapeHtml(it.name)}${it.size ? " (" + escapeHtml(it.size) + ")" : ""} × ${it.qty} — ₹${it.lineTotal}`)
            .join("<br>");
          const customerName = o.customer && o.customer.name ? o.customer.name : "—";
          const customerPhone = o.customer && o.customer.phone ? o.customer.phone : "—";
          const address = o.customer && o.customer.address ? o.customer.address : "";
          const ff = Array.isArray(o.sellerFulfilment) ? o.sellerFulfilment : [];
          const hasPending = ff.some(r => r.decision === "pending");
          const hasAccepted = ff.length && ff.every(r => r.decision === "accepted");
          const hasDeclined = ff.some(r => r.decision === "declined");
          const stage = ff.length ? (ff[0].stage || "Order Received") : "Order Received";
          const stageOptions = ["Processing","Ready to Ship","Shipped","Out for Delivery","Delivered"].map(st => `<option value="${st}" ${st===stage?'selected':''}>${st}</option>`).join("");
          row.innerHTML = `
            <div class="top-line">
              <span>${escapeHtml(o.orderNumber || "")}</span>
              <span class="order-status">${escapeHtml(stage)}</span>
            </div>
            <div class="item-line">${itemsText}</div>
            <div class="item-line">Your total: ₹${o.sellerTotal}</div>
            ${o.gift && o.gift.isGift ? `<div class="item-line" style="color:#8c6f7a;">🎁 Gift order${o.gift.hidePrice ? " — do not include a price slip" : ""}</div>` : ""}
            <div class="item-line" style="margin-top:6px;color:#8c6f7a;">👤 ${escapeHtml(customerName)} · ${escapeHtml(customerPhone)}</div>
            ${address ? `<div class="item-line" style="color:#8c6f7a;">📍 ${escapeHtml(address)}</div>` : ""}
            <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--line);">
              <div class="item-line"><strong>Seller decision:</strong> ${hasDeclined ? "Declined — awaiting admin takeover" : hasAccepted ? "Accepted" : "Pending"}</div>
              ${hasPending ? `<div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
                <button class="btn small" onclick="sellerDecision(${o.id}, 'accepted')">✓ Accept Order</button>
                <button class="btn small secondary" onclick="sellerDecision(${o.id}, 'declined')">✕ Decline</button>
              </div>` : ""}
              ${hasAccepted ? `<div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap;"><label class="item-line"><strong>Stage</strong></label><select class="checkout-input" style="width:auto;min-width:170px;padding:7px 10px;" onchange="sellerUpdateStage(${o.id}, this.value)">${stageOptions}</select></div>` : ""}
              ${hasDeclined ? `<div class="item-line" style="margin-top:7px;color:#b42318;">Design Makers admin has been notified and can take over fulfilment.</div>` : ""}
            </div>
          `;
          list.appendChild(row);
        });
      }

      async function sellerDecision(orderId, decision) {
        let reason = "";
        if (decision === "declined") { reason = prompt("Why are you declining this order?") || ""; if (!reason.trim()) return; }
        try { const { data } = await api(`/api/seller/orders/${orderId}/decision`, { method:"POST", body: JSON.stringify({ decision, reason }) }); if (!data.success) { alert(data.message || "Could not update the order."); return; } await loadOrders(); } catch (e) { alert("Could not update the order."); }
      }
      async function sellerUpdateStage(orderId, stage) {
        try { const { data } = await api(`/api/seller/orders/${orderId}/stage`, { method:"PUT", body: JSON.stringify({ stage }) }); if (!data.success) { alert(data.message || "Could not update the stage."); await loadOrders(); return; } await loadOrders(); } catch (e) { alert("Could not update the order stage."); }
      }
      let sellerOrdersPollTimer = null;
      function startSellerOrderLiveUpdates() { if (sellerOrdersPollTimer) clearInterval(sellerOrdersPollTimer); sellerOrdersPollTimer = setInterval(() => { const panel = document.getElementById("panel-orders"); if (panel && panel.style.display !== "none") loadOrders(); }, 5000); }
      startSellerOrderLiveUpdates();

      // ---------- Profile ----------
      async function loadProfile() {
        const { data } = await api("/api/seller/me");
        if (!data.success) return;
        const s = data.seller;
        document.getElementById("profileSellerId").value = s.sellerId;
        document.getElementById("profileName").value = s.name;
        document.getElementById("profilePhone").value = s.phone || "";
        document.getElementById("profileShopTitle").value = s.shopTitle || "";
      }

      async function submitProfileUpdate() {
        const errorEl = document.getElementById("profileError");
        const successEl = document.getElementById("profileSuccess");
        errorEl.style.display = "none";
        successEl.style.display = "none";

        const phone = document.getElementById("profilePhone").value.trim();
        const shopTitle = document.getElementById("profileShopTitle").value.trim();
        const fileInput = document.getElementById("profilePhoto");

        const btn = document.getElementById("profileSubmitBtn");
        btn.disabled = true;
        btn.textContent = "Submitting...";

        let photo = "";
        if (fileInput.files && fileInput.files[0]) {
          try {
            photo = await downscaleImage(fileInput.files[0], 800, 0.82);
          } catch (e) {
            errorEl.textContent = "Could not process the photo. Try a different image.";
            errorEl.style.display = "block";
            btn.disabled = false;
            btn.textContent = "Request update";
            return;
          }
        }

        const { data } = await api("/api/seller/profile-update-request", {
          method: "POST",
          body: JSON.stringify({ phone, shopTitle, photo }),
        });

        btn.disabled = false;
        btn.textContent = "Request update";

        if (!data.success) {
          errorEl.textContent = data.message || "Could not submit request.";
          errorEl.style.display = "block";
          return;
        }
        successEl.textContent = data.message || "Request submitted.";
        successEl.style.display = "block";
        document.getElementById("profilePendingNote").style.display = "block";
      }

      function escapeHtml(str) {
        return String(str || "").replace(/[&<>"']/g, (c) => ({
          "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
        }[c]));
      }

      // ---------- Boot ----------
      (async function boot() {
        // If the admin panel opened this page with "Log in as this seller",
        // the token arrives as ?impersonate=... — store it like a normal
        // login token, then strip it from the visible URL.
        const urlParams = new URLSearchParams(window.location.search);
        const impersonateToken = urlParams.get("impersonate");
        if (impersonateToken) {
          setToken(impersonateToken);
          window.history.replaceState({}, "", window.location.pathname);
        }

        const token = getToken();
        if (!token) return;
        const { data } = await api("/api/seller/me");
        if (data.success) {
          window.__dmSeller = data.seller;
          if (data.mustChangePassword) {
            // Seller left mid-flow last time (closed the tab, etc) without
            // setting their new password — pick up right where they left off.
            showMustChangeScreen("");
          } else {
            enterDashboard(data.seller);
          }
        } else {
          clearToken();
        }
      })();
    