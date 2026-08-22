
      let token = localStorage.getItem("dm_admin_token") || null;
      let role = localStorage.getItem("dm_admin_role") || null;
      let myUsername = localStorage.getItem("dm_admin_username") || null;
      let myCanDeleteProducts = false;
      let products = [];
      let orders = [];
      let admins = [];
      let editingId = null;
      let currentTab = "overview";
      let myDesignation = localStorage.getItem("dm_admin_designation") || null;
      let currentImages = [];
      let saleEndsAtMs = null; // base64 photo data for the product being edited

      // BUGFIX: showToast() is called from the inventory-copy, stock-import,
      // and callback-request-status handlers below but was never defined
      // anywhere in this file, so those confirmations silently did nothing.
      let adminToastTimer = null;
      function showToast(message) {
        let el = document.getElementById("dmAdminToast");
        if (!el) {
          el = document.createElement("div");
          el.id = "dmAdminToast";
          el.style.cssText = "position:fixed;left:50%;bottom:28px;transform:translateX(-50%);background:#2b2b2b;color:#fff;padding:11px 20px;border-radius:24px;font-size:0.88rem;box-shadow:0 4px 18px rgba(0,0,0,0.25);z-index:9999;opacity:0;transition:opacity .2s ease;max-width:90vw;text-align:center;";
          document.body.appendChild(el);
        }
        el.textContent = message;
        requestAnimationFrame(() => { el.style.opacity = "1"; });
        clearTimeout(adminToastTimer);
        adminToastTimer = setTimeout(() => { el.style.opacity = "0"; }, 2600);
      }

      // ---------- GLOBAL 401 HANDLER ----------
      // Every admin data call (products, orders, sellers, seller-applications,
      // overview, etc — 60+ call sites) sends the same Bearer token. Before
      // this fix, if that token ever went stale mid-session — the 2-device
      // concurrent-login limit evicting this session, JWT_SECRET changing
      // on a redeploy, or the 7-day expiry — every one of those calls would
      // just come back 401 and get silently swallowed by each function's own
      // catch block. The dashboard stayed visible but every tab sat empty
      // or half-loaded with no explanation — exactly "logged in, then blank/
      // broken". Wrapping fetch() once here means ANY /api/admin/* call that
      // comes back 401 immediately kicks the admin back to a visible login
      // screen with a clear reason, instead of a silent blank dashboard.
      (function installGlobal401Handler() {
        const nativeFetch = window.fetch.bind(window);
        window.fetch = async function (input, init) {
          const res = await nativeFetch(input, init);
          const url = typeof input === "string" ? input : (input && input.url) || "";
          const isAdminApiCall = url.startsWith("/api/admin/") && !url.endsWith("/api/admin/login");
          if (res.status === 401 && isAdminApiCall && token) {
            token = null;
            role = null;
            myUsername = null;
            localStorage.removeItem("dm_admin_token");
            localStorage.removeItem("dm_admin_role");
            localStorage.removeItem("dm_admin_username");
            localStorage.removeItem("dm_admin_designation");
            clearTimeout(sessionTimerId);
            clearInterval(sessionCountdownId);
            const overlay = document.getElementById("sessionPromptOverlay");
            if (overlay) overlay.style.display = "none";
            const dashboardEl = document.getElementById("dashboard");
            const loginScreenEl = document.getElementById("loginScreen");
            if (dashboardEl) dashboardEl.classList.add("hidden");
            if (loginScreenEl) loginScreenEl.classList.remove("hidden");
            const errorEl = document.getElementById("loginError");
            if (errorEl) {
              errorEl.textContent = "Your session ended (it expired, or the account was logged in on a 3rd device). Please log in again.";
            }
            setBubbleText("Design Makers");
          }
          return res;
        };
      })();

      // ---------- CENTRALIZED API HELPER (opt-in) ----------
      // admin.html's existing global fetch() patch above already handles
      // 401/session-expiry consistently across all 60+ call sites — that
      // part doesn't need touching. What it doesn't standardize is JSON
      // parsing and network-error handling, which each call site currently
      // does (or doesn't) on its own. This helper adds that consistently,
      // mirroring seller.html's api() wrapper, WITHOUT rewriting any
      // existing call site — it's available for new/updated admin code
      // going forward so those get the same reliability seller.html's
      // calls already have.
      async function apiAdmin(path, options = {}) {
        const headers = Object.assign(
          { "Content-Type": "application/json" },
          options.headers || {},
          token ? { Authorization: "Bearer " + token } : {},
        );
        try {
          const res = await fetch(path, Object.assign({}, options, { headers }));
          const data = await res.json().catch(() => ({ success: false, message: "Server error." }));
          return { ok: res.ok, status: res.status, data };
        } catch (err) {
          return { ok: false, status: 0, data: { success: false, message: "Network error — please check your connection and try again." } };
        }
      }

      // ---------- AUTH ----------

      async function login() {
        const username = document.getElementById("loginUsername").value.trim();
        const password = document.getElementById("loginPassword").value;
        const errorEl = document.getElementById("loginError");
        errorEl.textContent = "";

        if (!username || !password) {
          errorEl.textContent = "Enter username and password.";
          return;
        }

        try {
          const res = await fetch("/api/admin/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
          });
          const data = await res.json();

          if (!data.success) {
            errorEl.textContent = data.message || "Login failed.";
            triggerDmLoginReaction("error");
            return;
          }

          token = data.token;
          role = data.role || "admin";
          myUsername = String(data.username || username).trim();
          localStorage.setItem("dm_admin_token", token);
          localStorage.setItem("dm_admin_role", role);
          localStorage.setItem("dm_admin_username", myUsername);
          setBubbleText(myUsername);
          triggerDmLoginReaction("success", () => { showDashboard(); startSessionTimer(); });
        } catch (err) {
          errorEl.textContent = "Network error. Check your connection and try again.";
        }
      }

      // ---------- SESSION KEEP-ALIVE (10 min prompt, 10s to respond) ----------
      let sessionTimerId = null;
      let sessionCountdownId = null;

      function startSessionTimer() {
        clearTimeout(sessionTimerId);
        sessionTimerId = setTimeout(showSessionPrompt, 10 * 60 * 1000);
      }

      function showSessionPrompt() {
        const overlay = document.getElementById("sessionPromptOverlay");
        const countdownEl = document.getElementById("sessionPromptCountdown");
        let secondsLeft = 10;
        countdownEl.textContent = secondsLeft;
        overlay.style.display = "flex";

        clearInterval(sessionCountdownId);
        sessionCountdownId = setInterval(() => {
          secondsLeft -= 1;
          countdownEl.textContent = secondsLeft;
          if (secondsLeft <= 0) {
            clearInterval(sessionCountdownId);
            logout();
          }
        }, 1000);
      }

      // Called when the admin clicks "Yes, stay logged in" — hides the
      // prompt and restarts the 10-minute cycle.
      function staySessionAlive() {
        clearInterval(sessionCountdownId);
        document.getElementById("sessionPromptOverlay").style.display = "none";
        startSessionTimer();
      }

      function logout() {
        clearTimeout(sessionTimerId);
        clearInterval(sessionCountdownId);
        document.getElementById("sessionPromptOverlay").style.display = "none";

        // Best-effort: tell the server to free up this session slot so it
        // doesn't count against the 2-concurrent-login limit. Don't block
        // on it — logout should feel instant either way.
        if (token) {
          fetch("/api/admin/logout", {
            method: "POST",
            headers: { Authorization: "Bearer " + token },
          }).catch(() => {});
        }

        token = null;
        role = null;
        myUsername = null;
        localStorage.removeItem("dm_admin_token");
        localStorage.removeItem("dm_admin_role");
        localStorage.removeItem("dm_admin_username");
        localStorage.removeItem("dm_admin_designation");
        setBubbleText("Design Makers");
        document.getElementById("dashboard").classList.add("hidden");
        document.getElementById("loginScreen").classList.remove("hidden");
      }

      async function checkSession() {
        if (!token) return;
        try {
          const res = await fetch("/api/admin/me", {
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (data.success) {
            role = data.role || role;
            myDesignation = data.designation || myDesignation;
            myUsername = data.username ? String(data.username).trim() : myUsername;
            localStorage.setItem("dm_admin_role", role);
            if (myDesignation) localStorage.setItem("dm_admin_designation", myDesignation);
            if (myUsername) localStorage.setItem("dm_admin_username", myUsername);
            setBubbleText(myUsername || "Design Makers");
            showDashboard();
            startSessionTimer();
          } else {
            logout();
          }
        } catch (err) {
          logout();
        }
      }

      async function showDashboard() {
        document.getElementById("loginScreen").classList.add("hidden");
        document.getElementById("dashboard").classList.remove("hidden");
        document.getElementById("tabBtnAdmins").classList.toggle("hidden", role !== "boss");
        document.getElementById("tabBtnGiftcodes").classList.toggle("hidden", role !== "boss");
        document.getElementById("backupBtn").classList.toggle("hidden", role !== "boss");
        document.getElementById("newCategoryBtn").classList.toggle("hidden", role !== "boss");
        document.getElementById("seedCategoryProductsBtn").classList.toggle("hidden", role !== "boss");
        // Live Sellers used to be boss-only because it reveals real seller
        // identity (name/email/phone). It's now open to sub-admins too, so
        // they can edit seller details — a sub-admin's edit is just held
        // for boss approval instead of applying immediately (see the
        // "Pending Seller Detail Edits" card below, boss-only).
        document.getElementById("tabBtnSellerlist").classList.toggle("hidden", false);
        // The rest of "Approval for Seller" stays boss-only —
        // sub-admins keep that tab open, but only for the pending-products
        // list (which already shows shop name only, not real identity).
        document.getElementById("sellerInviteCard").classList.toggle("hidden", role !== "boss");
        document.getElementById("sellerAppsCard").classList.toggle("hidden", role !== "boss");
        document.getElementById("sellerPwCard").classList.toggle("hidden", role !== "boss");
        document.getElementById("sellerProfileReqCard").classList.toggle("hidden", role !== "boss");
        document.getElementById("pendingAdminEditsCard").classList.toggle("hidden", role !== "boss");
        document.getElementById("pendingSellerEditsCard").classList.toggle("hidden", role !== "boss");

        myCanDeleteProducts = role === "boss";
        try {
          const res = await fetch("/api/admin/me", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          if (data.success) {
            myCanDeleteProducts = !!data.canDeleteProducts;
            myDesignation = data.designation || myDesignation;
            if (myDesignation) localStorage.setItem("dm_admin_designation", myDesignation);
          }
        } catch (err) {
          // Keep the safe default set above if this fails.
        }

        loadProducts();
        loadSaleBanner();
        loadTheme();
        loadAdminNotifications();
        switchTab("overview");
      }

      // ---------- TABS ----------

      const DM_TAB_TITLES = {
        overview: ["Dashboard", "Overview & Stats"],
        products: ["Products", "Catalog & pricing"],
        inventory: ["Inventory", "Stock & Excel bulk updates"],
        orders: ["Orders", "Track & fulfil orders"],
        homepage: ["Homepage Sections", "Storefront highlights"],
        sellerlist: ["Live Sellers", "Approved sellers & their products"],
        sellers: ["Approval for Seller", "Review sellers & products"],
        customers: ["Customers", "Registered accounts"],
        admins: ["Admins", "Team access & roles"],
        giftcodes: ["Gift Codes", "Create and manage customer discounts"],
      };
      function dmToggleSidebar() {
        const shell = document.getElementById("dmShell");
        if (shell) shell.classList.toggle("dm-sidebar-open");
      }
      function switchTab(tab) {
        currentTab = tab;

        ["overview", "products", "inventory", "orders", "homepage", "sellerlist", "sellers", "customers", "admins", "giftcodes"].forEach((t) => {
          document.getElementById("tab" + capitalize(t)).classList.toggle("active", t === tab);
          document.getElementById("tabBtn" + capitalize(t)).classList.toggle("active", t === tab);
        });

        const titleInfo = DM_TAB_TITLES[tab];
        if (titleInfo) {
          const titleEl = document.getElementById("dmTopbarTitle");
          const subEl = document.getElementById("dmTopbarSub");
          if (titleEl) titleEl.textContent = titleInfo[0];
          if (subEl) subEl.textContent = titleInfo[1];
        }
        const shell = document.getElementById("dmShell");
        if (shell) shell.classList.remove("dm-sidebar-open");

        document.getElementById("addProductFab").classList.toggle("hidden", tab !== "products");

        if (tab === "overview") loadAdminOverview();
        if (tab === "inventory") loadInventory();
        if (tab === "orders" && !orders.length) loadOrders();
        if (tab === "homepage") {
          document.getElementById("homepageSectionsSaved").style.display = "none";
          loadHomepagePreview();
          loadHeroProductSettings();
        }
        if (tab === "sellerlist") loadSellerList();
        if (tab === "sellers") {
          if (role === "boss") {
            loadSellerApplications();
            loadSellerPasswordRequests();
            loadSellerProfileUpdateRequests();
            loadPendingAdminEdits();
            loadPendingSellerEdits();
          }
          loadPendingProducts();
        }
        if (tab === "customers") loadCustomers();
        if (tab === "admins") loadAdmins();
        if (tab === "giftcodes") loadGiftCodes();
      }

      function getDmGreeting() {
        const hour = new Date().getHours();
        if (hour >= 5 && hour < 12) return "Good morning";
        if (hour >= 12 && hour < 17) return "Good afternoon";
        return "Good evening";
      }
      function updateOverviewGreeting() {
        const el = document.getElementById("overviewGreeting");
        if (el) el.textContent = getDmGreeting();
      }

      // ---------- INVENTORY / EXCEL BULK STOCK ----------
      let inventoryRows = [];
      async function loadInventory() {
        const body = document.getElementById("inventoryTableBody");
        if (body) body.innerHTML = '<tr><td colspan="6" style="padding:20px;text-align:center;color:var(--muted);">Loading inventory…</td></tr>';
        const err = document.getElementById("inventoryError"); if (err) { err.textContent = ""; err.style.display = "none"; }
        try {
          const res = await fetch("/api/admin/inventory", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json(); if (!data.success) throw new Error(data.message || "Unable to load inventory.");
          inventoryRows = data.rows || []; renderInventory();
        } catch (e) { if (body) body.innerHTML = '<tr><td colspan="6" style="padding:20px;text-align:center;color:#a3002a;">Could not load inventory.</td></tr>'; if (err) { err.textContent = e.message || "Unable to load inventory."; err.style.display = "block"; } }
      }
      function inventoryStatus(row) {
        if (row.stockConfigured === false || row.currentStock === null) return { text: "Needs stock entry", cls: "status-new", icon: "⚪" };
        const n = Number(row.currentStock) || 0;
        if (n <= 0) return { text: "Out of Stock", cls: "status-cancelled", icon: "🔴" };
        if (n <= Number(row.lowStockThreshold || 5)) return { text: "Only " + n + " left", cls: "status-processing", icon: "🟡" };
        return { text: "In Stock", cls: "status-delivered", icon: "🟢" };
      }
      function renderInventory() {
        const body = document.getElementById("inventoryTableBody"); if (!body) return;
        const q = String(document.getElementById("inventorySearch")?.value || "").trim().toLowerCase();
        const rows = inventoryRows.filter(r => !q || String(r.productCode || "").toLowerCase().includes(q) || String(r.productName || "").toLowerCase().includes(q));
        const configured = inventoryRows.filter(r => r.stockConfigured !== false && r.currentStock !== null);
        const out = configured.filter(r => Number(r.currentStock) === 0).length;
        const low = configured.filter(r => Number(r.currentStock) > 0 && Number(r.currentStock) <= Number(r.lowStockThreshold || 5)).length;
        document.getElementById("inventoryStats").innerHTML = '<span class="badge status-delivered">🟢 ' + (configured.length - out - low) + ' In Stock</span> <span class="badge status-processing">🟡 ' + low + ' Low Stock</span> <span class="badge status-cancelled">🔴 ' + out + ' Out of Stock</span> <span class="badge gold">' + inventoryRows.length + ' Inventory Rows</span>';
        if (!rows.length) { body.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--muted);">No inventory rows found.</td></tr>'; return; }
        body.innerHTML = rows.map(r => { const st = inventoryStatus(r); return '<tr style="border-top:1px solid var(--line);"><td style="padding:12px 14px;font-weight:800;color:var(--rosewood);">' + escapeHtml(r.productCode || "—") + '</td><td style="padding:12px 14px;">' + escapeHtml(r.productName || "—") + '</td><td style="padding:12px 14px;">' + escapeHtml(r.variant || "Default") + '</td><td style="padding:12px 14px;font-weight:800;">' + (r.currentStock === null ? "—" : Number(r.currentStock).toLocaleString("en-IN")) + '</td><td style="padding:12px 14px;"><span class="badge ' + st.cls + '">' + st.icon + ' ' + escapeHtml(st.text) + '</span></td><td style="padding:12px 14px;">' + Number(r.lowStockThreshold || 5) + '</td></tr>'; }).join("");
      }
      function inventoryTsv() { const header=["Product ID","Product Name","Variant","Current Stock","New Stock","Low Stock Alert"]; const lines=inventoryRows.map(r=>[r.productCode,r.productName,r.variant||"",r.currentStock===null?"":r.currentStock,r.currentStock===null?"":r.currentStock,r.lowStockThreshold||5].map(v=>String(v??"").replace(/\t|\r?\n/g," ")).join("\t")); return [header.join("\t"),...lines].join("\n"); }
      async function copyInventoryForExcel() { const text=inventoryTsv(); try { await navigator.clipboard.writeText(text); } catch(e) { const ta=document.createElement("textarea");ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand("copy");ta.remove(); } showToast("Inventory copied — paste it directly into Excel."); }
      function downloadInventoryCsv() { const blob=new Blob(["\ufeff"+inventoryTsv()],{type:"text/tab-separated-values;charset=utf-8"}); const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="design-makers-inventory.tsv";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500); }
      let inventoryImportRows = [];
      let inventoryImportPreviewed = false;
      function openInventoryPaste(){
        document.getElementById("inventoryPasteOverlay").classList.add("open");
        document.getElementById("inventoryPasteText").value="";
        document.getElementById("inventoryPasteError").textContent="";
        document.getElementById("inventoryPastePreview").style.display="none";
        document.getElementById("inventoryPastePreview").innerHTML="";
        document.getElementById("inventoryPreviewBtn").textContent="Review Changes";
        inventoryImportRows=[];
        inventoryImportPreviewed=false;
      }
      function closeInventoryPaste(){document.getElementById("inventoryPasteOverlay").classList.remove("open");}
      function parseInventoryPaste(text){
        const lines=String(text||"").split(/\r?\n/).filter(line=>line.trim());
        if(lines.length<2)return[];
        const delim=lines[0].includes("\t")?"\t":",";
        const clean=v=>String(v||"").trim().replace(/^"|"$/g,"");
        const headers=lines[0].split(delim).map(clean).map(x=>x.toLowerCase());
        const codeIdx=headers.findIndex(x=>x==="product id"||x==="product code");
        const variantIdx=headers.findIndex(x=>x==="variant"||x==="size");
        const currentIdx=headers.findIndex(x=>x==="current stock"||x==="current");
        const newIdx=headers.findIndex(x=>x==="new stock"||x==="stock"||x==="quantity");
        if(codeIdx<0||newIdx<0)throw new Error("Excel must contain Product ID and New Stock columns.");
        return lines.slice(1).map(line=>{
          const cells=line.split(delim).map(clean);
          return {productCode:cells[codeIdx]||"",variant:variantIdx>=0?(cells[variantIdx]||""):"",currentStock:currentIdx>=0?(cells[currentIdx]||""):null,newStock:cells[newIdx]||""};
        }).filter(r=>r.productCode);
      }
      function renderInventoryImportPreview(preview, conflicts){
        const box=document.getElementById("inventoryPastePreview");
        if(!box)return;
        const rows=preview||[];
        const conflictKeys=new Set((conflicts||[]).map(r=>r.productCode+"::"+r.variant));
        box.style.display="block";
        box.innerHTML='<table style="width:100%;border-collapse:collapse;min-width:640px;font-size:12px;"><thead><tr style="background:var(--blush);text-align:left;">'+
          '<th style="padding:9px;">Product ID</th><th style="padding:9px;">Product</th><th style="padding:9px;">Size</th><th style="padding:9px;">Current</th><th style="padding:9px;">New</th><th style="padding:9px;">Check</th></tr></thead><tbody>'+
          rows.map(r=>{const conflict=conflictKeys.has(r.productCode+"::"+r.variant);return '<tr style="border-top:1px solid var(--line);background:'+(conflict?'#fff1f0':'transparent')+';">'+
            '<td style="padding:9px;font-weight:800;color:var(--rosewood);">'+escapeHtml(r.productCode)+'</td>'+
            '<td style="padding:9px;">'+escapeHtml(r.productName||"")+'</td>'+
            '<td style="padding:9px;">'+escapeHtml(r.variant||"Default")+'</td>'+
            '<td style="padding:9px;font-weight:700;">'+escapeHtml(String(r.currentStock))+'</td>'+
            '<td style="padding:9px;font-weight:900;">'+escapeHtml(String(r.newStock))+'</td>'+
            '<td style="padding:9px;font-weight:800;color:'+(conflict?'#b42318':'#1c7a34')+';">'+(conflict?'⚠ Stock changed':'✓ Ready')+'</td>'+
          '</tr>';}).join('')+'</tbody></table>';
      }
      async function importInventoryPaste(){
        const error=document.getElementById("inventoryPasteError");
        error.textContent="";
        try{
          if(!inventoryImportPreviewed){
            const rows=parseInventoryPaste(document.getElementById("inventoryPasteText").value);
            if(!rows.length)throw new Error("No valid rows found.");
            inventoryImportRows=rows;
            const res=await fetch("/api/admin/inventory/import",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token},body:JSON.stringify({rows,confirm:false})});
            const data=await res.json();
            if(!data.success)throw new Error(data.message||"Could not review inventory.");
            renderInventoryImportPreview(data.preview||[],data.conflicts||[]);
            if((data.conflicts||[]).length){
              error.textContent="Stock conflict found. Export the inventory again, then edit the fresh file before importing.";
              error.style.display="block";
              document.getElementById("inventoryPreviewBtn").textContent="Review Again";
              inventoryImportPreviewed=false;
              return;
            }
            error.style.display="none";
            document.getElementById("inventoryPreviewBtn").textContent="Confirm Stock Update";
            inventoryImportPreviewed=true;
            return;
          }

          const res=await fetch("/api/admin/inventory/import",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token},body:JSON.stringify({rows:inventoryImportRows,confirm:true})});
          const data=await res.json();
          if(!data.success){
            if(data.code==="INVENTORY_CONFLICT"){
              renderInventoryImportPreview(data.preview||[],data.conflicts||[]);
              error.textContent=data.message||"Stock changed. Export again and retry.";
              error.style.display="block";
              inventoryImportPreviewed=false;
              document.getElementById("inventoryPreviewBtn").textContent="Review Changes";
              return;
            }
            throw new Error(data.message||"Inventory update failed.");
          }
          closeInventoryPaste();
          await loadInventory();
          showToast((data.updates||[]).length+" stock row(s) updated successfully.");
        }catch(e){error.textContent=e.message||"Could not import stock.";error.style.display="block";}
      }

      // ---------- EXECUTIVE OVERVIEW ----------
      async function loadAdminOverview() {
        const ids = ["ovRevenue","ovOrders","ovCustomers","ovProducts","ovPending","ovSellers","ovRecentOrders","ovQueue","ovTopProducts","ovInventoryHealth"];
        ids.forEach((id) => { const el = document.getElementById(id); if (el && (id === "ovRecentOrders" || id === "ovQueue" || id === "ovTopProducts" || id === "ovInventoryHealth")) el.innerHTML = '<div class="dm-empty">Loading…</div>'; });
        const auth = { Authorization: "Bearer " + token };
        try {
          const [productsRes, ordersRes, customersRes, pendingRes, inventoryRes] = await Promise.all([
            fetch("/api/admin/products", { headers: auth }),
            fetch("/api/admin/orders", { headers: auth }),
            fetch("/api/admin/customers", { headers: auth }),
            fetch("/api/admin/products/pending", { headers: auth }),
            fetch("/api/admin/inventory", { headers: auth }),
          ]);
          const productsData = await productsRes.json();
          const ordersData = await ordersRes.json();
          const customersData = await customersRes.json();
          const pendingData = await pendingRes.json();
          const inventoryData = await inventoryRes.json();
          if (!productsData.success || !ordersData.success || !customersData.success) throw new Error("Could not load overview data");

          const ps = productsData.products || [];
          const os = ordersData.orders || [];
          const cs = customersData.customers || [];
          const pendingProducts = pendingData.success ? (pendingData.products || []) : [];
          const revenue = os.filter(o => o.status !== "Cancelled").reduce((sum,o) => sum + (Number(o.total)||0), 0);
          const liveProducts = ps.filter(p => p.approved !== false).length;

          document.getElementById("ovRevenue").textContent = fmtINR(revenue);
          document.getElementById("ovOrders").textContent = os.length.toLocaleString("en-IN");
          document.getElementById("ovCustomers").textContent = cs.length.toLocaleString("en-IN");
          document.getElementById("ovProducts").textContent = liveProducts.toLocaleString("en-IN");
          document.getElementById("ovProductsSub").textContent = liveProducts + " approved / " + ps.length + " total";
          document.getElementById("ovPending").textContent = pendingProducts.length.toLocaleString("en-IN");
          document.getElementById("overviewUserName").textContent = myUsername || "Admin";
          updateOverviewGreeting();
          const roleLabel = role === "boss" ? "Super Admin" : (myDesignation || "Sub-Admin");
          document.getElementById("overviewRoleText").textContent = (role === "boss" ? "Super Admin · full control" : (roleLabel + " · operational access"));

          // Sidebar + topbar profile mini-cards (same real data as the greeting above)
          const dmDisplayName = myUsername || "Admin";
          const dmInitials = dmDisplayName.trim().slice(0, 2).toUpperCase() || "DM";
          ["sidebarUserName","topbarUserName"].forEach((id) => { const el = document.getElementById(id); if (el) el.textContent = dmDisplayName; });
          ["sidebarUserRole","topbarUserRole"].forEach((id) => { const el = document.getElementById(id); if (el) el.textContent = roleLabel; });
          ["sidebarAvatar","topbarAvatar"].forEach((id) => { const el = document.getElementById(id); if (el) el.textContent = dmInitials; });

          if (role === "boss") {
            try {
              const sellersRes = await fetch("/api/admin/sellers", { headers: auth });
              const sellersData = await sellersRes.json();
              document.getElementById("ovSellers").textContent = sellersData.success ? (sellersData.sellers || []).length.toLocaleString("en-IN") : "—";
              document.getElementById("ovSellersSub").textContent = sellersData.success ? "Approved live sellers" : "Could not load";
            } catch(e) { document.getElementById("ovSellers").textContent = "—"; }
          } else {
            document.getElementById("ovSellers").textContent = "Restricted";
            document.getElementById("ovSellersSub").textContent = "Boss-only seller identity data";
          }

          const inventoryRows = inventoryData.success ? (inventoryData.rows || []) : [];
          const invConfigured = inventoryRows.filter(r => r.currentStock !== null);
          const invOut = invConfigured.filter(r => Number(r.currentStock) === 0);
          const invLow = invConfigured.filter(r => Number(r.currentStock) > 0 && Number(r.currentStock) <= Number(r.lowStockThreshold || 5));
          const invHealthy = invConfigured.length - invOut.length - invLow.length;
          const invNeedsEntry = inventoryRows.filter(r => r.currentStock === null);
          const invTopLow = invLow.slice().sort((a,b)=>Number(a.currentStock)-Number(b.currentStock)).slice(0,6);
          const invBox = document.getElementById("ovInventoryHealth");
          if (invBox) {
            invBox.innerHTML = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">' +
              '<span class="badge status-delivered">🟢 ' + invHealthy + ' In Stock</span>' +
              '<span class="badge status-processing">🟡 ' + invLow.length + ' Low Stock</span>' +
              '<span class="badge status-cancelled">🔴 ' + invOut.length + ' Out of Stock</span>' +
              (invNeedsEntry.length ? '<span class="badge status-new">⚪ ' + invNeedsEntry.length + ' Need Entry</span>' : '') +
            '</div>' +
            (invTopLow.length ? invTopLow.map(r => '<div style="display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid var(--line);"><span style="font-weight:700;">' + escapeHtml(r.productName) + (r.variant ? ' · ' + escapeHtml(r.variant) : '') + '</span><strong style="color:#b54708;">' + Number(r.currentStock) + ' left</strong></div>').join('') : '<div class="dm-empty">No low-stock items right now.</div>');
          }

          const recent = os.slice().sort((a,b)=>new Date(b.createdAt||0)-new Date(a.createdAt||0)).slice(0,6);
          document.getElementById("ovRecentOrders").innerHTML = recent.length ? recent.map(o => {
            const customer = o.customer && (o.customer.name || o.customer.phone) ? (o.customer.name || o.customer.phone) : "Customer";
            const statusClass = String(o.status||"").toLowerCase().replace(/[^a-z]/g,"");
            return `<div class="dm-order-row"><div class="dm-order-id">${escapeHtml(o.orderNumber || ("#" + o.id))}</div><div class="dm-order-customer">${escapeHtml(customer)}</div><div><span class="badge status status-${statusClass}">${escapeHtml(o.status || "New")}</span></div><div class="dm-order-amount">${fmtINR(o.total || 0)}</div></div>`;
          }).join("") : '<div class="dm-empty">No orders recorded yet.</div>';

          const queue = [];
          let dmBellTotal = pendingProducts.length;
          if (pendingProducts.length) queue.push({title:"Seller products",desc:pendingProducts.length+" product(s) waiting for approval",action:"Review in Seller Approvals",tab:"sellers"});
          if (role === "boss") {
            try {
              const appRes = await fetch("/api/admin/seller-applications", { headers: auth });
              const appData = await appRes.json();
              const pendingApps = appData.success ? (appData.applications||[]).filter(a => a.status === "pending") : [];
              if (pendingApps.length) { queue.push({title:"Seller applications",desc:pendingApps.length+" application(s) waiting for approval",action:"Review applications",tab:"sellers"}); dmBellTotal += pendingApps.length; }
            } catch(e) {}
          }
          document.getElementById("ovQueue").innerHTML = queue.length ? queue.map(q => `<div class="dm-queue-item"><div class="dm-queue-main"><strong>${escapeHtml(q.title)}</strong><span>${escapeHtml(q.desc)}</span></div><button class="dm-pill" onclick="switchTab('${q.tab}')">${escapeHtml(q.action)}</button></div>`).join("") : '<div class="dm-empty">Nothing urgent. You are all caught up. ✓</div>';

          const bellCountEl = document.getElementById("dmBellCount");
          if (bellCountEl) {
            bellCountEl.textContent = dmBellTotal > 99 ? "99+" : String(dmBellTotal);
            bellCountEl.classList.toggle("hidden", dmBellTotal === 0);
          }

          const productMap = new Map(ps.map(p => [p.id, p.name || "Unnamed product"]));
          const totals = {};
          os.forEach(o => (o.items||[]).forEach(it => { const key = it.productId; if (!totals[key]) totals[key] = {name: productMap.get(key) || it.name || "Product", qty:0, revenue:0}; totals[key].qty += Number(it.qty)||0; totals[key].revenue += Number(it.lineTotal)||0; }));
          const top = Object.values(totals).sort((a,b)=>b.qty-a.qty).slice(0,6);
          document.getElementById("ovTopProducts").innerHTML = top.length ? top.map((p,i) => `<div class="dm-queue-item"><div class="dm-queue-main"><strong>#${i+1} · ${escapeHtml(p.name)}</strong><span>${p.qty} unit(s) ordered</span></div><span class="dm-pill">${fmtINR(p.revenue)}</span></div>`).join("") : '<div class="dm-empty">No product sales data yet.</div>';

          // Order status + catalog health donuts — computed from the same real os/ps arrays above.
          const statusCounts = {};
          os.forEach(o => { const k = o.status || "New"; statusCounts[k] = (statusCounts[k] || 0) + 1; });
          dmRenderDonut("ovOrderDonut", "ovOrderDonutTotal", "ovOrderLegend", [
            { label: "Delivered", value: statusCounts["Delivered"] || 0, color: "#1f9d55" },
            { label: "Shipped", value: statusCounts["Shipped"] || 0, color: "#2f6fed" },
            { label: "Processing", value: statusCounts["Processing"] || 0, color: "#b8790a" },
            { label: "New", value: statusCounts["New"] || 0, color: "#8ab4ff" },
            { label: "Cancelled", value: statusCounts["Cancelled"] || 0, color: "#d6455a" },
          ]);
          dmRenderDonut("ovCatalogDonut", "ovCatalogDonutTotal", "ovCatalogLegend", [
            { label: "Approved", value: liveProducts, color: "#d4a24c" },
            { label: "Pending review", value: pendingProducts.length, color: "#c2660a" },
          ]);
        } catch (err) {
          document.getElementById("ovRecentOrders").innerHTML = '<div class="dm-empty">Could not load overview. <button class="btn small secondary" onclick="loadAdminOverview()">Retry</button></div>';
          document.getElementById("ovQueue").innerHTML = '<div class="dm-empty">Overview data unavailable.</div>';
          document.getElementById("ovTopProducts").innerHTML = '<div class="dm-empty">Overview data unavailable.</div>';
        }
      }

      // Pure-CSS conic-gradient donut, fed only by real counts — no fabricated data.
      function dmRenderDonut(wrapId, totalId, legendId, segments) {
        const wrap = document.getElementById(wrapId);
        const legend = document.getElementById(legendId);
        if (!wrap || !legend) return;
        const total = segments.reduce((s, x) => s + x.value, 0);
        const totalEl = document.getElementById(totalId);
        if (totalEl) totalEl.textContent = total.toLocaleString("en-IN");
        if (!total) {
          wrap.style.background = "conic-gradient(var(--line) 0deg 360deg)";
          legend.innerHTML = '<div class="dm-empty" style="padding:6px 0;">No data yet.</div>';
          return;
        }
        let angle = 0;
        const stops = segments.filter(s => s.value > 0).map((s) => {
          const start = angle;
          angle += (s.value / total) * 360;
          return s.color + " " + start.toFixed(1) + "deg " + angle.toFixed(1) + "deg";
        }).join(", ");
        wrap.style.background = "conic-gradient(" + stops + ")";
        legend.innerHTML = segments.map((s) => `<div class="dm-legend-row"><span class="dm-legend-dot" style="background:${s.color}"></span><span class="dm-legend-label">${escapeHtml(s.label)}</span><span class="dm-legend-value">${s.value}</span></div>`).join("");
      }

      async function loadHeroProductSettings() {
        const select = document.getElementById("heroProductSelect");
        if (!select) return;
        try {
          const [settingsRes, productsRes] = await Promise.all([
            fetch("/api/settings"),
            fetch("/api/admin/products", { headers: { Authorization: "Bearer " + token } }),
          ]);
          const settingsData = await settingsRes.json();
          const productsData = await productsRes.json();
          const ps = productsData.success ? (productsData.products || []).filter(p => p.active !== false && p.approved !== false) : [];
          const heroId = settingsData.success ? settingsData.settings.heroProductId : null;
          select.innerHTML = '<option value="">No hero product selected</option>' + ps.map(p => '<option value="'+p.id+'">'+escapeHtml(p.name || "Unnamed product")+' · ₹'+fmtINR(p.price || 0)+'</option>').join("");
          select.value = heroId == null ? "" : String(heroId);
          updateHeroProductPreview();
        } catch (e) {
          select.innerHTML = '<option value="">Could not load products</option>';
        }
      }

      function updateHeroProductPreview() {
        const select = document.getElementById("heroProductSelect");
        const preview = document.getElementById("heroProductPreview");
        if (!select || !preview) return;
        const id = Number(select.value);
        const product = products.find(p => Number(p.id) === id);
        if (product && product.image) preview.innerHTML = '<img src="'+escapeHtml(product.image)+'" alt="'+escapeHtml(product.name || "Hero product")+'">';
        else preview.innerHTML = '<span style="color:var(--muted);font-size:12px;">Select a product to preview</span>';
      }

      async function saveHeroProduct() {
        const select = document.getElementById("heroProductSelect");
        const status = document.getElementById("heroProductStatus");
        const productId = select.value ? Number(select.value) : null;
        updateHeroProductPreview();
        status.style.color = "#e8b84b";
        status.textContent = "Saving…";
        try {
          const res = await fetch("/api/admin/settings/hero-product", { method:"PUT", headers:{"Content-Type":"application/json", Authorization:"Bearer "+token}, body:JSON.stringify({productId}) });
          const data = await res.json();
          if (!data.success) throw new Error(data.message || "Unable to save");
          status.style.color = "#63e6b1";
          status.textContent = "✓ Hero product updated. Changes are live on the storefront.";
        } catch (e) {
          status.style.color = "#ff8f9a";
          status.textContent = e.message || "Unable to save hero product.";
        }
      }

      // ---------- HOMEPAGE SECTIONS (Most Popular / Trending) — AUTOMATIC ----------
      // Membership in each row is computed server-side from real order data.
      // This tab is a live, read-only preview of that computation, plus
      // still-editable MOQ / "BUY 10 @" discount % per product.
      let homepagePreview = { popular: [], trending: [] };

      async function loadHomepagePreview() {
        const popularEl = document.getElementById("popularPreview");
        const trendingEl = document.getElementById("trendingPreview");
        popularEl.innerHTML = '<p class="empty-state" style="margin:0;">Loading…</p>';
        trendingEl.innerHTML = '<p class="empty-state" style="margin:0;">Loading…</p>';

        try {
          const res = await fetch("/api/admin/homepage-preview", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          if (!data.success) {
            popularEl.innerHTML = trendingEl.innerHTML = '<p class="empty-state" style="margin:0;">Could not load preview.</p>';
            return;
          }
          homepagePreview = { popular: data.popular, trending: data.trending };
          renderHomepagePreviewSection("popular");
          renderHomepagePreviewSection("trending");
        } catch (err) {
          popularEl.innerHTML = trendingEl.innerHTML = '<p class="empty-state" style="margin:0;">Network error. Try again.</p>';
        }
      }

      function renderHomepagePreviewSection(section) {
        const listEl = document.getElementById(section + "Preview");
        const items = homepagePreview[section] || [];

        if (!items.length) {
          listEl.innerHTML = '<p class="empty-state" style="margin:0;">No active products yet.</p>';
          return;
        }

        listEl.innerHTML = items
          .map((p) => {
            const thumb = p.image
              ? '<img src="' + escapeHtml(p.image) + '" style="width:40px;height:40px;border-radius:8px;object-fit:cover;flex-shrink:0;" />'
              : '<div style="width:40px;height:40px;border-radius:8px;background:var(--blush);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;">🎁</div>';
            const pill = p.isNewest
              ? '<span style="flex-shrink:0;font-size:11px;font-weight:600;padding:3px 8px;border-radius:10px;background:#eee;color:var(--muted);">🆕 Newest</span>'
              : '<span style="flex-shrink:0;font-size:11px;font-weight:600;padding:3px 8px;border-radius:10px;background:var(--warn-bg);color:var(--warn);">👁 ' + p.viewCount + ' view' + (p.viewCount === 1 ? '' : 's') + '</span>';
            return (
              '<div style="display:flex;align-items:center;gap:10px;padding:6px 4px;border-bottom:1px solid var(--border);">' +
                thumb +
                '<span style="flex:1;font-size:14px;">' + escapeHtml(p.name) + '<span style="color:var(--muted);font-size:12px;"> — ' + escapeHtml(p.category || "") + '</span></span>' +
                pill +
                '<span style="flex-shrink:0;display:flex;align-items:center;gap:4px;font-size:12px;color:var(--muted);" title="Minimum order quantity for this product">MOQ ' +
                  '<input type="number" class="hp-moq" data-id="' + p.id + '" min="1" value="' + (p.moq || 1) + '" style="width:44px;padding:4px;text-align:center;" oninput="syncRowField(this, \'hp-moq\')" />' +
                '</span>' +
                '<span style="flex-shrink:0;display:flex;align-items:center;gap:4px;font-size:12px;color:var(--muted);" title="Discount used in this product\'s \u201cBUY 10 @\u2026\u201d badge">' +
                  '<input type="number" class="hp-badge-percent" data-id="' + p.id + '" min="1" max="90" value="' + (p.buyBadgePercent || 10) + '" style="width:44px;padding:4px;text-align:center;" oninput="syncRowField(this, \'hp-badge-percent\')" />%' +
                '</span>' +
              '</div>'
            );
          })
          .join("");
      }

      // Same product can appear in both the Popular and Trending previews —
      // keep its MOQ / "BUY 10 @" discount % in sync wherever it's edited,
      // so Save always sends one consistent value per product.
      function syncRowField(inputEl, cls) {
        const id = inputEl.dataset.id;
        const value = inputEl.value;
        document.querySelectorAll('.' + cls + '[data-id="' + id + '"]').forEach((el) => {
          if (el !== inputEl) el.value = value;
        });
      }

      async function saveHomepageSections() {
        const errorEl = document.getElementById("homepageSectionsError");
        const savedEl = document.getElementById("homepageSectionsSaved");
        errorEl.textContent = "";
        savedEl.style.display = "none";

        // One value per product, deduped across the Popular/Trending previews
        // (syncRowField keeps duplicates equal as the admin types, so any
        // copy here is fine — we just need one value per id).
        const buyBadgePercents = {};
        document.querySelectorAll(".hp-badge-percent").forEach((el) => {
          const percent = Number(el.value);
          if (Number.isFinite(percent) && percent > 0) buyBadgePercents[el.dataset.id] = percent;
        });

        const moqs = {};
        document.querySelectorAll(".hp-moq").forEach((el) => {
          const moq = Number(el.value);
          if (Number.isFinite(moq) && moq >= 1) moqs[el.dataset.id] = moq;
        });

        try {
          const res = await fetch("/api/admin/products/homepage-sections", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ buyBadgePercents, moqs }),
          });
          const data = await res.json();
          if (!data.success) {
            errorEl.textContent = data.message || "Could not save.";
            return;
          }
          products = data.products;
          savedEl.style.display = "block";
          loadHomepagePreview();
        } catch (err) {
          errorEl.textContent = "Network error. Try again.";
        }
      }

      function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

      // Indian rupee formatting: ₹ + lakh/crore comma grouping (e.g. 1,24,500).
      function fmtINR(n) {
        const num = Math.round(Number(n) || 0);
        return "₹" + num.toLocaleString("en-IN");
      }

      // ---------- SELLERS TAB — applications + pending products ----------

      // ---------- CUSTOMERS (mobile + password accounts) ----------
      // Renders a simple "‹ Prev  page X of Y  Next ›" pager into targetEl,
      // calling loadFn(page) on click. Shared between customers and orders
      // since both lists are now server-paginated.
      function renderPager(targetEl, meta, loadFn) {
        if (!meta || meta.pages <= 1) {
          targetEl.innerHTML = "";
          return;
        }
        targetEl.innerHTML =
          '<button class="btn small secondary" ' + (meta.page <= 1 ? "disabled" : "") + ' id="pagerPrev">‹ Prev</button>' +
          '<span style="font-size:13px;color:var(--muted);">Page ' + meta.page + ' of ' + meta.pages + ' (' + meta.total + ' total)</span>' +
          '<button class="btn small secondary" ' + (meta.page >= meta.pages ? "disabled" : "") + ' id="pagerNext">Next ›</button>';
        const prevBtn = targetEl.querySelector("#pagerPrev");
        const nextBtn = targetEl.querySelector("#pagerNext");
        if (prevBtn) prevBtn.onclick = () => loadFn(meta.page - 1);
        if (nextBtn) nextBtn.onclick = () => loadFn(meta.page + 1);
      }

      // ---------- DIRECTORY EXPORTS ----------
      let exportTargetKind = null;
      let exportTargetFormat = null;
      let exportOtpRequestId = null;

      function openExportChooser(kind) {
        exportTargetKind = kind;
        exportTargetFormat = null;
        exportOtpRequestId = null;
        document.getElementById("exportFormatChoices").style.display = "grid";
        document.getElementById("exportOtpStep").style.display = "none";
        document.getElementById("exportOtpInput").value = "";
        document.getElementById("exportOtpError").textContent = "";
        document.getElementById("exportChooserText").textContent = kind === "customers"
          ? "Choose Excel or PDF for the customer directory."
          : "Choose Excel or PDF for the live seller directory.";
        document.getElementById("exportChooserOverlay").style.display = "block";
      }

      function closeExportChooser() {
        document.getElementById("exportChooserOverlay").style.display = "none";
        exportTargetKind = null;
        exportTargetFormat = null;
        exportOtpRequestId = null;
      }

      async function startDirectoryExport(format) {
        if (!exportTargetKind) return;
        exportTargetFormat = format;
        if (role === "boss") {
          await performDirectoryExport(format);
          return;
        }
        try {
          const res = await fetch("/api/admin/export/request-otp", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ kind: exportTargetKind, format }),
          });
          const data = await res.json();
          if (!res.ok || !data.success) {
            alert(data.message || "Could not send the verification code.");
            return;
          }
          exportOtpRequestId = data.requestId;
          document.getElementById("exportFormatChoices").style.display = "none";
          document.getElementById("exportOtpStep").style.display = "block";
          document.getElementById("exportOtpEmailHint").textContent = "We sent a 6-digit OTP to " + (data.emailMasked || "your registered email") + ". It expires in 10 minutes.";
          document.getElementById("exportOtpInput").focus();
        } catch (err) {
          alert("Could not start export verification. Please try again.");
        }
      }

      async function verifyDirectoryExportOtp() {
        const otp = document.getElementById("exportOtpInput").value.trim();
        const errorEl = document.getElementById("exportOtpError");
        errorEl.textContent = "";
        if (!/^\d{6}$/.test(otp)) {
          errorEl.textContent = "Enter the 6-digit OTP.";
          return;
        }
        try {
          const res = await fetch("/api/admin/export/verify-otp", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ requestId: exportOtpRequestId, otp }),
          });
          const data = await res.json();
          if (!res.ok || !data.success) {
            errorEl.textContent = data.message || "Invalid or expired OTP.";
            return;
          }
          await performDirectoryExport(exportTargetFormat, data.exportGrant);
        } catch (err) {
          errorEl.textContent = "Verification failed. Please try again.";
        }
      }

      async function fetchExportRows(kind, exportGrant) {
        const endpoint = kind === "customers" ? "/api/admin/customers/export" : "/api/admin/sellers/export";
        const headers = { Authorization: "Bearer " + token };
        if (exportGrant) headers["X-Export-Grant"] = exportGrant;
        const res = await fetch(endpoint, { headers, cache: "no-store" });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || "Export data unavailable");
        return kind === "customers" ? (data.customers || []) : (data.sellers || []);
      }

      function downloadXlsx(rows, headers, filename, sheetName) {
        if (!window.XLSX) throw new Error("Excel export library did not load.");
        const ws = XLSX.utils.json_to_sheet(rows, { header: headers });
        ws['!cols'] = headers.map((h) => ({ wch: Math.min(42, Math.max(14, h.length + 5)) }));
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, sheetName || "Export");
        XLSX.writeFile(wb, filename);
      }

      function downloadPdf(rows, headers, title, filename) {
        const jsPDF = window.jspdf && window.jspdf.jsPDF;
        if (!jsPDF) throw new Error("PDF export library did not load.");
        const doc = new jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });
        doc.setFontSize(16);
        doc.text(title, 40, 40);
        doc.setFontSize(9);
        doc.text("Generated: " + new Date().toLocaleString(), 40, 56);
        doc.autoTable({
          head: [headers],
          body: rows.map((r) => headers.map((h) => r[h] == null ? "" : String(r[h]))),
          startY: 70,
          margin: { left: 40, right: 40 },
          styles: { fontSize: 9, cellPadding: 5, overflow: "linebreak" },
          headStyles: { fillColor: [92, 55, 43], textColor: 255 },
          alternateRowStyles: { fillColor: [250, 244, 240] },
        });
        doc.save(filename);
      }

      async function performDirectoryExport(format, exportGrant) {
        try {
          const rows = await fetchExportRows(exportTargetKind, exportGrant);
          if (exportTargetKind === "customers") {
            const headers = ["Name", "City", "Email", "Mobile Number"];
            const normalized = rows.map((r) => ({
              "Name": r.name || "",
              "City": r.city || "",
              "Email": r.email || "",
              "Mobile Number": r.mobile || "",
            }));
            if (format === "xlsx") downloadXlsx(normalized, headers, "design-makers-customers.xlsx", "Customers");
            else downloadPdf(normalized, headers, "Design Makers - Customers", "design-makers-customers.pdf");
          } else {
            const headers = ["Company Name", "Name", "City", "Mobile Number", "Email"];
            const normalized = rows.map((r) => ({
              "Company Name": r.companyName || "",
              "Name": r.name || "",
              "City": r.city || "",
              "Mobile Number": r.mobile || "",
              "Email": r.email || "",
            }));
            if (format === "xlsx") downloadXlsx(normalized, headers, "design-makers-live-sellers.xlsx", "Live Sellers");
            else downloadPdf(normalized, headers, "Design Makers - Live Sellers", "design-makers-live-sellers.pdf");
          }
          closeExportChooser();
        } catch (err) {
          alert("Export failed: " + (err.message || "Unknown error"));
        }
      }

      async function loadCustomers(page) {
        page = page || 1;
        const loadingEl = document.getElementById("customersLoading");
        const listEl = document.getElementById("customersList");
        const pagerEl = document.getElementById("customersPager");
        loadingEl.classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/customers?page=" + page + "&limit=50", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          loadingEl.classList.add("hidden");
          if (!data.success || !data.customers.length) {
            listEl.innerHTML = '<p class="empty-state">No customer accounts yet.</p>';
            pagerEl.innerHTML = "";
            return;
          }
          renderPager(pagerEl, data, loadCustomers);
          listEl.innerHTML = data.customers.map((c) => {
            const mobileText = c.mobile ? escapeHtml(c.mobile) : '<span style="color:var(--danger);">no mobile (legacy)</span>';
            const orderTag = c.orderCount ? ' · ' + c.orderCount + ' order' + (c.orderCount === 1 ? '' : 's') : '';
            return (
            '<div class="card" id="customerRow' + c.id + '" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap;">' +
              '<div><strong>' + escapeHtml(c.name || "—") + '</strong><br>' +
                '<span style="font-size:13px;color:var(--muted);">' + mobileText + orderTag + '</span></div>' +
              '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">' +
                '<span id="customerNewPw' + c.id + '" style="font-size:13px;color:var(--success);"></span>' +
                '<button class="btn small" onclick="openCustomerDetails(' + c.id + ')">View details</button>' +
                '<button class="btn small secondary" onclick="resetCustomerPassword(' + c.id + ')">Reset password</button>' +
                '<button class="btn small danger" onclick="deleteCustomer(' + c.id + ', \'' + escapeHtml(c.name || "").replace(/'/g, "\\'") + '\')">Delete</button>' +
              '</div>' +
            '</div>'
            );
          }).join("");
        } catch (err) {
          loadingEl.classList.add("hidden");
          listEl.innerHTML = '<p class="empty-state">Network error loading customers.</p>';
        }
      }

      // ---------- ADMIN NOTIFICATIONS / CALLBACK REQUESTS ----------
      let adminNotificationRequests = [];
      let adminNotificationsLoaded = false;

      async function loadAdminNotifications() {
        if (!token) return;
        try {
          const res = await fetch("/api/admin/callback-requests", { headers: { Authorization: "Bearer " + token }, cache: "no-store" });
          const data = await res.json();
          if (!data.success) return;
          adminNotificationRequests = data.requests || [];
          adminNotificationsLoaded = true;
          updateAdminNotificationBadge(Number(data.unreadCount || 0));
          renderAdminNotifications();
        } catch (err) {
          const list = document.getElementById("dmNotificationList");
          if (list) list.innerHTML = '<div class="dm-notification-empty">Could not load notifications.</div>';
        }
      }

      function updateAdminNotificationBadge(count) {
        const badge = document.getElementById("dmCallbackBellCount");
        if (!badge) return;
        const n = Number(count || 0);
        badge.textContent = n > 99 ? "99+" : String(n);
        badge.classList.toggle("hidden", n <= 0);
      }

      function toggleAdminNotifications(event) {
        if (event) event.stopPropagation();
        const panel = document.getElementById("dmNotificationPanel");
        if (!panel) return;
        const willOpen = !panel.classList.contains("open");
        panel.classList.toggle("open", willOpen);
        if (willOpen) loadAdminNotifications();
      }

      function renderAdminNotifications() {
        const list = document.getElementById("dmNotificationList");
        if (!list) return;
        const username = String(myUsername || "");
        if (!adminNotificationRequests.length) {
          list.innerHTML = '<div class="dm-notification-empty">No callback requests yet.</div>';
          return;
        }
        list.innerHTML = adminNotificationRequests.map((r) => {
          const read = Array.isArray(r.readBy) && r.readBy.includes(username);
          const when = r.createdAt ? new Date(r.createdAt).toLocaleString("en-IN", { day:"numeric", month:"short", hour:"2-digit", minute:"2-digit" }) : "—";
          const order = r.orderNumber ? '<div style="font-size:11.5px;color:var(--rosewood);font-weight:800;margin-top:4px;">Order: '+escapeHtml(r.orderNumber)+'</div>' : '<div style="font-size:11.5px;color:var(--muted);margin-top:4px;">General enquiry</div>';
          return '<div class="dm-notification-item '+(read?'':'unread')+'" onclick="openAdminCallbackRequest('+Number(r.id)+')">'+
            '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;"><strong>Callback request</strong><span style="font-size:10.5px;color:var(--muted);">'+escapeHtml(when)+'</span></div>'+
            '<div style="font-size:12px;margin-top:4px;">'+escapeHtml(r.name || "Customer")+'</div>'+order+
            '<div style="font-size:12px;color:var(--muted);margin-top:7px;line-height:1.4;">'+escapeHtml(r.reason || "")+'</div>'+
            '<div style="margin-top:8px;font-size:10.5px;font-weight:800;color:'+(r.status==="Completed"?'#1c7a34':r.status==="Cancelled"?'#b42318':'#9a5b00')+';">'+escapeHtml(r.status || "New")+'</div>'+
          '</div>';
        }).join("");
      }

      async function openAdminCallbackRequest(id) {
        const req = adminNotificationRequests.find((r) => Number(r.id) === Number(id));
        if (!req) return;
        try {
          await fetch("/api/admin/callback-requests/" + encodeURIComponent(id) + "/read", { method:"PUT", headers:{ Authorization:"Bearer "+token, "Content-Type":"application/json" } });
          req.readBy = Array.isArray(req.readBy) ? req.readBy : [];
          if (myUsername && !req.readBy.includes(myUsername)) req.readBy.push(myUsername);
          updateAdminNotificationBadge(adminNotificationRequests.filter(r => !(Array.isArray(r.readBy) && r.readBy.includes(myUsername))).length);
        } catch (_) {}
        const phone = req.phone ? '<div style="margin-top:8px;font-weight:700;">Customer phone: '+escapeHtml(req.phone)+'</div>' : '';
        const order = req.orderNumber ? '<div style="margin-top:8px;font-weight:700;">Order ID: '+escapeHtml(req.orderNumber)+'</div>' : '<div style="margin-top:8px;color:var(--muted);">General enquiry</div>';
        const status = ['New','Contacted','Completed','Cancelled'].map(x => '<option value="'+x+'" '+(req.status===x?'selected':'')+'>'+x+'</option>').join('');
        const panel = document.getElementById("dmNotificationPanel");
        if (panel) {
          panel.innerHTML = '<div class="dm-notification-head"><strong>Callback Request</strong><button class="btn small secondary" type="button" onclick="loadAdminNotifications()">← Back</button></div>' +
            '<div style="padding:10px 4px;font-size:12.5px;line-height:1.5;">' +
            '<div><strong>'+escapeHtml(req.name||"Customer")+'</strong></div>' + phone + order +
            '<div style="margin-top:12px;padding:10px;border-radius:10px;background:var(--field);"><strong>Reason</strong><div style="margin-top:4px;white-space:pre-wrap;">'+escapeHtml(req.reason||"")+'</div></div>' +
            '<div style="margin-top:12px;"><label style="font-size:11px;color:var(--muted);font-weight:800;">Status</label><select id="adminCallbackStatus" class="checkout-input" style="width:100%;margin-top:4px;">'+status+'</select></div>' +
            '<button class="btn small" style="margin-top:10px;width:100%;" onclick="updateAdminCallbackStatus('+Number(req.id)+')">Save Status</button>' +
            '</div>';
        }
      }

      async function updateAdminCallbackStatus(id) {
        const select = document.getElementById("adminCallbackStatus");
        const status = select ? select.value : "";
        try {
          const res = await fetch("/api/admin/callback-requests/" + encodeURIComponent(id) + "/status", { method:"PUT", headers:{ Authorization:"Bearer "+token, "Content-Type":"application/json" }, body:JSON.stringify({status}) });
          const data = await res.json();
          if (!data.success) throw new Error(data.message || "Unable to update callback request.");
          await loadAdminNotifications();
          showToast("Callback request updated.");
        } catch (e) { showToast(e.message || "Unable to update callback request."); }
      }

      document.addEventListener("click", function(e){
        const wrap=document.getElementById("dmNotificationWrap"), panel=document.getElementById("dmNotificationPanel");
        if(wrap && panel && panel.classList.contains("open") && !wrap.contains(e.target)) panel.classList.remove("open");
      });

      setInterval(() => { if (token) loadAdminNotifications(); }, 30000);

      async function openCustomerDetails(id) {
        const overlay = document.getElementById("customerDetailOverlay");
        const body = document.getElementById("customerDetailBody");
        body.innerHTML = '<p class="empty-state" style="margin:0;">Loading…</p>';
        overlay.style.display = "flex";
        try {
          const res = await fetch("/api/admin/customers/" + id, { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          if (!data.success) {
            body.innerHTML = '<p class="empty-state">' + escapeHtml(data.message || "Could not load customer.") + '</p>';
            return;
          }
          const c = data.customer;
          const joined = c.createdAt ? new Date(c.createdAt).toLocaleString("en-IN", { day: "numeric", month: "short", year: "numeric" }) : "—";
          const ordersHtml = (c.orders && c.orders.length)
            ? c.orders.map((o) => {
                const items = o.items.map((it) => escapeHtml(it.name) + (it.size ? " (" + escapeHtml(it.size) + ")" : "") + " × " + it.qty).join(", ");
                const cancelled = o.status === "Cancelled";
                return (
                  '<div style="border-bottom:1px solid #3d2b32;padding:8px 0;">' +
                    '<div style="display:flex;justify-content:space-between;gap:10px;">' +
                      '<strong>' + escapeHtml(o.orderNumber) + '</strong>' +
                      '<span style="' + (cancelled ? "text-decoration:line-through;color:var(--muted);" : "") + '">' + fmtINR(o.total || 0) + '</span>' +
                    '</div>' +
                    '<div style="font-size:12px;color:var(--muted);">' + escapeHtml(o.status || "") + ' · ' + items + '</div>' +
                  '</div>'
                );
              }).join("")
            : '<p style="color:var(--muted);font-size:13px;margin:0;">No orders yet.</p>';

          body.innerHTML =
            '<div style="margin-bottom:14px;">' +
              '<div style="font-size:20px;font-weight:700;">' + escapeHtml(c.name || "—") + '</div>' +
              '<div style="color:var(--muted);">' + (c.mobile ? escapeHtml(c.mobile) : '<span style="color:var(--danger);">no mobile (legacy account)</span>') + '</div>' +
            '</div>' +
            '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;">' +
              '<div class="stat-card" style="flex:1;min-width:120px;"><div class="stat-label">Orders</div><div class="stat-value">' + (c.orders ? c.orders.length : 0) + '</div></div>' +
              '<div class="stat-card" style="flex:1;min-width:120px;"><div class="stat-label">Spent (excl. cancelled)</div><div class="stat-value">' + fmtINR(c.totalSpent || 0) + '</div></div>' +
              '<div class="stat-card" style="flex:1;min-width:120px;"><div class="stat-label">Joined</div><div class="stat-value" style="font-size:15px;">' + joined + '</div></div>' +
            '</div>' +
            '<h4 style="margin:0 0 8px;color: var(--gold-soft);">Order history</h4>' +
            '<div>' + ordersHtml + '</div>';
        } catch (err) {
          body.innerHTML = '<p class="empty-state">Network error loading customer.</p>';
        }
      }

      function closeCustomerDetails() {
        document.getElementById("customerDetailOverlay").style.display = "none";
      }

      async function deleteCustomer(id, name) {
        if (!confirm('Delete the account for "' + (name || "this customer") + '"?\n\nThis permanently removes their login. This cannot be undone.')) return;
        try {
          const res = await fetch("/api/admin/customers/" + id, {
            method: "DELETE",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (!data.success) {
            alert(data.message || "Could not delete customer.");
            return;
          }
          loadCustomers();
        } catch (err) {
          alert("Network error. Please try again.");
        }
      }

      async function resetCustomerPassword(id) {
        if (!confirm("Generate a new password for this customer? Their old password will stop working.")) return;
        try {
          const res = await fetch("/api/admin/customers/" + id + "/reset-password", {
            method: "POST",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          const label = document.getElementById("customerNewPw" + id);
          if (!data.success) {
            alert(data.message || "Could not reset password.");
            return;
          }
          if (label) {
            label.textContent = "New password: " + data.newPassword + " (copy it now)";
          }
        } catch (err) {
          alert("Network error. Please try again.");
        }
      }

      // ---------- SELLER LIST (approved sellers + their products) ----------
      let sellerListData = [];

      async function loadSellerList() {
        const loadingEl = document.getElementById("sellerListLoading");
        const listEl = document.getElementById("sellerListContainer");
        loadingEl.classList.remove("hidden");
        // Make sure the global products array is loaded so inline "Edit" works.
        if (!products.length) {
          try { await loadProducts(); } catch (e) {}
        }
        try {
          const res = await fetch("/api/admin/sellers", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          loadingEl.classList.add("hidden");
          if (!data.success || !data.sellers.length) {
            listEl.innerHTML = '<p class="empty-state">No live sellers yet. Approve applications in the "Approval for Seller" tab.</p>';
            return;
          }
          sellerListData = data.sellers;
          listEl.innerHTML = data.sellers.map((s) => {
            // Seller List shows approved products only — pending ones are handled
            // in the Seller Approvals tab.
            const approvedProducts = s.products.filter((p) => p.approved);
            const productsHtml = approvedProducts.length
              ? approvedProducts.map((p) => (
                  '<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--blush-line);">' +
                    (p.image ? '<img src="' + escapeHtml(p.image) + '" style="width:44px;height:44px;border-radius:8px;object-fit:cover;" />' : '<div style="width:44px;height:44px;border-radius:8px;background:var(--blush);"></div>') +
                    '<div style="flex:1;min-width:0;">' +
                      '<div style="font-weight:600;">' + escapeHtml(p.name) + '</div>' +
                      '<div style="font-size:12px;color:var(--muted);">' + escapeHtml(p.category || "Uncategorised") + ' · ' + fmtINR(p.price || 0) + '</div>' +
                    '</div>' +
                    '<span class="badge status-delivered">Approved</span>' +
                    '<button class="btn small" onclick="editProduct(' + p.id + ')">Edit</button>' +
                  '</div>'
                )).join("")
              : '<p style="color:var(--muted);font-size:13px;margin:8px 0 0;">No approved products yet.</p>';

            const pendingNote = s.pendingCount
              ? '<div style="font-size:12px;color:var(--danger);margin-top:8px;">' + s.pendingCount + ' product' + (s.pendingCount === 1 ? '' : 's') + ' awaiting approval — review in the "Approval for Seller" tab.</div>'
              : '';

            const escapedName = escapeHtml(s.name).replace(/'/g, "\\'");
            const pendingPasswordBanner = s.hasPendingPassword
              ? '<div style="margin-top:10px;padding:8px 10px;background:var(--warn-bg);border:1px solid var(--warn);border-radius:8px;font-size:13px;color:var(--warn);">' +
                  '⚠️ This seller\'s password email never went through — open View details to share it manually.' +
                '</div>'
              : '';

            return (
              '<div class="card" style="margin-bottom:12px;' + (s.banned ? 'opacity:0.7;border-color:var(--danger);' : '') + '">' +
                '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;">' +
                  '<div style="cursor:pointer;" onclick="toggleSellerProducts(' + s.id + ')">' +
                    '<div style="font-weight:700;font-size:16px;color: var(--gold-soft);">' + escapeHtml(s.shopTitle || s.name) +
                      (s.banned ? ' <span class="badge" style="background:var(--danger);color:#fff;">Banned</span>' : '') +
                    '</div>' +
                    '<div style="font-size:13px;color:var(--muted);">' + escapeHtml(s.name) + ' · ' + escapeHtml(s.sellerId) + '</div>' +
                    '<div style="font-size:13px;color:var(--muted);">' + escapeHtml(s.phone || "—") + ' · ' + escapeHtml(s.email || "—") + '</div>' +
                  '</div>' +
                  '<div style="text-align:right;font-size:12px;color:var(--muted);">' +
                    '<div><strong style="color:var(--ink);font-size:15px;">' + s.productCount + '</strong> products</div>' +
                    '<div>' + s.approvedCount + ' approved · ' + s.pendingCount + ' pending</div>' +
                    '<div style="margin-top:6px;display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap;">' +
                      '<button class="btn small" onclick="toggleSellerProducts(' + s.id + ')" style="background:transparent;color: var(--gold-soft);border:1px solid var(--rosewood);">▼ Products</button>' +
                      '<button class="btn small" onclick="openSellerDetailFromLive(' + s.id + ')" style="background:var(--rosewood);color:#fff;">View details</button>' +
                      (s.banned
                        ? '<button class="btn small" onclick="unbanSeller(' + s.id + ')">Unban</button>'
                        : '<button class="btn small secondary" onclick="banSeller(' + s.id + ')">Ban</button>') +
                      (role === "boss"
                        ? '<button class="btn small" onclick=\'deleteSeller(' + s.id + ', ' + JSON.stringify(escapedName) + ')\' style="background:var(--danger);color:#fff;">Delete</button>'
                        : '') +
                    '</div>' +
                  '</div>' +
                '</div>' +
                pendingPasswordBanner +
                '<div id="sellerProducts' + s.id + '" style="display:none;margin-top:12px;border-top:1px solid var(--blush-line);padding-top:8px;">' +
                  productsHtml +
                  pendingNote +
                '</div>' +
              '</div>'
            );
          }).join("");
        } catch (err) {
          loadingEl.classList.add("hidden");
          listEl.innerHTML = '<p class="empty-state">Network error loading sellers.</p>';
        }
      }

      async function banSeller(id) {
        if (!confirm("Ban this seller? They won't be able to log in, and their products will disappear from the storefront until you unban them.")) return;
        const res = await fetch("/api/admin/sellers/" + id + "/ban", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        const data = await res.json();
        if (!data.success) alert(data.message || "Could not ban this seller.");
        loadSellerList();
      }

      async function unbanSeller(id) {
        const res = await fetch("/api/admin/sellers/" + id + "/unban", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        const data = await res.json();
        if (!data.success) alert(data.message || "Could not unban this seller.");
        loadSellerList();
      }

      async function deleteSeller(id, name) {
        if (role !== "boss") {
          alert("Only the Super Admin account can delete a seller.");
          return;
        }
        if (!confirm("Permanently delete " + name + "? This removes their account and every product they listed — this cannot be undone.")) return;
        if (!confirm("Are you absolutely sure? Type-check: this will erase " + name + "'s seller data for good.")) return;
        const res = await fetch("/api/admin/sellers/" + id, {
          method: "DELETE",
          headers: { Authorization: "Bearer " + token },
        });
        const data = await res.json();
        if (!data.success) {
          alert(data.message || "Could not delete this seller.");
          return;
        }
        alert(data.message || "Seller deleted.");
        loadSellerList();
      }

      // ---------- SELLER DETAILS (rich profile) ----------
      let sdMode = null; // 'pending' | 'live'
      let sdId = null;

      function sdInitials(name) {
        const parts = String(name || "?").trim().split(/\s+/).slice(0, 2);
        return parts.map((p) => p[0] || "").join("").toUpperCase() || "?";
      }

      function sdSet(id, value, fallback) {
        const el = document.getElementById(id);
        if (el) el.textContent = (value === undefined || value === null || value === "") ? (fallback !== undefined ? fallback : "—") : value;
      }

      function openSellerDetailFromApplication(id) {
        const a = sellerApplicationsData.find((x) => x.id === id);
        if (!a) return;
        renderSellerDetail(a, "pending");
      }

      function openSellerDetailFromLive(id) {
        const s = sellerListData.find((x) => x.id === id);
        if (!s) return;
        renderSellerDetail(s, "live");
      }

      function renderSellerDetail(obj, mode) {
        sdMode = mode;
        sdId = obj.id;

        sdSet("sdAvatar", sdInitials(obj.shopTitle || obj.name));
        sdSet("sdShopTitle", obj.shopTitle || obj.name, "Seller");
        sdSet("sdSellerName", obj.name);

        const statusBadge = document.getElementById("sdStatusBadge");
        if (mode === "pending") {
          statusBadge.textContent = "Pending Approval";
          statusBadge.className = "badge status-new";
        } else if (obj.banned) {
          statusBadge.textContent = "Banned";
          statusBadge.className = "badge status-cancelled";
        } else {
          statusBadge.textContent = "Approved";
          statusBadge.className = "badge status-delivered";
        }

        sdSet("sdSellerId", mode === "live" ? obj.sellerId : null, mode === "live" ? "—" : "Not yet assigned");
        sdSet("sdJoinedOn", mode === "live" ? formatDate(obj.createdAt) : null, mode === "live" ? "—" : "Not yet approved");
        sdSet("sdAppliedOn", formatDate(obj.createdAt));
        sdSet("sdStatus", mode === "pending" ? "Pending" : (obj.banned ? "Banned" : "Active"));

        const onlineDot = document.getElementById("sdOnlineDot");
        onlineDot.style.display = mode === "live" && !obj.banned ? "inline-flex" : "none";

        sdSet("sdAboutStore", obj.shopTitle ? ("Seller of " + obj.shopTitle + ".") : null, "No store description provided.");

        sdSet("sdName", obj.name);
        sdSet("sdEmail", obj.email);
        sdSet("sdPhone", obj.phone);
        sdSet("sdAltPhone", obj.altPhone);

        sdSet("sdShopName", obj.shopTitle);
        sdSet("sdBusinessType", obj.businessType);
        sdSet("sdBusinessAddress", obj.businessAddress);
        const cityStatePin = [obj.city, obj.state].filter(Boolean).join(", ") + (obj.pincode ? " - " + obj.pincode : "");
        sdSet("sdCityStatePin", cityStatePin.trim().replace(/^,\s*/, "") || null);

        sdSet("sdAadhaar", obj.aadhaarFull ? obj.aadhaarFull.replace(/(\d{4})(?=\d)/g, "$1 ") : null, obj.aadhaarLast4 ? "•••• •••• " + obj.aadhaarLast4 : "—");
        sdSet("sdPan", obj.panNumber);
        sdSet("sdDob", obj.dob);
        sdSet("sdGender", obj.gender);

        sdSet("sdBank", obj.bankAccountNumber);
        sdSet("sdIfsc", obj.ifscCode);
        sdSet("sdUpi", obj.upiId);
        sdSet("sdGst", obj.gstNumber, "Not Provided");

        // Recent products (up to 3) — only live sellers have a products array here.
        const productsList = document.getElementById("sdProductsList");
        const prods = (obj.products || []).slice(0, 3);
        sdSet("sdProductCount", obj.productCount !== undefined ? obj.productCount : (obj.products || []).length);
        if (!prods.length) {
          productsList.innerHTML = '<p class="empty-state" style="padding:16px;">No products yet.</p>';
        } else {
          productsList.innerHTML = prods.map((p) => (
            '<div class="sd-product-row">' +
              (p.image ? '<img src="' + escapeHtml(p.image) + '" />' : '<div class="ph"></div>') +
              '<div style="flex:1;min-width:0;">' +
                '<div class="sd-product-name">' + escapeHtml(p.name) + '</div>' +
                '<div class="sd-product-price">' + fmtINR(p.price || 0) + '</div>' +
              '</div>' +
              '<span class="badge ' + (p.approved ? "status-delivered" : "status-new") + '">' + (p.approved ? "Approved" : "Pending") + '</span>' +
            '</div>'
          )).join("");
        }
        document.getElementById("sdViewAllProducts").style.display = mode === "live" ? "inline" : "none";

        // Activity summary — only meaningful for a live seller.
        document.getElementById("sdSummaryCard").style.display = mode === "live" ? "block" : "none";
        if (mode === "live") {
          sdSet("sdTotalProducts", obj.productCount || 0);
          sdSet("sdApprovedProducts", obj.approvedCount || 0);
          sdSet("sdPendingProducts", obj.pendingCount || 0);
          sdSet("sdTotalOrders", obj.totalOrders || 0);
          sdSet("sdTotalRevenue", fmtINR(obj.totalRevenue || 0));
        }

        // Notes — admin-only, only exists once a seller is live.
        const notesCard = document.getElementById("sdNotesCard");
        notesCard.style.display = mode === "live" ? "block" : "none";
        document.getElementById("sdNotesInput").value = obj.notes || "";
        document.getElementById("sdNotesStatus").textContent = "";

        // Action buttons — different set depending on pending vs live.
        document.getElementById("sdApproveBtn").style.display = mode === "pending" ? "block" : "none";
        document.getElementById("sdRejectBtn").style.display = mode === "pending" ? "block" : "none";
        document.getElementById("sdEditBtn").style.display = mode === "live" ? "block" : "none";
        const banBtn = document.getElementById("sdBanBtn");
        banBtn.style.display = (mode === "live" && role === "boss") ? "block" : "none";
        banBtn.textContent = obj.banned ? "Unban Seller" : "Ban / Block Seller";
        document.getElementById("sdDeleteBtn").style.display = (mode === "live" && role === "boss") ? "block" : "none";

        document.getElementById("sellerDetailOverlay").classList.add("open");
      }

      function closeSellerDetail() {
        document.getElementById("sellerDetailOverlay").classList.remove("open");
        sdMode = null;
        sdId = null;
      }

      async function sdApprove() {
        if (sdMode !== "pending" || !sdId) return;
        await approveSellerApplication(sdId);
        closeSellerDetail();
      }

      async function sdReject() {
        if (sdMode !== "pending" || !sdId) return;
        await rejectSellerApplication(sdId);
        closeSellerDetail();
      }

      function sdEditDetails() {
        if (sdMode !== "live" || !sdId) return;
        closeSellerDetail();
        openSellerModal(sdId);
      }

      async function sdBanToggle() {
        if (sdMode !== "live" || !sdId) return;
        const s = sellerListData.find((x) => x.id === sdId);
        if (!s) return;
        if (s.banned) {
          await unbanSeller(sdId);
        } else {
          if (!confirm("Ban this seller? They won't be able to log in, and their products will disappear from the storefront until you unban them.")) return;
          const res = await fetch("/api/admin/sellers/" + sdId + "/ban", {
            method: "PUT",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (!data.success) alert(data.message || "Could not ban this seller.");
          await loadSellerList();
        }
        closeSellerDetail();
      }

      async function sdDeleteSeller() {
        if (sdMode !== "live" || !sdId) return;
        const s = sellerListData.find((x) => x.id === sdId);
        if (!s) return;
        await deleteSeller(sdId, s.name);
        closeSellerDetail();
      }

      async function sdSaveNote() {
        if (sdMode !== "live" || !sdId) return;
        const note = document.getElementById("sdNotesInput").value;
        const statusEl = document.getElementById("sdNotesStatus");
        statusEl.textContent = "Saving...";
        try {
          const res = await fetch("/api/admin/sellers/" + sdId + "/note", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ note }),
          });
          const data = await res.json();
          statusEl.textContent = data.success ? "Saved." : (data.message || "Could not save note.");
          if (data.success) {
            const s = sellerListData.find((x) => x.id === sdId);
            if (s) s.notes = data.notes;
          }
        } catch (e) {
          statusEl.textContent = "Network error — could not save note.";
        }
      }

      // ---------- SELLER DETAILS MODAL ----------
      // Replaces the old window.prompt()/alert() based flow. Browsers can
      // silently suppress repeated prompt/alert/confirm dialogs on a page
      // ("prevent this page from creating additional dialogs") — which
      // looks exactly like "I click OK and nothing happens". This modal
      // does everything inline instead, with its own visible status text.
      let sellerModalId = null;

      function openSellerModal(id) {
        const s = sellerListData.find((x) => x.id === id);
        if (!s) return;
        sellerModalId = id;

        document.getElementById("sellerModalShopTitle").textContent = s.shopTitle || s.name;
        document.getElementById("sellerModalSellerId").textContent = s.sellerId;
        document.getElementById("sellerModalName").value = s.name || "";
        document.getElementById("sellerModalEmail").value = s.email || "";
        document.getElementById("sellerModalPhone").value = s.phone || "";
        document.getElementById("sellerModalWhatsapp").value = s.whatsappNumber || s.phone || "";
        document.getElementById("sellerModalShopTitleInput").value = s.shopTitle || "";
        document.getElementById("sellerModalPhoto").value = "";
        document.getElementById("sellerModalDetailsStatus").textContent = "";
        document.getElementById("sellerModalCustomPassword").value = "";
        document.getElementById("sellerModalPasswordStatus").textContent = "";
        document.getElementById("sellerModalPasswordStatus").style.color = "";

        // Ban, password, and "log in as" are sensitive actions — boss-only.
        // The server already blocks these for a sub-admin (403), this just
        // keeps the buttons from showing up and confusing anyone.
        document.getElementById("sellerModalSensitiveSections").style.display = role === "boss" ? "block" : "none";
        document.getElementById("sellerModalWhatsappWrap").style.display = role === "boss" ? "block" : "none";
        const banBtn = document.getElementById("sellerModalBanBtn");
        banBtn.style.display = role === "boss" ? "inline-block" : "none";
        if (s.banned) {
          banBtn.textContent = "Unban this seller";
          banBtn.className = "btn small";
          banBtn.onclick = () => modalToggleBan(id, false);
        } else {
          banBtn.textContent = "Ban this seller";
          banBtn.className = "btn small secondary";
          banBtn.onclick = () => modalToggleBan(id, true);
        }

        // A sub-admin's Save button submits for approval instead of saving
        // directly — label it accordingly.
        document.getElementById("sellerModalSaveDetailsBtn").textContent = role === "boss" ? "Save details" : "Submit for approval";

        renderSellerModalPendingEdit(s);
        renderSellerModalPendingPassword(s);

        document.getElementById("sellerModalOverlay").classList.add("open");
      }

      // Shows a banner when this seller already has a sub-admin's edit
      // waiting on the boss — so nobody submits a second one blind, and a
      // sub-admin can see their change hasn't gone live yet.
      function renderSellerModalPendingEdit(s) {
        const box = document.getElementById("sellerModalPendingEditBox");
        if (!s.pendingSellerEdit) {
          box.innerHTML = "";
          box.style.display = "none";
          return;
        }
        box.style.display = "block";
        box.innerHTML =
          '<div style="padding:10px;background:var(--warn-bg);border:1px solid var(--warn);border-radius:8px;font-size:13px;color:var(--warn);margin:10px 0;">' +
            '⏳ A change to this seller\'s details (by ' + escapeHtml(s.pendingSellerEdit.requestedBy) + ') is waiting for the boss\'s approval' +
            (role === "boss" ? ' — review it from the Sellers tab\'s "Pending Seller Detail Edits" card.' : '.') +
          '</div>';
      }

      function closeSellerModal() {
        document.getElementById("sellerModalOverlay").classList.remove("open");
        sellerModalId = null;
      }

      function renderSellerModalPendingPassword(s) {
        const box = document.getElementById("sellerModalPendingBox");
        if (!s.hasPendingPassword) {
          box.innerHTML = "";
          box.style.display = "none";
          return;
        }
        box.style.display = "block";
        box.innerHTML =
          '<div style="padding:10px;background:var(--warn-bg);border:1px solid var(--warn);border-radius:8px;font-size:13px;color:var(--warn);margin-bottom:12px;">' +
            '⚠️ The last password generated for this seller never got emailed to them successfully.' +
            '<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">' +
              '<button class="btn small" onclick="modalViewPendingPassword(' + s.id + ')">View password</button>' +
              '<button class="btn small secondary" onclick="modalClearPendingPassword(' + s.id + ')">Mark as shared</button>' +
            '</div>' +
            '<div id="sellerModalPendingResult" style="margin-top:8px;font-weight:600;"></div>' +
          '</div>';
      }

      // Edit of a seller's details (name/email/phone/shop title/photo).
      // Boss's edit goes live immediately; a sub-admin's edit is held for
      // the boss to approve (the server decides which, based on role).
      async function saveSellerDetailsModal() {
        if (sellerModalId == null) return;
        const statusEl = document.getElementById("sellerModalDetailsStatus");
        const name = document.getElementById("sellerModalName").value.trim();
        const email = document.getElementById("sellerModalEmail").value.trim();
        const phone = document.getElementById("sellerModalPhone").value.trim();
        const whatsappNumber = document.getElementById("sellerModalWhatsapp").value.trim();
        const shopTitle = document.getElementById("sellerModalShopTitleInput").value.trim();
        const fileInput = document.getElementById("sellerModalPhoto");

        if (!name || !email || !shopTitle) {
          statusEl.style.color = "var(--danger)";
          statusEl.textContent = "Name, email, and shop title cannot be empty.";
          return;
        }

        let photo = "";
        if (fileInput.files && fileInput.files[0]) {
          statusEl.style.color = "";
          statusEl.textContent = "Processing photo...";
          try {
            const { dataUrl } = await compressImage(fileInput.files[0], 800, 0.82);
            photo = dataUrl;
          } catch (e) {
            statusEl.style.color = "var(--danger)";
            statusEl.textContent = "Could not process the photo. Try a different image.";
            return;
          }
        }

        statusEl.style.color = "";
        statusEl.textContent = "Saving...";
        try {
          const res = await fetch("/api/admin/sellers/" + sellerModalId, {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ name, email, phone, whatsappNumber, shopTitle, photo }),
          });
          const data = await res.json();
          if (res.status === 401) { closeSellerModal(); logout(); return; }
          if (!data.success) {
            statusEl.style.color = "var(--danger)";
            statusEl.textContent = data.message || "Could not update seller.";
            return;
          }
          if (data.pending) {
            statusEl.style.color = "var(--warn)";
            statusEl.textContent = "⏳ Submitted — waiting for the boss's approval.";
            await loadSellerList();
            const s = sellerListData.find((x) => x.id === sellerModalId);
            if (s) renderSellerModalPendingEdit(s);
            return;
          }
          statusEl.style.color = "var(--success)";
          statusEl.textContent = "✓ Saved.";
          document.getElementById("sellerModalShopTitle").textContent = shopTitle;
          await loadSellerList();
        } catch (err) {
          statusEl.style.color = "var(--danger)";
          statusEl.textContent = "Network error — check your connection and try again.";
        }
      }

      // Generates a brand-new random password, emails it, and (only if the
      // email fails) shows it here so it can be shared manually.
      async function generateRandomPasswordModal() {
        if (sellerModalId == null) return;
        const statusEl = document.getElementById("sellerModalPasswordStatus");
        statusEl.style.color = "";
        statusEl.textContent = "Generating...";
        try {
          const res = await fetch("/api/admin/sellers/" + sellerModalId + "/reset-password", {
            method: "PUT",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (res.status === 401) { closeSellerModal(); logout(); return; }
          if (!data.success) {
            statusEl.style.color = "var(--danger)";
            statusEl.textContent = data.message || "Could not generate a password.";
            return;
          }
          statusEl.style.color = "var(--success)";
          statusEl.textContent = data.newPassword
            ? "New password: " + data.newPassword + " (copy it now — it won't be shown again after you close this)"
            : "✓ " + data.message;
          await loadSellerList();
          const s = sellerListData.find((x) => x.id === sellerModalId);
          if (s) renderSellerModalPendingPassword(s);
        } catch (err) {
          statusEl.style.color = "var(--danger)";
          statusEl.textContent = "Network error — check your connection and try again.";
        }
      }

      // Lets the boss type an exact password for this seller's main ID,
      // instead of only ever being able to auto-generate a random one.
      async function setCustomPasswordModal() {
        if (sellerModalId == null) return;
        const statusEl = document.getElementById("sellerModalPasswordStatus");
        const pw = document.getElementById("sellerModalCustomPassword").value;

        if (pw.length < 6) {
          statusEl.style.color = "var(--danger)";
          statusEl.textContent = "Password must be at least 6 characters.";
          return;
        }

        statusEl.style.color = "";
        statusEl.textContent = "Setting password...";
        try {
          const res = await fetch("/api/admin/sellers/" + sellerModalId + "/set-password", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ password: pw }),
          });
          const data = await res.json();
          if (res.status === 401) { closeSellerModal(); logout(); return; }
          if (!data.success) {
            statusEl.style.color = "var(--danger)";
            statusEl.textContent = data.message || "Could not set password.";
            return;
          }
          statusEl.style.color = "var(--success)";
          statusEl.textContent = "✓ Password set. Share it with the seller directly.";
          document.getElementById("sellerModalCustomPassword").value = "";
          await loadSellerList();
          const s = sellerListData.find((x) => x.id === sellerModalId);
          if (s) renderSellerModalPendingPassword(s);
        } catch (err) {
          statusEl.style.color = "var(--danger)";
          statusEl.textContent = "Network error — check your connection and try again.";
        }
      }

      async function modalViewPendingPassword(id) {
        const resultEl = document.getElementById("sellerModalPendingResult");
        try {
          const res = await fetch("/api/admin/sellers/" + id + "/pending-password", {
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (res.status === 401) { closeSellerModal(); logout(); return; }
          if (!data.success) {
            if (resultEl) resultEl.textContent = data.message || "No unsent password on file.";
            await loadSellerList();
            return;
          }
          if (resultEl) resultEl.textContent = "Password: " + data.password;
        } catch (err) {
          if (resultEl) resultEl.textContent = "Network error — try again.";
        }
      }

      async function modalClearPendingPassword(id) {
        const resultEl = document.getElementById("sellerModalPendingResult");
        try {
          const res = await fetch("/api/admin/sellers/" + id + "/pending-password", {
            method: "DELETE",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (res.status === 401) { closeSellerModal(); logout(); return; }
          if (!data.success) {
            if (resultEl) resultEl.textContent = data.message || "Could not clear it.";
            return;
          }
          await loadSellerList();
          const s = sellerListData.find((x) => x.id === id);
          if (s) renderSellerModalPendingPassword(s);
        } catch (err) {
          if (resultEl) resultEl.textContent = "Network error — try again.";
        }
      }

      async function modalToggleBan(id, ban) {
        try {
          const res = await fetch("/api/admin/sellers/" + id + "/" + (ban ? "ban" : "unban"), {
            method: "PUT",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (res.status === 401) { closeSellerModal(); logout(); return; }
          if (!data.success) { alert(data.message || "Could not update ban status."); return; }
          await loadSellerList();
          const s = sellerListData.find((x) => x.id === id);
          if (s) openSellerModal(id);
        } catch (err) {
          alert("Network error. Try again.");
        }
      }

      // Opens the seller's own dashboard in a new tab, already authenticated
      // as them — no password needed at all. Useful for checking or fixing
      // something in their account directly, or when password sharing keeps
      // going wrong (typos, look-alike characters, WhatsApp autocorrect, etc).
      async function loginAsSellerModal() {
        if (sellerModalId == null) return;
        const statusEl = document.getElementById("sellerModalLoginAsStatus");
        statusEl.style.color = "";
        statusEl.textContent = "Opening...";
        try {
          const res = await fetch("/api/admin/sellers/" + sellerModalId + "/login-as", {
            method: "POST",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (res.status === 401) { closeSellerModal(); logout(); return; }
          if (!data.success) {
            statusEl.style.color = "var(--danger)";
            statusEl.textContent = data.message || "Could not log in as this seller.";
            return;
          }
          statusEl.style.color = "var(--success)";
          statusEl.textContent = "✓ Opened in a new tab.";
          window.open("/sell?impersonate=" + encodeURIComponent(data.token), "_blank");
        } catch (err) {
          statusEl.style.color = "var(--danger)";
          statusEl.textContent = "Network error — check your connection and try again.";
        }
      }

      function toggleSellerProducts(id) {
        const box = document.getElementById("sellerProducts" + id);
        if (box) box.style.display = box.style.display === "none" ? "block" : "none";
      }

      async function approveSellerProduct(id) {
        await fetch("/api/admin/products/" + id + "/approve", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        await loadProducts();
        loadSellerList();
      }

      async function rejectSellerProduct(id) {
        if (!confirm("Reject and remove this product?")) return;
        await fetch("/api/admin/products/" + id + "/reject", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        await loadProducts();
        loadSellerList();
      }

      function copySellerInviteLink() {
        const inviteEl = document.getElementById("sellerInviteLink");
        const copied = document.getElementById("sellerInviteCopied");
        if (!inviteEl) return;
        inviteEl.select();
        const done = () => { if (copied) { copied.style.display = "inline"; setTimeout(() => { copied.style.display = "none"; }, 2000); } };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(inviteEl.value).then(done).catch(() => { document.execCommand("copy"); done(); });
        } else {
          document.execCommand("copy");
          done();
        }
      }

      let sellerApplicationsData = [];

      async function loadSellerApplications() {
        // Fill in the shareable seller-invite link (based on the live site URL).
        const inviteEl = document.getElementById("sellerInviteLink");
        if (inviteEl) inviteEl.value = window.location.origin + "/sellerapplication";
        const loadingEl = document.getElementById("sellerAppsLoading");
        const listEl = document.getElementById("sellerAppsList");
        loadingEl.classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/seller-applications", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          loadingEl.classList.add("hidden");
          if (!data.success || !data.applications.length) {
            sellerApplicationsData = [];
            listEl.innerHTML = '<p class="empty-state">No pending seller applications.</p>';
            return;
          }
          sellerApplicationsData = data.applications;
          listEl.innerHTML = data.applications.map((a) => (
            '<div class="card" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px;cursor:pointer;" onclick="openSellerDetailFromApplication(' + a.id + ')">' +
              '<div><strong>' + escapeHtml(a.shopTitle) + '</strong><br>' +
                '<span style="font-size:13px;color:var(--muted);">' + escapeHtml(a.name) + ' — ' + escapeHtml(a.email) + '</span></div>' +
              '<div style="display:flex;gap:8px;" onclick="event.stopPropagation();">' +
                '<button class="btn small" onclick="approveSellerApplication(' + a.id + ')">Approve</button>' +
                '<button class="btn small secondary" onclick="rejectSellerApplication(' + a.id + ')">Reject</button>' +
              '</div>' +
            '</div>'
          )).join("");
        } catch (err) {
          loadingEl.classList.add("hidden");
          listEl.innerHTML = '<p class="empty-state">Network error loading applications.</p>';
        }
      }

      let approveModePendingId = null;

      function approveSellerApplication(id) {
        const a = sellerApplicationsData.find((x) => x.id === id);
        approveModePendingId = id;
        document.getElementById("approveModeShopTitle").textContent = a ? (a.shopTitle || a.name) : "this seller";
        document.getElementById("approveModeStatus").textContent = "";
        const radios = document.getElementsByName("approvePwMode");
        for (const r of radios) r.checked = r.value === "password";
        document.getElementById("approveModeOverlay").classList.add("open");
      }

      function closeApproveModeModal() {
        document.getElementById("approveModeOverlay").classList.remove("open");
        approveModePendingId = null;
      }

      async function confirmApproveSeller() {
        if (!approveModePendingId) return;
        const id = approveModePendingId;
        const mode = "password";
        const statusEl = document.getElementById("approveModeStatus");
        const btn = document.getElementById("approveModeConfirmBtn");
        statusEl.style.color = "";
        statusEl.textContent = "Sending...";
        btn.disabled = true;
        try {
          const res = await fetch("/api/admin/seller-applications/" + id + "/approve", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ passwordMode: mode }),
          });
          const data = await res.json();
          if (data.success && !data.emailSent) {
            alert(
              "⚠️ " + data.message + "\n\n" +
              "Seller ID: " + data.sellerId + "\n" +
              (mode === "otp" ? "One-time password: " : "Password: ") + data.plainPassword + "\n\n" +
              "Send these to them yourself (WhatsApp/SMS) — the automatic email did not go through. " +
              "This usually means GMAIL_USER / GMAIL_APP_PASSWORD aren't set correctly in Render's Environment tab.",
            );
          } else if (!data.success) {
            alert(data.message || "Could not approve this application.");
          }
          closeApproveModeModal();
          if (typeof closeSellerDetail === "function") closeSellerDetail();
          loadSellerApplications();
        } catch (err) {
          statusEl.style.color = "var(--danger)";
          statusEl.textContent = "Network error — try again.";
        } finally {
          btn.disabled = false;
        }
      }

      async function rejectSellerApplication(id) {
        if (!confirm("Reject this seller application?")) return;
        await fetch("/api/admin/seller-applications/" + id + "/reject", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        loadSellerApplications();
      }

      async function loadSellerPasswordRequests() {
        const loadingEl = document.getElementById("sellerPwLoading");
        const listEl = document.getElementById("sellerPwList");
        loadingEl.classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/seller-password-requests", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          loadingEl.classList.add("hidden");
          if (!data.success || !data.requests.length) {
            listEl.innerHTML = '<p class="empty-state">No pending password reset requests.</p>';
            return;
          }
          listEl.innerHTML = data.requests.map((r) => (
            '<div class="card" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px;">' +
              '<div><strong>' + escapeHtml(r.shopTitle) + '</strong><br>' +
                '<span style="font-size:13px;color:var(--muted);">' + escapeHtml(r.name) + ' — ' + escapeHtml(r.sellerId) + '</span></div>' +
              '<button class="btn small" onclick="resolveSellerPasswordRequest(' + r.id + ')">Generate & send new password</button>' +
            '</div>'
          )).join("");
        } catch (err) {
          loadingEl.classList.add("hidden");
          listEl.innerHTML = '<p class="empty-state">Network error loading requests.</p>';
        }
      }

      async function resolveSellerPasswordRequest(id) {
        const res = await fetch("/api/admin/seller-password-requests/" + id + "/resolve", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        const data = await res.json();
        if (data.success && !data.emailSent) {
          alert(
            "⚠️ " + data.message + "\n\n" +
            "Seller ID: " + data.sellerId + "\n" +
            "New Password: " + data.newPassword + "\n\n" +
            "Send these to them yourself (WhatsApp/SMS) — the automatic email did not go through. " +
            "This usually means GMAIL_USER / GMAIL_APP_PASSWORD aren't set correctly in Render's Environment tab.",
          );
        } else if (!data.success) {
          alert(data.message || "Could not resolve this request.");
        }
        loadSellerPasswordRequests();
      }

      async function loadSellerProfileUpdateRequests() {
        const loadingEl = document.getElementById("sellerProfileReqLoading");
        const listEl = document.getElementById("sellerProfileReqList");
        loadingEl.classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/seller-profile-update-requests", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          loadingEl.classList.add("hidden");
          if (!data.success || !data.requests.length) {
            listEl.innerHTML = '<p class="empty-state">No pending profile update requests.</p>';
            return;
          }
          listEl.innerHTML = data.requests.map((r) => {
            const changeLines = Object.keys(r.changes || {}).map((key) => {
              if (key === "photo") return '<div>New photo uploaded</div>';
              const label = key === "shopTitle" ? "Shop title" : key === "phone" ? "Phone" : key;
              return '<div>' + escapeHtml(label) + ' → ' + escapeHtml(String(r.changes[key])) + '</div>';
            }).join("");
            return (
              '<div class="card" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px;">' +
                '<div><strong>' + escapeHtml(r.name) + '</strong> — <span style="font-size:13px;color:var(--muted);">' + escapeHtml(r.sellerId) + '</span>' +
                  '<div style="font-size:13px;color:var(--muted);margin-top:4px;">' + changeLines + '</div></div>' +
                '<div style="display:flex;gap:8px;">' +
                  '<button class="btn small" onclick="resolveSellerProfileUpdateRequest(' + r.id + ', \'approve\')">Approve</button>' +
                  '<button class="btn small secondary" onclick="resolveSellerProfileUpdateRequest(' + r.id + ', \'reject\')">Reject</button>' +
                '</div>' +
              '</div>'
            );
          }).join("");
        } catch (err) {
          loadingEl.classList.add("hidden");
          listEl.innerHTML = '<p class="empty-state">Network error loading requests.</p>';
        }
      }

      async function resolveSellerProfileUpdateRequest(id, decision) {
        if (decision === "reject" && !confirm("Reject this profile update request?")) return;
        const res = await fetch("/api/admin/seller-profile-update-requests/" + id, {
          method: "PUT",
          headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
          body: JSON.stringify({ decision }),
        });
        const data = await res.json();
        if (!data.success) alert(data.message || "Could not resolve this request.");
        loadSellerProfileUpdateRequests();
      }

      let pendingProductsData = [];

      async function loadPendingProducts() {
        const loadingEl = document.getElementById("pendingProductsLoading");
        const listEl = document.getElementById("pendingProductsList");
        loadingEl.classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/products/pending", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          loadingEl.classList.add("hidden");
          if (!data.success || !data.products.length) {
            pendingProductsData = [];
            listEl.innerHTML = '<p class="empty-state">No products waiting for approval.</p>';
            return;
          }
          pendingProductsData = data.products;
          listEl.innerHTML = data.products.map((p) => (
            '<div class="card" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px;">' +
              '<div style="display:flex;gap:12px;align-items:center;">' +
                (p.image ? '<img src="' + escapeHtml(p.image) + '" style="width:48px;height:48px;object-fit:cover;border-radius:6px;" />' : '') +
                '<div><strong>' + escapeHtml(p.name) + '</strong> — ' + fmtINR(p.price) + '<br>' +
                  '<span style="font-size:13px;color:var(--muted);">by ' + escapeHtml(p.shopTitle || p.sellerName) + '</span></div>' +
              '</div>' +
              '<div style="display:flex;gap:8px;">' +
                '<button class="btn small secondary" onclick="openPendingProductModal(' + p.id + ')">View</button>' +
                '<button class="btn small" onclick="approvePendingProduct(' + p.id + ')">Approve</button>' +
                '<button class="btn small secondary" onclick="rejectPendingProduct(' + p.id + ')">Reject</button>' +
              '</div>' +
            '</div>'
          )).join("");
        } catch (err) {
          loadingEl.classList.add("hidden");
          listEl.innerHTML = '<p class="empty-state">Network error loading pending products.</p>';
        }
      }

      // Renders a simple before/after table for the fields that differ
      // between an old and new version of a product. Used for both a
      // seller's edit (pendingSnapshot) and a sub-admin's proposed edit
      // (pendingAdminEdit.changes).
      const DIFF_FIELDS = [
        { key: "name", label: "Name" },
        { key: "price", label: "Price", fmt: (v) => fmtINR(v) },
        { key: "category", label: "Category" },
        { key: "moq", label: "MOQ" },
        { key: "sizes", label: "Sizes", fmt: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "—") },
        { key: "description", label: "Description" },
      ];
      // Same field set, but for a seller's name/email/phone/shopTitle/photo
      // — used by the "Pending Seller Detail Edits" card below.
      const SELLER_DIFF_FIELDS = [
        { key: "name", label: "Name" },
        { key: "email", label: "Email" },
        { key: "phone", label: "Phone" },
        { key: "shopTitle", label: "Shop title" },
        { key: "photo", label: "Photo", fmt: (v) => (v ? "Photo (" + Math.round(v.length / 1024) + " KB)" : "—") },
      ];
      function buildDiffRows(before, after, fields) {
        const rows = (fields || DIFF_FIELDS).map((f) => {
          const oldVal = f.fmt ? f.fmt(before[f.key]) : (before[f.key] ?? "—");
          const newVal = f.fmt ? f.fmt(after[f.key]) : (after[f.key] ?? "—");
          const oldStr = String(oldVal ?? "—");
          const newStr = String(newVal ?? "—");
          if (oldStr === newStr) return "";
          return (
            '<div style="display:grid;grid-template-columns:90px 1fr 14px 1fr;gap:6px;align-items:start;padding:8px 10px;border-top:1px solid var(--blush-line,#eadfda);">' +
              '<div style="color:var(--muted);font-size:12px;">' + escapeHtml(f.label) + '</div>' +
              '<div style="color:var(--danger,#b3261e);text-decoration:line-through;white-space:pre-wrap;">' + escapeHtml(oldStr) + '</div>' +
              '<div style="color:var(--muted);">→</div>' +
              '<div style="color:var(--success,#1e8e3e);font-weight:600;white-space:pre-wrap;">' + escapeHtml(newStr) + '</div>' +
            '</div>'
          );
        }).filter(Boolean);
        return rows.length ? rows.join("") : '<div style="padding:8px 10px;color:var(--muted);font-size:13px;">No tracked fields changed.</div>';
      }

      // ---------- PENDING PRODUCT DETAIL MODAL ----------
      let pendingProductModalId = null;

      function openPendingProductModal(id) {
        const p = pendingProductsData.find((x) => x.id === id);
        if (!p) return;
        pendingProductModalId = id;

        document.getElementById("ppmName").textContent = p.name || "Product";
        document.getElementById("ppmShop").textContent = p.shopTitle || p.sellerName || "Unknown seller";

        const diffWrap = document.getElementById("ppmDiffWrap");
        if (p.isEdit && p.pendingSnapshot) {
          document.getElementById("ppmDiff").innerHTML = buildDiffRows(p.pendingSnapshot, p);
          diffWrap.style.display = "block";
        } else {
          diffWrap.style.display = "none";
        }

        const images = (p.images && p.images.length ? p.images : (p.image ? [p.image] : []));
        document.getElementById("ppmImages").innerHTML = images.length
          ? images.map((img) => '<img src="' + escapeHtml(img) + '" style="width:90px;height:90px;object-fit:cover;border-radius:8px;border:1px solid var(--blush-line);" />').join("")
          : '<div style="font-size:13px;color:var(--muted);">No photos uploaded.</div>';

        document.getElementById("ppmPrice").textContent = fmtINR(p.price);
        document.getElementById("ppmCategory").textContent = p.category || "Uncategorized";
        document.getElementById("ppmMoq").textContent = p.moq || 1;
        document.getElementById("ppmSizes").textContent = (p.sizes && p.sizes.length) ? p.sizes.join(", ") : "—";
        document.getElementById("ppmCustomization").textContent = p.customizationEnabled ? "Enabled" : "Not enabled";
        document.getElementById("ppmDiscounts").textContent = (p.discounts && p.discounts.length)
          ? p.discounts.map((d) => d.minQty + "+ qty: " + d.percent + "% off").join(", ")
          : "None";
        document.getElementById("ppmDescription").textContent = p.description || "No description provided.";
        document.getElementById("ppmSellerNote").textContent = p.sellerName ? ("Seller: " + p.sellerName) : "";

        document.getElementById("pendingProductModalOverlay").classList.add("open");
      }

      function closePendingProductModal() {
        document.getElementById("pendingProductModalOverlay").classList.remove("open");
        pendingProductModalId = null;
      }

      async function approvePendingProductFromModal() {
        if (!pendingProductModalId) return;
        await approvePendingProduct(pendingProductModalId);
        closePendingProductModal();
      }

      async function rejectPendingProductFromModal() {
        if (!pendingProductModalId) return;
        await rejectPendingProduct(pendingProductModalId);
        closePendingProductModal();
      }

      async function approvePendingProduct(id) {
        await fetch("/api/admin/products/" + id + "/approve", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        loadPendingProducts();
      }

      async function rejectPendingProduct(id) {
        if (!confirm("Reject and remove this product?")) return;
        await fetch("/api/admin/products/" + id + "/reject", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        loadPendingProducts();
      }

      // ---------- PENDING ADMIN EDITS (boss-only review of sub-admin changes) ----------
      async function loadPendingAdminEdits() {
        const loadingEl = document.getElementById("pendingAdminEditsLoading");
        const listEl = document.getElementById("pendingAdminEditsList");
        loadingEl.classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/products/pending-edits", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          loadingEl.classList.add("hidden");
          if (!data.success || !data.products.length) {
            listEl.innerHTML = '<p class="empty-state">No sub-admin edits waiting for approval.</p>';
            return;
          }
          listEl.innerHTML = data.products.map((p) => (
            '<div class="card" style="margin-bottom:10px;">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;">' +
                '<div><strong>' + escapeHtml(p.name) + '</strong><br>' +
                  '<span style="font-size:12.5px;color:var(--muted);">Edited by ' + escapeHtml(p.pendingAdminEdit.requestedBy) + '</span></div>' +
                '<div style="display:flex;gap:8px;">' +
                  '<button class="btn small" style="background:var(--success) !important;" onclick="approvePendingAdminEdit(' + p.id + ')">✓ Approve</button>' +
                  '<button class="btn small secondary" onclick="rejectPendingAdminEdit(' + p.id + ')">Reject</button>' +
                '</div>' +
              '</div>' +
              '<div style="border:1px solid var(--blush-line,#eadfda);border-radius:8px;overflow:hidden;font-size:13px;">' +
                buildDiffRows(p, p.pendingAdminEdit.changes) +
              '</div>' +
            '</div>'
          )).join("");
        } catch (err) {
          loadingEl.classList.add("hidden");
          listEl.innerHTML = '<p class="empty-state">Network error loading pending edits.</p>';
        }
      }

      async function approvePendingAdminEdit(id) {
        await fetch("/api/admin/products/" + id + "/approve-edit", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        loadPendingAdminEdits();
        loadProducts();
      }

      async function rejectPendingAdminEdit(id) {
        if (!confirm("Reject this edit? The product stays as it is now.")) return;
        await fetch("/api/admin/products/" + id + "/reject-edit", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        loadPendingAdminEdits();
      }

      // ---------- PENDING SELLER DETAIL EDITS (boss-only) ----------
      async function loadPendingSellerEdits() {
        const loadingEl = document.getElementById("pendingSellerEditsLoading");
        const listEl = document.getElementById("pendingSellerEditsList");
        loadingEl.classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/sellers/pending-edits", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          loadingEl.classList.add("hidden");
          if (!data.success || !data.sellers.length) {
            listEl.innerHTML = '<p class="empty-state">No sub-admin edits waiting for approval.</p>';
            return;
          }
          listEl.innerHTML = data.sellers.map((s) => (
            '<div class="card" style="margin-bottom:10px;">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;">' +
                '<div><strong>' + escapeHtml(s.shopTitle || s.name) + '</strong> <span style="font-size:12.5px;color:var(--muted);">(' + escapeHtml(s.sellerId) + ')</span><br>' +
                  '<span style="font-size:12.5px;color:var(--muted);">Edited by ' + escapeHtml(s.pendingSellerEdit.requestedBy) + '</span></div>' +
                '<div style="display:flex;gap:8px;">' +
                  '<button class="btn small" style="background:var(--success) !important;" onclick="approvePendingSellerEdit(' + s.id + ')">✓ Approve</button>' +
                  '<button class="btn small secondary" onclick="rejectPendingSellerEdit(' + s.id + ')">Reject</button>' +
                '</div>' +
              '</div>' +
              '<div style="border:1px solid var(--blush-line,#eadfda);border-radius:8px;overflow:hidden;font-size:13px;">' +
                buildDiffRows(s, s.pendingSellerEdit.changes, SELLER_DIFF_FIELDS) +
              '</div>' +
            '</div>'
          )).join("");
        } catch (err) {
          loadingEl.classList.add("hidden");
          listEl.innerHTML = '<p class="empty-state">Network error loading pending edits.</p>';
        }
      }

      async function approvePendingSellerEdit(id) {
        await fetch("/api/admin/sellers/" + id + "/approve-edit", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        loadPendingSellerEdits();
        loadSellerList();
      }

      async function rejectPendingSellerEdit(id) {
        if (!confirm("Reject this edit? The seller's details stay as they are now.")) return;
        await fetch("/api/admin/sellers/" + id + "/reject-edit", {
          method: "PUT",
          headers: { Authorization: "Bearer " + token },
        });
        loadPendingSellerEdits();
      }

      async function downloadBackup() {
        try {
          const res = await fetch("/api/admin/backup", { headers: { Authorization: "Bearer " + token } });
          if (!res.ok) { alert("Backup failed. Try again."); return; }
          const blob = await res.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "database-backup-" + new Date().toISOString().slice(0, 10) + ".json";
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
        } catch (err) {
          alert("Backup failed. Try again.");
        }
      }

      // ---------- PRODUCTS ----------

      // ---------- CATEGORY DROPDOWN ----------

      function getKnownCategories() {
        const seen = new Set();
        const list = [];
        products.forEach((p) => {
          const c = (p.category || "").trim();
          if (c && !seen.has(c.toLowerCase())) {
            seen.add(c.toLowerCase());
            list.push(c);
          }
        });
        (emptyCategories || []).forEach((c) => {
          if (c && !seen.has(c.toLowerCase())) {
            seen.add(c.toLowerCase());
            list.push(c);
          }
        });
        return list.sort((a, b) => a.localeCompare(b));
      }

      function onCategoryInput() {
        const input = document.getElementById("fCategory");
        const dropdown = document.getElementById("catDropdown");
        const query = input.value.trim().toLowerCase();
        const known = getKnownCategories();
        const matches = known.filter((c) => c.toLowerCase().includes(query));

        let html = "";
        if (matches.length) {
          html += matches
            .map((c) => '<div class="cat-option" onclick="chooseCategory(\'' + c.replace(/'/g, "\\'") + '\')">' + escapeHtmlCat(c) + "</div>")
            .join("");
        } else if (!known.length) {
          html += '<div class="cat-option empty">No categories yet — type one below</div>';
        }

        const exactMatch = known.some((c) => c.toLowerCase() === query);
        if (query && !exactMatch) {
          html += '<div class="cat-option add-new" onclick="chooseCategory(\'' + query.replace(/'/g, "\\'") + '\', true)">+ Add new category: "' + escapeHtmlCat(input.value.trim()) + '"</div>';
        }

        dropdown.innerHTML = html;
        dropdown.classList.toggle("open", html.length > 0);
      }

      function chooseCategory(value, useOriginalCase) {
        const input = document.getElementById("fCategory");
        input.value = useOriginalCase ? input.value.trim() : value;
        document.getElementById("catDropdown").classList.remove("open");
      }

      function escapeHtmlCat(s) {
        return String(s).replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
      }

      document.addEventListener("click", (e) => {
        const combo = document.querySelector(".cat-combo");
        if (combo && !combo.contains(e.target)) {
          document.getElementById("catDropdown").classList.remove("open");
        }
      });

      // Categories that exist (boss-created) but have zero products yet, so
      // they still show up in the filter dropdown / new-product suggestions.
      let emptyCategories = [];

      async function loadCategories() {
        try {
          const res = await fetch("/api/admin/categories", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          if (data.success) {
            const used = new Set(products.map((p) => p.category || "Uncategorized"));
            emptyCategories = data.categories.filter((c) => !used.has(c));
          }
        } catch (err) {
          // Non-fatal — dropdown just falls back to product-derived categories only.
        }
      }

      async function loadProducts() {
        document.getElementById("productsLoading").classList.remove("hidden");
        document.getElementById("addProductFab").classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/products", {
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();

          if (!data.success) {
            if (res.status === 401) logout();
            return;
          }

          products = data.products;
          await loadCategories();
          populateCategoryFilter();
          renderProducts();
        } finally {
          document.getElementById("productsLoading").classList.add("hidden");
        }
      }

      async function createCategory() {
        const errEl = document.getElementById("categoryActionError");
        errEl.textContent = "";
        const name = (prompt("New category name (e.g. Keychains):") || "").trim();
        if (!name) return;

        try {
          const res = await fetch("/api/admin/categories", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ name }),
          });
          const data = await res.json();
          if (!data.success) {
            errEl.textContent = data.message || "Could not create category.";
            return;
          }
          await loadCategories();
          populateCategoryFilter();
          document.getElementById("productCategoryFilter").value = name;
          renderProducts();
        } catch (err) {
          errEl.textContent = "Network error — please try again.";
        }
      }

      async function seedCategoryProducts() {
        const errEl = document.getElementById("categoryActionError");
        errEl.textContent = "";
        if (!confirm("Add 10 blank sample products to every existing category? They'll be hidden (inactive, no image) until you edit each one and add a photo. Your current products are kept as-is.")) return;

        try {
          const res = await fetch("/api/admin/seed-category-products", {
            method: "POST",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (!data.success) {
            errEl.textContent = data.message || "Could not add sample products.";
            return;
          }
          products = data.products;
          await loadCategories();
          populateCategoryFilter();
          renderProducts();
          alert(data.message);
        } catch (err) {
          errEl.textContent = "Network error — please try again.";
        }
      }

      // Builds the category dropdown (with a live count per category) from
      // whatever is currently in `products`. Called once per load — the
      // dropdown's selected value is then read by renderProducts() on every
      // search/filter change, so we don't rebuild (and reset) it on every keystroke.
      function populateCategoryFilter() {
        const select = document.getElementById("productCategoryFilter");
        const prevValue = select.value;
        const counts = {};
        products.forEach((p) => {
          const cat = p.category || "Uncategorized";
          counts[cat] = (counts[cat] || 0) + 1;
        });
        (emptyCategories || []).forEach((c) => {
          if (!(c in counts)) counts[c] = 0;
        });
        const cats = Object.keys(counts).sort();
        select.innerHTML =
          '<option value="">All Categories (' + products.length + ")</option>" +
          cats.map((c) => '<option value="' + escapeHtml(c) + '">' + escapeHtml(c) + " (" + counts[c] + ")</option>").join("");
        if (cats.includes(prevValue)) select.value = prevValue;
      }

      function renderProducts() {
        const list = document.getElementById("productList");
        const searchTerm = (document.getElementById("productSearchInput").value || "").trim().toLowerCase();
        const categoryFilter = document.getElementById("productCategoryFilter").value;

        const filtered = products.filter((p) => {
          const matchesSearch = !searchTerm || (p.name || "").toLowerCase().includes(searchTerm);
          const matchesCategory = !categoryFilter || (p.category || "Uncategorized") === categoryFilter;
          return matchesSearch && matchesCategory;
        });

        document.getElementById("productFilterCount").textContent =
          "Showing " + filtered.length + " of " + products.length + " products";

        if (!filtered.length) {
          list.innerHTML = '<p class="empty-state">No products match this search/filter.</p>';
          return;
        }

        list.innerHTML = filtered
          .map((p) => {
            const sizeText = (p.sizes || []).length ? p.sizes.join(", ") : "—";
            const discountText = (p.discounts || []).length
              ? p.discounts.map((d) => d.minQty + "+ qty: " + d.percent + "% off").join(" · ")
              : "No bulk discounts";
            const thumb = p.image
              ? '<img src="' + escapeHtml(p.image) + '" style="width:56px;height:56px;border-radius:10px;object-fit:cover;margin-right:10px;flex-shrink:0;" />'
              : '<div style="width:56px;height:56px;border-radius:10px;background:var(--blush);display:flex;align-items:center;justify-content:center;font-size:24px;margin-right:10px;flex-shrink:0;">🎁</div>';

            return (
              '<div class="card product-card ' + (p.active ? "" : "inactive") + '" style="align-items:flex-start;">' +
                thumb +
                '<div class="info">' +
                  "<h3>" + escapeHtml(p.name) + "</h3>" +
                  '<div class="meta">' +
                    '<span class="badge">' + fmtINR(p.price) + "</span>" +
                    '<span class="badge">MOQ ' + (p.moq || 1) + "</span>" +
                    (p.onSale ? '<span class="badge" style="background:var(--success-bg);color:var(--success);">🔥 ' + p.salePercent + "% off" + saleTimerLabel(p) + '</span>' : "") +
                    (p.giftFor === "her" ? '<span class="badge" style="background:var(--gold-bg);color: var(--gold-soft);">👧 Gift for Her</span>' : "") +
                    (p.giftFor === "him" ? '<span class="badge" style="background:var(--warn-bg);color:var(--warn);">👦 Gift for Him</span>' : "") +
                    (p.giftFor === "both" ? '<span class="badge" style="background:rgba(167,120,255,0.14);color:#c4a8ff;">👫 Gift for Both</span>' : "") +
                    (p.hotProduct ? '<span class="badge" style="background:var(--danger-bg);color:var(--danger);">🔥 Hot Product</span>' : "") +
                    (p.popular ? '<span class="badge" style="background:var(--info-bg);color:var(--info);">⭐ Most Popular</span>' : "") +
                    (p.trending ? '<span class="badge" style="background:var(--warn-bg);color:var(--warn);">📈 Trending</span>' : "") +
                    (p.active ? "" : '<span class="badge" style="background:var(--danger-bg);color:var(--danger);">Inactive</span>') +
                    (p.hidden ? '<span class="badge" style="background:var(--warn-bg);color:var(--warn);">Hidden from store</span>' : "") +
                    "<br/>Sizes: " + escapeHtml(sizeText) + "<br/>" +
                    escapeHtml(discountText) +
                  "</div>" +
                "</div>" +
                '<div>' +
                  '<button class="btn small secondary" onclick="editProduct(' + p.id + ')">Edit</button>' +
                  '<button class="btn small secondary" onclick="toggleProductHidden(' + p.id + ', ' + !p.hidden + ')">' + (p.hidden ? "Show in Store" : "Hide from Store") + '</button>' +
                  (myCanDeleteProducts ? '<button class="btn small danger" onclick="deleteProduct(' + p.id + ')">Delete</button>' : "") +
                "</div>" +
              "</div>"
            );
          })
          .join("");
      }

      function escapeHtml(str) {
        return String(str)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      // Static (non-ticking) summary of a product's sale timer for the admin
      // list — good enough for a glance, doesn't need a live per-second clock.
      function saleTimerLabel(p) {
        if (!p.saleEndsAt) return "";
        const remain = Number(p.saleEndsAt) - Date.now();
        if (remain <= 0) return " · Sale Ended";
        const hrs = Math.floor(remain / 3600000);
        const mins = Math.floor((remain % 3600000) / 60000);
        return " · ends in " + hrs + "h " + mins + "m";
      }

      // ---------- PRODUCT MODAL ----------

      function openModal() {
        editingId = null;
        currentImages = [];
        document.getElementById("modalTitle").textContent = "Add Product";
        document.getElementById("productId").value = "";
        document.getElementById("fName").value = "";
        document.getElementById("fCategory").value = "";
        document.getElementById("fPrice").value = "";
        document.getElementById("fDescription").value = "";
        document.getElementById("fImageFiles").value = "";
        document.getElementById("fSizes").value = "";
        document.getElementById("fLowStockThreshold").value = 5;
        document.getElementById("productStockEditor").innerHTML = '';
        document.getElementById("fMoq").value = 1;
        document.getElementById("fOnSale").checked = false;
        document.getElementById("fSalePercent").value = "";
        document.getElementById("fSaleMessage").value = "";
        document.getElementById("fSaleEndsAt").value = "";
        document.getElementById("saleEndsAtNote").textContent = "";
        saleEndsAtMs = null;
        document.getElementById("fActive").checked = true;
        document.getElementById("fGiftFor").value = "";
        document.getElementById("fHotProduct").checked = false;
        document.getElementById("discountRows").innerHTML = "";
        document.getElementById("modalError").textContent = "";
        document.getElementById("imageSizeWarning").style.display = "none";
        document.getElementById("imagePreviewSizes").textContent = "";
        toggleSaleField();
        renderImagePreview();
        updatePricePreview();
        document.getElementById("modalOverlay").classList.add("open");
      }

      // Live preview of MOQ + bulk-discount pricing so the admin can see the
      // actual per-piece / total prices before hitting Save.
      function updatePricePreview() {
        const preview = document.getElementById("pricePreview");
        const price = Number(document.getElementById("fPrice").value);
        const moq = Number(document.getElementById("fMoq").value) || 1;

        if (!price || price <= 0) {
          preview.classList.add("hidden");
          preview.innerHTML = "";
          return;
        }

        const tiers = Array.from(document.querySelectorAll(".discount-row")).map((row) => ({
          minQty: Number(row.querySelector(".d-minqty").value),
          percent: Number(row.querySelector(".d-percent").value),
        })).filter((d) => d.minQty > 0 && d.percent > 0)
          .sort((a, b) => a.minQty - b.minQty);

        let html = '<div><strong>Minimum order:</strong> ' + moq + ' pc' + (moq > 1 ? "s" : "") +
          ' — \u20B9' + (price * moq).toLocaleString("en-IN") + ' at regular price (\u20B9' + price.toLocaleString("en-IN") + '/pc)</div>';

        if (tiers.length) {
          html += '<div style="margin-top:6px;"><strong>Bulk discount preview:</strong></div>';
          tiers.forEach((t) => {
            const perPiece = price * (1 - t.percent / 100);
            const total = perPiece * t.minQty;
            html += '<div>' + t.minQty + '+ pcs \u2192 ' + t.percent + '% off \u2192 \u20B9' +
              (Math.round(perPiece * 100) / 100).toLocaleString("en-IN") + '/pc (\u20B9' +
              Math.round(total).toLocaleString("en-IN") + ' for ' + t.minQty + ')</div>';
          });
        } else {
          html += '<div style="margin-top:6px; color: var(--gold-soft);">No bulk discount tiers set \u2014 add one above to preview its pricing.</div>';
        }

        preview.innerHTML = html;
        preview.classList.remove("hidden");
      }

      function toggleSaleField() {
        document.getElementById("saleFieldWrap").classList.toggle("hidden", !document.getElementById("fOnSale").checked);
      }

      // Formats a Date as the value a <input type="datetime-local"> expects,
      // in the browser's local time (so what the admin sees matches what they picked).
      function toLocalDatetimeInputValue(date) {
        const pad = (n) => String(n).padStart(2, "0");
        return (
          date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate()) +
          "T" + pad(date.getHours()) + ":" + pad(date.getMinutes())
        );
      }

      // Quick-pick buttons: 24h / 48h set an end time that many hours from now.
      // "No timer" (0) clears it — the sale then stays on until turned off by hand.
      function setSaleDuration(hours) {
        if (!hours) {
          saleEndsAtMs = null;
          document.getElementById("fSaleEndsAt").value = "";
          document.getElementById("saleEndsAtNote").textContent = "No timer — sale stays on until you turn it off.";
          return;
        }
        const end = new Date(Date.now() + hours * 60 * 60 * 1000);
        saleEndsAtMs = end.getTime();
        document.getElementById("fSaleEndsAt").value = toLocalDatetimeInputValue(end);
        document.getElementById("saleEndsAtNote").textContent = "Sale ends " + end.toLocaleString();
      }

      // Manual pick from the datetime-local input.
      function onSaleEndsAtChange() {
        const val = document.getElementById("fSaleEndsAt").value;
        if (!val) {
          saleEndsAtMs = null;
          document.getElementById("saleEndsAtNote").textContent = "";
          return;
        }
        saleEndsAtMs = new Date(val).getTime();
        document.getElementById("saleEndsAtNote").textContent = "Sale ends " + new Date(saleEndsAtMs).toLocaleString();
      }

      // Hard cap: no compressed photo is ever allowed to leave the browser
      // above this size, no matter how big the original was. Product pages
      // load 3 of these at once, so keeping each one small is what keeps
      // the storefront feeling fast.
      const MAX_IMAGE_BYTES = 600 * 1024; // 600 KB per photo

      // Loads a File into an <img> once (used by compressImage below so we
      // don't re-read/re-decode the file for every quality attempt).
      function loadImageFromFile(file) {
        return new Promise((resolve, reject) => {
          const img = new Image();
          const reader = new FileReader();
          reader.onload = () => { img.src = reader.result; };
          reader.onerror = reject;
          img.onload = () => resolve(img);
          img.onerror = reject;
          reader.readAsDataURL(file);
        });
      }

      // Draws the image onto a canvas at the given max dimension and returns
      // a JPEG data URL at the given quality.
      function drawToDataUrl(img, maxDim, quality) {
        let { width, height } = img;
        if (width > maxDim || height > maxDim) {
          if (width > height) { height = Math.round(height * (maxDim / width)); width = maxDim; }
          else { width = Math.round(width * (maxDim / height)); height = maxDim; }
        }
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        canvas.getContext("2d").drawImage(img, 0, 0, width, height);
        return canvas.toDataURL("image/jpeg", quality);
      }

      // Reads the picked file, resizes+compresses it on a canvas (phone
      // photos are often 3-8MB each — three of those blows past the
      // server's 15MB body limit and just hangs with no feedback), and
      // keeps stepping DOWN until the result is under MAX_IMAGE_BYTES — so
      // uploads are always capped, whatever the original size was.
      //
      // To keep the photo looking CLEAN (not muddy/blocky), the order here
      // matters: JPEG quality below ~0.6 is what makes photos look dirty
      // (blocky artifacts, smudged edges), while a smaller dimension at
      // good quality still looks sharp, just physically smaller. So we
      // shrink the dimension first (quality held reasonably high) and only
      // drop quality into the risky low range as a last resort.
      // Returns { dataUrl, size, hitFloor }.
      async function compressImage(file, maxDim, quality, maxBytes) {
        maxBytes = maxBytes || MAX_IMAGE_BYTES;
        const img = await loadImageFromFile(file);

        // Pass 1: keep quality clean (>=0.72), shrink dimension step by step.
        const dimSteps = [maxDim, 1400, 1280, 1120, 1000, 900, 800];
        const cleanQualitySteps = [quality, 0.78, 0.72];

        let best = null;
        for (const dim of dimSteps) {
          for (const q of cleanQualitySteps) {
            const dataUrl = drawToDataUrl(img, dim, q);
            const size = dataUrlSize(dataUrl);
            if (!best || size < best.size) best = { dataUrl, size };
            if (size <= maxBytes) {
              return { dataUrl, size, hitFloor: false };
            }
          }
        }

        // Pass 2 (rare — very busy/high-detail photo): dimension is already
        // small and still over cap, so now allow quality to drop further.
        const fallbackQualitySteps = [0.62, 0.5, 0.4];
        for (const dim of [800, 700, 640]) {
          for (const q of fallbackQualitySteps) {
            const dataUrl = drawToDataUrl(img, dim, q);
            const size = dataUrlSize(dataUrl);
            if (!best || size < best.size) best = { dataUrl, size };
            if (size <= maxBytes) {
              return { dataUrl, size, hitFloor: false };
            }
          }
        }

        // Even the smallest/lowest-quality attempt is still over the cap.
        // Use the best (smallest) result we found rather than blocking the
        // upload.
        return { dataUrl: best.dataUrl, size: best.size, hitFloor: true };
      }

      function formatSize(bytes) {
        return bytes >= 1024 * 1024
          ? (bytes / (1024 * 1024)).toFixed(1) + " MB"
          : Math.max(1, Math.round(bytes / 1024)) + " KB";
      }

      // Rough size of a base64 data URL in bytes (base64 is ~4/3 the size of
      // the original binary; strip the "data:image/...;base64," header first).
      function dataUrlSize(dataUrl) {
        const b64 = dataUrl.slice(dataUrl.indexOf(",") + 1);
        return Math.round(b64.length * 0.75);
      }

      document.getElementById("fImageFiles").addEventListener("change", async (e) => {
        const files = Array.from(e.target.files || []).slice(0, 3);
        const row = document.getElementById("imagePreviewRow");
        const warnEl = document.getElementById("imageSizeWarning");
        const sizesEl = document.getElementById("imagePreviewSizes");
        warnEl.style.display = "none";
        sizesEl.textContent = "";

        if (!files.length) { row.innerHTML = ""; return; }

        // Heads up before we even compress: a single photo over ~8MB (common
        // with modern phone cameras) is the main thing that makes uploads
        // feel stuck, so tell the admin up front — auto-resize below still
        // handles it, this is just visibility.
        const bigOriginals = files.filter((f) => f.size > 8 * 1024 * 1024);
        if (bigOriginals.length) {
          warnEl.style.display = "block";
          warnEl.textContent =
            "⚠️ " + bigOriginals.length + " photo(s) are quite large (" +
            bigOriginals.map((f) => formatSize(f.size)).join(", ") +
            "). Auto-resizing them now to fit under " + formatSize(MAX_IMAGE_BYTES) + " each so the site stays fast.";
        }

        // Process one at a time (not Promise.all) so we can show live,
        // per-photo "Compressing…" progress instead of one generic line —
        // no matter how small the file is, the admin sees it happening.
        currentImages = [];
        const results = []; // { originalSize, compressedSize, hitFloor }
        row.innerHTML = files
          .map((f, i) => '<div class="img-slot" id="imgSlot' + i + '" style="width:64px; height:64px; border-radius:8px; border:1px solid var(--line); background:var(--field); display:flex; align-items:center; justify-content:center; overflow:hidden;">' +
            '<span class="dm-mini-spinner"></span></div>').join("");

        try {
          for (let i = 0; i < files.length; i++) {
            sizesEl.textContent = "Compressing photo " + (i + 1) + " of " + files.length + "…";
            const { dataUrl: src, size: compressedSize, hitFloor } = await compressImage(files[i], 1600, 0.82, MAX_IMAGE_BYTES);
            currentImages.push(src);
            results.push({ originalSize: files[i].size, compressedSize, hitFloor });
            const slot = document.getElementById("imgSlot" + i);
            if (slot) {
              const caption = formatSize(files[i].size) + " → " + formatSize(compressedSize);
              slot.innerHTML = '<img src="' + src + '" style="width:100%; height:100%; object-fit:cover;" />';
              slot.title = caption + " — click to view full size";
              slot.onclick = () => openImageZoom(src, caption);
            }
          }
        } catch (err) {
          row.innerHTML = '<div class="hint" style="color:var(--danger);">Could not read one of the images. Try a different photo.</div>';
          sizesEl.textContent = "";
          return;
        }

        const originalTotal = results.reduce((sum, r) => sum + r.originalSize, 0);
        const compressedTotal = results.reduce((sum, r) => sum + r.compressedSize, 0);
        sizesEl.textContent =
          "✓ Ready to save — " + formatSize(compressedTotal) +
          (originalTotal > compressedTotal ? " (auto-resized from " + formatSize(originalTotal) + ")" : "") +
          " · capped at " + formatSize(MAX_IMAGE_BYTES) + "/photo · tap a photo to check clarity";

        // Extremely rare edge case: even at the lowest quality/dimension
        // step, a photo (usually a very busy/high-detail image) is still
        // over the cap. We still upload the smallest version we found —
        // just let the admin know so they're not surprised.
        const flooredCount = results.filter((r) => r.hitFloor).length;
        if (flooredCount) {
          warnEl.style.display = "block";
          warnEl.textContent =
            "⚠️ " + flooredCount + " photo(s) couldn't be brought fully under " + formatSize(MAX_IMAGE_BYTES) +
            " even at the lowest quality setting (unusually detailed image) — uploading the smallest version we could make. Try a simpler photo if possible.";
        }
      });

      // Opens the full-size lightbox so the admin can actually judge
      // sharpness/blur — a 64px thumbnail is too small for that.
      function openImageZoom(src, caption) {
        document.getElementById("imgZoomTarget").src = src;
        document.getElementById("imgZoomCaption").textContent = caption || "";
        document.getElementById("imgZoomOverlay").classList.add("open");
      }
      function closeImageZoom() {
        document.getElementById("imgZoomOverlay").classList.remove("open");
        document.getElementById("imgZoomTarget").src = "";
      }

      function renderImagePreview() {
        const row = document.getElementById("imagePreviewRow");
        row.innerHTML = currentImages
          .map((src, i) => '<div class="img-slot" id="imgSlot' + i + '" style="width:64px; height:64px; border-radius:8px; border:1px solid var(--line); overflow:hidden;">' +
            '<img src="' + src + '" style="width:100%; height:100%; object-fit:cover;" /></div>')
          .join("");
        currentImages.forEach((src, i) => {
          const slot = document.getElementById("imgSlot" + i);
          if (slot) {
            slot.title = "Click to view full size";
            slot.onclick = () => openImageZoom(src, "Photo " + (i + 1));
          }
        });
      }

      function closeModal() {
        document.getElementById("modalOverlay").classList.remove("open");
      }

      function getProductSizesFromInput(id) {
        return (document.getElementById(id).value || "").split(",").map(s => s.trim()).filter(Boolean);
      }

      function renderProductStockEditor(stock = {}) {
        const wrap = document.getElementById("productStockEditor");
        if (!wrap) return;
        if (!Object.keys(stock).length) {
          wrap.querySelectorAll(".product-stock-input").forEach(input => { stock[input.dataset.size || "__default"] = Math.max(0, Math.floor(Number(input.value) || 0)); });
        }
        const sizes = getProductSizesFromInput("fSizes");
        if (!sizes.length) {
          const value = Number(stock.__default ?? stock.default ?? stock.stockQty ?? 0);
          wrap.innerHTML = '<div class="dm-stock-item"><label>Default Stock</label><input type="number" min="0" step="1" class="product-stock-input" data-size="" value="' + (Number.isInteger(value) && value >= 0 ? value : 0) + '" /></div>';
          return;
        }
        wrap.innerHTML = sizes.map(size => {
          const value = Number(stock[size] ?? 0);
          return '<div class="dm-stock-item"><label>' + escapeHtml(size) + ' Stock</label><input type="number" min="0" step="1" class="product-stock-input" data-size="' + escapeHtml(size) + '" value="' + (Number.isInteger(value) && value >= 0 ? value : 0) + '" /></div>';
        }).join("");
      }

      function collectProductStock() {
        const sizes = getProductSizesFromInput("fSizes");
        const inputs = Array.from(document.querySelectorAll("#productStockEditor .product-stock-input"));
        const variantStock = {};
        let stockQty = 0;
        inputs.forEach(input => {
          const value = Math.max(0, Math.floor(Number(input.value) || 0));
          const size = input.dataset.size || "";
          if (size) variantStock[size] = value;
          else stockQty = value;
        });
        return { stockQty, variantStock };
      }

      function editProduct(id) {
        const p = products.find((x) => x.id === id);
        if (!p) return;

        editingId = id;
        currentImages = Array.isArray(p.images) && p.images.length ? p.images : (p.image ? [p.image] : []);
        document.getElementById("modalTitle").textContent = "Edit Product";
        document.getElementById("productId").value = p.id;
        document.getElementById("fName").value = p.name || "";
        document.getElementById("fCategory").value = p.category || "";
        document.getElementById("fPrice").value = p.price || 0;
        document.getElementById("fDescription").value = p.description || "";
        document.getElementById("fImageFiles").value = "";
        document.getElementById("fSizes").value = (p.sizes || []).join(", ");
        document.getElementById("fLowStockThreshold").value = Number(p.lowStockThreshold ?? 5);
        renderProductStockEditor((p.sizes || []).length ? (p.variantStock || {}) : { stockQty: p.stockQty || 0 });
        document.getElementById("fMoq").value = p.moq || 1;
        document.getElementById("fOnSale").checked = Boolean(p.onSale);
        document.getElementById("fSalePercent").value = p.salePercent || "";
        document.getElementById("fSaleMessage").value = p.saleMessage || "";
        if (p.saleEndsAt) {
          saleEndsAtMs = Number(p.saleEndsAt);
          document.getElementById("fSaleEndsAt").value = toLocalDatetimeInputValue(new Date(saleEndsAtMs));
          const remain = saleEndsAtMs - Date.now();
          document.getElementById("saleEndsAtNote").textContent =
            remain > 0 ? "Sale ends " + new Date(saleEndsAtMs).toLocaleString() : "This timer has already ended.";
        } else {
          saleEndsAtMs = null;
          document.getElementById("fSaleEndsAt").value = "";
          document.getElementById("saleEndsAtNote").textContent = p.onSale ? "No timer — sale stays on until you turn it off." : "";
        }
        document.getElementById("fActive").checked = p.active !== false;
        document.getElementById("fGiftFor").value = p.giftFor || "";
        document.getElementById("fHotProduct").checked = Boolean(p.hotProduct);
        document.getElementById("modalError").textContent = "";
        document.getElementById("imageSizeWarning").style.display = "none";
        document.getElementById("imagePreviewSizes").textContent = "";
        toggleSaleField();
        renderImagePreview();

        const rows = document.getElementById("discountRows");
        rows.innerHTML = "";
        (p.discounts || []).forEach((d) => addDiscountRow(d.minQty, d.percent));
        updatePricePreview();

        document.getElementById("modalOverlay").classList.add("open");
      }

      function addDiscountRow(minQty, percent) {
        const rows = document.getElementById("discountRows");
        const row = document.createElement("div");
        row.className = "discount-row";
        row.innerHTML =
          '<input type="number" min="1" placeholder="Min qty" class="d-minqty" value="' + (minQty || "") + '" oninput="updatePricePreview()" />' +
          '<input type="number" min="1" max="100" placeholder="% off" class="d-percent" value="' + (percent || "") + '" oninput="updatePricePreview()" />' +
          '<button type="button" onclick="this.parentElement.remove(); updatePricePreview();">✕</button>';
        rows.appendChild(row);
        updatePricePreview();
      }

      async function saveProduct() {
        const errorEl = document.getElementById("modalError");
        errorEl.textContent = "";

        const name = document.getElementById("fName").value.trim();
        const price = document.getElementById("fPrice").value;
        const moq = document.getElementById("fMoq").value;

        if (!name) { errorEl.textContent = "Product name is required."; return; }
        if (price === "" || Number(price) < 0) { errorEl.textContent = "Enter a valid price."; return; }
        if (!moq || Number(moq) < 1) { errorEl.textContent = "MOQ must be at least 1."; return; }

        const discounts = Array.from(document.querySelectorAll(".discount-row")).map((row) => ({
          minQty: Number(row.querySelector(".d-minqty").value),
          percent: Number(row.querySelector(".d-percent").value),
        })).filter((d) => d.minQty > 0 && d.percent > 0);

        const onSale = document.getElementById("fOnSale").checked;
        if (onSale && !Number(document.getElementById("fSalePercent").value)) {
          errorEl.textContent = "Enter a sale percent greater than 0.";
          return;
        }

        const productStock = collectProductStock();
        const lowStockThreshold = Math.max(0, Math.floor(Number(document.getElementById("fLowStockThreshold").value) || 0));

        const payload = {
          name,
          category: document.getElementById("fCategory").value.trim(),
          description: document.getElementById("fDescription").value.trim(),
          images: currentImages,
          price: Number(price),
          sizes: document.getElementById("fSizes").value,
          stockQty: productStock.stockQty,
          variantStock: productStock.variantStock,
          lowStockThreshold,
          moq: Number(moq),
          discounts,
          onSale,
          salePercent: Number(document.getElementById("fSalePercent").value) || 0,
          saleMessage: document.getElementById("fSaleMessage").value.trim(),
          saleEndsAt: onSale ? saleEndsAtMs : null,
          active: document.getElementById("fActive").checked,
          giftFor: document.getElementById("fGiftFor").value,
          hotProduct: document.getElementById("fHotProduct").checked,
        };

        const isEdit = Boolean(editingId);
        const url = isEdit ? "/api/admin/products/" + editingId : "/api/admin/products";
        const method = isEdit ? "PUT" : "POST";

        const saveBtn = document.getElementById("saveProductBtn");
        const saveBtnText = document.getElementById("saveProductBtnText");
        if (saveBtn.disabled) return; // already saving — ignore extra clicks
        saveBtn.disabled = true;
        saveBtn.classList.add("btn-loading");
        saveBtnText.textContent = "Saving…";

        try {
          const res = await fetch(url, {
            method,
            headers: {
              "Content-Type": "application/json",
              Authorization: "Bearer " + token,
            },
            body: JSON.stringify(payload),
          });
          const data = await res.json();

          if (!data.success) {
            errorEl.textContent = data.message || "Could not save product.";
            return;
          }

          closeModal();
          loadProducts();
          if (data.pending) alert(data.message || "Change submitted — it needs the boss's approval before it goes live.");
        } catch (err) {
          errorEl.textContent = "Network error. Try again.";
        } finally {
          saveBtn.disabled = false;
          saveBtn.classList.remove("btn-loading");
          saveBtnText.textContent = "Save Product";
        }
      }

      // Reversible visibility toggle — available to every admin (boss and
      // every sub-admin, regardless of canDeleteProducts), since hiding a
      // product from the storefront isn't destructive the way Delete is.
      async function toggleProductHidden(id, nextHidden) {
        try {
          const res = await fetch("/api/admin/products/" + id + "/hidden", {
            method: "PUT",
            headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
            body: JSON.stringify({ hidden: nextHidden }),
          });
          const data = await res.json();
          if (data.success) loadProducts();
          else alert(data.message || "Unable to update visibility.");
        } catch (err) {
          alert("Network error. Try again.");
        }
      }

      async function deleteProduct(id) {
        if (!confirm("Delete this product? This cannot be undone.")) return;

        try {
          const res = await fetch("/api/admin/products/" + id, {
            method: "DELETE",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (data.success) loadProducts();
          else if (res.status === 403) alert(data.message || "Only the boss account can delete products.");
        } catch (err) {
          alert("Network error. Try again.");
        }
      }

      // ---------- ORDERS ----------

      const STATUS_OPTIONS = ["New", "Processing", "Shipped", "Delivered", "Cancelled"];

      async function loadOrders(page) {
        page = page || 1;
        document.getElementById("ordersLoading").classList.remove("hidden");
        try {
          const [listRes, statsRes] = await Promise.all([
            fetch("/api/admin/orders?page=" + page + "&limit=50", { headers: { Authorization: "Bearer " + token } }),
            fetch("/api/admin/orders/stats", { headers: { Authorization: "Bearer " + token } }),
          ]);
          const data = await listRes.json();
          const stats = await statsRes.json();

          if (!data.success) {
            if (listRes.status === 401) logout();
            return;
          }

          orders = data.orders;
          renderOrderStats(stats.success ? stats : null);
          renderOrders();
          renderPager(document.getElementById("ordersPager"), data, loadOrders);
        } finally {
          document.getElementById("ordersLoading").classList.add("hidden");
        }
      }

      // Stats come from /api/admin/orders/stats (computed over ALL orders
      // server-side) rather than from the `orders` array in memory, since
      // that array is now just the current page of the paginated list —
      // deriving totals from it would silently show numbers for one page
      // instead of the whole store.
      function renderOrderStats(stats) {
        if (!stats) {
          document.getElementById("orderStats").innerHTML = "";
          return;
        }
        document.getElementById("orderStats").innerHTML =
          statCard("Total Orders", stats.total) +
          statCard("New / Unfulfilled", stats.newCount) +
          statCard("Cancelled", stats.cancelledCount) +
          statCard("Revenue (COD)", fmtINR(stats.revenue));
      }

      function statCard(label, value) {
        return (
          '<div class="stat-card">' +
            '<div class="stat-label">' + escapeHtml(String(label)) + "</div>" +
            '<div class="stat-value">' + escapeHtml(String(value)) + "</div>" +
          "</div>"
        );
      }

      function renderOrders() {
        const list = document.getElementById("orderList");
        if (!orders.length) {
          list.innerHTML = '<p class="empty-state">No orders yet — they will show up here as customers check out.</p>';
          return;
        }

        list.innerHTML = orders
          .map((o) => {
            const itemsText = (o.items || [])
              .map((it) => it.name + (it.size ? " (" + it.size + ")" : "") + " × " + it.qty)
              .join(", ");

            const statusClass = "status-" + String(o.status || "New").toLowerCase();
            const isCancelled = o.status === "Cancelled";
            const lockReactivate = isCancelled && role !== "boss";
            const statusOptions = STATUS_OPTIONS
              .map((s) => '<option value="' + s + '" ' + (s === o.status ? "selected" : "") + ">" + s + "</option>")
              .join("");

            const sellerFulfilment = Array.isArray(o.sellerFulfilment) ? o.sellerFulfilment : [];
            const sellerBlock = sellerFulfilment.length ? '<div style="margin-top:10px;padding:10px 0;border-top:1px solid var(--line);">' +
              '<div style="font-size:11px;font-weight:800;color:var(--muted);margin-bottom:7px;">SELLER FULFILMENT</div>' +
              sellerFulfilment.map(r => {
                const declined = r.decision === 'declined';
                const decisionText = r.decision === 'accepted' ? 'Accepted' : r.decision === 'taken_over' ? 'Admin Takeover' : declined ? 'Declined' : 'Pending';
                const takeover = declined ? '<button type="button" class="btn small secondary" style="margin-left:6px;" onclick="takeoverSellerOrder(' + o.id + ',' + r.sellerId + ')">Take Over</button>' : '';
                const active = r.decision === 'accepted' || r.decision === 'taken_over';
                const stageSelect = active ? '<select class="status-select" style="margin-left:6px;" onchange="adminUpdateSellerStage(' + o.id + ',' + r.sellerId + ',this.value)">' + ['Processing','Ready to Ship','Shipped','Out for Delivery','Delivered'].map(st => '<option value="' + st + '" ' + (st === (r.stage || 'Processing') ? 'selected' : '') + '>' + st + '</option>').join('') + '</select>' : '';
                return '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin:5px 0;padding:7px 9px;border:1px solid var(--line);border-radius:9px;">' +
                  '<span><strong>' + escapeHtml(r.sellerName || 'Seller') + '</strong> · ' + escapeHtml(decisionText) + ' · ' + escapeHtml(r.stage || 'Order Received') + '</span>' + '<span>' + stageSelect + takeover + '</span>' + '</div>';
              }).join('') + '</div>' : '';

            const totalHtml = isCancelled
              ? '<span class="order-total" style="text-decoration:line-through;color:var(--muted);">' + fmtINR(o.total) + '</span>' +
                '<span style="font-size:11px;color:var(--danger);margin-left:6px;">not counted</span>'
              : '<span class="order-total">' + fmtINR(o.total) + "</span>";

            // Payment confirmation is manual for now (customer sends the
            // WhatsApp message, admin checks it and clicks Mark as Paid).
            // This is the same field/endpoint an online payment gateway
            // will flip automatically once one is added later.
            const isPaid = o.paymentStatus === "paid";
            const paymentHtml = isPaid
              ? '<span class="badge status-delivered" title="' + (o.paidAt ? escapeHtml(formatDate(o.paidAt)) : "") + '">✓ Paid</span>'
              : '<span class="badge status-new">Payment pending</span>' +
                '<button type="button" class="btn small secondary" onclick="markOrderPaid(' + o.id + ')" style="margin-left:6px;">Mark as Paid</button>';

            return (
              '<div class="card order-card">' +
                '<div class="order-head">' +
                  '<span class="order-num">' + escapeHtml(o.orderNumber) + "</span>" +
                  '<span class="order-date">' + formatDate(o.createdAt) + "</span>" +
                "</div>" +
                '<div class="meta">' +
                  escapeHtml(o.customer ? o.customer.name : "—") + " · " + escapeHtml(o.customer ? o.customer.phone : "—") +
                "</div>" +
                (o.customer && o.customer.address
                  ? '<div class="meta" style="font-size:12px;">📍 ' + escapeHtml(o.customer.address) + "</div>"
                  : "") +
                '<div class="order-items">' + escapeHtml(itemsText) + "</div>" +
                (o.gift && o.gift.isGift
                  ? '<div class="meta" style="font-size:12px;margin-top:4px;">🎁 Gift order' +
                    (o.gift.hidePrice ? ' · price hidden from recipient' : '') +
                    (o.gift.recipientName ? ' · To: ' + escapeHtml(o.gift.recipientName) : '') +
                    (o.gift.message ? '<div style="margin-top:2px;color:var(--muted);">“' + escapeHtml(o.gift.message) + '”</div>' : '') +
                    '</div>'
                  : '') +
                sellerBlock +
                '<div class="order-foot">' +
                  '<span class="badge gold">COD</span>' +
                  paymentHtml +
                  totalHtml +
                  '<select class="status-select ' + statusClass + '" ' +
                    (lockReactivate ? 'disabled title="Only the main admin can re-activate a cancelled order"' : "") +
                    ' onchange="updateOrderStatus(' + o.id + ', this.value, this)">' +
                    statusOptions +
                  "</select>" +
                "</div>" +
              "</div>"
            );
          })
          .join("");
      }

      async function adminUpdateSellerStage(orderId, sellerId, stage) {
        try {
          const res = await fetch("/api/admin/orders/" + orderId + "/seller-stage", { method:"PUT", headers:{"Content-Type":"application/json", Authorization:"Bearer "+token}, body:JSON.stringify({ sellerId, stage }) });
          const data = await res.json();
          if (!data.success) { alert(data.message || "Could not update the fulfilment stage."); return; }
          await loadOrders();
        } catch (e) { alert("Network error while updating the fulfilment stage."); }
      }

      async function takeoverSellerOrder(orderId, sellerId) {
        if (!confirm("Take over this seller's declined fulfilment? The customer will continue to see a normal order.")) return;
        try {
          const res = await fetch("/api/admin/orders/" + orderId + "/seller-takeover", { method:"PUT", headers:{"Content-Type":"application/json", Authorization:"Bearer "+token}, body:JSON.stringify({ sellerId }) });
          const data = await res.json();
          if (!data.success) { alert(data.message || "Could not take over the order."); return; }
          await loadOrders();
        } catch (e) { alert("Network error while taking over the seller fulfilment."); }
      }

      async function markOrderPaid(id) {
        try {
          const res = await fetch("/api/admin/orders/" + id + "/mark-paid", {
            method: "PUT",
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (data.success) {
            const o = orders.find((x) => x.id === id);
            if (o) {
              o.paymentStatus = data.order.paymentStatus;
              o.paidAt = data.order.paidAt;
            }
            renderOrders();
          } else {
            alert(data.message || "Could not update payment status.");
          }
        } catch (err) {
          alert("Network error updating payment status.");
        }
      }

      async function updateOrderStatus(id, status, selectEl) {
        const o = orders.find((x) => x.id === id);
        const prevStatus = o ? o.status : null;

        // Ask for confirmation before cancelling an order.
        if (status === "Cancelled") {
          const ok = confirm("Are you sure you want to cancel this order?\n\nIts amount will stop counting towards revenue. Only the main admin can re-activate it later.");
          if (!ok) {
            if (selectEl && prevStatus) selectEl.value = prevStatus; // revert the dropdown
            return;
          }
        }

        try {
          const res = await fetch("/api/admin/orders/" + id + "/status", {
            method: "PUT",
            headers: {
              "Content-Type": "application/json",
              Authorization: "Bearer " + token,
            },
            body: JSON.stringify({ status }),
          });
          const data = await res.json();
          if (data.success) {
            if (o) o.status = status;
            fetch("/api/admin/orders/stats", { headers: { Authorization: "Bearer " + token } })
              .then((r) => r.json())
              .then((stats) => renderOrderStats(stats.success ? stats : null));
            renderOrders();
          } else {
            alert(data.message || "Could not update this order.");
            if (selectEl && prevStatus) selectEl.value = prevStatus;
          }
        } catch (err) {
          alert("Network error. Try again.");
          if (selectEl && prevStatus) selectEl.value = prevStatus;
        }
      }

      function formatDate(iso) {
        try {
          return new Date(iso).toLocaleString("en-IN", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
        } catch (err) {
          return "";
        }
      }

      // ---------- SALE BANNER ----------

      async function loadSaleBanner() {
        try {
          const res = await fetch("/api/settings");
          const data = await res.json();
          if (data.success && data.settings.saleBanner) {
            document.getElementById("bannerEnabled").checked = Boolean(data.settings.saleBanner.enabled);
            document.getElementById("bannerText").value = data.settings.saleBanner.text || "";
          }
        } catch (err) {
          // non-fatal — leave fields as-is
        }
      }

      async function saveSaleBanner() {
        const errorEl = document.getElementById("bannerError");
        errorEl.textContent = "";
        try {
          const res = await fetch("/api/admin/settings/sale-banner", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({
              enabled: document.getElementById("bannerEnabled").checked,
              text: document.getElementById("bannerText").value.trim(),
            }),
          });
          const data = await res.json();
          if (!data.success) errorEl.textContent = data.message || "Could not save banner.";
        } catch (err) {
          errorEl.textContent = "Network error. Try again.";
        }
      }

      // ---------- THEME SWITCHER ----------

      let savedTheme = "normal"; // what's actually live on the site right now
      let selectedTheme = "normal"; // what admin has clicked, not yet applied

      async function loadTheme() {
        try {
          const res = await fetch("/api/settings");
          const data = await res.json();
          savedTheme = (data.success && data.settings.theme) || "normal";
          selectedTheme = savedTheme;
          updateThemeSelection();
        } catch (err) {
          // non-fatal — leave the default selection
        }
      }

      function updateThemeSelection() {
        document.querySelectorAll(".theme-card").forEach((card) => {
          card.classList.toggle("active", card.dataset.theme === selectedTheme);
        });
        document.getElementById("applyThemeBtn").style.display = selectedTheme !== savedTheme ? "block" : "none";
      }

      document.querySelectorAll(".theme-card").forEach((card) => {
        card.addEventListener("click", () => {
          selectedTheme = card.dataset.theme;
          updateThemeSelection();
        });
      });

      async function applyTheme() {
        const errorEl = document.getElementById("themeError");
        const btn = document.getElementById("applyThemeBtn");
        errorEl.textContent = "";
        btn.disabled = true;
        btn.textContent = "Applying...";
        try {
          const res = await fetch("/api/admin/settings/theme", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ theme: selectedTheme }),
          });
          const data = await res.json();
          if (data.success) {
            savedTheme = selectedTheme;
            updateThemeSelection();
          } else {
            errorEl.textContent = data.message || "Could not save theme.";
          }
        } catch (err) {
          errorEl.textContent = "Network error. Try again.";
        } finally {
          btn.disabled = false;
          btn.textContent = "Apply Selected Theme";
        }
      }

      // ---------- GIFT CODES (boss only) ----------
      async function loadGiftCodes() {
        const body = document.getElementById("giftCodesBody");
        if (!body) return;
        body.innerHTML = '<tr><td colspan="7" style="padding:20px;text-align:center;color:var(--muted);">Loading gift codes...</td></tr>';
        try {
          const res = await fetch("/api/admin/gift-codes", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          if (!res.ok || !data.success) throw new Error(data.message || "Could not load gift codes.");
          if (!data.codes.length) { body.innerHTML = '<tr><td colspan="7" style="padding:20px;text-align:center;color:var(--muted);">No gift codes created yet.</td></tr>'; return; }
          body.innerHTML = data.codes.map(g => {
            const discount = g.type === "fixed" ? "₹" + fmtINR(g.value) : g.value + "%";
            const usage = (g.usedCount || 0) + (g.usageLimit ? " / " + g.usageLimit : " / ∞");
            const validity = (g.startsAt ? new Date(g.startsAt).toLocaleString() : "Now") + " → " + (g.expiresAt ? new Date(g.expiresAt).toLocaleString() : "No expiry");
            return '<tr style="border-top:1px solid var(--blush-line);">' +
              '<td style="padding:12px 14px;font-weight:800;letter-spacing:.06em;">' + escapeHtml(g.code) + '</td>' +
              '<td style="padding:12px 14px;">' + escapeHtml(discount) + (g.maxDiscount ? ' <span style="color:var(--muted);">(max ₹' + fmtINR(g.maxDiscount) + ')</span>' : '') + '</td>' +
              '<td style="padding:12px 14px;">₹' + fmtINR(g.minOrder || 0) + '</td>' +
              '<td style="padding:12px 14px;">' + escapeHtml(usage) + '</td>' +
              '<td style="padding:12px 14px;font-size:12px;">' + escapeHtml(validity) + '</td>' +
              '<td style="padding:12px 14px;">' + (g.active ? '🟢 Active' : '⚪ Disabled') + '</td>' +
              '<td style="padding:12px 14px;display:flex;gap:6px;">' +
                '<button class="btn small secondary" onclick="toggleGiftCode(' + Number(g.id) + ',' + (!g.active) + ')">' + (g.active ? 'Disable' : 'Enable') + '</button>' +
                '<button class="btn small danger" onclick="deleteGiftCode(' + Number(g.id) + ')">Delete</button>' +
              '</td></tr>';
          }).join('');
        } catch (e) { body.innerHTML = '<tr><td colspan="7" style="padding:20px;color:#b42318;">' + escapeHtml(e.message) + '</td></tr>'; }
      }

      async function createGiftCode() {
        const err = document.getElementById("giftCodeError"); err.textContent = "";
        const body = {
          code: document.getElementById("gcCode").value,
          type: document.getElementById("gcType").value,
          value: Number(document.getElementById("gcValue").value),
          minOrder: Number(document.getElementById("gcMinOrder").value || 0),
          maxDiscount: Number(document.getElementById("gcMaxDiscount").value || 0),
          usageLimit: Number(document.getElementById("gcUsageLimit").value || 0),
          perCustomerLimit: Number(document.getElementById("gcPerCustomerLimit").value || 0),
          startsAt: document.getElementById("gcStartsAt").value || "",
          expiresAt: document.getElementById("gcExpiresAt").value || "",
        };
        try {
          const res = await fetch("/api/admin/gift-codes", { method:"POST", headers:{"Content-Type":"application/json",Authorization:"Bearer "+token}, body:JSON.stringify(body) });
          const data = await res.json();
          if (!res.ok || !data.success) { err.textContent = data.message || "Could not create gift code."; return; }
          ["gcCode","gcValue","gcMinOrder","gcMaxDiscount","gcUsageLimit","gcPerCustomerLimit","gcStartsAt","gcExpiresAt"].forEach(id => document.getElementById(id).value = "");
          await loadGiftCodes();
        } catch (e) { err.textContent = "Network error. Try again."; }
      }

      async function toggleGiftCode(id, active) {
        try { const res = await fetch("/api/admin/gift-codes/"+id,{method:"PATCH",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token},body:JSON.stringify({active})}); const data=await res.json(); if(!res.ok||!data.success) throw new Error(data.message||"Could not update code."); await loadGiftCodes(); } catch(e){ alert(e.message); }
      }
      async function deleteGiftCode(id) {
        if (!confirm("Delete this gift code? Existing orders using it will remain unchanged.")) return;
        try { const res=await fetch("/api/admin/gift-codes/"+id,{method:"DELETE",headers:{Authorization:"Bearer "+token}}); const data=await res.json(); if(!res.ok||!data.success) throw new Error(data.message||"Could not delete code."); await loadGiftCodes(); } catch(e){ alert(e.message); }
      }

      // ---------- ADMINS (boss only) ----------

      async function loadAdmins() {
        document.getElementById("adminsLoading").classList.remove("hidden");
        try {
          const res = await fetch("/api/admin/admins", {
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (!data.success) {
            if (res.status === 401) logout();
            return;
          }
          admins = data.admins;
          renderAdmins();
          loadAdminRoles();
          loadLoginHistory();
        } finally {
          document.getElementById("adminsLoading").classList.add("hidden");
        }
      }

      function formatLoginTime(iso) {
        if (!iso) return "";
        const d = new Date(iso);
        return d.toLocaleString();
      }

      async function loadLoginHistory() {
        try {
          const res = await fetch("/api/admin/login-history", {
            headers: { Authorization: "Bearer " + token },
          });
          const data = await res.json();
          if (!data.success) return;
          renderLoginHistory(data.history);
        } catch (err) {
          // Silent — this is a secondary panel, don't block the admins tab on it.
        }
      }

      function renderLoginHistory(history) {
        const el = document.getElementById("loginHistoryList");
        if (!history.length) {
          el.innerHTML = '<p class="empty-state">No login activity yet.</p>';
          return;
        }
        el.innerHTML = history
          .slice(0, 30)
          .map((h) => (
            '<div style="display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid var(--blush-line);">' +
              '<span>' + (h.success ? "" : "&#10060; ") + escapeHtml(h.username) + (h.role === "boss" ? " (boss)" : "") + "</span>" +
              '<span style="color:var(--muted);">' + escapeHtml(h.ip) + "</span>" +
              '<span style="color:var(--muted);">' + escapeHtml(formatLoginTime(h.at)) + "</span>" +
            "</div>"
          ))
          .join("");
      }

      function renderAdmins() {
        const list = document.getElementById("adminList");
        if (!admins.length) {
          list.innerHTML = '<p class="empty-state">No sub-admins yet — add one above.</p>';
          return;
        }
        list.innerHTML = admins
          .map((a) => {
            const lastLoginText = a.lastLogin
              ? "Last login: " + escapeHtml(a.lastLogin.ip) + " · " + escapeHtml(formatLoginTime(a.lastLogin.at))
              : "Never logged in";
            return (
              '<div class="card customer-card">' +
                '<div>' +
                  '<div class="name">' + escapeHtml(a.username) + (a.role === "boss" ? " (boss)" : "") +
                    (a.designation ? ' <span class="badge">' + escapeHtml(a.designation) + "</span>" : "") + "</div>" +
                  '<div class="phone">' + (a.locked ? "🔒 Locked (" + a.failedAttempts + " failed attempts)" : "Active") + "</div>" +
                  '<div class="phone">📧 ' + escapeHtml(a.email || "No email set") + "</div>" +
                  '<div class="phone">📱 ' + escapeHtml(a.phone || "No phone set") + "</div>" +
                  '<div class="phone">' + lastLoginText + "</div>" +
                  '<div class="phone">' + (a.canDeleteProducts ? "Can delete products" : "Cannot delete products") + "</div>" +
                "</div>" +
                '<div style="display:flex; gap:6px; flex-wrap:wrap; justify-content:flex-end;">' +
                  (a.role === "boss" ? "" :
                    (a.locked ? '<button class="btn small" onclick="unlockAdmin(\'' + a.username + '\')">Unlock</button>' : "") +
                    '<button class="btn small secondary" onclick="toggleDeletePermission(\'' + a.username + '\', ' + !a.canDeleteProducts + ')">' +
                      (a.canDeleteProducts ? "Revoke delete access" : "Allow delete access") +
                    "</button>" +
                    '<button class="btn small secondary" onclick="editAdminCredentials(\'' + a.username + '\')">Edit login</button>' +
                    '<button class="btn small secondary" onclick="editAdminContact(\'' + a.username + '\')">Edit contact</button>' +
                    '<button class="btn small danger" onclick="deleteAdmin(\'' + a.username + '\')">Remove</button>'
                  ) +
                "</div>" +
              "</div>"
            );
          })
          .join("");
      }

      // ---------- ADMIN ROLES (boss / main "om" account only) ----------
      let adminRoles = [];

      async function loadAdminRoles() {
        try {
          const res = await fetch("/api/admin/roles", { headers: { Authorization: "Bearer " + token } });
          const data = await res.json();
          if (!data.success) return;
          adminRoles = data.roles || [];
          const sel = document.getElementById("newAdminDesignation");
          const prev = sel.value;
          sel.innerHTML = adminRoles.map((r) => '<option value="' + escapeHtml(r) + '">' + escapeHtml(r) + '</option>').join("");
          if (adminRoles.includes(prev)) sel.value = prev;
        } catch (err) {
          // non-fatal
        }
      }

      async function addAdminRole() {
        const input = document.getElementById("newRoleName");
        const errEl = document.getElementById("roleError");
        errEl.textContent = "";
        const name = input.value.trim();
        if (!name) { errEl.textContent = "Enter a role name."; return; }
        try {
          const res = await fetch("/api/admin/roles", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ name }),
          });
          const data = await res.json();
          if (!data.success) { errEl.textContent = data.message || "Could not add role."; return; }
          adminRoles = data.roles || [];
          const sel = document.getElementById("newAdminDesignation");
          sel.innerHTML = adminRoles.map((r) => '<option value="' + escapeHtml(r) + '">' + escapeHtml(r) + '</option>').join("");
          sel.value = name;      // select the newly added role
          input.value = "";
        } catch (err) {
          errEl.textContent = "Network error. Try again.";
        }
      }

      async function createAdmin() {
        const errorEl = document.getElementById("adminError");
        errorEl.textContent = "";
        const username = document.getElementById("newAdminUsername").value.trim();
        const password = document.getElementById("newAdminPassword").value;
        const email = document.getElementById("newAdminEmail").value.trim();
        const phone = document.getElementById("newAdminPhone").value.trim();
        const designation = document.getElementById("newAdminDesignation").value;
        const canDeleteProducts = document.getElementById("newAdminCanDelete").checked;

        if (!username || !password || !email || !phone) { errorEl.textContent = "Enter username, password, registered email and phone number."; return; }
        if (!/^\S+@\S+\.\S+$/.test(email)) { errorEl.textContent = "Enter a valid email address."; return; }
        if (phone.replace(/\D/g, "").length < 7) { errorEl.textContent = "Enter a valid phone number."; return; }

        try {
          const res = await fetch("/api/admin/admins", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ username, password, email, phone, designation, canDeleteProducts }),
          });
          const data = await res.json();
          if (!data.success) { errorEl.textContent = data.message || "Could not create admin."; return; }

          document.getElementById("newAdminUsername").value = "";
          document.getElementById("newAdminPassword").value = "";
          document.getElementById("newAdminEmail").value = "";
          document.getElementById("newAdminPhone").value = "";
          document.getElementById("newAdminCanDelete").checked = false;
          loadAdmins();
        } catch (err) {
          errorEl.textContent = "Network error. Try again.";
        }
      }

      async function toggleDeletePermission(username, nextValue) {
        try {
          const res = await fetch("/api/admin/admins/" + encodeURIComponent(username) + "/permissions", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ canDeleteProducts: nextValue }),
          });
          const data = await res.json();
          if (!data.success) { alert(data.message || "Could not update permission."); return; }
          loadAdmins();
        } catch (err) {
          alert("Network error. Try again.");
        }
      }

      async function unlockAdmin(username) {
        try {
          await fetch("/api/admin/admins/" + encodeURIComponent(username) + "/unlock", {
            method: "PUT",
            headers: { Authorization: "Bearer " + token },
          });
          loadAdmins();
        } catch (err) {
          alert("Network error. Try again.");
        }
      }

      async function editAdminCredentials(username) {
        const newUsername = prompt("New username for \"" + username + "\" (leave as-is to keep):", username);
        if (newUsername === null) return;
        const newPassword = prompt("New password (leave blank to keep current, min 6 characters):", "");
        if (newPassword === null) return;

        const trimmedUsername = newUsername.trim();
        if (!trimmedUsername) { alert("Username cannot be empty."); return; }
        if (newPassword && newPassword.length < 6) { alert("Password should be at least 6 characters."); return; }

        try {
          const res = await fetch("/api/admin/admins/" + encodeURIComponent(username) + "/credentials", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ username: trimmedUsername, password: newPassword }),
          });
          const data = await res.json();
          if (!data.success) { alert(data.message || "Could not update admin."); return; }
          loadAdmins();
        } catch (err) {
          alert("Network error. Try again.");
        }
      }

      async function editAdminContact(username) {
        const admin = (admins || []).find((a) => a.username === username);
        if (!admin) return;
        const email = prompt("Registered email for \"" + username + "\":", admin.email || "");
        if (email === null) return;
        const phone = prompt("Phone number for \"" + username + "\":", admin.phone || "");
        if (phone === null) return;
        try {
          const res = await fetch("/api/admin/admins/" + encodeURIComponent(username) + "/contact", {
            method: "PUT",
            headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
            body: JSON.stringify({ email: email.trim(), phone: phone.trim() }),
          });
          const data = await res.json();
          if (!data.success) { alert(data.message || "Could not update admin contact details."); return; }
          loadAdmins();
        } catch (err) {
          alert("Network error. Try again.");
        }
      }

      async function deleteAdmin(username) {
        if (!confirm("Remove admin \"" + username + "\"?")) return;
        try {
          await fetch("/api/admin/admins/" + encodeURIComponent(username), {
            method: "DELETE",
            headers: { Authorization: "Bearer " + token },
          });
          loadAdmins();
        } catch (err) {
          alert("Network error. Try again.");
        }
      }

      // ---------- MASCOT (login helper girl) ----------
      function triggerDmLoginReaction(state, afterAnimation) {
        const wrap = document.getElementById("dmLoginLogoWrap");
        if (!wrap) { if (afterAnimation) afterAnimation(); return; }
        wrap.classList.remove("privacy","success");
        void wrap.offsetWidth;
        wrap.classList.add(state === "success" ? "success" : "privacy");
        setTimeout(() => { wrap.classList.remove("privacy","success"); if (afterAnimation) afterAnimation(); }, state === "success" ? 650 : 450);
      }

      document.addEventListener("DOMContentLoaded", () => {
        const loginPasswordInput = document.getElementById("loginPassword");
        if (loginPasswordInput) {
          loginPasswordInput.addEventListener("focus", () => triggerDmLoginReaction("privacy"));
          loginPasswordInput.addEventListener("input", () => triggerDmLoginReaction("privacy"));
          loginPasswordInput.addEventListener("blur", () => { const w=document.getElementById("dmLoginLogoWrap"); if(w) w.classList.remove("privacy"); });
          loginPasswordInput.addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
        }
        updateOverviewGreeting();
        checkSession();
      });

      // Updates the floating bubble's label (shows the logged-in admin's
      // username once signed in, falls back to the brand name otherwise).
      // Sets the bubble label and shrinks the font so long usernames don't
      // overflow the circle.
      function setBubbleText(text) {
        const el = document.getElementById("floatBubbleText");
        if (!el) return;
        el.textContent = String(text || "").trim();
        let size = 15;
        el.setAttribute("font-size", size);
        while (el.getComputedTextLength && el.getComputedTextLength() > 76 && size > 9) {
          size -= 1;
          el.setAttribute("font-size", size);
        }
      }

      // ===== Floating logo bubble: drifts around the page, pops on click =====
      (function () {
        const bubble = document.getElementById("floatBubble");
        if (!bubble) return;

        // Show the logged-in admin's username on the bubble if a session is
        // already saved (e.g. page refresh); otherwise the default label.
        setBubbleText(myUsername || "Design Makers");

        let x = 40, y = 110;
        let vx = 1.1, vy = 0.9;
        let popped = false;
        let raf = null;

        function step() {
          if (popped) return;
          const w = window.innerWidth, h = window.innerHeight;
          const bw = bubble.offsetWidth || 160, bh = bubble.offsetHeight || 40;
          x += vx;
          y += vy;
          if (x <= 0) { x = 0; vx = Math.abs(vx); }
          if (x + bw >= w) { x = w - bw; vx = -Math.abs(vx); }
          if (y <= 0) { y = 0; vy = Math.abs(vy); }
          if (y + bh >= h) { y = h - bh; vy = -Math.abs(vy); }
          bubble.style.left = x + "px";
          bubble.style.top = y + "px";
          raf = requestAnimationFrame(step);
        }
        raf = requestAnimationFrame(step);

        function spawnShards(cx, cy) {
          const count = 9;
          for (let i = 0; i < count; i++) {
            const s = document.createElement("div");
            s.className = "fb-shard";
            const size = 14 + Math.random() * 16;
            s.style.width = size + "px";
            s.style.height = (size * 0.55) + "px";
            s.style.left = cx + "px";
            s.style.top = cy + "px";
            s.style.background =
              "radial-gradient(circle at 35% 30%, rgba(255,255,255,0.8), rgba(193,74,114,0.55) 60%, rgba(90,16,41,0.35))";
            s.style.transform = "translate(-50%,-50%) rotate(" + Math.random() * 360 + "deg)";
            s.style.transition = "transform 0.55s cubic-bezier(0.2,0.6,0.4,1), opacity 0.55s ease-in";
            s.style.opacity = "1";
            document.body.appendChild(s);

            const angle = (Math.PI * 2 * i) / count + Math.random() * 0.4;
            const dist = 45 + Math.random() * 55;
            const dx = Math.cos(angle) * dist;
            const dy = Math.sin(angle) * dist * 0.6 - 10;

            requestAnimationFrame(() => {
              s.style.transform =
                "translate(calc(-50% + " + dx + "px), calc(-50% + " + (dy + 46) + "px)) rotate(" +
                (Math.random() * 360 + 180) + "deg) scale(0.4)";
              s.style.opacity = "0";
            });
            setTimeout(() => s.remove(), 650);
          }
        }

        bubble.addEventListener("click", () => {
          if (popped) return;
          popped = true;
          if (raf) cancelAnimationFrame(raf);

          const rect = bubble.getBoundingClientRect();
          bubble.classList.add("popping");

          setTimeout(() => {
            spawnShards(rect.left + rect.width / 2, rect.top + rect.height / 2);
            bubble.classList.remove("popping");
            bubble.style.opacity = "0";
          }, 90);

          setTimeout(() => {
            const w = window.innerWidth, h = window.innerHeight;
            x = 30 + Math.random() * Math.max(40, w - 220);
            y = 90 + Math.random() * Math.max(40, h - 260);
            bubble.style.left = x + "px";
            bubble.style.top = y + "px";
            requestAnimationFrame(() => {
              bubble.style.opacity = "1";
              popped = false;
              raf = requestAnimationFrame(step);
            });
          }, 20000);
        });
      })();
          // Keep seller fulfilment stages fresh for admins/sub-admins while the Orders tab is open.
      setInterval(() => { if (currentTab === "orders") loadOrders(); }, 5000);

