/* Digital Asset Center - Paket tanımları (sunucu ve site AYNI dosyayı kullanır; fiyatları sadece buradan değiştir) */
(function (root) {
  var PLANS = {
    trial: {
      id: "trial", name: "Ücretsiz Deneme", assets: 3, team: 1, history: 50, priceTRY: 0, priceUSD: 0,
      support: "Topluluk", audience: "Denemek isteyenler",
      features: ["3 gün ücretsiz", "3 varlık hakkı", "Tüm tarama türleri", "1 ekip kaydı", "Son 50 tarama geçmişi"]
    },
    freelance: {
      id: "freelance", name: "Freelance", assets: 25, team: 1, history: 200, priceTRY: 499.99, priceUSD: 11.99,
      support: "E-posta", audience: "Bireysel geliştirici ve freelancer'lar",
      features: ["25 varlık", "Tüm tarama türleri", "1 ekip kaydı", "Son 200 tarama geçmişi", "CSV / JSON dışa aktarma", "E-posta destek"]
    },
    kobi: {
      id: "kobi", name: "KOBİ", assets: 150, team: 10, history: 1000, priceTRY: 4999.99, priceUSD: 119.99,
      support: "Öncelikli e-posta", audience: "Küçük ve orta ölçekli işletmeler", popular: true,
      features: ["150 varlık", "Tüm tarama türleri", "10 ekip kaydı", "Son 1000 tarama geçmişi", "Yenileme takvimi ve maliyet raporu", "Öncelikli e-posta destek"]
    },
    enterprise: {
      id: "enterprise", name: "Enterprise", assets: null, team: null, history: 5000, priceTRY: 24999.99, priceUSD: 599.99,
      support: "Özel destek hattı", audience: "Çok ülkeli büyük şirketler",
      features: ["Sınırsız varlık", "Tüm tarama türleri", "Sınırsız ekip kaydı", "Son 5000 tarama geçmişi", "Yenileme takvimi ve maliyet raporu", "Özel destek hattı"]
    }
  };
  Object.keys(PLANS).forEach(function (k) { PLANS[k].prices = { TRY: PLANS[k].priceTRY, USD: PLANS[k].priceUSD }; }); // priceTRY/priceUSD geriye dönük uyumluluk için korunur
  var CFG = {
    PLANS: PLANS,
    PAID: ["freelance", "kobi", "enterprise"],
    TRIAL_DAYS: 3,
    YEARLY_MONTHS: 10, // yıllık ödemede 12 ay yerine 10 ay ücret (2 ay bedava)
    // Fiyatlar para birimi koduyla saklanır (PLANS[x].prices). EUR gibi fiyatı tanımlanmamış para birimi için null döner (uydurma fiyat yok).
    CURRENCIES: ["TRY", "USD", "EUR"],
    price: function (planId, currency, cycle) {
      var p = PLANS[planId]; if (!p) return null;
      var cur = currency || "TRY"; var base = p.prices && p.prices[cur] != null ? p.prices[cur] : null;
      if (base == null) return null;
      var m = cycle === "yearly" ? CFG.YEARLY_MONTHS : 1;
      return Math.round(base * m * 100) / 100;
    }
  };
  if (typeof module !== "undefined" && module.exports) module.exports = CFG; else root.DAC_PLANS = CFG;
})(typeof window !== "undefined" ? window : this);
