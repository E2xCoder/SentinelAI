# SentinelAI — Claude Code Agent Mimarisi

**Model dağılımı:** Opus/Fable 5 = Planner/Orchestrator (ana oturum, subagent DEĞİL) · Sonnet 5 = 6 subagent (uygulama katmanı)

Bu doküman, `/mnt/skills` ile üretilmiş değil — projenin (SentinelAI: modüler Python CLI, log parser, kural motoru, AI anomali analizi, threat intel enrichment, risk skorlama, firewall entegrasyonu) tarif edilen mimarisine göre tasarlanmıştır. Gerçek dosya ağacını görmedim; agent dosya listeleri bu yüzden **kategori bazlı** (glob pattern) verildi — Planner, her göreve özel gerçek dosya yollarını (2-5 dosya) bu kategoriler içinden seçip subagent'a promptunda açıkça verecek.

---

## 1) İdeal Agent Sayısı: 6 Sonnet subagent + 1 Opus orchestrator (ana oturum)

Neden 6 ve neden daha fazla değil — bkz. dokümanın sonundaki "Neden bu sayı" bölümü. Özet: modül bazlı agent (parser-agent, rule-agent, ai-agent, threat-intel-agent, firewall-agent, cli-agent...) sayıyı 10+'a çıkarır ve çoğu zaman boşta kalan, birbirinin işini asla yapamayan agentlar üretir. Bunun yerine **görev tipi** (rol) bazlı agent kullanmak, aynı 6 agent'ı SentinelAI'nin her modülünde tekrar tekrar (parser da, firewall entegrasyonu da) kullanmanı sağlar → ölçeklenebilir, düşük ezber/duplicate agent riski.

| # | Agent | Tek Sorumluluk |
|---|-------|-----------------|
| 1 | **code-writer** | Yeni kod/özellik/modül yazımı (sıfırdan) |
| 2 | **refactor-agent** | Davranışı değiştirmeden mevcut kodu iyileştirme |
| 3 | **test-agent** | Test yazma, güncelleme, çalıştırma |
| 4 | **bugfix-agent** | Verilen hata/stack trace'e göre nokta atışı düzeltme |
| 5 | **doc-agent** | README, docstring, CHANGELOG güncellemesi |
| 6 | **review-agent** | Diff üzerinde hızlı kalite/güvenlik/stil ön-incelemesi (Opus'un final review yükünü azaltır) |

---

## 2-9) Her Agent İçin Detaylı Tablo

### 1. code-writer
- **Ne zaman çağrılır:** Planner yeni bir özellik/fonksiyon/modül/CLI komutu tanımladığında (ör. yeni bir detection rule, yeni bir `sentinel` alt-komutu, yeni bir enrichment kaynağı).
- **Okuyabileceği dosyalar:** Planner'ın verdiği 2-5 hedef dosya + varsa 1 referans dosya (benzer bir modülün örneği, ör. mevcut bir rule dosyası şablon olarak).
- **Değiştirebileceği dosyalar:** Yalnızca görev kapsamındaki yeni/hedef dosya(lar).
- **Asla dokunmayacağı dosyalar:** `tests/`, `docs/`, `pyproject.toml`, `config.yaml`, `.github/`, CI dosyaları, başka modüllerin dosyaları.
- **Diğer agentlarla ilişki:** Çıktısını review-agent kontrol eder; test-agent aynı özellik için paralel/ardından test yazar; doc-agent aynı özellik için dokümantasyonu günceller. code-writer test yazmaz, dokümantasyon yazmaz.
- **Token kuralı:** Sadece verilen dosyaları okur, proje genelinde arama (grep/glob tüm repo) yapmaz; gerekiyorsa "referans dosya eksik" diye Planner'a rapor verir.

### 2. refactor-agent
- **Ne zaman çağrılır:** Davranış aynı kalacak şekilde kod kalitesi/performans/okunabilirlik iyileştirmesi istendiğinde.
- **Okuyabileceği dosyalar:** Sadece refactor edilecek 1-3 dosya + ilgili test dosyası (davranış bozulmadığını doğrulamak için, salt okunur).
- **Değiştirebileceği dosyalar:** Yalnızca hedef kaynak dosya(lar). Testleri **okur ama değiştirmez**.
- **Asla dokunmayacağı dosyalar:** Test dosyaları, public API/CLI imzaları (imza değişikliği code-writer+Planner kararı gerektirir), config/dokümantasyon.
- **Diğer agentlarla ilişki:** İş bitince test-agent'ın mevcut testleri çalıştırıp doğrulamasını Planner tetikler. Davranış değişikliği gerektiğini fark ederse iş yapmaz, Planner'a rapor eder.
- **Token kuralı:** Diff'i minimal tutar; tüm dosyayı yeniden yazmaz, sadece değişen bloğu.

### 3. test-agent
- **Ne zaman çağrılır:** Yeni kod için test yazımı, mevcut testlerin güncellenmesi, veya test suite'inin çalıştırılıp sonuç raporlanması gerektiğinde.
- **Okuyabileceği dosyalar:** Test edilecek kaynak dosya(lar) (salt okunur) + ilgili test dosyası.
- **Değiştirebileceği dosyalar:** Yalnızca `tests/` altındaki ilgili test dosyası.
- **Asla dokunmayacağı dosyalar:** `src/`/uygulama kaynak kodu, config, dokümantasyon.
- **Diğer agentlarla ilişki:** code-writer/refactor-agent/bugfix-agent'ın çıktısını doğrular. Kaynak kodda hata bulursa düzeltmez, Planner'a (gerekirse bugfix-agent'a yönlendirilmek üzere) rapor eder.
- **Token kuralı:** Test çıktısını (pass/fail + özet) rapor eder, tüm log'u değil.

### 4. bugfix-agent
- **Ne zaman çağrılır:** Elde somut bir hata mesajı/stack trace/başarısız test varken, nokta atışı düzeltme gerektiğinde.
- **Okuyabileceği dosyalar:** Hatanın geçtiği dosya + doğrudan çağırdığı 1-2 dosya (stack trace'den belli).
- **Değiştirebileceği dosyalar:** Yalnızca hatanın kök nedeni olan dosya(lar).
- **Asla dokunmayacağı dosyalar:** İlgisiz modüller, config, test dosyaları (test'i test-agent günceller).
- **Diğer agentlarla ilişki:** Kapsamı hatanın gerçek kök nedenini aşıyorsa (mimari sorun) düzeltmeyi durdurup Planner'a eskale eder. Düzeltme sonrası doğrulamayı test-agent yapar.
- **Token kuralı:** Sadece stack trace'in işaret ettiği dosyaları okur, "olabilir mi" diye proje geneli taramaz.

### 5. doc-agent
- **Ne zaman çağrılır:** Yeni/değişen bir özellik için README, docstring, CHANGELOG, CLI `--help` metni güncellenmesi gerektiğinde.
- **Okuyabileceği dosyalar:** İlgili kaynak dosya (davranışı anlamak için, salt okunur) + güncellenecek doküman dosyası.
- **Değiştirebileceği dosyalar:** Yalnızca doküman dosyaları (`README.md`, `CHANGELOG.md`, docstring'ler, `docs/`).
- **Asla dokunmayacağı dosyalar:** Kaynak kod mantığı, testler, config.
- **Diğer agentlarla ilişki:** code-writer/bugfix-agent/refactor-agent'ın işi bittikten SONRA çalışır (sıralı, paralel değil — çünkü değişmemiş davranışı belgelemeye çalışırsa yanlış doküman üretir).
- **Token kuralı:** Sadece değişen kısmı belgeler, tüm dosyayı yeniden yazmaz.

### 6. review-agent
- **Ne zaman çağrılır:** Bir subagent görevi tamamladıktan hemen sonra, Opus'a gitmeden ÖNCE hızlı bir ön-kontrol için (stil, bariz güvenlik açığı, ölü kod, isimlendirme).
- **Okuyabileceği dosyalar:** Yalnızca değişen diff + değişen dosyanın kendisi.
- **Değiştirebileceği dosyalar:** Hiçbiri (salt okunur, sadece rapor üretir).
- **Asla dokunmayacağı dosyalar:** Her şey — bu agent asla `Write`/`Edit` yapmaz.
- **Diğer agentlarla ilişki:** Basit/bariz sorunları burada yakalayıp Planner'ın (Opus) sadece mimari/kritik kararlar için devreye girmesini sağlar → Opus token tüketimini büyük oranda azaltan agent budur.
- **Token kuralı:** Sadece diff'i okur, tüm dosyayı değil; rapor maksimum birkaç madde.

---

## Ortak Kural (Tüm Subagentlar İçin)

- Hiçbir subagent kendi başına **hangi dosyayı okuyacağına karar vermez** — Planner, görev promptunda dosya yollarını açıkça verir. Subagent kendi kendine `grep`/`glob` ile tüm repo'yu taramaz.
- Belirsizlik durumunda (dosya bulunamadı, kapsam net değil, birden fazla çözüm yolu var) subagent **iş yapmayı durdurur** ve Planner'a kısa bir rapor döner. Karar subagent'a ait değildir.
- Her subagent çıktısını **kısa özet** olarak döner (ne değişti, hangi dosya, kaç satır) — tüm dosya içeriğini tekrar yazdırmaz.

---

## Neden Bu Agent Sayısı?

10-15 modül-bazlı agent (log-parser-agent, rule-agent, ai-analysis-agent, threat-intel-agent, firewall-agent, cli-agent, config-agent...) yerine **6 rol-bazlı agent** seçildi çünkü:
- Modül bazlı agentların çoğu bir sprint'te hiç kullanılmaz → boşta duran tanımlar, bakım yükü.
- Rol bazlı agentlar (code-writer, test-agent, vb.) SentinelAI'nin *her* modülünde (parser'da da, firewall entegrasyonunda da) yeniden kullanılır → tanım sayısı sabit kalır, proje büyüse de agent sayısı artmaz (ölçeklenebilirlik).
- Sorumluluk sınırı net: "kod yazan" hiçbir zaman "test yazan" değildir, karışma riski sıfıra iner.

## Paralel Çalışabilecek Görevler
- Birbirinden bağımsız modüllerde **code-writer** görevleri (ör. yeni bir detection rule + yeni bir enrichment kaynağı aynı anda, farklı dosyalar).
- Aynı özelliğin **test-agent** ve **doc-agent** işleri, code-writer bitince ikisi birbirini beklemeden paralel başlayabilir (ikisi de farklı dosyalara yazar).
- Birden fazla **bugfix-agent** görevi, hatalar birbirinden bağımsız dosyalardaysa paralel.

## Sıralı Yapılması Gereken Görevler
- code-writer → review-agent → (gerekirse düzeltme) → test-agent (aynı dosya üzerinde önce yazılmalı, sonra test edilmeli).
- refactor-agent → test-agent (davranış bozulmadığını doğrulamadan doc-agent çalışmamalı).
- Herhangi bir agent → doc-agent (dokümantasyon her zaman en son, değişen davranışı yansıtmak için).
- Tüm subagent çıktıları → Opus final review (en son, tek seferde toplu değerlendirme).

## Token Tüketimini Azaltmak İçin En İyi Stratejiler
1. **Görev parçalama:** Büyük özellikler Planner tarafından 20-30 küçük göreve bölünür, her biri 2-5 dosyalık dar kapsamda.
2. **Dosya listesi Planner'dan gelir:** Subagent kendi arama yapmaz, bu en büyük token tasarrufu.
3. **Diff-bazlı review:** review-agent tüm dosyayı değil sadece diff'i okur.
4. **Kısa rapor formatı:** Her subagent çıktısı madde madde özet, düzyazı anlatım yok.
5. **Opus sadece iki yerde devreye girer:** (a) görev planlama/bölme, (b) tüm subagent raporlarının toplu final review'u. Ara adımlarda hiç çağrılmaz.
6. **Paralel dağıtım:** Bağımsız görevler aynı anda birden fazla Sonnet subagent'a verilir, sıralı bekleme yerine toplam duvar-saati ve tekrar okuma azalır.

## Opus/Fable 5 + Sonnet 5 Birlikte Kullanımı — Önerilen İş Akışı
1. **Opus (Planner):** Kullanıcı isteğini alır, projeyi (sadece gerekli üst-seviye dosyaları — ör. `README`, ilgili modülün ana dosyası) okur, işi 20-30 küçük alt-göreve böler, her alt-görev için hangi agent + hangi 2-5 dosya olduğunu belirler.
2. **Opus → Sonnet dağıtımı:** Bağımsız alt-görevler paralel, bağımlı olanlar sıralı şekilde ilgili subagent'lara (code-writer/refactor-agent/test-agent/bugfix-agent/doc-agent) dağıtılır.
3. **Sonnet subagentlar:** Kendi dar kapsamlarında çalışır, kısa rapor döner.
4. **review-agent (Sonnet):** Her kod değişikliğinden hemen sonra hızlı ön-kontrol yapar, bariz sorunları burada eler.
5. **Opus (final review):** Tüm raporlar toplandıktan sonra TEK SEFERDE mimari/bütünlük/güvenlik açısından son değerlendirmeyi yapar, gerekirse belirli alt-görevleri yeniden Sonnet'e döndürür.
6. Bu akış Opus'un pahalı context'ini sadece "başta plan" ve "sonda review" olarak iki dar pencereye sıkıştırır — arada geçen tüm token yükü ucuz Sonnet katmanında kalır.
