# TIDEWATCH 🌊

**Rust ile yazılmış çevrimdışı Linux log tehdit avcılığı ve olay triyajı.**

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-58A6FF?logo=rust\&logoColor=white)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-58A6FF?logo=linux\&logoColor=white)](https://www.linux.org/)
[![License](https://img.shields.io/badge/License-MIT-58A6FF?logo=opensourceinitiative\&logoColor=white)](LICENSE)
[![Rust CI](https://img.shields.io/github/actions/workflow/status/raxwqx/TIDEWATCH/ci.yml?label=Rust%20CI\&logo=githubactions\&logoColor=white\&color=58A6FF)](https://github.com/raxwqx/TIDEWATCH/actions/workflows/ci.yml)

[English](README.md) | **Türkçe**

TIDEWATCH, Linux kimlik doğrulama ve sistem loglarını analiz eden, yerel öncelikli bir komut satırı aracıdır. Desteklenen log satırlarını normalleştirilmiş olaylara dönüştürür, yapılandırılabilir TOML tespit kurallarını değerlendirir, ilgili etkinlikleri zaman içinde ilişkilendirir ve kanıta dayalı bulguları terminal veya JSON biçiminde üretir.

Savunma amaçlı güvenlik araştırmaları, olay müdahalesi pratiği ve sahip olduğunuz ya da inceleme yetkiniz bulunan logların tekrarlanabilir triyajı için tasarlanmıştır.

> **Analist notu:** Bir tespit, ihlal kanıtı değil bir inceleme ipucudur. Bulguları çevredeki telemetri, beklenen yönetici etkinliği ve kurum politikasıyla doğrulayın.

## İçindekiler

* [Neden TIDEWATCH](#neden-tidewatch)
* [Yetenekler](#yetenekler)
* [Tespit kapsamı](#tespit-kapsamı)
* [Nasıl çalışır](#nasıl-çalışır)
* [Gereksinimler](#gereksinimler)
* [Derleme ve kurulum](#derleme-ve-kurulum)
* [Hızlı başlangıç](#hızlı-başlangıç)
* [Komut satırı referansı](#komut-satırı-referansı)
* [Giriş biçimleri](#giriş-biçimleri)
* [Tespit kuralları](#tespit-kuralları)
* [Olay özeti](#olay-özeti)
* [Raporlar ve kanıtlar](#raporlar-ve-kanıtlar)
* [Test ve geliştirme](#test-ve-geliştirme)
* [Mimari](#mimari)
* [Sınırlamalar](#sınırlamalar)
* [Sorumlu kullanım ve veri işleme](#sorumlu-kullanım-ve-veri-işleme)
* [Yol haritası fikirleri](#yol-haritası-fikirleri)
* [Lisans](#lisans)

## Neden TIDEWATCH

Güvenlik logları, ilişkili olaylar birlikte incelenebildiğinde en yararlı hale gelir. TIDEWATCH küçük ve şeffaf bir tespit hattına odaklanır: **neyin eşleştiğini, hangi kaynak satırların bulguyu desteklediğini ve bulguyu hangi kuralın ürettiğini** görmek kolaydır.

* **Tasarım gereği çevrimdışı:** yerel dosyaları veya standart girdiyi okur; uzak makinelere bağlanmaz, log verisi yüklemez.
* **Kanıt odaklı çıktı:** bulgular kaynak satır numaralarını, olay mesajlarını, varsa zaman damgalarını, gruplama anahtarlarını ve yapılandırılmış MITRE ATT&CK referanslarını korur.
* **Yapılandırılabilir tespitler:** her eşik değişikliği için Rust kodunu düzenlemek yerine TOML kurallarını düzenleyin.
* **Otomasyona uygun:** JSON raporları ve önem derecesine dayalı çıkış kodları betikler ve CI iş akışlarıyla uyumludur.
* **Test edilebilir temel:** ayrıştırma ve korelasyon mantığı, komut satırı arayüzüne sıkı bağlı olmadan birim ve CLI entegrasyon testleriyle ayrı modüllerde tutulur.
* **Olay özeti (0.2.0):** `--summary` ile zaman aralığını, olay türü dağılımını ve en yoğun kaynak IP/kullanıcıları tek bakışta görün.

## Yetenekler

| **Alan**             | **Mevcut yetenek**                                                                                                      |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Girişler             | Yaygın Linux authlog/syslog metni ve JSON Lines (JSONL)                                                                 |
| Normalleştirme       | Olay türü, ayrıştırılabilirse zaman damgası, host, program, PID, kullanıcı, kaynak IP, komut, mesaj ve özgün satır numarası |
| Tespit               | Eşik pencereleri ve başarısızlık-sonra-başarı sıra korelasyonu                                                           |
| Kural gruplama       | Kaynak IP, kullanıcı adı veya kaynak IP ve kullanıcı adı birleşimi                                                      |
| Olay özeti           | İsteğe bağlı `--summary`; zaman aralığı, tür sayıları ve `--top` ile sınırlanan kaynak IP/kullanıcı sıralamaları         |
| Sonuçlar             | İnsan tarafından okunabilir terminal raporu veya yapılandırılmış JSON                                                   |
| İş akışı entegrasyonu | Standart girdi, çıktı dosyası ve yapılandırılabilir önem derecesi çıkış eşiği                                            |
| ATT&CK bağlamı       | İlgili paket kurallarına eklenmiş teknik kimlikleri                                                                     |

## Tespit kapsamı

TIDEWATCH, [`rules/default.toml`](https://github.com/raxwqx/TIDEWATCH/blob/main/rules/default.toml) içinde başlangıç kurallarıyla gelir. Eşikler bilinçli olarak yapılandırılabilir ve ortama göre ayarlanmalıdır.

| **Kural**     | **Önem**  | **Neyi işaretler**                                              | **Varsayılan mantık**                                                                          |
| ------------- | --------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `SSH-001`     | Yüksek    | Tek kaynaktan SSH kimlik doğrulama hatası patlaması             | 300 saniye içinde 8 hata, kaynak IP'ye göre gruplanır                                          |
| `SSH-002`     | Kritik    | Tekrarlanan hatalardan sonra SSH giriş başarısı                 | 600 saniye içinde 5 hata ardından yapılandırılmış başarı olayı, kaynak IP'ye göre gruplanır     |
| `SSH-003`     | Yüksek    | root için başarılı SSH girişi                                   | Tek eşleşen olay                                                                               |
| `SSH-004`     | Orta      | Tek kaynaktan tekrarlanan geçersiz SSH kullanıcı adları         | 300 saniye içinde 5 geçersiz kullanıcı olayı, kaynak IP'ye göre gruplanır                      |
| `ACCOUNT-001` | Orta      | Yerel hesap oluşturma olayı                                     | Tek eşleşen olay, kullanıcı adına göre gruplanır                                               |
| `PRIV-001`    | Orta      | Bir kullanıcı tarafından kaydedilen sudo komutu patlaması       | 300 saniye içinde 10 olay, kullanıcı adına göre gruplanır                                      |

Bu kurallar doğrulanmış saldırıları değil, incelemeye değer desenleri tanımlar. Meşru yöneticiler, otomasyon, test etkinliği ve yanlış yapılandırılmış istemciler benzer bulgular üretebilir.

## Nasıl çalışır

```text
Yerel log dosyası veya standart girdi
             |
             v
   Biçim seçimi ve ayrıştırma
             |
             v
     Normalleştirilmiş olaylar
             |
             +--> İsteğe bağlı olay özeti (--summary)
             |
             v
    TOML kural yükleme/doğrulama
             |
             v
  Eşik ve sıra korelasyonu
             |
             v
     Kanıta dayalı bulgular
          /          \
         v            v
   Terminal metni   JSON raporu
```

Hat, tek tek aşamaların komut satırı işleyişine sıkı bağlı kalmadan test edilip genişletilebilmesi için bilinçli olarak yalındır.

## Gereksinimler

* Linux veya desteklenen bir Rust araç zincirine sahip başka bir ortam.
* `Cargo.toml` içinde belirtilen Rust 1.85 veya daha yeni sürüm.
* Okunabilir bir log dosyası veya standart girdiye aktarılmış bir akış.

## Derleme ve kurulum

Depoyu klonlayıp optimize edilmiş ikiliyi derleyin:

```bash
git clone https://github.com/raxwqx/TIDEWATCH.git
cd TIDEWATCH
cargo build --release
```

Çalıştırılabilir dosya `target/release/tidewatch` yoluna yazılır. Depo dizininden çalıştırabilir veya ikiliyi `PATH` içindeki bir dizine kopyalayabilirsiniz.

Normal dosya analizi için arka plan servisi, ayrıcalıklı hizmet veya ağ bağlantısı gerekmez. Korumalı sistem loglarını okumak uygun yerel izinler gerektirebilir.

## Hızlı başlangıç

### 1. Paketle gelen kimlik doğrulama logu örneğini analiz edin

```bash
cargo run --release -- --input examples/sample-auth.log
```

Örnek, sentetik eğitim verisidir. Rapor biçimini ve paket tespitleri tanımak için güvenle kullanılabilir.

### 2. JSON raporu kaydedin

```bash
cargo run --release -- \
  --input examples/sample-auth.log \
  --output-format json \
  --output report.json
```

### 3. JSONL örneğini analiz edin

```bash
cargo run --release -- \
  --input examples/sample-jsonl.jsonl \
  --format jsonl \
  --output-format json
```

### 4. Logları standart girdiden okuyun

```bash
cat /var/log/auth.log | target/release/tidewatch --format authlog
```

Dosyayı doğrudan `--input /yol/logdosyasi` ile de yönlendirebilirsiniz. Yalnızca erişim yetkiniz olan logları kullanın.

### 5. Uyarıları incelemeden önce olay akışını özetleyin

```bash
target/release/tidewatch \
  --input examples/sample-auth.log \
  --summary \
  --top 5
```

`--summary`, girdiye dair kompakt bir genel bakış ekler: gözlenen zaman aralığı, zaman damgası kapsamı, olay türü sayıları ve en yoğun kaynak IP'ler ile kullanıcı adları. Hem metin hem JSON raporlarında çalışır.

### 6. Önem eşiği aşıldığında sıfır olmayan durum döndürün

```bash
target/release/tidewatch \
  --input examples/sample-auth.log \
  --fail-on-severity high
```

Çıkış kodları:

| **Kod** | **Anlam**                                                                                         |
| ------- | ------------------------------------------------------------------------------------------------- |
| `0`     | Analiz tamamlandı ve seçilen önem eşiğini karşılayan uyarı yok, ya da eşik yapılandırılmadı       |
| `1`     | Yürütme veya girdi hatası oluştu                                                                  |
| `2`     | En az bir uyarı `--fail-on-severity` değerini karşıladı veya aştı                                 |

## Komut satırı referansı

CLI seçeneklerini görmek için `tidewatch --help` veya `cargo run -- --help` çalıştırın.

| **Seçenek**                     | **Varsayılan**  | **Açıklama**                                                                                       |
| ------------------------------- | --------------- | -------------------------------------------------------------------------------------------------- |
| `-i, --input <PATH>`            | `-`             | Girdi dosyası yolu; `-` standart girdiyi okur                                                       |
| `--format <FORMAT>`             | `auto`          | Ayrıştırıcı seçimi: `auto`, `authlog` veya `jsonl`                                                 |
| `--rules <PATH>`                | Paket kurallar  | Özel TOML kural dosyası yükle                                                                      |
| `--output-format <FORMAT>`      | `text`          | Çıktı biçimi: `text` veya `json`                                                                   |
| `-o, --output <PATH>`           | Standart çıktı  | Raporu standart çıktı yerine dosyaya yaz                                                           |
| `--fail-on-severity <SEVERITY>` | Kapalı          | Herhangi bir bulgu `info`, `low`, `medium`, `high` veya `critical` eşiğini karşılarsa `2` ile çık  |
| `--include-events`              | Kapalı          | JSON çıktısına normalleştirilmiş olayları ekle; `--output-format json` gerektirir                  |
| `--summary`                     | Kapalı          | Zaman aralığı, tür sayıları ve üst sıralamalar içeren olay özeti ekle                               |
| `--top <N>`                     | `5`             | `--summary` ile her üst listede gösterilecek kayıt sayısı; 1-100 arası                              |

Örnek yardım komutu:

```bash
cargo run -- --help
```

## Giriş biçimleri

### Linux authlog / syslog tarzı metin

TIDEWATCH, aşağıdakine benzer yaygın kimlik doğrulama mesajlarını tanır:

```text
Oct  9 19:01:01 lab-host sshd[2101]: Failed password for analyst from 203.0.113.77 port 50101 ssh2
```

Sınıflandırma desteklenen mesaj desenlerine dayanır. Ayrıştırıcının tanımadığı mesajlar sessizce atılmak yerine `other` olayı olarak görünür kalır.

**Zaman damgası uyarısı:** klasik syslog zaman damgaları genellikle hem yılı hem saat dilimini içermez. TIDEWATCH bu zaman damgalarına geçerli UTC yılını atar; ancak özgün saat dilimi yalnızca satırdan çıkarılamaz. Hostlar veya yıl sınırları arasında korelasyon kurarken dikkatli olun. Yıl, tek bir çalıştırma içinde bir kez çözümlenir; böylece aynı rapor farklı yılları karıştırmaz.

### JSON Lines (JSONL)

JSONL girdisi, satır başına bir JSON nesnesi içerir. Ayrıştırıcı öncelikle `message` alanını tercih eder; ayrıca `MESSAGE`, `msg`, `event.message` ve `event.original` alanlarını tanır. İsteğe bağlı alanlar `timestamp`, `host`, `program`, `pid`, `user`, `source_ip`, `command` ve `event_type` olabilir.

Düz anahtarların yanı sıra iç içe alanlar da desteklenir. Yaygın eşlemeler: `host.name`, `process.name`, `process.pid`, `process.command_line`, `user.name`, `source.ip`, `client.ip`, `event.kind` ve `event.action`. Bir nokta içeren gerçek anahtar varsa, düz anahtar önceliklidir.

RFC 3339, yaygın ISO benzeri ve tam sayı ya da ondalıklı epoch zaman damgaları desteklenir. `__REALTIME_TIMESTAMP` mikrosaniye olarak yorumlanır. Bozuk bir JSON satırı sayılır ve raporda sınıflandırılmamış bir olay olarak korunur.

Örnek için [`examples/sample-jsonl.jsonl`](https://github.com/raxwqx/TIDEWATCH/blob/main/examples/sample-jsonl.jsonl) dosyasına bakın.

## Tespit kuralları

Paket kurallar [`rules/default.toml`](https://github.com/raxwqx/TIDEWATCH/blob/main/rules/default.toml) içinde tanımlıdır. Özel bir kural dosyası mevcut tespitleri ayarlayabilir veya desteklenen olay türlerinin yeni birleşimlerini ekleyebilir.

Desteklenen koşullar:

* `threshold`: `window_seconds` içinde `threshold` değerine ulaşan eşleşen olay grubunu bulur.
* `failure_then_success`: aynı grup anahtarından yapılandırılmış sayıda eşleşen olayı ve ardından zaman penceresi içinde yapılandırılmış başarı olay türlerinden birini bulur.

Desteklenen `group_by` değerleri `source_ip`, `user` ve `source_ip_user` şeklindedir. Zaman penceresi ve sıra tespitleri ayrıştırılabilir zaman damgaları gerektirir. Tek olaylı kurallar zaman damgası olmadan da çalışabilir; bir grupta hem zaman damgalı hem de zaman damgasız olay varsa uyarı zaman damgalı olayı tercih eder. Her iki korelasyon penceresi de sınırda kapsayıcıdır.

Kural dosyaları bilinmeyen alanları reddeder. `threshhold = 8` gibi bir yazım hatası sessizce yok sayılmak yerine doğrulamayı başarısız kılar; bu da özel kural incelemesini daha güvenli hale getirir.

### Örnek özel kural

```toml
version = 1

[[rules]]
id = "CUSTOM-SSH-001"
name = "Tek kaynaktan tekrarlanan SSH hataları"
description = "Tek bir kaynak IP'den gelen tekrarlanan SSH kimlik doğrulama hatalarını inceleyin."
severity = "high"
condition = "threshold"
event_kinds = ["ssh_auth_failure"]
threshold = 6
window_seconds = 180
group_by = "source_ip"
mitre = ["T1110.001"]
enabled = true
```

Kuralı örneğin `my-rules.toml` olarak kaydedin, ardından çalıştırın:

```bash
target/release/tidewatch \
  --input examples/sample-auth.log \
  --rules my-rules.toml
```

`failure_then_success` için ayrıca `success_event_kinds` ayarlayın; örneğin `["ssh_auth_success", "ssh_root_login"]`. Tam şema ve korelasyon anlamları [`docs/DETECTION_RULES.md`](https://github.com/raxwqx/TIDEWATCH/blob/main/docs/DETECTION_RULES.md) içinde belgelenmiştir.

### Kural davranışı ve ayarlama

* Kural kimlikleri benzersiz ve boş olmamalıdır; geçersiz kural yapılandırması hata döndürür.
* Bilinmeyen kural alanları reddedilir; yanlış yazılmış bir seçenek bir tespiti sessizce devre dışı bırakamaz.
* Bir eşik kuralı, ilk uygun zaman penceresi gözlendiğinde kural/grup anahtarı başına en fazla bir uyarı üretir.
* Kanıtlar, yapılandırılmış eşiğe ulaşmak veya sırayı tamamlamak için kullanılan olayları içerir.
* ATT&CK referansları inceleme bağlamı sağlar; bir tekniğin kullanıldığını kanıtlamaz.
* Eşikleri hem olumlu hem olumsuz örneklerle ayarlayarak gürültüyü ve yanlış pozitifleri anlayın.

## Olay özeti

Normalleştirilmiş olay akışına analist odaklı bir genel bakış eklemek için `--summary` kullanın. Özellikle çok sayıda arka plan etkinliği içeren loglarda, tek tek uyarıları okumadan önce yararlıdır.

```bash
target/release/tidewatch --input /var/log/auth.log --summary --top 5
```

Metin raporuna şu bilgileri içeren bir `Event overview` bloğu eklenir:

* ilk ve son ayrıştırılabilir zaman damgaları ile gözlenen süre,
* zaman damgası olan ve olmayan olay sayıları,
* her normalleştirilmiş olay türü için sayılar,
* `--top` ile sınırlanan en yoğun kaynak IP'ler ve kullanıcı adları.

JSON çıktısında aynı veriler, `--include-events` gerekmeden `event_summary` nesnesi olarak görünür:

```json
{
  "event_summary": {
    "events_total": 18,
    "events_with_timestamp": 18,
    "events_without_timestamp": 0,
    "first_timestamp": "2026-10-09T19:01:01",
    "last_timestamp": "2026-10-09T19:03:08",
    "duration_seconds": 127,
    "by_kind": { "ssh_auth_failure": 8, "ssh_invalid_user": 5 },
    "top_source_ips": [{ "value": "203.0.113.77", "count": 14 }],
    "top_users": [{ "value": "analyst", "count": 2 }]
  }
}
```

`--top` 1 ile 100 arasında değer alır ve varsayılanı 5'tir. Eşit sayımlar değere göre sıralanır; böylece çıktı belirleyici kalır. Özet yalnızca ayrıştırılmış olayları yansıtır; kural ayarlamasının veya uyarı incelemesinin yerini tutmaz.

## Raporlar ve kanıtlar

Metin çıktısı etkileşimli triyaj için tasarlanmıştır. JSON çıktısı otomasyon ve ileri işleme yöneliktir.

Raporlar bir şema sürümü ve araç sürümü, girdi biçimi ve ayrıştırma özeti, uyarılar, önem toplamları ve kanıtlar sağlar. JSON şema sürümü `2`, `--summary` ile üretilen isteğe bağlı `event_summary` nesnesini ekler. Her uyarı şunları içerebilir:

* Sabit kural kimliği, başlık, önem derecesi ve analist odaklı açıklama.
* Gözlenen olay sayısı ve varsa kaynak IP veya kullanıcı pivotları.
* Varsa korelasyon başlangıç ve bitiş zamanları.
* Kural için yapılandırılmış MITRE ATT&CK teknik referansları.
* Özgün satır numaraları, olay türleri, varsa zaman damgaları ve kaynak mesajlar.

JSON raporuna normalleştirilmiş olay akışını eklemek için `--output-format json` ile birlikte `--include-events` kullanın.

**Raporları hassas veri olarak ele alın.** Gerçek loglar kullanıcı adları, host adları, IP adresleri, komut satırları ve ham mesajlar içerebilir. Bir raporu yayımlamadan veya herkese açık bir konuya eklemeden önce bu bilgileri gözden geçirin ve redakte edin.

## Test ve geliştirme

Yerel kalite kontrollerini depo kökünden çalıştırın:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Yeniden kontrol etmeden önce Rust biçimlendirmesini uygulamak için:

```bash
cargo fmt
```

GitHub Actions; gönderimler ve pull request'ler için projeyi Ubuntu, Windows ve macOS üzerinde derleyip test eder, ayrıca biçimlendirme, Clippy, sürüm derlemesi ve örnek duman testlerini çalıştırır. Yeni bir ayrıştırıcı deseni veya kural eklerken temsili olumlu ve olumsuz örnekler ile zaman damgası ya da eksik alan sınır durumlarını kapsayan testler ekleyin.

## Mimari

Uygulama odaklı Rust modüllerine ayrılmıştır:

| **Modül**   | **Sorumluluk**                                                                       |
| ----------- | ------------------------------------------------------------------------------------ |
| `parser`    | Biçim seçimi, syslog/JSONL ayrıştırma, iç içe alan çözümleme, olay sınıflandırma ve istatistikler |
| `model`     | Normalleştirilmiş olaylar, önem seviyeleri, uyarılar ve kanıt türleri                |
| `detection` | TOML kural doğrulama, gruplama anahtarları, eşik pencereleri ve sıra korelasyonu     |
| `report`    | İnsan tarafından okunabilir çıktı, JSON rapor oluşturma ve olay özeti toplama         |
| `main`      | CLI argümanları, dosya/standart girdi, rapor çıktısı ve çıkış kodları                |

Hat ve tasarım notları için [`docs/ARCHITECTURE.md`](https://github.com/raxwqx/TIDEWATCH/blob/main/docs/ARCHITECTURE.md) dosyasına bakın.

## Sınırlamalar

* TIDEWATCH çevrimdışı bir triyaj yardımcısıdır; tam bir SIEM, EDR veya otomatik olay müdahale platformu değildir.
* Mevcut paket tespitler seçili Linux kimlik doğrulama ve hesap yönetimi desenlerine odaklanır; kapsam kapsamlı değildir.
* Dağıtıma özgü log biçimleri ve yoğun özelleştirilmiş syslog şablonları ayrıştırıcı güncellemeleri gerektirebilir.
* Eksik, yanlış veya saat dilimi belirsiz zaman damgaları olay sıralamasına ve korelasyona olan güveni azaltır.
* Bazı log alanları eksik veya sahte olabilir. Eşleşen bir kaynak IP veya kullanıcı adı tek başına atıf için yeterli değildir.
* `--summary` sayıları ayrıştırılmış olay akışını tanımlar; ayrıştırıcının tanımadığı mesajlar `other` olarak kalır ve bir pivotu ham logdan daha küçük gösterebilir.
* Paket eşikler başlangıç değerleridir, evrensel politika değildir. Meşru etkinlik uyarı üretebilir ve desteklenmeyen saldırı desenleri tespit edilemeyebilir.
* Araç yalnızca verilen girdiyi analiz eder; logları sürekli toplamaz, bir hostu gerçek zamanlı izlemez veya iyileştirme eylemleri gerçekleştirmez.

## Sorumlu kullanım ve veri işleme

TIDEWATCH'i yalnızca sahip olduğunuz veya açıkça analiz etme yetkiniz bulunan loglarda kullanın. Proje; savunma amaçlı inceleme, güvenlik öğrenimi ve olay triyajı iş akışları için tasarlanmıştır.

TIDEWATCH ağları taramaz, uzak bağlantılar açmaz veya girdi loglarını yüklemez. Kaynak logları ve raporları, geldikleri sistemin erişim ve saklama gereksinimleriyle aynı şekilde koruyun.

Bu projeyle ilgili güvenlik açığı bildirimleri için [`SECURITY.md`](https://github.com/raxwqx/TIDEWATCH/blob/main/SECURITY.md) dosyasına başvurun.

## Yol haritası fikirleri

Test ve tasarım incelemesine tabi olmak üzere olası gelecek çalışmalar:

* Ek Linux denetim ve kimlik doğrulama log varyantları için daha geniş, örnek destekli ayrıştırma.
* Tespit sınır durumları için daha fazla olumsuz test ve regresyon örneği.
* Kural davranışını belirleyici ve açıklanabilir tutarken ek korelasyon temelleri.
* İsteğe bağlı HTML veya zaman çizelgesi odaklı rapor çıktısı.

Bunlar mevcut sürümdeki yetenekler değil, fikirlerdir.

## Lisans

MIT Lisansı altında yayımlanmıştır. [`LICENSE`](LICENSE) dosyasına bakın.
