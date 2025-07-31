# AWLog Server

Bu depo, evden çalışan kullanıcıların pencere ve AFK durumlarını takip etmek için geliştirilmiş Flask tabanlı sunucu uygulamasını içerir. `agent` klasöründeki istemci scripti, klavye veya fare kancası kullanmadan Windows API üzerinden son kullanıcı girişi zamanını okuyarak, pencere değişimleri ve ağ trafiğiyle birlikte AFK tahmini yapıp bu bilgileri sunucuya iletir.

## Özellikler
- **WindowLog** ve **StatusLog** modelleri ile kullanıcının aktif pencere ve AFK bilgileri kaydedilir.
- Tarayıcı pencereleri de dahil olmak üzere pencere başlıkları doğrudan
  kaydedilir.
- En son bildirimlere göre çevrimiçi/çevrimdışı durumunu takip eder.
- Günlük zaman çizelgesi, haftalık rapor ve kullanım raporu gibi çeşitli HTML panelleri sağlar.
- REST API uç noktaları aracılığıyla log kayıtlarını kabul eder ve rapor verilerini döndürür.

## Kurulum
1. Gerekli Python paketlerini yükleyin:
   ```bash
   pip install -r requirements.txt
   ```
   (Çevrim dışı ortamda çalışıyorsanız bu adımı atlamanız gerekebilir.)
2. Veritabanı dosyasının oluşturulabilmesi için `data/` klasörünün mevcut olduğundan emin olun.
3. Sunucuyu doğrudan çalıştırabilirsiniz:
   ```bash
   python server.py
   ```
   veya Docker kullanmak için:
   ```bash
   docker compose up --build
   ```

Sunucu varsayılan olarak 5050 portunda çalışır.

Başlatıldığında sunucu, `LOG_DIR` altında `server.log` dosyasına hata
ve uyarı mesajlarını yazar.

## Ortam Değişkenleri
- Artık global `SECRET` anahtarı kullanılmaz. Her istemci `/register` uç noktasından
  kendisine özel bir anahtar alır ve HMAC imzalı isteklerde bu anahtarı kullanır.
- `KEEPALIVE_INTERVAL` – Keepalive bildirimlerinin beklenen aralığı (saniye).
- `OFFLINE_MULTIPLIER` – Kullanıcıyı çevrimdışı kabul etmeden önce beklenen keepalive süresinin kaç katı süre geçmesi gerektiği.
- `MONITOR_INTERVAL` – Arka plan izleme iş parçacığının kontrol aralığı (saniye).
- `TIMEZONE_OFFSET` – Raporlarda kullanılacak saat dilimi ofseti (UTC + değer).
- `REMEMBER_ME_DAYS` – "Beni Hatırla" seçiliyse oturumun geçerli kalacağı gün
  sayısı (varsayılan 30).
- `LOG_DIR` – Sunucu günlüklerinin yazılacağı klasör (varsayılan `logs`).
- `DEBUG` – `1` veya `true` ise ek hata ayıklama mesajları loglanır.
- `MACRO_PROC_BLACKLIST` – Makro kaydedici olarak kabul edilen işlem
  isimlerinin virgülle ayrılmış listesi (sunucu tarafında tutulur).
- `MACRO_PROC_WHITELIST` – Tespit edilse de yoksayılacak işlem
  isimlerinin virgülle ayrılmış listesi (sunucu tarafında tutulur).
- `MACRO_PROC_CHECK_INTERVAL` – Süreç listesinin kaç saniyede bir
  taranacağı (varsayılan 10, sunucu tarafında tutulur).

## API Uç Noktaları
- `POST /register` – İstemciye benzersiz bir gizli anahtar döner.
- `POST /api/log` – `log_type` alanı "window" veya "status" olduğunda ilgili verileri kaydeder.
- `POST /report` – Kullanıcının çevrim içi/çevrim dışı/afk durumunu veya güncel pencere bilgisini bildirir.
  - `status` alanı `window` ise `window_title` ve `process_name` gönderilmelidir.
- `POST /agent/config` – Makro kaydedici kara listesi ve ilgili ayarları döndürür.
- `GET /api/statuslogs` – Son 50 durum kaydını JSON olarak döndürür.
- `GET /api/window_usage` – Belirtilen kullanıcı için pencere kullanım süresi özetini döndürür.
- `GET /api_logs` – Tüm API isteklerinin ham loglarını görüntüler (sadece admin).

Ayrıca `/`, `/daily_timeline`, `/weekly_report` ve `/usage_report` gibi HTML sayfaları mevcuttur.

## İstemci (Agent)
`agent` klasörü, Windows için hazırlanmış örnek istemci uygulamasını içerir. Bu istemci; aktif pencere değişimlerini izler, sistemdeki son giriş zamanını ve ağ trafiğini değerlendirerek AFK durumunu tahmin eder ve bu verileri düzenli olarak sunucuya gönderir. Windows kilitlenirse AFK durumu anında bildirilir. VPN bağlantısı `baylan.local` adresine erişilerek kontrol edilir. VPN açık olsa da API sunucusuna ulaşılamazsa arayüzde ayrı bir uyarı gösterilir.

AFK tespiti icin istemci, varsayilan olarak 60 saniyelik `afk_timeout` ve 1 MB (1.048.576 bayt) `net_active_threshold` degerlerini kullanir. Kucuk ama surekli ag trafiginin yanlis sonuclara yol acmamasi icin son `net_active_window` suresinde (varsayilan 5 saniye) biriken baytlarin toplami bu esigi asmadikca AFK durumuna gecilmez. Bu parametreleri `agent/agent.py` dosyasindaki sabitlerden dilediginiz gibi ayarlayabilirsiniz.
Ek olarak çalışmakta olan süreçler kara listeye göre taranarak bilinen makro kaydedici programlar tespit edilmeye çalışılır ve gerekirse `macro-suspect` bildirimi gönderilir.
Makro kara listesi ve tarama aralığı artık istemcinin `.env` dosyasında tutulmaz; bu ayarlar sunucu tarafındaki ortam değişkenlerinden okunur ve istemci başlangıçta `/agent/config` uç noktasından çekilir.

İstemci, sunucuya ulaşılamadığında log kayıtlarını geçici olarak `windowlog.txt` ve `statuslog.txt` dosyalarına yazar. Bağlantı tekrar sağlandığında bu dosyalardaki veriler otomatik olarak sunucuya iletilir ve başarılı gönderilen satırlar silinir. Bu iletim işlemleri artık asenkron HTTP çağrıları kullanılarak gerçekleşir.

İstemci başlatıldığında `https://evden.baylan.info.tr/agent_version.json` adresinden güncelleme kontrolü yapar. Sunucudaki sürüm bilgisi daha yeniyse yeni sürüm geçici klasöre indirilir ve imzası doğrulanır. Ardından gömülü `updater.py` betiği çalıştırılarak indirilen dosya mevcut çalıştırılan exe'nin üzerine yazılır ve uygulama yeni sürümle yeniden başlatılır. Böylece kullanıcının aynı exe dosyasını her başlatışında tekrar güncellemesi gerekmez.

## Lisans
Bu proje MIT lisansı ile dağıtılmaktadır.
