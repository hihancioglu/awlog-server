# AWLog Server

Bu depo, evden çalışan kullanıcıların pencere ve AFK durumlarını takip etmek için geliştirilmiş Flask tabanlı sunucu uygulamasını içerir. `agent` klasöründeki istemci scripti, kullanıcının aktif pencere bilgilerini ve klavye/fa re etkinliklerini izleyerek bu sunucuya iletir.

## Özellikler
- **WindowLog** ve **StatusLog** modelleri ile kullanıcının aktif pencere ve AFK bilgileri kaydedilir.
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

## Ortam Değişkenleri
- `SECRET` – İstemcilerin gönderdiği istekleri doğrulamak için kullanılan anahtar.
- `KEEPALIVE_INTERVAL` – Keepalive bildirimlerinin beklenen aralığı (saniye).
- `OFFLINE_MULTIPLIER` – Kullanıcıyı çevrimdışı kabul etmeden önce beklenen keepalive süresinin kaç katı süre geçmesi gerektiği.
- `MONITOR_INTERVAL` – Arka plan izleme iş parçacığının kontrol aralığı (saniye).
- `TIMEZONE_OFFSET` – Raporlarda kullanılacak saat dilimi ofseti (UTC + değer).
- `REMEMBER_ME_DAYS` – "Beni Hatırla" seçiliyse oturumun geçerli kalacağı gün
  sayısı (varsayılan 30).

## API Uç Noktaları
- `POST /api/log` – `log_type` alanı "window" veya "status" olduğunda ilgili verileri kaydeder.
- `POST /report` – Kullanıcının çevrim içi/çevrim dışı/afk durumunu bildirir.
- `GET /api/statuslogs` – Son 50 durum kaydını JSON olarak döndürür.
- `GET /api/window_usage` – Belirtilen kullanıcı için pencere kullanım süresi özetini döndürür.
- `GET /api_logs` – Tüm API isteklerinin ham loglarını görüntüler (sadece admin).

Ayrıca `/`, `/daily_timeline`, `/weekly_report` ve `/usage_report` gibi HTML sayfaları mevcuttur.

## İstemci (Agent)
`agent` klasörü, Windows için hazırlanmış örnek istemci uygulamasını içerir. Bu istemci; aktif pencere değişimlerini, klavye/fare etkinliklerini ve AFK durumunu tespit ederek düzenli olarak sunucuya gönderir.

## Lisans
Bu proje MIT lisansı ile dağıtılmaktadır.
