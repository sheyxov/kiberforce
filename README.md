# 🛡️ KiberForce Tool

**KiberForce** — Hash və şifrələrin (cipher) avtomatik aşkarlanması və qırılması üçün nəzərdə tutulmuş yüksək performanslı, modul quruluşlu Python CLI alətidir.

---

## 🚀 Əsas Xüsusiyyətlər
* **Avtomatik Aşkarlama**: Hash (MD5, SHA-X, BLAKE) və şifrə (Base64, Hex, ROT) növlərini özü tanıyır.
* **Yüksək Sürət**: `multiprocessing` dəstəyi ilə CPU nüvələrindən maksimum səmərə ilə istifadə edir.
* **Modul Arxitektura**: Yeni alqoritmlər əlavə etmək çox asandır.
* **Professional CLI**: İstifadəsi rahat, detallı loglama və formatlanmış çıxış.

---

## ⚙️ Quraşdırma

```bash
# 1. Repozitoriyanı yükləyin və qovluğa daxil olun
git clone https://github.com/sheyxov/kiberforce
cd kiberforce

# 2. Lazımi kitabxanaları quraşdırın
pip install -r requirements.txt
```
📖 Nümunə İşlətmə (Usage Examples)
1. Hash Qırma (Wordlist ilə)

Əgər hash-ın növünü bilirsinizsə və ya avtomatik aşkar edilməsini istəyirsinizsə:
Bash

python3 kiberforce.py -i "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413" -w rockyou.txt

2. Şifrəni Deşifrə Etmə (Base64/Hex/ROT)

Şifrəli mətnlər üçün wordlist lazım deyil:
Bash

# Base64 nümunəsi
python3 kiberforce.py -i "SGVsbG8gS2liZXJGb3JjZQ=="

# Hex nümunəsi
python3 kiberforce.py -i "48656c6c6f"

3. İrəli Səviyyə Parametrlər

Sürəti artırmaq və ya xüsusi parametrlər təyin etmək üçün:
Bash

# SHA256 alqoritmi üçün 8 worker ilə işlətmək
python3 kiberforce.py -i "<hash>" -w wordlist.txt -a sha256 --workers 8

# Detallı məlumat (verbose) görmək üçün
python3 kiberforce.py -i "<hash>" -w wordlist.txt -v
