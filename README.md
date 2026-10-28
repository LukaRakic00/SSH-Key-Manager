# SSH Key Manager za Windows

Uputstvo za korisnike: instalacija, prvo pokretanje, povezivanje sa GitHub nalogom, kreiranje SSH
ključeva, kloniranje privatnih repozitorijuma i rešavanje najčešćih problema.

---

## Sadržaj

1. [O projektu](#1-o-projektu)
2. [Mogućnosti](#2-mogućnosti)
3. [Preduslovi](#3-preduslovi)
4. [Instalacija korak po korak](#4-instalacija-korak-po-korak)
5. [Prvo pokretanje](#5-prvo-pokretanje)
6. [Povezivanje sa GitHub nalogom](#6-povezivanje-sa-github-nalogom)
7. [Kreiranje SSH ključa za GitHub](#7-kreiranje-ssh-ključa-za-github)
8. [Kreiranje SSH ključa za udaljeni server](#8-kreiranje-ssh-ključa-za-udaljeni-server)
9. [Kloniranje privatnog GitHub repozitorijuma](#9-kloniranje-privatnog-github-repozitorijuma)
10. [Korišćenje na drugom računaru](#10-korišćenje-na-drugom-računaru)
11. [Testiranje veze](#11-testiranje-veze)
12. [Struktura fajlova](#12-struktura-fajlova)
13. [Bezbednost](#13-bezbednost)
14. [Najčešći problemi i rešenja](#14-najčešći-problemi-i-rešenja)
15. [FAQ – često postavljana pitanja](#15-faq--često-postavljana-pitanja)
16. [Ograničenja](#16-ograničenja)

### Kako čitati ovo uputstvo

- Iznad svake komande piše u kom terminalu se izvršava: **PowerShell**, **CMD** ili **Git Bash**.
- Komande u kojima piše **PowerShell (kao administrator)** pokrenite u PowerShell prozoru otvorenom
  preko desnog klika → *Run as administrator* (*Pokreni kao administrator*).
- Delove napisane VELIKIM SLOVIMA morate zameniti svojim podacima:

| Oznaka | Čime je zamenjujete |
|--------|---------------------|
| `OWNER` | GitHub korisničko ime ili naziv organizacije koja je vlasnik repozitorijuma |
| `REPOSITORY` | naziv repozitorijuma |
| `VAŠE_KORISNIČKO_IME` | vaše GitHub korisničko ime (u primerima izlaza) |
| `ADRESA_SERVERA` | ime hosta ili IP adresa vašeg servera, na primer `server.example.com` |
| `KORISNIK` | korisničko ime na serveru |
| `PUTANJA\DO\SSH-Key-Manager` | folder u koji ste sačuvali projekat |

- Primeri naziva ključeva su uvek isti: `github-work` (poslovni GitHub nalog), `github-personal`
  (lični GitHub nalog) i `production-server` (udaljeni server). Možete koristiti i svoje nazive.
- Program prikazuje sve svoje poruke na srpskom jeziku. Poruke spoljnih alata (`ssh`, `gh`, `git`)
  ostaju na engleskom, jer ih ispisuju ti alati, a ne SSH Key Manager.

---

## 1. O projektu

**SSH Key Manager** je interaktivni program za komandnu liniju (terminal) za Windows 10 i 11. Vodi vas
kroz sve korake potrebne da na računaru napravite SSH ključ i bezbedno ga koristite za GitHub ili za
sopstvene servere.

SSH ključ je par fajlova:

- **privatni ključ** – tajna koja ostaje samo na vašem računaru;
- **javni ključ** (`.pub`) – deo koji smete da podelite i koji se dodaje na GitHub ili na server.

Kada se povezujete, računar dokazuje da poseduje privatni ključ, a GitHub ili server to proverava
pomoću javnog ključa. Lozinka se ne šalje.

### Koje probleme rešava

- Ne morate da pamtite parametre komande `ssh-keygen`.
- Ne morate ručno da uređujete fajl `~/.ssh/config`, gde je lako pogrešiti ili pokvariti postojeća
  podešavanja.
- Možete imati više GitHub naloga (na primer poslovni i lični) na istom računaru, svaki sa svojim
  ključem.
- Javni ključ se registruje na GitHub nalogu bez kopiranja i lepljenja na sajtu, preko zvaničnog
  alata GitHub CLI.
- Na novom računaru se pravi novi ključ, pa privatni ključ nikada ne prenosite sa računara na
  računar.
- Vezu možete proveriti pre nego što počnete da radite sa repozitorijumima.

Program je jedan fajl, `ssh_manager.py`, i koristi samo standardnu Python biblioteku. Ništa ne morate
da instalirate komandom `pip`, pa zato projekat nema fajl `requirements.txt`.

---

## 2. Mogućnosti

| Mogućnost | Šta tačno radi |
|-----------|----------------|
| Generisanje SSH ključeva | Pokreće Windows `ssh-keygen` i pravi Ed25519 ključ (za servere je opciono RSA 4096) u folderu `%USERPROFILE%\.ssh`. Nikada ne prepisuje postojeće ključeve. Nudi zaštitu ključa passphrase-om. |
| Automatsko ažuriranje SSH config fajla | Dodaje jasno označen blok `Host` u `%USERPROFILE%\.ssh\config`, pravi rezervnu kopiju, čuva sav postojeći sadržaj i proverava rezultat komandom `ssh -G`. |
| Povezivanje sa GitHub nalogom | Proverava prijavu u GitHub CLI (`gh auth status`) i po potrebi pokreće zvaničnu prijavu preko browsera (`gh auth login`). Nikada ne traži da unesete token. |
| Registracija javnog ključa | Dodaje **samo javni** ključ na vaš nalog kao ključ za autentifikaciju (`gh ssh-key add ... --type authentication`) i zatim proverava da li se ključ zaista nalazi na listi (`gh ssh-key list`). |
| Testiranje veze | Za GitHub pokreće `ssh -T git@ALIAS` i uspeh prijavljuje samo ako GitHub potvrdi autentifikaciju. Za server proverava prijavu bez izvršavanja ijedne komande na serveru. |
| Pregled | Prikazuje sve ključeve i blokove kojima upravlja, sa putanjama, otiscima (fingerprint) i, na vaš zahtev, javnim ključem. |

Glavni meni programa izgleda ovako:

```text
Glavni meni
  1. Kreiraj SSH ključ za GitHub
  2. Kreiraj SSH ključ za udaljeni server
  3. Prikaži upravljane SSH ključeve i konfiguracije
  4. Testiraj SSH vezu
  5. Izlaz
```

---

## 3. Preduslovi

| Alat | Obavezan | Čemu služi |
|------|----------|------------|
| Windows 10 ili Windows 11 | da | operativni sistem |
| Python 3.11 ili noviji | da | pokreće `ssh_manager.py` |
| Windows OpenSSH Client (`ssh`, `ssh-keygen`, `ssh-add`) | da | pravljenje ključeva i SSH veze |
| GitHub CLI (`gh`) | za automatsku registraciju na GitHub-u | prijava na GitHub i dodavanje javnog ključa |
| Git for Windows (`git`) | za kloniranje repozitorijuma | rad sa repozitorijumima |
| `winget` (Windows Package Manager) | preporučeno | instalacija alata jednom komandom |

Program radi u Windows Terminal-u, PowerShell-u, Command Prompt-u (CMD) i Git Bash-u.

OpenSSH Client je ugrađen u Windows 10 (verzija 1809 i novije) i u Windows 11, ali može biti
isključen. Kada je uključen, program koristi Windows verziju iz `C:\Windows\System32\OpenSSH`, čak i
ako Git Bash ili `PATH` na prvo mesto stavljaju Git-ov `ssh`. Tek ako Windows verzija ne postoji,
program koristi `ssh` koji pronađe u `PATH`-u (na primer onaj iz Git for Windows).

Bez GitHub CLI-ja program i dalje pravi ključ i podešava SSH config, ali javni ključ tada morate
ručno dodati na https://github.com/settings/keys.

---

## 4. Instalacija korak po korak

### 4.1 Provera alata koji su već instalirani

Otvorite **PowerShell** i proverite svaki alat posebno.

**PowerShell:**

```powershell
winget --version
```

Očekivani rezultat: broj verzije, na primer `v1.9.25200`. Ako se pojavi greška da komanda nije
prepoznata, instalirajte **App Installer** iz Microsoft Store-a ili instalirajte alate ručno sa
njihovih zvaničnih sajtova.

**PowerShell:**

```powershell
python --version
```

Očekivani rezultat: `Python 3.11.x` ili novija verzija. Ako se otvori Microsoft Store ili se pojavi
greška, Python nije instaliran.

**PowerShell:**

```powershell
& "$env:SystemRoot\System32\OpenSSH\ssh.exe" -V
```

Očekivani rezultat je sličan ovome (verzija može biti drugačija):

```text
OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2
```

Komanda namerno koristi punu putanju. Ako je instaliran Git for Windows, obično `ssh -V` pokreće
Git-ov OpenSSH (na primer `OpenSSH_10.2p1, OpenSSL 3.5.4 ...`), a program prednost daje Windows
verziji. Ako se pojavi greška da putanja ne postoji, uključite OpenSSH Client (poglavlje 4.2).

**PowerShell:**

```powershell
Test-Path "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe"
```

Očekivani rezultat: `True`.

**PowerShell:**

```powershell
gh --version
```

Očekivani rezultat: na primer `gh version 2.xx.x (...)`.

**PowerShell:**

```powershell
git --version
```

Očekivani rezultat: na primer `git version 2.xx.x.windows.1`.

### 4.2 Instalacija alata koji nedostaju

Instalirajte samo ono što je provera pokazala da nedostaje.

**Python – PowerShell:**

```powershell
winget install --id Python.Python.3.13
```

**OpenSSH Client – PowerShell (kao administrator):**

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

Očekivani rezultat: `Online : True` i `RestartNeeded : False`. Umesto ove komande možete otvoriti
*Settings → System → Optional features* i dodati **OpenSSH Client**.

**GitHub CLI – PowerShell:**

```powershell
winget install --id GitHub.cli
```

**Git for Windows – PowerShell:**

```powershell
winget install --id Git.Git
```

> **Važno:** posle instalacije **zatvorite i ponovo otvorite terminal**, da bi Windows učitao
> ažuriranu promenljivu `PATH`. Zatim ponovite proveru iz koraka 4.1.

### 4.3 Preuzimanje programa

Sačuvajte folder projekta (najmanje fajl `ssh_manager.py`) na računaru, na primer kopiranjem sa
USB-a, mrežnog diska ili cloud skladišta, ili preuzimanjem sa javne lokacije.

Program mora biti dostupan **nezavisno od privatnog repozitorijuma** kome želite da pristupite.
Privatni repozitorijum ne može da se klonira pre autentifikacije, osim ako već postoji neki drugi
ispravan način prijave. Više o tome u poglavlju [10](#10-korišćenje-na-drugom-računaru).

---

## 5. Prvo pokretanje

### 5.1 Ulazak u folder projekta

Zamenite `PUTANJA\DO\SSH-Key-Manager` stvarnom putanjom foldera u koji ste sačuvali projekat.

**PowerShell:**

```powershell
cd "PUTANJA\DO\SSH-Key-Manager"
```

**CMD:**

```bat
cd /d "PUTANJA\DO\SSH-Key-Manager"
```

**Git Bash** (putanja koristi kose crte `/`, na primer `/c/...`):

```bash
cd "/PUTANJA/DO/SSH-Key-Manager"
```

### 5.2 Provera zavisnosti

**PowerShell:**

```powershell
python ssh_manager.py --check
```

Komanda ništa ne menja, samo proverava stanje. Očekivani rezultat (putanje i verzije mogu biti
drugačije):

```text
SSH Key Manager 1.0.0 - provera zavisnosti
  Python      3.13.x (...)
  OS          Windows 10 (...)
[OK] ssh-keygen  C:\Windows\System32\OpenSSH\ssh-keygen.exe
[OK] ssh         C:\Windows\System32\OpenSSH\ssh.exe
[OK] ssh-add     C:\Windows\System32\OpenSSH\ssh-add.exe
[OK] gh          ...\gh.exe
[OK] git         ...\git.exe
  GitHub CLI  gh version 2.xx.x (...)
[OK] GitHub CLI je prijavljen kao 'VAŠE_KORISNIČKO_IME'. Može da dodaje SSH ključeve: da
[UPOZORENJE] ssh-agent   nije pokrenut
  Opcija 'AddKeysToAgent yes' dodaje ključ samo u ssh-agent koji je već pokrenut.
  ...
```

Ako neki obavezan alat nedostaje, program ispisuje `[GREŠKA]` i komandu za instalaciju, a izlazni
kod je `1`. Upozorenja o `gh`, `git` i `ssh-agent`-u ne sprečavaju rad programa.

### 5.3 Pokretanje programa

**PowerShell:**

```powershell
python ssh_manager.py
```

**CMD:**

```bat
python ssh_manager.py
```

**Git Bash:**

```bash
python ssh_manager.py
```

Ako u Git Bash-u ne vidite pitanje za passphrase, pokrenite program ovako:

**Git Bash:**

```bash
winpty python ssh_manager.py
```

Očekivani rezultat:

```text
SSH Key Manager 1.0.0
  Direktorijum ključeva: ...\.ssh
  SSH config:            ...\.ssh\config

Glavni meni
  1. Kreiraj SSH ključ za GitHub
  2. Kreiraj SSH ključ za udaljeni server
  3. Prikaži upravljane SSH ključeve i konfiguracije
  4. Testiraj SSH vezu
  5. Izlaz
Izaberite opciju [1-5]:
```

Kako se odgovara na pitanja:

- Na izbor iz menija odgovarate brojem, pa pritisnete Enter.
- Na pitanja sa `[D/n]` ili `[d/N]` odgovarate sa `d` (da) ili `n` (ne). Prihvataju se i `da`, `ne`,
  `y` i `yes`. Veliko slovo označava podrazumevani odgovor koji se primenjuje ako samo pritisnete
  Enter.
- Pre bilo kakve izmene program prikazuje **Plan** i pita `Nastaviti?`. Ako odgovorite `n`, ništa
  se ne menja.
- Trenutnu radnju možete prekinuti kombinacijom `Ctrl+C`. Program se tada vraća u glavni meni i
  prikazuje rezime već izvršenih koraka. `Ctrl+C` u samom glavnom meniju zatvara program.

Ostale opcije komandne linije:

**PowerShell:**

```powershell
python ssh_manager.py --help
```

**PowerShell:**

```powershell
python ssh_manager.py --version
```

---

## 6. Povezivanje sa GitHub nalogom

### 6.1 Dva različita mehanizma autentifikacije

Ovo je važno razumeti pre nego što počnete:

| | GitHub CLI autentifikacija | SSH autentifikacija |
|-|----------------------------|---------------------|
| Čemu služi | Da komanda `gh` u vaše ime koristi GitHub API (na primer da doda javni ključ na nalog) | Da `git` i `ssh` dokažu GitHub-u ko ste, kada klonirate, povlačite (pull) i šaljete (push) promene preko SSH-a |
| Kako se dobija | `gh auth login` (prijava preko browsera); gh čuva token | Par SSH ključeva; javni ključ je registrovan na vašem nalogu |
| Gde se proverava | `gh auth status` | `ssh -T git@github-work` |

SSH Key Manager koristi **GitHub CLI prijavu samo da bi registrovao javni ključ**. Posle toga Git
radi preko **SSH ključa**, nezavisno od `gh`. Uspešna prijava u `gh` ne znači da SSH radi, i obrnuto.

### 6.2 Prijava preko browsera

Program sam proverava prijavu kada izaberete opciju 1. Ako niste prijavljeni, prikazuje:

```text
[UPOZORENJE] GitHub CLI nije prijavljen na github.com: ...
  Ovaj alat nikada ne traži tokene. Može da pokrene zvaničnu prijavu preko browsera:
    gh auth login --hostname github.com --git-protocol ssh --web --skip-ssh-key
Pokrenuti prijavu preko browsera sada? [D/n]:
```

Isto možete uraditi i sami, pre pokretanja programa.

**PowerShell:**

```powershell
gh auth login --hostname github.com --git-protocol ssh --web --skip-ssh-key
```

Značenje opcija:

| Opcija | Značenje |
|--------|----------|
| `--hostname github.com` | prijava na javni GitHub (github.com) |
| `--git-protocol ssh` | gh će za Git operacije podrazumevano koristiti SSH |
| `--web` | prijava ide preko browsera; ne kucate lozinku ni token u terminal |
| `--skip-ssh-key` | gh ne nudi da sam napravi ili otpremi SSH ključ, jer to radi SSH Key Manager |

Tok prijave:

1. gh u terminalu ispisuje **jednokratni kod** (one-time code) u obliku `XXXX-XXXX`.
2. Kada pritisnete Enter, otvara se browser sa stranicom `https://github.com/login/device`.
3. U browseru se prijavite na GitHub (ako već niste) i unesite prikazani kod.
4. Pregledajte tražene dozvole i potvrdite klikom na **Authorize**.
5. Vratite se u terminal, gde gh potvrđuje da je prijava završena.

SSH Key Manager **nikada ne traži da u program nalepite token** i ne pravi Personal Access Token.

### 6.3 Provera prijave

**PowerShell:**

```powershell
gh auth status
```

Očekivani rezultat (izgled zavisi od verzije gh):

```text
github.com
  ✓ Logged in to github.com account VAŠE_KORISNIČKO_IME (keyring)
  - Active account: true
  - Git operations protocol: ssh
  - Token: gho_************************************
  - Token scopes: 'gist', 'read:org', 'repo', 'write:public_key'
```

Važan je red `Token scopes`: da bi program mogao da doda SSH ključ, token mora imati
`write:public_key` ili `admin:public_key`.

### 6.4 Odobravanje dodatne dozvole

Prijava ne daje automatski sve dozvole. Koje dozvole token dobija zavisi od verzije gh i od opcija
prijave. Ako dozvola za SSH ključeve nedostaje, program to otkriva i prikazuje:

```text
[UPOZORENJE] GitHub CLI token još ne može da dodaje SSH ključeve. Potreban je scope 'write:public_key' (ili 'admin:public_key'). Trenutni scope-ovi: gist, read:org, repo.
  Traži se samo ova jedna dodatna dozvola, kroz zvanični postupak:
    gh auth refresh --hostname github.com --scopes write:public_key
Zatražiti ovu dozvolu sada (otvara se browser)? [D/n]:
```

Isto možete uraditi i sami:

**PowerShell:**

```powershell
gh auth refresh --hostname github.com --scopes write:public_key
```

Tok je isti kao kod prijave: jednokratni kod, browser i potvrda. `write:public_key` dozvoljava
pravljenje i pregled javnih SSH ključeva na vašem nalogu, ali ne i njihovo brisanje. Program ne traži
nikakve druge dozvole.

Ako vaš token dolazi iz promenljive okruženja `GH_TOKEN` ili `GITHUB_TOKEN`, `gh auth refresh` ne može
da ga promeni. Program vas o tome obaveštava. Tada tokenu dodelite dozvolu tamo gde je napravljen, ili
uklonite promenljivu i prijavite se komandom `gh auth login`.

---

## 7. Kreiranje SSH ključa za GitHub

### 7.1 Primer celog postupka

Pokrenite `python ssh_manager.py` i izaberite `1`. Primer za poslovni nalog sa ključem `github-work`
(vaši odgovori su posle dvotačke):

```text
Kreiranje SSH ključa za GitHub
------------------------------
  Proveravam GitHub CLI prijavu (gh auth status)...
[OK] Prijavljeni ste na github.com kao 'VAŠE_KORISNIČKO_IME'.
[OK] Token ima dozvolu da dodaje SSH ključeve.
Naziv ključa (koristi se i kao SSH host alias), npr. github-work: work
Da li da koristim 'github-work', da bi alias jasno označavao GitHub? [D/n]: d
  Passphrase (lozinka ključa) šifruje privatni ključ na disku. ssh-keygen je traži
  direktno; ovaj alat je nikada ne vidi, ne čuva i ne beleži.
Zaštititi privatni ključ passphrase-om? [D/n]: d

Plan
----
  Privatni ključ : ...\.ssh\github-work
  Javni ključ    : ...\.ssh\github-work.pub
  Tip ključa     : Ed25519
  Passphrase     : da (ssh-keygen će je tražiti)
  SSH config     : dodati upravljani blok 'Host github-work' u ...\.ssh\config
  GitHub         : registrovati javni ključ kao ključ za AUTENTIFIKACIJU sa nazivom 'github-work' na nalogu 'VAŠE_KORISNIČKO_IME'
Nastaviti? [D/n]: d
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
```

Poslednja dva pitanja postavlja `ssh-keygen` (zato su na engleskom). Dok kucate passphrase, na ekranu
se ništa ne prikazuje; to je normalno.

Na kraju program prikazuje **Rezime** sa stvarnim ishodom svakog koraka:

```text
Rezime
------
  [OK]          Generisanje SSH ključa: ...\.ssh\github-work (256 SHA256:... (ED25519))
  [OK]          Ograničavanje dozvola privatnog ključa: nasleđene dozvole uklonjene; puna kontrola dodeljena korisniku ...
  [OK]          Ažuriranje SSH config fajla: upravljani blok 'github-work' dodat u ...\.ssh\config
  [OK]          Provera SSH config fajla (ssh -G): 'github-work' se razrešava u git@github.com
  [OK]          Registracija ključa na GitHub-u: dodat kao ključ za autentifikaciju sa nazivom 'github-work'
  [OK]          Provera ključa komandom 'gh ssh-key list': naveden je na vašem nalogu kao ključ za autentifikaciju
  [UPOZORENJE]  ssh-agent: ssh-agent nije dostupan, pa 'AddKeysToAgent yes' za sada nema efekta (pogledajte napomenu ispod)
```

Statusi u rezimeu:

| Status | Značenje |
|--------|----------|
| `[OK]` | korak je izvršen i proveren |
| `[UPOZORENJE]` | korak je izvršen, ali nešto treba da proverite |
| `[NEUSPEH]` | korak **nije** uspeo; razlog i predlog rešenja su odmah pored |
| `[PRESKOČENO]` | korak nije izvršavan (na primer ručna registracija ili postojeći ključ) |

Ako neki korak ne uspe, program ne briše ono što je već urađeno (na primer napravljen ključ ili
izmenjen config) i jasno prikazuje šta je uspelo, a šta nije. Program nikada ne tvrdi da je ključ
otpremljen ako komanda `gh ssh-key add` nije uspela.

Zatim program prikazuje gde su ključevi, primer `git clone` komande sa vašim aliasom, napomenu o
ssh-agent-u i nudi test veze (`Testirati vezu sada (ssh -T git@github-work)?`).

### 7.2 Naziv ključa i alias

Naziv koji unesete je istovremeno:

- naziv fajla privatnog ključa (`github-work`) i javnog ključa (`github-work.pub`);
- SSH host alias u config fajlu (`Host github-work`);
- naziv (title) ključa na GitHub-u.

Ako unesete naziv koji ne počinje sa `github` (na primer `work` ili `personal`), program **predlaže**
`github-work` odnosno `github-personal`. Ako unesete `github-work`, naziv se koristi tačno takav, pa
nikada ne nastaje `github-github-work`.

Pravila za naziv:

- dozvoljena su slova bez dijakritika (`a-z`, `A-Z`), cifre, `.`, `_` i `-`;
- naziv mora počinjati slovom ili cifrom i može imati najviše 64 znaka;
- nisu dozvoljeni `/`, `\`, `:`, `..`, razmaci i naziv koji se završava sa `.pub` ili tačkom;
- nisu dozvoljeni Windows nazivi uređaja (`CON`, `NUL`, `COM1`...), OpenSSH fajlovi (`config`,
  `known_hosts`, `authorized_keys`, `id_ed25519`, `id_rsa`...) ni `github.com`, jer bi takav alias
  promenio svaku vezu ka GitHub-u.

Ako ključ sa tim nazivom već postoji, program ga **nikada ne prepisuje**. Nudi vam da izaberete drugi
naziv ili da koristite postojeći ključ bez izmena (korisno ako je ranija registracija prekinuta).

### 7.3 Passphrase

Passphrase je lozinka koja šifruje privatni ključ na disku. Ako neko kopira fajl privatnog ključa,
bez passphrase-a ne može da ga koristi.

- Program preporučuje passphrase (podrazumevani odgovor je `D`).
- Passphrase unosite direktno u `ssh-keygen`; SSH Key Manager je nikada ne vidi, ne čuva i ne beleži.
- Ako izaberete `n`, ključ se pravi bez passphrase-a. To je jednostavnije, ali manje bezbedno.
- Da ne biste passphrase kucali pri svakom povezivanju, koristite ssh-agent (poglavlje
  [14](#ssh-agent-nije-pokrenut-ili-git-stalno-traži-passphrase)).

Passphrase postojećeg ključa možete kasnije promeniti ili dodati:

**PowerShell:**

```powershell
ssh-keygen -p -f "$env:USERPROFILE\.ssh\github-work"
```

### 7.4 Gde se nalaze ključevi

| Fajl | PowerShell putanja | Opis |
|------|--------------------|------|
| privatni ključ | `$env:USERPROFILE\.ssh\github-work` | tajna – nikome ga ne dajte |
| javni ključ | `$env:USERPROFILE\.ssh\github-work.pub` | bezbedno ga je deliti |

U CMD-u je ista putanja `%USERPROFILE%\.ssh\github-work`, a u Git Bash-u `~/.ssh/github-work`.

Otisak (fingerprint) javnog ključa možete proveriti ovako:

**PowerShell:**

```powershell
ssh-keygen -lf "$env:USERPROFILE\.ssh\github-work.pub"
```

### 7.5 Registracija javnog ključa

Kada je `gh` instaliran, prijavljen i ima potrebnu dozvolu, program izvršava:

```text
gh ssh-key add <putanja>\github-work.pub --type authentication --title github-work
```

- Otprema se **samo `.pub` fajl**. Program pre slanja proverava da fajl sadrži tačno jedan javni ključ.
- Ključ se dodaje kao **ključ za autentifikaciju** (authentication key) na vaš korisnički nalog.
  To nije *deploy key* (ključ jednog repozitorijuma) niti *signing key* (ključ za potpisivanje
  commit-ova).
- Posle dodavanja program pokreće `gh ssh-key list` i proverava da je ključ stvarno na listi kao
  ključ za autentifikaciju.

Listu ključeva možete proveriti i sami:

**PowerShell:**

```powershell
gh ssh-key list
```

Očekivani rezultat: red sa nazivom `github-work`, sadržajem ključa, datumom i tipom
`authentication`.

**Registracija bez GitHub CLI-ja:** ako `gh` nije instaliran ili ne želite automatsku registraciju,
program nudi da nastavite bez nje. Korak registracije je tada označen kao `[PRESKOČENO]`, a program
nudi da prikaže javni ključ. Zatim:

1. otvorite https://github.com/settings/keys;
2. kliknite **New SSH key**;
3. za **Key type** izaberite **Authentication Key**;
4. u polje **Key** nalepite ceo sadržaj fajla `github-work.pub`;
5. kliknite **Add SSH key**.

> Registracija SSH ključa **ne daje automatski pristup** repozitorijumima. Ključ dokazuje samo da ste
> vi vlasnik naloga; pristup imate samo repozitorijumima kojima vaš nalog već sme da pristupa.

### 7.6 Šta se upisuje u SSH config

```sshconfig
# BEGIN SSH-MANAGER github-work kind=github
# Upravlja ssh_manager.py (2026-10-28). Ne menjajte redove sa BEGIN/END oznakama.
Host github-work
    HostName github.com
    User git
    IdentityFile ~/.ssh/github-work
    IdentitiesOnly yes
    AddKeysToAgent yes
# END SSH-MANAGER github-work
```

| Red | Značenje |
|-----|----------|
| `Host github-work` | alias koji koristite umesto `github.com` |
| `HostName github.com` | stvarni server na koji se povezuje |
| `User git` | GitHub uvek koristi korisnika `git` |
| `IdentityFile ~/.ssh/github-work` | koji privatni ključ se koristi |
| `IdentitiesOnly yes` | koristi se samo ovaj ključ, ne i drugi ključevi iz agenta |
| `AddKeysToAgent yes` | ključ se dodaje u ssh-agent pri prvoj upotrebi, **ali samo ako agent već radi** |

Datum u drugom redu je datum kreiranja bloka.

---

## 8. Kreiranje SSH ključa za udaljeni server

### 8.1 Primer unosa

Pokrenite `python ssh_manager.py` i izaberite `2`. Primer za server `production-server`:

```text
Kreiranje SSH ključa za udaljeni server
---------------------------------------
Naziv ključa (koristi se i kao SSH host alias), npr. production-server: production-server
Adresa servera (ime hosta ili IP adresa): ADRESA_SERVERA
Korisničko ime na serveru: KORISNIK
SSH port (prazno za 22): 2222
Koristiti preporučeni tip ključa Ed25519? (odgovorite 'n' za RSA 4096 za starije servere) [D/n]: d
  Passphrase (lozinka ključa) šifruje privatni ključ na disku. ssh-keygen je traži
  direktno; ovaj alat je nikada ne vidi, ne čuva i ne beleži.
Zaštititi privatni ključ passphrase-om? [D/n]: d

Plan
----
  Privatni ključ : ...\.ssh\production-server
  Javni ključ    : ...\.ssh\production-server.pub
  Tip ključa     : Ed25519
  Passphrase     : da (ssh-keygen će je tražiti)
  SSH config     : dodati 'Host production-server' -> KORISNIK@ADRESA_SERVERA:2222
Nastaviti? [D/n]: d
```

- **Adresa servera** može biti ime hosta (na primer `server.example.com`), IPv4 adresa ili IPv6
  adresa. Razmaci, `%` i vrednosti koje počinju znakom `-` nisu dozvoljeni.
- **Korisničko ime** je nalog na serveru (ne vaš Windows nalog).
- **Port** ostavite prazan ako server koristi standardni port 22. Tada se red `Port` ne upisuje.

Blok koji se upisuje u config:

```sshconfig
# BEGIN SSH-MANAGER production-server kind=server
# Upravlja ssh_manager.py (2026-10-28). Ne menjajte redove sa BEGIN/END oznakama.
Host production-server
    HostName ADRESA_SERVERA
    User KORISNIK
    Port 2222
    IdentityFile ~/.ssh/production-server
    IdentitiesOnly yes
    AddKeysToAgent yes
# END SSH-MANAGER production-server
```

### 8.2 Postavljanje javnog ključa na server

SSH Key Manager **ne menja servere**. Javni ključ morate dodati u fajl `~/.ssh/authorized_keys`
korisnika na serveru. Program na kraju ispisuje gotovu komandu sa vašim podacima. Za gornji primer
ona izgleda ovako:

**PowerShell:**

```powershell
type "$env:USERPROFILE\.ssh\production-server.pub" | ssh -p 2222 KORISNIK@ADRESA_SERVERA "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
```

Ova komanda se prijavljuje postojećom lozinkom za server (ili drugim načinom prijave koji već imate)
i radi na Linux/Unix serverima. Ako to nije moguće, pošaljite sadržaj fajla `production-server.pub`
administratoru servera. **Nikada ne šaljite privatni ključ.**

### 8.3 Korišćenje aliasa

Kada je javni ključ na serveru, umesto `ssh -p 2222 KORISNIK@ADRESA_SERVERA` dovoljno je:

**PowerShell:**

```powershell
ssh production-server
```

Alias radi i sa drugim SSH alatima, na primer za kopiranje fajla na server (`izvestaj.txt` je primer
fajla, a `/tmp/` primer odredišta):

**PowerShell:**

```powershell
scp .\izvestaj.txt production-server:/tmp/
```

Efektivna podešavanja aliasa možete proveriti bez povezivanja:

**PowerShell:**

```powershell
ssh -G production-server
```

Očekivani rezultat: među redovima su `hostname ADRESA_SERVERA`, `user KORISNIK`, `port 2222` i
`identityfile ~/.ssh/production-server`.

---

## 9. Kloniranje privatnog GitHub repozitorijuma

### 9.1 Kako se koristi alias

GitHub obično daje SSH adresu u obliku:

```text
git@github.com:OWNER/REPOSITORY.git
```

Da bi Git koristio vaš ključ, zamenite `github.com` **tačnim aliasom** iz config fajla:

```text
git@github-work:OWNER/REPOSITORY.git
```

SSH tada pronalazi `Host github-work` u config fajlu, povezuje se na `github.com` kao korisnik `git`
i koristi ključ `~/.ssh/github-work`.

### 9.2 Kloniranje

Zamenite `OWNER` i `REPOSITORY` stvarnim vrednostima, na primer onima iz adrese
`https://github.com/OWNER/REPOSITORY`.

**PowerShell:**

```powershell
git clone git@github-work:OWNER/REPOSITORY.git
```

Očekivani rezultat:

```text
Cloning into 'REPOSITORY'...
...
Resolving deltas: 100% (...), done.
```

Za lični nalog koristite njegov alias:

**PowerShell:**

```powershell
git clone git@github-personal:OWNER/REPOSITORY.git
```

Program na kraju opcije 1 nudi da unesete `OWNER/REPOSITORY` i ispisuje gotovu komandu.

### 9.3 Repozitorijum koji je već kloniran

Ako ste repozitorijum ranije klonirali preko HTTPS-a ili sa `github.com`, promenite adresu:

**PowerShell:**

```powershell
git remote set-url origin git@github-work:OWNER/REPOSITORY.git
```

Proverite rezultat:

**PowerShell:**

```powershell
git remote -v
```

Očekivani rezultat:

```text
origin  git@github-work:OWNER/REPOSITORY.git (fetch)
origin  git@github-work:OWNER/REPOSITORY.git (push)
```

### 9.4 Pristup repozitorijumima

Alias **samo određuje koji ključ SSH koristi**. On ne daje pristup repozitorijumu. Možete klonirati
samo privatne repozitorijume kojima vaš GitHub nalog (onaj na kome je registrovan ključ) već ima
pristup, kao vlasnik, saradnik (collaborator) ili član tima u organizaciji.

### 9.5 Git for Windows i Windows OpenSSH (opciono)

Git for Windows podrazumevano koristi svoj `ssh`. On čita isti config fajl, pa alias radi, ali ne
koristi Windows ssh-agent servis. Ako želite da Git koristi Windows OpenSSH i ssh-agent:

**PowerShell:**

```powershell
git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
```

Program ovaj savet prikazuje sam ako `core.sshCommand` nije podešen.

---

## 10. Korišćenje na drugom računaru

Svaki računar treba da ima **svoj** ključ. Privatni ključ se **ne prenosi** sa računara na računar.
Na novom računaru se pravi novi par ključeva, a njegov javni ključ se dodaje na isti GitHub nalog.
GitHub dozvoljava više SSH ključeva na jednom nalogu.

Postupak na novom računaru:

1. **Instalirajte alate** – Python, OpenSSH Client, GitHub CLI i Git, kao u poglavlju
   [4](#4-instalacija-korak-po-korak). Posle instalacije otvorite novi terminal.
2. **Preuzmite program** – kopirajte `ssh_manager.py` (ili ceo folder) sa USB-a, mrežnog diska,
   cloud skladišta ili javne lokacije. Ako se program nalazi u **privatnom** repozitorijumu, ne možete
   ga klonirati preko SSH-a dok ne napravite ključ. Zato ga prenesite na drugi način, na primer
   kopirajte fajl sa računara koji već ima pristup.
3. **Pokrenite program** iz foldera u koji ste ga sačuvali:

   **PowerShell:**

   ```powershell
   python ssh_manager.py
   ```

4. **Prijavite se na GitHub** – izaberite opciju `1` i prihvatite prijavu preko browsera (poglavlje
   [6](#6-povezivanje-sa-github-nalogom)), sa **istim GitHub nalogom** kao na prvom računaru.
5. **Napravite novi ključ** – kao naziv možete ponovo koristiti `github-work`. Na GitHub-u će postojati
   dva ključa sa istim nazivom, ali različitim sadržajem. Ako želite da ih lakše razlikujete, koristite
   naziv kao što je `github-work-laptop`. Tada se i alias zove tako, pa u `git clone` komandi
   koristite `github-work-laptop`.
6. **Registracija** – program dodaje novi javni ključ na nalog i proverava ga komandom
   `gh ssh-key list`.
7. **SSH config** – program dodaje blok sa aliasom na novom računaru.
8. **Provera** – prihvatite test veze ili izaberite opciju `4`. Očekivani rezultat je
   `[OK] GitHub je potvrdio ovaj ključ za korisnika 'VAŠE_KORISNIČKO_IME'.`
9. **Kloniranje** – klonirajte repozitorijum aliasom sa ovog računara:

   **PowerShell:**

   ```powershell
   git clone git@github-work:OWNER/REPOSITORY.git
   ```

Kada računar više ne koristite, uklonite njegov ključ sa GitHub naloga (poglavlje
[13.4](#134-šta-uraditi-ako-je-ključ-kompromitovan)).

---

## 11. Testiranje veze

### 11.1 Test iz programa

Izaberite opciju `4` u glavnom meniju, a zatim jedan od ponuđenih unosa. Opcijom
`Drugi host alias iz SSH config fajla` možete testirati i alias koji niste napravili ovim programom.

### 11.2 GitHub

Program pokreće `ssh -T git@github-work`. Isto možete uraditi i sami:

**PowerShell:**

```powershell
ssh -T git@github-work
```

Očekivani rezultat:

```text
Hi VAŠE_KORISNIČKO_IME! You've successfully authenticated, but GitHub does not provide shell access.
```

Šta treba znati:

- GitHub **ne pruža pristup shell-u**, pa se veza odmah zatvara. To je normalno.
- GitHub i pri uspešnoj autentifikaciji vraća **izlazni kod 1**. Zato program uspeh ne procenjuje po
  izlaznom kodu, već samo po poruci `Hi ...! You've successfully authenticated`. U programu se tada
  prikazuje:

  ```text
  [OK] GitHub je potvrdio ovaj ključ za korisnika 'VAŠE_KORISNIČKO_IME'.
  ```

- Ako umesto korisničkog imena piše `Hi OWNER/REPOSITORY!`, ključ je registrovan kao **deploy key**
  jednog repozitorijuma, a ne kao ključ naloga. Program to prikazuje kao upozorenje.
- Pri prvom povezivanju SSH pita da li verujete serveru (`Are you sure you want to continue
  connecting (yes/no/[fingerprint])?`). Program pre toga ispisuje zvanične GitHub otiske
  (fingerprint). Otkucajte `yes` **samo ako se otisak poklapa** sa jednim od njih:

  ```text
  ED25519  SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU
  ECDSA    SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM
  RSA      SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
  ```

  Zvanični izvor: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints

### 11.3 Server

Program pokreće `ssh -v -N -o ConnectTimeout=15 production-server`. Opcija `-N` znači da se **ne
izvršava nijedna komanda** i ne otvara shell. Čim server potvrdi prijavu, program zatvara vezu i
prikazuje:

```text
[OK] Autentifikacija je uspela. Veza je odmah zatvorena.
```

Ručno možete proveriti prijavu i otvoriti sesiju na serveru (ovo **otvara shell**; izlazite komandom
`exit`):

**PowerShell:**

```powershell
ssh production-server
```

### 11.4 Kada test ne uspe

Program prikazuje `[GREŠKA] ... NIJE potvrđena (izlazni kod ssh: ...)` i predlog rešenja, na primer:

```text
[GREŠKA] GitHub autentifikacija NIJE potvrđena (izlazni kod ssh: 255).
  - Server je odbio ključ. Za GitHub proverite da li je javni ključ registrovan na vašem nalogu (gh ssh-key list). Za server proverite ~/.ssh/authorized_keys ciljnog korisnika.
```

Za detaljnu dijagnostiku pokrenite:

**PowerShell:**

```powershell
ssh -v -T git@github-work
```

---

## 12. Struktura fajlova

### 12.1 Fajlovi na vašem računaru

Svi SSH fajlovi su u folderu `.ssh` u vašem korisničkom folderu (`$env:USERPROFILE\.ssh` u
PowerShell-u, `%USERPROFILE%\.ssh` u CMD-u, `~/.ssh` u Git Bash-u).

| Fajl | Šta je | Smete li da ga delite? |
|------|--------|------------------------|
| `github-work` (bez ekstenzije) | **privatni ključ** – dokazuje vaš identitet | **Nikada** |
| `github-work.pub` | **javni ključ** – registruje se na GitHub-u ili serveru | Da |
| `config` | SSH podešavanja i aliasi (`Host ...`) | Ne objavljujte ga; može otkriti imena servera i korisnika |
| `config.ssh-manager-backup-GGGGMMDD-HHMMSS` | rezervna kopija config fajla pre svake izmene | Ne |
| `known_hosts` | otisci servera kojima ste potvrdili poverenje (pravi ga `ssh`) | Ne treba |

Kako program menja `config`:

- sav postojeći sadržaj ostaje isti, uključujući CRLF krajeve redova i UTF-8 BOM;
- novi blok se upisuje **pre prvog postojećeg `Host` ili `Match` unosa**, da opcije iz postojećeg
  `Host *` ne bi poništile njegova podešavanja;
- svaki blok je između redova `# BEGIN SSH-MANAGER ...` i `# END SSH-MANAGER ...`;
- unosi kojima program ne upravlja se nikada ne menjaju;
- program ne dodaje globalne opcije koje bi uticale na druge SSH veze;
- pre svake izmene se pravi rezervna kopija, a novi sadržaj se upisuje preko privremenog fajla, pa
  neuspelo upisivanje ostavlja original netaknut;
- posle upisa program pokreće `ssh -G`. Ako OpenSSH odbije novi config, original se automatski vraća.

Sadržaj config fajla možete pogledati ovako:

**PowerShell:**

```powershell
Get-Content "$env:USERPROFILE\.ssh\config"
```

**CMD:**

```bat
type "%USERPROFILE%\.ssh\config"
```

**Git Bash:**

```bash
cat ~/.ssh/config
```

### 12.2 Fajlovi projekta

```text
SSH-Key-Manager/
├── ssh_manager.py      # ceo program (samo standardna Python biblioteka)
├── README.md           # ovo uputstvo
├── .gitignore          # sprečava da ključevi, config fajlovi i tajne dospeju u Git
└── tests/              # automatski testovi (unittest)
    ├── helpers.py
    ├── test_cli.py
    ├── test_github.py
    ├── test_keys_and_runner.py
    ├── test_ssh_config.py
    └── test_validation.py
```

Ključevi se **nikada ne čuvaju u folderu projekta**, već samo u `.ssh` folderu.

Testovi ne pokreću prave `ssh`, `ssh-keygen` ni `gh` komande i ne menjaju vaš `.ssh` folder. Pokrećete
ih iz foldera projekta:

**PowerShell:**

```powershell
python -m unittest discover -s tests -t . -v
```

Očekivani rezultat na kraju: `OK`.

---

## 13. Bezbednost

### 13.1 Privatni ključ nikada ne napušta računar

- Privatni ključ **nikada ne šaljite na GitHub**, ne lepite ga u issue, chat ili e-poštu i ne
  dodajte ga (commit) u repozitorijum. Ko ima privatni ključ, može da se predstavi kao vi i da
  pristupi svim vašim repozitorijumima.
- GitHub-u i serverima treba **samo javni ključ** (`.pub`).
- Ako vas neko traži privatni ključ „radi podešavanja”, to je znak upozorenja.

Šta program radi da bi zaštitio ključ:

- nikada ne čita, ne prikazuje, ne beleži i ne šalje privatni ključ;
- čita samo `.pub` fajlove i pre toga proverava da sadrže samo javni ključ;
- javni ključ prikazuje samo kada to zatražite, uz jasnu oznaku `JAVNI ključ`;
- novom privatnom ključu ograničava dozvole (uklanja nasleđene dozvole i daje punu kontrolu samo
  trenutnom korisniku; SYSTEM i Administrators zadržavaju pristup);
- ne menja postojeće ključeve i ne briše fajlove;
- nikada ne isključuje proveru host ključa (ne koristi `StrictHostKeyChecking=no`);
- nikada ne traži GitHub token i ne pravi Personal Access Token;
- spoljne programe pokreće bez shell-a, sa proverenim argumentima;
- iz poruka o greškama uklanja sve što liči na token ili privatni ključ.

### 13.2 Passphrase

- Passphrase štiti ključ ako neko dođe do fajla (krađa laptopa, rezervna kopija, zlonamerni
  program).
- Koristite dugačku, jedinstvenu frazu i čuvajte je u menadžeru lozinki.
- Ako zaboravite passphrase, ključ ne može da se povrati. Napravite novi ključ i registrujte ga.
- Da ne biste passphrase kucali svaki put, uključite ssh-agent (poglavlje
  [14](#ssh-agent-nije-pokrenut-ili-git-stalno-traži-passphrase)).

### 13.3 Git i `.gitignore`

Projektni `.gitignore` isključuje ključeve (`id_rsa*`, `id_ed25519*`, `*.pub`, `*.pem`, `*.key`...), lokalne SSH config fajlove,
rezervne kopije, `known_hosts`, `.env` fajlove i tajne, kao i Python keš i virtuelna okruženja.
I pored toga, pre svakog commit-a proverite šta šaljete:

**PowerShell:**

```powershell
git status
```

### 13.4 Šta uraditi ako je ključ kompromitovan

Ako sumnjate da je neko došao do privatnog ključa (izgubljen laptop, ključ poslat greškom,
zlonamerni program):

1. **Odmah uklonite ključ sa GitHub-a.** Najjednostavnije je preko sajta: otvorite
   https://github.com/settings/keys i kliknite **Delete** pored ključa. Možete i preko GitHub CLI-ja.
   Brisanje zahteva scope `admin:public_key`, koji SSH Key Manager **ne** traži, pa ga prvo dodajte:

   **PowerShell:**

   ```powershell
   gh auth refresh --hostname github.com --scopes admin:public_key
   ```

   **PowerShell:**

   ```powershell
   gh ssh-key list
   ```

   Zamenite `KEY_ID` brojem iz kolone `ID` za kompromitovani ključ:

   **PowerShell:**

   ```powershell
   gh ssh-key delete KEY_ID
   ```

2. **Uklonite javni ključ sa svih servera**, iz fajla `~/.ssh/authorized_keys` (ili zamolite
   administratora da to uradi).
3. **Pregledajte bezbednosni dnevnik** na https://github.com/settings/security-log i proverite
   nepoznate aktivnosti.
4. **Napravite novi ključ** pod novim nazivom (na primer `github-work-2`) i registrujte ga.
5. **Stare fajlove obrišite ručno**, kada budete sigurni da vam više ne trebaju. SSH Key Manager
   namerno nikada ne briše ključeve ni blokove iz config fajla. Blok starog ključa uklonite ručno
   (od reda `# BEGIN SSH-MANAGER ...` do reda `# END SSH-MANAGER ...`).

---

## 14. Najčešći problemi i rešenja

### `gh` nije prepoznat

Poruka u terminalu: `gh : The term 'gh' is not recognized ...`, ili u programu
`[UPOZORENJE] GitHub CLI (gh) nije pronađen.`

1. Instalirajte GitHub CLI:

   **PowerShell:**

   ```powershell
   winget install --id GitHub.cli
   ```

2. Zatvorite i ponovo otvorite terminal (promenljiva `PATH` se učitava samo pri pokretanju).
3. Proverite instalaciju:

   **PowerShell:**

   ```powershell
   gh --version
   ```

Program sam traži `gh` i u standardnim instalacionim folderima, pa ga može pronaći čak i kada ga
terminal još ne prepoznaje.

### `ssh-keygen` nedostaje

Poruka: `Nedostaje obavezan program: ssh, ssh-keygen.` ili
`ssh-keygen : The term 'ssh-keygen' is not recognized ...`

**PowerShell (kao administrator):**

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

Zatim otvorite novi terminal i proverite:

**PowerShell:**

```powershell
& "$env:SystemRoot\System32\OpenSSH\ssh.exe" -V
```

Očekivani rezultat: red koji počinje sa `OpenSSH_for_Windows_`.

### Neuspešna autorizacija (prijava u GitHub CLI)

Poruke: `GitHub CLI nije prijavljen na github.com`, `I dalje niste prijavljeni.` ili u rezimeu
`GitHub CLI prijava nedostaje ili je istekla`.

- Ponovite prijavu:

  **PowerShell:**

  ```powershell
  gh auth login --hostname github.com --git-protocol ssh --web --skip-ssh-key
  ```

- Ako gh prijavi `unknown flag: --skip-ssh-key`, vaša verzija gh je stara. Ažurirajte je:

  **PowerShell:**

  ```powershell
  winget upgrade --id GitHub.cli
  ```

- Proverite da li ste u browseru prijavljeni na pravi GitHub nalog.
- Ako koristite `GH_TOKEN` ili `GITHUB_TOKEN`, proverite da token nije istekao ili ga uklonite iz
  trenutne PowerShell sesije, pa se prijavite ponovo:

  **PowerShell:**

  ```powershell
  Remove-Item Env:GH_TOKEN, Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
  ```

### Nedovoljne GitHub dozvole

Poruka: `GitHub CLI token još ne može da dodaje SSH ključeve.` ili u rezimeu
`[NEUSPEH] Registracija ključa na GitHub-u: NIJE otpremljen. GitHub CLI token nema dozvolu ...`

**PowerShell:**

```powershell
gh auth refresh --hostname github.com --scopes write:public_key
```

Zatim proverite red `Token scopes`:

**PowerShell:**

```powershell
gh auth status
```

Ostali razlozi koje program prepoznaje:

- **`Pravila organizacije ili preduzeća ... blokirala su zahtev`** – vaša organizacija koristi SAML
  SSO ili listu dozvoljenih IP adresa. Autorizujte token za organizaciju ili se obratite
  administratoru.
- **`GitHub već ima ovaj javni ključ`** – isti ključ je već na drugom GitHub nalogu ili je dodat kao
  deploy key. Jedan ključ može biti registrovan samo jednom; napravite novi ključ.
- **`Došlo je do mrežnog problema`** – proverite internet vezu, proxy i firewall.
- **Fine-grained token** – program ne može da očita dozvole, pa pokušava registraciju i prikazuje
  stvarni rezultat. Tokenu je potrebna dozvola **Git SSH keys: Read and write**.

Ključ i config ostaju napravljeni. Kada rešite problem, ponovo pokrenite opciju 1 sa istim nazivom i
izaberite `Koristi postojeći ključ takav kakav jeste`. Za postojeći config blok izaberite
`Zadrži postojeći upravljani blok bez izmena`.

### Dupliran alias

Poruke:

- `Host alias 'github-work' je već definisan u ... (red N) unosom kojim ovaj alat ne upravlja.` –
  alias već postoji u delu config fajla koji ste sami napisali. Program ga ne menja, pa unesite drugi
  naziv (na primer `github-work-2`).
- `Upravljani blok u SSH config fajlu za 'github-work' već postoji` – blok je ranije napravio ovaj
  program. Možete izabrati drugi naziv, zadržati blok ili ga eksplicitno zameniti (pre zamene se
  pravi rezervna kopija).
- `SSH već razrešava 'github-work' u '...' kroz postojeću konfiguraciju` – alias je definisan u
  `Include` fajlu ili ga hvata pravilo sa džokerom. Najbolje je izabrati drugi naziv.

Poređenje aliasa ne razlikuje velika i mala slova (`GitHub-Work` i `github-work` su isti alias).

### `Permission denied (publickey)`

Server ili GitHub je odbio ključ.

1. Proverite da li je ključ registrovan:

   **PowerShell:**

   ```powershell
   gh ssh-key list
   ```

2. Proverite da li koristite **tačan alias** (`git@github-work:...`, a ne `git@github.com:...`).
3. Proverite koji ključ SSH koristi za alias:

   **PowerShell:**

   ```powershell
   ssh -G github-work
   ```

   U izlazu mora postojati red `identityfile ~/.ssh/github-work`.

4. Pogledajte detaljan tok prijave:

   **PowerShell:**

   ```powershell
   ssh -v -T git@github-work
   ```

5. Za server proverite da javni ključ postoji u `~/.ssh/authorized_keys` korisnika na serveru i da
   ste uneli tačno korisničko ime.

### Neispravan config

- `Vaš postojeći SSH config već prijavljuje greške` – fajl je imao grešku i pre izmene. Pogledajte
  broj reda u poruci i ispravite ga. Proveru možete ponoviti komandom (`github-work` možete zameniti
  bilo kojim aliasom):

  **PowerShell:**

  ```powershell
  ssh -G github-work
  ```

- `'ssh -G' je odbio izmenjeni config, pa je originalni sadržaj vraćen` – program je vratio
  prethodni sadržaj; ništa nije izgubljeno.
- `SSH config, red N: upravljani blok '...' nema završnu oznaku` – neko je ručno obrisao red
  `# BEGIN SSH-MANAGER ...` ili `# END SSH-MANAGER ...`. Ispravite ili uklonite nepotpuni blok ručno.
  Program do tada ne menja fajl.
- `Bad owner or permissions on ...\.ssh\config` – pristup fajlu smeju imati samo vaš korisnik,
  SYSTEM i Administrators. U PowerShell-u pokrenite:

  **PowerShell:**

  ```powershell
  icacls "$env:USERPROFILE\.ssh\config" /inheritance:r /grant:r "${env:USERDOMAIN}\${env:USERNAME}:F" /grant:r "SYSTEM:F"
  ```

- Ako želite da vratite stariju verziju, rezervne kopije su u `.ssh` folderu
  (`config.ssh-manager-backup-...`).

### Privatni repozitorijum nije dostupan

Poruka pri kloniranju:

```text
ERROR: Repository not found.
fatal: Could not read from remote repository.
```

- Proverite `OWNER` i `REPOSITORY` (velika i mala slova, crtice).
- Proverite koji nalog GitHub vidi:

  **PowerShell:**

  ```powershell
  ssh -T git@github-work
  ```

  Korisničko ime u poruci `Hi ...!` mora biti nalog koji ima pristup repozitorijumu.
- Ako repozitorijum pripada drugom nalogu (na primer ličnom), koristite alias tog naloga
  (`github-personal`).
- Ako organizacija koristi SAML SSO, otvorite https://github.com/settings/keys, kliknite
  **Configure SSO** pored ključa i autorizujte ga za organizaciju.
- Ako nemate pristup, zatražite ga od vlasnika repozitorijuma. **Registracija ključa ne daje
  pristup** repozitorijumima za koje vaš nalog nema ovlašćenje.

### ssh-agent nije pokrenut ili Git stalno traži passphrase

Poruka: `ssh-agent nije dostupan, pa 'AddKeysToAgent yes' za sada nema efekta`.

`AddKeysToAgent yes` ne pokreće agenta, a servis *OpenSSH Authentication Agent* je na Windowsu
podrazumevano isključen. Uključite ga:

**PowerShell (kao administrator):**

```powershell
Get-Service ssh-agent | Set-Service -StartupType Automatic
```

**PowerShell (kao administrator):**

```powershell
Start-Service ssh-agent
```

Zatim dodajte ključ (traži passphrase jednom):

**PowerShell:**

```powershell
ssh-add "$env:USERPROFILE\.ssh\github-work"
```

Proverite koji su ključevi učitani:

**PowerShell:**

```powershell
ssh-add -l
```

Ako Git i dalje traži passphrase, podesite ga da koristi Windows OpenSSH (poglavlje
[9.5](#95-git-for-windows-i-windows-openssh-opciono)).

### `Host key verification failed` ili `REMOTE HOST IDENTIFICATION HAS CHANGED`

Otisak servera nije potvrđen ili se promenio. Proverite otisak iz pouzdanog izvora (za GitHub
pogledajte poglavlje [11.2](#112-github)). **Ne isključujte proveru host ključa.** Tek kada ste
sigurni da je promena legitimna, uklonite stari zapis:

**PowerShell:**

```powershell
ssh-keygen -R ADRESA_SERVERA
```

### `UNPROTECTED PRIVATE KEY FILE`

Dozvole privatnog ključa su previše otvorene:

**PowerShell:**

```powershell
icacls "$env:USERPROFILE\.ssh\github-work" /inheritance:r /grant:r "${env:USERDOMAIN}\${env:USERNAME}:F"
```

### Slova č, ć, š, ž, đ se ne prikazuju ispravno

U Windows konzoli (Windows Terminal, PowerShell, CMD) program ispisuje tekst preko Unicode
interfejsa konzole, pa se slova normalno prikazuju ispravno. Ako vidite kvadratiće, izaberite font
koji ima ova slova (na primer Cascadia Mono ili Consolas). Kada izlaz preusmeravate u fajl ili u
drugi program, kao i u Git Bash-u, program piše UTF-8. U Git Bash-u zato proverite da je u
podešavanjima prozora (*Options → Text → Character set*) izabran UTF-8.

---

## 15. FAQ – često postavljana pitanja

**Koliko SSH ključeva treba da imam?**
Preporuka je jedan ključ po računaru za svaki GitHub nalog, i poseban ključ za svaki server ili grupu
servera. Ako ukradu jedan računar, uklonite samo ključ tog računara, a ostali nastavljaju da rade.

**Mogu li da koristim jedan ključ za više repozitorijuma?**
Da. Ključ registrovan kao ključ za autentifikaciju naloga važi za **sve repozitorijume kojima vaš
nalog ima pristup**. Za svaki repozitorijum ne treba poseban ključ.

**Mogu li da imam različite ključeve za različite GitHub naloge?**
Da, i to je razlog za aliase. Napravite `github-work` dok ste u `gh` prijavljeni na poslovni nalog, a
`github-personal` dok ste prijavljeni na lični nalog. Klonirate sa
`git clone git@github-work:OWNER/REPOSITORY.git`, odnosno
`git clone git@github-personal:OWNER/REPOSITORY.git`. GitHub ne dozvoljava da isti javni ključ bude
na dva naloga.

**Kako da program registruje ključ na drugom GitHub nalogu?**
Program registruje ključ na nalogu koji je aktivan u GitHub CLI-ju (vidi se u
`Prijavljeni ste na github.com kao '...'` i u planu). Pre opcije 1 prijavite se na željeni nalog:

**PowerShell:**

```powershell
gh auth login --hostname github.com --git-protocol ssh --web --skip-ssh-key
```

Ako ste već prijavljeni na više naloga, aktivni nalog menjate ovako (`VAŠE_KORISNIČKO_IME` zamenite
nalogom na koji prelazite):

**PowerShell:**

```powershell
gh auth switch --hostname github.com --user VAŠE_KORISNIČKO_IME
```

**Koja je razlika između javnog i privatnog ključa?**
Privatni ključ (`github-work`) je tajna i ostaje samo na vašem računaru. Javni ključ
(`github-work.pub`) je kao brava koju može da otvori samo vaš privatni ključ. Bravu smete da date
svakome (GitHub-u, serveru), ali privatni ključ ne dajete nikome. Iz javnog ključa nije moguće
izračunati privatni.

**Mogu li da prekopiram ključ na drugi računar?**
Tehnički da, ali se ne preporučuje i ovaj program to ne radi. Na svakom računaru napravite novi ključ
(poglavlje [10](#10-korišćenje-na-drugom-računaru)).

**Da li moram da imam GitHub CLI?**
Ne. Bez njega program pravi ključ i config, a javni ključ dodajete ručno na
https://github.com/settings/keys kao **Authentication Key**.

**Šta je deploy key i da li ga program pravi?**
Deploy key je ključ vezan za jedan repozitorijum, a ne za nalog. Program ga **ne pravi**; uvek
registruje ključ za autentifikaciju naloga (`--type authentication`).

**Da li program briše stare ključeve?**
Ne. Program nikada ne briše ključeve, rezervne kopije ni blokove iz config fajla. To radite ručno
(poglavlje [13.4](#134-šta-uraditi-ako-je-ključ-kompromitovan)).

---

## 16. Ograničenja

- Podržan je samo javni GitHub (`github.com`), ne i GitHub Enterprise Server.
- Program ne postavlja javni ključ na udaljeni server; ispisuje predlog komande, a postavljanje radite
  sami.
- Program ne briše ključeve sa GitHub-a ni sa računara; za to pogledajte poglavlje
  [13.4](#134-šta-uraditi-ako-je-ključ-kompromitovan).
- Program ne pokreće i ne podešava ssh-agent servis (za to su potrebna administratorska prava); samo
  prikazuje stanje i uputstvo.
- Dozvole tokena se čitaju iz izlaza komande `gh auth status`. Kod fine-grained tokena ne mogu da se
  očitaju, pa program pokušava registraciju i prikazuje stvarni rezultat.
- Parser config fajla prepoznaje `Host` unose i sopstvene oznake. Podešavanja iz `Include` fajlova i
  `Match` blokova ne čita direktno, nego ih proverava komandom `ssh -G`.
- Poruke spoljnih alata (`ssh`, `ssh-keygen`, `gh`, `git`) ostaju na engleskom. Program prevodi samo
  najčešće greške opcija komandne linije; ostale poruke biblioteke `argparse` ostaju na engleskom.
- Rezervne kopije config fajla se gomilaju u `.ssh` folderu; stare kopije možete ručno obrisati kada
  vam više ne trebaju.
- Naziv ključa može sadržati samo slova bez dijakritika (bez č, ć, š, ž, đ), cifre, `.`, `_` i `-`.
