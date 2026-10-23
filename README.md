# PacketPhantom

Analyseur réseau temps réel : il capture le trafic, reconstruit les conversations et lève des alertes (mots de passe en clair, scans de ports, usurpation ARP, tunnels DNS…). Il s'utilise dans le terminal ou depuis un tableau de bord web.

- Interface terminal et tableau de bord web
- Lecture de fichiers `.pcap` / `.pcapng`, export PCAP
- Déchiffrement TLS 1.2 et 1.3 avec un fichier `SSLKEYLOGFILE`
- Inventaire des hôtes, empreintes TLS JA3 / JA4
- Globe 3D : les paquets voyagent de pays en pays en temps réel
- Mode capteur sans interface, avec API REST

## Prérequis

- **Python 3.10 ou plus récent**
- **Rust** : installé automatiquement par `setup.sh` sous Linux et macOS
- **Windows** : [Npcap](https://npcap.com) et [Rust](https://rustup.rs), à installer avant

## Installation

### Linux / macOS

```bash
git clone https://github.com/VISCHENZISCH/PacketPhantom.git
cd PacketPhantom
./setup.sh
```

Le script installe les dépendances système (apt, dnf ou pacman), Rust si besoin, crée l'environnement `.venv` et compile le projet. Comptez quelques minutes la première fois.

### Windows

1. Installez [Npcap](https://npcap.com) et [Rust](https://rustup.rs).
2. Clonez le dépôt, puis lancez `setup.bat`.
3. Lancez `run.bat` **en tant qu'administrateur**.

### Docker

```bash
docker build -t packetphantom .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e PACKETPHANTOM_TOKEN=mon-jeton packetphantom -i eth0
```

Le tableau de bord est alors sur http://127.0.0.1:8787.

## Premier lancement

```bash
./run.sh                     # capture en direct dans le terminal (demande sudo)
./run.sh --api               # idem + tableau de bord web
./run.sh -r capture.pcapng   # analyser un fichier (sans sudo)
./run.sh -L                  # lister les interfaces réseau
./run.sh --help              # toutes les options
```

Avec `--api`, l'adresse du tableau de bord s'affiche au démarrage, par exemple `http://127.0.0.1:8787/#token=…`. Ouvrez-la telle quelle : le jeton qu'elle contient sert d'authentification.

Dans le terminal, appuyez sur `?` pour afficher l'aide, `s` pour démarrer ou arrêter la capture, `q` pour quitter.

## Options utiles

| Option | Rôle |
|---|---|
| `-i eth0` | interface de capture |
| `-f "tcp port 443"` | filtre de capture (syntaxe BPF, comme tcpdump) |
| `-Y "tls or dns"` | filtre d'affichage initial |
| `-r fichier.pcap` | lire un fichier au lieu de capturer |
| `--api [HÔTE:]PORT` | tableau de bord web (défaut : `127.0.0.1:8787`) |
| `--api-token JETON` | jeton fixe (sinon aléatoire à chaque lancement) |
| `--headless` | sans interface : alertes en JSON sur la sortie standard |
| `--tls-keylog FICHIER` | déchiffrer TLS (voir plus bas) |
| `--rules FICHIER` | régler la détection (voir plus bas) |
| `--db FICHIER` | conserver les alertes entre deux lancements |
| `--home LAT,LON` | position de votre réseau sur le globe, ex. `--home 48.85,2.35` |

Exemples de filtres d'affichage : `ip.addr == 10.0.0.0/8`, `port 443`, `domain contains "google"`, `alert >= high`.

## Globe du trafic

Dans le tableau de bord, la page **Globe** (menu de gauche) montre les paquets en vol entre votre réseau et le reste du monde : orange pour le trafic sortant, bleu pour l'entrant. Cliquez-glissez pour faire tourner le globe, survolez un point pour voir le pays et le volume.

Le globe a besoin de la géolocalisation (activée par défaut) et de la position de votre réseau :
- avec `--geo online` (par défaut sans base GeoLite2), elle est déduite automatiquement ;
- sinon, indiquez-la avec `--home LAT,LON`.

## Déchiffrer TLS

Firefox, Chrome, curl et la plupart des clients écrivent leurs clés TLS si la variable `SSLKEYLOGFILE` est définie :

```bash
export SSLKEYLOGFILE=~/tls-keys.log
firefox &
./run.sh --api --tls-keylog ~/tls-keys.log
```

Cliquez ensuite sur un flux TLS dans le tableau de bord, ou appuyez sur `f` dans le terminal : la conversation s'affiche en clair.

## Régler la détection et garder l'historique

```bash
cp packaging/rules.example.toml rules.toml   # puis modifiez rules.toml
./run.sh --api --rules rules.toml --db alerts.db
```

- `rules.toml` permet de changer les seuils, de désactiver une règle ou d'ignorer un hôte précis. Le fichier d'exemple est commenté.
- `--db` conserve les alertes, leur acquittement et les exceptions. Les alertes sont gardées 30 jours (`--retention JOURS` pour changer).
- Dans le tableau de bord, une alerte peut être **acquittée**, ou **ignorée** pour sa source. La page **Exceptions** permet d'annuler.

## Problèmes fréquents

| Symptôme | Solution |
|---|---|
| `Environnement absent : lancez d'abord ./setup.sh` | L'installation n'a pas été faite ou a échoué : relancez `./setup.sh`. |
| La capture demande le mot de passe à chaque fois | Autorisez la capture sans sudo : `sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"` |
| Aucun paquet capturé | Vérifiez l'interface avec `./run.sh -L`, puis `./run.sh -i <interface>`. |
| Le tableau de bord affiche « Jeton absent » | Ouvrez l'adresse complète affichée au lancement (avec `#token=…`). |
| `Address already in use` | Le port 8787 est pris : `./run.sh --api 8788`. |
| Windows : aucune interface | Installez Npcap et lancez `run.bat` en administrateur. |

## Développement

```bash
.venv/bin/python -m pytest                                   # tests
VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --release   # recompiler après une modification Rust
.venv/bin/ruff check packetphantom tests                     # lint
```

La documentation de l'API REST est accessible depuis le tableau de bord, menu **Aide & API**.

## Licence

MIT. N'analysez que des réseaux dont vous êtes propriétaire ou pour lesquels vous avez une autorisation explicite.
