# LWB Domaine .cd — vérification des noms en .cd pour WHMCS

Module « registrar » WHMCS (`lwbdomainecd`) qui affiche le **vrai statut** des noms de domaine
en `.cd`, `.ac.cd`, `.edu.cd`, `.gouv.cd`, `.com.cd`, `.net.cd` et `.org.cd` dans la recherche de domaines
de WHMCS, en interrogeant directement le WHOIS du registre (`whois.nic.cd`, port 43).

- Il sert **uniquement à la vérification de disponibilité**. Il n'enregistre aucun domaine :
  l'enregistrement, le transfert et le renouvellement renvoient le message
  « Enregistrement manuel via le registre .cd », et les commandes se traitent à la main.
- **Un domaine n'est affiché « disponible » que si le registre le dit explicitement.**
  Délai dépassé, connexion refusée, réponse vide, limite de requêtes atteinte ou réponse
  non reconnue : le statut est « inconnu », jamais « disponible ».

Compatible WHMCS 8.x et PHP 8.1 à 8.3, sans dépendance externe en production.

## Comment le registre répond

Relevé sur `whois.nic.cd` le 12/10/2026 :

| Cas | Extrait de la réponse | Statut affiché |
|---|---|---|
| Nom libre (`.cd`, `.ac.cd`, `.gouv.cd`…) | `Domain Name: zzqtest….cd` puis `Domain Status: No Object Found` | disponible |
| Nom pris (ex. `ispbunia.ac.cd`) | `Registry Domain ID: 33365-niccd`, `Creation Date: …`, `Registrar: SCPT` | non disponible |
| Nom réservé (ex. `gouv.cd`) | `Registrar: NIC Reserved`, `Domain Status: inactive` | réservé |

Attention : même pour un nom **libre**, le registre renvoie une ligne `Domain Name: …`.
Le module teste donc d'abord les marqueurs « pris » et « réservé », puis la phrase
« libre », et seulement ensuite la ligne `Domain Name`.

## Installation

1. Copier le dossier `modules/registrars/lwbdomainecd/` dans `modules/registrars/` de WHMCS.
2. Dans l'administration : **Configuration › Paramètres système › Registraires de domaines**,
   activer « LWB Domaine .cd (vérification WHOIS) » et enregistrer la configuration
   (les valeurs par défaut conviennent).
3. Sur la même page, cliquer sur **Lookup Provider** et choisir ce module.
4. Dans **Configuration › Paramètres système › Tarifs des domaines**, créer les extensions
   vendues (`.cd`, `.ac.cd`, `.org.cd`…) avec leurs prix, sans registraire d'enregistrement
   automatique.

Les tables `mod_lwbdomainecd_cache` et `mod_lwbdomainecd_rate` sont créées
automatiquement à la première recherche.

## Configuration

| Réglage | Par défaut | Rôle |
|---|---|---|
| Serveur WHOIS / port | `whois.nic.cd` / `43` | serveur du registre .cd |
| Délai d'attente | 5 s | au-delà : statut « inconnu » |
| Extensions .cd gérées | `.cd .ac.cd .edu.cd .gouv.cd .com.cd .net.cd .org.cd` | une par ligne |
| Phrases « domaine libre » | `No Object Found`, `No match`, `No Data Found`, `not found`, `is available` | une par ligne ; la première est celle du registre |
| Phrases « réservé » | `Registrar: NIC Reserved` | les statuts `inactive` et `serverHold` sont toujours non disponibles |
| Cache « pris / réservé » | 10 min | |
| Cache « libre » | 2 min | |
| Requêtes max. par minute et par IP | 20 | les conditions du WHOIS interdisent les requêtes massives ; 0 = pas de limite |
| Extensions suggérées (bouton « Configurer » du Lookup Provider) | `.cd,.ac.cd,.gouv.cd,.edu.cd,.com,.net,.org,.biz,.info,.blog,.ca,.club` | extensions proposées quand le client tape un nom sans extension (12 au maximum). **Ne pas laisser vide** : WHMCS ne demande des suggestions au module que si cette liste est remplie. Seuls les noms libres sont proposés, car la page de commande affiche chaque suggestion comme disponible. Les extensions mises en avant (« Spotlight » dans Tarifs des domaines) ne sont pas répétées dans la liste |
| Autres extensions | cochée | le Lookup Provider s'applique à **toutes** les extensions : cochée, `.com`, `.net`… sont vérifiées par le WHOIS standard de WHMCS ; décochée, elles sont ignorées et n'apparaissent plus dans les résultats |

## Ouvrir le port 43 sortant (CSF)

Sur un serveur cPanel avec CSF, ajouter `43` à `TCP_OUT` dans `/etc/csf/csf.conf`, puis
redémarrer CSF :

```
TCP_OUT = "20,21,25,43,53,80,110,113,443,587,993,995"
csf -r
```

Test depuis le serveur : `whois -h whois.nic.cd ispbunia.ac.cd`.

## Dépannage

Chaque requête est journalisée dans **Utilitaires › Journaux › Journal des modules**
(activer « Enable Debug Logging ») : domaine demandé, serveur, réponse brute du registre et
statut déduit avec sa raison (ex. `available : libre (No Object Found)`).

- Tous les .cd en « inconnu » : le port 43 sortant est bloqué ou le serveur ne répond pas
  (voir le message « connexion impossible » ou « délai dépassé » dans le journal).
- « limite de requêtes atteinte » : augmenter la limite par minute ou attendre une minute.
- Le registre change sa formulation : ajouter la nouvelle phrase dans « Phrases domaine libre ».

## Tests

```
composer install
vendor/bin/phpunit
```

Les tests couvrent l'analyse des réponses (pris, réservé, libre, vide, limite de requêtes,
autre domaine) avec des réponses réelles du registre, et le client WHOIS (réponse brute,
réponse vide, délai dépassé, connexion refusée). Ils tournent automatiquement sur GitHub
Actions avec PHP 8.1, 8.2 et 8.3.

## Licence

MIT — LEWEBMAX Admin.
