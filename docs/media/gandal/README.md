# GANDAL — animation de présentation (15 s)

| Fichier | Rôle |
|---|---|
| `gandal-intro.mp4` | La vidéo : 1920 × 1080, 60 i/s, H.264, 15 s |
| `gandal-intro.html` | La source : ouvrir dans un navigateur pour la lire en boucle |
| `gandal-poster.png` | Carton final (image fixe, t = 14 s) |
| `render.cjs` | Rendu image par image de la page vers la vidéo |
| `fonts/` | Sora, Inter, JetBrains Mono — SIL Open Font License 1.1 |

## Découpage

| Temps | Plan |
|---|---|
| 0,0 – 1,4 s | Un point de lumière, une ligne d'horizon qui s'ouvre |
| 1,4 – 3,8 s | « Chaque milliseconde compte. » ; le parc supervisé se forme en réseau 3D |
| 4,3 – 5,9 s | **01 Détecter** : un nœud passe au rouge, trafic hostile vers la cible |
| 5,9 – 7,5 s | **02 Décider** : réticule, faisceaux d'analyse, lecture de classification (A4 · force brute) |
| 7,5 – 9,0 s | **03 Agir** : bouclier hexagonal, onde de neutralisation, « Confiné · 4 ms » |
| 9,0 – 10,25 s | Tout le réseau converge vers le centre |
| 10,25 s | Impact : éclair, onde de choc, éclat anamorphique, aberration chromatique |
| 10,25 – 14,5 s | Le monogramme se trace, puis le nom GANDAL, la signature et la devise |
| 14,5 – 15 s | Fondu au noir (la page boucle sans saut) |

## Lire la source

Ouvrir `gandal-intro.html` dans un navigateur. Espace : pause / lecture,
`R` : revenir au début, la barre de lecture apparaît au survol.
`gandal-intro.html?t=12.5` fige l'image à 12,5 s.

## Modifier

Tous les textes affichés sont dans l'objet `TEXTES` en tête du script ;
la chronologie est dans l'objet `T`. Aucun autre endroit n'est à toucher
pour changer un libellé ou décaler un plan.

## Refaire la vidéo

Il faut Node, le paquet `playwright` avec son Chromium, et un `ffmpeg`
compilé avec `libx264`.

```bash
NODE_PATH="$(npm root -g)" node docs/media/gandal/render.cjs
```

Toute l'animation est pilotée par une seule horloge : la page expose
`window.seek(t)`, et le script capture chaque image à un instant exact. Deux
rendus produisent donc le même film, quelle que soit la vitesse de la machine.

Variables utiles : `FPS=30` pour un rendu plus rapide, `FFMPEG=/chemin/ffmpeg`,
`STILLS="1.2,6.9,14"` pour ne sortir que quelques images fixes.
