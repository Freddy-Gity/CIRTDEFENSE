// Rendu image par image de gandal-intro.html en vidéo MP4 (H.264).
//
// La page expose window.ready et window.seek(t) : chaque image est calculée
// pour un instant exact, puis capturée. Le rendu ne dépend donc ni de la
// vitesse de la machine ni d'une horloge — deux rendus donnent le même film.
//
//   NODE_PATH="$(npm root -g)" node docs/media/gandal/render.cjs
//
// Variables : FPS (60), FFMPEG (ffmpeg), OUT (gandal-intro.mp4),
//             STILLS="1.2,5,14" pour ne produire que des images fixes.

const path = require("node:path");
const fs = require("node:fs");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { pathToFileURL } = require("node:url");
const { chromium } = require("playwright");

const ICI = __dirname;
const FPS = Number(process.env.FPS || 60);
const DUREE = 15;
const FFMPEG = process.env.FFMPEG || "ffmpeg";
const SORTIE = path.resolve(process.env.OUT || path.join(ICI, "gandal-intro.mp4"));
const STILLS = process.env.STILLS;

(async () => {
  const navigateur = await chromium.launch();
  const page = await navigateur.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  page.on("pageerror", e => { console.error("Erreur de page :", e.message); process.exitCode = 1; });
  await page.goto(pathToFileURL(path.join(ICI, "gandal-intro.html")).href + "?render");
  await page.evaluate(() => window.ready);

  if (STILLS) {
    const dossier = path.resolve(process.env.STILLS_DIR || ICI);
    fs.mkdirSync(dossier, { recursive: true });
    for (const t of STILLS.split(",").map(Number)) {
      await page.evaluate(x => window.seek(x), t);
      const fichier = path.join(dossier, `still-${t.toFixed(2)}.png`);
      await page.screenshot({ path: fichier });
      console.log(fichier);
    }
    await navigateur.close();
    return;
  }

  const ff = spawn(FFMPEG, [
    "-y", "-loglevel", "error",
    "-f", "image2pipe", "-framerate", String(FPS), "-c:v", "png", "-i", "-",
    "-c:v", "libx264", "-preset", "slow", "-crf", "18", "-pix_fmt", "yuv420p",
    "-movflags", "+faststart", SORTIE,
  ], { stdio: ["pipe", "inherit", "inherit"] });

  const total = FPS * DUREE, debut = Date.now();
  for (let i = 0; i < total; i++) {
    await page.evaluate(x => window.seek(x), i / FPS);
    const image = await page.screenshot({ type: "png" });
    if (!ff.stdin.write(image)) await once(ff.stdin, "drain");
    if (i % FPS === 0) process.stdout.write(`\r${i} / ${total} images — ${((Date.now() - debut) / 1000).toFixed(0)} s`);
  }
  ff.stdin.end();
  const [code] = await once(ff, "close");
  await navigateur.close();
  if (code !== 0) throw new Error(`ffmpeg a échoué (code ${code})`);
  console.log(`\n${SORTIE}`);
})().catch(e => { console.error(e); process.exit(1); });
