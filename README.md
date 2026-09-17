# rayengader.github.io

Portfolio site for Rayen Gader — Cyber Security Engineer, L2 SOC analyst.

Static HTML, CSS and vanilla JavaScript. No framework, no build step, no dependencies.
Two web fonts from Google Fonts; everything else ships with the page.

```
index.html               the whole page
assets/css/style.css     design tokens + layout
assets/js/main.js        terminal boot, scroll spy, attack replay, matrix, cert filter
assets/cv/               résumé PDFs (EN + FR)
.nojekyll                tells GitHub Pages to serve the files as-is
```

## Publishing it

The repository name has to be **exactly** `rayengader.github.io` for the site to
appear at that address.

1. Create the repository at <https://github.com/new> — owner `rayengader`,
   name `rayengader.github.io`, **Public**, no README, no .gitignore.
2. From this folder:

   ```bash
   git remote add origin https://github.com/rayengader/rayengader.github.io.git
   git branch -M main
   git push -u origin main
   ```

3. Repository → **Settings** → **Pages** → Source: *Deploy from a branch*,
   branch `main`, folder `/ (root)`. Save.
4. Wait a minute or two, then open <https://rayengader.github.io>.

Every later change is `git add -A && git commit -m "..." && git push` — the live site
follows within a minute.

## Keeping it current

**A new certification.** Add one row to the grid in `index.html` under
`<div class="certs" id="cert-grid">`, copying the shape of the row above it, and set
`data-domain` to one of `dfir`, `defense`, `offense`, `systems`. Then bump the two
counts that are written by hand: the `all · 18` chip label and the `18` inside
`<span id="cert-count">`.

**A new role or project.** The experience entries live under `<section id="timeline">`;
copy an `<article class="job">` block.

**A new résumé PDF.** Overwrite the files in `assets/cv/` keeping the same filenames and
nothing else needs to change.

**Colours and type.** Every colour is a custom property at the top of `style.css`. The
accent is amber `#FFB020` — the colour of an alert. Changing that one value re-themes
the page.

## Things worth adding later

- **TryHackMe and HackTheBox profile links.** The site states "Top 1% globally" but does
  not link the profile, because the handle was not to hand when it was built. Add it to
  the contact list in `index.html` under `<dl class="contact-rows">`.
- **The PFE report.** `Rapport_PFE_SOC.pdf` was deliberately left out — check it for
  client or internal detail first, then drop it in `assets/cv/` and link it from the
  `soc-build` section if it is safe to publish.
- **A social preview image.** GitHub Pages will serve one from `assets/og.png`
  (1200×630); add `<meta property="og:image">` to the head so LinkedIn shows a card
  instead of a bare link.
