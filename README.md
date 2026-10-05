# rayengader.github.io

Portfolio site for Rayen Gader - Cyber Security Engineer, L2 SOC analyst.

Static HTML, CSS and vanilla JavaScript. No framework, no build step, no dependencies.
Two web fonts from Google Fonts; everything else ships with the page.

```
index.html               the whole page
assets/css/style.css     design tokens + layout
assets/js/main.js        language switch, scroll spy, attack replay, matrix, cert filter, contact form
assets/js/i18n.js        the French translation of the whole page
assets/cv/               résumé PDFs (EN + FR)
.nojekyll                tells GitHub Pages to serve the files as-is
```

## English and French

English is the text in `index.html`. French lives in `assets/js/i18n.js`, keyed by CSS
selector, and the EN / FR control in the navigation swaps one for the other. The choice
is remembered, a French browser starts in French, and `?lang=fr` / `?lang=en` forces a
language - useful for the link you put on a French or English CV.

**When you change text in `index.html`, change the matching French line in `i18n.js`.**
Where a selector matches several elements the French is a list in page order, so adding
or removing an element (a role, a bullet, a filter) means adding or removing the same
position in that list. If the counts differ, that group stays in English and the browser
console prints `i18n: <selector> matches N, expected M`.

## Contact form

The form posts to [FormSubmit](https://formsubmit.co), which relays the message to the
inbox - the site has no server of its own. The address is `CONTACT_EMAIL` at the top of
the contact section in `main.js` (and the `action` of the form in `index.html`). The
first message ever sent triggers a one-time activation email from FormSubmit; nothing is
delivered until the link in it is clicked. If sending fails, the visitor is offered the
same message as a pre-filled email instead.

## Publishing it

The repository name has to be **exactly** `rayengader.github.io` for the site to
appear at that address.

1. Create the repository at <https://github.com/new> - owner `rayengader`,
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

Every later change is `git add -A && git commit -m "..." && git push` - the live site
follows within a minute.

## Keeping it current

**A new certification.** Add one row to the grid in `index.html` under
`<div class="certs" id="cert-grid">`, copying the shape of the row above it, and set
`data-domain` to one of `dfir`, `defense`, `offense`, `systems`. Then bump the two
counts that are written by hand: the `All 18` filter label and the `18` inside
`<span id="cert-count">` - and the same two in `i18n.js` (`Toutes (18)` and the heading).

**A new role or project.** The experience entries live under `<section id="experience">`;
copy an `<article class="role">` block.

**A new résumé PDF.** Overwrite the files in `assets/cv/` keeping the same filenames and
nothing else needs to change.

**Colours and type.** Every colour is a custom property at the top of `style.css`. The
accent is blue `#4D8DFF`, with `#2563EB` for filled buttons. Changing those re-themes
the page.

## Things worth adding later

- **TryHackMe and HackTheBox profile links.** The site states "Top 1% globally" but does
  not link the profile, because the handle was not to hand when it was built. Add it to
  the details list in `index.html` under `<dl class="details">`.
- **The PFE report.** `Rapport_PFE_SOC.pdf` was deliberately left out - check it for
  client or internal detail first, then drop it in `assets/cv/` and link it from the
  `work` section if it is safe to publish.
- **A social preview image.** GitHub Pages will serve one from `assets/og.png`
  (1200×630); add `<meta property="og:image">` to the head so LinkedIn shows a card
  instead of a bare link.
