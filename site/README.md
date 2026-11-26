# The Uninvited website

Three static pages, Live (`index.html`), Results and Method, with no build step, no framework and no third-party code. Every page reads one file, `data/snapshot.json`, and draws itself from it with `js/app.js`. That one file is also the replay: commit the final snapshot and the same pages show the finished experiment, with no key.

## Update the data

The site is not a live feed: the snapshot is replaced and committed at check-ins, a few times a day. The pages show how old it is (from its `generated` time), and once it is more than 5 minutes old during the run they say it is a check-in snapshot. A finished run's final snapshot never shows that.

On the controller (or on a copy of its data folder):

    python -m uninvited.export --data /var/lib/uninvited --out site/data/snapshot.json

The export holds no addresses (each attacker is a keyed hash) and refuses to write anything that looks like one. The site never shows usernames.

The repo-wide `.gitignore` hides every `data/` folder; `site/.gitignore` lets this one through, because it holds only the anonymised export.

## Publish

The site is served by GitHub Pages at **https://uninvited.aryangorde.com**, published by `.github/workflows/pages.yml` whenever something in `site/` changes on `main` (so each check-in's commit of `data/snapshot.json` republishes it within a minute or two). Nothing is built: the folder is uploaded as it is.

Once, in this order:

1. **DNS** (done Thu 26 Nov 2026; at the DNS host for aryangorde.com): a `CNAME` record with name `uninvited` and target `aryangorde6.github.io`. Then verify the domain on GitHub (your profile's Settings › Pages › Add a domain), which shows a `TXT` record to add; a verified domain can't be claimed by anyone else's Pages site.
2. **Make the repository public** (a free account serves Pages only from a public repository) and push `main` with `site/` and the workflow.
3. **Turn Pages on** for the workflow and set the domain:

       gh api -X POST repos/aryangorde6/uninvited/pages -f build_type=workflow
       gh api -X PUT repos/aryangorde6/uninvited/pages -f cname=uninvited.aryangorde.com

   then run the workflow once (Actions › Website › Run workflow, or `gh workflow run pages.yml`).
4. **HTTPS:** when GitHub has issued the certificate (minutes, sometimes an hour), `gh api -X PUT repos/aryangorde6/uninvited/pages -F https_enforced=true`.

With publishing from a workflow, no `CNAME` file is needed: the domain is a repository setting. The address is also written into each page's link-preview and canonical tags (`og:url`, `og:image`, `link rel="canonical"`), so change those three pages too if it ever moves.

## Try it locally

    python3 -m http.server 8765 --directory site

then open http://localhost:8765. (Opening the HTML file directly won't work: browsers block reading the JSON from `file://`.)

## Files

- `index.html`, `results.html`, `method.html`: the pages. The text that comes from the data sits in elements marked `data-fill="..."`.
- `js/app.js`: reads the snapshot every 5 minutes and fills the pages. Attacker data goes in as text, never as HTML.
- `css/site.css`: the look. The three arm colours (`--none`, `--m10`, `--h12`) are the same everywhere.
- `img/`: the art, as AVIF with a WebP fallback, made from `design/` with ffmpeg. `img/og.jpg` is the 1200×630 link preview (the wide hero with the title, text kept clear of the guardians).
- `fonts/uninvited-display.woff`: Ubuntu Sans, condensed and extra-bold, cut down to Latin characters; licence in `fonts/LICENCE.txt`.

## Content security policy

Each page allows only its own files (`default-src 'none'`, scripts, styles, images, fonts and data from `'self'`), so nothing is loaded from anywhere else.
