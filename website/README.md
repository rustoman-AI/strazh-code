# strazh.dev — marketing site

A single static page (no framework, no build step). The whole site is three files
plus assets:

```
website/
  index.html      # the landing page
  styles.css      # design tokens mirrored from the desktop app
  assets/         # logo + product screenshots
  CNAME           # custom domain for GitHub Pages (strazh.dev)
  netlify.toml    # Netlify config
  vercel.json     # Vercel config
```

Because it's plain HTML/CSS, you can also just open `index.html` locally, or serve
the folder with any static server:

```bash
# from the website/ folder
python -m http.server 5173
# then visit http://localhost:5173
```

## Deploy

Pick whichever host you prefer. The publish directory is this `website/` folder.

### GitHub Pages (recommended — already wired up)

A workflow at `.github/workflows/deploy-site.yml` deploys `website/` to Pages on
every push to `main` that touches the site.

1. In the repo: **Settings → Pages → Build and deployment → Source: GitHub Actions**.
2. Push to `main`. The workflow publishes the site and applies the custom domain
   from `website/CNAME` (`strazh.dev`).
3. Under **Settings → Pages**, confirm the custom domain shows `strazh.dev` and
   enable **Enforce HTTPS** once the certificate is issued.

### Netlify

1. New site → import the repo.
2. **Base directory:** `website` · **Publish directory:** `website` · **Build command:** leave empty.
   (These are already set in `netlify.toml`.)
3. **Domain settings → Add custom domain → `strazh.dev`**, then follow the DNS step below.

### Vercel

1. New project → import the repo.
2. **Root directory:** `website` · Framework preset: **Other** · no build command.
3. **Settings → Domains → add `strazh.dev`**, then follow the DNS step below.

## Pointing `strazh.dev` at the site

Set these records at your DNS provider (apex + `www`). Use the values for the host
you deployed to:

**GitHub Pages**

| Type  | Name  | Value |
|-------|-------|-------|
| A     | `@`   | `185.199.108.153` |
| A     | `@`   | `185.199.109.153` |
| A     | `@`   | `185.199.110.153` |
| A     | `@`   | `185.199.111.153` |
| CNAME | `www` | `<your-user>.github.io` |

**Netlify / Vercel** — add the domain in the dashboard and use the apex/`www`
records it shows you (an `A`/`ALIAS` to their load balancer and a `CNAME` for
`www`). Both can also manage DNS for you if you move the nameservers.

After DNS propagates, enable HTTPS (automatic on all three hosts).

## Updating content

- Copy — edit `index.html`.
- Colors/spacing — edit `styles.css` (tokens at the top mirror the desktop app:
  background `#0B1017`, panel `#151E29`, teal accent `#20C7BB`).
- Screenshots — drop new PNGs in `assets/` and update the `<img>` references.
- Download links + checksums — update the Download section in `index.html` when a
  new release ships (links point at the GitHub release assets).
