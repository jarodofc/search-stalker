# SHERLOCK 221B • Prism Intelligence Deck (v4.0)

Plataforma modular de Pericia Digital, Proxy & VPN Lab, OSINT e Threat Intelligence para **GitHub + Vercel**, construída sobre a identidade visual **Prism Tactical / Ivory Lab / Noir 221B** com backend serverless protegido contra SSRF e processamento forense em Web Worker.

## Arquitetura Modular
- **3 Temas Alternativos + Modo Solido:** `Prism` (escuro ciano/ouro), `Ivory` (claro) e `Noir` (ouro/carmesim), com alternador de paineis solidos para acessibilidade.
- **Zero Tailwind Play CDN:** CSS puro autossuficiente (`assets/css/styles.css`), CSP estrito em `vercel.json` e zero scripts inline.
- **15 Modulos Integrados:** VirusTotal API v3, Metadados EXIF + Mapa, Analise ELA, Custodia & Hex (Web Worker), Decodificador & JWT, Proxy & VPN Lab (Detector VPN/Proxy/Tor, servidores OpenVPN `.ovpn` e proxies live), Sherlock OSINT (12 APIs), Dorks Forenses, Vazamentos & E-mail, Subdominios SSL (`crt.sh`), DNS & Seguranca, Dono de Site (RDAP), Web Scraper & Security Headers, IP & Mapa e Consulta CNPJ & QSA.
- **Dynamic Island GitHub Footer** (`github.com/jarodofc` • `KIIK HACKING`), **Smart Omnibox** de auto-roteamento, **Command Palette (`Ctrl+K`)** e **Dossie da Sessao** em AES-256-GCM + exportacao HMAC-SHA256.

## Deploy no GitHub + Vercel
1. Extraia o conteudo da pasta `zFORENSE-prism-221b/` na raiz do repositorio Git.
2. Envie para o GitHub: `git add . && git commit -m "feat: SHERLOCK 221B Prism v4.0" && git push`.
3. Na Vercel, importe o repositorio com **Framework Preset: Other** (sem Build Command) e configure `VT_API_KEY` em **Environment Variables** para habilitar o VirusTotal v3 no servidor.
