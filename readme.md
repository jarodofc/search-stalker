# GlassOSINT • iOS Material Edition (KIIK HACKING)

[![Design](https://img.shields.io/badge/UI-iOS%20Liquid%20Glass%20%7C%20Material%203-0A84FF?style=for-the-badge&logo=apple)](#)
[![Security](https://img.shields.io/badge/Security-P2P%20E2EE%20%7C%20KIIK%20HACKING-30D158?style=for-the-badge&logo=shield)](#)
[![Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Web%20Crypto%20API-5E5CE6?style=for-the-badge&logo=javascript)](#)

> Painel OSINT, Central de Proxy, Web Scraping e Central Veicular em arquivo HTML único. Construído com design **iOS Liquid Glass + Material Design 3**, setorização limpa, fallback automático de APIs e camada silenciosa de criptografia P2P assinada por **KIIK HACKING**.

---

## 📑 Sumário
1. [Setores e Módulos](#1-setores-e-módulos)
2. [Central de Proxy (Gateway + Listas Live)](#2-central-de-proxy-gateway--listas-live)
3. [Redundância de APIs (Fallback)](#3-redundância-de-apis-fallback)
4. [Segurança e Criptografia P2P (KIIK HACKING)](#4-segurança-e-criptografia-p2p-kiik-hacking)
5. [Como Publicar](#5-como-publicar)

---

## 1. Setores e Módulos

### Setor 1 — Documentos & Veículos
- **Consulta CPF:** Integração com `CPFHub.io` e fallback local (validação matemática e Região Fiscal).
- **Consulta CNPJ:** Razão social, situação cadastral, CNAE, endereço e Quadro Societário (QSA).
- **Central Veicular (MG):** Organização de Placa (detecção automática Mercosul/Cinza), RENAVAM, consulta automática do titular (CPF/CNPJ), Tabela FIPE e atalhos para **DETRAN-MG (Situação e ATPV-e), SENATRAN (SERPRO) e Multas PBH**.
- **Consulta CEP:** Endereço completo e coordenadas geográficas.

### Setor 2 — Investigação, Dorks & Vazamentos
- **OSINT Direto (APIs):** Varredura paralela em **11 plataformas 100% compatíveis** com retorno real via API (GitHub, GitLab, Dev.to, Reddit, Hacker News, Chess.com, Lichess, Codeforces, npm, Wikipédia PT e Scratch).
- **Central de Dorks:** Buscas filtradas no Google organizadas por categoria (Redes Sociais, Sites Adultos, Namoro e Apostas).
- **Vazamentos (E-mail):** Verificação de exposição em bases vazadas (`XposedOrNot`) + fallback de validação MX.

### Setor 3 — Sites, Proxy & Infraestrutura
- **Central de Proxy:** Gateway CORS multi-rota e coletor de proxies HTTP/SOCKS ativos em tempo real.
- **Proprietário de Site:** Extração de **Titular (Proprietário)**, **Documento (CNPJ/CPF em `.br`)**, e-mail de contato, registrador, datas e registros DNS (`A`, `MX`, `NS`, `TXT`) via RDAP + DoH.
- **Web Scraper:** Extração de metadados, e-mails públicos, telefones (padrão BR), redes sociais e links externos usando o motor multi-proxy.
- **IP & Geolocalização:** Operadora (ISP), ASN, país, cidade e coordenadas.

---

## 2. Central de Proxy (Gateway + Listas Live)

O módulo **Central de Proxy** reúne duas funções principais em abas:

1. **Gateway URL (CORS Bypass):** Roteia requisições GET para qualquer URL pública através de 3 gateways com fallback automático (`AllOrigins` → `CodeTabs` → `CorsProxy.io`), exibindo rota utilizada, status HTTP, latência (ms), tamanho em KB e prévia da resposta com cópia e exportação assinada.
2. **Lista de Proxies (Live):** Busca servidores proxy ativos filtráveis por protocolo (`HTTP/HTTPS`, `SOCKS4`, `SOCKS5`) e país (`Global`, `BR`, `US`, `DE`), com cópia individual (`IP:Porta`), cópia em lote e exportação em JSON assinado.

---

## 3. Redundância de APIs (Fallback)

| Módulo | Fonte Principal | Alternativas (Fallback) |
| :--- | :--- | :--- |
| **Central de Proxy (Gateway)** | AllOrigins Proxy | CodeTabs Proxy → CorsProxy.io |
| **Central de Proxy (Listas)** | ProxyScrape v2 | GeoNode API → GitHub SpeedX List |
| **Consulta CPF** | CPFHub.io | Motor Fiscal Local |
| **Consulta CNPJ** | BrasilAPI | MinhaReceita → CNPJ.ws |
| **Consulta CEP** | BrasilAPI v2 | ViaCEP → AwesomeAPI |
| **Proprietário de Site** | RDAP Registro.br / RDAP.org + Google DoH | RDAP Verisign + Cloudflare DoH |
| **Web Scraper** | AllOrigins Proxy | CodeTabs Proxy → CorsProxy.io |
| **IP & Geolocalização** | ipwho.is | ipapi.co → FreeIPAPI |
| **Vazamentos (E-mail)** | XposedOrNot | Google DoH (MX Check) |

---

## 4. Segurança e Criptografia P2P (KIIK HACKING)

- **Criptografia P2P Silenciosa:** Implementada via **Web Crypto API** (`ECDH P-256` + `AES-256-GCM`) para selar o armazenamento local sem poluir a interface.
- **Assinatura Criptográfica:** Todo relatório copiado ou baixado em `.json` inclui assinatura **HMAC-SHA256** vinculada a `signed_by: "KIIK HACKING"`.
- **Proteção Anti-Inspeção:** Bloqueio de `F12`, `Ctrl+Shift+I/J/C/K`, `Cmd+Option+I/J/C`, `Ctrl+U`, `Ctrl+S`, clique direito e arraste, sem falsos positivos em dispositivos móveis ou navegadores com barra lateral.
- **Encapsulamento Total:** Código isolado em IIFE (`'use strict'`) com sanitização `escapeHtml()` contra XSS.

---

## 5. Como Publicar

1. Substitua os arquivos `index.html` e `README.md` na raiz do repositório.
2. Envie via `.\deploy.ps1` (ou `git add . ; git commit -m "update" ; git push`).
3. O deploy na Vercel / GitHub Pages / Cloudflare Pages entra no ar automaticamente.
