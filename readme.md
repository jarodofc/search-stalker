<div align="center">

<svg width="72" height="72" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="p-bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0E1729"/>
      <stop offset="100%" stop-color="#06090F"/>
    </linearGradient>
    <linearGradient id="p-teal" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#2DD4BF"/>
      <stop offset="100%" stop-color="#38BDF8"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="18" fill="url(#p-bg)" stroke="#2DD4BF" stroke-opacity="0.48" stroke-width="2"/>
  <circle cx="28" cy="28" r="13" fill="none" stroke="url(#p-teal)" stroke-width="3.8"/>
  <line x1="38" y1="38" x2="50" y2="50" stroke="#E2B354" stroke-width="4.4" stroke-linecap="round"/>
  <circle cx="28" cy="28" r="3.6" fill="#2DD4BF"/>
</svg>

# SHERLOCK 221B • Prism Intelligence Deck

**Plataforma Forense, Auditoria Proxy/VPN, Análise de Malware e OSINT**  
Assinado criptograficamente por **KIIK HACKING** • Repositório oficial: [`github.com/jarodofc`](https://github.com/jarodofc)

[![GitHub](https://img.shields.io/badge/GitHub-jarodofc-080A10?style=for-the-badge&logo=github&logoColor=white)](https://github.com/jarodofc)
[![Themes](https://img.shields.io/badge/Themes-Prism%20%7C%20Ivory%20%7C%20Noir-2DD4BF?style=for-the-badge&logo=apple&logoColor=06090F)](#)
[![Design](https://img.shields.io/badge/UI-iOS%20Material%203%20%7C%20Dynamic%20Island-38BDF8?style=for-the-badge&logo=materialdesign&logoColor=white)](#)
[![Crypto](https://img.shields.io/badge/Crypto-ECDH%20P--256%20%2B%20AES--256--GCM-30D158?style=for-the-badge&logo=letsencrypt&logoColor=white)](#)

</div>

---

## Sumário

1. [Arquitetura Deck, Temas & Dynamic Island](#1-arquitetura-deck-temas--dynamic-island)
2. [Catálogo Completo de Funções (14 Módulos)](#2-catálogo-completo-de-funções-14-módulos)
3. [Equações Matemáticas, Forenses e Criptográficas](#3-equações-matemáticas-forenses-e-criptográficas)
4. [Camada de Transporte via Proxy Remoto](#4-camada-de-transporte-via-proxy-remoto)
5. [Segurança, Dossiê e Cadeia de Custódia](#5-segurança-dossiê-e-cadeia-de-custódia)
6. [Deploy na Vercel](#6-deploy-na-vercel)

---

## 1. Arquitetura Deck, Temas & Dynamic Island

O **SHERLOCK 221B • Prism Intelligence Deck** combina superfícies translúcidas **iOS Material 3**, ícones vetoriais **SVG / Material Symbols** e **3 aparências alternáveis em 1 clique** (botão de paleta na barra superior ou na rail lateral):

- **Prism Tactical (Padrão):** Carbono profundo com orbes espectrais, borda refrativa prisma (`#2DD4BF` → `#E2B354`) e vidro líquido.
- **Ivory Lab (Claro Pericial):** Interface diurna de alto contraste em vidro fosco claro.
- **Baker Street Noir:** Obsidiana clássica com acentos em ouro envelhecido.

### Elementos de Interface
- **Dynamic Island GitHub (Rodapé):** Cápsula flutuante estilo iOS Dynamic Island ancorada na base da estação de trabalho com ícone vetorial do GitHub, indicador ativo, selo `KIIK HACKING`, expansão interativa (*spring*) no hover e link direto para [`https://github.com/jarodofc`](https://github.com/jarodofc). Oculta automaticamente na impressão em PDF (`@media print`).
- **Compact Vector Icon Rail:** Barra vertical minimalista de 76 px no desktop (e drawer deslizante no mobile).
- **Omnibox de Auto-Roteamento:** Colar um **CNPJ**, **SHA-256**, **IPv4**, **E-mail**, **URL**, **Domínio** ou **Username** aciona automaticamente o módulo correspondente.
- **Command Palette (`Ctrl + K`) & Dossiê da Sessão:** Busca instantânea entre os 14 módulos e arquivamento automático de evidências (`CASE-221B-...`).

```text
/
├── api/
│   └── proxy.js      # Proxy Remoto Serverless (Vercel) + Rota VirusTotal API v3
├── index.html        # Prism Intelligence Deck (14 módulos + 3 temas + Dynamic Island GitHub)
└── README.md         # Documentação técnica e equações forenses
