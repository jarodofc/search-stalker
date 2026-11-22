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
Assinado criptograficamente por **KIIK HACKING**

[![Themes](https://img.shields.io/badge/Themes-Prism%20%7C%20Ivory%20%7C%20Noir-2DD4BF?style=for-the-badge&logo=apple&logoColor=06090F)](#)
[![Design](https://img.shields.io/badge/UI-iOS%20Material%203%20%7C%20Vector%20SVG-38BDF8?style=for-the-badge&logo=materialdesign&logoColor=white)](#)
[![Network](https://img.shields.io/badge/Tools-Proxy%20%26%20VPN%20Lab%20(6%20APIs)-E2B354?style=for-the-badge&logo=wireguard&logoColor=06090F)](#)
[![Crypto](https://img.shields.io/badge/Crypto-ECDH%20P--256%20%2B%20AES--256--GCM-30D158?style=for-the-badge&logo=letsencrypt&logoColor=white)](#)

</div>

---

## Sumário

1. [Aparência Alternativa & Arquitetura Deck](#1-aparência-alternativa--arquitetura-deck)
2. [Catálogo Completo de Funções (14 Módulos)](#2-catálogo-completo-de-funções-14-módulos)
3. [Equações Matemáticas, Forenses e Criptográficas](#3-equações-matemáticas-forenses-e-criptográficas)
4. [Camada de Transporte via Proxy Remoto](#4-camada-de-transporte-via-proxy-remoto)
5. [Segurança, Dossiê e Cadeia de Custódia](#5-segurança-dossiê-e-cadeia-de-custódia)
6. [Deploy na Vercel](#6-deploy-na-vercel)

---

## 1. Aparência Alternativa & Arquitetura Deck

Esta edição reformula a estética para o padrão **Prism Intelligence Deck** com **3 aparências alternáveis em 1 clique** (botão de paleta na barra superior ou na rail lateral):

- **Prism Tactical (Padrão):** Fundo carbono profundo com orbes espectrais, vidro líquido translúcido, borda refrativa prisma (`#2DD4BF` → `#E2B354`) e ícones vetoriais Squircle.
- **Ivory Lab (Claro Pericial):** Modo diurno em vidro fosco claro de alto contraste, inspirado em dossiês impressos e interface iPadOS/Material 3.
- **Baker Street Noir:** Modo clássico em obsidiana, ouro envelhecido e acentos carmesim.

### Recursos Estruturais
- **Compact Vector Icon Rail:** Barra vertical minimalista de 76 px no desktop (e drawer deslizante no mobile) liberando área útil para laudos e mapas.
- **Omnibox de Auto-Roteamento:** Na tela inicial, colar um **CNPJ**, **SHA-256**, **IPv4**, **E-mail**, **URL**, **Domínio** ou **Username** redireciona e executa automaticamente o módulo correspondente.
- **Command Palette (`Ctrl + K`) & Dossiê da Sessão:** Busca instantânea entre os 14 módulos e registro automático de todas as evidências da sessão (`CASE-221B-...`).

```text
/
├── api/
│   └── proxy.js      # Proxy Remoto Serverless (Vercel) + Rota VirusTotal API v3
├── index.html        # Prism Intelligence Deck (14 módulos + 3 temas)
└── README.md         # Documentação técnica e equações forenses
