<div align="center">

<svg width="72" height="72" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="ws-bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#161B2B"/>
      <stop offset="100%" stop-color="#090B10"/>
    </linearGradient>
    <linearGradient id="ws-gold" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#EBC369"/>
      <stop offset="100%" stop-color="#A67422"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="16" fill="url(#ws-bg)" stroke="#D9A74A" stroke-opacity="0.45" stroke-width="2"/>
  <circle cx="28" cy="28" r="13" fill="none" stroke="url(#ws-gold)" stroke-width="3.8"/>
  <line x1="38" y1="38" x2="50" y2="50" stroke="#0A84FF" stroke-width="4.4" stroke-linecap="round"/>
  <circle cx="28" cy="28" r="3.6" fill="#D9A74A"/>
</svg>

# SHERLOCK 221B • Investigation Workstation

**Estação Profissional de Perícia Digital, Análise de Malware, OSINT e Inteligência Web**  
Assinado criptograficamente por **KIIK HACKING**

[![Layout](https://img.shields.io/badge/Architecture-Workstation%20App%20Shell-D9A74A?style=for-the-badge&logo=apple&logoColor=white)](#)
[![Design](https://img.shields.io/badge/Design-iOS%20Material%203%20%7C%20Sherlock-0A84FF?style=for-the-badge&logo=materialdesign&logoColor=white)](#)
[![Proxy](https://img.shields.io/badge/Network-Remote%20Proxy%20Serverless-30D158?style=for-the-badge&logo=vercel&logoColor=white)](#)
[![Crypto](https://img.shields.io/badge/Crypto-ECDH%20P--256%20%2B%20AES--256--GCM-BF5AF2?style=for-the-badge&logo=letsencrypt&logoColor=white)](#)

</div>

---

## Sumário

1. [Arquitetura da Estação de Trabalho](#1-arquitetura-da-estação-de-trabalho)
2. [Catálogo Completo de Funções (13 Módulos)](#2-catálogo-completo-de-funções-13-módulos)
3. [Equações Matemáticas, Forenses e Criptográficas](#3-equações-matemáticas-forenses-e-criptográficas)
4. [Camada de Rede e Proxy Remoto](#4-camada-de-rede-e-proxy-remoto)
5. [Cadeia de Custódia, Dossiê e Segurança](#5-cadeia-de-custódia-dossiê-e-segurança)
6. [Deploy e Configuração na Vercel](#6-deploy-e-configuração-na-vercel)

---

## 1. Arquitetura da Estação de Trabalho

O **SHERLOCK 221B** adota uma arquitetura de **Investigation Command Workstation** em tela cheia (*App Shell*), combinando a fluidez translúcida do **iOS Material 3**, ícones vetoriais **SVG / Material Symbols** e a identidade investigativa **Sherlock 221B**:

- **Sidebar Fixa / Drawer Responsivo:** Navegação setorizada permanente com telemetria de rede (`Proxy Remoto` + selo `P2P E2EE` de `KIIK HACKING`).
- **Topbar de Comando (`Ctrl + K`):** Título contextual, *Command Palette* instantânea para salto rápido entre ferramentas e contador vivo de evidências.
- **Workbench em 2 Painéis (*Master–Detail*):** Painel esquerdo dedicado à aquisição de parâmetros/arquivos e painel direito dedicado a laudos periciais, tabelas chave-valor, gráficos ELA e mapas.
- **Dossiê Unificado da Sessão:** Painel lateral retrátil que grava automaticamente cada consulta realizada na sessão (`EV-001`, `EV-002`, ...) e permite exportar todo o caso em um único JSON assinado com **HMAC-SHA256**.

```text
/
├── api/
│   └── proxy.js      # Proxy Remoto Serverless (Vercel) + Rota VirusTotal API v3
├── index.html        # Investigation Workstation single-file (App Shell + 13 Módulos)
└── README.md         # Documentação técnica e formulação matemática
