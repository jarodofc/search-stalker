<div align="center">

<svg width="68" height="68" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#181D2E"/>
      <stop offset="100%" stop-color="#07080D"/>
    </linearGradient>
    <linearGradient id="gold" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#F2CC74"/>
      <stop offset="100%" stop-color="#B5822A"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="18" fill="url(#bg)" stroke="#E0B354" stroke-opacity="0.45" stroke-width="2"/>
  <circle cx="28" cy="28" r="13" fill="none" stroke="url(#gold)" stroke-width="4"/>
  <line x1="38" y1="38" x2="50" y2="50" stroke="#0A84FF" stroke-width="4.5" stroke-linecap="round"/>
  <circle cx="28" cy="28" r="4" fill="#E0B354"/>
</svg>

# SHERLOCK 221B • iOS Material Forensics

**Suíte Unificada de Perícia Digital, Análise de Malware, OSINT e Inteligência Web**  
Assinado criptograficamente por **KIIK HACKING**

[![Design](https://img.shields.io/badge/Design-iOS%20Liquid%20Glass%20%2B%20Material%203-E0B354?style=for-the-badge&logo=apple&logoColor=white)](#)
[![Icons](https://img.shields.io/badge/Icons-Vector%20SVG%20%2B%20Material%20Symbols-0A84FF?style=for-the-badge&logo=materialdesign&logoColor=white)](#)
[![Transport](https://img.shields.io/badge/Network-Remote%20Proxy%20Serverless-30D158?style=for-the-badge&logo=vercel&logoColor=white)](#)
[![Crypto](https://img.shields.io/badge/Crypto-ECDH%20P--256%20%2B%20AES--256--GCM-BF5AF2?style=for-the-badge&logo=letsencrypt&logoColor=white)](#)

</div>

---

## Sumário

1. [Arquitetura e Identidade Visual](#1-arquitetura-e-identidade-visual)
2. [Catálogo Completo de Funções (13 Módulos)](#2-catálogo-completo-de-funções-13-módulos)
3. [Equações Matemáticas, Forenses e Criptográficas](#3-equações-matemáticas-forenses-e-criptográficas)
4. [Camada de Rede e Proxy Remoto](#4-camada-de-rede-e-proxy-remoto)
5. [Segurança e Cadeia de Custódia](#5-segurança-e-cadeia-de-custódia)
6. [Instalação e Deploy na Vercel](#6-instalação-e-deploy-na-vercel)

---

## 1. Arquitetura e Identidade Visual

O **SHERLOCK 221B** combina os padrões de superfície do **iOS Liquid Glass** (Dynamic Island, listas agrupadas translúcidas, ícones Squircle e Dock flutuante) com os componentes funcionais do **Material Design 3** (campos preenchidos com rótulo flutuante, filter chips tonais e hierarquia de elevação) sob a estética investigativa de **Baker Street**.

```text
/
├── api/
│   └── proxy.js      # Proxy Remoto Serverless (Vercel) + Rota dedicada VirusTotal v3
├── index.html        # Aplicação single-file (UI iOS Material + Motores Forenses locais)
└── README.md         # Documentação técnica e especificação matemática
