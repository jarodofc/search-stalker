# GlassOSINT — Painel de Investigação Digital & DETRAN-MG

[![Design System](https://img.shields.io/badge/Design-Liquid%20Glass%20%2F%20Material%20UX-blueviolet?style=for-the-badge&logo=apple)](#)
[![Category](https://img.shields.io/badge/Category-OSINT%20%2F%20Investigation-critical?style=for-the-badge&logo=shield)](#)
[![Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Vanilla%20JS-important?style=for-the-badge&logo=javascript)](#)

> Ferramenta de investigação digital (OSINT) e utilitário veicular em arquivo HTML único. Combina estética **Liquid Glass**, varredura progressiva de contas na web, APIs públicas com fallback automático, integração com **CPFHub.io** e acesso rápido para puxar **ATPV-e no DETRAN-MG**.

---

## 📑 Sumário
1. [Visão Geral](#1-visão-geral)
2. [Módulos Disponíveis](#2-módulos-disponíveis)
3. [Design System & Recursos](#3-design-system--recursos)
4. [Arquitetura de Fallback e Segurança](#4-arquitetura-de-fallback-e-segurança)
5. [Limitações e Considerações Técnicas](#5-limitações-e-considerações-técnicas)
6. [Como Usar](#6-como-usar)

---

## 1. Visão Geral

O **GlassOSINT** executa consultas ativas diretamente do navegador, sem necessidade de build ou backend. Todos os resultados são estruturados em cartões visuais com exportação em `.json` e histórico salvo localmente no `localStorage`.

---

## 2. Módulos Disponíveis

### 2.1 Puxar ATPV-e (DETRAN-MG)
- **Objetivo:** Agilizar a consulta e o download de uma **ATPV-e já existente** no portal oficial do DETRAN-MG.
- **Funcionamento:** Organiza **Placa, RENAVAM, CPF/CNPJ e CRV/Código de Segurança** com botões de cópia em 1 clique, salva placas recentes no histórico e abre diretamente a página oficial de emissão/consulta do DETRAN-MG.

### 2.2 Varredura OSINT (Web)
- **Objetivo:** Verificar a presença de um username ou nome em 4 categorias: **Redes Sociais, Sites Adultos, Sites de Namoro e Sites de Aposta**.
- **Funcionamento:** Verificação progressiva em tempo real via APIs públicas (GitHub, GitLab, Dev.to, Reddit) e proxy CORS (`allorigins.win`) para status HTTP, exibindo indicadores visuais:
  - 🟢 **Encontrado**
  - 🔴 **Não encontrado**
  - 🟡 **Protegido / Busca Google (Dork)** para plataformas fechadas (Tinder, Bet365, Betano, etc.).

### 2.3 CPF (CPFHub.io + Validador Local)
- **Objetivo:** Consultar dados cadastrais via **CPFHub.io** (`x-api-key`).
- **Fallback:** Caso a API esteja indisponível, executa validação matemática dos dígitos verificadores e identifica a **Região Fiscal**.

### 2.4 CNPJ
- **Objetivo:** Consultar situação cadastral, CNAE principal, capital social, endereço e **Quadro Societário (QSA)**.
- **Fontes:** `BrasilAPI` → `MinhaReceita` → `CNPJ.ws`.

### 2.5 Vazamentos (E-mail)
- **Objetivo:** Verificar exposição de e-mail em bases de vazamentos conhecidos.
- **Fonte:** `XposedOrNot API`.

### 2.6 CEP / Endereço
- **Objetivo:** Consultar logradouro, bairro, município, UF e coordenadas geográficas.
- **Fontes:** `BrasilAPI v2` → `ViaCEP`.

### 2.7 IP / Geolocalização
- **Objetivo:** Identificar país, região, cidade, ISP, ASN, fuso horário e coordenadas.
- **Fontes:** `ipwho.is` → `ipapi.co`.

### 2.8 Domínio (DNS + RDAP)
- **Objetivo:** Mapear registros `A`, `MX`, `NS`, `TXT` e dados de registro de domínio.
- **Fontes:** `Google DNS-over-HTTPS` + `rdap.registro.br` / `rdap.org`.

### 2.9 DDD (Brasil)
- **Objetivo:** Listar estado e municípios atendidos por um DDD brasileiro.
- **Fonte:** `BrasilAPI (DDD v1)`.

---

## 3. Design System & Recursos

- **Liquid Glass:** Superfícies translúcidas (`backdrop-filter: blur(24px)`) em tema escuro (`#050508`) com ícones **Material Symbols Rounded**.
- **Produtividade:** Histórico local por módulo, cópia rápida por campo, cópia de JSON completo e download em `.json`.

---

## 4. Arquitetura de Fallback e Segurança

- **`tryFallback()` + `AbortController`:** Timeout de 9 segundos por requisição com troca automática de provedor em caso de falha.
- **Proteção XSS:** Todos os dados dinâmicos passam por `escapeHtml()` antes de serem renderizados no DOM.
- **Links Seguros:** Links externos abrem com `rel="noopener noreferrer"`.

---

## 5. Limitações e Considerações Técnicas

- **CORS e Cloudflare:** Sites de namoro, apostas e parte das redes sociais bloqueiam requisições diretas do navegador. Nesses casos, o painel sinaliza como verificação manual e fornece o **Google Dork** pronto.
- **Chave de API no Front-end:** A chave da `CPFHub.io` está no cliente para uso em arquivo único. Em hospedagem pública, recomenda-se protegê-la via proxy/worker.

---

## 6. Como Usar

1. Salve o arquivo como `index.html`.
2. Abra diretamente em qualquer navegador moderno ou publique no **Cloudflare Pages**, **Netlify** ou **GitHub Pages**.
3. Selecione o módulo desejado, preencha o alvo e execute a consulta.
