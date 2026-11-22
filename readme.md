# GlassOSINT — Painel de Investigação Digital

[![Design System](https://img.shields.io/badge/Design-Liquid%20Glass%20%2F%20Material%20UX-blueviolet?style=for-the-badge&logo=apple)](#)
[![Category](https://img.shields.io/badge/Category-OSINT%20%2F%20Investigation-critical?style=for-the-badge&logo=shield)](#)
[![Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Vanilla%20JS-important?style=for-the-badge&logo=javascript)](#)

> Ferramenta de investigação digital (OSINT) construída para analistas, pesquisadores e consultores. Combina a estética **Liquid Glass** com APIs reais de correlação de dados, permitindo consultas de CPF, CNPJ, CEP, IP, Domínios (DNS + RDAP), Usernames, Vazamentos de E-mail e DDD em uma interface única e responsiva.

---

## 📑 Sumário
1. [Visão Geral](#1-visão-geral)
2. [Módulos de Investigação](#2-módulos-de-investigação)
3. [Design System](#3-design-system)
4. [Arquitetura de Fallback e Segurança](#4-arquitetura-de-fallback-e-segurança)
5. [Limitações e Considerações Técnicas](#5-limitações-e-considerações-técnicas)
6. [Como Usar](#6-como-usar)

---

## 1. Visão Geral

O **GlassOSINT** foi projetado para ser uma ferramenta de **investigação ativa** em fontes abertas (**OSINT — Open Source Intelligence**). Ele executa consultas em tempo real diretamente do navegador, estrutura os retornos em cartões visuais com ícones semânticos e permite copiar ou exportar os dados brutos em `.json`.

O projeto roda em um **arquivo HTML único**, sem necessidade de build ou instalação de dependências, com suporte a histórico local (`localStorage`) por módulo.

---

## 2. Módulos de Investigação

### 2.1 CPF (CPFHub.io + Validador Local)
- **Objetivo:** Consultar dados cadastrais vinculados a um CPF e validar a estrutura do documento.
- **Implementação:** Consulta primária na API **CPFHub.io** (via header `x-api-key`). Caso a API esteja indisponível, ativa automaticamente o fallback local com validação matemática dos dígitos verificadores e identificação da **Região Fiscal** emissora.

### 2.2 CNPJ (Empresas e Quadro Societário)
- **Objetivo:** Obter situação cadastral, atividade principal (CNAE), capital social, endereço e **QSA (Quadro Societário)**.
- **Fontes:** `BrasilAPI` → fallback para `MinhaReceita` → fallback para `CNPJ.ws`.

### 2.3 CEP / Endereço
- **Objetivo:** Localizar logradouro, bairro, município, UF e coordenadas geográficas (latitude/longitude).
- **Fontes:** `BrasilAPI v2` → fallback para `ViaCEP`.

### 2.4 IP / Geolocalização
- **Objetivo:** Identificar país, região, cidade, provedor (ISP), ASN, fuso horário e coordenadas de um endereço IP (ou do próprio IP atual se o campo ficar vazio).
- **Fontes:** `ipwho.is` → fallback para `ipapi.co`.

### 2.5 Domínio (DNS + RDAP)
- **Objetivo:** Mapear a infraestrutura técnica e o registro de um domínio.
- **Implementação:** Consultas paralelas via **Google DNS-over-HTTPS** (`A`, `MX`, `NS`, `TXT`) combinadas com protocolo **RDAP** (`rdap.registro.br` para domínios `.br` e `rdap.org` para domínios globais).

### 2.6 Username (OSINT em Plataformas)
- **Objetivo:** Rastrear a existência de perfis públicos a partir de um nome de usuário.
- **Fontes:** Consultas simultâneas nas APIs públicas do **GitHub**, **GitLab**, **Dev.to** e **Hacker News**.

### 2.7 Vazamentos (E-mail)
- **Objetivo:** Verificar se um endereço de e-mail apareceu em bases de vazamentos conhecidos (*data breaches*).
- **Fonte:** API pública **XposedOrNot**.

### 2.8 DDD (Brasil)
- **Objetivo:** Identificar o estado e listar todos os municípios atendidos por um código DDD brasileiro.
- **Fonte:** `BrasilAPI (DDD v1)`.

---

## 3. Design System

- **Estética Liquid Glass:** Superfícies translúcidas com `backdrop-filter: blur(24px) saturate(180%)`, bordas sutis de alto contraste e fundo escuro (`#050508`) com gradientes radiais suaves.
- **Iconografia Semântica:** Ícones do **Material Symbols Rounded** mapeados automaticamente conforme o nome de cada campo retornado pelas APIs.
- **Recursos de Produtividade:**
  - Navegação SPA baseada em *hash* (`#cpf`, `#cnpj`, `#domain`, etc.).
  - Histórico das últimas consultas salvas no `localStorage` com preenchimento rápido em 1 clique.
  - Botões de **Copiar JSON** e **Exportar `.json`** em todos os resultados.

---

## 4. Arquitetura de Fallback e Segurança

- **Função `tryFallback()`:** Executa uma lista ordenada de provedores com *timeout* controlado (`AbortController` de 10s). Se uma API falhar por *rate limit* ou instabilidade, a próxima assume automaticamente.
- **Proteção contra XSS:** Todos os dados dinâmicos retornados por APIs externas passam pela função `escapeHtml()` antes de serem injetados no DOM.
- **Links Externos Seguros:** Todos os links de perfis abrem em nova aba com `rel="noopener noreferrer"`.

---

## 5. Limitações e Considerações Técnicas

- **CORS no Navegador:** Algumas APIs externas podem aplicar restrições de CORS ou limites de requisições por IP (*rate limiting*). Em ambientes de produção, recomenda-se rotear as chamadas por um proxy backend leve.
- **Chave de API no Front-end:** A `x-api-key` da CPFHub.io está configurada diretamente no cliente para facilitar o uso em arquivo único. Caso hospede o projeto publicamente, mova a chave para variáveis de ambiente em um servidor/worker (ex.: Cloudflare Workers ou Netlify Functions).
- **Uso Responsável:** Utilize a ferramenta apenas para fins legítimos de pesquisa, auditoria, validação cadastral e segurança da informação, respeitando a LGPD e os termos de uso de cada API.

---

## 6. Como Usar

1. Baixe ou salve o arquivo `index.html`.
2. Abra diretamente em qualquer navegador moderno (Chrome, Edge, Brave, Firefox) ou hospede em serviços estáticos como **Cloudflare Pages**, **Netlify** ou **GitHub Pages**.
3. Escolha um módulo no painel inicial, informe o alvo e clique em **Consultar**.
