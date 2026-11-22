# GlassOSINT — Painel de Investigação Digital

[![Design System](https://img.shields.io/badge/Design-Liquid%20Glass%20%2F%20Material%20UX-blueviolet?style=for-the-badge&logo=apple)](#)
[![Category](https://img.shields.io/badge/Category-OSINT%20%2F%20Investigation-critical?style=for-the-badge&logo=shield)](#)
[![Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Vanilla%20JS-important?style=for-the-badge&logo=javascript)](#)

> Ferramenta de investigação digital (OSINT) construída para detetives e pesquisadores. Combina a estética **Liquid Glass** da Apple com APIs reais de correlação de dados, permitindo buscas de usernames, verificação de vazamentos de e-mail, análise de telefones e consultas de CNPJ, CPF e Placa.

---

## 📑 Sumário
1. [Visão Geral](#1-visão-geral)
2. [Módulos de Investigação](#2-módulos-de-investigação)
3. [Design System](#3-design-system)
4. [Arquitetura de Fallback](#4-arquitetura-de-fallback)
5. [Limitações e Considerações Técnicas](#5-limitações-e-considerações-técnicas)
6. [Referências](#6-referências)

---

## 1. Visão Geral

O **GlassOSINT** foi projetado para ser uma ferramenta de **investigação ativa**. Diferente de dashboards passivos, ele executa consultas em APIs públicas e retorna dados estruturados para análise. O foco é **OSINT (Open Source Intelligence)**: obtenção de informações a partir de fontes abertas e legítimas.

O projeto é um arquivo HTML único, sem dependências de backend, o que permite execução imediata em qualquer navegador moderno.

---

## 2. Módulos de Investigação

### 2.1 Sherlock (Username Search)
**Objetivo:** Rastrear a presença de um username em redes sociais.

**Implementação:** Consulta as APIs públicas do **GitHub** e **Reddit** (via proxy CORS
