# Experimento — Medição Multi-Scanner de Imagens de SO no Docker Hub
**Trilha:** SBSeg, artigos curtos (6 páginas). **Data de referência do corpus:** 18/05/2026.

## 1. Objetivo e perguntas de medição (RQs)

Medir, com a bateria multi-scanner mais recente, a postura de segurança das imagens de **sistema operacional** do Docker Hub — a raiz da cadeia de suprimentos de contêineres (todo `FROM` parte de uma delas).

- **RQ1 — Postura por distro:** quanto vulnerável é cada SO base em `:latest`? (críticas/altas por scanner, nº de pacotes, misconfig, segredos, malware)
- **RQ2 — Gradiente de defasagem:** dentro de uma família (ubuntu LTS, debian, alpine, centos), como a contagem de vulnerabilidades cresce com a idade da versão?
- **RQ3 — Divergência entre scanners no subconjunto de SO:** quanto trivy/grype/osv/clair discordam na mesma imagem de SO? (achado secundário; reusa a tese do longo aplicada a SO)
- **RQ4 — Exposição de EOL:** quanto pull ainda vai para SO **sem suporte** (centos, sl, clearlinux, clefos) — ponderado por pulls?
- **RQ5 — "Mínima = mais segura?":** imagens tiny (alpine, busybox, cirros) vs distros completas — pacotes vs CVEs. Testar a crença comum.

## 2. Corpus (23 imagens da categoria "Operating systems")

| # | Imagem | Tags | Pulls | Status |
|---|---|---|---|---|
| 1 | library/ubuntu | 10K+ | 1B+ | ativa |
| 2 | library/alpine | 10K+ | 1B+ | ativa |
| 3 | library/centos | 7.8K | 1B+ | **deprecada (EOL jun/2024)** |
| 4 | library/debian | 5.3K | 1B+ | ativa |
| 5 | library/busybox | 3.5K | 1B+ | ativa |
| 6 | library/amazonlinux | 1.5K | 500M+ | ativa |
| 7 | library/fedora | 1.3K | 100M+ | ativa |
| 8 | library/oraclelinux | 1.1K | 10M+ | ativa |
| 9 | kalilinux/kali-rolling | 1.0K | 5M+ | ativa |
| 10 | library/archlinux | 660 | 10M+ | ativa |
| 11 | library/rockylinux | 320 | 10M+ | **congelada (último push 2023)** |
| 12 | library/almalinux | 210 | 10M+ | ativa |
| 13 | library/photon | 202 | 10M+ | ativa (VMware) |
| 14 | library/clearlinux | 18 | 25M+ | **deprecada** |
| 15 | opensuse/leap | 106 | 10M+ | ativa |
| 16 | rockylinux/rockylinux | 104 | 5M+ | ativa (substitui a library/) |
| 17 | opensuse/tumbleweed | 84 | 10M+ | ativa |
| 18 | library/cirros | 79 | 5M+ | ativa (tiny test OS) |
| 19 | library/alt | 71 | 500K+ | ativa (ALT Linux, RU) |
| 20 | library/sl | 58 | 500K+ | **deprecada (Scientific Linux, EOL jun/2024)** |
| 21 | library/mageia | 44 | 1M+ | ativa |
| 22 | library/clefos | poucas | 500K+ | **deprecada (CentOS p/ IBM Z)** |
| 23 | library/opensuse | 0 | — | removida (redireciona p/ opensuse/) — **excluída** |

→ **22 imagens scaneáveis** (opensuse/library removida). Pull count vem do seu crawl (peso de popularidade).

### Amostragem de tags (sai direto do Mongo `tags_data` — sem recrawl)
Regra uniforme e reproduzível, focada em recência e em medir o efeito do desatualizamento:

> **As 100 tags mais recentes por imagem** (ordenadas por `tags_data.last_updated` desc, arquitetura amd64), fixadas por digest. Para imagens com <100 tags, todas.

- **Variável de defasagem (staleness) p/ RQ2:** `idade = hoje − last_pushed` de cada tag, lida direto do Mongo (`tags_data.images[].last_pushed`). Correlaciona-se nº de vulns × idade. Não exige escolher versão "na mão".
- **Âncoras de EOL/antigas mantidas à força:** como as 100 mais recentes tendem a ser rebuilds frescos (baixa defasagem), incluir explicitamente as séries antigas/EOL que dão *amplitude* ao eixo de idade: ubuntu 14.04/16.04, debian jessie/stretch, centos 6/7/8, alpine 3.15. Sem isso, RQ2 fica achatado.
- Estimativa: 22 imagens × ≤100 tags ≈ **1.000–1.500 pares (imagem, tag)** — trivial para o harness (já scaneou 8.382 imagens). Toda imagem **pinada por digest**, **amd64**, pull count e timestamps vindos do crawl.

## 3. Bateria de scanners (seleção pela natureza do artefato)

Imagem de SO base = *filesystem estático, sem código de app, sem serviço rodando*. Selecionamos os eixos aplicáveis da Tabela 3 do estudo de 31 scanners; DAST/Network/SAST são podados com justificativa.

| Eixo | Scanners usados | Nota |
|---|---|---|
| SBOM | **syft, cdxgen** | inventário de pacotes (denominador p/ RQ5) |
| Vuln/SCA | **trivy, grype, osv-scanner, clair** | núcleo; bases de SO diferentes |
| Hardening | **dockle, checkov** | CIS Docker Benchmark + misconfig |
| Segredos | **trufflehog, gitleaks, detect-secrets, whispers** | baseline de FP (SO não deveria ter segredo) |
| Malware/IOC | **clamav, yarahunter** | "as imagens oficiais estão limpas?" |

**13 scanners.** Podados (com justificativa no paper): govulncheck/pip-audit (app-específico), bandit/gosec/brakeman/njsscan (precisam de fonte de app), kube-linter (sem manifesto K8s — reportar como zero), todo DAST (sem serviço) e Network (sem porta).

### Reuso vs novo (tudo roda em container Docker, DooD via docker.sock)
| Status | Scanner | Imagem Docker |
|---|---|---|
| ✅ já no harness | syft, trivy, grype, osv, dockle, trufflehog | (já configurados no ChimangoScan) |
| ➕ novo | cdxgen | `ghcr.io/cyclonedx/cdxgen` |
| ➕ novo | **clair** | `quay.io/projectquay/clair` + `clairctl` (precisa de Postgres efêmero — subir em container) |
| ➕ novo | checkov | `bridgecrew/checkov` |
| ➕ novo | gitleaks | `zricethezav/gitleaks` |
| ➕ novo | detect-secrets | sem imagem oficial → wrap `python:3.12-slim` + `pip install detect-secrets` |
| ➕ novo | whispers | sem imagem oficial → wrap `python:3.12-slim` + `pip install whispers` |
| ➕ novo | clamav | `clamav/clamav` |
| ➕ novo | yarahunter | imagem do projeto / build a partir do Dockerfile |

Cada novo precisa de: (1) imagem Docker pinada, (2) comando que lê o tarball em `/work/image.tar` (mesma convenção dos 6 atuais), (3) **adapter Python** que normaliza a saída crua para o schema `Finding`. O padrão de adapter já existe — copiar de um dos 6 e ajustar o parser.

**Clair** (re-incluído): excluído do longo por *layer-indexing failure*; é o scanner de referência histórico p/ SO (Shu et al./CODASPY'17). É o de maior atrito (exige Postgres + clairctl). Testar cedo em poucas imagens; se falhar de novo → nota honesta de reprodutibilidade.

## 4. Harness e normalização (reuso do ChimangoScan/DITector)
- **Reusar o harness Docker-only existente** (`scan-pipeline (1).md`): claim de job → `docker pull @digest` → `docker save` para tarball compartilhado → cada scanner em **container Docker isolado** → adapter → schema `Finding` → merge → SQLite. Nada instalado no host.
- **Fonte da fila:** em vez do ranker por exposure, gerar a lista de jobs (imagem, tag, digest) a partir de uma query no Mongo `tags_data` (as 100 mais recentes por repo de SO + âncoras EOL). Reaproveita a mesma tabela `jobs`.
- Normalizar ao **schema Finding** já existente (scanner, scanners[], category, severity, id, package, version, cvss, location); severidade nos 6 níveis.
- **Cuidado com a RQ3:** o harness atual faz merge/dedup entre scanners (junta em `scanners[]`). Para medir divergência, **preservar o campo `scanners[]`** (já preservado) — a divergência sai de quantos scanners aparecem em cada finding `pkg-vuln`. Não precisa desligar o merge.
- Registrar **runtime por invocação** (`invocations[].wall_seconds`, já coletado).
- Hardware: o mesmo cluster de workers distribuídos já em uso.

## 5. Métricas
- **Vuln:** contagem por severidade, por scanner; união/interseção entre {trivy, grype, osv, clair}; Jaccard par-a-par por (imagem, CVE).
- **SBOM:** nº de pacotes (syft, cdxgen) — base para RQ5 (densidade de CVE por pacote).
- **Hardening:** achados Dockle/Checkov por nível (FATAL/WARN/INFO).
- **Segredos:** contagem + **rotulagem manual de FP** numa amostra (esperado ~100% FP em SO base).
- **Malware:** hits clamav/yarahunter (esperado 0 → claim "limpas").
- **EOL:** pulls acumulados em imagens deprecadas/EOL/congeladas vs ativas.

## 6. Plano de análise e figuras
- **RQ1 →** heatmap `distro × severidade` (em `:latest`), 1 painel por scanner; tabela com nº de pacotes.
- **RQ2 →** curva `nº de CVEs vs idade da versão` por família (ubuntu LTS, debian, alpine, centos).
- **RQ3 →** diagrama de Venn (trivy/grype/osv/clair) das CVEs no subconjunto SO + Jaccard médio.
- **RQ4 →** barras de pulls acumulados: ativas vs EOL/congeladas (destaque: **centos 1B+ pulls, EOL desde jun/2024**).
- **RQ5 →** dispersão `pacotes × CVEs` (tiny vs completas); testar correlação.

## 7. Ameaças à validade
- Sem ground truth → medimos **cobertura/divergência**, não acurácia (precisão/recall fora de escopo), igual ao longo.
- Amostra de tags por regra fixa, não exaustiva (10K+ tags inviável).
- amd64 apenas; multi-arch fica como trabalho futuro.
- Bases de vulnerabilidade dos scanners têm data de corte — registrar a data do scan (a recência é o argumento do paper).
- Open-source only; comerciais (Docker Scout, Snyk) fora de escopo.

## 8. Estrutura de 6 páginas (orçamento)
1. **Introdução** (¾ pág) — SO base = raiz da cadeia; medições anteriores são single-scanner e antigas; nossa contribuição = multi-scanner, recente, ponderada por popularidade.
2. **Trabalhos relacionados** (½ pág) — Shu/CODASPY'17, arXiv:2112.12597, Zerouali (technical lag), Churakova (divergência); posicionar: eles usam 1 scanner / corpus antigo.
3. **Metodologia** (1¼ pág) — corpus (Tab. 1), amostragem de tags, bateria (Tab. 2 com a justificativa de eixos), harness, normalização.
4. **Resultados** (2½ pág) — RQ1–RQ5 com as 5 figuras.
5. **Discussão/ameaças** (½ pág).
6. **Conclusão** (¼ pág) — guia prático de escolha de SO base + dataset liberado.

## 9. Ordem prática de execução
1. **Query no Mongo** `tags_data`: para os 22 repos de SO, pegar as 100 tags mais recentes (amd64) + âncoras EOL → gerar lista de jobs (imagem, tag, digest, last_pushed, pull_count). Inserir na tabela `jobs`.
2. **Validar o harness existente** rodando os 6 scanners já configurados (syft/trivy/grype/osv/dockle/trufflehog) num punhado de imagens de SO — confirma que o caminho ponta-a-ponta funciona com o corpus novo.
3. **Adicionar os scanners novos** um a um (imagem Docker + comando + adapter, copiando o padrão): cdxgen, checkov, gitleaks, detect-secrets, whispers, clamav, yarahunter. Validar cada adapter em 1–2 imagens.
4. **Clair** por último (maior atrito): subir Postgres efêmero + clairctl em container, testar em poucas imagens; decidir incluir ou registrar falha.
5. Rodar a fila completa (~1.000–1.500 jobs) nos workers.
6. Exportar findings do SQLite; gerar as 5 figuras (RQ1–RQ5).
7. Rotular manualmente a amostra de segredos (FP) para a RQ1/baseline.

## 10. Achados de execução (notas para o paper)

- **Imagens de schema legado não-puláveis (~20% skip):** ~1 em cada 5 imagens de SO pinadas por digest falha no `docker pull` com `unknown: manifest schema unsupported`. Causa: imagens antigas no **Docker manifest schema 1** (pré-2017), cujo suporte foi **removido do Docker Engine 29**. Os digests existem no Docker Hub; falta compatibilidade de formato. Concentra-se nas tags mais antigas. **Métrica/achado de longevidade de supply-chain:** fração relevante das imagens de SO historicamente puxadas não é mais instalável por um Docker moderno. Decisão: documentar (não recuperar via skopeo). Reportar taxa por distro (ubuntu = maior skip; archlinux/almalinux ≈ 0).
- **Clair tem lacuna de matcher por distro:** roda OK e acha vulns em distros suportadas (ex.: alpine), mas reporta **0** em Rocky/AlmaLinux (não mapeia rebuilds do RHEL aos feeds). Relevante para a RQ3 (divergência/cobertura por scanner).
