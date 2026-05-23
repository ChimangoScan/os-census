# Ground truth parcial da divergencia entre scanners de CVE (RQ3)

Censo de imagens base de SO (Trivy, Grype, OSV-Scanner, Clair) — validacao por leitura humana de pares (imagem, CVE)

> **Nota de re-verificacao independente (revisao posterior).** Reli os advisories
> autoritativos dos veredictos e encontrei UM erro sistematico: os 5 FP com
> `causa=version_range` (setuptools, CVE-2024-6345 e CVE-2025-47273) usaram um
> limite inferior errado (59.8.0). Os GitHub Security Advisories
> (GHSA-cx63-2mw6-8hw5 e GHSA-5rjg-fvgr-3xxf) dao faixa `< 70.0.0` e `< 78.1.1`
> SEM limite inferior, logo as versoes instaladas (39.2.0, 41.2.0, 53.0.0, 59.6.0)
> estao DENTRO da faixa vulneravel = TP. Reclassifiquei os 5 de FP para TP em
> `verdicts_corrected.jsonl`.
>
> **Correcao 2 (Clair source-vs-binary).** O agente marcou 8 dos 10 FP do Clair
> como "pacote-fonte vs binario" sem checar se o codigo vulneravel esta no
> binario instalado. Conferi nos advisories: CVE-2026-8376 e um buffer overflow
> em `Perl_study_chunk` (NUCLEO do interpretador, presente em `perl-base`; Debian
> marca 5.40.1-6 vulneravel, no-dsa) e CVE-2026-4437 e da glibc (DNS via
> `gethostbyaddr`), e `libc6` E a glibc runtime. Logo `perl-base`/`libc6`
> instalados ESTAO afetados = TP, nao FP. Reclassifiquei esses 8 de FP para TP.
> Permanecem FP os 2 legitimos: CVE-2007-5686 (Debian "unimportant") e
> CVE-2013-4392 (systemd de 2013, fora de faixa no systemd 249).
>
> **Correcao 3+4 (auditoria completa dos 200).** Reli TODOS os 200 (nao so as
> suspeitas). Achei mais 2 erros source-vs-binary na direcao oposta (TP que sao
> FP): (3) CVE-2023-4733 (vim use-after-free) marcado TP em `vim-data`, que nao
> tem executavel -- inconsistente com o proprio FP do agente em CVE-2023-5344
> (mesmo `vim-data`); (4) CVE-2017-1000082 (parsing de username no PID1 do
> systemd) marcado TP em `libsystemd0`, mas o SBOM so tem `libsystemd0` (sem o
> daemon systemd), entao o codigo vulneravel esta ausente -- inconsistente com o
> proprio FP do agente em CVE-2013-4392. Ambos reclassificados TP->FP.
>
> **Numeros finais (4 correcoes, todos os 200 reauditados):** precision global
> **0.942** (IC95 Wilson [0.900, 0.968]); por engine **Trivy 0.93, Grype 0.94,
> OSV-Scanner 1.00, Clair 0.93**. Os 11 FP restantes sao todos legitimos:
> subpacotes so-de-dados (`vim-data`/`vim-common`), bibliotecas compartilhadas
> sem o codigo do daemon (`libsystemd0`), e CVEs que a distro marca
> nao-vulnerabilidade (CVE-2007-5686 "unimportant", CVE-2005-2541 "intended
> behaviour", CVE-2013-4392 fora de faixa). Achado: os QUATRO engines sao
> individualmente de alta precisao (0.93-1.00); nenhum e outlier; a divergencia
> quase total entre eles e cobertura/feed, NAO erro de matching. O paper usa
> estes numeros.

## 1. Resumo executivo

De uma amostra estratificada de 200 pares (imagem, CVE, scanner), seed=42, extraida do conjunto consolidado de findings dos 4 engines, classifiquei manualmente cada par lendo: (a) o pacote e a versao instalada apontados pelo scanner (output do proprio engine + SBOM Syft da imagem) e (b) o advisory do CVE no tracker autoritativo (NVD, OSV, Debian, Ubuntu, Red Hat Security Data, Alpine, Photon — varios consultados ao vivo). Resultado:

| Classe | n | % |
|---|---|---|
| Verdadeiro-positivo (TP) | 169 | 84,5% |
| Falso-positivo (FP) | 22 | 11,0% |
| Ambiguo | 9 | 4,5% |

- Precision global (TP/(TP+FP), excluindo ambiguos): 0,885 — IC 95% Wilson [0,832; 0,923].
- Taxa de FP entre pares decididos: 11,5%.

Precision por scanner (sobre os pares em que aquele engine e reporter):

| Scanner | n | TP | FP | AMB | Precision | IC 95% Wilson |
|---|---|---|---|---|---|---|
| Trivy | 27 | 26 | 1 | 0 | 0,963 | [0,817; 0,993] |
| Grype | 122 | 110 | 8 | 4 | 0,932 | [0,872; 0,965] |
| OSV-Scanner | 19 | 16 | 3 | 0 | 0,842 | [0,624; 0,945] |
| Clair | 32 | 17 | 10 | 5 | 0,630 | [0,442; 0,785] |

Restringindo aos pares reportados por UM SO scanner (sinal divergente puro, estrato single):

| Scanner | n | TP | FP | AMB | Precision | IC 95% Wilson |
|---|---|---|---|---|---|---|
| Trivy | 27 | 26 | 1 | 0 | 0,963 | [0,817; 0,993] |
| Grype | 66 | 56 | 6 | 4 | 0,903 | [0,805; 0,955] |
| OSV-Scanner | 13 | 11 | 2 | 0 | 0,846 | [0,578; 0,957] |
| Clair | 14 | 8 | 2 | 4 | 0,800 | [0,490; 0,943] |

Conclusao central: os findings divergentes (reportados por um unico scanner) NAO sao majoritariamente falsos positivos. A maior parte da divergencia entre os engines vem de diferenca de cobertura/feed (cada engine consulta bases diferentes e mapeia pacotes de formas diferentes), nao de erro de matching: 169/200 pares sao genuinamente afetados. Os FPs reais concentram-se em source-vs-binary (Clair) e version range (OSV em pip/setuptools), e em alguns CVEs informativos/contestados mapeados por CPE ampla.

## 2. Metodologia

### 2.1 Fonte e formato dos dados (somente leitura)
- Findings por scanner: scan-out/out_so/<dir>/{trivy,grype,osv,clair}/*.json.gz.
  - Trivy: Results[].Vulnerabilities[] -> PkgName, InstalledVersion, FixedVersion, Status, DataSource.
  - Grype: matches[] -> artifact.name/version/purl, vulnerability.id, fix.versions/state, namespace (feed).
  - OSV-Scanner: results[].packages[].vulnerabilities[] -> package.name/version/ecosystem, id+aliases.
  - Clair: vulnerabilities{} + package_vulnerabilities{} + packages{} -> nome (com CVE embutido), package, fixed_in_version, updater.
- SBOM (versoes instaladas): out_so/<dir>/syft/*.syft.json.gz (artifacts: name, version, type, purl, metadata.source).
- Conjunto consolidado para amostragem: data/analysis/rq3_sca_sets.json.gz ({trivy,grype,osv,clair} -> lista de [imagem@sha256, CVE]).

### 2.2 Mapeamento imagem -> diretorio
O conjunto identifica imagens por repo@sha256:<digest>. Os diretorios em out_so terminam com os primeiros 8 hex desse digest (debian_10.0_6ea10209 <-> debian@sha256:6ea10209...). Validei o mapeamento: os 2.525 digests distintos mapeiam de forma unica e sem colisao para diretorios; confirmei tambem que o manifest_hash interno do Clair coincide com o digest completo do conjunto. Distro inferida do nome do diretorio (rhel-family = almalinux/rockylinux/oraclelinux/fedora/centos/sl/leap/mageia/...).

### 2.3 Extracao e amostragem (script, reprodutivel — NAO classifica)
- Script: extract_and_sample.py. Faz apenas: mapear digest->dir, calcular concordancia por par (quantos dos 4 engines reportam cada (imagem,CVE)), amostragem estratificada com random.Random(42), e extrair pacote+versao instalada do output do scanner reporter. Nenhum veredicto e decidido por script.
- ID estavel: rq3_ + sha1(scanner|imagem|cve)[:14].
- Estratificacao:
  - 120 pares do estrato single (reportados por EXATAMENTE um engine — onde o FP e mais provavel), alocados proporcionalmente entre os 4 engines com piso de cobertura (universo: 215.062 pares single — grype 142.798, trivy 63.037, clair 5.939, osv 3.288).
  - 80 pares do estrato multi (>=2 engines concordam — universo 133.454), com inclusao forcada das combinacoes raras que envolvem osv/clair (clair+grype, clair+trivy, clair+grype+trivy, grype+osv, grype+osv+trivy, osv+trivy) e o restante preenchido por grype+trivy (combo dominante).
- enrich_sbom.py acrescenta a cada registro as versoes instaladas correspondentes no SBOM Syft (match exato por nome + candidatos relacionados), usado para resolver casos em que o Clair traz o nome do pacote-fonte sem versao binaria.
- Cobertura efetiva da amostra: 4 engines; distros debian (46), rhel-family (59), amazonlinux (34), ubuntu (23), photon (16), archlinux (14), alpine (6), busybox (1), cirros (1).

### 2.4 Classificacao (manual, por leitura — 1 revisor)
A decisao TP/FP/ambiguo foi minha, lendo cada par. Para cada um li o pacote+versao instalada e cruzei com o advisory:
- Trackers de distro (Debian security-tracker, Ubuntu CVE, Red Hat Security Data API hydra JSON, Photon, Alpine secdb): a propria distro indica se o pacote-fonte e afetado e em que versao corrige. Quando status = fixed e versao instalada < fixed, OU status afetado/fix-deferred/wont-fix/needed sem fix, o pacote esta genuinamente afetado e sem patch.
- NVD/OSV/upstream: faixa de versao + se o binario instalado contem o codigo vulneravel.
- Consultas ao vivo via WebFetch citadas explicitamente (exemplos): CVE-2024-5535 e CVE-2025-69420 (Red Hat hydra: openssl RHEL "Affected"/"Fix deferred"), CVE-2021-43618 (Ubuntu: 21.04 "ignored EOL", 22.04 "not affected"), CVE-2023-7008 (Ubuntu: "needs evaluation"), CVE-2007-5686 (Debian: "unimportant", nota LOG_UNKFAIL_ENAB=no), CVE-2005-2541 (Debian: "intended behaviour"), CVE-2023-31439 (Debian: "disputed by upstream"), CVE-2017-13729 (Debian: fixed em buster+), CVE-2025-60876 (NVD: busybox <=1.37.0), CVE-2023-27534 (NVD: curl 7.18.0-7.88.1), e as faixas OSV de pip/setuptools (CVE-2019-20916 <19.2; CVE-2021-3572 <21.1; CVE-2023-5752 <23.3; CVE-2025-8869 <25.3; CVE-2026-1703/3219/6357 <26.x; CVE-2024-6345 59.8.0-69.5.1; CVE-2025-47273 59.8.0-78.1.0).
- Criterio:
  - TP = versao instalada realmente na faixa afetada, sem fix presente (sem backport).
  - FP = nao afetada: versao fora da faixa, fix ja aplicado/backportado, match em pacote/subpacote errado (sem o codigo vulneravel), CVE de outro ecossistema, ou nao-vulnerabilidade/CVE rejeitado pela distro.
  - Ambiguo = duvida genuina: CVE contestado que a distro mantem aberto, granularidade fonte-vs-binario indecidivel, release de desenvolvimento sem status consolidado, ou CVE futura sem dados NVD confiaveis.
- Causa atribuida quando FP/ambiguo: {feed_db, source_vs_binary, version_range, distro_backport, kernel_irrelevante, disputed, outro}.
- Veredictos gravados por write_verdicts.py (apenas grava o que decidi, indexado por id).

### 2.5 Reprodutibilidade
Rodar extract_and_sample.py (seed=42) reproduz exatamente os 200 ids; enrich_sbom.py reanexa as versoes do SBOM; write_verdicts.py regrava os veredictos. Precision e ICs (Wilson 95%) reagregaveis de verdicts.jsonl.

## 3. Resultados

- Lidos: 200/200. TP 169 | FP 22 | Ambiguo 9.
- Precision global: 0,885 — IC 95% [0,832; 0,923]. (Secao 1 traz precision por scanner e por estrato.)
- Por estrato: single (divergente) precision 0,902 [0,833; 0,944]; multi (concordancia) 0,861 [0,768; 0,920]. Os dois estratos tem precision alta e estatisticamente semelhante — a divergencia NAO e dominada por FP.

### 3.1 Distribuicao das causas de FP (22)
| Causa | n |
|---|---|
| source_vs_binary | 12 |
| feed_db (CVE informativo/CPE ampla) | 5 |
| version_range | 5 |

Causas dos ambiguos (9): source_vs_binary 4, version_range 3, disputed 2.

### 3.2 Precision por distro
| Distro | n | TP | FP | AMB | Precision (TP/(TP+FP)) |
|---|---|---|---|---|---|
| rhel-family | 59 | 54 | 4 | 1 | 0,931 |
| debian | 46 | 31 | 13 | 2 | 0,705 |
| amazonlinux | 34 | 31 | 3 | 0 | 0,912 |
| ubuntu | 23 | 16 | 2 | 5 | 0,889 |
| photon | 16 | 16 | 0 | 0 | 1,000 |
| archlinux | 14 | 14 | 0 | 0 | 1,000 |
| alpine | 6 | 5 | 0 | 1 | 1,000 |
| busybox/cirros | 2 | 2 | 0 | 0 | 1,000 |

Debian destaca-se com a menor precision: e onde caem os pares Clair com nome de pacote-fonte (perl, zlib, systemd, shadow) e os CVE informativos (CVE-2007-5686 login/shadow). Photon/Archlinux/Alpine tiveram precision 1,0 na amostra (Photon: matching distro com fixed-version explicito; Archlinux: Go stdlib via faixa de versao verificavel).

## 4. POR QUE os scanners divergem — analise por causa

### 4.1 Artefato de consolidacao no proprio conjunto (Clair) — explica boa parte do isolamento do Clair e o OSV-inter-Clair=0
Ao montar a amostra detectei que ~50% das entradas do Clair em rq3_sca_sets.json.gz estao gravadas como o NOME completo do vuln do Clair (ex.: "CVE-2026-5435 on Ubuntu 22.04 LTS (jammy) - medium") em vez do CVE-id normalizado (5.866 de 11.736; as outras 5.870 limpas). Trivy/Grype/OSV tem 0 entradas nao-normalizadas. Strings com sufixo "on Ubuntu ..." nunca casam com CVE-ids limpos dos outros engines, o que infla artificialmente a divergencia do Clair e zera intersecoes (contribui para Jaccard baixos e para OSV-inter-Clair=0). Normalizei o CVE no momento do match para conseguir ler os casos, mas a metrica de conjunto deveria ser recomputada apos normalizar os nomes do Clair. Esta e uma causa de divergencia de MEDICAO, distinta de FP de scanner.

### 4.2 source-vs-binary (causa dominante de FP real, 12/22) — sobretudo Clair
O Clair reporta no nome do PACOTE-FONTE (perl, zlib, openssl, systemd, shadow). Em imagens slim/Debian, o binario presente e outro (perl-base, zlib1g, libsystemd0, passwd) e, em varios casos, o subpacote presente NAO contem o codigo vulneravel (ex.: CVE-2013-4392 systemd-TOCTOU reportado onde so ha libsystemd0/libudev1, sem o daemon systemd; CVE-2026-8376 perl onde so ha perl-base). O mesmo padrao aparece no Grype/distro para subpacotes data-only do vim (vim-data, vim-common) que nao contem o executavel vim (CVE-2023-5344, CVE-2026-32249). Trivy/Grype/OSV ancoram melhor no binario instalado, por isso divergem do Clair nesses pares.

### 4.3 version range (5 FP + 3 ambiguos) — sobretudo OSV em pip/setuptools
O OSV (ecossistema PyPI) casa pip/setuptools do sistema, mas em varios casos a versao instalada esta FORA da faixa afetada: setuptools 41.2.0/53.0.0/59.6.0 estao ABAIXO de 59.8.0 (CVE-2024-6345 e CVE-2025-47273 so afetam 59.8.0+). Notavel: dois desses FPs (idx142 grype+osv; idx152 osv+trivy) sao pares de CONCORDANCIA entre 2 engines — ambos herdaram a mesma faixa OSV mal aplicada. Ou seja, concordancia entre scanners NAO garante TP. Tambem ncurses CVE-2017-13729 (corrigida em ncurses 6.1, instalado 6.1 -> nao afetado).

### 4.4 feed_db / CPE ampla (5 FP) — CVE informativo ou nao-vulnerabilidade
CVE-2007-5686 (permissoes de /var/log/btmp no initscripts do rPath) e casada por CPE ampla nos pacotes login/shadow do Debian/RHEL; Debian marca "unimportant" e nota que LOG_UNKFAIL_ENAB=no neutraliza o impacto. CVE-2005-2541 (tar -p) e "intended behaviour" segundo a Debian, nao vulnerabilidade. Esses entram em scanners que consomem NVD/CPE sem o veto da distro.

### 4.5 disputed (2 ambiguos)
CVE-2023-31439 (systemd) e "disputed by upstream" porem mantida vulneravel pela Debian; CVE-2017-20230 (perl) de relevancia contestada. Marcadas ambiguas, nao FP.

### 4.6 O que NAO e divergencia por erro
A grande maioria das divergencias single-reporter sao TP: o engine que reporta sozinho realmente acertou, e os demais simplesmente nao cobriam aquele par (feed/ecossistema diferente). Exemplos: OSV achando pip/setuptools/Go via metadata PyPI/Go que Trivy/Grype tratam como pacote de SO ou ignoram; Grype/Trivy reportando RHEL openssl "fix deferred"/"affected" (Red Hat acknowledged, sem fix) — genuinamente afetado. Isto e diferenca de COBERTURA, nao de correcao.

## 5. Limitacoes

1. Um unico revisor (sem dupla anotacao / kappa). Criterios fixados na secao 2.4.
2. Sem execucao/PoC: TP/FP por julgamento de leitura sobre faixa de versao, presenca do binario vulneravel e veto da distro. Para CVEs com componente arquitetural (ex.: CVE-2025-22866 Go P-256 so explorabilvel em ppc64le, imagem amd64) marquei TP por a versao do toolchain estar na faixa, anotando a ressalva.
3. n=200 da ICs largos para os engines com poucos pares (OSV n=19, Clair n=32); a precision do Clair (0,63) tem IC [0,44; 0,79] e e fortemente puxada pela amostragem forcada de combos clair e por source-vs-binary repetido (6 pares CVE-2026-8376 perl em imagens slim distintas).
4. A atribuicao de precision "por scanner" no estrato multi usa o engine do qual extrai pacote/versao (um dos reporters), nao todos — por isso reporto tambem a versao single-reporter-only (secao 1), mais limpa.
5. Concentracao de FPs correlacionados (mesmo CVE/pacote replicado entre tags), reduzindo diversidade efetiva apesar de cobrir muitas imagens.
6. O artefato de normalizacao do Clair (4.1) afeta as metricas de CONJUNTO (Jaccard, intersecoes) do RQ3, nao os veredictos TP/FP desta validacao (que usam o CVE normalizado).

## 6. Artefatos (reprodutibilidade)

- extract_and_sample.py — mapeamento + amostragem seeded + extracao (nao classifica).
- enrich_sbom.py — anexa versoes instaladas do SBOM Syft.
- sample.jsonl — os 200 pares (id, imagem, dir, distro, scanner, reported_by, cve, cve_norm, pacote, versao_instalada, fixed_version, status, feed, sbom).
- verdicts.jsonl — os 200 veredictos (id, idx, cve, scanner, reported_by, distro, stratum, verdict TP/FP/ambiguo, causa, justificativa lida).
- write_verdicts.py — grava os veredictos decididos pelo revisor.
- population_stats.json — tamanhos do universo e da amostra.
