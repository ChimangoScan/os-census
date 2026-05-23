# Validação manual de falso-positivo vs verdadeiro-positivo das detecções de "secrets"

Censo de imagens Docker (TruffleHog + Gitleaks) — validação por leitura humana

## 1. Resumo executivo

De uma amostra aleatória de 1.100 detecções de secret (estratificada por scanner, seed=42), extraída do universo de 26.892 detecções distintas em 2.747 imagens, classifiquei manualmente (lendo cada finding) as 1.100. Resultado:

| Classe | n | % |
|---|---|---|
| Verdadeiro-positivo (TP) | 0 | 0,00% |
| Falso-positivo (FP) | 1.100 | 100,00% |
| Ambíguo | 0 | 0,00% |

- Taxa de FP validada: 100,0% (IC 95% Wilson: 99,65% – 100,00%).
- Taxa de TP validada: 0,0% (IC 95% Wilson: 0,00% – 0,348%; limite superior pela regra de três: 0,273%).

Nenhuma credencial real e utilizável foi encontrada na amostra. Todas as 1.100 detecções são placeholders de documentação, chaves de teste embutidas em bibliotecas, checksums/hashes de pacote, identificadores de código, material de chave pública, ou tokens temporários já expirados em logs.

## 2. Metodologia

### 2.1 Fonte e formato dos dados
- Diretório: scan-out/out_so/<imagem>/{trufflehog,gitleaks}/ (somente leitura).
- TruffleHog: JSONL, um finding por linha. Campos usados: DetectorName, Raw/RawV2, Verified, SourceMetadata.Data.Docker.file. Todos os findings têm Verified=false.
- Gitleaks: array JSON. Campos usados: RuleID, Secret, Match, File, StartLine, Entropy.
- Arquivos .gz descomprimidos para leitura. Markers vazios: [] (gitleaks), 0 bytes (trufflehog).

### 2.2 Extração e amostragem (script, reprodutível)
- Script: extract_and_sample.py. Faz APENAS (a) extração de todos os findings, (b) ID estável, (c) amostragem com seed fixo, (d) gravação. Não classifica nada.
- ID estável: sha1(scanner|imagem|arquivo|regra|locator|valor)[:16], prefixado por tr_/gi_. Locator = nº da linha (trufflehog) ou StartLine (gitleaks).
- Universo após deduplicação por ID: 26.892 findings (15.039 trufflehog + 11.853 gitleaks). A diferença para os 27.285 brutos vem da dedup de findings idênticos e raras linhas não parseáveis.
- Amostragem estratificada proporcional por scanner com random.Random(42): 615 trufflehog + 485 gitleaks = 1.100, cobrindo 677 imagens distintas.
- Amostra salva em sample.jsonl (1 finding/linha, com ID, scanner, imagem, arquivo, regra, valor/trecho).

### 2.3 Classificação (manual, por leitura)
- A decisão TP/FP foi minha, lendo cada finding (valor + arquivo + regra + trecho de contexto), em 11 lotes de 100. Nenhum filtro, regex ou heurística automática decidiu o veredicto; o script só gravou o que eu decidi.
- Critério:
  - TP = credencial/segredo real e utilizável (chave privada de produção, token de API válido em formato e contexto, senha real em config).
  - FP = placeholder, exemplo/doc, hash/checksum de pacote, chave pública, secret de teste conhecido, caminho/binário casado por engano, token temporário expirado.
  - Ambíguo = dúvida genuína (contado à parte). Não houve nenhum.
- Veredictos gravados incrementalmente em verdicts.jsonl (ID + veredicto + 1 frase de motivo).

### 2.4 Representatividade e precisão
- N=26.892, n=1.100. Para proporção ~0,5 daria IC 95% de ±~2,95%; como a proporção observada de FP é ~1,0, o IC efetivo é muito mais estreito (Wilson: limite inferior 99,65% para FP).
- Amostra reprodutível: rodar extract_and_sample.py com seed=42 produz exatamente os mesmos 1.100 IDs.

## 3. Resultados

- Lidos: 1.100 / 1.100. TP: 0 | FP: 1.100 | Ambíguo: 0.
- FP: 100,0% — IC 95% Wilson [99,65%, 100,00%].
- TP: 0,0% — IC 95% Wilson [0,00%, 0,348%]; regra de três (0/1100) ⇒ limite superior 0,273%.

### 3.1 Taxa de secrets VALIDADA por imagem (estimativa)
O censo indica que ~72% das imagens têm ≥1 detecção bruta. Para estimar a fração com ≥1 secret real:
- Suposição: a probabilidade de uma detecção ser TP ~ taxa de TP medida (ponto = 0%), tratando detecções de uma imagem de forma independente (suposição conservadora; na prática os FPs são fortemente correlacionados, pois vêm dos mesmos arquivos de sistema replicados entre imagens).
- Estimativa pontual: fração de imagens com ≥1 secret real ≈ 0%.
- Limite superior grosseiro: usando o teto do IC de TP (0,348%) e o teto de 72%, a fração de imagens com ≥1 secret real fica abaixo de ~0,25% (no máximo ~7 das 2.747 imagens, e provavelmente nenhuma).
- Em termos práticos: o achado "72% das imagens têm secrets" desaba para ~0% quando exigimos credencial real validada por leitura.

## 4. Por que tudo é FP — categorias dominantes observadas

(a) Chaves de teste embutidas em bibliotecas do sistema — chaves de teste compiladas no GnuTLS (libgnutls.so*, gnutls-cli): RSA "MIIEogIBAAKCAQEA6yCv+BLrRP..." e EC "MHcCAQEEIPAKWV7...". Fixtures públicas, não credenciais. Padrão "PrivateKey" mais frequente.

(b) Chaves de exemplo/teste em docs de pacotes — m2crypto-*/demo/.../server.pem e rsa.priv.pem; chaves PGP de teste do pygpgme (tests/keys/key1.sec, key2.sec, signonly.sec). Chaves reais em formato, porém amostras de teste públicas.

(c) Hashes/checksums de pacote casados como token — TruffleHog Box/Agora/Alchemy/Pastebin/Flickr/BingSubscriptionKey casando MD5 de libc6:amd64.md5sums, fatias de apt .../Packages e Translation-en, e GUIDs de 32 hex em binários (systemd-resolved).

(d) Identificadores de código C em headers — Gitleaks generic-api-key casando nomes de macros/tipos: TPM2B_ENCRYPTED_SECRET, krb5_const_principal, gnutls_x509_crt_fmt_t, NL80211_KEY_MAX, __NFTA_TUNNEL_KEY_IP6_MAX, COPHH_KEY_UTF8, soft_heap_limit64/column_bytes16 (sqlite), _mm512_srli_epi64 (intrínseca x86), b4_api_PREFIX (template bison).

(e) URLs de exemplo em documentação — http://joe:password@proxy.example.com, http://user:host@foo:3128, ftp://user:passwd@my.site.com, http://john%40example.com:password@example.com, http://test:pass;auth=NTLM@example.com, username:fakepwd (curl MANUAL). De urllib2, urlgrabber, HTTP/Tiny.pm, man pages do yum/curl.

(f) Material de chave pública — fatias base64 de pacman/keyrings/archlinux.gpg (pacotes PGP de chaves públicas) casadas por Box/UnifyID/generic-api-key.

(g) Assinaturas de tipo de arquivo em binário — Gitleaks private-key casando strings literais "BEGIN PRIVATE KEY"/"BEGIN OPENSSH PRIVATE KEY" dentro de magic.mgc (banco compilado do libmagic). Entropia ~1,3-2,0.

(h) Hash de política padrão e UUID de doc — tpm2-tss/fapi-profiles/*.json authPolicy é hash de política padrão da especificação TSS; gnutls/NEWS tpmkey:uuid=... é exemplo de changelog.

(i) Hashes de sessão em log de instalador — var/log/anaconda/* "key: <sha1>" são IDs de transação do instalador, não credenciais.

(j) Tokens AWS STS temporários e expirados em log — var/log/dnf.librepo.log contém ASIAT2EO7SSD... e X-Amz-Security-Token=IQoJb3JpZ2luX2Vj... capturados em URLs pré-assinadas de espelhos RPM em S3. Credenciais de sessão de curta duração, expiradas, registradas em log — não utilizáveis. Caso mais borderline da amostra; FP sob o critério de "secret real e utilizável".

Não houve nenhum exemplo de TP para ilustrar — nenhuma chave privada de produção, token de API válido, nem senha de config real na amostra de 1.100.

## 5. Comparação com a literatura

| Estudo | Método | Hits válidos/reais |
|---|---|---|
| Este trabalho | Leitura humana de 1.100 de 26.892 (imagens de SO oficiais) | 0,0% (IC 95% [0%, 0,35%]) |
| Dahlmanns et al. | Validação de secrets em imagens Docker | ~8,5% validados |
| Dr. Docker | Filtragem de hits | ~99,3% inválidos => ~0,7% válidos |

Nosso resultado é ainda mais extremo na direção de "quase tudo é FP" que ambos:
- vs Dr. Docker (~0,7% válidos): nosso ponto é 0% e o teto do IC (0,35%) fica abaixo de 0,7%. Consistente em ordem de grandeza, porém mais baixo.
- vs Dahlmanns et al. (8,5%): muito abaixo. Diferença explicável pelo corpus: nosso censo é de imagens base de SO oficiais (almalinux, debian, ubuntu, archlinux, amazonlinux, etc.), com bibliotecas, headers e docs de sistema, mas sem código de aplicação de terceiros com credenciais commitadas por engano. Dahlmanns amostra imagens de aplicação onde segredos reais aparecem. Conclusão: imagens de SO base têm taxa de TP efetivamente nula; o risco de secrets está nas camadas de aplicação, não na base.

## 6. Limitações

1. Sem verificação ativa: não autentiquei tokens contra o provedor (invasivo/antiético). TP/FP por julgamento de leitura sobre formato, conteúdo, arquivo e contexto. Para os tokens AWS STS, "expirado" foi inferido pelo tipo (STS de sessão, prefixo ASIA, em log de download), não testado.
2. Corpus enviesado para SO base: o 0% TP aplica-se a imagens base de SO oficiais; NÃO generalizar para imagens de aplicação.
3. Concentração de FPs: fortemente correlacionados (mesmos arquivos de sistema replicados entre centenas de imagens/tags), reduzindo a diversidade efetiva mesmo com 677 imagens distintas. O IC binomial assume independência (otimista); como a taxa de TP é 0 em todas as categorias, a conclusão qualitativa (~0% real) é robusta.
4. Dedup: trabalhei sobre 26.892 findings deduplicados, não os 27.285 brutos; diferença ~1,4%, não afeta a conclusão.
5. Apenas 2 scanners (TruffleHog, Gitleaks); outros poderiam ter perfis de FP diferentes.

## 7. Artefatos (reprodutibilidade)

- extract_and_sample.py — extração + amostragem seeded (não classifica).
- sample.jsonl — os 1.100 findings amostrados (ID estável + metadados).
- verdicts.jsonl — os 1.100 veredictos (ID + TP/FP/AMB + motivo).
- population_stats.json — contagens do universo e da amostra.

Para reproduzir a amostra: python3 extract_and_sample.py (seed=42 fixo). Para reproduzir as estatísticas: agregue verdicts.jsonl por verdict e aplique IC de Wilson.
