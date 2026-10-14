"""Run and audit the complete 644-pair signature experiment."""
import csv
import hashlib
import json
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'results/query-signature-full-final-20260923'
RAW = Path('/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump')
GO = ROOT / 'artifacts/n-domain-regression-pilot-runtime/go/bin/go'
MODCACHE = ROOT / 'artifacts/n-domain-regression-pilot-runtime/modcache'
NATIVE = ROOT / 'artifacts/n-domain-regression-pilot-runtime/native'
CONFIGS = [('anchor', r, 4) for r in (2, 3, 4, 6)] + [('target', 4, r) for r in (2, 3, 4, 6)]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write(name, value):
    with (OUT / name).open('x', encoding='utf-8') as f:
        f.write(value)


def csv_read(name):
    with (OUT / name).open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def csv_write(name, rows):
    with (OUT / name).open('x', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def verify_queries(data, pairs):
    assert data['label'] == 'full length-controlled constructed query set'
    assert (data['eligible_pairs'], data['sampled_pairs'], data['q'], data['bucket_bits']) == (644, 644, 4, 16)
    assert len(pairs) == 644 and len(data['cases']) == 5152
    assert len({(p['anchor_id'], p['target_id']) for p in pairs}) == 644
    expected = {(p['anchor_id'], p['target_id']) for p in pairs}
    per_config = {config: set() for config in CONFIGS}
    for i, c in enumerate(data['cases']):
        assert c['case_id'] == i and 0 <= c['pair_index'] < 644
        p = pairs[c['pair_index']]
        assert all(c[key] == p[key] for key in ('anchor_id', 'target_id', 'anchor_name', 'target_name'))
        config = (c['variable_side'], c['anchor_signatures'], c['target_signatures'])
        assert config in per_config and c['tau_anchor'] == c['tau_target'] == 1
        assert c['anchor_signatures'] > 1 and c['target_signatures'] > 1
        assert c['anchor_query'] == c['anchor_name'][:4*c['anchor_signatures']]
        assert c['target_query'] == c['target_name'][:4*c['target_signatures']]
        assert len(c['anchor_query']) == 4*c['anchor_signatures']
        assert len(c['target_query']) == 4*c['target_signatures']
        assert c['pair_index'] not in per_config[config]
        per_config[config].add(c['pair_index'])
    assert all(len(v) == 644 and v == set(range(644)) for v in per_config.values())
    assert all({(data['cases'][i]['anchor_id'], data['cases'][i]['target_id']) for i in range(len(data['cases'])) if (data['cases'][i]['variable_side'], data['cases'][i]['anchor_signatures'], data['cases'][i]['target_signatures']) == config} == expected for config in CONFIGS)


def audit(data):
    token = csv_read('token-raw.csv')
    candidate = csv_read('candidate-raw.csv')
    checks = csv_read('correctness.csv')
    assert len(token) == len(candidate) == 8*644*3
    assert len(checks) == 8*644
    token_by, candidate_by, checks_by = {}, {}, {}
    for rows, dest in ((token, token_by), (candidate, candidate_by)):
        for row in rows:
            key = (int(row['case_id']), int(row['trial']))
            assert key not in dest and 0 <= key[0] < 5152 and key[1] in (1, 2, 3)
            c = data['cases'][key[0]]
            assert int(row['pair_index']) == c['pair_index']
            assert (row['variable_side'], int(row['anchor_signatures']), int(row['target_signatures'])) == (c['variable_side'], c['anchor_signatures'], c['target_signatures'])
            dest[key] = row
    expected = {(i, trial) for i in range(5152) for trial in (1, 2, 3)}
    assert token_by.keys() == candidate_by.keys() == expected
    for row in checks:
        i = int(row['case_id'])
        assert i not in checks_by and 0 <= i < 5152
        c = data['cases'][i]
        assert int(row['pair_index']) == c['pair_index']
        assert (row['variable_side'], int(row['anchor_signatures']), int(row['target_signatures'])) == (c['variable_side'], c['anchor_signatures'], c['target_signatures'])
        assert row['all_three_equal_oracle'] == 'true'
        assert all(int(row[k]) == 0 for k in ('FP', 'FN', 'duplicates', 'wrong_anchor_id', 'wrong_target_id'))
        assert all(int(row[f'trial{j}_pairs']) == int(row['oracle_pairs']) for j in (1, 2, 3))
        checks_by[i] = row
    assert checks_by.keys() == set(range(5152))
    tm, cm = [], []
    for i, c in enumerate(data['cases']):
        ts = [token_by[(i, j)] for j in (1, 2, 3)]
        cs = [candidate_by[(i, j)] for j in (1, 2, 3)]
        common = dict(variation_side=c['variable_side'], source_id=f"{c['anchor_id']}:{c['target_id']}", anchor_r=c['anchor_signatures'], target_r=c['target_signatures'])
        assert all(int(x['generation_ns']) > 0 for x in ts)
        assert all(int(x['cs0_token_bytes'])+int(x['cs1_token_bytes']) == int(x['total_token_bytes']) for x in ts)
        assert all(int(x['candidate_discovery_ns']) > 0 and int(x['candidate_discovery_ns']) < int(x['local_e2e_ns']) for x in cs)
        assert all(sum(int(x[k]) for k in ('user_to_cloud_bytes', 'cs_to_cs_bytes', 'cloud_to_user_bytes')) == int(x['total_online_bytes']) for x in cs)
        assert all(int(x['final_pairs']) == int(x['oracle_pairs']) == int(checks_by[i]['oracle_pairs']) for x in cs)
        assert all(all(int(x[k]) == 0 for k in ('FP', 'FN', 'duplicates', 'wrong_anchor_id', 'wrong_target_id')) for x in cs)
        assert len({x['pair_sha256'] for x in cs}) == 1
        assert len({x['cs0_token_sha256'] for x in ts}) == 3
        assert len({x['cs1_token_sha256'] for x in ts}) == 3
        assert all(int(ts[j-1]['total_token_bytes']) == int(cs[j-1]['user_to_cloud_bytes']) for j in (1, 2, 3))
        tm.append(dict(**common, token_generation_ms=statistics.median(int(x['generation_ns']) for x in ts)/1e6,
                       cs1_token_bytes=statistics.median(int(x['cs0_token_bytes']) for x in ts), cs2_token_bytes=statistics.median(int(x['cs1_token_bytes']) for x in ts), total_token_bytes=statistics.median(int(x['total_token_bytes']) for x in ts)))
        cm.append(dict(**common, candidate_discovery_ms=statistics.median(int(x['candidate_discovery_ns']) for x in cs)/1e6,
                       online_bytes=statistics.median(int(x['total_online_bytes']) for x in cs), K=statistics.median(int(x['K']) for x in cs),
                       route_count=statistics.median(int(x['routes']) for x in cs), target_slots=statistics.median(int(x['target_slots']) for x in cs),
                       candidate_pair_count=statistics.median(int(x['final_pairs']) for x in cs)))
    csv_write('token-query-medians.csv', tm)
    csv_write('candidate-query-medians.csv', cm)
    tsummary, csummary = [], []
    for side, ar, tr in CONFIGS:
        t = [x for x in tm if (x['variation_side'], x['anchor_r'], x['target_r']) == (side, ar, tr)]
        c = [x for x in cm if (x['variation_side'], x['anchor_r'], x['target_r']) == (side, ar, tr)]
        assert len(t) == len(c) == 644 and {x['source_id'] for x in t} == {x['source_id'] for x in c}
        base = dict(variation_side=side, anchor_r=ar, target_r=tr, query_count=644)
        tsummary.append(dict(**base, mean_token_generation_ms=statistics.mean(x['token_generation_ms'] for x in t), mean_total_token_bytes=statistics.mean(x['total_token_bytes'] for x in t)))
        csummary.append(dict(**base, mean_candidate_discovery_ms=statistics.mean(x['candidate_discovery_ms'] for x in c),
                             mean_online_mib=statistics.mean(x['online_bytes'] for x in c)/(2**20), mean_K=statistics.mean(x['K'] for x in c),
                             mean_route_count=statistics.mean(x['route_count'] for x in c), mean_target_slots=statistics.mean(x['target_slots'] for x in c),
                             mean_candidate_pair_count=statistics.mean(x['candidate_pair_count'] for x in c)))
    csv_write('token-summary.csv', tsummary)
    csv_write('candidate-summary.csv', csummary)
    return tsummary, csummary, sum(int(x['oracle_pairs']) == 0 for x in checks)


def add_paper_columns(data):
    for name in ('token-raw.csv', 'candidate-raw.csv'):
        rows = csv_read(name)
        for row in rows:
            c = data['cases'][int(row['case_id'])]
            row['variation_side'] = c['variable_side']
            row['source_id'] = f"{c['anchor_id']}:{c['target_id']}"
            row['anchor_r'] = c['anchor_signatures']
            row['target_r'] = c['target_signatures']
            if name == 'token-raw.csv':
                row['token_generation_ms'] = int(row['generation_ns'])/1e6
                old_cs1 = row['cs1_token_bytes']
                row['cs1_token_bytes'] = row['cs0_token_bytes']
                row['cs2_token_bytes'] = old_cs1
            else:
                row['candidate_discovery_ms'] = int(row['candidate_discovery_ns'])/1e6
                row['online_bytes'] = row['total_online_bytes']
                row['route_count'] = row['routes']
                row['candidate_pair_count'] = row['final_pairs']
        with (OUT/name).open('w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)


def merge_shards():
    for name in ('candidate-raw.csv', 'correctness.csv'):
        all_rows = []
        for shard in range(4):
            with (OUT/'shards'/str(shard)/name).open(newline='', encoding='utf-8') as f:
                all_rows.extend(csv.DictReader(f))
        if name == 'candidate-raw.csv':
            all_rows.sort(key=lambda r: (int(r['case_id']), int(r['trial'])))
        else:
            all_rows.sort(key=lambda r: int(r['case_id']))
        csv_write(name, all_rows)


def main():
    assert not OUT.exists(), f'Refusing to overwrite {OUT}'
    assert GO.is_file() and MODCACHE.is_dir() and (NATIVE/'libphase6scmp.a').is_file()
    formal = json.loads((ROOT/'results/database-scalability-formal-20260920/environment.json').read_text())
    raw_hashes = {name: digest(RAW/name) for name in ('area', 'area_alias')}
    assert raw_hashes == formal['raw_sha256']
    OUT.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix='pmeq-signature-full-') as temp:
        rt = Path(temp)
        for name in ('cache', 'gopath', 'tmp'):
            (rt/name).mkdir()
        env = {k:v for k,v in os.environ.items() if not k.startswith(('PMEQ_', 'GO', 'CGO'))}
        env.update(GOROOT=str(GO.parents[1]), GOMODCACHE=str(MODCACHE), GOPATH=str(rt/'gopath'), GOCACHE=str(rt/'cache'), GOTMPDIR=str(rt/'tmp'), TMPDIR=str(rt/'tmp'), GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local', GOENV='off', GOFLAGS='', GOMAXPROCS='32', GOGC='100', GOMEMLIMIT='off', GODEBUG='', CGO_ENABLED='1', CGO_CFLAGS='', CGO_CPPFLAGS='', CGO_CXXFLAGS='', CGO_LDFLAGS=f'-L{NATIVE} -lphase6scmp -lcrypto -pthread', PMEQ_SIGNATURE_FULL='1', PMEQ_SIGNATURE_OUTPUT=str(OUT), PMEQ_SIGNATURE_RAW=str(RAW), PMEQ_SIGNATURE_CANDIDATE_OUTPUT=str(OUT), PMEQ_SIGNATURE_CANDIDATE_QUERYSET=str(OUT/'constructed-queries.json'))
        binary = rt/'signature-full.test'
        build = [str(GO), 'test', '-tags', 'phase6native', '-c', '-o', str(binary), './internal/discovery']
        run_token = [str(binary), '-test.run=^TestTokenSignatureCountExperiment$', '-test.count=1', '-test.v', '-test.timeout=30m']
        run_candidate = [str(binary), '-test.run=^TestSignatureCandidateDiscoveryExperiment$', '-test.count=1', '-test.v', '-test.timeout=12h']
        write('run-command.txt', 'Entry point: python3 tools/run_query_signature_full_final_20260923.py\nBuild: '+shlex.join(build)+'\nToken: '+shlex.join(run_token)+'\nCandidate: '+shlex.join(run_candidate)+'\nCandidate shards: PMEQ_SIGNATURE_SHARD_COUNT=4; PMEQ_SIGNATURE_SHARD_INDEX=0,1,2,3; pair_index modulo 4; GOMAXPROCS=8 per shard\nEnvironment: token GOMAXPROCS=32; GOGC=100 GOMEMLIMIT=off CGO_ENABLED=1 GOPROXY=off PMEQ_SIGNATURE_FULL=1\n')
        with (OUT/'build.log').open('x') as log:
            b = subprocess.run(build, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        if b.returncode: raise RuntimeError('Build failed; see build.log')
        with (OUT/'run.log').open('x') as log:
            log.write('BEGIN token\n'); log.flush()
            result = subprocess.run(run_token, cwd=ROOT/'internal/discovery', env=env, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode: raise RuntimeError('token failed; see run.log')
            log.write('END token\nBEGIN candidate shards\n'); log.flush()
            (OUT/'shards').mkdir()
            children = []
            for shard in range(4):
                dest = OUT/'shards'/str(shard)
                dest.mkdir()
                shard_env = dict(env, PMEQ_SIGNATURE_CANDIDATE_OUTPUT=str(dest), PMEQ_SIGNATURE_SHARD_COUNT='4', PMEQ_SIGNATURE_SHARD_INDEX=str(shard), GOMAXPROCS='8')
                shard_log = (dest/'run.log').open('x')
                children.append((shard, subprocess.Popen(run_candidate, cwd=ROOT/'internal/discovery', env=shard_env, stdout=shard_log, stderr=subprocess.STDOUT), shard_log))
            failed = []
            for shard, child, shard_log in children:
                code = child.wait()
                shard_log.close()
                log.write(f'shard {shard} exit={code}\n'); log.flush()
                if code: failed.append(shard)
            if failed: raise RuntimeError(f'candidate shard failure: {failed}; see shards/*/run.log')
            merge_shards()
            log.write('END candidate shards; merged raw records\n'); log.flush()
        data = json.loads((OUT/'constructed-queries.json').read_text())
        pairs = json.loads((OUT/'source-pairs.json').read_text())
        verify_queries(data, pairs)
        tsummary, csummary, zeros = audit(data)
        add_paper_columns(data)
        paths = ['source-pairs.json', 'constructed-queries.json', 'token-raw.csv', 'candidate-raw.csv', 'correctness.csv', 'token-query-medians.csv', 'candidate-query-medians.csv', 'token-summary.csv', 'candidate-summary.csv', 'run-command.txt', 'build.log', 'run.log']
        sources = ['internal/discovery/token.go', 'internal/discovery/local.go', 'internal/discovery/offline.go', 'internal/discovery/token_signature_experiment_test.go', 'internal/discovery/signature_candidate_experiment_native_test.go', 'internal/discovery/real_native_test.go', 'internal/anchorfilter/filter.go', 'tools/run_query_signature_full_final_20260923.py', 'artifacts/phase7b/manifest.json', 'artifacts/phase7b/payload-manifest.json', 'artifacts/phase10b/manifest.json']
        provenance = dict(status='passed', source_pairs=644, queries_per_config=644, configs=8, trials_per_query=3, token_runs=15456, candidate_runs=15456, zero_candidate_queries=zeros, raw_sha256=raw_hashes, source_sha256={p:digest(ROOT/p) for p in sources}, output_sha256={p:digest(OUT/p) for p in paths}, binary_sha256=digest(binary), timing_boundary='cloudStart through RecoverForDomain: Metrics.Cloud + Metrics.Recovery', candidate_shards=4, shard_rule='pair_index modulo 4', runtime_env={k:env[k] for k in ('GOMAXPROCS','GOGC','GOMEMLIMIT','CGO_ENABLED','GOPROXY')})
        write('provenance.json', json.dumps(provenance, indent=2, ensure_ascii=False)+'\n')
        write('notes.md', '# 查询签名数量对 PMEQ 性能影响：644 对正式全量实验\n\n全部 644 对真实连接记录，无抽样；每档相同源记录集合，每条查询三轮。q=4，B=2^16，tau_delta=tau_gamma=1。\n\n查询使用源名称合法前缀及正式 QueryChunks。Token 时间为正式 generate 与两云 token 编码。Candidate Discovery 时间为两云取得 token 后至用户恢复记录对：Metrics.Cloud + Metrics.Recovery；不含 GetToken、离线材料、静态构建、明文核对与最终编辑距离验证。在线通信包含两份 token、两云通信与两份输出。逐查询先取三轮中位数，再对每档 644 条取均值。\n\n自动审计通过：8 档均为 644 条；每条查询两项实验各 3 轮；各 15,456 条原始记录；明文候选集合完全一致且无缺失、额外、重复；零候选查询保留。\n\n论文汇总见 token-summary.csv 与 candidate-summary.csv。\n')
        print('AUDIT PASSED: 644 pairs, 5152 queries, 15456 token runs, 15456 candidate runs, all correct')
        print('TOKEN SUMMARY', json.dumps(tsummary, ensure_ascii=False))
        print('CANDIDATE SUMMARY', json.dumps(csummary, ensure_ascii=False))

if __name__ == '__main__':
    main()
