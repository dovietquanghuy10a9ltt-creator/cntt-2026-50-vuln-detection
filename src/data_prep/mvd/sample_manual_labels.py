import pandas as pd, numpy as np, difflib, json, re
import os
S = os.environ.get('WORK_DIR', 'work') + '/'   # thư mục làm việc tạm (clean.pkl, v2/flags.pkl ...)
raw=pd.concat([pd.read_csv(f'data/raw/{n}_w_line.csv') for n in ('train','val','test')],ignore_index=True)
c=pd.read_pickle(S+'clean.pkl'); f2=pd.read_csv('data/mvd_v2/groups_and_folds_v2.csv')
v2=c[c.unit_id.isin(f2.unit_id)].merge(f2[['unit_id','group']],on='unit_id')
fid={s:u for s,u in zip(c.func,c.unit_id)}
raw['unit_id']=raw.func.map(fid)
nvuln=raw[raw.target==1].groupby('url').size()
rng=np.random.default_rng(20261115)
pool=v2[v2.target==1]
pick=[]
for l in ['C','C++','C#','Go','Java','JavaScript','Python']:
    p=pool[pool.language==l]; idx=rng.choice(len(p),15,replace=False); pick.append(p.iloc[np.sort(idx)])
pick=pd.concat(pick).reset_index(drop=True)
out=[]
for i,r in pick.iterrows():
    rr=raw[(raw.unit_id==r.unit_id)&(raw.target==1)].iloc[0]
    cand=raw[(raw.url==rr.url)&(raw.target==0)]
    best,ratio=None,0.0
    a=r.func.splitlines()
    for _,cr in cand.iterrows():
        q=difflib.SequenceMatcher(None,a,cr.func.splitlines(),autojunk=False).ratio()
        if q>ratio: best,ratio=cr.func,q
    diff=[]
    if best is not None:
        diff=[t for t in difflib.unified_diff(a,best.splitlines(),lineterm='',n=1)][2:]
    out.append(dict(no=i+1,unit_id=r.unit_id,language=r.language,cve=rr.cve_id,cwe=rr.CWE,url=rr.url,
                    n_vuln_funcs_in_commit=int(nvuln.get(rr.url,0)),pair_similarity=round(ratio,3),
                    vuln_func=r.func,fixed_func=best,diff=diff,n_lines=len(a)))
json.dump(out,open(S+'lab/sample.json','w'),ensure_ascii=False)
d=pd.DataFrame(out)
print(d.groupby('language').agg(n=('no','size'),no_pair=('fixed_func',lambda s:s.isna().sum()),med_nvuln=('n_vuln_funcs_in_commit','median'),one_func=('n_vuln_funcs_in_commit',lambda s:(s==1).sum())).to_string())
print('diff lines median', int(np.median([len(x) for x in d['diff']])), 'max', max(len(x) for x in d['diff']))
