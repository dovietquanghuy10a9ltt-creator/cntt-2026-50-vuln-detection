import pandas as pd, numpy as np, sys, hashlib
sys.path.insert(0,'src/training')
import grouped_cv_splits as SP
import os
S = os.environ.get('WORK_DIR', 'work') + '/'   # thư mục làm việc tạm (clean.pkl, v2/flags.pkl ...)
d=pd.read_pickle(S+'v2/flags.pkl')
# R3: bản trùng token cùng nhãn: giữ hàm có unit_id nhỏ nhất trong mỗi nhóm
keep_first=d[~d.exclude].sort_values('unit_id').duplicated(['language','tokkey'],keep='first')
d['R3']=False; d.loc[keep_first[keep_first].index,'R3']=True
d['exclude']=d.R1|d.R2|d.R3
print('R3 (trùng token cùng nhãn, bỏ bản thừa):', d.R3.sum(), '| tổng loại:', d.exclude.sum(), '| còn', (~d.exclude).sum())
f1=pd.read_csv('data/mvd_v1/groups_and_folds_v1.csv')
reason=np.where(d.R1,'R1_formatting_only_label_conflict',np.where(d.R2,'R2_test_function','R3_token_duplicate_same_label'))
ex=d[d.exclude][['unit_id','language','target','group','fold']].assign(reason=reason[d.exclude.values])
ex.to_csv('data/mvd_v2/excluded_units_v2.csv',index=False)
f2=f1[~f1.unit_id.isin(ex.unit_id)].reset_index(drop=True)
f2.to_csv('data/mvd_v2/groups_and_folds_v2.csv',index=False)
print('folds v2 rows', len(f2), '| cột giống v1:', list(f2.columns)==list(f1.columns))
# kiểm tra bằng đúng hàm chia của runner
clean=pd.read_pickle(S+'clean.pkl')
clean2=clean[clean.unit_id.isin(f2.unit_id)]
df=SP.attach_folds(clean2,f2)
jobs=SP.build_jobs(df)
print('số job', len(jobs))
plan=SP.plan_table(df,epochs=5,jobs=jobs)
bad=[]
for (mode,key,k) in jobs:
    tr,va,te,rem=SP.get_split(df,mode,key,k)
    for nm,x in (('train',tr),('val',va),('test',te)):
        if x.target.nunique()<2: bad.append((mode,key,k,nm))
    if mode!='lolo':
        for nm,x in (('val',va),('test',te)):
            for l,g in x.groupby('language'):
                if g.target.nunique()<2: bad.append((mode,key,k,nm,l))
print('job thiếu một nhãn:', bad)
print(plan.groupby('mode')[['n_train','n_val','n_test']].sum())
print('theo ngôn ngữ v2:'); print(df.groupby('language').agg(n=('unit_id','size'),pos=('target','mean'),clusters=('group','nunique')).round(3).to_string())
print('min test per mono job:', plan[plan['mode']=='mono'].groupby('key').n_test.min().to_dict())
print('min val per mono job:', plan[plan['mode']=='mono'].groupby('key').n_val.min().to_dict())
plan.to_csv(S+'v2/plan_v2.csv',index=False)
