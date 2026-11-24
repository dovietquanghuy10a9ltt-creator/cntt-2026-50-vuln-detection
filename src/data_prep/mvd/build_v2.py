"""Dựng danh sách loại bỏ cho dữ liệu sạch v2 (chạy trên tập sạch 18.694 hàm)."""
import pandas as pd, numpy as np, re, io, tokenize, sys
import os
S = os.environ.get('WORK_DIR', 'work') + '/'   # thư mục làm việc tạm (clean.pkl, v2/flags.pkl ...)
c=pd.read_pickle(S+'clean.pkl'); f=pd.read_csv('data/mvd_v1/groups_and_folds_v1.csv')
d=c[['unit_id','func','language','target']].merge(f[['unit_id','group','fold','is_giant']],on='unit_id')
assert len(d)==18694

# ---- R1: hai phiên bản chỉ khác định dạng hoặc chú thích ----
STR = r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\''
GEN = re.compile(r'(?P<c1>/\*.*?\*/)|(?P<c2>//[^\n]*)|(?P<s>`(?:\\.|[^`\\])*`|' + STR + r')|(?P<t>[A-Za-z_$][\w$]*|\d[\w.]*|\S)', re.S)
def lex_generic(src):
    out=[]
    for m in GEN.finditer(src):
        if m.group('c1') or m.group('c2'): continue
        out.append(m.group('s') or m.group('t'))
    return tuple(out)
def lex_python(src):
    toks=[]; skip={tokenize.COMMENT, tokenize.NL, tokenize.ENCODING}
    try:
        body=src
        # hàm có thể bị thụt lề sẵn (phương thức trong lớp): bỏ thụt lề chung
        import textwrap; body=textwrap.dedent(src)
        for t in tokenize.generate_tokens(io.StringIO(body).readline):
            if t.type in skip: continue
            if t.type==tokenize.NEWLINE: toks.append('<NL>'); continue
            if t.type in (tokenize.INDENT, tokenize.DEDENT): toks.append(tokenize.tok_name[t.type]); continue
            toks.append(t.string)
        # docstring đứng riêng một câu lệnh = chú thích: bỏ chuỗi đứng ngay sau '<NL>'/'INDENT' và trước '<NL>'
        clean=[]
        for i,t in enumerate(toks):
            if t[:1] in '\'"' or t[:2].lower() in ('r"',"r'",'b"',"b'",'f"',"f'") or t[:3] in ('"""',"'''"):
                prev=toks[i-1] if i else '<NL>'; nxt=toks[i+1] if i+1<len(toks) else '<NL>'
                if prev in ('<NL>','INDENT','DEDENT') and nxt=='<NL>': continue
            clean.append(t)
        return tuple(clean), True
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return lex_generic(re.sub(r'(?m)#[^\n]*','',src)), False
ok_py=0
keys=[]
for s,l in zip(d.func,d.language):
    if l=='Python':
        k,ok=lex_python(s); ok_py+=ok
    else: k=lex_generic(s)
    keys.append(hash(k))
d['tokkey']=keys
print('Python tokenize OK:', ok_py, '/', (d.language=='Python').sum())
g=d.groupby(['language','tokkey']).target.agg(['size','nunique'])
bad=g[(g['size']>1)&(g['nunique']>1)].reset_index()
d['R1']=d.set_index(['language','tokkey']).index.isin(bad.set_index(['language','tokkey']).index)
# nhóm trùng token nhưng CÙNG nhãn (không phải nhiễu nhãn nhưng là bản trùng): đếm để báo cáo
same=g[(g['size']>1)&(g['nunique']==1)]
print('R1 (cặp ngược nhãn chỉ khác định dạng/chú thích):', d.R1.sum(), d[d.R1].language.value_counts().to_dict())
print('   nhóm trùng token cùng nhãn (giữ lại):', len(same), 'nhóm,', int(same['size'].sum()), 'hàm')

# ---- R2: hàm kiểm thử ----
PAT = {
 'Python': [r'^\s*(?:async\s+)?def\s+test\w*\s*\(', r'^\s*(?:async\s+)?def\s+(?:setUp|tearDown|setUpClass|tearDownClass)\s*\('],
 'Java':   [r'@(?:Test|ParameterizedTest|RepeatedTest|BeforeEach|AfterEach|BeforeAll|AfterAll|Before|After)\b', r'^\s*(?:public\s+|protected\s+|private\s+)?(?:static\s+)?void\s+test\w*\s*\('],
 'Go':     [r'^\s*func\s+(?:Test|Benchmark|Fuzz|Example)[A-Z_]\w*\s*\(\s*\w+\s+\*?testing\.', r'^\s*func\s+\w+\s*\(\s*\w+\s+\*testing\.[TBF]\s*\)'],
 'C#':     [r'\[(?:Test|TestMethod|Fact|Theory|TestCase|SetUp|TearDown)\b'],
 'C':      [r'^\s*(?:static\s+)?(?:void|int)\s+test_\w+\s*\(', r'^\s*(?:START_TEST|TEST|TEST_F|TEST_P)\s*\('],
 'C++':    [r'^\s*(?:TEST|TEST_F|TEST_P|TYPED_TEST|BOOST_AUTO_TEST_CASE|TEST_CASE)\s*\(', r'^\s*(?:static\s+)?void\s+test_\w+\s*\('],
 'JavaScript': [r'^\s*(?:it|test|describe)\s*\(\s*[\'"`]', r'^\s*(?:async\s+)?function\s+test\w*\s*\('],
}
def head(s, n=4):  # chỉ xét phần khai báo (vài dòng đầu) để tránh khớp lời gọi bên trong thân hàm
    return '\n'.join(s.splitlines()[:n])
d['R2']=[any(re.search(p, head(s), re.M) for p in PAT[l]) for s,l in zip(d.func,d.language)]
print('R2 (hàm kiểm thử):', d.R2.sum(), d[d.R2].language.value_counts().to_dict(), 'tỷ lệ nhãn 1:', round(d[d.R2].target.mean(),3))
print('R1 và R2 cùng lúc:', (d.R1&d.R2).sum())
d['exclude']=d.R1|d.R2
print('TỔNG loại:', d.exclude.sum(), f'({d.exclude.mean():.2%}); còn lại', (~d.exclude).sum())
print(d.groupby('language').agg(n=('unit_id','size'),R1=('R1','sum'),R2=('R2','sum'),excl=('exclude','sum')).assign(con_lai=lambda t:t.n-t.excl, pct=lambda t:(t.excl/t.n*100).round(1)).to_string())
d.to_pickle(S+'v2/flags.pkl')
