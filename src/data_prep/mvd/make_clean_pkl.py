"""Bước 1 của phần dựng dữ liệu MVD: nạp ba file gốc của MVD (data/raw/{train,val,test}_w_line.csv), bỏ trùng lặp
chính xác theo mã băm SHA-256 của nội dung hàm và lưu tập sạch 18.694 hàm ra work/clean.pkl.
unit_id của mỗi hàm = SHA-256 của nội dung hàm sau khi đổi CRLF/CR thành LF và bỏ khoảng trắng hai đầu
(xem src/preprocessing/dataset_loader.py). Chạy từ thư mục gốc của repo:  python src/data_prep/mvd/make_clean_pkl.py
"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from src.preprocessing.dataset_loader import MVDDatasetLoader

work = Path(os.environ.get('WORK_DIR', 'work')); work.mkdir(parents=True, exist_ok=True)
clean = MVDDatasetLoader().clean_exact_hash(copy=True)
assert len(clean) == 18694, len(clean)
clean.to_pickle(work / 'clean.pkl')
print('đã lưu', work / 'clean.pkl', len(clean), 'hàm')
