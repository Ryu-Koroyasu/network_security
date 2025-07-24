# Makefile for IPS/IDS Evaluation Paper

# コンパイル用変数
TEX_FILE = ips_ids_evaluation.tex
PDF_FILE = ips_ids_evaluation.pdf
DATA_SCRIPT = generate_evaluation_data.py

# LuaLaTeXコンパイラ
LATEX = lualatex
BIBTEX = bibtex

# デフォルトターゲット
.PHONY: all clean data pdf view

all: data pdf

# 評価データ生成
data:
	@echo "評価データを生成中..."
	../../../.venv/bin/python $(DATA_SCRIPT)

# PDFコンパイル
pdf: $(PDF_FILE)

$(PDF_FILE): $(TEX_FILE)
	@echo "論文をコンパイル中..."
	$(LATEX) $(TEX_FILE)
	$(LATEX) $(TEX_FILE)  # 参照解決のため2回実行
	@echo "コンパイル完了: $(PDF_FILE)"

# PDFビューア起動
view: $(PDF_FILE)
	@if command -v evince >/dev/null 2>&1; then \
		evince $(PDF_FILE) & \
	elif command -v okular >/dev/null 2>&1; then \
		okular $(PDF_FILE) & \
	elif command -v xdg-open >/dev/null 2>&1; then \
		xdg-open $(PDF_FILE) & \
	else \
		echo "PDFビューアが見つかりません"; \
	fi

# 一時ファイル削除
clean:
	@echo "一時ファイルを削除中..."
	rm -f *.aux *.log *.out *.toc *.bbl *.blg *.fls *.fdb_latexmk *.synctex.gz
	rm -f *.csv *.png *.json latex_tables.tex

# 完全削除（PDFも含む）
distclean: clean
	rm -f $(PDF_FILE)

# ヘルプ
help:
	@echo "利用可能なターゲット:"
	@echo "  all      - データ生成とPDFコンパイルを実行"
	@echo "  data     - 評価データとグラフを生成"
	@echo "  pdf      - LaTeX論文をコンパイル"
	@echo "  view     - PDFをビューアで開く"
	@echo "  clean    - 一時ファイルを削除"
	@echo "  distclean- 全ファイルを削除（PDFも含む）"
	@echo "  help     - このヘルプを表示"

# 依存関係チェック
check-deps:
	@echo "依存関係をチェック中..."
	@command -v python3 >/dev/null 2>&1 || { echo "Python3が必要です"; exit 1; }
	@command -v $(LATEX) >/dev/null 2>&1 || { echo "LuaLaTeXが必要です"; exit 1; }
	@python3 -c "import pandas, matplotlib, numpy, seaborn" 2>/dev/null || { echo "Python依存パッケージが不足しています"; exit 1; }
	@echo "依存関係OK"

# インストール（必要パッケージ）
install-deps:
	@echo "必要パッケージをインストール中..."
	sudo apt-get update
	sudo apt-get install -y texlive-full python3-pip
	pip3 install pandas matplotlib numpy seaborn

# 論文統計情報
stats: $(TEX_FILE)
	@echo "=== 論文統計 ==="
	@echo "文字数: $$(wc -c < $(TEX_FILE))"
	@echo "行数: $$(wc -l < $(TEX_FILE))"
	@echo "セクション数: $$(grep -c '^\\section' $(TEX_FILE))"
	@echo "図表数: $$(grep -c '^\\begin{figure\|^\\begin{table' $(TEX_FILE))"
	@echo "参考文献数: $$(grep -c '^\\bibitem' $(TEX_FILE))"
