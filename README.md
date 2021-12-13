# 2020-internship-rens-heddes

## Generating all tables and figures

```bash
cd data-analysis
virtualenv env
source env/bin/activate
pip install -r requirements.txt
cd src
python run_all.py -p "./data/update_data.p"
```
