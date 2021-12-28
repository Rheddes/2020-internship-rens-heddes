# 2020-internship-rens-heddes


[![DOI](https://zenodo.org/badge/358278903.svg)](https://zenodo.org/badge/latestdoi/358278903)

## Generating all tables and figures

```bash
cd data-analysis
virtualenv env
source env/bin/activate
pip install -r requirements.txt
cd src
python run_all.py -p "./data/update_data.p"
```

## Or use docker-compose
```bash
cd data-analysis
docker compose up
```
