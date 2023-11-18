#cve_dataset.py
import glob
import json
import sys, os
import sqlite3
import pandas as pd
import numpy as np

class CveDataSet():
    def __init__(self):
        self.nvd: pd.DataFrame = self._set_nvd()
        self.epss: pd.DataFrame = self._set_epss('data/epss_scores-current.csv')
        self.kev: pd.DataFrame = self._set_kev('data/known_exploited_vulnerabilities.csv')
        self.exploitdb: pd.DataFrame = self._set_exploitdb('data/go-exploitdb.sqlite3')

    def _set_nvd(self):
        row_accumulator = []
        for filename in glob.glob('data/nvdcve-1.1-*.json'):
            with open(filename, 'r', encoding='utf-8') as f:
                nvd_data = json.load(f)
                for entry in nvd_data['CVE_Items']:
                    cve = entry['cve']['CVE_data_meta']['ID']
                    try:
                        base_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
                    except KeyError:
                        base_score = '0.0'
                    new_row = { 
                        'CVE': cve, 
                        'CVSS3': base_score,
                    }
                    row_accumulator.append(new_row)
                nvd = pd.DataFrame(row_accumulator)
                
        nvd['CVSS3'] = pd.to_numeric(nvd['CVSS3']);
        # nvd['CVSS3'] = nvd['CVSS3'].replace(0, np.NaN);  
        return nvd
    
    def _set_epss(self, f) -> pd.DataFrame: 
        try:
            epss = pd.read_csv(f, skiprows=1)
            return epss.rename(columns={"cve": "CVE", "epss" : "EPSS", "percentile" : "EPSS Percentile"})
        except FileNotFoundError as e:
            sys.stderr.write(f'epssのファイル({f})が無いよ。ちゃんとfetchしてきてね。')
            sys.exit(1)

    def _set_kev(self, f) -> pd.DataFrame:
        try:
            kev = pd.read_csv(f)
            kev.columns = kev.columns.str.strip("\u200b")
            return kev.rename(columns={"cveID": "CVE", "shortDescription" : "Description", "dateAdded" : "date"})
        except FileNotFoundError as e:
            sys.stderr.write(f'kevのファイル({f})が無いよ。ちゃんとfetchしてきてね。')
            sys.exit(1)

    def _set_exploitdb(self, f) -> pd.DataFrame:
        if not os.path.exists(f):
            sys.stderr.write(f'Error: The file {f} does not exist.')
            sys.exit(1)
        conn = sqlite3.connect(f)
        return pd.read_sql_query('SELECT cve_id as CVE, url as PoC FROM exploits', conn)