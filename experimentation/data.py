import pandas as pd
from pymongo import MongoClient
import matplotlib.pyplot as plt
import seaborn as sns

"""
Can be used to extract data vulnerability data from MongoDB
"""


def _connect_mongo(host, port, username, password, db):
    """ A util for making a connection to mongo """

    if username and password:
        mongo_uri = 'mongodb://%s:%s@%s:%s/%s' % (username, password, host, port, db)
        conn = MongoClient(mongo_uri)
    else:
        conn = MongoClient(host, port)

    return conn[db]


def read_mongo(db, collection, query=None, host='localhost', port=27017, username=None, password=None, no_id=True):
    """ Read from Mongo and Store into DataFrame """

    # Connect to MongoDB
    if query is None:
        query = {}
    db = _connect_mongo(host=host, port=port, username=username, password=password, db=db)

    # Make a query to the specific DB and Collection
    cursor = db[collection].find(query)

    # Expand the cursor and construct the DataFrame
    df = pd.json_normalize(list(cursor))

    # Delete the _id
    if no_id:
        del df['_id']

    return df


if __name__ == '__main__':
    cves = read_mongo('NVD', 'CVE')
    scores = cves['impact.baseMetricV2.cvssV2.baseScore']
    density_graph = scores.plot.density()
    density_graph.set(xlim=(0, 10), ylim=(0, 1))
    density_graph.set_xlabel("CVSS (v2) score")
    density_graph.set_ylabel("Density")
    plt.show()
    print(cves['impact.baseMetricV2.cvssV2.baseScore'])
    g = sns.ecdfplot(data=cves, x="impact.baseMetricV2.cvssV2.baseScore")
    g.set(xlim=(0, 10), ylim=(0, 1))
    g.set_xlabel("CVSS (v2) score")
    g.set_ylabel("Cumulative distribution")
    plt.show()
    print('25% quantile----------')
    print(cves.quantile(0.25))
    print('50% quantile----------')
    print(cves.quantile(0.5))
    print('75% quantile----------')
    print(cves.quantile(0.75))

# DATA FROM: 2015-2020
# /Users/rheddes/Development/2020-internship-rens-heddes/experimentation/venv/bin/python /Users/rheddes/Development/2020-internship-rens-heddes/experimentation/data.py
# 0         2.1
# 1         9.3
# 2         3.7
# 3         4.3
# 4         7.2
#          ...
# 83074     5.8
# 83075     5.8
# 83076     4.3
# 83077    10.0
# 83078     5.0
# Name: impact.baseMetricV2.cvssV2.baseScore, Length: 83079, dtype: float64
# 70% quantile----------
# impact.baseMetricV3.cvssV3.baseScore        7.8
# impact.baseMetricV3.exploitabilityScore     3.9
# impact.baseMetricV3.impactScore             5.9
# impact.baseMetricV2.cvssV2.baseScore        6.8
# impact.baseMetricV2.exploitabilityScore    10.0
# impact.baseMetricV2.impactScore             6.4
# Name: 0.7, dtype: float64
# 80% quantile----------
# impact.baseMetricV3.cvssV3.baseScore        8.8
# impact.baseMetricV3.exploitabilityScore     3.9
# impact.baseMetricV3.impactScore             5.9
# impact.baseMetricV2.cvssV2.baseScore        7.5
# impact.baseMetricV2.exploitabilityScore    10.0
# impact.baseMetricV2.impactScore             6.9
# Name: 0.8, dtype: float64
# 90% quantile----------
# impact.baseMetricV3.cvssV3.baseScore        9.8
# impact.baseMetricV3.exploitabilityScore     3.9
# impact.baseMetricV3.impactScore             5.9
# impact.baseMetricV2.cvssV2.baseScore        9.0
# impact.baseMetricV2.exploitabilityScore    10.0
# impact.baseMetricV2.impactScore            10.0
# Name: 0.9, dtype: float64





# 25% quantile----------
# impact.baseMetricV3.cvssV3.baseScore       6.1
# impact.baseMetricV3.exploitabilityScore    1.8
# impact.baseMetricV3.impactScore            3.6
# impact.baseMetricV2.cvssV2.baseScore       4.3
# impact.baseMetricV2.exploitabilityScore    6.8
# impact.baseMetricV2.impactScore            2.9
# Name: 0.25, dtype: float64
# 50% quantile----------
# impact.baseMetricV3.cvssV3.baseScore       7.5
# impact.baseMetricV3.exploitabilityScore    2.8
# impact.baseMetricV3.impactScore            3.6
# impact.baseMetricV2.cvssV2.baseScore       5.0
# impact.baseMetricV2.exploitabilityScore    8.6
# impact.baseMetricV2.impactScore            4.9
# Name: 0.5, dtype: float64
# 75% quantile----------
# impact.baseMetricV3.cvssV3.baseScore        8.8
# impact.baseMetricV3.exploitabilityScore     3.9
# impact.baseMetricV3.impactScore             5.9
# impact.baseMetricV2.cvssV2.baseScore        7.2
# impact.baseMetricV2.exploitabilityScore    10.0
# impact.baseMetricV2.impactScore             6.4
# Name: 0.75, dtype: float64