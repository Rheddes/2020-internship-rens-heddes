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


def read_mongo(db, collection, query={}, host='localhost', port=27017, username=None, password=None, no_id=True):
    """ Read from Mongo and Store into DataFrame """

    # Connect to MongoDB
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
    scores = cves['impact.baseMetricV3.cvssV3.baseScore']
    scores.plot.density()
    plt.show()
    print(cves['impact.baseMetricV3.cvssV3.baseScore'])
    sns.ecdfplot(data=cves, x="impact.baseMetricV3.cvssV3.baseScore")
    plt.show()
    print('70% quantile----------')
    print(cves.quantile(0.7))
    print('80% quantile----------')
    print(cves.quantile(0.8))
    print('90% quantile----------')
    print(cves.quantile(0.9))
