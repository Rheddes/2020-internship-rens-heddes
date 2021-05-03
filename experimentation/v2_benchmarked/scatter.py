import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import constants
import pickle


if __name__ == '__main__':
    cvss_distribution = pickle.load(open('../data/distribution.p', 'br'))
    sampled = np.random.choice(cvss_distribution, 100)
    mu, sigma = 0, 0.7
    s = np.random.normal(mu, sigma, len(sampled))
    update_delays = 30+(1+s)*1000 / np.power(sampled, 2)
    df = pd.DataFrame({'CVSS': sampled, 'update_delay': update_delays})
    sns.regplot(data=df, x='update_delay', y='CVSS', logx=True, ci=None)
    plt.title('Impact of CVSS score associated with vulnerability patch\n and update delay')
    plt.xlabel('Update delay to fixed version (days)')
    plt.ylabel('CVSS score of patched vulnerability')
    plt.show()
