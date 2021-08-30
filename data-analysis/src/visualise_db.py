import pickle

from sqlalchemy import create_engine
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib import rcParams
import numpy as np
from scipy import stats
import mysql
from statsmodels.formula.api import ols


import config


def _get_data_from_pickle():
    """
    Instead of loading data from DB we can also read a pickle dump, make sure the path is set correct.
    :return: Dataframe with all update data
    """
    df = pickle.load(open('dataframe.p', 'rb'))
    return df


def _write_to_pickle(df):
    pickle.dump(df, open('dataframe.p', 'wb'))


def _get_data():
    query = """
                SELECT u.*, r.full_name, r.is_vulnerable as uses_vulnerable_code, r.risk_score, v.package_coords, v.first_fix_release_date, v.disclosure_date, v.cvss_score, cves.* FROM updates u
                INNER JOIN repos r ON u.repo_id = r.id
                INNER JOIN vulnerabilities v ON u.cve = v.cve
                LEFT JOIN cves ON fixes_cve_id = cves.id
                WHERE is_fork = 0;
            """
    # v.cve = 'CVE-2020-8840' AND
    df = pd.read_sql(query, con=config.get_db_connection(), parse_dates=['commit_date', 'old_release_date', 'new_release_date', 'first_fix_release_date', 'disclosure_date'])
    # deduplicate 'cve' column names
    df.columns = pd.io.parsers.ParserBase({'names': df.columns})._maybe_dedup_names(df.columns)
    df['log_update_delay'] = np.log10(df['update_delay'])
    means = df.groupby('repo_id')['log_update_delay'].mean()
    stds = df.groupby('repo_id')['log_update_delay'].std()
    df = df[df['repo_id'].isin(stds[stds > 0].index)]
    df['log_update_delay_Z'] = df.apply(
        lambda row: (row['log_update_delay'] - means[row['repo_id']]) / stds[row['repo_id']], axis=1)
    df['short_name'] = df.apply(lambda row: row['full_name'].split('/')[1], axis=1)
    df['unique_name'] = df.apply(lambda row: '{} - {}'.format(row['full_name'], row['cve']), axis=1)
    return df


def scatter_dist():
    df = _get_data_from_pickle()

    fig, axs = plt.subplots(1, 2, figsize=(10, 6))
    sns.histplot(data=df, x='log_update_delay_Z', bins=65, ax=axs[0])
    axs[0].set_xlabel('Standardised log update delay')
    axs[0].set_title('Standardised log update delays for\nall updates across all scanned repositories')
    data = {
        'Fitted normal distribution': np.random.normal(df.log_update_delay_Z.mean(), df.log_update_delay_Z.std(),
                                                       df.shape[0]),
        'Observed': df.log_update_delay_Z,
    }
    sns.ecdfplot(data, palette=['red', 'blue'], ax=axs[1])
    axs[1].set_title('Cumulative distribution of standardised\nlog update delays')
    axs[1].set_xlabel('Standardised log update delay')
    plt.savefig(config.BASE_DIR + '/plots/stats/all_update_delays.pdf')
    plt.show()

    testing_for_normality = False
    if testing_for_normality:
        for repo_id, count in list(df['repo_id'].value_counts().items())[:100]:
            df_repo = df[df['repo_id'] == repo_id]

            stat, p = stats.normaltest(df_repo['log_update_delay_Z'])
            print('---------STATS for {}--------'.format(repo_id))
            print('Statistics=%.3f, p=%.10f' % (stat, p))
            # interpret
            alpha = 0.05
            if p > alpha:
                print('Sample looks Gaussian (fail to reject H0)')
                sns.displot(data=df_repo, x='log_update_delay_Z')
                plt.title('Update delay distributions for repo {} ({} updates)'.format(repo_id, count))
                plt.show()
            else:
                print('Sample does not look Gaussian (reject H0)')

    df_all = df
    df = df.query('is_fix_update == 1 and commit_date > disclosure_date').sort_values(by='log_update_delay_Z')

    with sns.color_palette(['mediumaquamarine', 'red']):
        fig, ax = plt.subplots(figsize=(11.7, 8.27))
        g = sns.barplot(data=df, ax=ax, x='unique_name', y='log_update_delay_Z', hue='uses_vulnerable_code', dodge=False, ci=False)
        g.set_xticklabels(g.get_xticklabels(), rotation=90)  # , horizontalalignment='right')
        legend = g.legend()
        legend.set_title('Uses vulnerable code')
        for t, l in zip(legend.texts, ('False', 'True')):
            t.set_text(l)
        # g.legend_.remove()
        plt.xlabel('Repository')
        plt.ylabel('Normalized update delay deviation from mean')
        plt.title('Distribution of normalised fix update delay deviations')
        g.set_xticklabels([])
        plt.savefig(config.BASE_DIR + '/plots/stats/fix_update_delays.png', dpi=300)
        plt.show()

    print('Normality test 68/95/99')
    print(df_all.log_update_delay_Z.between(-1, 1).mean())
    print(df_all.log_update_delay_Z.between(-2, 2).mean())
    print(df_all.log_update_delay_Z.between(-3, 3).mean())

    for cve in df['cve'].unique():
        df_cve = df[df['cve'] == cve]
        if df_cve.shape[0] < 20:
            print('Skipping on {} because low number of updates'.format(cve))
            continue
        print(cve)
        g = sns.barplot(data=df_cve, x='short_name', y='log_update_delay_Z', hue='uses_vulnerable_code',
                        dodge=False, ci=False)
        g.set_xticklabels(g.get_xticklabels(), rotation=90)  # , horizontalalignment='right')
        plt.xlabel('Repository')
        plt.ylabel('Normalized update delay deviation from mean')
        plt.title('Distribution of normalised fix update delay deviations\n for {}'.format(cve))
        vulnerable_short_names = df_cve[df_cve['uses_vulnerable_code'] == 1]['short_name'].to_list()
        for n, label in enumerate(g.get_xticklabels()):
            if label.get_text() not in vulnerable_short_names:
                label.set_visible(False)
        plt.show()

    print(df['log_update_delay_Z'].describe())

    cve_update_delays = df.groupby('cve').agg({'log_update_delay_Z': 'mean', 'cvss_score': 'min'})
    sns.regplot(data=cve_update_delays, x='cvss_score', y='log_update_delay_Z')
    plt.show()
    df_all['cvss_buckets'] = df_all['v3BaseScore'].fillna(0.0).round().astype(int)
    sns.boxplot(data=df_all, x='cvss_buckets', y='log_update_delay_Z', order=range(0, 10))
    plt.title('Effect of CVSS score on update behaviour')
    plt.xlabel('CVSS score (rounded to nearest integer)')
    plt.ylabel('Standardised log update delay')
    plt.show()
    return df, df_all


def plot_for_single_repo():
    repo_id = 745
    df = _get_data_from_pickle()
    repo_df = df[df['repo_id'] == repo_id]
    sns.displot(data=repo_df, x='update_delay', bins=30)
    plt.xlabel('Update delay in days')
    # plt.xlim(0, 800)
    plt.title('Absolute update delay (in number of days)\n for "Apache/Tika"')
    plt.savefig(config.BASE_DIR + '/plots/tika/absolute_apache_tika.pdf')
    plt.show()

    sns.displot(data=repo_df, x='log_update_delay', kde=True, bins=30)
    plt.xlabel('Log(Update delay in days)')
    plt.title('Log of update delay for "Apache/Tika"')
    plt.savefig(config.BASE_DIR + '/plots/tika/log_apache_tika.pdf')
    plt.show()

    sns.distplot(repo_df['log_update_delay'], fit=stats.norm, bins=30)
    plt.xlabel('Log(Update delay in days)')
    plt.title('Probability density estimation for\nlog of update delay for "Apache/Tika"')
    plt.savefig(config.BASE_DIR + '/plots/tika/log_apache_tika_with_fit.pdf')
    plt.show()

    lud_mean = repo_df.log_update_delay.mean()
    lud_stdev = repo_df.log_update_delay.std()
    fit = np.random.normal(lud_mean, lud_stdev, 10000)
    data = {
        'Fitted normal distribution': fit,
        'Log update delay': repo_df['log_update_delay'],
    }
    sns.ecdfplot(data=data, legend=True, palette=['red', 'blue'])
    plt.title('Cumulative distribution of log update delays')
    plt.xlabel('Log update delay')
    plt.savefig(config.BASE_DIR + '/plots/tika/cdf_with_fit.pdf')
    plt.show()
    return repo_df


def plot_risk_scores():
    df = _get_data_from_pickle()
    df_vulnerable = df.query('uses_vulnerable_code==1 and is_fix_update==1 and risk_score == risk_score').copy()
    df_vulnerable = df_vulnerable.query('log_update_delay_Z > 0 or risk_score > 2')
    fig, axs = plt.subplots(1, 2, figsize=(10, 6))
    sns.regplot(data=df_vulnerable, x='cvss_score', y='log_update_delay_Z', ax=axs[0])
    axs[0].set_xlabel('CVSS score')
    axs[0].set_ylabel('Standardised log update delay')
    axs[0].set_title('Effect of CVSS Score on\nupdate behaviour')
    axs[0].set_xlim(0, 10)
    sns.regplot(data=df_vulnerable, x='risk_score', y='log_update_delay_Z', ax=axs[1])
    axs[1].set_xlabel('Risk score')
    axs[1].set_ylabel('Standardised log update delay')
    axs[1].set_title('Effect of Risk Score (Model D) on\nupdate behaviour')
    axs[1].set_xlim(0, 10)
    plt.savefig(config.BASE_DIR + '/plots/risk_score_comparison.pdf')
    plt.show()

    model_cvss = ols('log_update_delay_Z ~ cvss_score', df_vulnerable).fit()
    print(model_cvss.summary())
    model_risk = ols('log_update_delay_Z ~ risk_score', df_vulnerable).fit()
    print(model_risk.summary())

    return df_vulnerable, df


if __name__ == '__main__':
    rcParams.update({'figure.autolayout': True})

    # result_repo = plot_for_single_repo()
    # result_vulnerable, result_all = scatter_dist()
    result_risk, result_all = plot_risk_scores()
