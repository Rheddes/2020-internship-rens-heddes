import logging
import os
import pickle

import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

from utils.config import BASE_DIR, get_db_connection, ensure_path
from utils.latex import latex_percentage, latex_float, latex_int, process_and_write_latex_table


class VulnerabilityHistory:
    def __init__(self, update_df_path):
        self.raw_df = self._get_data(update_df_path)
        self.df = self._process_data(self.raw_df)

    def _get_data(self, update_df_path):
        if update_df_path is None:
            return self._get_data_from_db()
        return self._get_data_from_pickle(update_df_path)

    @staticmethod
    def _get_data_from_pickle(update_df_path):
        """
        Instead of loading data from DB we can also read a pickle dump, make sure the path is set correct.
        :return: Dataframe with all update data
        """
        df = pickle.load(open(os.path.join(BASE_DIR, update_df_path), 'rb'))
        return df

    @staticmethod
    def _get_data_from_db():
        query = """
                    SELECT r.id as repo_id, r.full_name, r.cve as repo_cve, r.is_vulnerable as uses_vulnerable_code, r.risk_score, u.*, v.package_coords, v.first_fix_release_date, v.disclosure_date, v.cvss_score, cves.*
                    FROM repos r
                    LEFT JOIN updates u ON u.repo_id = r.id
                    LEFT JOIN vulnerabilities v ON u.cve = v.cve
                    LEFT JOIN cves ON fixes_cve_id = cves.id
                    WHERE is_fork = 0;
                """
        # v.cve = 'CVE-2020-8840' AND
        df = pd.read_sql(query, con=get_db_connection(), parse_dates=['commit_date', 'old_release_date', 'new_release_date', 'first_fix_release_date', 'disclosure_date'])
        # deduplicate 'cve' column names
        df.columns = pd.io.parsers.ParserBase({'names': df.columns})._maybe_dedup_names(df.columns)
        return df

    @staticmethod
    def _process_data(raw_df: pd.DataFrame):
        df = raw_df.copy(deep=True)
        df['log_update_delay'] = np.log10(df['update_delay'])
        means = df.groupby('repo_id')['log_update_delay'].mean()
        stds = df.groupby('repo_id')['log_update_delay'].std()
        df = df[df['repo_id'].isin(stds[stds > 0].index)]
        df['log_update_delay_Z'] = df.apply(
            lambda row: (row['log_update_delay'] - means[row['repo_id']]) / stds[row['repo_id']], axis=1)
        df['short_name'] = df.apply(lambda row: row['full_name'].split('/')[1], axis=1)
        df['unique_name'] = df.apply(lambda row: '{} - {}'.format(row['full_name'], row['cve']), axis=1)
        return df

    @staticmethod
    def values_within_standard_deviation_table(df, output_path):
        stdev = df.log_update_delay_Z.std()
        df = pd.DataFrame([
            ['\mu\pm\sigma', df.log_update_delay_Z.between(-stdev, stdev).mean()],
            ['\mu\pm2\sigma', df.log_update_delay_Z.between(-2 * stdev, 2 * stdev).mean()],
            ['\mu\pm3\sigma', df.log_update_delay_Z.between(-3 * stdev, 3 * stdev).mean()],
        ], columns=['range', 'percentage of data within range'])
        table_string = df.to_latex(index=False, escape=False,
                    column_format=r'@{}lr@{}', label='tab:normality_stdev', formatters=[latex_int, latex_percentage],
                    caption='Percentage of datapoints that lie within 1, 2 \& 3 standard deviations from the mean in the observed distribution',
                    header=['range', 'percentage of data within range'])
        process_and_write_latex_table(table_string, os.path.join(BASE_DIR, output_path, 'datapoints_in_standarddeviations.tex'))

    def data_overview(self, output_path):
        table_data = self.raw_df.groupby('repo_cve').agg({'repo_id': 'nunique', 'is_fix_update': 'sum'}).astype({'is_fix_update': 'int'}).sort_values(by='repo_id', ascending=False).reset_index()
        table_string = table_data.to_latex(
                      index=False, escape=False,
                      column_format=r'@{}lrr@{}', label='tab:scanned_repos',
                      formatters=[None, latex_int, latex_int],
                      caption='The number of scanned repositories per vulnerability',
                      header=['vulnerability', 'found repositories', 'found fix updates for'])
        process_and_write_latex_table(table_string, os.path.join(BASE_DIR, output_path, 'scanned_repos.tex'))

    def scatter_dist(self, output_path):
        df = self.df
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
        plt.savefig(os.path.join(BASE_DIR, output_path, 'all_update_delays.pdf'))
        plt.show()

        df_fix_updates = df.query('is_fix_update == 1 and commit_date > disclosure_date').sort_values(by='log_update_delay_Z')

        with sns.color_palette(['mediumaquamarine', 'red']):
            fig, ax = plt.subplots(figsize=(11.7, 8.27))
            g = sns.barplot(data=df_fix_updates, ax=ax, x='unique_name', y='log_update_delay_Z', hue='uses_vulnerable_code', dodge=False, ci=False)
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
            plt.savefig(os.path.join(BASE_DIR, output_path, 'fix_update_delays.pdf'))
            plt.show()

        self.values_within_standard_deviation_table(df, output_path)

        ensure_path(os.path.join(BASE_DIR, output_path, 'fix_update_delays'))
        for cve in df_fix_updates['cve'].unique():
            df_cve = df_fix_updates[df_fix_updates['cve'] == cve]
            if df_cve.shape[0] < 20:
                logging.info('Skipping on {} because low number of updates'.format(cve))
                continue
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
            plt.savefig(os.path.join(BASE_DIR, output_path, 'fix_update_delays', '{}.pdf'.format(cve)))
            plt.show()

        df['cvss_buckets'] = df['v3BaseScore'].fillna(0.0).round().astype(int)
        sns.boxplot(data=df, x='cvss_buckets', y='log_update_delay_Z', order=range(0, 10))
        plt.title('Effect of CVSS score on update behaviour')
        plt.xlabel('CVSS score (rounded to nearest integer)')
        plt.ylabel('Standardised log update delay')
        plt.savefig(os.path.join(BASE_DIR, output_path, 'cvss_update_delays.pdf'))
        plt.show()

    def plot_for_single_repo(self, output_path, repo_id=745):
        """
        Plot detailed update information for a single repository, by default Apache/Tika
        :param output_path:
        :param repo_id:
        :return:
        """
        df = self.df
        repo_df = df[df['repo_id'] == repo_id]
        short_name = repo_df.iloc[0].full_name.split('/')[-1]
        repo_output_dir = os.path.join(BASE_DIR, output_path, short_name)
        ensure_path(repo_output_dir)
        sns.displot(data=repo_df, x='update_delay', bins=30)
        plt.xlabel('Update delay in days')
        # plt.xlim(0, 800)
        plt.title('Absolute update delay (in number of days)\n for "Apache/Tika"')
        plt.savefig(os.path.join(repo_output_dir, 'absolute_apache_tika.pdf'))
        plt.show()

        sns.distplot(repo_df['log_update_delay'], fit=stats.norm, bins=30)
        plt.xlabel('Log(Update delay in days)')
        plt.title('Probability density estimation for\nlog of update delay for "Apache/Tika"')
        plt.savefig(os.path.join(repo_output_dir, 'log_apache_tika_with_fit.pdf'))
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
        plt.savefig(os.path.join(repo_output_dir, 'cdf_with_fit.pdf'))
        plt.show()

        index = ['count',
                 'mean',
                 'standard deviation',
                 'minimum',
                 '25th percentile',
                 '50th percentile',
                 '75th percentile',
                 'maximum']
        table_string = repo_df.update_delay.describe().set_axis(index).to_frame().reset_index().to_latex(escape=False, column_format=r'@{}lr@{}',
                            formatters=[None, latex_float], index=False,
                            header=['metric', 'update delay in days'])
        process_and_write_latex_table(table_string, os.path.join(repo_output_dir, 'data_description.tex'))

        return repo_df

