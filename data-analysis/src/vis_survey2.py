import os
import re

import pandas as pd
import config
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.patheffects as path_effects

import textwrap

labels = {
    'Q9_1': ['Yes', 'No'],
    'Q3': ['Daily', '2-3 times a week', 'Weekly', 'Less frequently than weekly'],
    'Q4': ['Daily', '2-3 times a week', 'Weekly', 'Less frequently than weekly', 'Never'],
    'Q2': ['NVD', 'Automatic tool', 'GitHub alerts', 'CLI tool', 'Other people', 'Other'],
}


def plot_question(column_name, df, output=None, chart_type='pie'):
    question = '\n'.join(textwrap.wrap(re.match(r'.*\?', df[column_name][0]).group(0), 65))
    responses = df.iloc[2:]

    subtitle = '{} responses'.format(responses.shape[0])

    if chart_type == 'pie':
        fig, ax = plt.subplots(figsize=(6, 4))
        aggregated_data = responses.groupby(column_name)[column_name].count()
        aggregated_data.index = aggregated_data.index.map(str.lower)
        total = sum(aggregated_data)
        sizes = [100*aggregated_data.get(option.lower(), 0)/total for option in labels[column_name]]
        _, _, wedge_labels = ax.pie(sizes, labels=None, autopct=lambda p: '{:.1f}%'.format(round(p)) if p > 0 else '')
        for text_item in wedge_labels:
            text_item.set_path_effects([path_effects.Stroke(linewidth=1.1, foreground='white'),
                                        path_effects.Normal()])
        # aggregated_data.plot.pie(autopct='%.1f%%', labels=None)
        plt.ylabel('')
        ax.legend(labels=labels[column_name], bbox_to_anchor=(1, 0, 0.5, 0.8))
        suptitle = plt.suptitle(question, fontsize=12, ha='left', x=0.01)

    else:
        fig, ax = plt.subplots(figsize=(6, 6))
        responses = responses.sort_values(column_name)
        sns.countplot(data=responses, x=column_name)
        plt.xticks(rotation=90)
        suptitle = plt.suptitle(question, fontsize=12, ha='left', x=0.01, y=1.1)

    height = suptitle.get_window_extent(renderer=fig.canvas.get_renderer()).height / fig.get_window_extent().height
    plt.figtext(s=subtitle, fontsize=9, fontstyle='italic', fontweight='light', ha='left', va='top', x=0.01,
                y=suptitle.get_position()[1] - height - 0.01)
    # plt.tight_layout()
    if output:
        plt.savefig(os.path.join(output, f'{column_name}.pdf'), bbox_inches='tight')
    plt.show()


def plot_multiselect(column_name, df, output=None):
    question = '\n'.join(textwrap.wrap(re.match(r'.*\?', df[column_name][0]).group(0), 65))
    df[column_name] = df[column_name].fillna('')
    responses = df.iloc[2:]
    subtitle = '{} responses'.format(responses.shape[0])

    answer_map = {
        'National Vulnerability Database (NVD) or similar': 'NVD',
        'Automatic tool such as dependabot': 'Automatic tool',
        'GitHub security reports or similar': 'GitHub alerts',
        'Command line tool (such as NPM Audit or dependencycheck) during development': 'CLI tool',
        'Other people in the development process': 'Other people',
        'Other (please specify)': 'Other',
    }
    totals = responses.groupby('Q4')['Q4'].count().to_dict()

    data = {
        'vulnerability_source': list(answer_map.values())*len(totals),
        'investigation_frequency': list(totals.keys())*len(answer_map),
        'count': [0] * len(answer_map)*len(totals)
    }
    mapped = pd.DataFrame(data=data)
    for i, row in responses.iterrows():
        selected_options = row['Q2'].split(',')
        frequency = row['Q4']
        for option in selected_options:
            if option:
                mapped_option = answer_map[option]
                index = mapped.query('vulnerability_source == @mapped_option and investigation_frequency == @frequency').index[0]
                mapped.at[index, 'count'] += 1

    mapped['percentage'] = mapped.apply(lambda row: 100 * row['count'] / totals[row['investigation_frequency']], axis=1)

    fig, ax = plt.subplots(figsize=(6, 6))
    hue_order = labels['Q4']
    sns.barplot(data=mapped, x='vulnerability_source', y='percentage', hue='investigation_frequency', hue_order=hue_order)
    plt.xticks(rotation=90)
    suptitle = plt.suptitle(question, fontsize=12, ha='left', x=0.01, y=1.1)
    height = suptitle.get_window_extent(renderer=fig.canvas.get_renderer()).height / fig.get_window_extent().height
    plt.figtext(s=subtitle, fontsize=9, fontstyle='italic', fontweight='light', ha='left', va='top', x=0.01,
                y=suptitle.get_position()[1] - height - 0.01)
    plt.xlabel('Vulnerability information source')
    plt.ylabel('Percentage of respondents using that source\n(categorised by vulnerability investigation frequency)')
    plt.legend(title='Vulnerability investigation frequency', loc='upper left', bbox_to_anchor=(1.05, 1))
    if output:
        plt.savefig(os.path.join(output, f'{column_name}.pdf'), bbox_inches='tight')
    plt.show()

def table_numeric(column_name, df, output=None):
    responses = df.iloc[2:].copy()
    responses[column_name] = pd.to_numeric(responses[column_name], errors='coerce')
    years_of_experience = responses.groupby(column_name)[column_name].count().to_latex()
    if output:
        with open(os.path.join(output, 'years_of_experience.tex'), 'w') as f:
            f.write(years_of_experience)
    print(years_of_experience)


if __name__ == '__main__':
    plots_dir = os.path.join(config.BASE_DIR, 'plots', 'questionnaire2')
    if not os.path.exists(plots_dir):
        os.mkdir(plots_dir)
    df = pd.read_csv(os.path.join(config.BASE_DIR, 'data', 'survey_responses_25_august.csv'))
    print(df)
    for question, chart_type in [('Q3', 'pie'), ('Q4', 'pie')]:
        plot_question(question, df, output=plots_dir, chart_type=chart_type)

    plot_multiselect('Q2', df, output=plots_dir)
    table_numeric('Q9_1', df, output=plots_dir)
