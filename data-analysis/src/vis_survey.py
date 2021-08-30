import os
import pandas as pd
import config
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.patheffects as path_effects

import textwrap

labels = {
    'Q1': ['Yes', 'No'],
    'Q2': ['Yes', 'No'],
    'Q3': ['Always', 'Very frequently', 'Occasionally', 'Rarely', 'Very rarely', 'Never'],
    'Q4': ['To a great extent', 'Somewhat', 'Very little', 'Not at all'],
}


def plot_question(column_name, df, output=None):
    question = column_name + ': ' + df[column_name][0]
    question = '\n'.join(textwrap.wrap(question, 65))
    responses = df.iloc[2:]
    subtitle = '{} responses'.format(responses.shape[0])
    aggregated_data = responses.groupby(column_name)[column_name].count()
    aggregated_data.index = aggregated_data.index.map(str.lower)
    total = sum(aggregated_data)
    sizes = [100*aggregated_data.get(option.lower(), 0)/total for option in labels[column_name]]
    fig, ax = plt.subplots(figsize=(6, 4))
    _, _, wedge_labels = ax.pie(sizes, labels=None, autopct=lambda p: '{:.1f}%'.format(round(p)) if p > 0 else '')
    for text_item in wedge_labels:
        text_item.set_path_effects([path_effects.Stroke(linewidth=1.1, foreground='white'),
                                    path_effects.Normal()])
    # aggregated_data.plot.pie(autopct='%.1f%%', labels=None)
    suptitle = plt.suptitle(question, fontsize=12, ha='left', x=0.01)
    height = suptitle.get_window_extent(renderer=fig.canvas.get_renderer()).height / fig.get_window_extent().height
    plt.figtext(s=subtitle, fontsize=9, fontstyle='italic', fontweight='light', ha='left', va='top', x=0.01, y=suptitle.get_position()[1]-height-0.01)
    plt.ylabel('')
    ax.legend(labels=labels[column_name], bbox_to_anchor=(1, 0, 0.5, 0.8))
    plt.tight_layout()
    if output:
        plt.savefig(os.path.join(output, f'{column_name}.pdf'))
    plt.show()


if __name__ == '__main__':
    plots_dir = os.path.join(config.BASE_DIR, 'plots', 'questionnaire')
    if not os.path.exists(plots_dir):
        os.mkdir(plots_dir)
    df = pd.read_csv(os.path.join(config.BASE_DIR, 'data', 'survey_responses_12_august.csv'))
    for question in ['Q1', 'Q2', 'Q3', 'Q4']:
        plot_question(question, df, output=plots_dir)
