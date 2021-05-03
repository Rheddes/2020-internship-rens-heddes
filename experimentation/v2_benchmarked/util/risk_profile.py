from enum import Enum

import matplotlib.pyplot as plt
import numpy as np


class RiskLevel(Enum):
    NONE = 'None'
    LOW = 'Low'
    MODERATE = 'Moderate'
    HIGH = 'High'
    VERY_HIGH = 'Very High'

    @classmethod
    def list(cls):
        return list(map(lambda c: c.value, cls))


class RiskProfile:
    def __init__(self):
        self._total_weight = 0
        self._callables = {
            RiskLevel.NONE: {},
            RiskLevel.LOW: {},
            RiskLevel.MODERATE: {},
            RiskLevel.HIGH: {},
            RiskLevel.VERY_HIGH: {},
        }

    def add_callable(self, callable_id, weight, risk_level: RiskLevel):
        self._callables[risk_level][callable_id] = weight
        self._total_weight += weight

    def get_ratio(self, risk_level: RiskLevel) -> float:
        if self._total_weight == 0:
            return 0.0
        return sum(self._callables[risk_level].values())/self._total_weight

    def __str__(self):
        str = '{'
        for level in self._callables.keys():
            str += '{}: {}, '.format(level, self.get_ratio(level))
        str += '}'
        return str

    def as_distribution(self):
        if self._total_weight == 0.0:
            return {risk_level: 1.0 if risk_level == RiskLevel.NONE else 0.0 for risk_level in self._callables.keys()}
        return {risk_level: sum(callables.values())/self._total_weight for risk_level, callables in self._callables.items()}


    def plot(self):
        distribution = self.as_distribution()

        fig1, ax1 = plt.subplots()
        wedges, text, autotexts = ax1.pie(distribution.values(),
                                          autopct=lambda p: '{:.1f}%'.format(round(p)) if p > 0 else '',
                                          startangle=90,
                                          pctdistance=1.1
        )
        ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

        for pie_wedge in wedges:
            pie_wedge.set_edgecolor('white')

        ax1.legend(wedges, distribution.keys(), title="Risk Levels", loc="best")
        plt.tight_layout()
        plt.show()


def plot_risk_profiles(risk_profile_results, title):
    labels = list(risk_profile_results.keys())
    data = np.array([list(profile.as_distribution().values()) for profile in risk_profile_results.values()])
    data_cum = data.cumsum(axis=1)
    category_colors = plt.get_cmap('RdYlGn_r')(np.linspace(0.15, 0.85, data.shape[1]))

    fig, ax = plt.subplots(figsize=(9.2, 5))
    ax.invert_yaxis()
    ax.xaxis.set_visible(False)
    ax.set_xlim(0, 1)

    for i, (risk_level, color) in enumerate(zip(RiskLevel.list(), category_colors)):
        widths = data[:, i]
        starts = data_cum[:, i] - widths
        ax.barh(labels, widths, left=starts, height=0.5, label=risk_level, color=color)
        x_centers = starts + widths / 2

        r, g, b, _ = color
        text_color = 'white' if r * g * b < 0.5 else 'darkgrey'
        for y, (x, c) in enumerate(zip(x_centers, widths)):
            if not c == 0.0:
                ax.text(x, y, '{:.1f}%'.format(c*100), ha='center', va='center', color=text_color)
    ax.legend(ncol=len(RiskLevel.list()), bbox_to_anchor=(0, 1), loc='upper left', fontsize='small')
    plt.title(title)
    plt.tight_layout()
    plt.show()