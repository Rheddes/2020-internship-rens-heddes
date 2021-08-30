import pickle
import seaborn as sns
import matplotlib.pyplot as plt
from statsmodels.formula.api import ols

import config

if __name__ == '__main__':
    df = pickle.load(open('dataframe_old.p', 'rb'))
    df_repo = df[df['repo_id'] == 745] # Updates for Apache/Tika
    df_patches = df[df['is_fix_update'] == 1].sort_values(by=['log_update_delay_Z'])

    risks = {
        'hibernate-json': {'A': 0.010129036553874303, 'B': 10.0, 'C': 0.012127896800358461, 'D': 4.473503945832144},
        'pg2k4j': {'A': 0.010644003307709995, 'B': 10.0, 'C': 0.018179602344115007, 'D': 6.5465454765997215},
        'spring-boot-java-swing-reservations': {'A': 0.00038599396853413067, 'B': 8.042250106944246,
                                                'C': 5.562330080316038e-05, 'D': 0.041109533344525495},
        'baremaps': {'A': 0.006317576650557212, 'B': 10.0, 'C': 0.01961006794198637, 'D': 9.050124272845817},
        'pincette-netty-http': {'A': 0, 'B': 0.0, 'C': 0, 'D': 0.0},
        'xgossip': {'A': 0.00015025500796067475, 'B': 3.3384953590620423, 'C': 0.00015589596144469995,
                    'D': 0.14766957489090737},
        'encon-java': {'A': 0, 'B': 0.0, 'C': 0, 'D': 0.0},
        'aquiver': {'A': 0.0004216213471155663, 'B': 4.158089748867852, 'C': 0.00023056701619362157,
                    'D': 0.09291880033160949},
        'vertx-zero': {'A': 0.002958372814946364, 'B': 10.0, 'C': 0.003901055907321438, 'D': 6.922451807235302},
        'mu-server': {'A': 0.002136037027700315, 'B': 7.473558206564634, 'C': 0.01296637509544501,
                      'D': 3.4254929793753632},
        'KittehIRCClientLib': {'A': 0, 'B': 0.0, 'C': 0, 'D': 0.0},
        'netty-websocket-spring-boot-starter': {'A': 0, 'B': 0.0, 'C': 0, 'D': 0.0},
        'proxyee': {'A': 0, 'B': 0.0, 'C': 0, 'D': 0.0},
        'latke': {'A': 0.0001480410142164042, 'B': 3.330104196001127, 'C': 0.00015814210320470862,
                  'D': 0.13873785389689863},
        'firebase-admin-java': {'A': 0, 'B': 0.0, 'C': 0, 'D': 0.0},
        'webtau': {'A': 0.03522112216588397, 'B': 10.0, 'C': 0.06923015081735122, 'D': 6.984736019240076},
        'twilio-java': {'A': 0.012506891476234534, 'B': 10.0, 'C': 0.019308823852892548, 'D': 8.657020899136489},
        'sendgrid-java': {'A': 0.016274146833052675, 'B': 10.0, 'C': 0.04047572677327212, 'D': 7.522459893115354},
        'GeoIP2-java': {'A': 0.03637826991303731, 'B': 10.0, 'C': 0.04308478908589231, 'D': 5.377596988408163},
        'td-client-java': {'A': 0.01036222129942943, 'B': 10.0, 'C': 0.015705303631317932, 'D': 6.647575182961729},
        'zjsonpatch': {'A': 0.030446664500721147, 'B': 9.999999999999998, 'C': 0.05989404950710361,
                       'D': 7.065066012153835},
        'cucumber-reporting': {'A': 0.009733857898036609, 'B': 10.0, 'C': 0.014938980483323285, 'D': 6.541721525440398},
        'docker-image-analyzer': {'A': 0.03175608952433298, 'B': 10.0, 'C': 0.032237744292097394,
                                  'D': 4.557187113994256},
        'docker-client': {'A': 0.006638736249381521, 'B': 10.0, 'C': 0.01299289730335636, 'D': 7.89262442588341},
    }

    scanned_repos = list(risks.keys())
    # df_vulnerable = df.query('cve=="CVE-2020-10683" and uses_vulnerable_code==1 and is_fix_update==1 and short_name in @scanned_repos').copy()
    df_vulnerable = df.query('uses_vulnerable_code==1 and is_fix_update==1 and short_name in @scanned_repos').copy()
    df_vulnerable['risk_a'] = df_vulnerable.apply(lambda row: risks[row['short_name']]['A'], axis=1)
    df_vulnerable['risk_b'] = df_vulnerable.apply(lambda row: risks[row['short_name']]['B'], axis=1)
    df_vulnerable['risk_c'] = df_vulnerable.apply(lambda row: risks[row['short_name']]['C'], axis=1)
    df_vulnerable['risk_d'] = df_vulnerable.apply(lambda row: risks[row['short_name']]['D'], axis=1)

    df_vulnerable = df_vulnerable.query('log_update_delay_Z > 0 or risk_d > 2')
    fig, ((ax1, ax2), (ax3, ax4), (ax5, ax6)) = plt.subplots(3, 2, figsize=(10, 12))
    sns.regplot(data=df_vulnerable, x='cvss_score', y='log_update_delay_Z', ax=ax1)
    ax1.set_xlabel('CVSS score')
    ax1.set_ylabel('Standardised log update delay')
    ax1.set_title('Effect of CVSS Score on\nupdate behaviour')
    ax1.set_xlim(0, 10)
    sns.regplot(data=df_vulnerable, x='cvss_score', y='log_update_delay_Z', ax=ax2)
    ax2.set_xlabel('Risk score')
    ax2.set_ylabel('Standardised log update delay')
    ax2.set_title('Effect of CVSS Score on\nupdate behaviour (zoomed in)')
    ax2.set_xlim(7, 10)
    sns.regplot(data=df_vulnerable, x='risk_a', y='log_update_delay_Z', ax=ax3)
    ax3.set_xlabel('Risk score')
    ax3.set_ylabel('Standardised log update delay')
    ax3.set_title('Effect of Risk Score (Model A) on\nupdate behaviour (zommed in)')
    ax3.set_xlim(0, df_vulnerable.risk_a.max())
    sns.regplot(data=df_vulnerable, x='risk_b', y='log_update_delay_Z', ax=ax4)
    ax4.set_xlabel('Risk score')
    ax4.set_ylabel('Standardised log update delay')
    ax4.set_title('Effect of Risk Score (Model B) on\nupdate behaviour')
    ax4.set_xlim(0, 10)
    sns.regplot(data=df_vulnerable, x='risk_c', y='log_update_delay_Z', ax=ax5)
    ax5.set_xlabel('Risk score')
    ax5.set_ylabel('Standardised log update delay')
    ax5.set_title('Effect of Risk Score (Model C) on\nupdate behaviour (zoomed in)')
    ax5.set_xlim(0, df_vulnerable.risk_c.max())
    sns.regplot(data=df_vulnerable, x='risk_d', y='log_update_delay_Z', ax=ax6)
    ax6.set_xlabel('Risk score')
    ax6.set_ylabel('Standardised log update delay')
    ax6.set_title('Effect of Risk Score (Model D) on\nupdate behaviour')
    ax6.set_xlim(0, 10)
    plt.tight_layout()
    plt.savefig(config.BASE_DIR + '/plots/risk_score_comparison.pdf')
    plt.show()

    model_cvss = ols('log_update_delay_Z ~ cvss_score', df_vulnerable).fit()
    print(model_cvss.summary())
    model_risk = ols('log_update_delay_Z ~ risk_a', df_vulnerable).fit()
    print(model_risk.summary())
    model_risk = ols('log_update_delay_Z ~ risk_b', df_vulnerable).fit()
    print(model_risk.summary())
    model_risk = ols('log_update_delay_Z ~ risk_c', df_vulnerable).fit()
    print(model_risk.summary())
    model_risk = ols('log_update_delay_Z ~ risk_d', df_vulnerable).fit()
    print(model_risk.summary())

    # sns.displot(data=df_repo, x='update_delay')
    # plt.show()
    #
    # sns.displot(data=df_repo, x='log_update_delay') #': still the natural logarithm
    # plt.show()
    #
    # sns.displot(data=df_patches, x='log_update_delay_Z')
    # plt.show()
