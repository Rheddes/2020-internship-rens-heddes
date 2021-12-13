def latex_int(i):
    return f'${i}$'


def latex_float(f):
    float_str = '{0:.2e}'.format(f) if f < 0.01 else '{:.2f}'.format(f)
    if 'e' in float_str:
        base, exponent = float_str.split('e')
        return r'${0} \times 10^{{{1}}}$'.format(base, int(exponent))
    return f'${float_str}$'


def latex_percentage(p):
    return '${:.1%}$'.format(p).replace('%', r'\%')


def process_and_write_latex_table(table_string, output_path):
    with open(output_path, 'w') as f:
        f.write(table_string.replace(r'\toprule', r'\hline').replace(r'\midrule', '\\hline\n\\hline').replace(
            r'\bottomrule', r'\hline'))
