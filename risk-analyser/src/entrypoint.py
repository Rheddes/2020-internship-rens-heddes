#!/usr/bin/env python
import logging
import os
from mysql.connector import connect

from utils import config
from utils.config import get_db_credentials
from repo_analyser.repo_analyser import RepoAnalyser


def _update_risk_score(connection, repo_id, risk_score):
    with connection.cursor() as cursor:
        cursor.execute("UPDATE repos SET risk_score=%(risk_score)s WHERE id = %(id)s", {
            'risk_score': risk_score,
            'id': repo_id,
        })
    connection.commit()


def main():
    risk_data = []
    with connect(**(get_db_credentials())) as connection:
        with connection.cursor(buffered=True) as cursor:
            cursor.execute("""
                SELECT repos.id, updates.commit_hash, repos.full_name, repos.pom_path
                FROM updates
                INNER JOIN repos ON updates.repo_id = repos.id
                WHERE is_fix_update = 1 AND is_vulnerable = 1
                ORDER BY updates.id DESC
            """)
            for (repo_id, commit_hash, project_name, pom_path) in cursor:
                print(commit_hash, project_name, pom_path)
                try:
                    repo_scanner = RepoAnalyser(project_name, commit_hash, pom_path)
                    risk_scores = repo_scanner.run()
                    # _update_risk_score(connection, repo_id, risk_score)
                    risk_data.append((repo_id, commit_hash, project_name, risk_scores))
                except Exception as err:
                    exception_type = type(err).__name__
                    print('Error occured: {}'.format(exception_type))
                    print(err)
            print(risk_data)


if __name__ == '__main__':
    logging.basicConfig(filename=os.path.join(config.BASE_DIR, 'logs', 'repository_scan.log'), level=logging.INFO,
                        filemode='w+')
    main()
