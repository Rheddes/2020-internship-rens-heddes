import logging
from time import sleep
from mysql.connector import connect, DatabaseError

from config import get_db_credentials
from repo_analyser.repo_analyser import RepoAnalyser


def main(logger):
    with connect(**(get_db_credentials())) as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT updates.commit_hash, repos.full_name, repos.pom_path
                FROM updates
                INNER JOIN repos ON updates.repo_id = repos.id
                WHERE is_fix_update = 1 AND updates.cve = 'CVE-2020-8840' AND full_name NOT LIKE '%tessera'
            """)
            for (commit_hash, project_name, pom_path) in cursor:
                print(commit_hash, project_name, pom_path)
                repo_scanner = RepoAnalyser(project_name, commit_hash, pom_path)
                repo_scanner.run()


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    main(logging.getLogger())

    # while True:
    #     try:
    #         main(log)
    #     except DatabaseError:
    #         log.warning('MySql Not ready yet')
    #         sleep(5)
