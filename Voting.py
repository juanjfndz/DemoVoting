import sqlite3
import getpass

from CheckCertificate import CertificateHandler

class Vote:
    def __init__(self, db_name):
        """
        Initializes a Vote object with the specified database name.
        
        Parameters:
        db_name (str): The name of the database.
        
        Returns:
        None
        """
        self._db_name = db_name
        self._create_database()

    def _create_database(self):
        """
        Creates the 'votes' table if it does not already exist in the database.
        
        Parameters:
        None
        
        Returns:
        None
        """
        with sqlite3.connect(self._db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS votes (
                    voter_id TEXT PRIMARY KEY,
                    choice TEXT NOT NULL
                )
            """)
            conn.commit()

    def _insert_vote(self, voter_id, choice):
        """
        Inserts a vote into the 'votes' table in the database.
        
        Parameters:
        voter_id (str): The ID of the voter.
        choice (str): The voter's choice of 'OptionA', 'OptionB', or 'OptionC'.
        
        Returns:
        None
        """
        with sqlite3.connect(self._db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO votes (voter_id, choice)
                VALUES (?, ?)
            """, (voter_id, choice))
            conn.commit()

    def cast_vote(self, voter_id, choice):
        """
        Casts a vote for the specified voter ID and choice.
        
        Parameters:
        voter_id (str): The ID of the voter.
        choice (str): The voter's choice of 'OptionA', 'OptionB', or 'OptionC'.
        
        Returns:
        None
        
        Raises:
        ValueError: If the choice is not one of 'OptionA', 'OptionB', or 'OptionC'.
        """
        if choice not in ["OptionA", "OptionB", "OptionC"]:
            raise ValueError("Invalid choice. Choose from 'OptionA', 'OptionB', or 'OptionC'.")
        self._insert_vote(voter_id, choice)

    def get_vote_results(self):
        """
        Retrieves the vote results from the 'votes' table in the database.
        
        Parameters:
        None
        
        Returns:
        results (list): A list of tuples containing the choice and the number of votes for that choice.
        """
        with sqlite3.connect(self._db_name) as conn:
            cursor = conn.cursor()
            results = cursor.execute("""
                SELECT choice, COUNT(*) as count
                FROM votes
                GROUP BY choice
                ORDER BY count DESC
            """).fetchall()
            return results

# Usage example of voting:

# Vote ID extraction
try:
    p12_path = '/Users/juanjosefernandezmorales/Documents/FERNANDEZ_MORALES_JUAN_JOSE___45343816Y.p12'
    p12_password = getpass.getpass("Enter your password: ").encode('utf-8')

    cert_handler = CertificateHandler(p12_path, p12_password)
    voter_id = cert_handler.common_name_sha256

# Erase the information.
finally:
    p12_path = None
    p12_password = None
    cert_handler = None

# Vote
vote_db = Vote("vote_db.sqlite3")
vote_db.cast_vote(voter_id,
                  input("Choose from 'OptionA', 'OptionB', or 'OptionC': "))

# Get vote results
results = vote_db.get_vote_results()
print("Vote results:")
for choice, count in results:
    print(f"{choice}: {count} votes")